"""Invites, dynamically joined identities, and per-request signatures.

The invite flow is the one place a stranger becomes an identity, so these tests
probe it from every side the contract names: the store's atomic redemption
rules, the unauthenticated ``POST /v1/join`` endpoint, the ``admin`` and ``join``
commands, and — the property the feature exists for — a joined identity that
still authenticates and can still settle after the server is rebuilt from its
SQLite file alone.

The second half pins ``Authorization: AIPotluck-Sig``: the positive path, and
every refusal (unknown key, wrong purpose, revoked key, bad signature, stale
timestamp, replayed nonce), each of which must fail closed without echoing the
key or the signature back.
"""

from __future__ import annotations

import datetime as dt
import http.client
import json
import secrets
import stat
from pathlib import Path
from typing import Any

import pytest
from aipotluck.canonical import canonical_digest, canonicalize, sign_payload
from aipotluck.cli import main
from aipotluck.errors import (
    ConflictError,
    IdentityBindingError,
    KeyRevokedError,
    ProtocolError,
    SignatureError,
    StateTransitionError,
    UnknownKeyError,
)
from aipotluck.identity import generate_key_pair, load_private_key
from aipotluck.metering import Measurement, NormalizedUsage
from aipotluck.records import (
    DOMAIN_REQUEST_AUTH,
    SpendAuthorization,
    UsageReport,
    format_request_auth_header,
    new_nonce,
    request_auth_payload,
    request_body_digest,
)
from aipotluck.wire import (
    AttemptDecision,
    AttemptEvent,
    AttemptOffer,
    AttemptRef,
    Envelope,
    NodeHello,
    NodePolicy,
    compute_acceptance_hash,
    compute_request_digest,
    user_message,
)
from conftest import Keyring

from aipotluck_server.cli import main as server_main
from aipotluck_server.deploy import load_server
from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import Credential, ServerStore

#: The instant every test works from; also the midpoint of an authorization's
#: validity window, so a signed authorization is valid at it with no juggling.
BASE = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
#: Keys provisioned by `Keyring` are registered well in the past, so key
#: validity never depends on the wall clock.
REGISTERED_AT = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
MODEL = "coding-pool"
DELIVERY = "buffered_complete"


# --------------------------------------------------------------------------
# Fixtures and helpers
# --------------------------------------------------------------------------


class _Setup:
    """A real `GatewayService` over a real store, with a provisioned keyring.

    The ledger is *not* injected: the first service rebuilds it from the (empty)
    replay log, and every later funding goes through `fund_account`, so a
    rebuilt service reproduces the exact same books from the log alone — which is
    what the restart test relies on.
    """

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.keyring = Keyring()
        self.registry = self.keyring.registry
        self.store = ServerStore.open(tmp_path / "server.db")
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(tmp_path / "server.db"),
            platform_id="platform-1",
            settlement_key_id="settlement-key-1",
            settlement_private_key_b64=self.keyring.private_b64["settlement-key-1"],
        )
        self.service = GatewayService(
            config=self.config, store=self.store, registry=self.registry, now=BASE
        )

    def close(self) -> None:
        """Close the store."""
        self.store.close()

    def mint(self, code: str, *, role: str = "consumer", tenant: str = "auto",
             max_uses: int = 1, created_at: dt.datetime = BASE,
             expires_at: dt.datetime | None = None) -> None:
        """Register an invite under `code` through the store."""
        self.store.add_invite(
            code, role, tenant, max_uses=max_uses, created_at=created_at,
            expires_at=expires_at,
        )

    def join(self, code: str, *, subject_id: str, key_id: str, public_key_b64: str,
             device: dict[str, Any] | None = None,
             now: dt.datetime = BASE) -> Any:
        """Redeem `code` through the service's domain `join`."""
        return self.service.join(
            invite_code=code,
            identity={
                "subject_id": subject_id,
                "key_id": key_id,
                "public_key_b64": public_key_b64,
                "display_name": None,
            },
            device=device,
            server_url="http://server.test",
            now=now,
        )


@pytest.fixture
def setup(tmp_path: Path) -> _Setup:
    """Return a setup over a fresh store, closed at the end of the test."""
    built = _Setup(tmp_path)
    yield built
    built.close()


class _Server:
    """A real `GatewayServer` bound to a loopback port, for the HTTP tests."""

    def __init__(self, setup: _Setup) -> None:
        self.setup = setup
        self.server = GatewayServer(setup.service, config=setup.config)

    def start(self) -> None:
        """Bind the port."""
        self.server.start()

    @property
    def url(self) -> str:
        """The base URL of the bound listener."""
        return self.server.url

    def stop(self) -> None:
        """Shut the listener down."""
        self.server.stop()


def _post(url: str, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Send one unauthenticated canonical-JSON POST and return the answer."""
    parts = url.split("://", 1)[1]
    host, _, port = parts.partition(":")
    payload = canonicalize(body)
    connection = http.client.HTTPConnection(host, int(port), timeout=10)
    try:
        connection.request(
            "POST",
            path,
            body=payload,
            headers={"content-type": "application/json", "content-length": str(len(payload))},
        )
        response = connection.getresponse()
        raw = response.read()
    finally:
        connection.close()
    document = json.loads(raw) if raw else {}
    return response.status, document


def _send_signed(url: str, path: str, header: str) -> int:
    """Send one GET carrying an ``AIPotluck-Sig`` header and return the status."""
    parts = url.split("://", 1)[1]
    host, _, port = parts.partition(":")
    connection = http.client.HTTPConnection(host, int(port), timeout=10)
    try:
        connection.request("GET", path, headers={"authorization": header})
        response = connection.getresponse()
        response.read()
    finally:
        connection.close()
    return response.status


def _auth_kwargs(private_key: Any, key_id: str, *, issued_at: dt.datetime,
                 nonce: str | None = None, method: str = "GET",
                 path: str = "/v1/requests/R-1", query: str = "",
                 body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the keyword arguments `authenticate_signed_request` accepts."""
    body_digest = request_body_digest(canonicalize(body) if body is not None else None)
    payload = request_auth_payload(
        method=method, path=path, query=query, body_digest=body_digest,
        key_id=key_id, issued_at=issued_at, nonce=nonce or secrets.token_urlsafe(24),
    )
    return {
        "payload": payload,
        "key_id": key_id,
        "issued_at": issued_at,
        "nonce": payload["nonce"],
        "signature_b64": sign_payload(DOMAIN_REQUEST_AUTH, payload, private_key),
    }


def _authorization(private_key: Any, key_id: str, *, request_id: str, consumer_id: str,
                   messages: tuple[Any, ...], max_charge: int = 20_000) -> Any:
    """Sign a consumer spend authorization bound to `messages`/`MODEL`/`DELIVERY`."""
    record = SpendAuthorization(
        authorization_id=f"auth-{request_id}",
        payer_account_id=consumer_id,
        consumer_id=consumer_id,
        request_id=request_id,
        request_digest=compute_request_digest(
            messages=messages, model=MODEL, delivery_mode=DELIVERY
        ),
        max_charge_milli_credits=max_charge,
        pricing_version="flat-v1",
        billing_basis="reported_native_usage",
        minimum_evidence_level="node_reported",
        allowed_models=frozenset({MODEL}),
        allowed_trust_pools=frozenset({"trusted-beta"}),
        max_attempts=2,
        duplicate_execution_policy="bounded_model_only",
        max_provider_fanout=2,
        nonce=new_nonce(),
        issued_at=BASE - dt.timedelta(minutes=1),
        expires_at=BASE + dt.timedelta(minutes=5),
        key_id=key_id,
    )
    return record.sign(private_key, key_id)


def _hello(*, model: str = MODEL) -> NodeHello:
    """Build the opening message a well-formed contribution node sends."""
    return NodeHello(
        node_id="node-A",
        device_id="device-A",
        device_key_id="device-key-A",
        provider_id="provider-A",
        adapter_name="mock-adapter",
        model=model,
        policy=NodePolicy(share_enabled=True, max_concurrency=2,
                          max_local_reserved_milli_credits=0),
    )


def _ref(offer: AttemptOffer) -> AttemptRef:
    """Return the wire reference for an offer."""
    return AttemptRef(request_id=offer.request_id, attempt_id=offer.attempt_id, epoch=offer.epoch)


def _accept(offer: AttemptOffer, acceptance_hash: str) -> Envelope:
    """Build the `attempt.accept` a node sends for an offer."""
    return Envelope(
        type="attempt.accept",
        payload=AttemptDecision(
            ref=_ref(offer), accepted=True, permit_hash=offer.permit_hash,
            acceptance_hash=acceptance_hash,
        ).to_payload(),
    )


def _delta(offer: AttemptOffer, seq: int, text: str) -> Envelope:
    """Build an `output.delta` event for an offer."""
    return Envelope(
        type="attempt.event",
        payload=AttemptEvent(ref=_ref(offer), seq=seq, event_type="output.delta",
                             text=text).to_payload(),
    )


def _usage_event(keyring: Keyring, offer: AttemptOffer, acceptance_hash: str) -> Envelope:
    """Build the device-signed `usage.final` event that settles an attempt."""
    report = UsageReport(
        report_id=f"rep-{offer.attempt_id}",
        permit_id=offer.permit_hash,
        permit_hash=offer.permit_hash,
        acceptance_hash=acceptance_hash,
        attempt_id=offer.attempt_id,
        provider_id="provider-A",
        device_id="device-A",
        measurement=Measurement(
            measurement_id=f"m-{offer.attempt_id}",
            scope="upstream_call",
            semantics="terminal_total",
            counter_epoch="epoch_1",
            revision=1,
            usage=NormalizedUsage(input_total=800, output_total=200),
            attempt_id=offer.attempt_id,
        ),
        result_commitment=None,
        final_event_seq=2,
        outcome="completed",
        reported_at=BASE,
        key_id="device-key-A",
    ).sign(keyring.private["device-key-A"], "device-key-A")
    return Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=_ref(offer),
            seq=2,
            event_type="usage.final",
            usage=NormalizedUsage(input_total=800, output_total=200),
            report={
                "schema": report.schema,
                "record_id": report.record_id,
                "revision": report.revision,
                "signed_at": report.signed_at.astimezone(dt.UTC).isoformat(),
                "signer_key_id": report.signer_key_id,
                "signer_id": report.signer_id,
                "signature": report.signature,
                "previous_record_hash": report.previous_record_hash,
                "payload": dict(report.payload),
            },
        ).to_payload(),
    )


def _drive_to_settlement(
    service: GatewayService, keyring: Keyring, credential: Credential, *, request_id: str,
    messages: tuple[Any, ...], private_key: Any, key_id: str, received: list[Envelope],
) -> dict[str, Any]:
    """Connect a node, admit one request, and settle it; return the status doc."""
    service.register_node(
        credential=Credential(tenant_id=credential.tenant_id, subject_id="node-A", role="node"),
        hello=_hello(),
        enqueue=received.append,
        now=BASE,
    )
    service.admit_request(
        credential=credential,
        idempotency_key=f"idem-{request_id}",
        messages=messages,
        authorization=_authorization(private_key, key_id, request_id=request_id,
                                     consumer_id=credential.subject_id, messages=messages),
        model=MODEL,
        max_charge_milli_credits=20_000,
        delivery_mode=DELIVERY,
        max_attempts=2,
        now=BASE,
    )
    offer = next(
        AttemptOffer.from_payload(envelope.payload)
        for envelope in received
        if envelope.type == "attempt.offer"
    )
    received.clear()
    acceptance_hash = compute_acceptance_hash(
        permit_hash=offer.permit_hash,
        request_id=offer.request_id,
        attempt_id=offer.attempt_id,
        epoch=offer.epoch,
        adapter_name="mock-adapter",
        accepted_at=BASE,
    )
    service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash), now=BASE
    )
    service.handle_node_message(node_id="node-A", envelope=_delta(offer, 1, "a ledger"), now=BASE)
    service.handle_node_message(
        node_id="node-A", envelope=_usage_event(keyring, offer, acceptance_hash), now=BASE
    )
    return service.request_status(credential=credential, request_id=request_id)


# --------------------------------------------------------------------------
# Invite lifecycle (domain level)
# --------------------------------------------------------------------------


def test_an_auto_invite_gives_the_joiner_a_private_derived_tenant(setup: _Setup) -> None:
    """`tenant_scope=auto` mints a private tenant the joiner cannot choose."""
    public_b64, _private = generate_key_pair()
    setup.mint("code-auto")
    result = setup.join("code-auto", subject_id="user-1", key_id="key-1",
                        public_key_b64=public_b64)

    # The identity is server-derived: the subject and key id the body claimed
    # are ignored entirely, and the tenant is private to this join.
    assert result.subject_id != "user-1"
    assert result.key_id != "key-1"
    assert result.subject_id.startswith("consumer-")
    assert result.key_id == result.subject_id
    assert result.tenant_id == "t-" + result.subject_id.split("-", 1)[1]
    assert result.role == "consumer"
    assert result.server_url == "http://server.test"
    assert setup.store.get_invite("code-auto").used_count == 1
    assert setup.store.get_identity("key-1") is None


def test_a_concrete_tenant_invite_puts_every_joiner_in_that_tenant(setup: _Setup) -> None:
    """A named tenant scope shares one tenant across everyone it admits."""
    public_b64, _private = generate_key_pair()
    setup.mint("code-shared", tenant="tenant-shared")
    result = setup.join("code-shared", subject_id="user-2", key_id="key-2",
                        public_key_b64=public_b64)

    assert result.tenant_id == "tenant-shared"


def test_a_single_use_invite_is_exhausted_after_one_join(setup: _Setup) -> None:
    """A second, different joiner with a spent code is refused."""
    first_public, _first_private = generate_key_pair()
    second_public, _second_private = generate_key_pair()
    setup.mint("code-one")
    setup.join("code-one", subject_id="user-1", key_id="key-1", public_key_b64=first_public)

    with pytest.raises(ProtocolError):
        setup.join("code-one", subject_id="user-2", key_id="key-2",
                   public_key_b64=second_public)
    assert setup.store.get_invite("code-one").used_count == 1


def test_rejoining_with_the_same_key_is_free_even_when_the_code_is_spent(
    setup: _Setup,
) -> None:
    """Idempotency is keyed on the identity, not on the invite's remaining uses."""
    public_b64, _private = generate_key_pair()
    setup.mint("code-rejoin")
    first = setup.join("code-rejoin", subject_id="user-1", key_id="key-1",
                       public_key_b64=public_b64)
    second = setup.join("code-rejoin", subject_id="user-1", key_id="key-1",
                        public_key_b64=public_b64)

    assert first == second
    assert setup.store.get_invite("code-rejoin").used_count == 1


def test_rebinding_a_known_key_id_to_new_material_conflicts(setup: _Setup) -> None:
    """A known key id may never come to speak for different material.

    The join path derives key ids on the server, so a caller can no longer
    choose one; the surviving invariant is the store's. Binding one key id to a
    second, different identity is refused rather than silently overwriting the
    first.
    """
    first_public, _first = generate_key_pair()
    second_public, _second = generate_key_pair()
    setup.store.add_identity(
        key_id="key-fixed", owner_id="owner-1", purpose="consumer",
        public_key_b64=first_public, tenant_id="t-1", role="consumer",
        display_name=None, provider_id=None, account_id="owner-1",
        registered_at=BASE,
    )

    with pytest.raises(ConflictError):
        setup.store.add_identity(
            key_id="key-fixed", owner_id="owner-2", purpose="consumer",
            public_key_b64=second_public, tenant_id="t-2", role="consumer",
            display_name=None, provider_id=None, account_id="owner-2",
            registered_at=BASE,
        )


def test_an_unknown_invite_code_fails_closed(setup: _Setup) -> None:
    """A code nobody minted is refused, and nothing is registered."""
    public_b64, _private = generate_key_pair()
    with pytest.raises(ProtocolError):
        setup.join("code-that-does-not-exist", subject_id="user-1", key_id="key-1",
                   public_key_b64=public_b64)
    assert setup.store.get_identity("key-1") is None


def test_an_expired_invite_is_refused(setup: _Setup) -> None:
    """An invite past its expiry admits nobody."""
    public_b64, _private = generate_key_pair()
    setup.mint("code-expired", created_at=BASE - dt.timedelta(days=2),
               expires_at=BASE - dt.timedelta(days=1))
    with pytest.raises(ProtocolError):
        setup.join("code-expired", subject_id="user-1", key_id="key-1",
                   public_key_b64=public_b64)


def test_a_revoked_invite_is_refused(setup: _Setup) -> None:
    """A revoked code admits a new joiner no more."""
    public_b64, _private = generate_key_pair()
    setup.mint("code-revoked")
    setup.store.revoke_invite("code-revoked", BASE)
    with pytest.raises(ProtocolError):
        setup.join("code-revoked", subject_id="user-1", key_id="key-1",
                   public_key_b64=public_b64)


def test_a_role_mismatch_is_refused(setup: _Setup) -> None:
    """A consumer invite carrying a device block, and a node invite without one."""
    public_b64, _private = generate_key_pair()
    setup.mint("code-consumer")
    with pytest.raises(ProtocolError):
        setup.join("code-consumer", subject_id="user-1", key_id="key-1",
                   public_key_b64=public_b64, device={"device_id": "d", "device_key_id": "dk",
                                                      "provider_id": "p"})

    setup.mint("code-node", role="node")
    with pytest.raises(ProtocolError):
        setup.join("code-node", subject_id="user-1", key_id="key-1",
                   public_key_b64=public_b64, device=None)


def test_a_node_invite_registers_and_binds_the_device(setup: _Setup) -> None:
    """A node join derives a provider_device key bound to its own provider."""
    public_b64, _private = generate_key_pair()
    device_public, _device_private = generate_key_pair()
    setup.mint("code-node", role="node")
    result = setup.join(
        "code-node", subject_id="node-1", key_id="node-key-1", public_key_b64=public_b64,
        device={"public_key_b64": device_public},
    )

    assert result.device_key_id is not None
    assert result.device_id is not None
    assert result.provider_id is not None
    device_identity = setup.store.get_identity(result.device_key_id)
    assert device_identity is not None
    assert device_identity.purpose == "provider_device"
    assert device_identity.provider_id == result.provider_id
    assert device_identity.role == "node"
    # The binding is live in the registry, not only in the store row.
    setup.registry.check_device_binding(result.device_id, result.provider_id)
    with pytest.raises(IdentityBindingError):
        setup.registry.check_device_binding(result.device_id, "provider-other")


def test_join_requires_a_public_key(setup: _Setup) -> None:
    """A join without a public key is a protocol error, not a crash."""
    setup.mint("code-shape")
    with pytest.raises(ProtocolError):
        setup.join("code-shape", subject_id="user-1", key_id="key-1", public_key_b64="")


def test_the_store_never_stores_the_plaintext_invite_code(setup: _Setup) -> None:
    """Only the code's digest is persisted; the plaintext never reaches the file."""
    code = "invite-plaintext-SENTINEL-9f3a"
    setup.mint(code)

    assert setup.store.get_invite(code).code_digest == canonical_digest(code)
    assert setup.store.get_invite("something-else") is None
    blob = b"".join(
        path.read_bytes() for path in setup.tmp_path.glob("server.db*") if path.is_file()
    )
    assert code.encode() not in blob


# --------------------------------------------------------------------------
# POST /v1/join over a real socket
# --------------------------------------------------------------------------


def test_join_over_http_mints_an_identity_and_echoes_no_secret(setup: _Setup) -> None:
    """The unauthenticated join endpoint answers with the identity it derived."""
    server = _Server(setup)
    setup.mint("code-http")
    public_b64, _private = generate_key_pair()
    server.start()
    try:
        status, document = _post(
            server.url,
            "/v1/join",
            {
                "invite_code": "code-http",
                "identity": {"subject_id": "user-http", "key_id": "key-http",
                             "public_key_b64": public_b64, "display_name": "Ada"},
                "device": None,
            },
        )
    finally:
        server.stop()

    assert status == 200
    # The claimed identity is ignored; the derived one is echoed back.
    assert document["subject_id"] != "user-http"
    assert document["key_id"] != "key-http"
    assert document["subject_id"].startswith("consumer-")
    assert document["tenant_id"] == "t-" + document["subject_id"].split("-", 1)[1]
    assert document["role"] == "consumer"
    assert document["server_url"].startswith("http://")
    assert "code-http" not in json.dumps(document)


def test_join_over_http_refuses_a_bad_code_without_echoing_it(setup: _Setup) -> None:
    """An unusable code is a 400 whose message carries no code material."""
    server = _Server(setup)
    public_b64, _private = generate_key_pair()
    server.start()
    try:
        status, document = _post(
            server.url,
            "/v1/join",
            {
                "invite_code": "code-unknown-xyz",
                "identity": {"subject_id": "user-http", "key_id": "key-http",
                             "public_key_b64": public_b64},
                "device": None,
            },
        )
    finally:
        server.stop()

    assert status == 400
    assert "code-unknown-xyz" not in json.dumps(document)


def test_join_over_http_refuses_a_malformed_identity(setup: _Setup) -> None:
    """A join body whose identity is not an object is refused with 400."""
    server = _Server(setup)
    server.start()
    try:
        status, _document = _post(
            server.url, "/v1/join", {"invite_code": "x", "identity": "nope", "device": None}
        )
    finally:
        server.stop()

    assert status == 400


# --------------------------------------------------------------------------
# Per-request signatures over a real socket
# --------------------------------------------------------------------------


def test_a_signed_request_authenticates_over_http(setup: _Setup) -> None:
    """A key minted by joining can sign a later request and be admitted."""
    server = _Server(setup)
    setup.mint("code-sig")
    public_b64, private_b64 = generate_key_pair()
    server.start()
    try:
        status, document = _post(
            server.url,
            "/v1/join",
            {
                "invite_code": "code-sig",
                "identity": {"subject_id": "user-sig", "key_id": "key-sig",
                             "public_key_b64": public_b64},
                "device": None,
            },
        )
        assert status == 200
        key_id = document["key_id"]

        private_key = load_private_key(private_b64)
        issued_at = dt.datetime.now(dt.UTC)
        nonce = secrets.token_urlsafe(24)
        payload = request_auth_payload(
            method="GET", path="/v1/checkpoint", query="",
            body_digest=request_body_digest(None), key_id=key_id,
            issued_at=issued_at, nonce=nonce,
        )
        header = format_request_auth_header(
            key_id=key_id, issued_at=issued_at, nonce=nonce,
            signature_b64=sign_payload(DOMAIN_REQUEST_AUTH, payload, private_key),
        )
        assert _send_signed(server.url, "/v1/checkpoint", f"AIPotluck-Sig {header}") == 200
        # A replayed nonce is refused.
        assert _send_signed(server.url, "/v1/checkpoint", f"AIPotluck-Sig {header}") == 401
    finally:
        server.stop()


def test_a_tampered_signature_is_refused_over_http(setup: _Setup) -> None:
    """A signature that does not verify fails closed with 401, echoing nothing."""
    server = _Server(setup)
    setup.mint("code-tamper")
    public_b64, private_b64 = generate_key_pair()
    server.start()
    try:
        _post(
            server.url,
            "/v1/join",
            {
                "invite_code": "code-tamper",
                "identity": {"subject_id": "user-t", "key_id": "key-t",
                             "public_key_b64": public_b64},
                "device": None,
            },
        )
        private_key = load_private_key(private_b64)
        issued_at = dt.datetime.now(dt.UTC)
        nonce = secrets.token_urlsafe(24)
        payload = request_auth_payload(
            method="GET", path="/v1/checkpoint", query="",
            body_digest=request_body_digest(None), key_id="key-t",
            issued_at=issued_at, nonce=nonce,
        )
        real = sign_payload(DOMAIN_REQUEST_AUTH, payload, private_key)
        forged = ("A" if real[0] != "A" else "B") + real[1:]
        header = format_request_auth_header(
            key_id="key-t", issued_at=issued_at, nonce=nonce, signature_b64=forged
        )
        assert _send_signed(server.url, "/v1/checkpoint", f"AIPotluck-Sig {header}") == 401
    finally:
        server.stop()


# --------------------------------------------------------------------------
# `admin` and `join` commands
# --------------------------------------------------------------------------


def _server_config(tmp_path: Path) -> Path:
    """Write the minimal server.json `admin` needs (just a database_path).

    It names the database the `setup` fixture already created, because an `admin`
    command opens a server's database and never creates one.
    """
    path = tmp_path / "server-admin.json"
    path.write_text(json.dumps({"database_path": str(tmp_path / "server.db")}), encoding="utf-8")
    return path


def test_admin_invite_prints_the_code_once_and_stores_only_its_digest(
    setup: _Setup, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The operator sees the code once; the store keeps only its digest."""
    config = _server_config(tmp_path)
    assert server_main(["admin", "invite", "--config", str(config), "--role", "consumer"]) == 0
    captured = capsys.readouterr()
    code = captured.out.strip()

    assert code
    assert "shown once" in captured.err
    invite = setup.store.get_invite(code)
    assert invite is not None
    assert invite.role == "consumer"
    assert invite.tenant_scope == "auto"
    assert invite.used_count == 0
    blob = b"".join(
        path.read_bytes() for path in tmp_path.glob("server.db*") if path.is_file()
    )
    assert code.encode() not in blob


def test_admin_invite_refuses_a_server_database_that_is_not_there(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only `serve` creates the server's database; `admin` opens the one there is.

    An invite minted into a database the minting itself created is an invite no
    server will ever honour: the code is printed once, handed over out of band,
    and the join fails on an unknown code with nothing left to compare against.
    The refusal names the path so the operator sees which of the two it is — a
    server that was never started here, or a ``database_path`` that is wrong.
    """
    database = tmp_path / "not-this-directory" / "server.db"
    config = tmp_path / "server-typo.json"
    config.write_text(json.dumps({"database_path": str(database)}), encoding="utf-8")

    assert server_main(["admin", "invite", "--config", str(config), "--role", "consumer"]) == 1

    error = capsys.readouterr().err
    assert str(database) in error
    assert "does not exist" in error
    assert "potluck serve" in error
    assert not database.exists()
    assert not database.parent.exists()


def test_admin_invite_list_is_redacted(
    setup: _Setup, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The listing shows a digest prefix and never a usable code."""
    setup.mint("code-listed", tenant="tenant-listed")
    config = _server_config(tmp_path)

    assert server_main(["admin", "invite-list", "--config", str(config)]) == 0
    out = capsys.readouterr().out

    assert canonical_digest("code-listed")[:20] in out
    assert "code-listed" not in out
    assert "tenant-listed" in out


def test_admin_revoke_key_stops_a_live_key(
    setup: _Setup, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`admin revoke-key` writes the store, and the running server honours it."""
    setup.mint("code-revoke")
    public_b64, private_b64 = generate_key_pair()
    result = setup.join("code-revoke", subject_id="user-rv", key_id="key-rv",
                        public_key_b64=public_b64)
    key_id = result.key_id
    private_key = load_private_key(private_b64)

    # The key works before revocation.
    setup.service.authenticate_signed_request(
        **_auth_kwargs(private_key, key_id, issued_at=BASE), now=BASE
    )

    config = _server_config(tmp_path)
    assert server_main(["admin", "revoke-key", "--config", str(config), "--key-id", key_id]) == 0
    capsys.readouterr()

    assert setup.store.get_identity(key_id).revoked_at is not None
    # Revocation closes a window rather than erasing history, so the request is
    # judged at an instant after the revocation the command just stamped.
    after = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=1)
    with pytest.raises(KeyRevokedError):
        setup.service.authenticate_signed_request(
            **_auth_kwargs(private_key, key_id, issued_at=after), now=after
        )


def test_admin_revoke_key_unknown_key_fails_cleanly(
    setup: _Setup, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Revoking a key nobody joined reports the failure without a traceback."""
    config = _server_config(tmp_path)
    assert server_main(
        ["admin", "revoke-key", "--config", str(config), "--key-id", "key-ghost"]
    ) == 1
    err = capsys.readouterr().err
    assert "error" in err
    assert "Traceback" not in err


def test_cli_join_saves_a_0600_key_and_a_config_and_prints_no_private_key(
    setup: _Setup, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The saved identity is usable, and the private key never reaches a stream."""
    server = _Server(setup)
    setup.mint("code-cli")
    config_dir = tmp_path / "identity"
    server.start()
    try:
        assert main([
            "join", "--server", server.url, "--invite", "code-cli",
            "--config-dir", str(config_dir), "--subject-id", "user-cli",
        ]) == 0
    finally:
        server.stop()
    captured = capsys.readouterr()

    key_path = config_dir / "key.json"
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    key_document = json.loads(key_path.read_text(encoding="utf-8"))
    config_document = json.loads((config_dir / "config.json").read_text(encoding="utf-8"))
    # The identity in the config is the one the *server* derived, not the
    # ``--subject-id`` the command was given.
    assert config_document["subject_id"] != "user-cli"
    assert config_document["subject_id"].startswith("consumer-")
    assert config_document["tenant_id"].startswith("t-")
    assert config_document["role"] == "consumer"
    assert config_document["key_id"].startswith("consumer-")
    # The key file carries only key material; the identity lives in the config.
    assert set(key_document) >= {"public_key_b64", "private_key_b64"}
    assert key_document["private_key_b64"] not in captured.out
    assert key_document["private_key_b64"] not in captured.err
    assert setup.store.get_invite("code-cli").used_count == 1


def test_cli_join_is_idempotent_on_rerun(
    setup: _Setup, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Re-running `join` reuses the saved key and burns no extra use."""
    server = _Server(setup)
    setup.mint("code-idem")
    config_dir = tmp_path / "identity"
    server.start()
    try:
        argv = [
            "join", "--server", server.url, "--invite", "code-idem",
            "--config-dir", str(config_dir), "--subject-id", "user-idem",
        ]
        assert main(argv) == 0
        first_config = json.loads((config_dir / "config.json").read_text(encoding="utf-8"))
        assert main(argv) == 0
    finally:
        server.stop()
    capsys.readouterr()

    second_config = json.loads((config_dir / "config.json").read_text(encoding="utf-8"))
    assert second_config == first_config
    assert setup.store.get_invite("code-idem").used_count == 1


def test_cli_join_after_exhaustion_fails_without_leaking_the_key(
    setup: _Setup, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A fresh joiner on a spent code is refused, and no stream carries a key."""
    server = _Server(setup)
    setup.mint("code-spent")
    public_b64, _private = generate_key_pair()
    setup.join("code-spent", subject_id="user-first", key_id="key-first",
               public_key_b64=public_b64)
    second_dir = tmp_path / "identity-second"
    server.start()
    try:
        code = main([
            "join", "--server", server.url, "--invite", "code-spent",
            "--config-dir", str(second_dir), "--subject-id", "user-second",
        ])
    finally:
        server.stop()
    captured = capsys.readouterr()

    assert code == 1
    assert "error" in captured.err
    assert "Traceback" not in captured.err
    if (second_dir / "key.json").exists():
        private_key = json.loads((second_dir / "key.json").read_text(encoding="utf-8"))[
            "private_key_b64"
        ]
        assert private_key not in captured.out
        assert private_key not in captured.err


# --------------------------------------------------------------------------
# `version`
# --------------------------------------------------------------------------


def test_version_reports_the_package_and_protocol(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """`potluck version` prints the package version and the protocol schema."""
    assert main(["version"]) == 0
    out = capsys.readouterr().out

    assert out.startswith("potluck ")
    assert "protocol" in out
    assert "v0.1" in out


# --------------------------------------------------------------------------
# Signature authentication (domain level, all refusals)
# --------------------------------------------------------------------------


def _joined_key(setup: _Setup, *, subject_id: str = "user-sig", key_id: str = "key-sig",
                code: str = "code-sigdn") -> tuple[str, str, str]:
    """Mint an invite, join, and return ``(public_b64, private_b64, key_id)``.

    The returned key id is the one the server derived, which is what the joiner
    must sign with.
    """
    public_b64, private_b64 = generate_key_pair()
    setup.mint(code)
    result = setup.join(code, subject_id=subject_id, key_id=key_id,
                        public_key_b64=public_b64)
    return public_b64, private_b64, result.key_id


def test_signed_request_resolves_the_joined_credential(setup: _Setup) -> None:
    """The positive path: a valid signature becomes the joined credential."""
    _public, private_b64, key_id = _joined_key(setup, subject_id="user-sig")
    credential = setup.service.authenticate_signed_request(
        **_auth_kwargs(load_private_key(private_b64), key_id, issued_at=BASE), now=BASE
    )
    assert credential.role == "consumer"
    assert credential.subject_id.startswith("consumer-")
    assert credential.tenant_id.startswith("t-")
    # The credential carries the account admission binds the payer to.
    assert credential.account_id == credential.subject_id


def test_signed_request_with_an_unknown_key_is_refused(setup: _Setup) -> None:
    """A key the registry never saw cannot authenticate."""
    _public, private_b64 = generate_key_pair()
    with pytest.raises(UnknownKeyError):
        setup.service.authenticate_signed_request(
            **_auth_kwargs(load_private_key(private_b64), "key-unknown", issued_at=BASE),
            now=BASE,
        )


def test_signed_request_with_a_wrong_purpose_is_refused(setup: _Setup) -> None:
    """A provider-device key may not authenticate a consumer request."""
    with pytest.raises(IdentityBindingError):
        setup.service.authenticate_signed_request(
            **_auth_kwargs(setup.keyring.private["device-key-A"], "device-key-A",
                           issued_at=BASE),
            now=BASE,
        )


def test_signed_request_with_a_bad_signature_is_refused(setup: _Setup) -> None:
    """A signature produced by another key does not verify."""
    _public, private_b64, key_id = _joined_key(setup)
    _other_public, other_private = generate_key_pair()
    kwargs = _auth_kwargs(load_private_key(private_b64), key_id, issued_at=BASE)
    kwargs["signature_b64"] = sign_payload(
        DOMAIN_REQUEST_AUTH, kwargs["payload"], load_private_key(other_private)
    )
    with pytest.raises(SignatureError):
        setup.service.authenticate_signed_request(**kwargs, now=BASE)


def test_signed_request_with_a_stale_timestamp_is_refused(setup: _Setup) -> None:
    """A signature outside the acceptance window is refused."""
    _public, private_b64, key_id = _joined_key(setup)
    with pytest.raises(ProtocolError):
        setup.service.authenticate_signed_request(
            **_auth_kwargs(
                load_private_key(private_b64), key_id,
                issued_at=BASE - dt.timedelta(minutes=10),
            ),
            now=BASE,
        )


def test_signed_request_with_a_replayed_nonce_is_refused(setup: _Setup) -> None:
    """The same nonce may be spent once per key."""
    _public, private_b64, key_id = _joined_key(setup)
    kwargs = _auth_kwargs(load_private_key(private_b64), key_id, issued_at=BASE)
    setup.service.authenticate_signed_request(**kwargs, now=BASE)
    with pytest.raises(ProtocolError):
        setup.service.authenticate_signed_request(**kwargs, now=BASE)


def test_signed_request_with_a_revoked_key_is_refused(setup: _Setup) -> None:
    """A key revoked in the registry cannot authenticate."""
    _public, private_b64, key_id = _joined_key(setup)
    setup.registry.revoke_key(key_id, BASE)
    with pytest.raises(KeyRevokedError):
        setup.service.authenticate_signed_request(
            **_auth_kwargs(load_private_key(private_b64), key_id, issued_at=BASE), now=BASE
        )


def test_signed_request_with_a_revoked_identity_row_is_refused(setup: _Setup) -> None:
    """A key revoked in the store (as `admin revoke-key` does) fails closed."""
    _public, private_b64, key_id = _joined_key(setup)
    setup.store.revoke_identity(key_id, BASE)
    with pytest.raises(KeyRevokedError):
        setup.service.authenticate_signed_request(
            **_auth_kwargs(load_private_key(private_b64), key_id, issued_at=BASE), now=BASE
        )


# --------------------------------------------------------------------------
# G01: a joined identity survives a restart, from SQLite alone
# --------------------------------------------------------------------------


def test_a_joined_identity_survives_a_restart_and_can_settle_again(
    tmp_path: Path, setup: _Setup
) -> None:
    """The headline property: after a rebuild the joined key still works.

    The first server joins an identity from an invite, admits and settles a
    request with it, and then is closed. A second server is built by
    `load_server` from the same ``server.db`` (and a ``server.json`` that names
    only the settlement key and the provider device key — never the consumer),
    which replays the ``identities`` table into a fresh registry. The same key
    must still authenticate, the old receipt must still be readable, and a new
    request must still settle.
    """
    # -- first server: join, settle, then close ----------------------------
    public_b64, private_b64 = generate_key_pair()
    setup.mint("code-restart")
    result = setup.join("code-restart", subject_id="user-joined", key_id="key-joined",
                        public_key_b64=public_b64)
    key_id = result.key_id
    subject_id = result.subject_id
    assert result.tenant_id == "t-" + subject_id.split("-", 1)[1]
    setup.service.fund_account(
        account_id=subject_id, kind="consumer_available", amount=100_000, now=BASE
    )

    private_key = load_private_key(private_b64)
    credential = setup.service.authenticate_signed_request(
        **_auth_kwargs(private_key, key_id, issued_at=BASE), now=BASE
    )
    received: list[Envelope] = []
    document = _drive_to_settlement(
        setup.service, setup.keyring, credential, request_id="R-1",
        messages=(user_message("first answer"),),
        private_key=private_key, key_id=key_id, received=received,
    )
    assert document["status"] == "SUCCEEDED"
    receipt_id = document["settlement"]["receipt_id"]

    server_path = tmp_path / "server.json"
    server_path.write_text(
        json.dumps(
            {
                "host": "127.0.0.1",
                "port": 0,
                "database_path": str(tmp_path / "server.db"),
                "platform_id": "platform-1",
                "settlement_key_id": "settlement-key-1",
                "settlement_private_key_b64": setup.keyring.private_b64["settlement-key-1"],
                "certfile": None,
                "keyfile": None,
                "credentials": [],
                "providers": [
                    {
                        "device_id": "device-A",
                        "device_key_id": "device-key-A",
                        "provider_id": "provider-A",
                        "public_key_b64": setup.keyring.public["device-key-A"],
                        "demo_float_milli_credits": 0,
                    }
                ],
                "consumer_floats": [],
            }
        ),
        encoding="utf-8",
    )
    setup.close()

    # -- second server: rebuilt from the same SQLite file ------------------
    deployment = load_server(server_path)
    try:
        rebuilt = deployment.service

        # The consumer exists only in the identities table; the replay is what
        # puts its key back in the registry.
        assert deployment.store.get_identity(key_id) is not None
        credential = rebuilt.authenticate_signed_request(
            **_auth_kwargs(private_key, key_id, issued_at=BASE), now=BASE
        )
        assert credential == Credential(
            tenant_id=result.tenant_id, subject_id=subject_id, role="consumer",
            account_id=subject_id,
        )

        # The old receipt is still readable through the rebuilt log.
        receipt = rebuilt.receipt_for(credential=credential, receipt_id=receipt_id)
        assert receipt["receipt_id"] == receipt_id
        assert receipt["log_index"] == 0

        # And a brand-new request still settles with the same identity.
        received2: list[Envelope] = []
        document2 = _drive_to_settlement(
            rebuilt, setup.keyring, credential, request_id="R-2",
            messages=(user_message("second answer"),),
            private_key=private_key, key_id=key_id, received=received2,
        )
        assert document2["status"] == "SUCCEEDED"
        assert document2["settlement"]["receipt_id"] != receipt_id
    finally:
        deployment.store.close()


# --------------------------------------------------------------------------
# The store's invite table is atomic and single-source
# --------------------------------------------------------------------------


def test_consume_invite_is_atomic_under_concurrency(tmp_path: Path) -> None:
    """Two concurrent redemptions of a one-use code admit exactly one."""
    import threading

    store = ServerStore.open(tmp_path / "server.db")
    try:
        store.add_invite("code-race", "consumer", "auto", max_uses=1, created_at=BASE)
        outcomes: list[str] = []
        barrier = threading.Barrier(2)

        def redeem() -> None:
            barrier.wait()
            try:
                store.consume_invite("code-race", at=BASE)
                outcomes.append("ok")
            except ProtocolError:
                outcomes.append("refused")

        threads = [threading.Thread(target=redeem) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sorted(outcomes) == ["ok", "refused"]
        assert store.get_invite("code-race").used_count == 1
    finally:
        store.close()


def test_consuming_an_unknown_code_raises(tmp_path: Path) -> None:
    """The atomic consume refuses a code that was never minted."""
    store = ServerStore.open(tmp_path / "server.db")
    try:
        with pytest.raises(ProtocolError):
            store.consume_invite("code-ghost", at=BASE)
    finally:
        store.close()


def test_revoke_identity_of_an_unknown_key_raises(setup: _Setup) -> None:
    """Revoking an identity nobody registered is a state error, not a silent no-op."""
    with pytest.raises(StateTransitionError):
        setup.store.revoke_identity("key-ghost", BASE)
