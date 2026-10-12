"""F02 acceptance: revocation covers the token, dispatch, and in-flight work.

Companion to ``docs/release-fix-plan.zh-CN.md`` §3 (F02). Before this fix a node
whose identity and device keys ``admin revoke-key`` had withdrawn could still
authenticate with its link token: ``resolve_credential`` consulted only the
credential's own ``revoked_at`` and never the ``identities`` rows the token was
bound to, so the bearer path disagreed with the signature path about what
"revoked" meant. Each test here pins one lifecycle property the fix restores:

* revoking either the node identity key or the device key withdraws the token;
* an already-connected session is offered no new work once its device is gone;
* a late usage report from a revoked device ends its request with a named
  result — FAILED, usage held unknown — instead of hanging or settling;
* the revocation survives a restart and a repeated revoke is a clear no-op;
* a fresh invite mints a working token the old credential never reclaims;
* and the refusal is proven over a real loopback WebSocket, not only a direct
  function call.

These tests deliberately live apart from the shared suites so the F02 lane does
not churn files the F01 (hello-binding) lane also edits.
"""

from __future__ import annotations

import datetime as dt
import http.client
import json
from pathlib import Path
from typing import Any

import pytest
from aipotluck.errors import KeyRevokedError, StateTransitionError
from aipotluck.identity import generate_key_pair, load_private_key
from aipotluck.ledger import Ledger
from aipotluck.metering import Measurement, NormalizedUsage
from aipotluck.records import UsageReport
from aipotluck.websocket import ClientConnection, WebSocketProtocolError
from aipotluck.wire import (
    AttemptDecision,
    AttemptEvent,
    AttemptOffer,
    AttemptRef,
    Envelope,
    NodeHello,
    NodePolicy,
    compute_acceptance_hash,
    user_message,
)
from conftest import Keyring, signed_authorization

from aipotluck_server.cli import main as server_main
from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import CenterStore, Credential

#: The instant every service-level test works from. It is also the
#: authorization window's midpoint (``conftest.SETTLEMENT_AT``), so a signed
#: authorization is valid at it without juggling the clock.
BASE = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
MODEL = "coding-pool"
TENANT = "tenant-a"
PROMPT = "write a haiku about ledgers"
#: The conversation every admission here signs and submits, as one user turn.
MESSAGES = (user_message(PROMPT),)
SETTLEMENT_KEY_ID = "settlement-key-1"
ADAPTER = "mock-adapter"

#: A funded consumer, matching ``conftest.signed_authorization``'s defaults.
CONSUMER = Credential(
    tenant_id=TENANT, subject_id="consumer-X", role="consumer", account_id="consumer-X"
)


def _funded_ledger() -> Ledger:
    """Return a ledger with a funded consumer and the provider pending buckets."""
    book = Ledger()
    book.issue("consumer-X", "consumer_available", 100_000)
    for account in ("provider-A", "provider-B"):
        book.account(f"{account}/pending", "provider_pending")
    book.fund_reserve(50_000)
    return book


class _Center:
    """A real service over a real store; a real loopback server when asked.

    The settlement key comes from ``Keyring``, which already registers it, so a
    rebuilt service settles against the same platform identity across a restart.
    """

    def __init__(self, tmp_path: Path, *, with_server: bool = False) -> None:
        self.tmp_path = tmp_path
        self.keyring = Keyring()
        self.registry = self.keyring.registry
        self.store = CenterStore.open(tmp_path / "center.db")
        self.ledger = _funded_ledger()
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(tmp_path / "center.db"),
            platform_id="platform-1",
            settlement_key_id=SETTLEMENT_KEY_ID,
            settlement_private_key_b64=self.keyring.private_b64[SETTLEMENT_KEY_ID],
        )
        # A real server authenticates against the wall clock (the HTTP layer
        # resolves credentials at ``now()``), so its service must fall back to
        # the wall clock too; a fixed ``BASE`` would sit in the past relative to
        # a wall-clock join and read every fresh key as "not registered yet".
        # Service-level tests keep the deterministic ``BASE``.
        self._now: dt.datetime | None = None if with_server else BASE
        self.service = self._build_service()
        self.server: GatewayServer | None = None
        if with_server:
            self._start_server()

    def _build_service(self) -> GatewayService:
        return GatewayService(
            config=self.config,
            store=self.store,
            registry=self.registry,
            ledger=self.ledger,
            now=self._now,
        )

    def _start_server(self) -> None:
        self.server = GatewayServer(self.service, config=self.config)
        self.server.start()

    @property
    def port(self) -> int:
        """The real bound loopback port."""
        assert self.server is not None
        return int(self.server.url.rsplit(":", 1)[1])

    def restart(self) -> None:
        """Rebuild the service and server over the same store, as a restart does."""
        assert self.server is not None
        self.server.stop()
        self.service = self._build_service()
        self._start_server()

    def get(self, path: str, token: str) -> tuple[int, dict[str, Any]]:
        """GET one authenticated node route over real HTTP."""
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", path, headers={"authorization": f"Bearer {token}"})
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        return response.status, (json.loads(raw) if raw else {})

    def close(self) -> None:
        """Stop the server (if any) and close the store."""
        if self.server is not None:
            self.server.stop()
        self.store.close()


@pytest.fixture
def center(tmp_path: Path) -> Any:
    """A service-level center over a fresh store, closed at the end."""
    built = _Center(tmp_path)
    yield built
    built.close()


def _join_node(center: _Center, code: str = "code-node", *, now: dt.datetime = BASE) -> Any:
    """Join a node through a real invite; return its ``JoinResult`` and private keys.

    The join mints the node identity row (``owner_id == subject_id``), the
    device key row (``owner_id == device_id``), and the link credential bound to
    both — the exact rows ``resolve_credential`` and dispatch consult, so a
    revocation of either key has something real to bite.
    """
    node_public, node_private = generate_key_pair()
    device_public, device_private = generate_key_pair()
    center.store.add_invite(
        code, "node", "auto", max_uses=1, created_at=now, quota_milli_credits=0
    )
    result = center.service.join(
        invite_code=code,
        identity={"public_key_b64": node_public},
        device={"public_key_b64": device_public},
        center_url="http://center.test",
        now=now,
    )
    return result, node_private, device_private


def _node_hello(result: Any) -> NodeHello:
    """Build the ``node.hello`` a connector dialled from this join would send."""
    return NodeHello(
        node_id=result.device_id,
        device_id=result.device_id,
        device_key_id=result.device_key_id,
        provider_id=result.provider_id,
        adapter_name=ADAPTER,
        model=MODEL,
        policy=NodePolicy(
            share_enabled=True, max_concurrency=2, max_local_reserved_milli_credits=0
        ),
    )


def _connect_node(center: _Center, result: Any, sink: Any) -> None:
    """Register the joined node's link, authenticating with its real credential."""
    credential = center.store.resolve_credential(str(result.node_token), BASE)
    assert credential is not None
    center.service.register_node(
        credential=credential, hello=_node_hello(result), enqueue=sink, now=BASE
    )


def _admit(center: _Center, request_id: str, idempotency_key: str) -> None:
    """Admit one consumer request, which dispatches immediately to a live node."""
    center.service.admit_request(
        credential=CONSUMER,
        idempotency_key=idempotency_key,
        messages=MESSAGES,
        authorization=signed_authorization(
            center.keyring, request_id=request_id, messages=MESSAGES, model=MODEL
        ),
        model=MODEL,
        max_charge_milli_credits=20_000,
        delivery_mode="buffered_complete",
        max_attempts=2,
        now=BASE,
    )


# --------------------------------------------------------------------------
# Fix 1: revoking a linked identity withdraws the bearer credential
# --------------------------------------------------------------------------


def test_revoking_the_node_identity_key_withdraws_its_link_token(center: _Center) -> None:
    """The node's own key governs its token, not only the credential row."""
    result, _, _ = _join_node(center)
    assert center.store.resolve_credential(str(result.node_token), BASE) is not None

    center.store.revoke_identity(result.key_id, BASE)

    assert center.store.resolve_credential(str(result.node_token), BASE) is None
    # History is preserved, not deleted: a past signature still verifies.
    row = center.store.get_identity(result.key_id)
    assert row is not None and row.revoked_at is not None


def test_revoking_the_device_key_withdraws_the_node_link_token(center: _Center) -> None:
    """Revoking the device key alone is enough to kill the link token."""
    result, _, _ = _join_node(center)
    assert center.store.resolve_credential(str(result.node_token), BASE) is not None

    center.store.revoke_identity(result.device_key_id, BASE)

    assert center.store.resolve_credential(str(result.node_token), BASE) is None
    assert center.store.identity_revoked(result.device_id, BASE) is True


def test_a_token_still_resolves_before_the_revocation_instant(center: _Center) -> None:
    """Revocation closes a window; it does not rewrite the token's whole past."""
    result, _, _ = _join_node(center)
    revoke_at = BASE + dt.timedelta(minutes=1)
    center.store.revoke_identity(result.device_key_id, revoke_at)

    # Resolving strictly before the revocation still yields the credential...
    assert center.store.resolve_credential(str(result.node_token), BASE) is not None
    # ...and at or after it, the token is gone.
    assert center.store.resolve_credential(str(result.node_token), revoke_at) is None


def test_repeated_revocation_is_an_idempotent_no_op_that_keeps_the_first_instant(
    center: _Center,
) -> None:
    """A second revoke reports the truth and never moves the recorded instant."""
    result, _, _ = _join_node(center)

    assert center.store.revoke_identity(result.key_id, BASE) is True
    first = center.store.get_identity(result.key_id).revoked_at
    later = BASE + dt.timedelta(seconds=30)
    assert center.store.revoke_identity(result.key_id, later) is False

    assert center.store.get_identity(result.key_id).revoked_at == first
    assert center.store.resolve_credential(str(result.node_token), later) is None


def test_revoking_an_unknown_key_raises(center: _Center) -> None:
    """Revoking a key nobody joined is a clean, named failure."""
    with pytest.raises(StateTransitionError):
        center.store.revoke_identity("key-ghost", BASE)


# --------------------------------------------------------------------------
# Fix 2: an already-connected session is dispatched no new work
# --------------------------------------------------------------------------


def test_an_already_connected_node_is_offered_nothing_after_its_device_is_revoked(
    center: _Center,
) -> None:
    """Revocation bites dispatch on the running center, not only the next dial."""
    result, _, _ = _join_node(center)
    received: list[Envelope] = []
    _connect_node(center, result, received.append)

    _admit(center, "R-1", "idem-1")
    assert any(e.type == "attempt.offer" for e in received), "a live node gets work"
    received.clear()

    # The device key is revoked while the session stays connected.
    center.store.revoke_identity(result.device_key_id, BASE)

    _admit(center, "R-2", "idem-2")
    assert not any(e.type == "attempt.offer" for e in received), (
        "a node whose device key was revoked must be offered no new work"
    )


def test_revocation_survives_a_center_restart(tmp_path: Path) -> None:
    """The store, not memory, governs: a fresh process keeps the refusal."""
    center = _Center(tmp_path)
    result, _, _ = _join_node(center)
    token = str(result.node_token)
    device_id = result.device_id
    center.store.revoke_identity(result.device_key_id, BASE)
    center.close()

    reopened = CenterStore.open(tmp_path / "center.db")
    try:
        assert reopened.resolve_credential(token, BASE) is None
        assert reopened.identity_revoked(device_id, BASE) is True
    finally:
        reopened.close()


# --------------------------------------------------------------------------
# Fix 3: a late report from a revoked device ends with a named result
# --------------------------------------------------------------------------


def _final_usage_event(
    offer: AttemptOffer, result: Any, acceptance_hash: str, device_private: str
) -> Envelope:
    """Build the ``usage.final`` event a node sends to settle its attempt."""
    usage = NormalizedUsage(input_total=800, output_total=200)
    report = UsageReport(
        report_id=f"rep-{offer.attempt_id}",
        permit_id=offer.permit_hash,
        permit_hash=offer.permit_hash,
        acceptance_hash=acceptance_hash,
        attempt_id=offer.attempt_id,
        provider_id=result.provider_id,
        device_id=result.device_id,
        measurement=Measurement(
            measurement_id=f"m-{offer.attempt_id}",
            scope="upstream_call",
            semantics="terminal_total",
            counter_epoch="epoch_1",
            revision=1,
            usage=usage,
            attempt_id=offer.attempt_id,
        ),
        result_commitment=None,
        final_event_seq=2,
        outcome="completed",
        reported_at=BASE,
        key_id=result.device_key_id,
    ).sign(load_private_key(device_private), result.device_key_id)
    return Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=AttemptRef(
                request_id=offer.request_id, attempt_id=offer.attempt_id, epoch=offer.epoch
            ),
            seq=2,
            event_type="usage.final",
            usage=usage,
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


def _drive_to_in_flight(center: _Center, result: Any, device_private: str) -> tuple[
    AttemptOffer, Envelope
]:
    """Accept an attempt on the joined node and return its offer and late report."""
    received: list[Envelope] = []
    _connect_node(center, result, received.append)
    _admit(center, "R-1", "idem-1")
    offer = next(
        AttemptOffer.from_payload(e.payload) for e in received if e.type == "attempt.offer"
    )
    ref = AttemptRef(request_id=offer.request_id, attempt_id=offer.attempt_id, epoch=offer.epoch)
    acceptance_hash = compute_acceptance_hash(
        permit_hash=offer.permit_hash,
        request_id=offer.request_id,
        attempt_id=offer.attempt_id,
        epoch=offer.epoch,
        adapter_name=ADAPTER,
        accepted_at=BASE,
    )
    center.service.handle_node_message(
        node_id=result.device_id,
        envelope=Envelope(
            type="attempt.accept",
            payload=AttemptDecision(
                ref=ref, accepted=True, permit_hash=offer.permit_hash,
                acceptance_hash=acceptance_hash,
            ).to_payload(),
        ),
        now=BASE,
    )
    return offer, _final_usage_event(offer, result, acceptance_hash, device_private)


def test_a_late_usage_report_from_a_revoked_device_ends_the_request_with_a_named_result(
    center: _Center,
) -> None:
    """The report is refused, and the request terminates instead of hanging."""
    result, _, device_private = _join_node(center)
    offer, usage_event = _drive_to_in_flight(center, result, device_private)

    # The device is revoked while its attempt is in flight.
    center.store.revoke_identity(result.device_key_id, BASE)

    with pytest.raises(KeyRevokedError):
        center.service.handle_node_message(
            node_id=result.device_id, envelope=usage_event, now=BASE
        )

    request = center.store.get_request(offer.request_id)
    assert request is not None
    assert request.status == "FAILED"
    assert request.billing_note is not None and "revoked" in request.billing_note
    attempt = center.store.get_attempt(offer.attempt_id)
    assert attempt is not None
    assert attempt.status == "OUTCOME_UNKNOWN"
    # Usage is held unknown (to be confirmed), never recorded as a free zero.
    assert attempt.usage_status == "UNKNOWN"
    assert attempt.usage_tokens is None
    assert center.store.get_settlement(offer.request_id, 1) is None


def test_a_repeated_late_report_from_a_revoked_device_stays_terminal(
    center: _Center,
) -> None:
    """A retried report — or one replayed after a restart — changes nothing."""
    result, _, device_private = _join_node(center)
    offer, usage_event = _drive_to_in_flight(center, result, device_private)
    center.store.revoke_identity(result.device_key_id, BASE)

    for _ in range(2):
        with pytest.raises(KeyRevokedError):
            center.service.handle_node_message(
                node_id=result.device_id, envelope=usage_event, now=BASE
            )

    request = center.store.get_request(offer.request_id)
    assert request is not None and request.status == "FAILED"
    assert center.store.get_settlement(offer.request_id, 1) is None


# --------------------------------------------------------------------------
# Fix 4: a fresh invite recovers; the old credential never comes back
# --------------------------------------------------------------------------


def test_a_fresh_invite_mints_a_working_token_the_old_one_never_reclaims(
    center: _Center,
) -> None:
    """Re-joining with new material recovers; the revoked token stays dead."""
    first, _, _ = _join_node(center, code="code-first")
    center.store.revoke_identity(first.key_id, BASE)
    center.store.revoke_identity(first.device_key_id, BASE)
    assert center.store.resolve_credential(str(first.node_token), BASE) is None

    second, _, _ = _join_node(center, code="code-second")
    assert str(second.node_token) != str(first.node_token)
    revived = center.store.resolve_credential(str(second.node_token), BASE)
    assert revived is not None and revived.role == "node"
    # The old credential did not come back to life because somebody re-joined.
    assert center.store.resolve_credential(str(first.node_token), BASE) is None


# --------------------------------------------------------------------------
# Fix 2 (CLI): admin revoke-key is idempotent and reports a clear result
# --------------------------------------------------------------------------


def test_admin_revoke_key_is_idempotent_and_reports_clearly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Drive the operator command twice, then at a key nobody joined."""
    center = _Center(tmp_path)
    wall = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
    try:
        result, _, _ = _join_node(center, now=wall)
        config = tmp_path / "center-admin.json"
        config.write_text(
            json.dumps({"database_path": str(tmp_path / "center.db")}), encoding="utf-8"
        )
        key_id = str(result.device_key_id)

        assert server_main(
            ["admin", "revoke-key", "--config", str(config), "--key-id", key_id]
        ) == 0
        assert "revoked key" in capsys.readouterr().out

        assert server_main(
            ["admin", "revoke-key", "--config", str(config), "--key-id", key_id]
        ) == 0
        assert "already revoked" in capsys.readouterr().out

        assert server_main(
            ["admin", "revoke-key", "--config", str(config), "--key-id", "key-ghost"]
        ) == 1
        err = capsys.readouterr().err
        assert "error" in err and "Traceback" not in err

        # The command's write withdrew the token on the store the center reads.
        # Resolve at the wall clock the command stamped, not the join instant.
        now = dt.datetime.now(dt.UTC)
        assert center.store.resolve_credential(str(result.node_token), now) is None
    finally:
        center.close()


# --------------------------------------------------------------------------
# Fix 1 + 2 over a real loopback WebSocket (the required WS negative)
# --------------------------------------------------------------------------


def test_a_revoked_node_token_is_refused_on_a_real_websocket(tmp_path: Path) -> None:
    """Not just a direct call: the real handshake answers 401 after revocation."""
    center = _Center(tmp_path, with_server=True)
    wall = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=1)
    try:
        result, _, _ = _join_node(center, now=wall)
        token = str(result.node_token)
        headers = {"Authorization": f"Bearer {token}"}
        url = f"ws://127.0.0.1:{center.port}/v1/node-link"

        # Before revocation the token opens a real node link and is acknowledged.
        link = ClientConnection.connect(url, headers=headers, timeout=10)
        try:
            link.send_text(
                Envelope(type="node.hello", payload=_node_hello(result).to_payload()).encode()
            )
            assert Envelope.decode(link.recv_text(timeout=10)).type == "hello.ack"
        finally:
            link.close()
        # The protected node route answers for the live token too.
        assert center.get("/v1/node/attempts", token)[0] == 200

        # Revoke the device key exactly as `admin revoke-key` does.
        center.store.revoke_identity(result.device_key_id, dt.datetime.now(dt.UTC))

        # The same token is now refused at the real WebSocket upgrade...
        with pytest.raises(WebSocketProtocolError) as refused:
            ClientConnection.connect(url, headers=headers, timeout=10)
        assert "401" in str(refused.value)
        # ...and at the protected node route.
        assert center.get("/v1/node/attempts", token)[0] == 401

        # A full center restart keeps the refusal: the store governs, not memory.
        center.restart()
        restarted = f"ws://127.0.0.1:{center.port}/v1/node-link"
        with pytest.raises(WebSocketProtocolError) as after_restart:
            ClientConnection.connect(restarted, headers=headers, timeout=10)
        assert "401" in str(after_restart.value)
    finally:
        center.close()
