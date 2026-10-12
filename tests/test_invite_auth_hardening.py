"""Regressions for the invite/identity authorization hardening work.

Each test here pins a property that the pre-hardening build got wrong, so the
module doubles as the evidence that the fixes bite:

* **Identity is derived by the server.** A join body that claims ``subject_id``
  or ``key_id`` for someone else must have no effect: two joiners who both claim
  ``subject_id="alice"`` must still land in two tenants, read nothing of each
  other's, and be unable to sign a charge against alice's account.
* **Revocation is immediate on every settlement path.** ``admin revoke-key``
  writes the store; the device-report path must consult the store row, not only
  the in-memory registry, before it settles.
* **Nonce memory is per key.** Flooding one key's nonce bucket must not evict
  another key's spent nonce and so reopen a replay.
* **A failed join leaves nothing behind.** A registry key registered mid-join
  must be dropped again when a later step fails, and a binding conflict must not
  burn an invite use.
* **An invited node can authenticate itself.** A node join provisions the link
  credential it returns — digest at rest, plaintext once — and that credential
  alone completes the ``node.hello`` handshake and receives an offer. An
  idempotent re-join mints no second one.
"""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
from typing import Any

import pytest
from aipotluck.canonical import sign_payload
from aipotluck.errors import (
    ConflictError,
    IdentityBindingError,
    KeyRevokedError,
    ProtocolError,
)
from aipotluck.identity import KeyPurpose, generate_key_pair, load_private_key
from aipotluck.metering import Measurement, NormalizedUsage
from aipotluck.records import (
    DOMAIN_REQUEST_AUTH,
    SpendAuthorization,
    UsageReport,
    new_nonce,
    request_auth_payload,
    request_body_digest,
)
from aipotluck.wire import (
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

from aipotluck_server.deploy import load_center
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import CenterStore, Credential

BASE = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
MODEL = "coding-pool"
DELIVERY = "buffered_complete"


class _Center:
    """A real service over a real store, with invites minted by a helper."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.keyring = Keyring()
        self.store = CenterStore.open(tmp_path / "center.db")
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(tmp_path / "center.db"),
            platform_id="platform-1",
            settlement_key_id="settlement-key-1",
            settlement_private_key_b64=self.keyring.private_b64["settlement-key-1"],
        )
        self.service = GatewayService(
            config=self.config, store=self.store, registry=self.keyring.registry, now=BASE
        )

    def close(self) -> None:
        """Close the store."""
        self.store.close()

    def mint(self, code: str, *, role: str = "consumer", tenant: str = "auto",
             max_uses: int = 1, quota: int = 20_000) -> None:
        """Register an invite through the store."""
        self.store.add_invite(
            code, role, tenant, max_uses=max_uses, created_at=BASE,
            quota_milli_credits=quota,
        )

    def join(self, code: str, *, public_key_b64: str,
             claimed_subject_id: str | None = None,
             claimed_key_id: str | None = None,
             device: dict[str, Any] | None = None) -> Any:
        """Join, optionally asserting a claimed identity the server must ignore."""
        identity: dict[str, Any] = {"public_key_b64": public_key_b64}
        if claimed_subject_id is not None:
            identity["subject_id"] = claimed_subject_id
        if claimed_key_id is not None:
            identity["key_id"] = claimed_key_id
        return self.service.join(
            invite_code=code, identity=identity, device=device,
            center_url="http://center.test", now=BASE,
        )


@pytest.fixture
def center(tmp_path: Path) -> _Center:
    """Return a center over a fresh store, closed at the end of the test."""
    built = _Center(tmp_path)
    yield built
    built.close()


def _authorization(private_key: Any, key_id: str, *, request_id: str, consumer_id: str,
                   payer_account_id: str, messages: tuple[Any, ...],
                   max_charge: int = 20_000) -> Any:
    """Sign a consumer authorization bound to the given identity and account."""
    record = SpendAuthorization(
        authorization_id=f"auth-{request_id}",
        payer_account_id=payer_account_id,
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


# --------------------------------------------------------------------------
# P0: identity is server-derived, never taken from the body
# --------------------------------------------------------------------------


def test_two_joiners_claiming_the_same_subject_stay_isolated(center: _Center) -> None:
    """Both claim ``alice``; the server must still separate them completely."""
    center.service.fund_account(
        account_id="alice", kind="consumer_available", amount=100_000, now=BASE
    )
    first_public, first_private = generate_key_pair()
    second_public, second_private = generate_key_pair()
    center.mint("code-a")
    center.mint("code-b")

    first = center.join("code-a", public_key_b64=first_public, claimed_subject_id="alice",
                        claimed_key_id="alice-key")
    second = center.join("code-b", public_key_b64=second_public, claimed_subject_id="alice",
                         claimed_key_id="alice-key")

    # Their tenants and accounts are distinct, and neither is "alice".
    assert first.tenant_id != second.tenant_id
    assert first.subject_id != second.subject_id
    assert first.subject_id != "alice"
    assert second.subject_id != "alice"
    assert first.key_id != second.key_id

    # A cannot be reached by B: B's credential cannot read A's request.
    first_credential = Credential(
        tenant_id=first.tenant_id, subject_id=first.subject_id, role="consumer",
        account_id=first.subject_id,
    )
    second_credential = Credential(
        tenant_id=second.tenant_id, subject_id=second.subject_id, role="consumer",
        account_id=second.subject_id,
    )
    first_authorization = _authorization(
        load_private_key(first_private), first.key_id, request_id="R-a",
        consumer_id=first.subject_id, payer_account_id=first.subject_id,
        messages=(user_message("hi"),),
    )
    center.service.admit_request(
        credential=first_credential, idempotency_key="idem-a",
        messages=(user_message("hi"),),
        authorization=first_authorization, model=MODEL, max_charge_milli_credits=20_000,
        delivery_mode=DELIVERY, max_attempts=2, now=BASE,
    )
    with pytest.raises(IdentityBindingError):
        center.service.request_status(credential=second_credential, request_id="R-a")

    # B cannot sign a charge against alice's funded account either.
    forged = _authorization(
        load_private_key(second_private), second.key_id, request_id="R-b",
        consumer_id="alice", payer_account_id="alice", messages=(user_message("steal"),),
    )
    with pytest.raises(IdentityBindingError):
        center.service.admit_request(
            credential=second_credential, idempotency_key="idem-b",
            messages=(user_message("steal"),),
            authorization=forged, model=MODEL, max_charge_milli_credits=20_000,
            delivery_mode=DELIVERY, max_attempts=2, now=BASE,
        )


def test_a_join_body_claiming_another_identity_changes_nothing(center: _Center) -> None:
    """A body that names someone else's key id must not create that key id."""
    public_b64, _private = generate_key_pair()
    center.mint("code-claim")
    result = center.join(
        "code-claim", public_key_b64=public_b64,
        claimed_subject_id="alice", claimed_key_id="alice-key",
    )

    assert result.key_id != "alice-key"
    assert result.subject_id != "alice"
    assert center.store.get_identity("alice-key") is None
    row = center.store.get_identity(result.key_id)
    assert row is not None
    assert row.owner_id == result.subject_id


def test_join_requires_a_public_key(center: _Center) -> None:
    """Without key material there is nothing to derive an identity from."""
    center.mint("code-nokey")
    with pytest.raises(ProtocolError):
        center.join("code-nokey", public_key_b64="")


def test_an_auto_join_funds_its_own_account_once(center: _Center) -> None:
    """Join mints the identity's account with the invite's quota, idempotently."""
    public_b64, _private = generate_key_pair()
    center.mint("code-quota", tenant="auto", quota=12_345)
    first = center.join("code-quota", public_key_b64=public_b64)
    assert center.service.balance(first.subject_id) == 12_345

    # Re-joining with the same key returns the same identity and adds nothing.
    second = center.join("code-quota", public_key_b64=public_b64)
    assert second == first
    assert center.service.balance(first.subject_id) == 12_345


def test_a_concrete_tenant_invite_still_shares_the_tenant(center: _Center) -> None:
    """A named scope is shared by design, so two joiners land in one tenant."""
    first_public, _first_private = generate_key_pair()
    second_public, _second_private = generate_key_pair()
    center.mint("code-shared", tenant="tenant-shared", max_uses=2)
    first = center.join("code-shared", public_key_b64=first_public)
    second = center.join("code-shared", public_key_b64=second_public)

    assert first.tenant_id == "tenant-shared"
    assert second.tenant_id == "tenant-shared"
    assert first.key_id != second.key_id


# --------------------------------------------------------------------------
# P0: the store's identity uniqueness invariants
# --------------------------------------------------------------------------


def test_the_store_refuses_two_identities_for_one_owner(center: _Center) -> None:
    """``(role, owner_id)`` is unique, so a second key for one owner is refused."""
    public_one, _p1 = generate_key_pair()
    public_two, _p2 = generate_key_pair()
    center.store.add_identity(
        key_id="k-1", owner_id="owner-1", purpose="consumer", public_key_b64=public_one,
        tenant_id="tenant-1", role="consumer", display_name=None, provider_id=None,
        account_id="owner-1", registered_at=BASE,
    )
    with pytest.raises(ConflictError):
        center.store.add_identity(
            key_id="k-2", owner_id="owner-1", purpose="consumer", public_key_b64=public_two,
            tenant_id="tenant-2", role="consumer", display_name=None, provider_id=None,
            account_id="owner-1", registered_at=BASE,
        )


def test_the_store_refuses_two_auto_identities_sharing_a_tenant(center: _Center) -> None:
    """Two auto-scoped identities may not silently share one private tenant."""
    public_one, _p1 = generate_key_pair()
    public_two, _p2 = generate_key_pair()
    center.store.add_identity(
        key_id="k-1", owner_id="owner-1", purpose="consumer", public_key_b64=public_one,
        tenant_id="t-collide", role="consumer", display_name=None, provider_id=None,
        account_id="owner-1", registered_at=BASE,
    )
    with pytest.raises(ConflictError):
        center.store.add_identity(
            key_id="k-2", owner_id="owner-2", purpose="consumer", public_key_b64=public_two,
            tenant_id="t-collide", role="consumer", display_name=None, provider_id=None,
            account_id="owner-2", registered_at=BASE,
        )


# --------------------------------------------------------------------------
# P1-1: a revoked device key cannot report usage, before or after a restart
# --------------------------------------------------------------------------


def _node_join(center: _Center) -> tuple[Any, str, str]:
    """Join a node, returning its identity, the device private key, and its id."""
    node_public, _node_private = generate_key_pair()
    device_public, device_private = generate_key_pair()
    center.mint("code-node", role="node")
    result = center.join(
        "code-node", public_key_b64=node_public,
        device={"public_key_b64": device_public},
    )
    assert result.device_key_id is not None
    device_row = center.store.get_identity(result.device_key_id)
    assert device_row is not None
    return result, device_private, device_row.key_id


def _drive_to_usage_final(
    center: _Center, *, device_key_id: str, node_token: str, consumer: Any,
    consumer_key_id: str, private_key: Any,
) -> tuple[AttemptOffer, dict[str, Any]]:
    """Drive an attempt to the edge of settlement; return the offer and facts.

    The node link is opened by the credential the join minted, dialing as the
    node id that credential is bound to — its device — exactly as the connector
    does. `register_node` refuses any other pairing.
    """
    from aipotluck.wire import AttemptDecision

    device_row = center.store.get_identity(device_key_id)
    assert device_row is not None
    device_id = device_row.owner_id
    provider_id = device_row.provider_id
    assert provider_id is not None

    node_credential = center.store.resolve_credential(node_token, BASE)
    assert node_credential is not None
    node_id = device_id
    received: list[Envelope] = []
    center.service.register_node(
        credential=node_credential,
        hello=NodeHello(
            node_id=node_id, device_id=device_id, device_key_id=device_key_id,
            provider_id=provider_id, adapter_name="mock-adapter", model=MODEL,
            policy=NodePolicy(share_enabled=True, max_concurrency=2,
                              max_local_reserved_milli_credits=0),
        ),
        enqueue=received.append, now=BASE,
    )
    center.service.admit_request(
        credential=consumer, idempotency_key="idem-1", messages=(user_message("hi"),),
        authorization=_authorization(
            private_key, consumer_key_id, request_id="R-1",
            consumer_id=consumer.subject_id, payer_account_id=consumer.subject_id,
            messages=(user_message("hi"),),
        ),
        model=MODEL, max_charge_milli_credits=20_000, delivery_mode=DELIVERY,
        max_attempts=2, now=BASE,
    )
    offer = next(
        AttemptOffer.from_payload(envelope.payload)
        for envelope in received
        if envelope.type == "attempt.offer"
    )
    received.clear()
    ref = AttemptRef(request_id=offer.request_id, attempt_id=offer.attempt_id, epoch=offer.epoch)
    acceptance_hash = compute_acceptance_hash(
        permit_hash=offer.permit_hash, request_id=offer.request_id,
        attempt_id=offer.attempt_id, epoch=offer.epoch, adapter_name="mock-adapter",
        accepted_at=BASE,
    )
    center.service.handle_node_message(
        node_id=node_id,
        envelope=Envelope(
            type="attempt.accept",
            payload=AttemptDecision(
                ref=ref, accepted=True, permit_hash=offer.permit_hash,
                acceptance_hash=acceptance_hash,
            ).to_payload(),
        ),
        now=BASE,
    )
    center.service.handle_node_message(
        node_id=node_id,
        envelope=Envelope(
            type="attempt.event",
            payload=AttemptEvent(ref=ref, seq=1, event_type="output.delta",
                                 text="a ledger").to_payload(),
        ),
        now=BASE,
    )
    return offer, {"node_id": node_id, "device_id": device_id,
                   "provider_id": provider_id,
                   "acceptance_hash": acceptance_hash, "ref": ref}


def test_a_revoked_device_key_cannot_settle_usage(center: _Center) -> None:
    """After ``admin revoke-key`` drops the device, its report buys nothing."""
    public_b64, private_b64 = generate_key_pair()
    center.mint("code-consumer")
    joined = center.join("code-consumer", public_key_b64=public_b64)
    node_result, device_private, device_key_id = _node_join(center)
    assert node_result.role == "node"

    consumer = Credential(
        tenant_id=joined.tenant_id, subject_id=joined.subject_id, role="consumer",
        account_id=joined.subject_id,
    )
    offer, facts = _drive_to_usage_final(
        center, device_key_id=device_key_id,
        node_token=str(node_result.node_token),
        consumer=consumer, consumer_key_id=joined.key_id,
        private_key=load_private_key(private_b64),
    )

    # Revoke the device key through the store, exactly as `admin revoke-key` does.
    center.store.revoke_identity(device_key_id, BASE)

    report = UsageReport(
        report_id=f"rep-{offer.attempt_id}",
        permit_id=offer.permit_hash,
        permit_hash=offer.permit_hash,
        acceptance_hash=facts["acceptance_hash"],
        attempt_id=offer.attempt_id,
        provider_id=facts["provider_id"],
        device_id=facts["device_id"],
        measurement=Measurement(
            measurement_id=f"m-{offer.attempt_id}", scope="upstream_call",
            semantics="terminal_total", counter_epoch="epoch_1", revision=1,
            usage=NormalizedUsage(input_total=800, output_total=200),
            attempt_id=offer.attempt_id,
        ),
        result_commitment=None,
        final_event_seq=2,
        outcome="completed",
        reported_at=BASE,
        key_id=device_key_id,
    ).sign(load_private_key(device_private), device_key_id)
    envelope = Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=facts["ref"], seq=2, event_type="usage.final",
            usage=NormalizedUsage(input_total=800, output_total=200),
            report={
                "schema": report.schema, "record_id": report.record_id,
                "revision": report.revision,
                "signed_at": report.signed_at.astimezone(dt.UTC).isoformat(),
                "signer_key_id": report.signer_key_id, "signer_id": report.signer_id,
                "signature": report.signature,
                "previous_record_hash": report.previous_record_hash,
                "payload": dict(report.payload),
            },
        ).to_payload(),
    )

    with pytest.raises(KeyRevokedError):
        center.service.handle_node_message(
            node_id=facts["node_id"], envelope=envelope, now=BASE
        )
    assert center.store.get_settlement("R-1", 1) is None

    # A restart must not resurrect the key: the store row, replayed by
    # `load_center`, is what the rebuilt center trusts.
    center_path = center.tmp_path / "center.json"
    center_path.write_text(
        json.dumps(
            {
                "host": "127.0.0.1",
                "port": 0,
                "database_path": str(center.tmp_path / "center.db"),
                "platform_id": "platform-1",
                "settlement_key_id": "settlement-key-1",
                "settlement_private_key_b64": center.keyring.private_b64["settlement-key-1"],
                "certfile": None,
                "keyfile": None,
                "credentials": [],
                "providers": [],
                "consumer_floats": [],
            }
        ),
        encoding="utf-8",
    )
    center.store.close()
    deployment = load_center(center_path)
    try:
        assert deployment.store.get_identity(device_key_id).revoked_at is not None
        with pytest.raises(KeyRevokedError):
            deployment.service.handle_node_message(
                node_id=facts["node_id"], envelope=envelope, now=BASE
            )
        assert deployment.store.get_settlement("R-1", 1) is None
    finally:
        deployment.store.close()


# --------------------------------------------------------------------------
# P2-1: nonce memory is per key
# --------------------------------------------------------------------------


def _auth_kwargs(private_key: Any, key_id: str, *, nonce: str) -> dict[str, Any]:
    """Build the keyword arguments ``authenticate_signed_request`` accepts."""
    issued_at = dt.datetime.now(dt.UTC)
    payload = request_auth_payload(
        method="GET", path="/v1/checkpoint", query="",
        body_digest=request_body_digest(None), key_id=key_id, issued_at=issued_at,
        nonce=nonce,
    )
    return {
        "payload": payload, "key_id": key_id, "issued_at": issued_at, "nonce": nonce,
        "signature_b64": sign_payload(DOMAIN_REQUEST_AUTH, payload, private_key),
    }


def test_flooding_one_key_does_not_evict_another_keys_nonce(center: _Center) -> None:
    """A busy key cannot push a quiet key's spent nonce out of the replay window."""
    first_public, first_private = generate_key_pair()
    second_public, second_private = generate_key_pair()
    center.mint("code-flood-a")
    center.mint("code-flood-b")
    first = center.join("code-flood-a", public_key_b64=first_public)
    second = center.join("code-flood-b", public_key_b64=second_public)

    first_nonce = "nonce-first-key"
    first_kwargs = _auth_kwargs(load_private_key(first_private), first.key_id, nonce=first_nonce)
    center.service.authenticate_signed_request(**first_kwargs)  # spends the nonce

    # Flood the *other* key's bucket past the capacity.
    capacity = 4096
    for index in range(capacity + 16):
        kwargs = _auth_kwargs(
            load_private_key(second_private), second.key_id, nonce=f"flood-{index}"
        )
        center.service.authenticate_signed_request(**kwargs)

    # The first key's spent nonce must still be refused.
    with pytest.raises(ProtocolError):
        center.service.authenticate_signed_request(**first_kwargs)
    assert second.key_id  # keeps the value used above from being lint-dead


# --------------------------------------------------------------------------
# P2-3: a failed join leaves no orphan registry key and burns no use
# --------------------------------------------------------------------------


def test_a_failed_join_rolls_back_the_registry_key(center: _Center, monkeypatch: Any) -> None:
    """If a later join step fails, the registered key must be pulled again."""
    public_b64, _private = generate_key_pair()
    center.mint("code-rollback")

    registered: list[str] = []
    original = center.keyring.registry.register_key

    def record(key_id: str, *args: Any, **kwargs: Any) -> Any:
        registered.append(key_id)
        return original(key_id, *args, **kwargs)

    monkeypatch.setattr(center.keyring.registry, "register_key", record)

    def boom(**_kwargs: Any) -> Any:
        raise ConflictError("simulated persistence failure")

    monkeypatch.setattr(center.store, "add_identity", boom)
    with pytest.raises(ConflictError):
        center.join("code-rollback", public_key_b64=public_b64)

    # No identity row survives, and the key registered mid-join was withdrawn
    # again, so nothing is left that could authenticate with no row behind it.
    assert registered, "the join should have registered a key before failing"
    assert center.store.identities() == []
    for key_id in registered:
        assert center.keyring.registry.get_key(key_id).status == "revoked"


def test_a_binding_conflict_does_not_burn_the_invite(center: _Center, monkeypatch: Any) -> None:
    """A registry binding conflict is decided before the invite is consumed."""
    public_b64, _private = generate_key_pair()
    center.mint("code-conflict")

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise IdentityBindingError("simulated binding conflict")

    monkeypatch.setattr(center.keyring.registry, "register_key", refuse)
    with pytest.raises(IdentityBindingError):
        center.join("code-conflict", public_key_b64=public_b64)

    assert center.store.get_invite("code-conflict").used_count == 0
    assert center.store.identities() == []


# --------------------------------------------------------------------------
# P2-4: register_key refuses a silent public-key change
# --------------------------------------------------------------------------


def test_register_key_refuses_a_same_owner_different_public_key(center: _Center) -> None:
    """Re-registering one key id with new material must not be a silent no-op."""
    first_public, _first = generate_key_pair()
    second_public, _second = generate_key_pair()
    center.keyring.registry.register_key("k-x", "owner-x", "consumer", first_public, BASE)
    # Identical material stays a no-op.
    center.keyring.registry.register_key("k-x", "owner-x", "consumer", first_public, BASE)
    with pytest.raises(IdentityBindingError):
        center.keyring.registry.register_key("k-x", "owner-x", "consumer", second_public, BASE)


# --------------------------------------------------------------------------
# P2-5: the operator purpose is gone
# --------------------------------------------------------------------------


def test_the_operator_purpose_is_removed() -> None:
    """No endpoint accepts ``operator``, so the purpose is not advertised."""
    import typing

    assert "operator" not in typing.get_args(KeyPurpose)


# --------------------------------------------------------------------------
# P0-1: an invited node holds the credential its own link needs
# --------------------------------------------------------------------------


def test_a_node_join_provisions_the_link_credential_it_returns(center: _Center) -> None:
    """The token a node join returns resolves to that node's credential.

    This is the seam the invite path was missing: ``join --node`` used to hand
    back an identity the node could not authenticate with, so the only working
    contributor route was an operator hand-writing ``credentials[]`` into
    center.json and restarting the center. The token is minted by the join,
    returned once, and stored as a digest only — the same contract an
    ``admin invite`` code and an operator-provisioned credential both have.
    """
    result, _device_private, _device_key_id = _node_join(center)

    assert result.node_token, "a first node join must return its link token"
    credential = center.store.resolve_credential(result.node_token, BASE)
    assert credential is not None
    assert credential.role == "node"
    assert credential.tenant_id == result.tenant_id
    assert credential.subject_id == result.subject_id

    # At rest there is only a digest, so losing the response loses the token —
    # which is why the recovery path is a revoke plus a fresh invite.
    blob = b"".join(
        path.read_bytes() for path in center.tmp_path.glob("center.db*") if path.is_file()
    )
    assert result.node_token.encode() not in blob


def test_a_node_credential_is_bound_to_the_device_the_join_derived(
    center: _Center,
) -> None:
    """The link credential names its device, which is what scopes a node's reads.

    A node join mints three rows: the node's identity, its contribution device,
    and the link credential the connector authenticates with. The credential used
    to share nothing with the device but a tenant, so a read scoped to "this
    node" could only be scoped to the tenant — and an operator who invites a
    community into one concrete ``--tenant`` would then have handed every member
    every other member's dispatch history. Recording the binding at the one
    moment the center knows it is what lets ``GET /v1/node/attempts`` derive its
    scope from the authenticated credential alone.
    """
    result, _device_private, _device_key_id = _node_join(center)

    credential = center.store.resolve_credential(str(result.node_token), BASE)
    assert credential is not None
    assert credential.device_id == result.device_id
    # The connector dials as its device, so the binding is the node id a scoped
    # read has to answer for — and only that one.
    assert center.service.node_attempts(credential=credential)["node_ids"] == [
        result.device_id
    ]


def test_a_consumer_join_provisions_no_node_credential(center: _Center) -> None:
    """A consumer must not acquire a credential that could open a node link."""
    public_b64, _private = generate_key_pair()
    center.mint("code-consumer-only")
    result = center.join("code-consumer-only", public_key_b64=public_b64)

    assert result.node_token is None
    assert "node_token" not in result.to_payload()


def test_rejoining_a_node_mints_no_second_credential(center: _Center) -> None:
    """Idempotency covers the token: one identity, one credential, one use."""
    node_public, _node_private = generate_key_pair()
    device_public, _device_private = generate_key_pair()
    center.mint("code-node-once", role="node")
    first = center.join(
        "code-node-once", public_key_b64=node_public,
        device={"public_key_b64": device_public},
    )
    second = center.join(
        "code-node-once", public_key_b64=node_public,
        device={"public_key_b64": device_public},
    )

    # The re-join names the same identity and cannot reproduce the plaintext.
    assert second.node_token is None
    assert (second.tenant_id, second.subject_id, second.key_id) == (
        first.tenant_id, first.subject_id, first.key_id
    )
    # The first token still resolves, and the invite was not spent twice.
    assert center.store.resolve_credential(str(first.node_token), BASE) is not None
    assert center.store.get_invite("code-node-once").used_count == 1


def test_the_provisioned_token_opens_a_node_link_and_receives_an_offer(
    center: _Center,
) -> None:
    """Handshake, then dispatch, authenticated by nothing but the join token.

    The socket-level form of the P0-1 acceptance (``join --node`` with zero token
    input, then ``share run``, then a routed ``ask``) lives in
    ``tests/test_contributor_wizard.py``. This pins the authorization property
    underneath it, at the level this module works at: the credential a join
    minted is accepted by ``register_node`` — which is what answers
    ``hello.ack`` — and a request admitted afterwards is offered to that node.
    No operator-provisioned credential is involved anywhere. The hello dials as
    the node id the credential is bound to (its device), the only one
    `register_node` accepts from a join-minted credential.
    """
    result, _device_private, device_key_id = _node_join(center)
    node_credential = center.store.resolve_credential(str(result.node_token), BASE)
    assert node_credential is not None
    device_row = center.store.get_identity(device_key_id)
    assert device_row is not None and device_row.provider_id is not None

    received: list[Envelope] = []
    center.service.register_node(
        credential=node_credential,
        hello=NodeHello(
            node_id=device_row.owner_id,
            device_id=device_row.owner_id,
            device_key_id=device_key_id,
            provider_id=device_row.provider_id,
            adapter_name="mock-adapter",
            model=MODEL,
            policy=NodePolicy(
                share_enabled=True, max_concurrency=2,
                max_local_reserved_milli_credits=20_000,
            ),
        ),
        enqueue=received.append,
        now=BASE,
    )
    assert [envelope.type for envelope in received] == ["hello.ack"]

    consumer_public, consumer_private = generate_key_pair()
    center.mint("code-consumer-for-node", quota=100_000)
    consumer = center.join("code-consumer-for-node", public_key_b64=consumer_public)
    center.service.admit_request(
        credential=Credential(
            tenant_id=consumer.tenant_id, subject_id=consumer.subject_id,
            role="consumer", account_id=consumer.subject_id,
        ),
        idempotency_key="idem-invited",
        messages=(user_message("hi"),),
        authorization=_authorization(
            load_private_key(consumer_private), consumer.key_id,
            request_id="R-invited", consumer_id=consumer.subject_id,
            payer_account_id=consumer.subject_id, messages=(user_message("hi"),),
        ),
        model=MODEL, max_charge_milli_credits=20_000, delivery_mode=DELIVERY,
        max_attempts=2, now=BASE,
    )

    offers = [
        AttemptOffer.from_payload(envelope.payload)
        for envelope in received
        if envelope.type == "attempt.offer"
    ]
    assert len(offers) == 1, [envelope.type for envelope in received]
    assert offers[0].resource_id == device_row.owner_id
    assert offers[0].model == MODEL
