"""G02 — an interrupted settlement leaves either a complete settlement or nothing.

What this file verifies (plan v0.3 §5.1 B G02)
------------------------------------------------
Settlement is the one place credit moves, so the durable boundary is where a
crash hurts. This file injects an interruption at each of the four writes that
used to be separate transactions — the acceptance of the event, the journal, the
settlement revision, and the receipt/log write — and then:

* proves the durable outcome is **all-or-nothing**: either a complete settlement
  (one leaf, one receipt, one settlement, one journal, for the same receipt hash
  and log index) or an untouched request (no leaf, no receipt, no journal, no
  credit moved). There is never an orphan receipt leaf and never a partial
  transfer;
* proves the **ACK only acknowledges work that finished**: an interruption
  between "the event row was written" and "the settlement committed" means no
  acknowledgement is sent, and a resend of the same ``usage.final`` is
  *re-ingested* rather than short-circuited as already-done — the resend settles
  the request exactly once;
* proves a **rejected usage report stays rejected on resend**: a report whose
  signature is not the offered device's, or whose acceptance hash does not match
  what the node accepted, is refused every time it is presented, and never
  settles, never moves credit and never becomes a receipt.

Each requirement is pinned by its own test, and every interruption point has its
own explicit assertions rather than one loose ``assert something failed``:

* `test_an_interruption_at_<boundary>_commits_nothing` (five boundaries) —
  parametrized over ``append_event``, ``_bundle_write_leaf``,
  ``_bundle_write_receipt``, ``_bundle_write_settlement`` and
  ``_bundle_write_journal``.
* `test_an_interruption_before_settlement_does_not_ack_the_usage` — the ACK
  semantics, stated as the durable facts the plain sequence number hides.
* `test_the_plain_sequence_number_alone_is_not_a_completion_marker` — a unit pin
  of the predicate that decides whether a replayed ``usage.final`` must be
  re-ingested, so the fix cannot silently regress.
* `test_a_rejected_usage_report_is_refused_every_time_it_is_resent` — the
  refusal is stable across resends.
* `test_a_lost_acknowledgement_after_a_commit_is_answered_from_durable_state` —
  the opposite direction: once the commit is durable, a resend is a pure ack and
  the log does not grow.
* `test_an_interrupted_settlement_survives_a_restart_as_an_untouched_request` —
  the recoverable state is durable, and after a rebuild the receipt (when one
  exists) still verifies.

What this file canNOT prove
---------------------------
* It does not inject a real process kill: the store is an ordinary object in one
  process, so the "interruption" is an exception raised from a named method. It
  exercises the transaction boundaries, not ``SIGKILL``, WAL recovery, or the OS.
* It does not make the offer/acceptance context survive a restart. When a
  settlement is interrupted and the server is then *rebuilt*, the resend can no
  longer settle (`GatewayError: no permit context`) and the request converges as
  unknown — see `test_an_interrupted_settlement_survives_a_restart_as_an_untouched_request`,
  which asserts that honestly rather than papering over it.
* It does not exercise two concurrent settlements for one request; the service
  serialises node messages under its own lock, so that race is out of reach here.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import json
import secrets
from pathlib import Path
from typing import Any

import pytest
from aipotluck.canonical import sign_payload
from aipotluck.errors import (
    GatewayError,
    ProtocolError,
    SettlementError,
)
from aipotluck.identity import generate_key_pair, load_private_key
from aipotluck.metering import Measurement, NormalizedUsage
from aipotluck.records import (
    DOMAIN_REQUEST_AUTH,
    SpendAuthorization,
    UsageReport,
    new_nonce,
    request_auth_payload,
    request_body_digest,
)
from aipotluck.transparency import InclusionProof, LogEntry, verify_inclusion
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

from aipotluck_server.deploy import load_server
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import Credential, ServerStore

BASE = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
MODEL = "coding-pool"
DELIVERY = "buffered_complete"

#: The five durable writes an interruption can land on. Each name is a method on
#: `ServerStore`; the first is the event-acceptance write and the rest are the
#: steps of the atomic settlement bundle.
BOUNDARIES = (
    "append_event",
    "_bundle_write_leaf",
    "_bundle_write_receipt",
    "_bundle_write_settlement",
    "_bundle_write_journal",
)


# --------------------------------------------------------------------------
# Wire-level helpers
# --------------------------------------------------------------------------


def _hello() -> NodeHello:
    """Build the opening message a well-formed contribution node sends."""
    return NodeHello(
        node_id="node-A",
        device_id="device-A",
        device_key_id="device-key-A",
        provider_id="provider-A",
        adapter_name="mock-adapter",
        model=MODEL,
        policy=NodePolicy(
            share_enabled=True, max_concurrency=2, max_local_reserved_milli_credits=0
        ),
    )


def _ref(offer: AttemptOffer) -> AttemptRef:
    """Return the wire reference for an offer."""
    return AttemptRef(
        request_id=offer.request_id, attempt_id=offer.attempt_id, epoch=offer.epoch
    )


def _accept(offer: AttemptOffer, acceptance_hash: str) -> Envelope:
    """Build the `attempt.accept` a node sends for an offer."""
    return Envelope(
        type="attempt.accept",
        payload=AttemptDecision(
            ref=_ref(offer),
            accepted=True,
            permit_hash=offer.permit_hash,
            acceptance_hash=acceptance_hash,
        ).to_payload(),
    )


def _delta(offer: AttemptOffer, seq: int, text: str) -> Envelope:
    """Build an `output.delta` event for an offer."""
    return Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=_ref(offer), seq=seq, event_type="output.delta", text=text
        ).to_payload(),
    )


def _signed_record_mapping(record: Any) -> dict[str, Any]:
    """Render a signed record the way the wire mapping carries it."""
    return {
        "schema": record.schema,
        "record_id": record.record_id,
        "revision": record.revision,
        "signed_at": record.signed_at.astimezone(dt.UTC).isoformat(),
        "signer_key_id": record.signer_key_id,
        "signer_id": record.signer_id,
        "signature": record.signature,
        "previous_record_hash": record.previous_record_hash,
        "payload": dict(record.payload),
    }


def _usage_envelope(
    keyring: Keyring,
    offer: AttemptOffer,
    *,
    acceptance_hash: str,
    signing_key_id: str = "device-key-A",
    claimed_device_id: str = "device-A",
    seq: int = 2,
    measured: tuple[int, int] = (800, 200),
) -> Envelope:
    """Build a `usage.final` event carrying a device-signed usage report.

    `signing_key_id` and `claimed_device_id` are separate so a test can present a
    report signed by a key the server did *not* offer the work to, which is the
    "wrong authority" refusal case.
    """
    report = UsageReport(
        report_id=f"rep-{offer.attempt_id}",
        permit_id=offer.permit_hash,
        permit_hash=offer.permit_hash,
        acceptance_hash=acceptance_hash,
        attempt_id=offer.attempt_id,
        provider_id="provider-A",
        device_id=claimed_device_id,
        measurement=Measurement(
            measurement_id=f"m-{offer.attempt_id}",
            scope="upstream_call",
            semantics="terminal_total",
            counter_epoch="epoch_1",
            revision=1,
            usage=NormalizedUsage(input_total=measured[0], output_total=measured[1]),
            attempt_id=offer.attempt_id,
        ),
        result_commitment=None,
        final_event_seq=seq,
        outcome="completed",
        reported_at=BASE,
        key_id=signing_key_id,
    ).sign(keyring.private[signing_key_id], signing_key_id)
    return Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=_ref(offer),
            seq=seq,
            event_type="usage.final",
            usage=NormalizedUsage(input_total=measured[0], output_total=measured[1]),
            report=_signed_record_mapping(report),
        ).to_payload(),
    )


def _auth_kwargs(private_key: Any, key_id: str) -> dict[str, Any]:
    """Build the keyword arguments `authenticate_signed_request` accepts."""
    payload = request_auth_payload(
        method="GET",
        path="/v1/requests/R-1",
        query="",
        body_digest=request_body_digest(None),
        key_id=key_id,
        issued_at=BASE,
        nonce=secrets.token_urlsafe(24),
    )
    return {
        "payload": payload,
        "key_id": key_id,
        "issued_at": BASE,
        "nonce": payload["nonce"],
        "signature_b64": sign_payload(DOMAIN_REQUEST_AUTH, payload, private_key),
    }


def _authorization(
    private_key: Any, key_id: str, *, request_id: str, messages: tuple[Any, ...]
) -> Any:
    """Sign a consumer spend authorization bound to `messages`/`MODEL`/`DELIVERY`."""
    return SpendAuthorization(
        authorization_id=f"auth-{request_id}",
        payer_account_id=key_id,
        consumer_id=key_id,
        request_id=request_id,
        request_digest=compute_request_digest(
            messages=messages, model=MODEL, delivery_mode=DELIVERY
        ),
        max_charge_milli_credits=20_000,
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
    ).sign(private_key, key_id)


# --------------------------------------------------------------------------
# The rig
# --------------------------------------------------------------------------


class _Rig:
    """A real `GatewayService` over a real store, driven to the settle boundary."""

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
        self.received: list[Envelope] = []
        self.joined_private: Any = None

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        """Close the store, as a process stop does."""
        self.store.close()

    def connect(self) -> None:
        """Register the node link."""
        self.service.register_node(
            credential=Credential(tenant_id="tenant-a", subject_id="node-A", role="node"),
            hello=_hello(),
            enqueue=self.received.append,
            now=BASE,
        )

    def join(self, code: str) -> Any:
        """Mint `code`, redeem it, and keep the generated private key."""
        self.store.add_invite(code, "consumer", "auto", max_uses=1, created_at=BASE)
        public_b64, private_b64 = generate_key_pair()
        result = self.service.join(
            invite_code=code,
            identity={"public_key_b64": public_b64, "display_name": None},
            device=None,
            server_url="http://server.test",
            now=BASE,
        )
        self.joined_private = load_private_key(private_b64)
        return result

    def credential(self) -> Credential:
        """Return the joined consumer's credential."""
        return self.service.authenticate_signed_request(
            **_auth_kwargs(self.joined_private, self.identity_key_id), now=BASE
        )

    # -- driving one attempt ------------------------------------------------

    def prepare(
        self, code: str, *, request_id: str, messages: tuple[Any, ...]
    ) -> tuple[Credential, AttemptOffer]:
        """Admit one request and drive it to the point a `usage.final` is due.

        Connects the node, joins the consumer, admits the request, records the
        node's acceptance and commits one output chunk. No usage has arrived yet,
        so the request is durable and live but unsettled — the state every
        interruption test starts from.
        """
        self.connect()
        joined = self.join(code)
        self.identity_key_id = joined.key_id
        credential = self.credential()
        self.service.admit_request(
            credential=credential,
            idempotency_key=f"idem-{request_id}",
            messages=messages,
            authorization=_authorization(
                self.joined_private, joined.key_id, request_id=request_id, messages=messages
            ),
            model=MODEL,
            max_charge_milli_credits=20_000,
            delivery_mode=DELIVERY,
            max_attempts=2,
            now=BASE,
        )
        offer = next(
            AttemptOffer.from_payload(envelope.payload)
            for envelope in self.received
            if envelope.type == "attempt.offer"
        )
        acceptance = compute_acceptance_hash(
            permit_hash=offer.permit_hash,
            request_id=offer.request_id,
            attempt_id=offer.attempt_id,
            epoch=offer.epoch,
            adapter_name="mock-adapter",
            accepted_at=BASE,
        )
        self.service.handle_node_message(
            node_id="node-A", envelope=_accept(offer, acceptance), now=BASE
        )
        self.service.handle_node_message(
            node_id="node-A", envelope=_delta(offer, 1, "a ledger"), now=BASE
        )
        self.acceptance = acceptance
        self.credential_obj = credential
        return credential, offer

    def deliver(self, envelope: Envelope) -> list[Envelope]:
        """Hand one message to the service."""
        return self.service.handle_node_message(
            node_id="node-A", envelope=envelope, now=BASE
        )

    # -- restart ------------------------------------------------------------

    def write_server_json(self) -> Path:
        """Write a `server.json` naming only the settlement and device keys."""
        path = self.tmp_path / "server.json"
        path.write_text(
            json.dumps(
                {
                    "host": "127.0.0.1",
                    "port": 0,
                    "database_path": str(self.tmp_path / "server.db"),
                    "platform_id": "platform-1",
                    "settlement_key_id": "settlement-key-1",
                    "settlement_private_key_b64": self.keyring.private_b64[
                        "settlement-key-1"
                    ],
                    "certfile": None,
                    "keyfile": None,
                    "credentials": [],
                    "providers": [
                        {
                            "device_id": "device-A",
                            "device_key_id": "device-key-A",
                            "provider_id": "provider-A",
                            "public_key_b64": self.keyring.public["device-key-A"],
                            "demo_float_milli_credits": 0,
                        }
                    ],
                    "consumer_floats": [],
                }
            ),
            encoding="utf-8",
        )
        return path

    def rebuild(self) -> Any:
        """Close the store and return a fresh deployment over the same database."""
        self.close()
        return load_server(self.write_server_json())


@pytest.fixture
def rig(tmp_path: Path) -> _Rig:
    """Return a rig over a fresh store, closed at the end of the test."""
    built = _Rig(tmp_path)
    try:
        yield built
    finally:
        built.close()


# --------------------------------------------------------------------------
# Invariant helpers
# --------------------------------------------------------------------------


def _journals(store: ServerStore) -> list[dict[str, Any]]:
    """Return every ledger-replay journal payload, in order."""
    return [payload for _seq, kind, payload in store.ledger_events() if kind == "journal"]


def _assert_no_orphans(store: ServerStore, request_id: str) -> None:
    """A leaf, a receipt, a settlement and a journal exist together, or not at all."""
    leaves = store.log_leaves()
    settlement = store.get_settlement(request_id, 1)
    journals = _journals(store)
    if settlement is None:
        assert leaves == [], f"orphan log leaf with no settlement: {leaves}"
        assert journals == [], f"orphan journal with no settlement: {journals}"
        return
    assert len(leaves) == 1
    assert leaves[0].log_index == settlement.log_index
    assert leaves[0].receipt_hash == settlement.receipt_hash
    receipt = store.get_receipt(settlement.receipt_id)
    assert receipt is not None, "a settlement must always have its receipt"
    assert receipt.receipt_hash == settlement.receipt_hash
    assert receipt.log_index == settlement.log_index
    assert len(journals) == 1


def _assert_untouched(rig: _Rig, request_id: str, attempt_id: str) -> None:
    """The request settled nothing: no credit, no leaf, no receipt, no usage."""
    store = rig.store
    assert store.log_size() == 0
    assert store.get_settlement(request_id, 1) is None
    assert _journals(store) == []
    assert rig.service.balance("provider-A/pending") == 0
    assert rig.service.engine.ledger.total_supply() == 20_000
    assert rig.service.balance(rig.credential_obj.subject_id) == 20_000
    attempt = store.get_attempt(attempt_id)
    assert attempt is not None
    assert attempt.usage_status != "COMPLETE"
    assert attempt.usage_tokens is None
    assert rig.service.request_status(
        credential=rig.credential_obj, request_id=request_id
    )["settlement"] is None
    _assert_no_orphans(store, request_id)


def _assert_settled_once(rig: _Rig, request_id: str, attempt_id: str) -> dict[str, Any]:
    """The request settled exactly once, with one leaf, receipt and journal."""
    store = rig.store
    assert store.log_size() == 1
    settlement = store.get_settlement(request_id, 1)
    assert settlement is not None
    assert settlement.log_index == 0
    assert store.get_receipt(settlement.receipt_id) is not None
    assert len(_journals(store)) == 1
    assert rig.service.balance("provider-A/pending") == 1_000
    assert rig.service.balance(rig.credential_obj.subject_id) == 19_000
    attempt = store.get_attempt(attempt_id)
    assert attempt is not None
    assert attempt.usage_status == "COMPLETE"
    assert attempt.usage_tokens == 1_000
    _assert_no_orphans(store, request_id)
    document = rig.service.request_status(
        credential=rig.credential_obj, request_id=request_id
    )
    assert document["status"] == "SUCCEEDED"
    return document["settlement"]


@contextlib.contextmanager
def _interrupt_at(store: ServerStore, method: str):
    """Make one durable write raise, as an interruption at that boundary does."""
    from unittest import mock

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError(f"injected interruption at {method}")

    with mock.patch.object(store, method, boom):
        yield


# --------------------------------------------------------------------------
# The four (five) write boundaries: all-or-nothing
# --------------------------------------------------------------------------


@pytest.mark.parametrize("boundary", BOUNDARIES)
def test_an_interruption_at_a_durable_write_commits_nothing(
    rig: _Rig, boundary: str
) -> None:
    """An interruption at any settlement write leaves the request untouched.

    The event-acceptance write and the four steps of the settlement bundle are
    each broken in turn. Because the settlement commits in one transaction, every
    one of them must leave *no* durable trace of the attempt to settle and no
    credit moved — the state a rebuild reads back is "this request is still
    live and unsettled", never a half-written settlement.
    """
    credential, offer = rig.prepare(
        "code-bd", request_id="req-1", messages=(user_message("interrupted"),)
    )
    usage = _usage_envelope(rig.keyring, offer, acceptance_hash=rig.acceptance)

    with _interrupt_at(rig.store, boundary), pytest.raises(RuntimeError, match=boundary):
        rig.deliver(usage)

    # No acknowledgement was produced, so a real node would resend; and nothing
    # durable was committed, so there is nothing to contradict the resend.
    _assert_untouched(rig, "req-1", offer.attempt_id)

    # The resend, once the interruption is over, settles the request exactly once.
    replies = rig.deliver(usage)
    assert [reply.type for reply in replies] == ["event.ack"]
    assert replies[0].payload["acked_seq"] == 2
    settlement = _assert_settled_once(rig, "req-1", offer.attempt_id)

    # Rebuilding from persistence reproduces the same single settlement, and its
    # receipt still proves inclusion — the durable log is not merely present, it
    # is consistent.
    deployment = rig.rebuild()
    try:
        assert deployment.store.log_size() == 1
        stored = deployment.store.get_settlement("req-1", 1)
        assert stored is not None
        assert stored.receipt_id == settlement["receipt_id"]
        assert stored.receipt_hash == settlement["receipt_hash"]
        assert deployment.service.balance("provider-A/pending") == 1_000
        proof = deployment.service.log.inclusion_proof(stored.log_index)
        leaf_row = deployment.store.log_leaves()[0]
        leaf = LogEntry(
            index=leaf_row.log_index,
            receipt_hash=leaf_row.receipt_hash,
            committed_at=leaf_row.committed_at,
        )
        assert verify_inclusion(proof, leaf.leaf_bytes())
        assert isinstance(proof, InclusionProof)
    finally:
        deployment.store.close()
    assert credential.subject_id


# --------------------------------------------------------------------------
# ACK semantics: an acknowledgement must not outrun the durable work
# --------------------------------------------------------------------------


def test_an_interruption_before_settlement_does_not_ack_the_usage(rig: _Rig) -> None:
    """A usage acknowledged only on the sequence number would be lost forever.

    The event row is written *before* the usage is ingested, so an interruption
    in between leaves ``last_attempt_seq`` already past the ``usage.final`` while
    the request is unsettled. No acknowledgement is sent — the interruption
    propagates — and the resend must therefore be re-ingested and settle the
    request, rather than being short-circuited as "already done".
    """
    _credential, offer = rig.prepare(
        "code-ack", request_id="req-1", messages=(user_message("acked?"),)
    )
    usage = _usage_envelope(rig.keyring, offer, acceptance_hash=rig.acceptance)

    with _interrupt_at(rig.store, "record_settlement_bundle"), pytest.raises(
        RuntimeError, match="record_settlement_bundle"
    ):
        rig.deliver(usage)

    # The durable sequence number says "everything up to 2 arrived", yet nothing
    # was settled: this is exactly the state a plain `event.seq <= acked` check
    # would have declared complete.
    assert rig.store.last_attempt_seq(offer.attempt_id) == 2
    assert rig.store.get_settlement("req-1", 1) is None
    assert rig.service.balance("provider-A/pending") == 0
    _assert_untouched(rig, "req-1", offer.attempt_id)

    # The resend is re-ingested, not acknowledged away: it settles exactly once.
    replies = rig.deliver(usage)
    assert [reply.type for reply in replies] == ["event.ack"]
    _assert_settled_once(rig, "req-1", offer.attempt_id)


def test_the_plain_sequence_number_alone_is_not_a_completion_marker(rig: _Rig) -> None:
    """A unit pin of the predicate that decides whether a replay must be re-ingested.

    Reconstructs the durable state an interruption leaves — the event row on
    file, no settlement, usage not final — and asserts the service now answers
    "re-ingest" for it, while still answering "already done" once the usage is
    truly final. This is the regression guard for the ACK fix: a later change
    that restores the bare ``event.seq <= acked`` short-circuit fails here.
    """
    _credential, offer = rig.prepare(
        "code-pred", request_id="req-1", messages=(user_message("predicate"),)
    )
    usage = _usage_envelope(rig.keyring, offer, acceptance_hash=rig.acceptance)
    event = AttemptEvent.from_payload(usage.payload)

    with _interrupt_at(rig.store, "record_settlement_bundle"), pytest.raises(RuntimeError):
        rig.deliver(usage)

    attempt = rig.store.get_attempt(offer.attempt_id)
    assert attempt is not None
    assert rig.store.last_attempt_seq(offer.attempt_id) == 2
    assert rig.service._usage_final_needs_ingest(event, attempt) is True

    # Once it settles, the same event is final and the replay short-circuits.
    rig.deliver(usage)
    settled_attempt = rig.store.get_attempt(offer.attempt_id)
    assert settled_attempt is not None
    assert settled_attempt.usage_status == "COMPLETE"
    assert rig.service._usage_final_needs_ingest(event, settled_attempt) is False


def test_a_lost_acknowledgement_after_a_commit_is_answered_from_durable_state(
    rig: _Rig,
) -> None:
    """The opposite direction: a resend after a *successful* commit changes nothing.

    Once the settlement is durable, the resend is a pure acknowledgement — no
    second leaf, no second receipt, no second debit — which is what makes
    "at-least-once delivery, exactly-once settlement" hold.
    """
    _credential, offer = rig.prepare(
        "code-lost", request_id="req-1", messages=(user_message("lost ack"),)
    )
    usage = _usage_envelope(rig.keyring, offer, acceptance_hash=rig.acceptance)
    rig.deliver(usage)
    first = _assert_settled_once(rig, "req-1", offer.attempt_id)

    replies = rig.deliver(usage)
    assert [reply.type for reply in replies] == ["event.ack"]
    assert replies[0].payload["acked_seq"] == 2
    second = _assert_settled_once(rig, "req-1", offer.attempt_id)
    assert second == first


def test_an_interrupted_settlement_survives_a_restart_as_an_untouched_request(
    rig: _Rig,
) -> None:
    """The recoverable state is durable, and a rebuild reads it back intact.

    After an interruption at the settlement write and a rebuild, the database
    must not contain a leaf, a receipt or a journal for a request that never
    settled. The honest consequence is then pinned too: the rebuilt server has
    lost the offer terms (G01·f), so a resent ``usage.final`` is refused with
    "no permit context" rather than settled — the request converges as unknown
    through the recovery path, not by silently completing.
    """
    _credential, offer = rig.prepare(
        "code-restart", request_id="req-1", messages=(user_message("durable?"),)
    )
    usage = _usage_envelope(rig.keyring, offer, acceptance_hash=rig.acceptance)

    with _interrupt_at(rig.store, "_bundle_write_settlement"), pytest.raises(RuntimeError):
        rig.deliver(usage)

    deployment = rig.rebuild()
    try:
        assert deployment.store.log_size() == 0
        assert deployment.store.get_settlement("req-1", 1) is None
        assert _journals(deployment.store) == []
        attempt = deployment.store.get_attempt(offer.attempt_id)
        assert attempt is not None
        assert attempt.usage_status != "COMPLETE"
        assert attempt.usage_tokens is None
        # No credit moved, so the rebuilt books agree with the durable log.
        assert deployment.service.balance("provider-A/pending") == 0
        assert deployment.service.balance(_credential.subject_id) == 20_000

        # The permit context did not survive the restart, so the resend cannot
        # settle; it is refused, and the refusal leaves no fabricated usage.
        with pytest.raises(GatewayError, match="no permit context"):
            deployment.service.handle_node_message(
                node_id="node-A", envelope=usage, now=BASE
            )
        after = deployment.store.get_attempt(offer.attempt_id)
        assert after is not None
        assert after.usage_status != "COMPLETE"
        assert after.usage_tokens is None
        assert deployment.store.get_settlement("req-1", 1) is None
        assert deployment.store.log_size() == 0
    finally:
        deployment.store.close()


# --------------------------------------------------------------------------
# A rejected usage report must stay rejected
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("case", "signing_key_id", "claimed_device_id", "acceptance_override", "expected"),
    (
        ("wrong-signing-key", "device-key-B", "device-A", None, SettlementError),
        (
            "wrong-acceptance-hash",
            "device-key-A",
            "device-A",
            "not-the-acceptance",
            ProtocolError,
        ),
    ),
)
def test_a_rejected_usage_report_is_refused_every_time_it_is_resent(
    rig: _Rig,
    case: str,
    signing_key_id: str,
    claimed_device_id: str,
    acceptance_override: str | None,
    expected: type[BaseException],
) -> None:
    """A refused report never becomes a success by being sent again.

    Two refusals are pinned: a report signed by a device the server never
    offered the work to (identity binding), and a report whose acceptance hash
    is not the one the node returned. Both are refused on the first delivery and
    on the resend, and neither moves credit nor leaves a receipt.
    """
    _credential, offer = rig.prepare(
        f"code-{case}", request_id="req-1", messages=(user_message(case),)
    )
    usage = _usage_envelope(
        rig.keyring,
        offer,
        acceptance_hash=acceptance_override or rig.acceptance,
        signing_key_id=signing_key_id,
        claimed_device_id=claimed_device_id,
    )

    with pytest.raises(expected):
        rig.deliver(usage)
    after_first = _assert_untouched_but_arrival_journalled(rig, "req-1", offer.attempt_id)

    with pytest.raises(expected):
        rig.deliver(usage)
    after_second = _assert_untouched_but_arrival_journalled(rig, "req-1", offer.attempt_id)
    assert after_second == after_first
    assert rig.service.balance("provider-A/pending") == 0
    assert rig.store.log_size() == 0


def _assert_untouched_but_arrival_journalled(
    rig: _Rig, request_id: str, attempt_id: str
) -> tuple[str, int | None, int]:
    """Assert nothing settled, and return the durable facts for a repeat check.

    A refused report is journalled on arrival by design (`_on_event` archives the
    event before it validates the report) and only the settlement is withheld.
    The interesting facts are therefore that no usage became final and no receipt
    exists — not that the event row is absent.
    """
    store = rig.store
    assert store.get_settlement(request_id, 1) is None
    assert store.log_size() == 0
    assert _journals(store) == []
    attempt = store.get_attempt(attempt_id)
    assert attempt is not None
    assert attempt.usage_status != "COMPLETE"
    assert attempt.usage_tokens is None
    _assert_no_orphans(store, request_id)
    return (attempt.usage_status, attempt.usage_tokens, store.log_size())
