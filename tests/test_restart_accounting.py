"""G01 — the center restarts and its accounts, receipts and identities survive.

What this file verifies (plan v0.3 §5.1 B G01)
------------------------------------------------
The headline claim is that the center can be **closed and rebuilt from its
SQLite file alone**: after a first center settles a request, a second center is
built by `load_center` over the very same database — with a *fresh*
`IdentityRegistry` and a *rebuilt* ledger, never the old in-memory objects — and
it can still read the old receipt (with a verifiable inclusion proof), reconcile
a request that was in flight when the center stopped, and settle a brand-new
request without colliding with the receipt the first run issued.

Each requirement is pinned by its own test:

* **G01·a** the account-creation replay is complete: a ledger rebuilt from the
  durable replay log is *entry-for-entry* equal to the ledger that was live
  before the restart, including the provider's ``<provider>/pending`` account —
  the case that once failed with a cold `KeyError` because the provider
  account's creation event was replayed without its ``account_kind``.
* **G01·a(fail-closed)** a replay-log row that names no account kind is refused
  with a domain error the rebuild can name, not with a bare ``KeyError``.
* **G01·b** receipt ids are unique across a restart: the rebuilt engine continues
  its numbering instead of starting again, so a new settlement gets a new
  receipt and a new log leaf, while re-reporting the *old* request's usage after
  the restart is a pure no-op.
* **G01·c** total supply is conserved across the restart and the old receipt is
  still readable with an inclusion proof that folds back to the stored root.
* **G01·d** an invited (dynamically registered) identity still authenticates
  after the restart, because `load_center` replays the ``identities`` rows and
  the one-time invite quota is not minted twice.
* **G01·e** an in-flight request — accepted and with output committed, but with
  no final usage — survives as durable rows and is handled after the restart by
  asking the node what happened and recording the outcome as **unknown**, never
  as a settled success and never as zero usage.
* **G01·f** the permit/acceptance context is **in-memory only** and is pinned as
  such: after a restart the offer terms and the node's acceptance are gone, so a
  late acceptance or a late usage report is *refused* rather than trusted. This
  is a documented limitation, not a passing grade.

What this file canNOT prove
---------------------------
* It does not prove the center is crash-safe *during* a settlement write — that
  is G02's territory (`tests/test_settlement_interruption.py`).
* It does not prove anything about a real process restart: the store is closed
  and reopened in one process, so only the *durable* boundary is exercised, not
  socket teardown, worker threads, or the OS.
* It does not make permit/acceptance durable. The tests assert the honest
  post-restart refusal; they do not claim a late report can be completed.
* It relies on `load_center` as the rebuild entry point, so it pins that path
  (config provisioning + identity replay + ledger replay) and not a bespoke one.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
from pathlib import Path
from typing import Any

import pytest
from aipotluck.canonical import canonical_digest, sign_payload
from aipotluck.errors import GatewayError, PotluckError
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
    AttemptState,
    Envelope,
    NodeHello,
    NodePolicy,
    compute_acceptance_hash,
)
from conftest import Keyring

from aipotluck_server.deploy import load_center
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import CenterStore, Credential

#: The instant every test works from. It sits inside an authorization's validity
#: window and after every key's registration time, so no test depends on the
#: wall clock.
BASE = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
MODEL = "coding-pool"
DELIVERY = "buffered_complete"
#: Past the 10s offer-accept timeout, so `tick` treats a silent attempt as stuck.
QUIET = BASE + dt.timedelta(seconds=11)


# --------------------------------------------------------------------------
# Wire-level helpers (one node, one consumer, one attempt per request)
# --------------------------------------------------------------------------


def _hello(*, model: str = MODEL) -> NodeHello:
    """Build the opening message a well-formed contribution node sends."""
    return NodeHello(
        node_id="node-A",
        device_id="device-A",
        device_key_id="device-key-A",
        provider_id="provider-A",
        adapter_name="mock-adapter",
        model=model,
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


def _usage_event(
    keyring: Keyring,
    *,
    request_id: str,
    attempt_id: str,
    epoch: int,
    permit_hash: str,
    acceptance_hash: str,
    seq: int = 2,
    measured: tuple[int, int] = (800, 200),
) -> Envelope:
    """Build a `usage.final` event carrying a device-signed usage report."""
    report = UsageReport(
        report_id=f"rep-{attempt_id}",
        permit_id=permit_hash,
        permit_hash=permit_hash,
        acceptance_hash=acceptance_hash,
        attempt_id=attempt_id,
        provider_id="provider-A",
        device_id="device-A",
        measurement=Measurement(
            measurement_id=f"m-{attempt_id}",
            scope="upstream_call",
            semantics="terminal_total",
            counter_epoch="epoch_1",
            revision=1,
            usage=NormalizedUsage(input_total=measured[0], output_total=measured[1]),
            attempt_id=attempt_id,
        ),
        result_commitment=None,
        final_event_seq=seq,
        outcome="completed",
        reported_at=BASE,
        key_id="device-key-A",
    ).sign(keyring.private["device-key-A"], "device-key-A")
    return Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=AttemptRef(request_id=request_id, attempt_id=attempt_id, epoch=epoch),
            seq=seq,
            event_type="usage.final",
            usage=NormalizedUsage(input_total=measured[0], output_total=measured[1]),
            report=_signed_record_mapping(report),
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


def _auth_kwargs(
    private_key: Any, key_id: str, *, issued_at: dt.datetime = BASE
) -> dict[str, Any]:
    """Build the keyword arguments `authenticate_signed_request` accepts."""
    payload = request_auth_payload(
        method="GET",
        path="/v1/requests/R-1",
        query="",
        body_digest=request_body_digest(None),
        key_id=key_id,
        issued_at=issued_at,
        nonce=secrets.token_urlsafe(24),
    )
    return {
        "payload": payload,
        "key_id": key_id,
        "issued_at": issued_at,
        "nonce": payload["nonce"],
        "signature_b64": sign_payload(DOMAIN_REQUEST_AUTH, payload, private_key),
    }


def _authorization(
    private_key: Any,
    key_id: str,
    *,
    request_id: str,
    consumer_id: str,
    prompt: str,
) -> Any:
    """Sign a consumer spend authorization bound to `prompt`/`MODEL`/`DELIVERY`."""
    record = SpendAuthorization(
        authorization_id=f"auth-{request_id}",
        payer_account_id=consumer_id,
        consumer_id=consumer_id,
        request_id=request_id,
        request_digest=canonical_digest(
            {"prompt": prompt, "model": MODEL, "delivery_mode": DELIVERY}
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
    )
    return record.sign(private_key, key_id)


# --------------------------------------------------------------------------
# The center under test
# --------------------------------------------------------------------------


class Center:
    """A real `GatewayService` over a real SQLite file, without an injected ledger.

    The ledger is deliberately *not* injected: the service rebuilds it from the
    (initially empty) replay log and every later funding goes through
    `fund_account`, which journals an ``issue`` event. A service built over the
    same database therefore reproduces the very same books from the log alone,
    which is the property every restart test here rests on.
    """

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.keyring = Keyring()
        self.registry = self.keyring.registry
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
            config=self.config, store=self.store, registry=self.registry, now=BASE
        )
        self.received: list[Envelope] = []
        self.joined_private: Any = None

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        """Close the store, as a process stop does."""
        self.store.close()

    def connect(self) -> None:
        """Register the node link, appending everything the center sends to `received`."""
        self.service.register_node(
            credential=Credential(tenant_id="tenant-a", subject_id="node-A", role="node"),
            hello=_hello(),
            enqueue=self.received.append,
            now=BASE,
        )

    def mint(self, code: str) -> None:
        """Register a single-use consumer invite with the default quota."""
        self.store.add_invite(code, "consumer", "auto", max_uses=1, created_at=BASE)

    def join(self, code: str) -> Any:
        """Mint `code` if needed, redeem it, and keep the private key for signing."""
        self.mint(code)
        public_b64, private_b64 = generate_key_pair()
        result = self.service.join(
            invite_code=code,
            identity={"public_key_b64": public_b64, "display_name": None},
            device=None,
            center_url="http://center.test",
            now=BASE,
        )
        self.joined_private = load_private_key(private_b64)
        return result

    def authenticate(self, service: GatewayService, key_id: str) -> Credential:
        """Authenticate the joined key against `service`."""
        return service.authenticate_signed_request(
            **_auth_kwargs(self.joined_private, key_id), now=BASE
        )

    # -- driving one request ------------------------------------------------

    def offers_for(self, node_id: str = "node-A") -> list[AttemptOffer]:
        """Return the offers delivered to `node_id`, oldest first."""
        return [
            AttemptOffer.from_payload(envelope.payload)
            for envelope in self.received
            if envelope.type == "attempt.offer"
        ]

    def admit(
        self,
        service: GatewayService,
        credential: Credential,
        *,
        request_id: str,
        prompt: str,
    ) -> AttemptOffer:
        """Admit one request and return the offer it produced."""
        self.received.clear()
        service.admit_request(
            credential=credential,
            idempotency_key=f"idem-{request_id}",
            prompt=prompt,
            authorization=_authorization(
                self.joined_private,
                credential.subject_id,
                request_id=request_id,
                consumer_id=credential.subject_id,
                prompt=prompt,
            ),
            model=MODEL,
            max_charge_milli_credits=20_000,
            delivery_mode=DELIVERY,
            max_attempts=2,
            now=BASE,
        )
        return self.offers_for()[-1]

    def accept(
        self, service: GatewayService, offer: AttemptOffer, acceptance_hash: str
    ) -> None:
        """Record the node's acceptance of `offer` through `service`."""
        service.handle_node_message(
            node_id="node-A", envelope=_accept(offer, acceptance_hash), now=BASE
        )

    def settle(
        self,
        service: GatewayService,
        credential: Credential,
        *,
        request_id: str,
        prompt: str,
        measured: tuple[int, int] = (800, 200),
    ) -> tuple[AttemptOffer, str, dict[str, Any]]:
        """Drive one request to full settlement; return `(offer, acceptance, status)`."""
        offer = self.admit(service, credential, request_id=request_id, prompt=prompt)
        acceptance = self.acceptance_hash(offer)
        self.accept(service, offer, acceptance)
        service.handle_node_message(
            node_id="node-A", envelope=_delta(offer, 1, "a ledger"), now=BASE
        )
        service.handle_node_message(
            node_id="node-A",
            envelope=_usage_event(
                self.keyring,
                request_id=offer.request_id,
                attempt_id=offer.attempt_id,
                epoch=offer.epoch,
                permit_hash=offer.permit_hash,
                acceptance_hash=acceptance,
                measured=measured,
            ),
            now=BASE,
        )
        return (
            offer,
            acceptance,
            service.request_status(credential=credential, request_id=request_id),
        )

    @staticmethod
    def acceptance_hash(offer: AttemptOffer) -> str:
        """Return the acceptance hash the node computes for `offer`."""
        return compute_acceptance_hash(
            permit_hash=offer.permit_hash,
            request_id=offer.request_id,
            attempt_id=offer.attempt_id,
            epoch=offer.epoch,
            adapter_name="mock-adapter",
            accepted_at=BASE,
        )

    # -- restart ------------------------------------------------------------

    def write_center_json(self) -> Path:
        """Write a `center.json` naming only the settlement and device keys.

        The invited consumer is deliberately absent: it exists nowhere but the
        ``identities`` table, so a rebuilt center can only know it by replaying
        the store.
        """
        path = self.tmp_path / "center.json"
        path.write_text(
            json.dumps(
                {
                    "host": "127.0.0.1",
                    "port": 0,
                    "database_path": str(self.tmp_path / "center.db"),
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
        return load_center(self.write_center_json())


@pytest.fixture
def center(tmp_path: Path) -> Center:
    """Return a center over a fresh store, closed at the end of the test."""
    built = Center(tmp_path)
    try:
        yield built
    finally:
        built.close()


# --------------------------------------------------------------------------
# G01·a + G01·c: the rebuilt ledger replays the durable log entry for entry
# --------------------------------------------------------------------------


def test_a_rebuilt_ledger_replays_the_log_entry_for_entry(center: Center) -> None:
    """A second center's books equal the first's, built from the log alone.

    This is the account-creation-completeness requirement, including the
    provider ``<provider>/pending`` account whose creation event must carry its
    ``account_kind`` or the rebuild cannot interpret it.
    """
    center.connect()
    joined = center.join("code-a")
    credential = center.authenticate(center.service, joined.key_id)
    _offer, _acceptance, document = center.settle(
        center.service, credential, request_id="req-1", prompt="first answer"
    )
    assert document["status"] == "SUCCEEDED"

    # The durable log must explain the provider account it opened, or a rebuild
    # has nothing to open it from. This is the regression the G01 write-up names.
    account_events = [
        payload
        for _seq, kind, payload in center.store.ledger_events()
        if kind == "account"
    ]
    assert account_events == [
        {"account_id": "provider-A/pending", "account_kind": "provider_pending"}
    ], "the provider account's creation event must record its account_kind"

    before_journals = [
        (journal.journal_id, journal.postings, journal.kind)
        for journal in center.service.engine.ledger.journals()
    ]
    before_supply = center.service.engine.ledger.total_supply()
    before_provider = center.service.balance("provider-A/pending")
    before_consumer = center.service.balance(credential.subject_id)
    old_ledger_id = id(center.service.engine.ledger)
    old_registry_id = id(center.registry)
    # A key that exists only in the running registry, never in the store: a
    # rebuilt center must not know it.
    center.registry.register_key(
        "throwaway-key", "throwaway", "consumer", generate_key_pair()[0], BASE
    )

    deployment = center.rebuild()
    try:
        rebuilt = deployment.service
        assert id(rebuilt.engine.ledger) != old_ledger_id, (
            "the old ledger object must not be reused"
        )
        assert id(rebuilt._registry) != old_registry_id, (
            "the old registry must not be reused"
        )
        with pytest.raises(PotluckError):
            rebuilt._registry.get_key("throwaway-key")

        after_journals = [
            (journal.journal_id, journal.postings, journal.kind)
            for journal in rebuilt.engine.ledger.journals()
        ]
        assert after_journals == before_journals, (
            "the replayed books must match entry for entry"
        )
        assert rebuilt.engine.ledger.total_supply() == before_supply
        assert rebuilt.balance("provider-A/pending") == before_provider == 1_000
        assert rebuilt.balance(credential.subject_id) == before_consumer == 19_000
    finally:
        deployment.store.close()


def test_a_log_row_missing_account_kind_fails_closed(center: Center) -> None:
    """A malformed replay row is refused with a domain error, not a ``KeyError``.

    A row an older build could have written — an issuance whose payload carries
    no ``account_kind`` — must fail as a `GatewayError` this build can name,
    because a bare ``KeyError`` escaping the rebuild would be indistinguishable
    from a bug in the reader.
    """
    center.store.append_ledger_event(
        "issue", {"account_id": "provider-A/pending", "amount": 5}, at=BASE
    )
    with pytest.raises(GatewayError, match="unknown account kind"):
        GatewayService(
            config=center.config,
            store=center.store,
            registry=center.registry,
            now=BASE,
        )


# --------------------------------------------------------------------------
# G01·b: receipt ids stay unique and a settled request never double-settles
# --------------------------------------------------------------------------


def test_receipt_ids_are_unique_across_a_restart(center: Center) -> None:
    """The rebuilt engine continues its numbering and never reissues an id."""
    center.connect()
    joined = center.join("code-b")
    credential = center.authenticate(center.service, joined.key_id)
    offer, acceptance, document = center.settle(
        center.service, credential, request_id="req-1", prompt="first answer"
    )
    first = document["settlement"]
    assert first["log_index"] == 0
    assert center.service.balance("provider-A/pending") == 1_000

    deployment = center.rebuild()
    try:
        rebuilt = deployment.service
        rebuilt_credential = rebuilt.authenticate_signed_request(
            **_auth_kwargs(center.joined_private, joined.key_id), now=BASE
        )
        # The node link is re-established (its callback lived only in memory).
        rebuilt.register_node(
            credential=Credential(tenant_id="tenant-a", subject_id="node-A", role="node"),
            hello=_hello(),
            enqueue=center.received.append,
            now=BASE,
        )

        # Re-reporting the OLD request's usage must be a pure no-op: the receipt
        # already exists and the log must not grow a second leaf for it. The
        # permit hash on the replay is irrelevant there — the event is answered
        # from durable state before any report field is read.
        stored = deployment.store.attempts_for_request("req-1")[0]
        assert stored.settlement_status == "SETTLED"
        replies = rebuilt.handle_node_message(
            node_id="node-A",
            envelope=_usage_event(
                center.keyring,
                request_id="req-1",
                attempt_id=stored.attempt_id,
                epoch=stored.dispatch_epoch,
                permit_hash="unused-on-a-settled-replay",
                acceptance_hash=acceptance,
            ),
            now=BASE,
        )
        assert [reply.type for reply in replies] == ["event.ack"]
        assert deployment.store.log_size() == 1
        assert rebuilt.balance("provider-A/pending") == 1_000

        # A new request settles on the NEXT leaf, with a new receipt id and a
        # receipt-hash chain link that names the previous receipt.
        _offer2, _acceptance2, document2 = center.settle(
            rebuilt, rebuilt_credential, request_id="req-2", prompt="second answer"
        )
        assert document2["status"] == "SUCCEEDED"
        second = document2["settlement"]
        assert second["receipt_id"] != first["receipt_id"]
        assert second["receipt_hash"] != first["receipt_hash"]
        assert second["log_index"] == 1
        assert deployment.store.log_size() == 2
        assert rebuilt.balance("provider-A/pending") == 2_000
        assert offer.attempt_id == stored.attempt_id
    finally:
        deployment.store.close()


# --------------------------------------------------------------------------
# G01·c: the old receipt is still readable, with a proof that verifies
# --------------------------------------------------------------------------


def test_the_old_receipt_is_served_with_a_verifiable_inclusion_proof(
    center: Center,
) -> None:
    """The rebuilt log serves the old receipt's proof, and the proof folds home."""
    center.connect()
    joined = center.join("code-proof")
    credential = center.authenticate(center.service, joined.key_id)
    _offer, _acceptance, document = center.settle(
        center.service, credential, request_id="req-1", prompt="first answer"
    )
    receipt_id = document["settlement"]["receipt_id"]
    receipt_hash = document["settlement"]["receipt_hash"]

    deployment = center.rebuild()
    try:
        rebuilt = deployment.service
        rebuilt_credential = rebuilt.authenticate_signed_request(
            **_auth_kwargs(center.joined_private, joined.key_id), now=BASE
        )
        served = rebuilt.receipt_for(
            credential=rebuilt_credential, receipt_id=receipt_id
        )
        assert served["receipt_hash"] == receipt_hash
        assert served["log_index"] == 0
        assert served["inclusion_proof"]["tree_size"] == 1

        # Fold the audit path against the stored leaf's canonical bytes and
        # check it reaches the root the proof names.
        payload = served["inclusion_proof"]
        claimed = InclusionProof(
            index=payload["index"],
            tree_size=payload["tree_size"],
            leaf_hash=payload["leaf_hash"],
            root_hash=payload["root_hash"],
            siblings=tuple(payload["siblings"]),
            directions=tuple(payload["directions"]),
        )
        stored_leaf = deployment.store.log_leaves()[0]
        leaf = LogEntry(
            index=stored_leaf.log_index,
            receipt_hash=stored_leaf.receipt_hash,
            committed_at=stored_leaf.committed_at,
        )
        assert verify_inclusion(claimed, leaf.leaf_bytes())
    finally:
        deployment.store.close()


# --------------------------------------------------------------------------
# G01·d: an invited identity still authenticates after the restart
# --------------------------------------------------------------------------


def test_an_invited_identity_still_authenticates_after_a_restart(center: Center) -> None:
    """The ``identities`` table is replayed, so the join survives the restart."""
    joined = center.join("code-d")

    deployment = center.rebuild()
    try:
        rebuilt = deployment.service
        assert deployment.store.get_identity(joined.key_id) is not None
        credential = rebuilt.authenticate_signed_request(
            **_auth_kwargs(center.joined_private, joined.key_id), now=BASE
        )
        assert credential == Credential(
            tenant_id=joined.tenant_id,
            subject_id=joined.subject_id,
            role="consumer",
            account_id=joined.subject_id,
        )
        # The invite quota was minted once, at join time; replaying the log must
        # not mint it again.
        assert rebuilt.balance(joined.subject_id) == 20_000
    finally:
        deployment.store.close()


# --------------------------------------------------------------------------
# G01·e + G01·f: the in-flight request and the in-memory permit context
# --------------------------------------------------------------------------


def test_an_in_flight_request_survives_and_is_reconciled_as_unknown(
    center: Center,
) -> None:
    """An accepted, output-committed, un-reported attempt is durable and handled.

    After the restart the center cannot finish the old settlement — the permit
    and acceptance live only in memory (G01·f) — so it asks the node what
    happened and records the answer as unknown, never as zero.
    """
    center.connect()
    joined = center.join("code-e")
    credential = center.authenticate(center.service, joined.key_id)
    # Drive req-1 to a full settlement, so the log, the provider account and a
    # receipt all exist before the restart.
    center.settle(center.service, credential, request_id="req-1", prompt="first answer")

    # Admit req-2 and stop after the output commit: no usage.final ever arrives.
    offer = center.admit(center.service, credential, request_id="req-2", prompt="in flight")
    acceptance = center.acceptance_hash(offer)
    center.accept(center.service, offer, acceptance)
    center.service.handle_node_message(
        node_id="node-A", envelope=_delta(offer, 1, "partial"), now=BASE
    )

    deployment = center.rebuild()
    try:
        rebuilt = deployment.service
        rebuilt_credential = rebuilt.authenticate_signed_request(
            **_auth_kwargs(center.joined_private, joined.key_id), now=BASE
        )

        # The durable rows survive: attempt, output commit, readable status.
        stored = deployment.store.get_attempt(offer.attempt_id)
        assert stored is not None
        assert deployment.store.output_commit("req-2") is not None
        document = rebuilt.request_status(
            credential=rebuilt_credential, request_id="req-2"
        )
        assert document["status"] == "RUNNING"
        assert document["output"]["committed"] is True
        assert document["settlement"] is None

        # G01·f: the offer terms and the node's acceptance are gone. A late
        # acceptance is refused rather than trusted against terms the rebuilt
        # center can no longer recompute.
        with pytest.raises(GatewayError, match="no permit context"):
            rebuilt.handle_node_message(
                node_id="node-A", envelope=_accept(offer, acceptance), now=BASE
            )
        # A late usage report is refused for the same reason, and leaves no
        # fabricated usage behind.
        with pytest.raises(GatewayError, match="no permit context"):
            rebuilt.handle_node_message(
                node_id="node-A",
                envelope=_usage_event(
                    center.keyring,
                    request_id="req-2",
                    attempt_id=offer.attempt_id,
                    epoch=offer.epoch,
                    permit_hash="unused-with-no-permit-context",
                    acceptance_hash=acceptance,
                ),
                now=BASE,
            )
        refused = deployment.store.get_attempt(offer.attempt_id)
        assert refused is not None
        assert refused.usage_status != "COMPLETE"
        assert refused.usage_tokens is None, "a refused report must not write zero usage"
        assert deployment.store.get_settlement("req-2", 1) is None
        assert deployment.store.log_size() == 1

        # Reconcile on the live path: the node reconnects, the center probes the
        # silent attempt, and the node answers "unknown".
        rebuilt.register_node(
            credential=Credential(tenant_id="tenant-a", subject_id="node-A", role="node"),
            hello=_hello(),
            enqueue=center.received.append,
            now=BASE,
        )
        pairs = rebuilt.tick(now=QUIET)
        queries = [
            envelope
            for _node, envelope in pairs
            if envelope.type == "attempt.query"
            and envelope.payload["attempt_id"] == offer.attempt_id
        ]
        assert len(queries) == 1, "the silent in-flight attempt must be probed"

        rebuilt.handle_node_message(
            node_id="node-A",
            envelope=Envelope(
                type="attempt.state",
                payload=AttemptState(
                    ref=_ref(offer),
                    state="FAILED",
                    certainty="unknown",
                    upstream_calls=0,
                    last_seq=0,
                ).to_payload(),
            ),
            now=QUIET,
        )

        reconciled = deployment.store.get_attempt(offer.attempt_id)
        assert reconciled is not None
        assert reconciled.status == "OUTCOME_UNKNOWN"
        assert reconciled.usage_status == "UNKNOWN"
        assert reconciled.usage_tokens is None, "unknown usage must never become zero"
        assert deployment.store.get_settlement("req-2", 1) is None
        assert (
            rebuilt.request_status(
                credential=rebuilt_credential, request_id="req-2"
            )["status"]
            == "FAILED"
        )
    finally:
        deployment.store.close()


def test_the_rebuilt_center_does_not_reuse_the_first_runs_memory_objects(
    center: Center,
) -> None:
    """The rebuild is from durable state, so nothing in-memory is carried over.

    A cheap but load-bearing sanity check for every test above: the second
    service's ledger, log and settlement engine are all newly constructed, and a
    key that was only ever in the running registry is gone.
    """
    center.connect()
    joined = center.join("code-fresh")
    center.authenticate(center.service, joined.key_id)
    old_log_id = id(center.service.log)
    old_engine_id = id(center.service.engine)

    deployment = center.rebuild()
    try:
        rebuilt = deployment.service
        assert id(rebuilt.log) != old_log_id
        assert id(rebuilt.engine) != old_engine_id
        # The consumer's own key survives *because it is in the store*, which is
        # the point: only in-memory state — the registry's copy aside from the
        # replay, the offer map, the node callbacks — is lost.
        rebuilt.authenticate_signed_request(
            **_auth_kwargs(center.joined_private, joined.key_id), now=BASE
        )
    finally:
        deployment.store.close()
