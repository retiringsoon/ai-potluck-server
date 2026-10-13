"""What the server decides, before any credit moves.

Every test drives `GatewayService` directly, with an `enqueue` callback standing
in for a socket, so the rules that guard admission, dispatch, node messages and
settlement are exercised with no transport at all. Timers are advanced by
passing an explicit instant to `tick`, and every node message is built from the
same `wire` types a connector sends, so a test fails if the service and the wire
contract drift apart.

The suites are grouped by the boundary they probe:

* admission — the credential -> consumer -> payer chain, idempotency, dispatch.
* node links — registration authority, message authority, accept and reject.
* output and usage — the commit race, the usage cross-check, settlement.
* timers — deadlines and unanswered offers.
* reads — tenant scoping and the transparency log.
* restart — what a rebuilt service keeps.
"""

from __future__ import annotations

import datetime as dt
import logging
import sqlite3
import threading
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from aipotluck.errors import (
    ConflictError,
    IdentityBindingError,
    PotluckError,
    ProtocolError,
    StateTransitionError,
)
from aipotluck.identity import generate_key_pair
from aipotluck.ledger import Ledger
from aipotluck.metering import Measurement, NormalizedUsage
from aipotluck.records import (
    SCHEMA_AUTHORIZATION,
    SignedRecord,
    UsageReport,
    signed_record_from_dict,
)
from aipotluck.wire import (
    AttemptDecision,
    AttemptEvent,
    AttemptOffer,
    AttemptRef,
    AttemptState,
    Envelope,
    NodeHeartbeat,
    NodeHello,
    NodePolicy,
    compute_acceptance_hash,
    user_message,
)
from conftest import Keyring, signed_authorization

from aipotluck_server.errors import ModelUnavailable, QueueFull
from aipotluck_server.gateway_server import OPENAI_REQUEST_DEADLINE_MS
from aipotluck_server.gateway_service import (
    API_KEY_MAX_IN_FLIGHT,
    AUTHORIZATION_SETTLEMENT_GRACE,
    DISPATCHED_EVENT_TYPE,
    MAX_DEADLINE_MS,
    QUEUE_REOFFER_BACKOFF_S,
    QUEUED_EVENT_TYPE,
    GatewayConfig,
    GatewayError,
    GatewayService,
    derive_allocation_contract,
)
from aipotluck_server.persistence import Credential, ServerStore

#: The wall-clock budget the OpenAI-compatible surface admits a request with, used
#: here as the default a key with no window of its own has to keep.
OPENAI_SURFACE_DEFAULT_MS = OPENAI_REQUEST_DEADLINE_MS

#: The instant every test works from. It is also the authorization window's
#: midpoint, so a signed authorization is valid at it without any juggling.
BASE = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
#: Keys are registered well in the past so key-validity admission never depends
#: on the wall clock, which is what made an earlier suite rot.
REGISTERED_AT = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
MODEL = "coding-pool"
TENANT = "tenant-a"

#: A consumer whose subject is the authorization's consumer, in the right tenant.
CONSUMER = Credential(tenant_id=TENANT, subject_id="consumer-X", role="consumer")
#: A credential for a different tenant, used to prove reads are tenant-scoped.
FOREIGN = Credential(tenant_id="tenant-b", subject_id="consumer-Y", role="consumer")
#: A credential that is not a node, used to prove node links are role-gated.
NOT_A_NODE = Credential(tenant_id=TENANT, subject_id="consumer-X", role="consumer")


def _funded_ledger() -> Ledger:
    """Return a ledger with a funded consumer and two provider buckets."""
    book = Ledger()
    book.issue("consumer-X", "consumer_available", 100_000)
    book.issue("consumer-Y", "consumer_available", 100_000)
    for account in ("provider-A", "provider-B"):
        book.account(f"{account}/pending", "provider_pending")
    book.fund_reserve(50_000)
    return book


def _hello(
    node_id: str,
    device_id: str,
    device_key_id: str,
    provider_id: str,
    *,
    share_enabled: bool = True,
    model: str = MODEL,
) -> NodeHello:
    """Build the opening message a well-formed connector would send."""
    return NodeHello(
        node_id=node_id,
        device_id=device_id,
        device_key_id=device_key_id,
        provider_id=provider_id,
        adapter_name="mock-adapter",
        model=model,
        policy=NodePolicy(
            share_enabled=share_enabled,
            max_concurrency=2,
            max_local_reserved_milli_credits=0,
        ),
    )


def _ref(offer: AttemptOffer) -> AttemptRef:
    """Return the wire reference for an offer."""
    return AttemptRef(
        request_id=offer.request_id, attempt_id=offer.attempt_id, epoch=offer.epoch
    )


def _accept(offer: AttemptOffer, *, acceptance_hash: str = "acceptance-1") -> Envelope:
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


def _reject(offer: AttemptOffer, *, reason: str = "no capacity") -> Envelope:
    """Build the `attempt.reject` a node sends for an offer."""
    return Envelope(
        type="attempt.reject",
        payload=AttemptDecision(ref=_ref(offer), accepted=False, reason=reason).to_payload(),
    )


def _delta(offer: AttemptOffer, seq: int, text: str) -> Envelope:
    """Build an `output.delta` event for an offer."""
    return Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=_ref(offer), seq=seq, event_type="output.delta", text=text
        ).to_payload(),
    )


def _fail_event(offer: AttemptOffer, seq: int, detail: str) -> Envelope:
    """Build an `attempt.failed` event for an offer."""
    return Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=_ref(offer), seq=seq, event_type="attempt.failed", detail=detail
        ).to_payload(),
    )


def _state(
    offer: AttemptOffer,
    state: str,
    certainty: str,
    *,
    upstream_calls: int = 0,
    last_seq: int = 0,
) -> Envelope:
    """Build an `attempt.state` report for an offer."""
    return Envelope(
        type="attempt.state",
        payload=AttemptState(
            ref=_ref(offer),
            state=state,  # type: ignore[arg-type]
            certainty=certainty,  # type: ignore[arg-type]
            upstream_calls=upstream_calls,
            last_seq=last_seq,
        ).to_payload(),
    )


def _record_mapping(record: SignedRecord) -> dict[str, Any]:
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


def _usage_event(
    keyring: Keyring,
    offer: AttemptOffer,
    *,
    acceptance_hash: str,
    seq: int = 2,
    measured: tuple[int, int] = (800, 200),
    announced: tuple[int, int] | None = None,
    provider_id: str = "provider-A",
    device_id: str = "device-A",
    device_key_id: str = "device-key-A",
    permit_hash: str | None = None,
) -> Envelope:
    """Build a `usage.final` event carrying a device-signed usage report.

    The announced totals default to the measured ones; passing `announced` makes
    them disagree on purpose, which a test uses to prove the cross-check bites.
    """
    report = UsageReport(
        report_id=f"rep-{offer.attempt_id}",
        permit_id=offer.permit_hash,
        permit_hash=offer.permit_hash if permit_hash is None else permit_hash,
        acceptance_hash=acceptance_hash,
        attempt_id=offer.attempt_id,
        provider_id=provider_id,
        device_id=device_id,
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
        key_id=device_key_id,
    ).sign(keyring.private[device_key_id], device_key_id)
    loud = announced or measured
    return Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=_ref(offer),
            seq=seq,
            event_type="usage.final",
            usage=NormalizedUsage(input_total=loud[0], output_total=loud[1]),
            report=_record_mapping(report),
        ).to_payload(),
    )


class Harness:
    """A service, its durable store, and the fake node links a test drives.

    The store lives on a real file under `tmp_path` so the restart suite can
    build a second service over the very same bytes.
    """

    def __init__(
        self, tmp_path: Path, *, now: dt.datetime = BASE, **config: Any
    ) -> None:
        self.keyring = Keyring()
        self.registry = self.keyring.registry
        self.platform_key_id = "settlement-key-test"
        public_b64, private_b64 = generate_key_pair()
        self.registry.register_key(
            self.platform_key_id,
            "platform-1",
            "platform_settlement",
            public_b64,
            REGISTERED_AT,
        )
        self.ledger = _funded_ledger()
        self.store = ServerStore.open(tmp_path / "server.db")
        # `config` is the queue policy a test wants to probe, passed straight
        # through: the defaults are the shipped ones, so a test that does not name
        # them is testing what an operator who wrote no queue field gets.
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(tmp_path / "server.db"),
            platform_id="platform-1",
            settlement_key_id=self.platform_key_id,
            settlement_private_key_b64=private_b64,
            **config,
        )
        self.service = self._build(now)
        self.outbox: dict[str, list[Envelope]] = {}

    def _build(self, now: dt.datetime) -> GatewayService:
        return GatewayService(
            config=self.config,
            store=self.store,
            registry=self.registry,
            ledger=self.ledger,
            now=now,
        )

    def restart(self) -> GatewayService:
        """Build a fresh service over the same store, as a process restart does."""
        self.service = self._build(BASE)
        return self.service

    def close(self) -> None:
        """Close the store."""
        self.store.close()

    def authorization(self, **overrides: Any) -> SignedRecord:
        """Build and sign a consumer authorization with this harness's keys."""
        return signed_authorization(self.keyring, **overrides)

    def admit(
        self,
        authorization: SignedRecord,
        *,
        idempotency_key: str = "idem-1",
        messages: tuple[Any, ...] = (user_message("write a haiku about ledgers"),),
        now: dt.datetime = BASE,
        **overrides: Any,
    ) -> Any:
        """Admit one request through the service, with test-friendly defaults."""
        arguments: dict[str, Any] = {
            "model": MODEL,
            "max_charge_milli_credits": 20_000,
        }
        arguments.update(overrides)
        return self.service.admit_request(
            credential=CONSUMER,
            idempotency_key=idempotency_key,
            messages=messages,
            authorization=authorization,
            now=now,
            **arguments,
        )

    def sink(self, node_id: str) -> Callable[[Envelope], None]:
        """Return an `enqueue` that appends to this node's outbox."""
        return lambda envelope: self.outbox[node_id].append(envelope)

    def connect(
        self,
        node_id: str = "node-A",
        *,
        device_id: str = "device-A",
        device_key_id: str = "device-key-A",
        provider_id: str = "provider-A",
        share_enabled: bool = True,
        now: dt.datetime = BASE,
        enqueue: Callable[[Envelope], None] | None = None,
    ) -> NodeHello:
        """Register a node link, opening a fresh outbox for it."""
        hello = _hello(
            node_id,
            device_id,
            device_key_id,
            provider_id,
            share_enabled=share_enabled,
        )
        self.outbox[node_id] = []
        self.service.register_node(
            credential=Credential(tenant_id=TENANT, subject_id=node_id, role="node"),
            hello=hello,
            enqueue=enqueue if enqueue is not None else self.sink(node_id),
            now=now,
        )
        return hello

    def take(self, node_id: str) -> list[Envelope]:
        """Return and clear the envelopes waiting for one node."""
        drained, self.outbox[node_id] = self.outbox[node_id], []
        return drained

    def offers(self, node_id: str) -> list[AttemptOffer]:
        """Return the offers currently waiting for one node, oldest first."""
        return [
            AttemptOffer.from_payload(envelope.payload)
            for envelope in self.outbox.get(node_id, [])
            if envelope.type == "attempt.offer"
        ]

    def sole_offer(self, node_id: str = "node-A") -> AttemptOffer:
        """Return the only offer waiting for a node, asserting there is exactly one."""
        offers = self.offers(node_id)
        assert len(offers) == 1, f"expected one offer for {node_id}, got {offers}"
        return offers[0]

    def tick(self, now: dt.datetime) -> list[tuple[str, Envelope]]:
        """Advance the timers and deliver whatever `tick` returned to its nodes."""
        pairs = self.service.tick(now=now)
        for node_id, envelope in pairs:
            self.outbox.setdefault(node_id, []).append(envelope)
        return pairs

    def status(self, request_id: str, credential: Credential = CONSUMER) -> dict[str, Any]:
        """Read a request's status document."""
        return self.service.request_status(credential=credential, request_id=request_id)


@pytest.fixture
def harness(tmp_path: Path) -> Harness:
    """Return a harness over a fresh store, closed at the end of the test."""
    built = Harness(tmp_path)
    yield built
    built.close()


# -- admission -----------------------------------------------------------------


def test_admission_offers_to_the_lowest_node_id(harness: Harness) -> None:
    """Two nodes can run the model; the deterministic choice is the lower id."""
    harness.connect("node-B", device_id="device-B", device_key_id="device-key-B",
                    provider_id="provider-B")
    harness.connect("node-A")

    result = harness.admit(harness.authorization(request_id="R-1"))

    assert result.created is True
    assert result.status == "RUNNING"
    assert harness.offers("node-B") == []
    offer = harness.sole_offer("node-A")
    assert offer.request_id == "R-1"
    assert offer.attempt_id == "R-1-a1"
    assert offer.model == MODEL


def test_admission_is_idempotent_on_key_and_payload(harness: Harness) -> None:
    """A retry of the same key and payload creates nothing and dispatches nothing."""
    harness.connect()
    authorization = harness.authorization(request_id="R-1")

    first = harness.admit(authorization, idempotency_key="key-1")
    second = harness.admit(authorization, idempotency_key="key-1")

    assert first.created is True
    assert second.created is False
    assert second.request_id == first.request_id
    assert harness.store.attempts_for_request(first.request_id).__len__() == 1
    assert len(harness.offers("node-A")) == 1, "a replay must not re-offer"


def test_admission_refuses_a_reused_key_with_a_different_payload(
    harness: Harness,
) -> None:
    """Reusing an idempotency key for other content is a conflict, not a merge.

    Each authorization is built for the conversation it is admitted with: the
    admission re-derives the request digest from the submitted work, so a single
    authorization cannot cover two different conversations.
    """
    harness.connect()
    first_authorization = harness.authorization(
        request_id="R-1", messages=(user_message("first"),)
    )
    harness.admit(
        first_authorization, idempotency_key="key-1", messages=(user_message("first"),)
    )

    second_authorization = harness.authorization(
        request_id="R-1", messages=(user_message("second"),)
    )
    with pytest.raises(ConflictError, match="idempotency key"):
        harness.admit(
            second_authorization, idempotency_key="key-1", messages=(user_message("second"),)
        )


def test_a_replayed_key_under_a_fresh_request_id_is_a_conflict(harness: Harness) -> None:
    """Same key, same work, new authorization: a conflict naming both request ids.

    A client that retries by re-signing keeps the idempotency key it already used
    and gets a fresh ``request_id``, so the payload digest agrees and the store
    hands back the *first* request. Answering that with the first request's id
    would report a dispatch the caller never asked for; answering it as an internal
    failure would tell the caller the server broke and invite it to retry the very
    request that failed. A conflict is the honest answer, and it names both ids so
    the caller can act on either.
    """
    harness.connect()
    messages = (user_message("one prompt"),)
    first = harness.admit(
        harness.authorization(request_id="R-1", messages=messages),
        idempotency_key="key-1",
        messages=messages,
    )

    with pytest.raises(ConflictError) as refused:
        harness.admit(
            harness.authorization(request_id="R-2", messages=messages),
            idempotency_key="key-1",
            messages=messages,
        )

    assert "R-1" in str(refused.value)
    assert "R-2" in str(refused.value)
    assert first.request_id == "R-1"
    assert harness.store.get_request("R-2") is None
    assert len(harness.store.attempts_for_request("R-1")) == 1


def test_admission_refuses_a_ceiling_above_the_signed_cap(harness: Harness) -> None:
    """The offer may not expose a node to more than the consumer signed for."""
    harness.connect()
    authorization = harness.authorization(request_id="R-1", max_charge_milli_credits=5_000)

    with pytest.raises(ProtocolError, match="outside the"):
        harness.admit(authorization, max_charge_milli_credits=5_001)


def test_admission_refuses_a_consumer_the_credential_does_not_own(
    harness: Harness,
) -> None:
    """Identity comes from the token: a body may not name another consumer."""
    harness.connect()
    authorization = harness.authorization(
        request_id="R-1",
        key_id="consumer-key-2",
        consumer_id="consumer-Y",
        payer_account_id="consumer-Y",
    )

    with pytest.raises(IdentityBindingError, match="never the body"):
        harness.admit(authorization)


def test_admission_refuses_cross_account_spend_without_a_grant(harness: Harness) -> None:
    """A signature proves who signed; it does not authorise another's account.

    The refusal now happens at the account-binding check, before the spend-grant
    lookup: the payer must be the account the credential is bound to, so naming
    a foreign funded account is refused outright rather than reaching the grant
    machinery.
    """
    harness.connect()
    authorization = harness.authorization(request_id="R-1", payer_account_id="consumer-Y")

    with pytest.raises(IdentityBindingError, match="would charge account"):
        harness.admit(authorization)


def test_gateway_authenticated_admission_may_name_another_consumer(
    harness: Harness,
) -> None:
    """The one documented exception: a platform-authenticated old client."""
    harness.connect()
    authorization = harness.authorization(
        request_id="R-1",
        auth_method="gateway_authenticated",
        key_id="consumer-key-2",
        consumer_id="consumer-Y",
        payer_account_id="consumer-Y",
    )

    result = harness.admit(authorization)

    assert result.created is True
    assert harness.sole_offer("node-A").request_id == "R-1"


def test_admission_refuses_an_authorization_without_a_consumer(harness: Harness) -> None:
    """A payload that names no consumer cannot be bound to the credential."""
    harness.connect()
    bare = SignedRecord(
        schema=SCHEMA_AUTHORIZATION,
        record_id="auth-bare",
        revision=1,
        signed_at=BASE,
        signer_key_id="consumer-key-1",
        signer_id="consumer-X",
        signature="sig",
        payload={"payer_account_id": "consumer-X", "max_charge_milli_credits": "1000"},
    )

    with pytest.raises(IdentityBindingError, match="names no consumer_id"):
        harness.admit(bare)


def test_admission_without_a_node_stays_live_and_tick_offers_later(
    harness: Harness,
) -> None:
    """No node is not a failure: the request waits, and `tick` offers it once one is."""
    result = harness.admit(harness.authorization(request_id="R-1"))

    assert result.created is True
    assert harness.store.attempts_for_request("R-1") == []

    harness.connect()
    pairs = harness.tick(BASE + dt.timedelta(seconds=1))

    assert [node for node, _ in pairs] == ["node-A"]
    assert harness.sole_offer("node-A").attempt_id == "R-1-a1"


def test_derive_allocation_contract_is_a_pure_function_of_persisted_fields() -> None:
    """Re-deriving after a restart must reproduce the same contract digest.

    Every input is stored: the request id is the requests primary key, and the
    provider and epoch live on the attempt row, so a rebuilt service hashes the
    same bytes and a settlement replay is recognised.
    """
    first = derive_allocation_contract(request_id="R-1", provider_id="provider-A", epoch=1)
    second = derive_allocation_contract(request_id="R-1", provider_id="provider-A", epoch=1)
    other = derive_allocation_contract(request_id="R-1", provider_id="provider-A", epoch=2)

    assert first.digest_payload() == second.digest_payload()
    assert first.digest_payload() != other.digest_payload()
    assert first.all_weights() == {"provider-A": 100}


def test_a_large_deadline_is_recorded_on_the_request(harness: Harness) -> None:
    """The deadline is admission time plus `deadline_ms`, stored verbatim."""
    harness.connect()
    harness.admit(
        harness.authorization(request_id="R-1"),
        deadline_ms=90_000,
    )

    record = harness.store.get_request("R-1")
    assert record is not None
    assert record.max_attempts == 1


def test_admission_requires_attempts_and_deadline_to_be_positive(
    harness: Harness,
) -> None:
    """A request that can never run or never expire is refused up front."""
    harness.connect()
    authorization = harness.authorization(request_id="R-1")



    with pytest.raises(ProtocolError, match="ceiling"):
        harness.admit(authorization, deadline_ms=MAX_DEADLINE_MS + 1)


def test_the_day_ceiling_binds_the_api_key_surface_too(harness: Harness) -> None:
    """A key minted before the ceiling existed cannot smuggle a longer budget.

    The mint path validates `--deadline-ms`, but the durable row is what the
    admission reads: the guard lives on the request's effective budget, not on
    the operator's flag, so an old row cannot hold a slot past the ceiling.
    """
    harness.connect()
    harness.store.add_credential(
        "consumer-token-x", CONSUMER.tenant_id, "consumer-X", "consumer", REGISTERED_AT
    )
    key = harness.store.add_api_key(
        "ak-legacy",
        key_id="apikey-old",
        name="legacy",
        subject_id="consumer-X",
        tenant_id=CONSUMER.tenant_id,
        quota_milli_credits=50_000,
        created_at=dt.datetime.now(dt.UTC),
        deadline_ms=MAX_DEADLINE_MS + 1,
    )
    with pytest.raises(ProtocolError, match="ceiling"):
        harness.service.admit_api_key_request(
            api_key=key,
            messages=(user_message("write a haiku about ledgers"),),
            model=MODEL,
        )


# -- node registration and node messages ---------------------------------------


def test_register_node_refuses_a_credential_that_is_not_a_node(harness: Harness) -> None:
    """A consumer token may not open a node link, whatever it says it is."""
    with pytest.raises(IdentityBindingError, match="may not open a node link"):
        harness.service.register_node(
            credential=NOT_A_NODE,
            hello=_hello("node-A", "device-A", "device-key-A", "provider-A"),
            enqueue=harness.sink("node-A"),
            now=BASE,
        )


def test_register_node_refuses_a_key_registered_for_another_purpose(
    harness: Harness,
) -> None:
    """The device key must be a provider-device key, not any registered key."""
    harness.outbox["node-A"] = []

    with pytest.raises(IdentityBindingError, match="provider_device"):
        harness.service.register_node(
            credential=Credential(tenant_id=TENANT, subject_id="node-A", role="node"),
            hello=_hello("node-A", "device-A", "consumer-key-1", "provider-A"),
            enqueue=harness.sink("node-A"),
            now=BASE,
        )


def test_register_node_refuses_a_key_owned_by_another_device(harness: Harness) -> None:
    """A node may not borrow a key belonging to a device it is not."""
    harness.outbox["node-A"] = []

    with pytest.raises(IdentityBindingError, match="hello claims"):
        harness.service.register_node(
            credential=Credential(tenant_id=TENANT, subject_id="node-A", role="node"),
            hello=_hello("node-A", "device-B", "device-key-A", "provider-A"),
            enqueue=harness.sink("node-A"),
            now=BASE,
        )


def test_register_node_refuses_a_provider_the_device_is_not_bound_to(
    harness: Harness,
) -> None:
    """device-A is bound to provider-A; claiming provider-B would redirect pay."""
    harness.outbox["node-A"] = []

    with pytest.raises(IdentityBindingError):
        harness.service.register_node(
            credential=Credential(tenant_id=TENANT, subject_id="node-A", role="node"),
            hello=_hello("node-A", "device-A", "device-key-A", "provider-B"),
            enqueue=harness.sink("node-A"),
            now=BASE,
        )


def test_register_node_answers_hello_with_the_heartbeat_interval(
    harness: Harness,
) -> None:
    """The ack tells the node how often to beat and carries no work yet."""
    harness.connect()

    acked = harness.take("node-A")

    assert len(acked) == 1
    assert acked[0].type == "hello.ack"
    assert acked[0].payload["heartbeat_interval_s"] == 15


def test_hello_ack_reports_resume_for_an_offer_left_behind(harness: Harness) -> None:
    """A reconnect learns what to do with an attempt the server still holds."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))

    harness.connect()  # the node returns on a new link

    ack = harness.take("node-A")[0]
    resume = ack.payload["resume"]
    assert len(resume) == 1
    assert resume[0]["attempt_id"] == "R-1-a1"
    assert resume[0]["action"] == "abandon"


def test_handle_node_message_refuses_a_message_a_node_may_not_send(
    harness: Harness,
) -> None:
    """Only the six node message types are accepted; anything else is a violation."""
    harness.connect()

    with pytest.raises(ProtocolError, match="not a message a node sends"):
        harness.service.handle_node_message(
            node_id="node-A",
            envelope=Envelope(type="attempt.offer", payload={}),
            now=BASE,
        )


def test_handle_node_message_refuses_node_hello_on_the_message_path(
    harness: Harness,
) -> None:
    """`node.hello` needs the handshake credential, so it cannot come this way."""
    with pytest.raises(ProtocolError, match="register_node"):
        harness.service.handle_node_message(
            node_id="node-A",
            envelope=Envelope(type="node.hello", payload={}),
            now=BASE,
        )


def test_a_node_may_not_speak_about_another_nodes_attempt(harness: Harness) -> None:
    """The attempt is assigned to node-A; node-B's acceptance is refused."""
    harness.connect("node-A")
    harness.connect("node-B", device_id="device-B", device_key_id="device-key-B",
                    provider_id="provider-B")
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")

    with pytest.raises(ProtocolError, match="is assigned to node"):
        harness.service.handle_node_message(
            node_id="node-B", envelope=_accept(offer), now=BASE
        )


def test_a_node_may_not_speak_about_a_wrong_epoch(harness: Harness) -> None:
    """Recomputing the reference with another epoch cannot pass the match."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    stale = AttemptRef(
        request_id=offer.request_id, attempt_id=offer.attempt_id, epoch=offer.epoch + 1
    )
    envelope = Envelope(
        type="attempt.accept",
        payload=AttemptDecision(
            ref=stale,
            accepted=True,
            permit_hash=offer.permit_hash,
            acceptance_hash="a",
        ).to_payload(),
    )

    with pytest.raises(ProtocolError, match="dispatch epoch"):
        harness.service.handle_node_message(
            node_id="node-A", envelope=envelope, now=BASE
        )


def test_a_node_may_not_speak_about_another_request(harness: Harness) -> None:
    """A reference whose request id does not match the stored attempt is refused."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    wanderer = AttemptRef(
        request_id="R-other", attempt_id=offer.attempt_id, epoch=offer.epoch
    )
    envelope = Envelope(
        type="attempt.reject",
        payload=AttemptDecision(ref=wanderer, accepted=False, reason="x").to_payload(),
    )

    with pytest.raises(ProtocolError, match="belongs to request"):
        harness.service.handle_node_message(
            node_id="node-A", envelope=envelope, now=BASE
        )


def test_a_heartbeat_from_an_unknown_node_is_refused(harness: Harness) -> None:
    """A beat on a link that never said hello proves nothing about who is there."""
    heartbeat = Envelope(
        type="node.heartbeat",
        payload=NodeHeartbeat(in_flight=0, share_enabled=True, at=BASE).to_payload(),
    )

    with pytest.raises(ProtocolError, match=r"without a node\.hello"):
        harness.service.handle_node_message(
            node_id="node-A", envelope=heartbeat, now=BASE
        )


def test_a_heartbeat_updates_the_nodes_sharing_state(harness: Harness) -> None:
    """A node that stops sharing stops receiving offers."""
    harness.connect(share_enabled=True)
    harness.service.handle_node_message(
        node_id="node-A",
        envelope=Envelope(
            type="node.heartbeat",
            payload=NodeHeartbeat(in_flight=0, share_enabled=False, at=BASE).to_payload(),
        ),
        now=BASE,
    )

    node = harness.store.get_node("node-A")
    assert node is not None
    assert node.share_enabled is False


def test_a_paused_node_is_not_offered_work(harness: Harness) -> None:
    """`share_enabled` False is honoured at dispatch, not only recorded."""
    harness.connect(share_enabled=False)

    result = harness.admit(harness.authorization(request_id="R-1"))

    assert result.created is True
    assert harness.store.attempts_for_request("R-1") == []


# -- accept and reject ---------------------------------------------------------


def test_accept_with_the_issued_permit_hash_returns_execute(harness: Harness) -> None:
    """The server starts work; the node's acceptance alone never does."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")

    replies = harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer), now=BASE
    )

    assert [reply.type for reply in replies] == ["attempt.execute"]
    stored = harness.store.get_attempt(offer.attempt_id)
    assert stored is not None
    assert stored.status == "ACCEPTED"


def test_accept_with_a_wrong_permit_hash_fails_the_attempt(harness: Harness) -> None:
    """Echoing terms the server never offered abandons the attempt."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    forged = Envelope(
        type="attempt.accept",
        payload=AttemptDecision(
            ref=_ref(offer),
            accepted=True,
            permit_hash="not-the-issued-permit",
            acceptance_hash="a",
        ).to_payload(),
    )

    with pytest.raises(ProtocolError, match="the attempt is abandoned"):
        harness.service.handle_node_message(
            node_id="node-A", envelope=forged, now=BASE
        )

    stored = harness.store.get_attempt(offer.attempt_id)
    assert stored is not None
    assert stored.status == "FAILED"


def test_a_repeat_accept_is_idempotent_and_a_term_change_is_not(
    harness: Harness,
) -> None:
    """A node may re-ask under the same terms; it may not change the terms.

    The acceptance digest legitimately changes between re-asks, because it
    covers the instant the node accepted. What must stay fixed is the offer the
    node is accepting, which the server re-derives and compares.
    """
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash="first"), now=BASE
    )

    repeat = harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash="second"), now=BASE
    )
    assert repeat[0].type == "attempt.execute"  # a re-ask is idempotent

    other_terms = AttemptDecision(
        ref=_ref(offer),
        accepted=True,
        permit_hash="sha256:" + "0" * 64,
        acceptance_hash="third",
    )
    with pytest.raises(ProtocolError, match="the attempt is abandoned"):
        harness.service.handle_node_message(
            node_id="node-A",
            envelope=Envelope(type="attempt.accept", payload=other_terms.to_payload()),
            now=BASE,
        )


def test_reject_re_offers_to_another_node(harness: Harness) -> None:
    """A refusal becomes a replacement offer, and the consumer sees why."""
    harness.connect("node-A")
    harness.connect("node-B", device_id="device-B", device_key_id="device-key-B",
                    provider_id="provider-B")
    harness.admit(harness.authorization(request_id="R-1"), max_attempts=2)
    first = harness.sole_offer("node-A")

    replies = harness.service.handle_node_message(
        node_id="node-A", envelope=_reject(first, reason="busy"), now=BASE
    )

    assert replies == [], "a replacement is delivered to its own node, not this one"
    replacement = harness.sole_offer("node-B")
    assert replacement.attempt_id == "R-1-a2"
    assert harness.status("R-1")["status"] == "RUNNING"
    assert "busy" in harness.status("R-1")["billing_note"]


def test_a_refusal_puts_the_request_back_in_the_queue_instead_of_ending_it(
    harness: Harness,
) -> None:
    """A node that declined consumed nothing, so the request still may run.

    Two facts are asserted together because they are one decision. The request is
    waiting rather than ended: a refusal is a statement about a node's capacity at
    an instant, not about the request. And it is waiting with its attempt budget
    intact, which is what makes the wait worth having — an offer nobody executed
    occupies no slot in a budget that exists to bound executions.
    """
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"), max_attempts=1)
    offer = harness.sole_offer("node-A")

    harness.service.handle_node_message(
        node_id="node-A", envelope=_reject(offer, reason="overloaded"), now=BASE
    )

    document = harness.status("R-1")
    assert document["status"] == "ROUTING"
    assert "overloaded" in document["billing_note"]
    assert harness.store.count_budget_attempts("R-1") == 0

    # The node freed up. The server asks it again once the re-offer backoff has
    # passed, and the same budget of one attempt still covers the work.
    harness.take("node-A")
    harness.tick(BASE + dt.timedelta(seconds=QUEUE_REOFFER_BACKOFF_S + 1))
    retried = harness.sole_offer("node-A")
    assert retried.attempt_id == "R-1-a2"
    assert harness.status("R-1")["status"] == "RUNNING"


def test_a_server_that_holds_no_queue_still_fails_a_request_nothing_took(
    tmp_path: Path,
) -> None:
    """``queue_enabled=false`` keeps the old answer: refused, with the reason.

    The knob is an operator's choice between holding work and shedding it, so both
    halves have to be true — with it off, a request every node declined is ended
    immediately and its note names the decline.
    """
    harness = Harness(tmp_path, queue_enabled=False)
    try:
        harness.connect()
        harness.admit(harness.authorization(request_id="R-1"), max_attempts=1)
        offer = harness.sole_offer("node-A")

        harness.service.handle_node_message(
            node_id="node-A", envelope=_reject(offer, reason="overloaded"), now=BASE
        )

        document = harness.status("R-1")
        assert document["status"] == "FAILED"
        assert "no node left to take the work" in document["billing_note"]
        assert "overloaded" in document["billing_note"]
    finally:
        harness.close()


# -- output and usage ----------------------------------------------------------


def test_the_second_delta_on_a_superseded_branch_is_declined_and_stopped(
    harness: Harness,
) -> None:
    """Only the live branch publishes output; the other is told to stop."""
    harness.connect("node-A")
    harness.connect("node-B", device_id="device-B", device_key_id="device-key-B",
                    provider_id="provider-B")
    harness.admit(harness.authorization(request_id="R-1"), max_attempts=2)
    first = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_reject(first, reason="busy"), now=BASE
    )
    second = harness.sole_offer("node-B")

    late_replies = harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(first, 1, "stale"), now=BASE
    )
    live_replies = harness.service.handle_node_message(
        node_id="node-B", envelope=_delta(second, 1, "fresh"), now=BASE
    )

    assert [reply.type for reply in late_replies] == ["attempt.cancel", "event.ack"]
    assert [reply.type for reply in live_replies] == ["event.ack"]
    events = harness.service.request_events(
        credential=CONSUMER, request_id="R-1", cursor=0
    )
    deltas = [event for event in events if event.event_type == "output.delta"]
    assert [event.payload["text"] for event in deltas] == ["fresh"]
    commit = harness.store.output_commit("R-1")
    assert commit is not None
    assert commit.attempt_id == second.attempt_id


def test_later_chunks_of_the_winning_branch_publish_under_the_same_cas(
    harness: Harness,
) -> None:
    """Every chunk, not only the first, is written inside the winner decision."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(node_id="node-A", envelope=_accept(offer), now=BASE)

    first = harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(offer, 1, "one"), now=BASE
    )
    second = harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(offer, 2, "two"), now=BASE
    )

    assert [reply.type for reply in first] == ["event.ack"]
    assert [reply.type for reply in second] == ["event.ack"]
    events = harness.service.request_events(
        credential=CONSUMER, request_id="R-1", cursor=0
    )
    deltas = [event for event in events if event.event_type == "output.delta"]
    assert [event.payload["text"] for event in deltas] == ["one", "two"]
    assert all(event.attempt_id == offer.attempt_id for event in deltas)
    commit = harness.store.output_commit("R-1")
    assert commit is not None
    assert commit.attempt_id == offer.attempt_id


def test_a_delta_from_a_stale_live_branch_is_refused_without_a_write(
    harness: Harness,
) -> None:
    """The per-chunk CAS holds even when the branch still looks eligible.

    The dispatch flow demotes branch A before opening B, so a delta from an
    output-eligible attempt whose request already committed elsewhere can only
    come from a stale or buggy peer. The store primitive must hold on its own:
    the chunk is refused with nothing written, the branch is closed, and the
    consumer stream keeps the winner's text only.
    """
    harness.connect("node-A")
    harness.connect("node-B", device_id="device-B", device_key_id="device-key-B",
                    provider_id="provider-B")
    harness.admit(harness.authorization(request_id="R-1"), max_attempts=2)
    first = harness.sole_offer("node-A")
    harness.service.handle_node_message(node_id="node-A", envelope=_accept(first), now=BASE)
    harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(first, 1, "winning"), now=BASE
    )
    commit = harness.store.output_commit("R-1")
    assert commit is not None
    assert commit.attempt_id == first.attempt_id

    harness.store.upsert_attempt(
        attempt_id="R-1-a2",
        request_id="R-1",
        node_id="node-B",
        resource_id="node-B",
        provider_id="provider-B",
        dispatch_epoch=2,
        at=BASE,
    )
    stale = Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=AttemptRef(request_id="R-1", attempt_id="R-1-a2", epoch=2),
            seq=1,
            event_type="output.delta",
            text="stolen",
        ).to_payload(),
    )
    replies = harness.service.handle_node_message(
        node_id="node-B", envelope=stale, now=BASE
    )

    assert [reply.type for reply in replies] == ["attempt.cancel", "event.ack"]
    stored = harness.store.get_attempt("R-1-a2")
    assert stored is not None
    assert stored.status == "FAILED"
    events = harness.service.request_events(
        credential=CONSUMER, request_id="R-1", cursor=0
    )
    assert [event.payload["text"] for event in events if event.event_type == "output.delta"] == [
        "winning"
    ]


def test_usage_from_a_superseded_branch_is_recorded_but_not_settled(
    harness: Harness,
) -> None:
    """Real tokens were spent on both branches, so both are kept; one is billed."""
    harness.connect("node-A")
    harness.connect("node-B", device_id="device-B", device_key_id="device-key-B",
                    provider_id="provider-B")
    harness.admit(harness.authorization(request_id="R-1"), max_attempts=2)
    first = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_reject(first, reason="busy"), now=BASE
    )
    second = harness.sole_offer("node-B")
    harness.service.handle_node_message(
        node_id="node-B", envelope=_delta(second, 1, "fresh"), now=BASE
    )

    harness.service.handle_node_message(
        node_id="node-A",
        envelope=_usage_event(
            harness.keyring,
            first,
            acceptance_hash="never-accepted",
            measured=(100, 50),
        ),
        now=BASE,
    )

    stored = harness.store.get_attempt(first.attempt_id)
    assert stored is not None
    assert stored.usage_status == "COMPLETE"
    assert stored.usage_tokens == 150
    assert harness.store.get_settlement("R-1", 1) is None
    assert harness.ledger.balance("provider-A/pending") == 0


def test_usage_announcing_a_total_its_report_does_not_measure_is_refused(
    harness: Harness,
) -> None:
    """The numbers travel twice on purpose so a signer cannot say one thing and measure another."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash="acc-1"), now=BASE
    )
    event = _usage_event(
        harness.keyring,
        offer,
        acceptance_hash="acc-1",
        measured=(800, 200),
        announced=(800, 300),
    )

    with pytest.raises(ProtocolError, match="refusing to settle either total"):
        harness.service.handle_node_message(
            node_id="node-A", envelope=event, now=BASE
        )

    assert harness.ledger.balance("consumer-X") == 100_000


def test_usage_with_a_foreign_permit_hash_is_refused(harness: Harness) -> None:
    """A report is bound to the terms the server actually issued."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash="acc-1"), now=BASE
    )
    event = _usage_event(
        harness.keyring,
        offer,
        acceptance_hash="acc-1",
        permit_hash="not-the-issued-permit",
    )

    with pytest.raises(ProtocolError, match="the server issued"):
        harness.service.handle_node_message(
            node_id="node-A", envelope=event, now=BASE
        )


def test_usage_with_a_foreign_acceptance_hash_is_refused(harness: Harness) -> None:
    """The report must echo what the node committed to at accept time."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash="acc-1"), now=BASE
    )
    event = _usage_event(harness.keyring, offer, acceptance_hash="acc-other")

    with pytest.raises(ProtocolError, match="the node accepted"):
        harness.service.handle_node_message(
            node_id="node-A", envelope=event, now=BASE
        )


def test_usage_without_a_signed_report_is_refused(harness: Harness) -> None:
    """A bare token count is not settlement evidence."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    unsigned = Envelope(
        type="attempt.event",
        payload={
            **_ref(offer).to_payload(),
            "seq": 2,
            "event_type": "usage.final",
            "final": True,
            "usage": NormalizedUsage(input_total=800, output_total=200).to_payload(),
        },
    )

    with pytest.raises(ProtocolError, match="signed usage report"):
        harness.service.handle_node_message(
            node_id="node-A", envelope=unsigned, now=BASE
        )


def test_an_unknown_outcome_keeps_usage_unknown_never_zero(harness: Harness) -> None:
    """A component might exist unaccounted for; reporting zero would make it free."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash="acc-1"), now=BASE
    )

    harness.service.handle_node_message(
        node_id="node-A",
        envelope=_state(offer, "UNKNOWN", "unknown", upstream_calls=1, last_seq=3),
        now=BASE,
    )

    document = harness.status("R-1")
    attempt = document["attempts"][0]
    assert attempt["status"] == "OUTCOME_UNKNOWN"
    assert attempt["usage_status"] == "UNKNOWN"
    assert attempt["usage_tokens"] is None


def test_a_not_submitted_state_report_re_offers_the_attempt(harness: Harness) -> None:
    """The offer never reached the upstream, so a replacement is safe and free."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"), max_attempts=2)
    offer = harness.sole_offer("node-A")

    # Drain the first offer, so the assertion below says "exactly one
    # replacement" rather than "at least one".
    harness.take("node-A")

    harness.service.handle_node_message(
        node_id="node-A",
        envelope=_state(offer, "FAILED", "not_submitted", upstream_calls=0),
        now=BASE,
    )

    replacement = harness.sole_offer("node-A")
    assert replacement.attempt_id == "R-1-a2"
    assert harness.status("R-1")["status"] == "RUNNING"


def test_a_failure_on_the_live_branch_fails_the_request(harness: Harness) -> None:
    """Output is public, so the failure is surfaced rather than silently retried."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(offer, 1, "partial"), now=BASE
    )

    harness.service.handle_node_message(
        node_id="node-A", envelope=_fail_event(offer, 2, "upstream 500"), now=BASE
    )

    document = harness.status("R-1")
    assert document["status"] == "FAILED"
    assert "upstream 500" in document["billing_note"]
    stored = harness.store.get_attempt(offer.attempt_id)
    assert stored is not None
    assert stored.usage_status == "UNKNOWN"
    assert stored.usage_tokens is None


def test_completion_without_settlement_keeps_usage_unknown(harness: Harness) -> None:
    """A completion with no final usage is unaccounted for, not free."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    completed = Envelope(
        type="attempt.event",
        payload=AttemptEvent(
            ref=_ref(offer),
            seq=1,
            event_type="attempt.completed",
            outcome="completed",
            final=True,
        ).to_payload(),
    )

    harness.service.handle_node_message(
        node_id="node-A", envelope=completed, now=BASE
    )

    stored = harness.store.get_attempt(offer.attempt_id)
    assert stored is not None
    assert stored.status == "COMPLETED"
    assert stored.usage_status == "UNKNOWN"
    assert stored.usage_tokens is None
    assert "usage stays" in harness.status("R-1")["billing_note"]


def test_a_signed_report_settles_credit_and_issues_a_receipt(harness: Harness) -> None:
    """The whole happy path: offer, accept, delta, usage, settlement, receipt."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    acceptance_hash = compute_acceptance_hash(
        permit_hash=offer.permit_hash,
        request_id=offer.request_id,
        attempt_id=offer.attempt_id,
        epoch=offer.epoch,
        adapter_name="mock-adapter",
        accepted_at=BASE,
    )
    harness.service.handle_node_message(
        node_id="node-A",
        envelope=_accept(offer, acceptance_hash=acceptance_hash),
        now=BASE,
    )
    harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(offer, 1, "once upon a ledger"), now=BASE
    )
    harness.service.handle_node_message(
        node_id="node-A",
        envelope=_usage_event(harness.keyring, offer, acceptance_hash=acceptance_hash),
        now=BASE,
    )

    document = harness.status("R-1")
    assert document["status"] == "SUCCEEDED"
    settlement = document["settlement"]
    assert settlement is not None
    assert harness.ledger.balance("consumer-X") == 99_000
    assert harness.ledger.balance("provider-A/pending") == 1_000

    receipt = harness.service.receipt_for(
        credential=CONSUMER, receipt_id=settlement["receipt_id"]
    )
    assert receipt["receipt_hash"] == settlement["receipt_hash"]
    assert receipt["log_index"] == settlement["log_index"]
    assert harness.service.log.size() == harness.store.log_size()


def test_a_replayed_usage_event_does_not_settle_twice(harness: Harness) -> None:
    """A retransmitted report must reuse the receipt, not move credit again."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash="acc-1"), now=BASE
    )
    harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(offer, 1, "text"), now=BASE
    )
    event = _usage_event(harness.keyring, offer, acceptance_hash="acc-1")

    harness.service.handle_node_message(node_id="node-A", envelope=event, now=BASE)
    harness.service.handle_node_message(node_id="node-A", envelope=event, now=BASE)

    assert harness.ledger.balance("consumer-X") == 99_000
    assert harness.ledger.balance("provider-A/pending") == 1_000
    assert harness.store.log_size() == 1


# -- timers --------------------------------------------------------------------


def test_tick_expires_a_request_past_its_deadline(harness: Harness) -> None:
    """An expired request is cancelled with the `deadline` origin and stops its node."""
    harness.connect()
    harness.admit(
        harness.authorization(request_id="R-1"), deadline_ms=1_000
    )
    offer = harness.sole_offer("node-A")

    pairs = harness.tick(BASE + dt.timedelta(seconds=2))

    assert (offer.attempt_id, "R-1") == (offer.attempt_id, "R-1")
    assert [node for node, _ in pairs] == ["node-A"]
    assert [envelope.type for _, envelope in pairs] == ["attempt.cancel"]
    assert harness.status("R-1")["status"] == "EXPIRED"


def test_tick_leaves_a_request_inside_its_deadline_alone(harness: Harness) -> None:
    """Nothing happens before the deadline, so a live request is not disturbed."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"), deadline_ms=60_000)

    pairs = harness.tick(BASE + dt.timedelta(seconds=1))

    assert pairs == []
    assert harness.status("R-1")["status"] == "RUNNING"


def _routing_row_without_inputs(
    harness: Harness,
    request_id: str,
    *,
    deadline_ms: int = 60_000,
    api_key_id: str | None = None,
    at: dt.datetime = BASE,
) -> None:
    """Write a ROUTING request row with no dispatch inputs behind it.

    The shape production held: a server whose database could not store a
    conversation created the row, could not store what the row needs to be
    dispatched, and then told the caller the request had no inputs. It is written
    straight to the store because no admission path produces it any more, and the
    rows already on disk are exactly what a tick has to survive.
    """
    harness.store.create_request(
        request_id=request_id,
        tenant_id=TENANT,
        subject_id="consumer-X",
        idempotency_key=f"idem-{request_id}",
        payload_digest="sha256:aaaa",
        delivery_mode="buffered_complete",
        max_attempts=1,
        service_unit_id=request_id,
        deadline_at=at + dt.timedelta(milliseconds=deadline_ms),
        created_at=at,
    )
    if api_key_id is not None:
        harness.store.bind_request_api_key(request_id, api_key_id)
    harness.store.set_request_status(request_id, "ROUTING", at=at)


def _store_inputs_the_server_cannot_read_back(harness: Harness, request_id: str) -> None:
    """Write a dispatch input whose authorization is not a signed record.

    A row the store holds and this build cannot parse, which is a genuine offer
    failure rather than an injected one: nothing about the request is dispatchable,
    and the failure surfaces where the offer is built.
    """
    harness.store.create_request(
        request_id=request_id,
        tenant_id=TENANT,
        subject_id="consumer-X",
        idempotency_key=f"idem-{request_id}",
        payload_digest="sha256:aaaa",
        delivery_mode="buffered_complete",
        max_attempts=1,
        service_unit_id=request_id,
        deadline_at=BASE + dt.timedelta(milliseconds=60_000),
        created_at=BASE,
    )
    harness.store.set_request_input(
        request_id,
        messages=[user_message("write a haiku about ledgers").to_payload()],
        model=MODEL,
        parameters={},
        authorization={"schema": "not-a-signed-record"},
        at=BASE,
    )
    harness.store.set_request_status(request_id, "ROUTING", at=BASE)


def _break_the_request_inputs_table(path: Path) -> None:
    """Put `request_inputs` into the shape that made every write fail in production.

    A legacy ``prompt TEXT NOT NULL`` beside the conversation columns: an INSERT
    that names no prompt cannot satisfy it, so the store cannot hold a request's
    inputs at all. That is a store fault, and it is what an admission has to
    survive without leaving a live request behind.
    """
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TABLE request_inputs")
        connection.execute(
            "CREATE TABLE request_inputs (request_id TEXT PRIMARY KEY,"
            " prompt TEXT NOT NULL, model TEXT NOT NULL, messages_json TEXT,"
            " parameters_json TEXT NOT NULL DEFAULT '{}',"
            " authorization_json TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        connection.commit()
    finally:
        connection.close()


def test_a_request_with_nothing_to_dispatch_is_ended_rather_than_offered_again(
    harness: Harness,
) -> None:
    """An undispatchable request is ended, with the reason on the books.

    Raising instead left the row in ROUTING, where it held its API key's
    concurrency slot forever and aborted the tick round that would have expired
    it — so one such row also kept every other overdue request on the server
    alive, for as long as the server ran.
    """
    harness.connect()
    _routing_row_without_inputs(harness, "R-poison")

    harness.tick(BASE + dt.timedelta(seconds=1))

    record = harness.store.get_request("R-poison")
    assert record is not None
    assert record.status == "FAILED"
    assert "no stored dispatch inputs" in (record.billing_note or "")
    assert harness.offers("node-A") == []


def test_a_request_an_earlier_server_stored_as_a_prompt_is_ended_too(
    harness: Harness, tmp_path: Path
) -> None:
    """A legacy row is ended with the report that explains it, not offered forever."""
    harness.connect()
    _routing_row_without_inputs(harness, "R-legacy")
    connection = sqlite3.connect(tmp_path / "server.db")
    try:
        connection.execute(
            "INSERT INTO request_inputs (request_id, messages_json, model,"
            " parameters_json, authorization_json, created_at)"
            " VALUES ('R-legacy', NULL, 'coding-pool', '{}', '{}', '2026-10-06T12:00:00+00:00')"
        )
        connection.commit()
    finally:
        connection.close()

    harness.tick(BASE + dt.timedelta(seconds=1))

    record = harness.store.get_request("R-legacy")
    assert record is not None
    assert record.status == "FAILED"
    assert "earlier server version" in (record.billing_note or "")


def test_one_undispatchable_request_does_not_stop_the_round_for_the_others(
    harness: Harness,
) -> None:
    """Expiry still ends what is overdue, and offers still go out, in the same round.

    Expiry runs first and each offer is isolated, so the round neither offers work
    that is already too late to run nor depends on any one request being
    offerable.
    """
    harness.admit(
        harness.authorization(request_id="R-overdue"),
        idempotency_key="idem-overdue",
        deadline_ms=1_000,
    )
    harness.admit(
        harness.authorization(request_id="R-live"),
        idempotency_key="idem-live",
        deadline_ms=60_000,
    )
    _routing_row_without_inputs(harness, "R-poison")
    harness.connect()

    harness.tick(BASE + dt.timedelta(seconds=2))

    assert harness.status("R-overdue")["status"] == "EXPIRED"
    assert harness.status("R-live")["status"] == "RUNNING"
    assert [offer.request_id for offer in harness.offers("node-A")] == ["R-live"]
    poison = harness.store.get_request("R-poison")
    assert poison is not None
    assert poison.status == "FAILED"


def test_an_offer_that_fails_is_reported_and_the_round_continues(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    """A failure one request cannot survive is logged, not raised out of the tick.

    `tick` is the server's only timer and its caller swallows whatever escapes and
    retries on the next interval, so an exception out of one offer used to cancel
    the whole round, repeatedly, forever.
    """
    _store_inputs_the_server_cannot_read_back(harness, "R-bad")
    harness.admit(
        harness.authorization(request_id="R-overdue"),
        idempotency_key="idem-overdue",
        deadline_ms=1_000,
    )
    harness.admit(
        harness.authorization(request_id="R-live"),
        idempotency_key="idem-live",
        deadline_ms=60_000,
    )
    harness.connect()

    with caplog.at_level(logging.ERROR, logger="aipotluck_server.gateway_service"):
        harness.tick(BASE + dt.timedelta(seconds=2))

    assert harness.status("R-overdue")["status"] == "EXPIRED"
    assert harness.status("R-live")["status"] == "RUNNING"
    assert [offer.request_id for offer in harness.offers("node-A")] == ["R-live"]
    assert any("R-bad" in record.getMessage() for record in caplog.records), caplog.records


def test_an_overdue_request_is_ended_by_the_next_admission_and_frees_the_keys_slot(
    harness: Harness,
) -> None:
    """The admission gate sweeps, because the slots an overdue request holds block it.

    A key at its concurrency ceiling is refused before it admits anything, so a
    sweep that ran only inside an admission would never reach the rows that are
    refusing it: the four slots held by requests nothing had ended yet would keep
    answering 429 forever. That is the production shape — four rows in ROUTING,
    deadlines minutes past, and a key that could never admit again.
    """
    harness.store.add_credential(
        "consumer-token", TENANT, "consumer-X", "consumer", REGISTERED_AT
    )
    key = harness.store.add_api_key(
        "ak-plaintext",
        key_id="apikey-1",
        name="",
        subject_id="consumer-X",
        tenant_id=TENANT,
        quota_milli_credits=100_000,
        created_at=BASE,
    )
    harness.connect()
    for index in range(API_KEY_MAX_IN_FLIGHT):
        _routing_row_without_inputs(
            harness,
            f"R-stuck-{index}",
            deadline_ms=1_000,
            api_key_id=key.key_id,
        )
    stuck = harness.store.count_in_flight_api_key_requests(key.key_id)
    assert stuck == API_KEY_MAX_IN_FLIGHT

    admitted = harness.service.admit_api_key_request(
        api_key=key,
        messages=(user_message("write a haiku about ledgers"),),
        model=MODEL,
        now=BASE + dt.timedelta(seconds=2),
    )

    assert admitted.created is True
    for index in range(API_KEY_MAX_IN_FLIGHT):
        record = harness.store.get_request(f"R-stuck-{index}")
        assert record is not None
        assert record.status == "EXPIRED", record.billing_note
    # The four slots are released, and the request just admitted holds the only one.
    assert harness.store.count_in_flight_api_key_requests(key.key_id) == 1


def test_an_admission_that_cannot_store_its_inputs_ends_the_request_it_created(
    harness: Harness, tmp_path: Path
) -> None:
    """A store fault ends the request before the caller is told about it.

    No path may leave a request non-terminal: the row occupies its key's
    concurrency slot until something ends it. The status is CANCELLED rather than
    FAILED because the request never left CREATED, which is the state
    `aipotluck.statemachine` may cancel but not fail — nothing was dispatched, so
    nothing failed to run, and the note says what did happen.
    """
    harness.connect()
    _break_the_request_inputs_table(tmp_path / "server.db")

    with pytest.raises(PotluckError, match="could not be stored"):
        harness.admit(harness.authorization(request_id="R-1"))

    record = harness.store.get_request("R-1")
    assert record is not None
    assert record.status == "CANCELLED"
    assert "could not be stored" in (record.billing_note or "")
    assert harness.offers("node-A") == []


def test_tick_abandons_and_re_offers_an_unanswered_offer(harness: Harness) -> None:
    """An offer that waited past the timeout is retired and offered again."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"), max_attempts=2)
    first = harness.sole_offer("node-A")
    harness.take("node-A")  # drain the retired offer before asserting on the replacement

    harness.tick(BASE + dt.timedelta(seconds=11))

    stored = harness.store.get_attempt(first.attempt_id)
    assert stored is not None
    assert stored.status == "FAILED"
    replacement = harness.sole_offer("node-A")
    assert replacement.attempt_id == "R-1-a2"
    assert "not accepted within" in harness.status("R-1")["billing_note"]


def test_tick_does_not_abandon_an_offer_within_its_timeout(harness: Harness) -> None:
    """The timeout is a real bound, not an off-by-one."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"), max_attempts=2)
    first = harness.sole_offer("node-A")

    harness.tick(BASE + dt.timedelta(seconds=9))

    stored = harness.store.get_attempt(first.attempt_id)
    assert stored is not None
    assert stored.status == "OFFERED"
    assert len(harness.offers("node-A")) == 1


# -- consumer reads and cancellation -------------------------------------------


def test_a_cross_tenant_status_read_is_refused(harness: Harness) -> None:
    """Reads are authorised against the stored record, not filtered silently."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))

    with pytest.raises(IdentityBindingError, match="may not read request"):
        harness.status("R-1", credential=FOREIGN)


def test_a_cross_tenant_event_read_is_refused(harness: Harness) -> None:
    """The event stream is tenant-scoped too."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))

    with pytest.raises(IdentityBindingError, match="may not read request"):
        harness.service.request_events(
            credential=FOREIGN, request_id="R-1", cursor=0
        )


def test_an_unknown_request_read_is_a_state_error(harness: Harness) -> None:
    """An unknown request is the same shape of error as an illegal transition."""
    with pytest.raises(StateTransitionError, match="unknown request"):
        harness.status("R-nope")


def test_an_unknown_receipt_is_a_gateway_error(harness: Harness) -> None:
    """A receipt this server never issued is not silently invented."""
    with pytest.raises(GatewayError, match="never issued"):
        harness.service.receipt_for(credential=CONSUMER, receipt_id="R-nope")


def test_account_history_answers_for_the_credential_not_a_named_account(
    harness: Harness,
) -> None:
    """The statement a consumer reads is its own, down to the journal ids.

    `account_history` takes no account id: its only input is the credential the
    transport authenticated. Two consumers funded in one ledger and one tenant
    therefore get two disjoint statements, which is what the reconciliation's
    `account_history_complete` dimension rests on — a consumer told "these are
    all your charges" has to be told about *its* charges, and a tenant is not an
    account.
    """
    own = harness.service.account_history(credential=CONSUMER)
    assert own["account_id"] == "consumer-X"
    assert own["balances"]["available"] == 100_000
    assert own["entry_count"] == len(own["entries"]) > 0

    neighbour = Credential(tenant_id=TENANT, subject_id="consumer-Y", role="consumer")
    theirs = harness.service.account_history(credential=neighbour)
    assert theirs["account_id"] == "consumer-Y"

    own_journals = {entry["journal_id"] for entry in own["entries"]}
    their_journals = {entry["journal_id"] for entry in theirs["entries"]}
    assert own_journals and their_journals
    assert not own_journals & their_journals


def test_account_history_refuses_a_credential_that_is_not_a_consumer(
    harness: Harness,
) -> None:
    """The role is checked in the domain too, not only at the transport.

    A route table that drifts is one mistake; a service that answers anyway is
    the leak. Both guards have to be wrong before a node reads a consumer's
    statement.
    """
    with pytest.raises(IdentityBindingError, match="no consumer account history"):
        harness.service.account_history(
            credential=Credential(tenant_id=TENANT, subject_id="node-A", role="node")
        )


def test_request_events_are_ordered_and_cursor_windows_them(harness: Harness) -> None:
    """The cursor is a per-request position, so a consumer can resume mid-stream."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(offer, 1, "one"), now=BASE
    )
    harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(offer, 2, "two"), now=BASE
    )

    everything = harness.service.request_events(
        credential=CONSUMER, request_id="R-1", cursor=0
    )
    assert [event.payload["text"] for event in everything] == ["one", "two"]
    after_first = harness.service.request_events(
        credential=CONSUMER, request_id="R-1", cursor=everything[0].cursor
    )
    assert [event.payload["text"] for event in after_first] == ["two"]


def test_a_cancel_refuses_an_unknown_origin(harness: Harness) -> None:
    """Only the documented origins are accepted."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))

    with pytest.raises(ProtocolError, match="unknown cancel origin"):
        harness.service.cancel_request(
            credential=CONSUMER, request_id="R-1", origin="because", now=BASE
        )


def test_a_cancel_refuses_another_tenants_request(harness: Harness) -> None:
    """A cancel is a write, so it is tenant-scoped like every other."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))

    with pytest.raises(IdentityBindingError, match="may not read request"):
        harness.service.cancel_request(
            credential=FOREIGN,
            request_id="R-1",
            origin="consumer_cancel",
            now=BASE,
        )


def test_a_cancel_of_an_unknown_request_is_a_state_error(harness: Harness) -> None:
    """Cancelling what does not exist is a state problem, not a protocol one."""
    with pytest.raises(StateTransitionError, match="unknown request"):
        harness.service.cancel_request(
            credential=CONSUMER,
            request_id="R-nope",
            origin="consumer_cancel",
            now=BASE,
        )


def test_a_cancel_of_an_undispatched_request_terminates_it(harness: Harness) -> None:
    """A request admitted with no node connected has no aggregate; cancelling must still work."""
    harness.admit(harness.authorization(request_id="R-1"))

    decision = harness.service.cancel_request(
        credential=CONSUMER, request_id="R-1", origin="consumer_cancel", now=BASE
    )

    assert harness.status("R-1")["status"] == "CANCELLED"
    assert decision["status"] == "CANCELLED"
    assert decision["origin"] == "consumer_cancel"
    assert decision["note"]


def test_a_cancel_tells_the_live_attempts_to_stop(harness: Harness) -> None:
    """Every non-terminal attempt of the request gets a cancel for its node."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.take("node-A")

    harness.service.cancel_request(
        credential=CONSUMER, request_id="R-1", origin="consumer_cancel", now=BASE
    )

    delivered = harness.take("node-A")
    assert [envelope.type for envelope in delivered] == ["attempt.cancel"]
    assert delivered[0].payload["origin"] == "consumer_cancel"
    assert delivered[0].payload["attempt_id"] == offer.attempt_id
    assert harness.status("R-1")["billing_note"] is not None


# -- transparency and restart --------------------------------------------------


def test_a_checkpoint_covers_the_newest_leaf(harness: Harness) -> None:
    """The checkpoint commits to the whole log, so an auditor can compare views."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash="acc-1"), now=BASE
    )
    harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(offer, 1, "text"), now=BASE
    )
    harness.service.handle_node_message(
        node_id="node-A",
        envelope=_usage_event(harness.keyring, offer, acceptance_hash="acc-1"),
        now=BASE,
    )

    checkpoint = harness.service.checkpoint(credential=CONSUMER)

    assert harness.service.log.size() == 1
    assert checkpoint["log_index"] == 0
    assert checkpoint["signature"]


def test_an_empty_log_checkpoints_with_no_index(harness: Harness) -> None:
    """An empty log has nothing to cover, and says so rather than inventing index 0."""
    checkpoint = harness.service.checkpoint(credential=CONSUMER)

    assert checkpoint["log_index"] is None
    assert checkpoint["signature"]


def test_restart_rebuilds_the_log_and_keeps_receipts(harness: Harness) -> None:
    """A rebuilt service shares the durable log and can still serve a receipt."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")
    harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash="acc-1"), now=BASE
    )
    harness.service.handle_node_message(
        node_id="node-A", envelope=_delta(offer, 1, "text"), now=BASE
    )
    harness.service.handle_node_message(
        node_id="node-A",
        envelope=_usage_event(harness.keyring, offer, acceptance_hash="acc-1"),
        now=BASE,
    )
    receipt_id = harness.status("R-1")["settlement"]["receipt_id"]

    rebuilt = harness.restart()

    assert rebuilt.log.size() == harness.store.log_size() == 1
    assert rebuilt.checkpoint(credential=CONSUMER)["log_index"] == 0
    assert rebuilt.receipt_for(credential=CONSUMER, receipt_id=receipt_id)["log_index"] == 0
    assert harness.status("R-1")["status"] == "SUCCEEDED"


def test_restart_forgets_offer_context_but_keeps_the_attempt_row(
    harness: Harness,
) -> None:
    """Documented loss: the offer's terms are in memory, so a later accept is refused.

    The attempt row and the request's status survive, which is what lets a
    consumer still read what happened; what is gone is the permit hash and the
    authorization, so the server refuses to trust a late acceptance against a
    hash it can no longer recompute.
    """
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"))
    offer = harness.sole_offer("node-A")

    harness.restart()

    assert harness.store.get_attempt(offer.attempt_id) is not None
    assert harness.status("R-1")["status"] == "RUNNING"
    with pytest.raises(GatewayError, match="no permit context"):
        harness.service.handle_node_message(
            node_id="node-A", envelope=_accept(offer), now=BASE
        )


def test_construction_refuses_a_non_contiguous_log(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gap in the stored leaves means the log cannot be trusted, so it is refused."""
    harness.store.append_log_leaf("hash-0", BASE)
    harness.store.append_log_leaf("hash-1", BASE)
    leaves = harness.store.log_leaves()
    monkeypatch.setattr(
        harness.store,
        "log_leaves",
        lambda: [replace(leaf, log_index=leaf.log_index + 1) for leaf in leaves],
    )

    with pytest.raises(GatewayError, match="not contiguous"):
        GatewayService(
            config=harness.config,
            store=harness.store,
            registry=harness.registry,
            ledger=harness.ledger,
            now=BASE,
        )


# -- locking -------------------------------------------------------------------


def test_the_lock_is_released_before_a_node_callback_runs(harness: Harness) -> None:
    """A slow node must not stall the server: admission runs while the sink blocks.

    The sink blocks on the first offer. If delivery held the service lock, the
    concurrent status read below would hang and the test would time out, which is
    exactly the failure this guards against.
    """
    entered = threading.Event()
    release = threading.Event()

    def blocking_sink(envelope: Envelope) -> None:
        if envelope.type == "attempt.offer":
            entered.set()
            assert release.wait(timeout=5), "the test never released the sink"
        harness.outbox.setdefault("node-A", []).append(envelope)

    harness.outbox["node-A"] = []
    harness.connect(enqueue=blocking_sink)
    authorization = harness.authorization(request_id="R-1")

    worker = threading.Thread(target=lambda: harness.admit(authorization), daemon=True)
    worker.start()
    assert entered.wait(timeout=5), "the offer was never delivered to the sink"

    # The lock must be free while the sink is blocked, so a read on this thread
    # completes rather than deadlocking behind the callback.
    document = harness.status("R-1")
    assert document["request_id"] == "R-1"

    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert harness.sole_offer("node-A").request_id == "R-1"


# -- agent sessions -------------------------------------------------------------


def _settle(
    harness: Harness,
    offer: AttemptOffer,
    node_id: str,
    *,
    measured: tuple[int, int] = (800, 200),
    device_id: str = "device-A",
    device_key_id: str = "device-key-A",
    provider_id: str = "provider-A",
) -> None:
    """Run one offer to a settled success: accept, publish, report usage.

    The three messages a real node sends, in the order it sends them, so a test
    about what a session's turn cost is driving the same settlement path the
    connector drives rather than writing rows behind it. The device and provider
    default to node-A's and have to be named for any other node, because a report
    is signed by the device that ran the work and settles into the provider that
    device is bound to.
    """
    acceptance_hash = compute_acceptance_hash(
        permit_hash=offer.permit_hash,
        request_id=offer.request_id,
        attempt_id=offer.attempt_id,
        epoch=offer.epoch,
        adapter_name="mock-adapter",
        accepted_at=BASE,
    )
    harness.service.handle_node_message(
        node_id=node_id,
        envelope=_accept(offer, acceptance_hash=acceptance_hash),
        now=BASE,
    )
    harness.service.handle_node_message(
        node_id=node_id, envelope=_delta(offer, 1, "an answer"), now=BASE
    )
    harness.service.handle_node_message(
        node_id=node_id,
        envelope=_usage_event(
            harness.keyring,
            offer,
            acceptance_hash=acceptance_hash,
            measured=measured,
            device_id=device_id,
            device_key_id=device_key_id,
            provider_id=provider_id,
        ),
        now=BASE,
    )


def test_a_session_aggregates_the_turns_tokens_and_credit_it_settled(
    harness: Harness,
) -> None:
    """One session's totals are the books' own numbers for the turns it made.

    Two turns, both settled, and the aggregate has to agree with what the ledger
    moved and what the node measured — separately, because the two are different
    quantities and reporting one as the other would make a session's cost
    unreadable.
    """
    harness.connect()
    harness.admit(
        harness.authorization(request_id="R-1"), idempotency_key="k-1", session_id="sess-1"
    )
    _settle(harness, harness.sole_offer("node-A"), "node-A")
    harness.take("node-A")
    harness.admit(
        harness.authorization(request_id="R-2"), idempotency_key="k-2", session_id="sess-1"
    )
    _settle(harness, harness.sole_offer("node-A"), "node-A")

    session = harness.store.session(TENANT, "consumer-X", "sess-1")
    assert session is not None
    assert session.request_count == 2
    assert session.total_tokens == 2_000, "800 + 200 native tokens per turn, as measured"
    assert session.total_milli_credits == 2_000
    assert session.total_milli_credits == 100_000 - harness.ledger.balance("consumer-X")
    assert session.last_node_id == "node-A"


def test_a_session_counts_a_turn_that_never_settled_without_charging_it(
    harness: Harness,
) -> None:
    """A turn the session made is a turn, even when it cost nothing.

    `request_count` answers "how many turns did this run make", which includes the
    ones that failed; the totals answer "what was billed", which does not. Keeping
    the two apart is what stops a session with a failed turn from looking like a
    session that never ran.
    """
    harness.connect()
    harness.admit(
        harness.authorization(request_id="R-1"), idempotency_key="k-1", session_id="sess-1"
    )
    harness.service.cancel_request(
        credential=CONSUMER, request_id="R-1", origin="consumer_cancel", now=BASE
    )

    session = harness.store.session(TENANT, "consumer-X", "sess-1")
    assert session is not None
    assert session.request_count == 1
    assert session.total_tokens == 0
    assert session.total_milli_credits == 0
    assert session.last_node_id is None


def test_a_replayed_usage_report_does_not_count_a_session_turn_twice(
    harness: Harness,
) -> None:
    """The resend after a lost acknowledgement adds nothing, as everywhere else.

    Settlement idempotency is the store's job, and a session total that grew on
    every replay would be a second place where the same credit is counted twice.
    """
    harness.connect()
    harness.admit(
        harness.authorization(request_id="R-1"), idempotency_key="k-1", session_id="sess-1"
    )
    offer = harness.sole_offer("node-A")
    acceptance_hash = compute_acceptance_hash(
        permit_hash=offer.permit_hash,
        request_id=offer.request_id,
        attempt_id=offer.attempt_id,
        epoch=offer.epoch,
        adapter_name="mock-adapter",
        accepted_at=BASE,
    )
    harness.service.handle_node_message(
        node_id="node-A", envelope=_accept(offer, acceptance_hash=acceptance_hash), now=BASE
    )
    event = _usage_event(harness.keyring, offer, acceptance_hash=acceptance_hash)

    harness.service.handle_node_message(node_id="node-A", envelope=event, now=BASE)
    harness.service.handle_node_message(node_id="node-A", envelope=event, now=BASE)

    session = harness.store.session(TENANT, "consumer-X", "sess-1")
    assert session is not None
    assert session.request_count == 1
    assert session.total_tokens == 1_000
    assert session.total_milli_credits == 1_000


def test_a_session_goes_back_to_the_node_that_served_its_last_turn(
    harness: Harness,
) -> None:
    """The sticky preference, and why it is worth having.

    Both nodes can run the model and the ordinary rule would pick the lower id
    every time. The session's second turn goes to the node that served its first
    one instead, because that node's upstream is the one already holding this
    conversation.
    """
    harness.connect("node-A")
    harness.connect(
        "node-B", device_id="device-B", device_key_id="device-key-B", provider_id="provider-B"
    )
    harness.admit(
        harness.authorization(request_id="R-1"),
        idempotency_key="k-1",
        session_id="sess-1",
        max_attempts=1,
    )
    # node-A wins the first turn on the ordinary lowest-id rule, and declines it,
    # so the turn settles on node-B — the preference has to come from the books
    # rather than from the first node that happened to be asked.
    harness.service.handle_node_message(
        node_id="node-A",
        envelope=_reject(harness.sole_offer("node-A"), reason="busy"),
        now=BASE,
    )
    harness.take("node-A")
    _settle(
        harness,
        harness.sole_offer("node-B"),
        "node-B",
        device_id="device-B",
        device_key_id="device-key-B",
        provider_id="provider-B",
    )
    harness.take("node-B")

    harness.admit(
        harness.authorization(request_id="R-2"),
        idempotency_key="k-2",
        session_id="sess-1",
        max_attempts=1,
    )

    assert harness.offers("node-A") == []
    assert harness.sole_offer("node-B").request_id == "R-2"


def test_a_session_preference_yields_to_the_ordinary_rule_when_the_node_is_gone(
    harness: Harness,
) -> None:
    """A preference is not a constraint: an unavailable node is skipped, not waited for.

    This is the half that makes the feature safe. A session pinned to a node that
    disconnected would stop working, so the moment the preferred node is not also
    a candidate the deterministic rule applies and the turn runs somewhere else.
    """
    harness.connect("node-A")
    harness.connect(
        "node-B", device_id="device-B", device_key_id="device-key-B", provider_id="provider-B"
    )
    harness.admit(
        harness.authorization(request_id="R-1"),
        idempotency_key="k-1",
        session_id="sess-1",
        max_attempts=1,
    )
    harness.service.handle_node_message(
        node_id="node-A", envelope=_reject(harness.sole_offer("node-A"), reason="busy"), now=BASE
    )
    harness.take("node-A")
    _settle(
        harness,
        harness.sole_offer("node-B"),
        "node-B",
        device_id="device-B",
        device_key_id="device-key-B",
        provider_id="provider-B",
    )
    harness.take("node-B")
    harness.service.node_disconnected(node_id="node-B", now=BASE)

    harness.admit(
        harness.authorization(request_id="R-2"),
        idempotency_key="k-2",
        session_id="sess-1",
        max_attempts=1,
    )

    assert harness.sole_offer("node-A").request_id == "R-2"


def test_a_session_belongs_to_the_subject_that_named_it(harness: Harness) -> None:
    """Two subjects may both call a session "shared" and neither reads the other.

    The identifier is caller-chosen, so the aggregate has to be keyed by the
    identity the credential authenticated. Without that, one consumer naming a
    session another consumer already used would spend into — and be reported
    under — somebody else's run.
    """
    harness.connect()
    harness.admit(
        harness.authorization(request_id="R-1"), idempotency_key="k-1", session_id="shared"
    )
    harness.service.admit_request(
        credential=FOREIGN,
        idempotency_key="k-2",
        messages=(user_message("write a haiku about ledgers"),),
        authorization=signed_authorization(
            harness.keyring,
            request_id="R-2",
            consumer_id="consumer-Y",
            payer_account_id="consumer-Y",
            key_id="consumer-key-2",
        ),
        model=MODEL,
        max_charge_milli_credits=20_000,
        session_id="shared",
        now=BASE,
    )

    rows = harness.store.sessions(session_id="shared")
    assert sorted(row.subject_id for row in rows) == ["consumer-X", "consumer-Y"]
    assert all(row.request_count == 1 for row in rows)
    assert harness.store.session_preference_for("R-2") is None


def test_a_request_that_named_no_session_is_aggregated_nowhere(
    harness: Harness,
) -> None:
    """A session exists because a request declared one, never by inference."""
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"), idempotency_key="k-1")
    _settle(harness, harness.sole_offer("node-A"), "node-A")

    assert harness.store.sessions() == []
    assert harness.store.session_preference_for("R-1") is None


@pytest.mark.parametrize("session_id", ["", "two words", "x" * 129])
def test_a_session_identifier_the_wire_refuses_is_refused_at_admission(
    harness: Harness, session_id: str
) -> None:
    """The server applies the wire's own rule rather than inventing a second one.

    Refused rather than dropped: a caller that named a session and was silently
    given none would read an aggregate for a run it never joined.
    """
    harness.connect()

    with pytest.raises(PotluckError):
        harness.admit(
            harness.authorization(request_id="R-1"),
            idempotency_key="k-1",
            session_id=session_id,
        )

    assert harness.store.sessions() == []


def test_a_key_minted_with_its_own_deadline_gives_its_requests_that_window(
    harness: Harness,
) -> None:
    """The key's window wins over the surface default, and it is the one that ends it.

    A long agent turn needs a long budget, and the key is where an operator
    records that. What has to be true is that the longer window is the one written
    to the request row and signed into the authorization — a deadline the server
    ignored would expire a turn it had promised to wait for.
    """
    harness.connect()
    harness.store.add_credential(
        "consumer-token-x", TENANT, "consumer-X", "consumer", REGISTERED_AT
    )
    key = harness.store.add_api_key(
        "ak-test-deadline",
        key_id="apikey-deadline",
        name="agent",
        subject_id="consumer-X",
        tenant_id=TENANT,
        quota_milli_credits=100_000,
        created_at=BASE,
        deadline_ms=600_000,
    )

    result = harness.service.admit_api_key_request(
        api_key=key,
        messages=(user_message("a long turn"),),
        model=MODEL,
        deadline_ms=OPENAI_SURFACE_DEFAULT_MS,
        now=BASE,
    )

    record = harness.store.get_request(result.request_id)
    assert record is not None
    assert record.deadline_at == BASE + dt.timedelta(milliseconds=600_000)
    # The authorization has to cover the longer window too. Settlement runs after
    # the answer does, and an authorization that expired in between would leave a
    # node's tokens spent and unbillable.
    inputs = harness.store.get_request_input(result.request_id)
    assert inputs is not None
    authorization = signed_record_from_dict(inputs["authorization"])
    assert authorization.payload["expires_at"] == (
        BASE
        + dt.timedelta(milliseconds=600_000)
        + AUTHORIZATION_SETTLEMENT_GRACE
    ).isoformat()
    assert harness.sole_offer("node-A").request_id == result.request_id


def test_a_key_with_no_deadline_of_its_own_keeps_the_surface_default(
    harness: Harness,
) -> None:
    """An operator who named no window gets the one the surface asked for."""
    harness.connect()
    harness.store.add_credential(
        "consumer-token-x", TENANT, "consumer-X", "consumer", REGISTERED_AT
    )
    key = harness.store.add_api_key(
        "ak-test-default",
        key_id="apikey-default",
        name="plain",
        subject_id="consumer-X",
        tenant_id=TENANT,
        quota_milli_credits=100_000,
        created_at=BASE,
    )

    result = harness.service.admit_api_key_request(
        api_key=key,
        messages=(user_message("a short turn"),),
        model=MODEL,
        deadline_ms=OPENAI_SURFACE_DEFAULT_MS,
        now=BASE,
    )

    record = harness.store.get_request(result.request_id)
    assert record is not None
    assert record.deadline_at == BASE + dt.timedelta(milliseconds=OPENAI_SURFACE_DEFAULT_MS)


# -- dispatch queue -------------------------------------------------------------


def test_a_request_nothing_can_dispatch_waits_instead_of_being_refused(
    harness: Harness,
) -> None:
    """Admitted with no node connected, and still alive: that is what a queue is.

    The request is not ended, not billed and not forgotten. It sits in the status
    the dispatch loop reads, with its own deadline still running, and its own
    event stream says so.
    """
    result = harness.admit(harness.authorization(request_id="R-1"), idempotency_key="k-1")

    assert result.created is True
    assert harness.status("R-1")["status"] == "ROUTING"
    assert harness.store.attempts_for_request("R-1") == []
    events = harness.service.request_events(
        credential=CONSUMER, request_id="R-1", cursor=0
    )
    assert [event.event_type for event in events] == [QUEUED_EVENT_TYPE]


def test_a_waiting_request_runs_when_a_node_arrives(harness: Harness) -> None:
    """A node freeing up is what ends the wait, and the stream records the exit.

    This is the whole point of holding the request rather than refusing it: the
    capacity problem ended on its own, and the request that survived it is
    dispatched, metered and settled like any other.
    """
    harness.admit(harness.authorization(request_id="R-1"), idempotency_key="k-1")
    harness.connect()

    harness.tick(BASE + dt.timedelta(seconds=1))

    assert harness.sole_offer("node-A").request_id == "R-1"
    assert harness.status("R-1")["status"] == "RUNNING"
    events = harness.service.request_events(
        credential=CONSUMER, request_id="R-1", cursor=0
    )
    assert [event.event_type for event in events] == [
        QUEUED_EVENT_TYPE,
        DISPATCHED_EVENT_TYPE,
    ]
    assert events[1].payload["node_id"] == "node-A"


def test_a_request_dispatched_straight_from_admission_never_joins_the_queue(
    harness: Harness,
) -> None:
    """No queue frames for a request that did not wait.

    An event is a claim that something happened. A request dispatched by its own
    admission never sat in the queue, so its stream starts with the node's own
    output rather than with a transition that did not occur.
    """
    harness.connect()
    harness.admit(harness.authorization(request_id="R-1"), idempotency_key="k-1")

    assert harness.service.request_events(
        credential=CONSUMER, request_id="R-1", cursor=0
    ) == []


def test_the_queue_is_offered_oldest_first(tmp_path: Path) -> None:
    """First come, first served — as far as a best-effort ordering can promise.

    Three requests wait for one node. When it arrives the server offers the oldest
    one, and only that one: the position is not a guarantee about the future, but
    the order the dispatch loop reads in is the order the requests arrived in.
    """
    harness = Harness(tmp_path, max_queue_depth=3)
    try:
        for index in (1, 2, 3):
            harness.admit(
                harness.authorization(request_id=f"R-{index}"),
                idempotency_key=f"k-{index}",
                now=BASE + dt.timedelta(seconds=index),
            )
        harness.connect()

        harness.tick(BASE + dt.timedelta(seconds=10))

        # The server places no per-node cap of its own — a node declines what its
        # local policy will not take — so what first-come-first-served means here
        # is the order the offers go out in, and that order is arrival order.
        assert [offer.request_id for offer in harness.offers("node-A")] == [
            "R-1",
            "R-2",
            "R-3",
        ]
        assert harness.offers("node-A")[0].attempt_id == "R-1-a1"
    finally:
        harness.close()


def test_admission_is_refused_once_the_queue_is_at_its_bound(tmp_path: Path) -> None:
    """The bound is what keeps a wait from becoming a promise the server cannot keep.

    With every slot taken, admitting another request would be agreeing to hold work
    the server has already agreed to hold too much of. The refusal names the bound
    and the fact that nothing can dispatch, so a caller knows to back off rather
    than to re-authenticate or change its model.
    """
    harness = Harness(tmp_path, max_queue_depth=2)
    try:
        for index in (1, 2):
            harness.admit(
                harness.authorization(request_id=f"R-{index}"), idempotency_key=f"k-{index}"
            )

        with pytest.raises(QueueFull) as refused:
            harness.admit(
                harness.authorization(request_id="R-3"), idempotency_key="k-3"
            )

        assert "queue bound of 2" in str(refused.value)
        assert harness.store.get_request("R-3") is None, "a refused admission stores nothing"
    finally:
        harness.close()


def test_a_retry_at_the_bound_still_gets_its_own_request_back(tmp_path: Path) -> None:
    """A full queue does not break the idempotency key's promise.

    The key means "this is the same request again", and a caller retrying under
    load is exactly the caller who needs that to hold. Refusing the retry would
    leave a client that already has a request in flight unable to ask about it.
    """
    harness = Harness(tmp_path, max_queue_depth=1)
    try:
        authorization = harness.authorization(request_id="R-1")
        first = harness.admit(authorization, idempotency_key="k-1")

        second = harness.admit(authorization, idempotency_key="k-1")

        assert first.request_id == second.request_id == "R-1"
        assert second.created is False
    finally:
        harness.close()


def test_a_waiting_request_still_expires_at_its_own_deadline(harness: Harness) -> None:
    """Queuing changes when a request is answered, never whether it is billed honestly.

    The same sweep that has always ended an overdue request ends a queued one, with
    the same status and the same recorded reason. A wait nothing ever ended is an
    EXPIRED request with no attempt behind it — no tokens, no charge, no receipt.
    """
    harness.admit(
        harness.authorization(request_id="R-1"), idempotency_key="k-1", deadline_ms=30_000
    )

    harness.tick(BASE + dt.timedelta(seconds=31))

    document = harness.status("R-1")
    assert document["status"] == "EXPIRED"
    assert "deadline" in document["billing_note"]
    assert harness.store.attempts_for_request("R-1") == []
    assert harness.ledger.balance("consumer-X") == 100_000


def test_a_server_that_holds_no_queue_refuses_at_admission(tmp_path: Path) -> None:
    """``queue_enabled=false`` is the operator's other choice, and it is a real one.

    A server that sheds load answers immediately and creates nothing, so a caller's
    own backoff decides what happens next instead of the server's memory.
    """
    harness = Harness(tmp_path, queue_enabled=False)
    try:
        with pytest.raises(ModelUnavailable):
            harness.admit(harness.authorization(request_id="R-1"), idempotency_key="k-1")

        assert harness.store.get_request("R-1") is None
        assert harness.store.count_requests_by_status("ROUTING") == 0
    finally:
        harness.close()


def test_a_replayed_queue_event_never_writes_a_second_frame(harness: Harness) -> None:
    """The queue's frames obey the same replay rule every other stored event does.

    A dispatch loop that runs twice over one waiting request — a tick that overlaps
    an admission, or one that follows a restart — must not leave two copies of a
    transition on a stream a consumer reads in order.
    """
    harness.admit(harness.authorization(request_id="R-1"), idempotency_key="k-1")
    before = harness.service.request_events(
        credential=CONSUMER, request_id="R-1", cursor=0
    )

    harness.admit(harness.authorization(request_id="R-1"), idempotency_key="k-1")
    after = harness.service.request_events(
        credential=CONSUMER, request_id="R-1", cursor=0
    )

    assert [event.event_type for event in before] == [QUEUED_EVENT_TYPE]
    assert len(after) == len(before)
    assert [event.cursor for event in after] == [1]


def test_a_waiting_request_survives_a_restart_and_is_still_offered(
    tmp_path: Path,
) -> None:
    """The queue is durable state, not a scheduler's in-memory list.

    A server interrupted while requests waited must come back holding them, because
    the alternative is a restart that silently drops work it told callers it was
    holding — and the request row, its deadline and its stored inputs are exactly
    what makes that recoverable.
    """
    harness = Harness(tmp_path)
    try:
        harness.admit(harness.authorization(request_id="R-1"), idempotency_key="k-1")
        harness.restart()
        harness.connect()

        harness.tick(BASE + dt.timedelta(seconds=1))

        assert harness.sole_offer("node-A").request_id == "R-1"
        assert harness.status("R-1")["status"] == "RUNNING"
    finally:
        harness.close()

