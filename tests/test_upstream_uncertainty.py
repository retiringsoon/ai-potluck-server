"""G04 — an upstream call with no answer stays *unknown*, never "never submitted".

What this file verifies (plan v0.3 §5.1 B G04)
------------------------------------------------
When a request has been handed to the upstream but the response is lost — a read
timeout is the canonical case — two facts must be kept apart:

1. **a submission was attempted**, and
2. **a successful response was received**.

A node that only counts fact 2 cannot tell a timeout from an attempt that never
ran, so it reports ``certainty="not_submitted"`` for a call that may have
consumed tokens. The server then treats the attempt as `never_started`, retries
it, and the operator's upstream quota is spent twice while the first
consumption is recorded as nothing. This file pins, on both sides of the wire:

* **G04·a (node)** the durable facts a timed-out call leaves behind — the
  adapter's own call counter versus the execution row's ``upstream_calls`` — and
  the state/certainty the node reports for it.
* **G04·b (server)** a failure report never becomes zero usage: the attempt's
  usage goes to ``UNKNOWN`` with a ``NULL`` total and no settlement is recorded.
* **G04·c (server)** a ``not_submitted`` report opens exactly one replacement
  attempt, and the per-request attempt budget (`max_attempts`) bounds the total.
* **G04·d (server)** an ``unknown`` report is **not** retried; the request
  converges as ``OUTCOME_UNKNOWN`` with usage left unknown.
* **G04·e (server)** with two concurrent requests, only the one whose node
  reported an un-submitted failure is retried; the other settles normally, and a
  superseded branch can never publish output.

The defect, and its fix
-----------------------
`Connector` used to record ``upstream_calls`` **only after** the adapter
returned, so an in-process timeout left ``upstream_calls == 0`` with
``state == "FAILED"`` and `_certainty_for` reported ``not_submitted`` — a claim
the node could not support. The fix gives the dispatch boundary a name:
adapters raise ``AdapterOutcomeUnknown`` when the request was sent but the
answer was lost, and the connector answers that by recording the submission,
finishing the execution ``UNKNOWN``, and spooling **no** failure event — the
server's tick probe and reconciliation decide, so a possibly-running call is
never retried into a second bill. The formerly ``xfail(strict=True)`` test now
runs as a plain assertion of the fixed behaviour.

What this file canNOT prove
---------------------------
* It does not prove the node survives a real network timeout; the adapter is a
  test-local stand-in that raises the error the connector treats as one.
* It does not exercise the socket, the WebSocket framing, or TLS: every node
  message goes through `Connector.handle_message` and every server message
  through `GatewayService.handle_node_message`.
* It does not prove the HTTP adapter classifies every real transport failure
  exactly; only that the boundary contract (unavailable vs outcome-unknown vs
  definitive failure) is honoured by the connector and the wire.
"""

from __future__ import annotations

import datetime as dt
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from aipotluck.adapters import AdapterOutcomeUnknown, AdapterResult
from aipotluck.canonical import sign_payload
from aipotluck.connector import Connector, ConnectorConfig
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
    compute_request_digest,
    user_message,
)
from conftest import Keyring

from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import Credential, ServerStore

BASE = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
MODEL = "coding-pool"
DELIVERY = "buffered_complete"


# --------------------------------------------------------------------------
# A test-local adapter that models "the request went out, the answer never came"
# --------------------------------------------------------------------------


@dataclass
class _TimingOutAdapter:
    """An adapter whose upstream request is issued but whose response is lost.

    `calls` counts requests the adapter actually put on the wire; the connector
    never learns this number, which is exactly the gap under test.
    """

    name: str = "timing-out-upstream"
    model: str = "fake-model-v1"
    supports_streaming: bool = False
    calls: int = 0
    detail: str = "upstream read timed out after the request was sent"

    def complete(
        self, messages: Any, *, request_digest: str, parameters: Any
    ) -> AdapterResult:
        """Record the call, then fail as a lost response does."""
        del messages, request_digest, parameters
        self.calls += 1
        raise AdapterOutcomeUnknown(self.detail)


@dataclass
class _UsageLessAdapter:
    """An adapter that answers, but reports no usage block at all."""

    name: str = "usage-less-upstream"
    model: str = "fake-model-v1"
    supports_streaming: bool = False
    calls: int = 0

    def complete(
        self, messages: Any, *, request_digest: str, parameters: Any
    ) -> AdapterResult:
        """Return a completion with no usage, as a provider that omits it does."""
        del messages, request_digest, parameters
        self.calls += 1
        return AdapterResult(
            chunks=("an answer",), usage=None, provider_style="openai", upstream_calls=self.calls
        )


@dataclass
class _Node:
    """A real `Connector` over a real `NodeStore`, driven without a socket."""

    connector: Connector
    adapter: Any
    received: list[Envelope] = field(default_factory=list)

    def offer(self, offer: AttemptOffer) -> Envelope:
        """Send an offer and return the node's single reply."""
        replies = self.connector.handle_message(
            Envelope("attempt.offer", offer.to_payload())
        )
        assert len(replies) == 1
        return replies[0]

    def execute(self, offer: AttemptOffer) -> None:
        """Start the attempt's execution worker."""
        self.connector.handle_message(
            Envelope(
                "attempt.execute",
                AttemptRef(offer.request_id, offer.attempt_id, offer.epoch).to_payload(),
            )
        )

    def query(self, offer: AttemptOffer) -> dict[str, Any]:
        """Ask the node what happened to the attempt; return the state payload."""
        replies = self.connector.handle_message(
            Envelope(
                "attempt.query",
                {"request_id": offer.request_id, "attempt_id": offer.attempt_id},
            )
        )
        assert len(replies) == 1
        assert replies[0].type == "attempt.state"
        return replies[0].payload

    def spooled(self, attempt_id: str) -> list[Envelope]:
        """Return the still-unacknowledged events spooled for an attempt."""
        return [
            Envelope("attempt.event", record.payload)
            for record in self.connector.store.unacked_spool(attempt_id)
        ]


def _node(tmp_path: Path, adapter: Any, **overrides: Any) -> _Node:
    """Build a connector over a fresh node database with `adapter`."""
    _public_b64, private_b64 = generate_key_pair()
    values: dict[str, Any] = {
        "server_url": "ws://127.0.0.1:1/v1/node-link",
        "node_id": "node-1",
        "device_id": "device-1",
        "device_key_id": "device-key-1",
        "provider_id": "provider-1",
        "database_path": str(tmp_path / "node.db"),
        "token": "node-token-not-logged",
        "adapter_name": adapter.name,
        "model": adapter.model,
        "device_private_key_b64": private_b64,
        "delta_chars": 2,
    }
    values.update(overrides)
    return _Node(connector=Connector(ConnectorConfig(**values), adapter=adapter), adapter=adapter)


def _wire_offer(
    *, attempt_id: str = "A1", request_id: str = "R1", max_milli_credits: int = 1_000
) -> AttemptOffer:
    """Build an offer whose `permit_hash` matches its own fields."""
    from aipotluck.wire import compute_permit_hash

    permit_hash = compute_permit_hash(
        request_id=request_id,
        attempt_id=attempt_id,
        epoch=1,
        model=MODEL,
        request_digest="sha256:req",
        max_milli_credits=max_milli_credits,
        authorization_hash="auth-1",
    )
    return AttemptOffer(
        request_id=request_id,
        attempt_id=attempt_id,
        epoch=1,
        resource_id="node-1",
        model=MODEL,
        request_digest="sha256:req",
        max_milli_credits=max_milli_credits,
        deadline_ms=60_000,
        delivery_mode="buffered_complete",
        messages=(user_message("hi"),),
        parameters={},
        authorization_hash="auth-1",
        permit_hash=permit_hash,
    )


def _wait_until(predicate: Callable[[], bool], *, timeout: float = 5.0) -> None:
    """Poll `predicate` until it is true or fail the test."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("condition never became true")


def _usage_less_report_measurement(events: list[Envelope]) -> dict[str, Any]:
    """Return the measurement a spooled `usage.final` carries (via its report)."""
    for envelope in events:
        if envelope.payload["event_type"] == "usage.final":
            return envelope.payload["report"]["payload"]["measurement"]
    raise AssertionError("no usage.final was spooled")


# --------------------------------------------------------------------------
# G04·a — the node side: what a timed-out upstream call leaves behind
# --------------------------------------------------------------------------


def test_a_timed_out_call_counts_as_a_request_but_not_as_a_response(tmp_path: Path) -> None:
    """The durable row keeps the submission fact and refuses to guess the outcome.

    The adapter issued one request; the execution row must carry that fact
    (``upstream_calls == 1``) while the outcome stays ``UNKNOWN`` — the node
    cannot say whether the upstream ran to completion. No failure event is
    spooled, because a clean-failure report would invite a replacement attempt
    while the original call may still be running upstream.
    """
    node = _node(tmp_path, _TimingOutAdapter())
    offer = _wire_offer()
    assert node.offer(offer).type == "attempt.accept"
    node.execute(offer)
    _wait_until(
        lambda: node.connector.store.get_execution("A1") is not None
        and node.connector.store.get_execution("A1").finished_at is not None  # type: ignore[union-attr]
    )

    record = node.connector.store.get_execution("A1")
    assert record is not None
    assert node.adapter.calls == 1, "the request did reach the upstream"
    assert record.upstream_calls == 1, "the submission is a durable fact, not a success"
    assert record.state == "UNKNOWN", "whether the upstream ran is unknowable"

    # No failure event: the outcome is the server's to reconcile, via the tick
    # probe asking for this attempt's state.
    assert node.spooled("A1") == []


def test_a_timed_out_upstream_call_is_reported_as_unknown(tmp_path: Path) -> None:
    """A sent-but-unanswered call must be reported `unknown`, never `not_submitted`.

    The adapter raised ``AdapterOutcomeUnknown`` — the request bytes were sent,
    the answer was lost — so the node cannot say whether the upstream ran. The
    attempt state must carry ``certainty="unknown"`` with the submission visible
    (``upstream_calls >= 1``) and no fabricated failure, because a clean failure
    report would let the server open a replacement attempt while the original
    call may still be running upstream.
    """
    node = _node(tmp_path, _TimingOutAdapter())
    offer = _wire_offer()
    node.offer(offer)
    node.execute(offer)
    _wait_until(
        lambda: node.connector.store.get_execution("A1") is not None
        and node.connector.store.get_execution("A1").finished_at is not None  # type: ignore[union-attr]
    )
    assert node.adapter.calls == 1, "the upstream request was definitely issued"

    state = node.query(offer)
    assert state["state"] == "UNKNOWN"
    assert state["certainty"] == "unknown"
    assert state["upstream_calls"] >= 1


def test_a_completion_without_usage_is_labelled_unknown_not_silently_zero(
    tmp_path: Path,
) -> None:
    """A successful call that reported no usage is marked `unknown`, not assumed free.

    The totals are 0 because no numbers arrived, but the completeness flag carries
    the truth: the node says "unknown" rather than presenting 0 as a measurement.
    """
    node = _node(tmp_path, _UsageLessAdapter())
    offer = _wire_offer()
    assert node.offer(offer).type == "attempt.accept"
    node.execute(offer)
    # Wait for the terminal report itself, not for "anything spooled": the
    # buffered worker spools its `output.delta` chunks before `usage.final`, so
    # the first spooled envelope is usually a delta and reading the measurement
    # at that moment finds no report at all.
    _wait_until(
        lambda: any(
            envelope.payload["event_type"] == "usage.final" for envelope in node.spooled("A1")
        )
    )

    measurement = _usage_less_report_measurement(node.spooled("A1"))
    assert measurement["usage"]["completeness"] == "unknown"
    assert measurement["usage"]["input_total"] == 0
    assert measurement["usage"]["output_total"] == 0

    usage_final = next(
        envelope
        for envelope in node.spooled("A1")
        if envelope.payload["event_type"] == "usage.final"
    )
    assert usage_final.payload["usage"]["completeness"] == "unknown"


# --------------------------------------------------------------------------
# The server side: a real gateway over a real SQLite file
# --------------------------------------------------------------------------


class _Server:
    """A real `GatewayService` over a real store, with one connected node."""

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
        self.key_id: str = ""
        self.credential: Credential | None = None

    def close(self) -> None:
        """Close the store."""
        self.store.close()

    def connect(self) -> None:
        """Register the node link."""
        self.service.register_node(
            credential=Credential(tenant_id="tenant-a", subject_id="node-A", role="node"),
            hello=NodeHello(
                node_id="node-A",
                device_id="device-A",
                device_key_id="device-key-A",
                provider_id="provider-A",
                adapter_name="mock-adapter",
                model=MODEL,
                policy=NodePolicy(
                    share_enabled=True, max_concurrency=2, max_local_reserved_milli_credits=0
                ),
            ),
            enqueue=self.received.append,
            now=BASE,
        )

    def join(self, code: str) -> None:
        """Mint `code`, redeem it, and remember the credential."""
        self.store.add_invite(code, "consumer", "auto", max_uses=1, created_at=BASE)
        public_b64, private_b64 = generate_key_pair()
        joined = self.service.join(
            invite_code=code,
            identity={"public_key_b64": public_b64, "display_name": None},
            device=None,
            server_url="http://server.test",
            now=BASE,
        )
        self.joined_private = load_private_key(private_b64)
        self.key_id = joined.key_id
        self.credential = self.service.authenticate_signed_request(
            **_auth_kwargs(self.joined_private, self.key_id), now=BASE
        )

    # -- driving ------------------------------------------------------------

    def admit(self, *, request_id: str, messages: tuple[Any, ...]) -> AttemptOffer:
        """Admit one request and return the offer it produced.

        Every offer the server sends is accumulated in `received`, so a test can
        ask for the offers of one request after several admissions.
        """
        assert self.credential is not None
        self.service.admit_request(
            credential=self.credential,
            idempotency_key=f"idem-{request_id}",
            messages=messages,
            authorization=_authorization(
                self.joined_private,
                self.key_id,
                request_id=request_id,
                messages=messages,
            ),
            model=MODEL,
            max_charge_milli_credits=20_000,
            delivery_mode=DELIVERY,
            max_attempts=2,
            now=BASE,
        )
        return self.offers(request_id)[-1]

    def offers(self, request_id: str | None = None) -> list[AttemptOffer]:
        """Return the offers the server sent, optionally for one request."""
        return [
            AttemptOffer.from_payload(envelope.payload)
            for envelope in self.received
            if envelope.type == "attempt.offer"
            and (request_id is None or envelope.payload["request_id"] == request_id)
        ]

    @staticmethod
    def acceptance_hash(offer: AttemptOffer) -> str:
        """Return the acceptance hash a node would compute for `offer`."""
        return compute_acceptance_hash(
            permit_hash=offer.permit_hash,
            request_id=offer.request_id,
            attempt_id=offer.attempt_id,
            epoch=offer.epoch,
            adapter_name="mock-adapter",
            accepted_at=BASE,
        )

    def accept(self, offer: AttemptOffer) -> str:
        """Record the node's acceptance and return the acceptance hash."""
        acceptance = self.acceptance_hash(offer)
        self.service.handle_node_message(
            node_id="node-A",
            envelope=Envelope(
                "attempt.accept",
                AttemptDecision(
                    ref=AttemptRef(offer.request_id, offer.attempt_id, offer.epoch),
                    accepted=True,
                    permit_hash=offer.permit_hash,
                    acceptance_hash=acceptance,
                ).to_payload(),
            ),
            now=BASE,
        )
        return acceptance

    def node_failed(self, offer: AttemptOffer, *, seq: int = 1, detail: str) -> list[Envelope]:
        """Deliver an `attempt.failed` event for `offer`."""
        return self.service.handle_node_message(
            node_id="node-A",
            envelope=Envelope(
                "attempt.event",
                AttemptEvent(
                    ref=AttemptRef(offer.request_id, offer.attempt_id, offer.epoch),
                    seq=seq,
                    event_type="attempt.failed",
                    outcome="failed",
                    detail=detail,
                    final=True,
                ).to_payload(),
            ),
            now=BASE,
        )

    def node_state(
        self,
        offer: AttemptOffer,
        *,
        state: str,
        certainty: str,
        upstream_calls: int,
    ) -> None:
        """Deliver the node's answer to an `attempt.query`."""
        self.service.handle_node_message(
            node_id="node-A",
            envelope=Envelope(
                "attempt.state",
                AttemptState(
                    ref=AttemptRef(offer.request_id, offer.attempt_id, offer.epoch),
                    state=state,
                    certainty=certainty,
                    upstream_calls=upstream_calls,
                    last_seq=0,
                ).to_payload(),
            ),
            now=BASE,
        )

    def delta(self, offer: AttemptOffer, seq: int, text: str) -> list[Envelope]:
        """Deliver an `output.delta` for `offer`."""
        return self.service.handle_node_message(
            node_id="node-A",
            envelope=Envelope(
                "attempt.event",
                AttemptEvent(
                    ref=AttemptRef(offer.request_id, offer.attempt_id, offer.epoch),
                    seq=seq,
                    event_type="output.delta",
                    text=text,
                ).to_payload(),
            ),
            now=BASE,
        )

    def usage(self, offer: AttemptOffer, acceptance: str) -> list[Envelope]:
        """Deliver the device-signed `usage.final` that settles `offer`."""
        report = UsageReport(
            report_id=f"rep-{offer.attempt_id}",
            permit_id=offer.permit_hash,
            permit_hash=offer.permit_hash,
            acceptance_hash=acceptance,
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
        ).sign(self.keyring.private["device-key-A"], "device-key-A")
        return self.service.handle_node_message(
            node_id="node-A",
            envelope=Envelope(
                "attempt.event",
                AttemptEvent(
                    ref=AttemptRef(offer.request_id, offer.attempt_id, offer.epoch),
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
            ),
            now=BASE,
        )

    def status(self, request_id: str) -> dict[str, Any]:
        """Return a request's status document."""
        assert self.credential is not None
        return self.service.request_status(credential=self.credential, request_id=request_id)


@pytest.fixture
def server(tmp_path: Path) -> _Server:
    """Return a server over a fresh store, closed at the end of the test."""
    built = _Server(tmp_path)
    built.connect()
    built.join("code-g04")
    try:
        yield built
    finally:
        built.close()


# --------------------------------------------------------------------------
# G04·b — a failed upstream call never becomes zero usage
# --------------------------------------------------------------------------


def test_a_failed_upstream_call_leaves_usage_unknown_and_never_zero(server: _Server) -> None:
    """A timeout is a failed attempt whose usage is unknown, not a free one.

    The node reports the failure and nothing else. The server must move the
    attempt's usage to `UNKNOWN` with a `NULL` total, settle nothing and mint no
    receipt — the opposite of writing a 0 that would later read as "free".
    """
    offer = server.admit(request_id="req-to", messages=(user_message("timed out"),))
    server.accept(offer)
    replies = server.node_failed(offer, seq=1, detail="upstream read timed out")
    assert [reply.type for reply in replies] == ["event.ack"]

    attempt = server.store.get_attempt(offer.attempt_id)
    assert attempt is not None
    assert attempt.usage_status == "UNKNOWN"
    assert attempt.usage_tokens is None, "an unknown consumption is never stored as zero"
    assert server.store.get_settlement("req-to", 1) is None
    assert server.store.log_size() == 0
    assert server.service.balance("provider-A/pending") == 0
    document = server.status("req-to")
    assert document["settlement"] is None
    assert document["output"]["committed"] is False


# --------------------------------------------------------------------------
# G04·c — a `not_submitted` report opens exactly one replacement, within the cap
# --------------------------------------------------------------------------


def test_a_not_submitted_report_opens_one_replacement_and_respects_the_cap(
    server: _Server,
) -> None:
    """Retries are bounded by the signed `max_attempts`, and branches are demoted.

    `max_attempts` is 2 for this request. The first report opens attempt 2, and a
    second identical report exhausts the budget instead of opening attempt 3. Each
    time a branch is opened the previous one is demoted, so only one branch can
    ever be output-eligible.
    """
    first = server.admit(request_id="req-cap", messages=(user_message("retry me"),))
    server.accept(first)
    server.node_state(
        first, state="FAILED", certainty="not_submitted", upstream_calls=0
    )

    replacements = server.offers("req-cap")
    assert [offer.attempt_id for offer in replacements] == ["req-cap-a1", "req-cap-a2"]
    second = replacements[1]
    assert second.attempt_id != first.attempt_id

    attempts = server.store.attempts_for_request("req-cap")
    assert len(attempts) == 2
    eligible = [attempt.attempt_id for attempt in attempts if attempt.output_eligible]
    assert eligible == ["req-cap-a2"], "only the newest branch may publish output"

    # A second un-submitted report cannot open a third attempt: the budget is spent.
    server.accept(second)
    server.node_state(
        second, state="FAILED", certainty="not_submitted", upstream_calls=0
    )
    assert len(server.store.attempts_for_request("req-cap")) == 2
    assert server.status("req-cap")["status"] == "FAILED"
    assert server.store.get_attempt("req-cap-a2") is not None


# --------------------------------------------------------------------------
# G04·d — an `unknown` report is not retried
# --------------------------------------------------------------------------


def test_an_unknown_report_is_not_retried_and_keeps_usage_unknown(server: _Server) -> None:
    """When the node cannot say whether it ran, the server does not guess by retrying.

    `certainty="unknown"` is the one answer that must *not* produce a replacement
    offer: a retry could double-consume the upstream. The request converges as
    `OUTCOME_UNKNOWN`, usage stays `NULL`, and no receipt is issued.
    """
    offer = server.admit(request_id="req-unknown", messages=(user_message("maybe ran"),))
    server.accept(offer)
    server.node_state(offer, state="FAILED", certainty="unknown", upstream_calls=0)

    assert server.offers("req-unknown") == [offer], "no replacement attempt is offered"
    assert len(server.store.attempts_for_request("req-unknown")) == 1
    attempt = server.store.get_attempt(offer.attempt_id)
    assert attempt is not None
    assert attempt.status == "OUTCOME_UNKNOWN"
    assert attempt.usage_status == "UNKNOWN"
    assert attempt.usage_tokens is None
    assert server.store.get_settlement("req-unknown", 1) is None
    assert server.status("req-unknown")["status"] == "FAILED"


# --------------------------------------------------------------------------
# G04·e — one of two requests times out; only it is retried
# --------------------------------------------------------------------------


def test_of_two_requests_only_the_timed_out_one_is_retried(server: _Server) -> None:
    """The healthy request settles untouched while the failed one gets one retry.

    Both requests are admitted while the node is connected. The first is reported
    as an un-submitted failure, which opens a replacement; the second accepts,
    publishes output and reports usage, and must settle with exactly one attempt.
    A late delta from the demoted first branch is refused with a `superseded`
    cancel, so the two branches can never both publish output.
    """
    timed_out = server.admit(request_id="req-1", messages=(user_message("will time out"),))
    healthy = server.admit(request_id="req-2", messages=(user_message("will succeed"),))
    server.accept(timed_out)
    healthy_acceptance = server.accept(healthy)

    # The healthy request publishes output and settles.
    server.delta(healthy, 1, "the answer")
    replies = server.usage(healthy, healthy_acceptance)
    assert [reply.type for reply in replies] == ["event.ack"]
    assert server.status("req-2")["status"] == "SUCCEEDED"
    assert server.status("req-2")["settlement"]["log_index"] == 0
    assert len(server.store.attempts_for_request("req-2")) == 1

    # The timed-out request is reported and gets exactly one replacement.
    server.node_state(timed_out, state="FAILED", certainty="not_submitted", upstream_calls=0)
    offers = server.offers("req-1")
    assert [offer.attempt_id for offer in offers] == ["req-1-a1", "req-1-a2"]
    assert server.offers("req-2") == [healthy], "the healthy request is not retried"
    assert len(server.store.attempts_for_request("req-2")) == 1

    # A delta from the demoted branch is refused and told to wind down.
    late = server.delta(timed_out, 2, "stale text")
    assert [reply.type for reply in late] == ["attempt.cancel", "event.ack"]
    assert late[0].payload["origin"] == "superseded"
    assert server.store.output_commit("req-1") is None

    # And the healthy request's settlement is still the only one on the log.
    assert server.store.log_size() == 1
    assert server.store.get_settlement("req-2", 1) is not None
    assert server.store.get_settlement("req-1", 1) is None
    assert server.service.balance("provider-A/pending") == 1_000


# --------------------------------------------------------------------------
# The server's retry rule is only as good as the node's classification
# --------------------------------------------------------------------------


def test_the_server_retries_because_the_node_claimed_not_submitted(server: _Server) -> None:
    """The coupling the node-side defect exploits, stated at the server.

    The server's re-offer is not a bug: `not_submitted` with zero upstream calls
    is exactly the contract's trigger for a retry. The bug is that a timed-out
    call *is* classified that way (see
    `test_a_timed_out_upstream_call_is_reported_as_unknown`), so this test shows
    the exact path by which the node's misclassification spends the upstream
    quota twice.
    """
    offer = server.admit(request_id="req-couple", messages=(user_message("one upstream call"),))
    server.accept(offer)
    server.node_state(offer, state="FAILED", certainty="not_submitted", upstream_calls=0)

    offered = server.offers("req-couple")
    assert len(offered) == 2, (
        "a not_submitted report authorises one replacement attempt, so the same "
        "conversation would be sent upstream a second time"
    )
    assert server.store.get_attempt("req-couple-a2") is not None
    assert server.store.get_attempt("req-couple-a1").status == "FAILED"  # type: ignore[union-attr]


# --------------------------------------------------------------------------
# Helpers for signing the consumer's request
# --------------------------------------------------------------------------


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
