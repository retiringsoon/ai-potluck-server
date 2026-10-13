"""End-to-end acceptance over real sockets: server, connector, and consumer.

Nothing here mocks the transport. The server runs `GatewayServer` on a real
loopback TCP port, the connector dials it out with `ClientConnection`, and the
consumer speaks plain HTTP. What is proven is the wiring the unit tests cannot
see: that an admitted request becomes exactly one upstream call, that a receipt
comes back with a log position, and that a reconnect does not repeat work.

Deliberately out of scope (documented in network contract v0.1 §9): cross-machine NAT and
proxy behaviour, TLS with a publicly trusted certificate. The §6 acceptance
steps 4, 6, 7 and 8 below do use a second contribution node where the scenario
names one, over its own real socket, credential, and database.
"""

from __future__ import annotations

import datetime as dt
import http.client
import json
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from aipotluck.adapters import FakeResponse, FakeUpstream, FakeUpstreamAdapter
from aipotluck.canonical import loads_strict
from aipotluck.connector import Connector, ConnectorConfig
from aipotluck.identity import generate_key_pair
from aipotluck.metering import NormalizedUsage
from aipotluck.persistence import NodeStore
from aipotluck.wire import user_message
from conftest import Keyring, signed_authorization

from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import ServerStore

BASE = dt.datetime(2026, 10, 6, 12, 0, tzinfo=dt.UTC)
REGISTERED_AT = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
MODEL = "coding-pool"
TENANT = "tenant-a"
CONSUMER_TOKEN = "consumer-token-e2e"
NODE_TOKEN = "node-token-e2e"
NODE_B_TOKEN = "node-token-e2e-b"


def _wait_until(condition: Any, *, timeout: float = 10.0, what: str = "condition") -> None:
    """Block until `condition()` is truthy, failing with a readable message."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


def _assert_absent_for(condition: Any, *, duration: float, what: str) -> None:
    """Assert `condition()` stays falsy for `duration` seconds.

    A bounded negative wait: long enough that the server's 0.25s ticker would
    have acted several times over, short enough to keep the suite fast.
    """
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        assert not condition(), f"{what} happened"
        time.sleep(0.05)


def _authorization_body(
    keyring: Keyring,
    request_id: str,
    *,
    messages: tuple[Any, ...] = (user_message("write a haiku about sockets"),),
) -> dict[str, Any]:
    """Build the serialized authorization a real client would POST.

    The window is anchored to the wall clock on purpose: this suite exercises
    the real server, so a record the consumer just signed must be valid at the
    instant the server settles it. The digest is bound to `messages`, which must
    equal the ``messages`` in the POST body.
    """
    moment = dt.datetime.now(dt.UTC)
    record = signed_authorization(
        keyring,
        request_id=request_id,
        issued_at=moment - dt.timedelta(minutes=1),
        expires_at=moment + dt.timedelta(minutes=10),
        messages=messages,
        model=MODEL,
    )
    return {
        "schema": record.schema,
        "record_id": record.record_id,
        "revision": record.revision,
        "signed_at": record.signed_at.isoformat(),
        "signer_key_id": record.signer_key_id,
        "signer_id": record.signer_id,
        "signature": record.signature,
        "payload": dict(record.payload),
        "previous_record_hash": record.previous_record_hash,
    }


class Server:
    """A real gateway over a real store, with credentials provisioned."""

    def __init__(self, tmp_path: Path, keyring: Keyring, **config: Any) -> None:
        self.keyring = keyring
        self.tmp_path = tmp_path
        self.store = ServerStore.open(tmp_path / "server.db")
        # `config` is the dispatch-queue policy a test wants to probe; the defaults
        # are the shipped ones, so a test that names none drives what an operator
        # who wrote no queue field gets.
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(tmp_path / "server.db"),
            platform_id="platform-1",
            settlement_key_id="settlement-key-1",
            settlement_private_key_b64=keyring.private_b64["settlement-key-1"],
            **config,
        )
        self.service = GatewayService(
            config=self.config, store=self.store, registry=keyring.registry
        )
        self.server = GatewayServer(self.service, config=self.config)
        self.server.start()
        self.store.add_credential(
            CONSUMER_TOKEN, TENANT, "consumer-X", "consumer", REGISTERED_AT
        )
        self.store.add_credential(NODE_TOKEN, TENANT, "node-A", "node", REGISTERED_AT)
        self.store.add_credential(NODE_B_TOKEN, TENANT, "node-B", "node", REGISTERED_AT)
        self.service.fund_account(
            account_id="consumer-X", kind="consumer_available", amount=100_000, now=BASE
        )

    @property
    def port(self) -> int:
        """The real bound port."""
        return int(self.server.url.rsplit(":", 1)[1])

    def stop(self) -> None:
        """Shut the listener down."""
        self.server.stop()
        self.store.close()

    def post(self, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """POST an authenticated consumer request."""
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request(
            "POST",
            path,
            body=json.dumps(body).encode(),
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {CONSUMER_TOKEN}",
            },
        )
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        return response.status, (loads_strict(raw) if raw else {})

    def get(self, path: str, token: str = CONSUMER_TOKEN) -> tuple[int, dict[str, Any]]:
        """GET an authenticated resource."""
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", path, headers={"authorization": f"Bearer {token}"})
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        return response.status, (loads_strict(raw) if raw else {})

    def status_of(self, request_id: str) -> dict[str, Any]:
        """Return the current status document for a request."""
        _code, document = self.get(f"/v1/requests/{request_id}")
        return document


class _PostCallGateAdapter:
    """Wraps the node's adapter and blocks *after* the upstream call returned.

    This is the crash window of §7.3: `FakeUpstream.execute` has already counted
    the call, but the connector has not yet recorded it, spooled any event, or
    finished the execution row. A test that never sets the gate models a process
    killed exactly there.
    """

    def __init__(self, inner: FakeUpstreamAdapter, gate: threading.Event) -> None:
        self._inner = inner
        self.gate = gate

    @property
    def name(self) -> str:
        return self._inner.name

    @property
    def model(self) -> str:
        return self._inner.model

    def complete(
        self, messages: Any, *, request_digest: str, parameters: Any
    ) -> Any:
        result = self._inner.complete(
            messages, request_digest=request_digest, parameters=parameters
        )
        self.gate.wait()
        return result


class _GatedSpoolStore:
    """Delegating `NodeStore` wrapper that can pause one spool write.

    Every method is the real store's; only `enqueue_spool` for one configured
    event type waits on a test-owned gate first. Used to hold a node between
    "the first output segment is spooled" and "the usage report is spooled", so
    a test can drop the link deterministically after the server committed.
    """

    def __init__(self, inner: NodeStore, event_type: str, gate: threading.Event) -> None:
        self._inner = inner
        self._event_type = event_type
        self._gate = gate

    def enqueue_spool(
        self,
        *,
        attempt_id: str,
        attempt_seq: int,
        event_type: str,
        payload: dict[str, Any],
        at: Any,
    ) -> int:
        if event_type == self._event_type:
            self._gate.wait()
        return self._inner.enqueue_spool(
            attempt_id=attempt_id,
            attempt_seq=attempt_seq,
            event_type=event_type,
            payload=payload,
            at=at,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class Node:
    """A real connector dialing the server over loopback TCP."""

    def __init__(
        self,
        tmp_path: Path,
        keyring: Keyring,
        server_port: int,
        *,
        node_id: str = "node-A",
        device_id: str = "device-A",
        device_key_id: str = "node-device-key",
        provider_id: str = "provider-A",
        database_name: str = "node.db",
        token: str = NODE_TOKEN,
        fault: str | None = None,
        post_call_gate: threading.Event | None = None,
        pause_before_event: tuple[str, threading.Event] | None = None,
    ) -> None:
        self.upstream = FakeUpstream()
        if fault is not None:
            self.upstream.fault = fault
        self.upstream.queue(
            FakeResponse(
                text_chunks=("Hello ", "from the node"),
                usage=NormalizedUsage(input_total=800, output_total=200),
            )
        )
        self.adapter: Any = FakeUpstreamAdapter(upstream=self.upstream, model=MODEL)
        if post_call_gate is not None:
            self.adapter = _PostCallGateAdapter(self.adapter, post_call_gate)
        store: Any = NodeStore.open(tmp_path / database_name)
        if pause_before_event is not None:
            event_type, gate = pause_before_event
            store = _GatedSpoolStore(store, event_type, gate)
        self.store = store
        public_b64, private_b64 = generate_key_pair()
        keyring.registry.register_key(
            device_key_id, device_id, "provider_device", public_b64, REGISTERED_AT
        )
        keyring.registry.bind_device(device_id, provider_id)
        self.config = ConnectorConfig(
            server_url=f"ws://127.0.0.1:{server_port}/v1/node-link",
            node_id=node_id,
            device_id=device_id,
            device_key_id=device_key_id,
            provider_id=provider_id,
            database_path=str(tmp_path / database_name),
            token=token,
            adapter_name="fake-adapter",
            model=MODEL,
            device_private_key_b64=private_b64,
            heartbeat_interval_s=3600,
        )
        self.connector = Connector(self.config, adapter=self.adapter, store=self.store)
        self.thread = threading.Thread(target=self.connector.run_once, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        """Stop the connector and join its session thread."""
        self.connector.stop()
        self.thread.join(timeout=5)


@pytest.fixture
def server(tmp_path: Path) -> Any:
    """A running server, closed at the end of the test."""
    built = Server(tmp_path, Keyring())
    yield built
    built.stop()


def _admit(
    server: Server, request_id: str, idempotency_key: str, *, deadline_ms: int = 60000
) -> dict[str, Any]:
    """Submit one request through the real HTTP API."""
    status, document = server.post(
        "/v1/requests",
        {
            "idempotency_key": idempotency_key,
            "messages": [{"role": "user", "content": "write a haiku about sockets"}],
            "model": MODEL,
            "delivery_mode": "buffered_complete",
            "max_attempts": 2,
            "deadline_ms": deadline_ms,
            "max_charge_milli_credits": 20_000,
            "authorization": _authorization_body(server.keyring, request_id),
        },
    )
    assert status == 200, document
    return document


def _await_settlement(server: Server, request_id: str) -> dict[str, Any]:
    """Block until the request settles, then return its status document."""
    _wait_until(
        lambda: server.status_of(request_id).get("settlement") is not None,
        what=f"request {request_id} to settle",
    )
    return server.status_of(request_id)


def _read_sse_events(
    server: Server, request_id: str, cursor: int
) -> tuple[list[dict[str, Any]], str | None]:
    """Read the event endpoint over real HTTP and parse the SSE frames.

    The endpoint is SSE-only (`gateway_server.py` answers every GET on
    `/v1/requests/{id}/events` with `_serve_events`), but for a terminal request
    the stream replays the stored events, ends with a `done` frame, and closes
    the connection — so a plain client that reads to EOF performs a bounded,
    non-streaming read. Returns `(events, done_status)` where each event carries
    the `cursor`, `event_type`, and decoded `data` payload.
    """
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    connection.request(
        "GET",
        f"/v1/requests/{request_id}/events?cursor={cursor}",
        headers={"authorization": f"Bearer {CONSUMER_TOKEN}"},
    )
    response = connection.getresponse()
    assert response.status == 200, response.status
    raw = response.read().decode("utf-8")
    connection.close()
    events: list[dict[str, Any]] = []
    done_status: str | None = None
    for frame in raw.split("\n\n"):
        fields: dict[str, str] = {}
        for line in frame.splitlines():
            name, _, value = line.partition(": ")
            fields[name] = value
        if not fields.get("data"):
            continue
        data = json.loads(fields["data"])
        if "id" in fields:
            events.append(
                {
                    "cursor": int(fields["id"]),
                    "event_type": fields.get("event", ""),
                    "data": data,
                }
            )
        elif fields.get("event") == "done":
            done_status = data["status"]
    return events, done_status


def test_normal_path_one_upstream_call_one_receipt(server: Server) -> None:
    """§6 step 2: OFFER → ACCEPT → EXECUTE with call_count=1 and a signed receipt."""
    node = Node(server.tmp_path, server.keyring, server.port)
    try:
        _wait_until(
            lambda: bool(server.store.connected_nodes()), what="the node to register"
        )
        document = _admit(server, "R-e2e-1", "idem-e2e-1")
        request_id = document["request_id"]

        document = _await_settlement(server, request_id)
        assert document["status"] == "SUCCEEDED"
        assert document["attempts"][0]["usage_tokens"] == 1_000

        settlement = document["settlement"]
        _code, receipt = server.get(f"/v1/receipts/{settlement['receipt_id']}")
        assert receipt["receipt_hash"] == settlement["receipt_hash"]
        assert receipt["log_index"] == settlement["log_index"]
        assert receipt["inclusion_proof"]["root_hash"]

        assert node.adapter.upstream_calls == 1
        assert server.service.balance("consumer-X") == 99_000
        assert server.service.balance("provider-A/pending") == 1_000
    finally:
        node.stop()


def test_idempotent_replay_creates_nothing_new(server: Server) -> None:
    """§6 step 3: the same key and payload returns the same logical request."""
    node = Node(server.tmp_path, server.keyring, server.port)
    try:
        _wait_until(
            lambda: bool(server.store.connected_nodes()), what="the node to register"
        )
        body = {
            "idempotency_key": "idem-e2e-2",
            "messages": [{"role": "user", "content": "one prompt"}],
            "model": MODEL,
            "delivery_mode": "buffered_complete",
            "max_attempts": 2,
            "deadline_ms": 60000,
            "max_charge_milli_credits": 20_000,
            "authorization": _authorization_body(
                server.keyring, "R-e2e-2", messages=(user_message("one prompt"),)
            ),
        }
        status, first = server.post("/v1/requests", body)
        assert status == 200
        request_id = first["request_id"]
        _await_settlement(server, request_id)
        calls_after_first = node.adapter.upstream_calls
        assert calls_after_first == 1

        status, second = server.post("/v1/requests", body)
        assert status == 200
        assert second["request_id"] == request_id
        time.sleep(0.3)

        # A different conversation under the same key is a conflict. Its
        # authorization is rebuilt for that conversation so the request digest
        # matches; the refusal comes from the idempotency key, which is the point
        # of the test.
        conflict_body = {
            **body,
            "messages": [{"role": "user", "content": "other"}],
            "authorization": _authorization_body(
                server.keyring, "R-e2e-2", messages=(user_message("other"),)
            ),
        }
        status, _conflict = server.post("/v1/requests", conflict_body)
        assert status == 409

        assert node.adapter.upstream_calls == calls_after_first, (
            "an idempotent replay must not make another upstream call"
        )
    finally:
        node.stop()


def test_a_full_dispatch_queue_answers_503_on_the_platforms_own_surface(
    tmp_path: Path,
) -> None:
    """The signed door names the queue's own condition, not a generic bad request.

    A caller cannot act on `400 bad_request`: it says the request was wrong, and
    this request was not — the server was full. `503` with its own code says "the
    platform is taking no more work right now", which is a condition that ends, and
    is the same fact the OpenAI-compatible surface answers as a `429` an existing
    client already backs off on.
    """
    server = Server(tmp_path, Keyring(), max_queue_depth=1)
    try:
        first = _admit(server, "R-queue-1", "idem-queue-1")
        assert server.store.count_requests_by_status("ROUTING") == 1

        status, document = server.post(
            "/v1/requests",
            {
                "idempotency_key": "idem-queue-2",
                "messages": [{"role": "user", "content": "write a haiku about sockets"}],
                "model": MODEL,
                "delivery_mode": "buffered_complete",
                "max_attempts": 2,
                "deadline_ms": 60000,
                "max_charge_milli_credits": 20_000,
                "authorization": _authorization_body(server.keyring, "R-queue-2"),
            },
        )

        assert status == 503, document
        assert document["error"] == "queue_full"
        assert "queue bound of 1" in document["detail"]
        assert server.store.get_request("R-queue-2") is None
        assert server.store.count_requests_by_status("ROUTING") == 1
        assert first["request_id"] == "R-queue-1"
    finally:
        server.stop()


def test_a_replayed_key_under_a_fresh_request_id_is_a_conflict_not_a_crash(
    server: Server,
) -> None:
    """Re-signing the same work under the same key is a 409, in the conflict shape.

    The defect this guards is a 500. A client that retries by re-signing — a fresh
    authorization, so a fresh ``request_id`` — while keeping the idempotency key it
    already used arrives with a payload digest the stored row agrees with, so the
    store hands back the *first* request. The admission then looked up the second
    request id, found nothing, and asserted: an ``AssertionError`` is not a
    ``PotluckError``, so the transport had no vocabulary for it and answered
    ``500 internal_error``.

    A 500 says "the server broke", which invites the caller to retry the very
    request that broke it. A 409 says "this key already named another request",
    which is true and is actionable: resubmit with the id the server returned, or
    mint a fresh key for genuinely new work. Asserted over the real HTTP surface
    because the status and the error shape are the caller-visible half of the fix.
    """
    node = Node(server.tmp_path, server.keyring, server.port)
    try:
        _wait_until(
            lambda: bool(server.store.connected_nodes()), what="the node to register"
        )
        messages = [{"role": "user", "content": "one prompt"}]
        conversation = (user_message("one prompt"),)
        body = {
            "idempotency_key": "idem-resigned",
            "messages": messages,
            "model": MODEL,
            "delivery_mode": "buffered_complete",
            "max_attempts": 2,
            "deadline_ms": 60000,
            "max_charge_milli_credits": 20_000,
            "authorization": _authorization_body(
                server.keyring, "R-first", messages=conversation
            ),
        }
        status, first = server.post("/v1/requests", body)
        assert status == 200
        first_request_id = first["request_id"]

        resigned = {
            **body,
            "authorization": _authorization_body(
                server.keyring, "R-second", messages=conversation
            ),
        }
        status, document = server.post("/v1/requests", resigned)

        assert status == 409, document
        assert document["error"] == "conflict"
        assert "R-second" in document["detail"]
        assert first_request_id in document["detail"]
        # The stored request is untouched: still one row, still the first one's id,
        # and the second authorization dispatched nothing of its own.
        assert server.store.get_request("R-second") is None
        assert server.store.attempts_for_request(first_request_id)
        assert node.adapter.upstream_calls <= 1
    finally:
        node.stop()


def test_a_node_reconnect_does_not_repeat_the_upstream_call(server: Server) -> None:
    """§6 step 5: a dropped link is not an unexecuted attempt."""
    node = Node(server.tmp_path, server.keyring, server.port)
    try:
        _wait_until(
            lambda: bool(server.store.connected_nodes()), what="the node to register"
        )
        document = _admit(server, "R-e2e-3", "idem-e2e-3")
        _await_settlement(server, document["request_id"])
        assert node.adapter.upstream_calls == 1

        # A second session over the same node database: reconnect, not redo.
        reconnect = Connector(node.config, adapter=node.adapter, store=node.store)
        thread = threading.Thread(target=reconnect.run_once, daemon=True)
        thread.start()
        thread.join(timeout=5)
        time.sleep(0.2)

        assert node.adapter.upstream_calls == 1, (
            "a reconnect must not make a second upstream call"
        )
        assert server.status_of(document["request_id"])["status"] == "SUCCEEDED"
    finally:
        node.stop()


def test_consumer_resume_by_cursor_replays_every_event_exactly_once(server: Server) -> None:
    """§6 step 4: reconnecting from cursor C sees the suffix once, in order.

    The read goes over real HTTP against the running server. The events
    endpoint is SSE-only, but a terminal request's stream is bounded: stored
    events replay, a `done` frame closes it, so a plain GET to EOF is an
    honest non-streaming read.
    """
    node = Node(server.tmp_path, server.keyring, server.port)
    try:
        _wait_until(
            lambda: bool(server.store.connected_nodes()), what="the node to register"
        )
        document = _admit(server, "R-e2e-4", "idem-e2e-4")
        request_id = document["request_id"]
        document = _await_settlement(server, request_id)
        assert document["status"] == "SUCCEEDED"
        attempt_id = document["attempts"][0]["attempt_id"]

        full, done_status = _read_sse_events(server, request_id, 0)
        assert done_status == "SUCCEEDED"
        cursors = [event["cursor"] for event in full]
        assert cursors == list(range(1, len(cursors) + 1)), (
            "event cursors must be contiguous from 1 with no gap"
        )
        types = [event["event_type"] for event in full]
        assert types == ["output.delta", "usage.final", "attempt.completed"]
        assert server.store.has_event_gap(attempt_id) is False

        # A consumer that saw the first event, dropped, and reconnects from its
        # cursor gets exactly the suffix: no repeat, no gap, same payloads.
        seen_through = cursors[0]
        tail, tail_done = _read_sse_events(server, request_id, seen_through)
        assert tail_done == "SUCCEEDED"
        assert [event["cursor"] for event in tail] == cursors[1:]
        assert [event["event_type"] for event in tail] == types[1:]
        assert [event["data"] for event in tail] == [event["data"] for event in full[1:]]

        # A consumer that reads from cursor 0 gets the whole stream, including
        # the settlement-time events.
        again, again_done = _read_sse_events(server, request_id, 0)
        assert again_done == "SUCCEEDED"
        assert again == full
    finally:
        node.stop()


def test_node_killed_mid_submitting_reports_unknown_and_stays_unbilled(server: Server) -> None:
    """§6 step 6 / §7.3: a kill between the upstream call and any report.

    The adapter is gated right after `FakeUpstream.execute` returned, which is
    inside `Connector._run_execution`'s window between the upstream call and the
    first spool write — so the node's execution row is SUBMITTING and the server
    has seen nothing. The restart is a second `Connector` over the same node
    database, whose `__init__` runs `mark_interrupted_as_unknown`.
    """
    gate = threading.Event()
    node = Node(server.tmp_path, server.keyring, server.port, post_call_gate=gate)
    restart: Connector | None = None
    restart_thread: threading.Thread | None = None
    try:
        _wait_until(
            lambda: bool(server.store.connected_nodes()), what="the node to register"
        )
        document = _admit(server, "R-e2e-6", "idem-e2e-6")
        request_id = document["request_id"]
        attempt_id = f"{request_id}-a1"

        # The crash window: upstream called, execution row SUBMITTING, the
        # server has received nothing at all.
        _wait_until(lambda: node.upstream.call_count == 1, what="the upstream call")
        execution = node.store.get_execution(attempt_id)
        assert execution is not None, "the node must have begun the execution"
        assert execution.state == "SUBMITTING"
        assert execution.finished_at is None
        assert execution.upstream_calls == 0, (
            "the crash window is before the connector records the call"
        )
        assert server.store.events_after(request_id, 0) == []
        assert server.status_of(request_id)["attempts"][0]["usage_tokens"] is None

        # The kill: the session dies with the row still SUBMITTING. The worker
        # stays parked on the gate, like a process that ceased to exist.
        node.stop()

        # A restarted connector over the same database marks the row UNKNOWN.
        restart = Connector(node.config, adapter=node.adapter, store=node.store)
        assert node.store.get_execution(attempt_id).state == "UNKNOWN"
        restart_thread = threading.Thread(target=restart.run_once, daemon=True)
        restart_thread.start()
        # The server sends `resend_spool` for an accepted attempt, so the row
        # must STAY unknown: the node reports what it knows and the server
        # rules. Waiting for a FAILED row here would be waiting for the node to
        # overwrite evidence the server asked for.
        _wait_until(
            lambda: server.status_of(request_id)["attempts"][0]["status"]
            == "OUTCOME_UNKNOWN",
            what="the server to rule the attempt outcome-unknown",
            timeout=5,
        )

        # §7.3: the server must report the attempt as outcome-unknown, keep the
        # usage unknown (never zero), and bill nobody.
        document = server.status_of(request_id)
        attempt = document["attempts"][0]
        assert attempt["status"] == "OUTCOME_UNKNOWN", document
        assert attempt["usage_status"] == "UNKNOWN"
        assert attempt["usage_tokens"] is None
        assert "unknown" in (document["billing_note"] or "").lower()
        assert document["settlement"] is None
        assert server.service.balance("consumer-X") == 100_000
        assert node.upstream.call_count == 1, (
            "the whole episode must call the upstream exactly once"
        )
    finally:
        node.stop()
        if restart is not None:
            restart.stop()
        if restart_thread is not None:
            restart_thread.join(timeout=5)


def test_failure_before_any_output_retries_on_a_second_node(server: Server) -> None:
    """§6 step 7a / §7.4: a clean pre-output failure re-offers within budget.

    Node A's upstream raises before any output; the node reports the attempt
    failed cleanly. With `max_attempts=2` and node B connected, the server is
    expected to re-offer to B, whose attempt settles for the consumer.
    """
    failed = Node(server.tmp_path, server.keyring, server.port, fault="error_before_output")
    healthy = Node(
        server.tmp_path,
        server.keyring,
        server.port,
        node_id="node-B",
        device_id="device-B",
        device_key_id="node-device-key-b",
        provider_id="provider-B",
        database_name="node-b.db",
        token=NODE_B_TOKEN,
    )
    try:
        _wait_until(
            lambda: len(server.store.connected_nodes()) == 2, what="both nodes to register"
        )
        document = _admit(server, "R-e2e-7", "idem-e2e-7")
        request_id = document["request_id"]

        _wait_until(
            lambda: server.status_of(request_id)["status"] in ("SUCCEEDED", "FAILED"),
            what="the request to reach a terminal state",
        )
        document = server.status_of(request_id)
        assert document["status"] == "SUCCEEDED", document["billing_note"]
        attempts = document["attempts"]
        assert len(attempts) == 2, "the first attempt must be replaced, not reused"
        assert attempts[0]["status"] == "FAILED"
        assert attempts[0]["usage_status"] == "UNKNOWN"
        assert attempts[1]["status"] == "COMPLETED"
        assert attempts[1]["usage_tokens"] == 1_000
        assert document["settlement"] is not None
        assert failed.upstream.call_count == 1
        assert healthy.upstream.call_count == 1
        assert server.service.balance("consumer-X") == 99_000
    finally:
        failed.stop()
        healthy.stop()


def test_committed_output_then_link_drop_ends_expired_without_a_replacement(
    server: Server,
) -> None:
    """§6 step 7b / §7.5: after the first segment commits, no attempt is spliced.

    The node is held between spooling its output delta and spooling its usage
    report, so the server commits the output while the attempt is still live.
    The link then drops. What this build actually does: the request is never
    re-offered (the output commit guards `_offer_new_attempt`), no second node
    executes anything, and the consumer's explicit terminal result is EXPIRED
    when the request's deadline passes — hence the test's name.
    """
    pause = threading.Event()
    node_a = Node(
        server.tmp_path,
        server.keyring,
        server.port,
        pause_before_event=("usage.final", pause),
    )
    node_b = Node(
        server.tmp_path,
        server.keyring,
        server.port,
        node_id="node-B",
        device_id="device-B",
        device_key_id="node-device-key-b",
        provider_id="provider-B",
        database_name="node-b.db",
        token=NODE_B_TOKEN,
    )
    try:
        _wait_until(
            lambda: len(server.store.connected_nodes()) == 2, what="both nodes to register"
        )
        document = _admit(server, "R-e2e-8", "idem-e2e-8", deadline_ms=2000)
        request_id = document["request_id"]
        attempt_id = f"{request_id}-a1"

        _wait_until(
            lambda: server.store.output_commit(request_id) is not None,
            what="the first output segment to commit at the server",
        )
        commit = server.store.output_commit(request_id)
        assert commit is not None
        assert commit.attempt_id == attempt_id
        assert node_a.upstream.call_count == 1

        # The link drops after the commit; the usage report never leaves.
        node_a.stop()

        _wait_until(
            lambda: server.status_of(request_id)["status"] == "EXPIRED",
            what="the deadline tick to give the consumer a terminal result",
        )
        document = server.status_of(request_id)
        assert document["status"] == "EXPIRED"
        assert "deadline" in (document["billing_note"] or "")
        assert len(document["attempts"]) == 1, (
            "a committed output must not open a replacement attempt"
        )
        assert document["attempts"][0]["attempt_id"] == attempt_id
        assert document["output"]["committed"] is True
        assert document["output"]["attempt_id"] == attempt_id
        assert document["settlement"] is None
        assert server.service.balance("consumer-X") == 100_000
        assert node_a.upstream.call_count == 1
        assert node_b.upstream.call_count == 0, (
            "no second node may execute anything once output is committed"
        )
    finally:
        node_a.stop()
        node_b.stop()


def test_a_paused_node_receives_no_new_work(server: Server) -> None:
    """§6 step 8 (partial) / §7.9: share_enabled=false means zero new offers.

    The pause travels the realistic route: the operator disables sharing and
    the connector reconnects, so the server learns `share_enabled=false` from a
    real `node.hello` over the real socket (not a hand-built heartbeat). A new
    admission must then produce no attempt, no offer, and no tick delivery.
    """
    node = Node(server.tmp_path, server.keyring, server.port)
    try:
        _wait_until(
            lambda: bool(server.store.connected_nodes()), what="the node to register"
        )
        node.stop()

        paused_config = replace(node.config, share_enabled=False)
        paused = Connector(paused_config, adapter=node.adapter, store=node.store)
        thread = threading.Thread(target=paused.run_once, daemon=True)
        thread.start()
        try:

            def pause_registered() -> bool:
                record = server.store.get_node("node-A")
                return (
                    record is not None
                    and record.share_enabled is False
                    and record.connected
                )

            _wait_until(pause_registered, what="the paused policy to reach the server")

            document = _admit(server, "R-e2e-9", "idem-e2e-9")
            request_id = document["request_id"]

            _assert_absent_for(
                lambda: server.store.attempts_for_request(request_id),
                duration=1.5,
                what="an attempt offered to a paused node",
            )
            document = server.status_of(request_id)
            assert document["status"] == "ROUTING"
            assert document["attempts"] == []
            assert server.store.attempts_for_request(request_id) == []

            deliveries = server.service.tick()
            assert deliveries == [], "tick must not deliver anything to a paused node"
            assert server.store.attempts_for_request(request_id) == []
            assert node.adapter.upstream_calls == 0
            assert node.upstream.call_count == 0

            _code, nodes = server.get("/v1/nodes")
            entry = next(n for n in nodes["nodes"] if n["node_id"] == "node-A")
            assert entry["share_enabled"] is False
        finally:
            paused.stop()
            thread.join(timeout=5)
    finally:
        node.stop()
