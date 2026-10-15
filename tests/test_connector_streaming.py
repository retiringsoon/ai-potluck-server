"""End-to-end streaming over real sockets: server, connector, and consumer.

Nothing is mocked. The server is a real `GatewayServer` on a loopback port, the
connector dials it out with `ClientConnection` and reads a fake upstream that
emits incrementally, and the consumer reads the event endpoint over plain HTTP.
What this file proves is the U04 contract: a `stream_strict` request reaches the
server as several `output.delta` events *before* its `usage.final`, the per-attempt
sequence stays contiguous, and the settlement is identical to the buffered path —
while a buffered request still takes the `chunk_text` route. The last two tests
drive the connector without a socket to pin the crash semantics: a stream that
breaks is a failure, and a process that dies mid-stream restarts as UNKNOWN.
"""

from __future__ import annotations

import datetime as dt
import http.client
import json
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import pytest
from aipotluck.adapters import FakeResponse, FakeUpstream, FakeUpstreamAdapter, StreamChunk
from aipotluck.canonical import loads_strict
from aipotluck.connector import Connector, ConnectorConfig
from aipotluck.identity import generate_key_pair
from aipotluck.metering import NormalizedUsage
from aipotluck.persistence import NodeStore
from aipotluck.wire import (
    AttemptOffer,
    AttemptRef,
    Envelope,
    compute_permit_hash,
    user_message,
)
from conftest import Keyring, signed_authorization

from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import ServerStore

BASE = dt.datetime(2026, 10, 6, 12, 0, tzinfo=dt.UTC)
REGISTERED_AT = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
MODEL = "coding-pool"
TENANT = "tenant-a"
CONSUMER_TOKEN = "consumer-token-stream"
NODE_TOKEN = "node-token-stream"

#: The scripted answer: two blocks, so a streaming attempt must produce two deltas
#: and a buffered attempt (chunk_text with the default 4096-char size) exactly one.
TEXT_BLOCKS = ("Hello ", "from the node")
EXPECTED_TEXT = "".join(TEXT_BLOCKS)
SCRIPTED_USAGE = NormalizedUsage(input_total=800, output_total=200)


def _wait_until(
    condition: Callable[[], bool], *, timeout: float = 10.0, what: str = "condition"
) -> None:
    """Block until `condition()` is truthy, failing with a readable message."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


PROMPT = "write a haiku about sockets"
#: The conversation every admission here signs and submits, as one user turn.
MESSAGES = (user_message(PROMPT),)


def _authorization_body(
    keyring: Keyring, request_id: str, *, delivery_mode: str = "stream_strict"
) -> dict[str, Any]:
    """Build the serialized authorization a real client would POST.

    The digest is bound to the exact messages/model/delivery_mode the caller
    will submit, because admission recomputes it from what arrived and refuses a
    request the authorization did not sign over.
    """
    moment = dt.datetime.now(dt.UTC)
    record = signed_authorization(
        keyring,
        request_id=request_id,
        messages=MESSAGES,
        model=MODEL,
        delivery_mode=delivery_mode,
        issued_at=moment - dt.timedelta(minutes=1),
        expires_at=moment + dt.timedelta(minutes=10),
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

    def __init__(self, tmp_path: Path, keyring: Keyring) -> None:
        self.keyring = keyring
        self.tmp_path = tmp_path
        self.store = ServerStore.open(tmp_path / "server.db")
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(tmp_path / "server.db"),
            platform_id="platform-1",
            settlement_key_id="settlement-key-1",
            settlement_private_key_b64=keyring.private_b64["settlement-key-1"],
        )
        self.service = GatewayService(
            config=self.config, store=self.store, registry=keyring.registry
        )
        self.server = GatewayServer(self.service, config=self.config)
        self.server.start()
        self.store.add_credential(CONSUMER_TOKEN, TENANT, "consumer-X", "consumer", REGISTERED_AT)
        self.store.add_credential(NODE_TOKEN, TENANT, "node-A", "node", REGISTERED_AT)
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


class _GatedSpoolStore:
    """Delegating `NodeStore` that pauses one spool write until a gate opens.

    Used to hold a node between "the first deltas are spooled" and "the usage
    report is spooled", so a test can observe — deterministically — that the
    server received incremental output before any final usage arrived.
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
        """Wait on the gate before spooling the watched event type."""
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
        pause_before_event: tuple[str, threading.Event] | None = None,
    ) -> None:
        self.upstream = FakeUpstream()
        self.upstream.queue(
            FakeResponse(text_chunks=TEXT_BLOCKS, usage=SCRIPTED_USAGE)
        )
        self.adapter = FakeUpstreamAdapter(upstream=self.upstream, model=MODEL)
        store: Any = NodeStore.open(tmp_path / "node.db")
        if pause_before_event is not None:
            event_type, gate = pause_before_event
            store = _GatedSpoolStore(store, event_type, gate)
        self.store = store
        public_b64, private_b64 = generate_key_pair()
        keyring.registry.register_key(
            "node-device-key", "device-A", "provider_device", public_b64, REGISTERED_AT
        )
        keyring.registry.bind_device("device-A", "provider-A")
        self.config = ConnectorConfig(
            server_url=f"ws://127.0.0.1:{server_port}/v1/node-link",
            node_id="node-A",
            device_id="device-A",
            device_key_id="node-device-key",
            provider_id="provider-A",
            database_path=str(tmp_path / "node.db"),
            token=NODE_TOKEN,
            adapter_name="fake-adapter",
            model=MODEL,
            device_private_key_b64=private_b64,
            heartbeat_interval_s=3600,
        )
        self.connector = Connector(self.config, adapter=self.adapter, store=self.store)
        self.thread = threading.Thread(target=self.connector.run_once, daemon=True)
        self.thread.start()

    def queue_response(self) -> None:
        """Queue one more scripted answer for a subsequent request."""
        self.upstream.queue(FakeResponse(text_chunks=TEXT_BLOCKS, usage=SCRIPTED_USAGE))

    def stop(self) -> None:
        """Stop the connector and join its session thread."""
        self.connector.stop()
        self.thread.join(timeout=5)


@pytest.fixture
def server(tmp_path: Path) -> Iterator[Server]:
    """A running server, closed at the end of the test."""
    built = Server(tmp_path, Keyring())
    yield built
    built.stop()


def _admit(
    server: Server,
    request_id: str,
    idempotency_key: str,
    *,
    delivery_mode: str,
    deadline_ms: int = 60000,
) -> dict[str, Any]:
    """Submit one request through the real HTTP API."""
    status, document = server.post(
        "/v1/requests",
        {
            "idempotency_key": idempotency_key,
            "messages": [message.to_payload() for message in MESSAGES],
            "model": MODEL,
            "delivery_mode": delivery_mode,
            "max_attempts": 2,
            "deadline_ms": deadline_ms,
            "max_charge_milli_credits": 20_000,
            "authorization": _authorization_body(
                server.keyring, request_id, delivery_mode=delivery_mode
            ),
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
    """Read `/v1/requests/{id}/events` over real HTTP and parse the SSE frames.

    For a terminal request the stream replays the stored events, ends with a
    `done` frame, and closes — so a plain read to EOF is a bounded read. Returns
    `(events, done_status)`, each event carrying `cursor`, `event_type`, and the
    decoded `data` payload.
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


# --------------------------------------------------------------------------- #
# 1. Incremental publishing, sequencing, and the consumer view
# --------------------------------------------------------------------------- #


def test_streaming_commits_deltas_before_the_usage_report(server: Server) -> None:
    """The server must hold ≥2 deltas before it ever sees `usage.final`."""
    gate = threading.Event()
    node = Node(
        server.tmp_path, server.keyring, server.port, pause_before_event=("usage.final", gate)
    )
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        document = _admit(server, "R-str-1", "idem-str-1", delivery_mode="stream_strict")
        request_id = document["request_id"]
        attempt_id = f"{request_id}-a1"

        def deltas_seen() -> int:
            return sum(
                1 for event in server.store.events_after(request_id, 0)
                if event.event_type == "output.delta"
            )

        # The worker is parked before spooling usage.final, so whatever the server
        # has received is provably output-only.
        _wait_until(lambda: deltas_seen() >= 2, what="two deltas to reach the server")
        types_before = [event.event_type for event in server.store.events_after(request_id, 0)]
        assert types_before.count("output.delta") >= 2
        assert "usage.final" not in types_before, "usage must not precede the deltas"
        assert node.adapter.upstream_calls == 1, "the whole stream is one upstream call"

        gate.set()
        document = _await_settlement(server, request_id)

        assert document["status"] == "SUCCEEDED"
        assert document["attempts"][0]["usage_tokens"] == 1_000
        assert document["output"]["committed"] is True
        assert document["output"]["attempt_id"] == attempt_id
        assert node.adapter.upstream_calls == 1
        assert server.service.balance("consumer-X") == 99_000
        assert server.service.balance("provider-A/pending") == 1_000

        # The consumer sees the deltas as separate frames, in order, with no gap.
        events, done_status = _read_sse_events(server, request_id, 0)
        assert done_status == "SUCCEEDED"
        assert [event["cursor"] for event in events] == list(range(1, len(events) + 1))
        assert [event["event_type"] for event in events] == [
            "output.delta",
            "output.delta",
            "usage.final",
            "attempt.completed",
        ]
        assert [int(event["data"]["seq"]) for event in events] == [1, 2, 3, 4]
        streamed = "".join(
            str(event["data"]["text"])
            for event in events
            if event["event_type"] == "output.delta"
        )
        assert streamed == EXPECTED_TEXT
        assert server.store.has_event_gap(attempt_id) is False
    finally:
        gate.set()
        node.stop()


# --------------------------------------------------------------------------- #
# 2. Equivalence with the buffered path
# --------------------------------------------------------------------------- #


def test_streaming_settles_like_buffered_and_buffered_still_chunks(server: Server) -> None:
    """Same answer, same bill; buffered keeps the `chunk_text` split.

    The two requests are run one after another. A node's local reservation
    covers the whole offered budget, so admitting both at once would be refused
    on local policy — a capacity effect that has nothing to do with the delivery
    mode under test.
    """
    node = Node(server.tmp_path, server.keyring, server.port)
    try:
        node.queue_response()  # one scripted answer per request
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")

        streamed = _admit(server, "R-cmp-s", "idem-cmp-s", delivery_mode="stream_strict")
        streamed_doc = _await_settlement(server, streamed["request_id"])
        buffered = _admit(server, "R-cmp-b", "idem-cmp-b", delivery_mode="buffered_complete")
        buffered_doc = _await_settlement(server, buffered["request_id"])

        assert streamed_doc["status"] == "SUCCEEDED"
        assert buffered_doc["status"] == "SUCCEEDED"
        # Same model answer, same recorded usage, same charge.
        assert streamed_doc["attempts"][0]["usage_tokens"] == 1_000
        assert buffered_doc["attempts"][0]["usage_tokens"] == 1_000
        assert node.adapter.upstream_calls == 2, "one upstream call per request, no more"

        for request_id in (streamed["request_id"], buffered["request_id"]):
            attempt_id = f"{request_id}-a1"
            assert node.store.get_execution(attempt_id).upstream_calls == 1

        # One bill each: 1000 tokens at the flat rate.
        assert server.service.balance("consumer-X") == 98_000
        assert server.service.balance("provider-A/pending") == 2_000

        def _published(request_id: str) -> list[str]:
            events, _ = _read_sse_events(server, request_id, 0)
            return [event["event_type"] for event in events]

        # The server publishes asynchronously: read again until the terminal
        # event is visible, otherwise a slow runner asserts a mid-flight list.
        _wait_until(
            lambda: _published(streamed["request_id"])[-1:] == ["attempt.completed"],
            what="the streamed attempt.completed to be published",
        )
        _wait_until(
            lambda: _published(buffered["request_id"])[-1:] == ["attempt.completed"],
            what="the buffered attempt.completed to be published",
        )
        streamed_events, _ = _read_sse_events(server, streamed["request_id"], 0)
        buffered_events, _ = _read_sse_events(server, buffered["request_id"], 0)
        streamed_types = [event["event_type"] for event in streamed_events]
        buffered_types = [event["event_type"] for event in buffered_events]

        # The streaming path publishes each upstream block as its own delta...
        assert streamed_types == [
            "output.delta",
            "output.delta",
            "usage.final",
            "attempt.completed",
        ]
        # ...while the buffered path still joins the answer and slices it with
        # chunk_text, so a two-block answer is one delta at the default size.
        assert buffered_types == ["output.delta", "usage.final", "attempt.completed"]
        assert buffered_events[0]["data"]["text"] == EXPECTED_TEXT
    finally:
        node.stop()


# --------------------------------------------------------------------------- #
# 3. Crash semantics (no socket: the connector is driven directly)
# --------------------------------------------------------------------------- #


def _node_config(tmp_path: Path, adapter: Any) -> ConnectorConfig:
    """Build a connector config for the socket-free tests."""
    _public, private_b64 = generate_key_pair()
    return ConnectorConfig(
        server_url="ws://127.0.0.1:1/v1/node-link",
        node_id="node-1",
        device_id="device-1",
        device_key_id="device-key-1",
        provider_id="provider-1",
        database_path=str(tmp_path / "node.db"),
        token="token",
        adapter_name=adapter.name,
        model=adapter.model,
        device_private_key_b64=private_b64,
        delta_chars=4096,
    )


def _offer(
    *,
    delivery_mode: Literal["stream_strict", "buffered_complete"],
    attempt_id: str = "A1",
    request_id: str = "R1",
) -> AttemptOffer:
    """Build an offer whose `permit_hash` matches its own fields."""
    permit_hash = compute_permit_hash(
        request_id=request_id,
        attempt_id=attempt_id,
        epoch=1,
        model="fake-model-v1",
        request_digest="sha256:req",
        max_milli_credits=1000,
        authorization_hash="auth-1",
    )
    return AttemptOffer(
        request_id=request_id,
        attempt_id=attempt_id,
        epoch=1,
        resource_id="res-1",
        model="fake-model-v1",
        request_digest="sha256:req",
        max_milli_credits=1000,
        deadline_ms=1000,
        delivery_mode=delivery_mode,
        messages=(user_message("hi"),),
        parameters={},
        authorization_hash="auth-1",
        permit_hash=permit_hash,
    )


def _start(connector: Connector, offer: AttemptOffer) -> None:
    """Drive OFFER then EXECUTE into the connector without a socket."""
    connector.handle_message(Envelope("attempt.offer", offer.to_payload()))
    reference = AttemptRef(offer.request_id, offer.attempt_id, offer.epoch)
    connector.handle_message(Envelope("attempt.execute", reference.to_payload()))


def test_a_stream_that_breaks_is_a_failure_not_a_short_answer(tmp_path: Path) -> None:
    """A mid-stream break must fail the attempt, never pass off the prefix as final."""
    upstream = FakeUpstream(fault="truncate_mid_stream")
    upstream.queue(FakeResponse(text_chunks=("first ", "second"), usage=SCRIPTED_USAGE))
    adapter = FakeUpstreamAdapter(upstream=upstream)
    store = NodeStore.open(str(tmp_path / "node.db"))
    config = _node_config(tmp_path, adapter)
    connector = Connector(config, adapter=adapter, store=store)

    _start(connector, _offer(delivery_mode="stream_strict"))
    _wait_until(
        lambda: store.get_execution("A1").finished_at is not None, what="the execution to finish"
    )

    record = store.get_execution("A1")
    assert record.state == "FAILED"
    assert record.upstream_calls == 1, "the upstream was called and emitted the prefix"
    # finished_at flips before the spool writes land: wait for the failure
    # event itself, then assert the full sequence.
    _wait_until(
        lambda: any(
            event.event_type == "attempt.failed" for event in store.unacked_spool("A1")
        ),
        what="the attempt.failed to spool",
    )
    spooled = store.unacked_spool("A1")
    assert [event.event_type for event in spooled] == ["output.delta", "attempt.failed"]
    assert [event.attempt_seq for event in spooled] == [1, 2]
    assert spooled[0].payload["text"] == "first "
    assert "after output had already been emitted" in str(spooled[1].payload["detail"])
    assert upstream.call_count == 1


@dataclass
class _BlockingStreamAdapter:
    """A streaming adapter that emits one chunk, then holds the stream open."""

    entered: threading.Event = field(default_factory=threading.Event)
    gate: threading.Event = field(default_factory=threading.Event)
    name: str = "blocking-stream"
    model: str = "fake-model-v1"

    @property
    def supports_streaming(self) -> bool:
        """This adapter streams by construction."""
        return True

    def complete(self, messages: Any, *, request_digest: str, parameters: Any) -> Any:
        """The buffered path is not expected in this test."""
        raise AssertionError("the buffered path must not be used for a streaming adapter")

    def stream(
        self, messages: Any, *, request_digest: str, parameters: Any
    ) -> Iterator[StreamChunk]:
        """Emit one chunk, then block forever: the process that never returns."""
        del messages, request_digest, parameters
        yield StreamChunk(text="partial ")
        self.entered.set()
        self.gate.wait()
        yield StreamChunk(is_final=True)


def test_a_process_killed_mid_stream_restarts_as_unknown(tmp_path: Path) -> None:
    """A node that dies mid-stream leaves SUBMITTING, and a restart marks it UNKNOWN."""
    adapter = _BlockingStreamAdapter()
    store = NodeStore.open(str(tmp_path / "node.db"))
    config = _node_config(tmp_path, adapter)
    connector = Connector(config, adapter=adapter, store=store)

    _start(connector, _offer(delivery_mode="stream_strict"))
    _wait_until(lambda: adapter.entered.is_set(), what="the first streamed chunk")

    record = store.get_execution("A1")
    assert record.state == "SUBMITTING", "the row must not be finished while the stream is open"
    assert record.finished_at is None
    assert [event.event_type for event in store.unacked_spool("A1")] == ["output.delta"]

    # The restart: a fresh connector over the same database runs the startup sweep.
    restarted = Connector(config, adapter=adapter, store=store)
    assert restarted is not None
    assert store.get_execution("A1").state == "UNKNOWN"
    assert store.get_execution("A1").upstream_calls == 1, "recorded as called upon stream start"
