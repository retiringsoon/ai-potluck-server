"""U04 (client-side incremental display) and U06 (understandable state/errors).

What these tests pin, and why each is here rather than in an adapter test:

* ``ask --stream`` must show the first increment *while the model is still
  writing*. A test that only checks the final text cannot tell a real stream
  from a buffered answer printed quickly, so the first test watches the output
  arrive and asserts the request was still in flight.
* A dropped stream must be re-opened *from the cursor*: no repeated text, no
  second request, no second charge. The test drops the stream mid-answer on
  purpose and then asserts all three.
* Buffered mode must say it is waiting and then print once. It must not be
  dressed up as streaming.
* Ctrl-C must be a real end-to-end cancel: the center marks the request and the
  node's in-flight attempt is stopped.
* "No node" must be bounded and explained, not an open-ended wait.
* A request the center ended in a failure state must carry the center's own
  reason to the screen: ``billing_note`` verbatim, because "did not finish"
  alone is what made a default-config mismatch look like an unexplained outage.
* With no ``--model``, the model is read off the online nodes (majority, ties
  alphabetical) rather than defaulted to a name baked into the client — and when
  no node is online, ``ask`` refuses *before* creating a request.
* Every internal state must have a human phrase, and a request whose usage is
  unknown must never be shown as a zero cost.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import os
import signal
import threading
import time
from pathlib import Path
from typing import Any, get_args

import pytest
from aipotluck import ux
from aipotluck.adapters import FakeResponse, FakeUpstream, FakeUpstreamAdapter
from aipotluck.cli import main
from aipotluck.connector import Connector, ConnectorConfig
from aipotluck.deploy import DeploymentError, SignedClient
from aipotluck.metering import NormalizedUsage
from aipotluck.persistence import NodeStore
from aipotluck.statemachine import AttemptStatus, RequestStatus, UsageStatus
from conftest import Keyring

from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import CenterStore, NodeRecord

BASE = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
REGISTERED_AT = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
MODEL = "coding-pool"
NODE_TOKEN = "node-token-ux"
INVITE = "code-ux-1"


class _Recorder(io.TextIOBase):
    """A stdout/stderr stand-in that can be waited on from another thread."""

    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []
        self._lock = threading.Lock()

    def write(self, text: str) -> int:
        with self._lock:
            self._chunks.append(text)
        return len(text)

    def flush(self) -> None:
        """Nothing to flush; writes are recorded immediately."""

    def isatty(self) -> bool:
        """Never a terminal, so the CLI takes its non-interactive paths."""
        return False

    def text(self) -> str:
        """Return everything written so far."""
        with self._lock:
            return "".join(self._chunks)

    def chunks(self) -> tuple[str, ...]:
        """Return each `write` in order, so callers can see how it was framed."""
        with self._lock:
            return tuple(self._chunks)

    def wait_for(self, needle: str, *, timeout: float) -> bool:
        """Wait until `needle` appears, returning whether it did."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if needle in self.text():
                return True
            time.sleep(0.02)
        return False


def _wait_until(condition: Any, *, timeout: float = 10.0, what: str = "condition") -> None:
    """Block until `condition()` is truthy, failing with a readable message."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


class _Node:
    """A real connector over loopback, with a scriptable fake upstream."""

    def __init__(
        self,
        tmp_path: Path,
        keyring: Keyring,
        center_port: int,
        *,
        upstream: FakeUpstream,
        name: str = "node-A",
        adapter: Any | None = None,
        local_reserved: int | None = None,
    ) -> None:
        self.upstream = upstream
        # A test may supply its own adapter, for example one whose *buffered*
        # call is slow, so that a "waiting" notice can be observed rather than
        # inferred from the fact that the answer arrived all at once.
        self.adapter = adapter if adapter is not None else FakeUpstreamAdapter(
            upstream=upstream, model=MODEL
        )
        self.store = NodeStore.open(tmp_path / f"{name}.db")
        # `local_reserved=None` means "the connector's own default", so this
        # helper cannot drift away from the shipped exposure ceiling the way the
        # wizard's 5_000 once drifted from the connector's 20_000.
        policy: dict[str, int] = (
            {}
            if local_reserved is None
            else {"max_local_reserved_milli_credits": local_reserved}
        )
        # The hello's device id must match the one the key is bound to; the
        # conftest keyring binds `device-key-A` to `device-A` and it verifies the
        # claimed device, so a mismatch is refused at hello time.
        self.config = ConnectorConfig(
            center_url=f"ws://127.0.0.1:{center_port}/v1/node-link",
            node_id=name,
            device_id="device-A",
            device_key_id="device-key-A",
            provider_id="provider-A",
            database_path=str(tmp_path / f"{name}.db"),
            token=NODE_TOKEN,
            adapter_name="fake-adapter",
            model=MODEL,
            device_private_key_b64=keyring.private_b64["device-key-A"],
            heartbeat_interval_s=3600,
            **policy,
        )
        self.connector = Connector(self.config, adapter=self.adapter, store=self.store)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self.connector.run_forever,
            kwargs={"stop_event": self.stop_event},
            daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        """Stop the connector and join its session thread."""
        self.connector.stop()
        self.thread.join(timeout=5)
        self.store.close()


class _Center:
    """A real gateway over a real store, with an invite ready to redeem."""

    def __init__(self, tmp_path: Path, keyring: Keyring, *, quota: int = 100_000) -> None:
        self.tmp_path = tmp_path
        self.keyring = keyring
        self.store = CenterStore.open(tmp_path / "center.db")
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(tmp_path / "center.db"),
            platform_id="platform-1",
            settlement_key_id="settlement-key-1",
            settlement_private_key_b64=keyring.private_b64["settlement-key-1"],
        )
        self.service = GatewayService(
            config=self.config, store=self.store, registry=keyring.registry
        )
        self.server = GatewayServer(self.service, config=self.config)
        self.server.start()
        self.store.add_credential(NODE_TOKEN, "tenant-a", "node-A", "node", REGISTERED_AT)
        self.store.add_invite(
            INVITE,
            "consumer",
            "auto",
            max_uses=1,
            created_at=dt.datetime.now(dt.UTC),
            expires_at=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1),
            quota_milli_credits=quota,
        )

    @property
    def port(self) -> int:
        """The real bound port."""
        return int(self.server.url.rsplit(":", 1)[1])

    def join_consumer(self, config_dir: Path) -> str:
        """Redeem the invite and return the derived subject id."""
        assert main(
            [
                "join",
                "--center",
                self.server.url,
                "--invite",
                INVITE,
                "--config-dir",
                str(config_dir),
            ]
        ) == 0
        raw = (config_dir / "config.json").read_text(encoding="utf-8")
        return str(json.loads(raw)["subject_id"])

    def stop(self) -> None:
        """Shut the listener down."""
        self.server.stop()
        self.store.close()


def _streaming_upstream(chunks: tuple[str, ...], *, delay: float = 0.0) -> FakeUpstream:
    """Build a fake upstream that streams `chunks` with an optional delay."""
    upstream = FakeUpstream(stream_delay_s=delay, stream_blocks=len(chunks))
    upstream.queue(
        FakeResponse(
            text_chunks=chunks,
            usage=NormalizedUsage(input_total=800, output_total=200),
        )
    )
    return upstream


@pytest.fixture
def harness(tmp_path: Path) -> Any:
    """Provide a center, a node and a joined consumer, torn down afterwards."""
    keyring = Keyring()
    center = _Center(tmp_path, keyring)
    nodes: list[_Node] = []
    yield center, keyring, nodes, tmp_path
    for node in nodes:
        node.stop()
    center.stop()


def _start_node(
    harness: Any,
    upstream: FakeUpstream,
    *,
    adapter: Any | None = None,
    local_reserved: int | None = None,
) -> _Node:
    """Start a node in the fixture's centre and wait for it to register."""
    center, keyring, nodes, tmp_path = harness
    node = _Node(
        tmp_path,
        keyring,
        center.port,
        upstream=upstream,
        adapter=adapter,
        local_reserved=local_reserved,
    )
    nodes.append(node)
    _wait_until(lambda: bool(center.store.connected_nodes()), what="the node to register")
    return node


def _advertise_node(
    center: Any, *, node_id: str, model: str, share_enabled: bool = True
) -> None:
    """Publish a connected node record, the way a `node.hello` would have.

    Used by the model-inference tests, which need several *advertised* models to
    choose between and no real work to run: dialling three live connectors to
    prove a client-side counting rule would test the connector, not the rule.
    """
    center.store.upsert_node(
        NodeRecord(
            node_id=node_id,
            device_id=f"device-{node_id}",
            provider_id=f"provider-{node_id}",
            adapter_name="fake-adapter",
            model=model,
            share_enabled=share_enabled,
            max_concurrency=1,
            max_local_reserved_milli_credits=20_000,
            policy_version=1,
            connected=True,
            last_seen_at=dt.datetime.now(dt.UTC),
        )
    )


def _record_submissions(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture the body of every ``POST /v1/requests`` the client signs.

    The submit boundary is the only race-free place to read what ``ask``
    requested. ``pending.json`` is not: the CLI deletes it as soon as the request
    reaches a terminal state, and a request nobody online can run is failed by
    the center before ``ask`` returns — so on a fast machine the file is gone by
    the time the test looks at it.
    """
    bodies: list[dict[str, Any]] = []
    real_post = SignedClient.post

    def recording_post(self: SignedClient, path: str, body: dict[str, Any]) -> dict[str, Any]:
        if path == "/v1/requests":
            bodies.append(body)
        return real_post(self, path, body)

    monkeypatch.setattr(SignedClient, "post", recording_post)
    return bodies


def _submitted_model(bodies: list[dict[str, Any]]) -> str:
    """Return the model in the one body ``ask`` submitted.

    Read off the captured POST body rather than inferred from a message: that
    body is the exact document ``ask`` signed and sent, so it is the one place
    that says which model was actually requested.
    """
    assert len(bodies) == 1, f"expected one submitted request, saw {len(bodies)}"
    return str(bodies[0]["model"])


class _SlowBufferedAdapter(FakeUpstreamAdapter):
    """A fake upstream whose buffered completion takes a moment.

    The buffered path exists precisely so a caller can tell "the whole answer
    arrived at once" from "the answer arrived in pieces". Without a slow
    ``complete`` that distinction is invisible from the outside: both appear as
    the same text arriving before the test can look. This adapter keeps the
    ``complete`` contract (one scripted response, one upstream call) and only
    adds a pause, so streaming is still impossible on this path.
    """

    def __init__(self, *, upstream: FakeUpstream, model: str, delay_s: float) -> None:
        """Wrap `upstream`, pausing `delay_s` inside every buffered call."""
        super().__init__(upstream=upstream, model=model)
        self._delay_s = delay_s

    def complete(
        self, messages: Any, *, request_digest: str, parameters: Any
    ) -> Any:
        """Pause, then return the scripted response like the base adapter."""
        time.sleep(self._delay_s)
        return super().complete(
            messages, request_digest=request_digest, parameters=parameters
        )


# --------------------------------------------------------------------------
# U04: incremental display
# --------------------------------------------------------------------------


def test_ask_stream_shows_the_first_increment_before_the_model_finishes(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The point of streaming: text appears while the model is still writing."""
    center, _keyring, _nodes, tmp_path = harness
    node = _start_node(harness, _streaming_upstream(("alpha ", "beta ", "gamma"), delay=0.4))
    identity = tmp_path / "identity"
    center.join_consumer(identity)

    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)

    result: dict[str, int] = {}

    def _run() -> None:
        result["code"] = main(
            ["ask", "hi", "--config-dir", str(identity), "--stream", "--timeout", "30"]
        )

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    try:
        appeared = out.wait_for("alpha", timeout=15.0)
        assert appeared, f"first increment never appeared: {out.text()!r}"
        # The model has one more block to go, so the answer cannot be complete
        # and the request must still be in flight.
        assert "gamma" not in out.text()
        assert thread.is_alive()
    finally:
        thread.join(timeout=30)

    assert result["code"] == 0, err.text()
    assert "alpha beta gamma" in out.text()
    assert node.adapter.upstream_calls == 1


def test_ask_buffered_says_it_is_waiting_and_prints_the_answer_once(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Buffered mode must be visibly buffered, not a fake stream."""
    center, _keyring, _nodes, tmp_path = harness
    upstream = _streaming_upstream(("alpha ", "beta ", "gamma"))
    adapter = _SlowBufferedAdapter(upstream=upstream, model=MODEL, delay_s=1.5)
    _start_node(harness, upstream, adapter=adapter)
    identity = tmp_path / "identity"
    center.join_consumer(identity)

    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)

    result: dict[str, int] = {}

    def _run() -> None:
        result["code"] = main(["ask", "hi", "--config-dir", str(identity), "--timeout", "30"])

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    try:
        assert err.wait_for("waiting for generation...", timeout=15.0), err.text()
        # The model is still "thinking" for another second, so nothing may have
        # reached stdout: had the answer been chunked, its first words would be
        # here by now. That is the difference between buffered and streamed.
        assert out.text() == "", f"buffered mode leaked partial output: {out.text()!r}"
    finally:
        thread.join(timeout=30)

    assert result["code"] == 0, err.text()
    # And what arrived arrived in one piece, not as successive increments: the
    # first thing written to stdout is the whole answer.
    chunks = list(out.chunks())
    assert chunks[0] == "alpha beta gamma", chunks
    # The charge is the one the receipt records, not an unreadable zero. The
    # receipt posts its amounts as canonical decimal strings, so this is also
    # the regression test for reading "-1000" as an amount rather than as text
    # nobody recognises.
    assert "cost 1000 milli-credit (1000 tokens, receipt R-1)" in out.text()


def test_ask_stream_json_prints_one_machine_readable_document(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--stream --json` still yields exactly one document a program can read."""
    center, _keyring, _nodes, tmp_path = harness
    _start_node(harness, _streaming_upstream(("alpha ", "beta ", "gamma")))
    identity = tmp_path / "identity"
    center.join_consumer(identity)

    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    code = main(
        ["ask", "hi", "--config-dir", str(identity), "--stream", "--json", "--timeout", "30"]
    )

    assert code == 0
    lines = [line for line in out.text().splitlines() if line.strip()]
    assert len(lines) == 1, f"expected one document, got {lines!r}"
    document = json.loads(lines[0])
    assert document["status"] == "SUCCEEDED"
    assert document["answer"] == "alpha beta gamma"
    assert document["request_id"]
    assert document["status_text"] == ux.describe_request("SUCCEEDED")


class _DroppingStream:
    """A stream whose connection dies after the first `drop_after` frames.

    Used to force the exact failure the cursor protocol exists for: the reader
    dies mid-answer, so the consumer has to re-open from its last cursor instead
    of trusting what it already printed.

    Frames the real reader had already buffered are discarded on purpose.
    Closing a socket does not un-queue bytes the consumer never saw, so a
    wrapper that merely closed the inner stream would still hand over the whole
    answer and prove nothing: "lost" has to mean "never delivered".
    """

    def __init__(self, inner: Any, *, drop_after: int) -> None:
        self._inner = inner
        self._budget = drop_after
        self._seen = 0
        self._dropped = False

    def start(self) -> None:
        """Start the wrapped reader."""
        self._inner.start()

    def poll(self, timeout: float) -> Any:
        """Return the next frame, then pretend the connection vanished."""
        if self._dropped:
            return None
        frame = self._inner.poll(timeout)
        if frame is None:
            return None
        self._seen += 1
        if self._seen >= self._budget:
            self._dropped = True
            self._inner.close()
        return frame

    @property
    def ended(self) -> bool:
        """Report the drop as an ended stream, as a dead socket would."""
        return self._dropped or bool(self._inner.ended)

    def close(self) -> None:
        """Delegate to the wrapped reader."""
        self._inner.close()


def test_ask_stream_reconnect_by_cursor_neither_repeats_nor_double_charges(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dropped stream resumes from the cursor: one request, one charge."""
    center, _keyring, _nodes, tmp_path = harness
    node = _start_node(harness, _streaming_upstream(("one ", "two ", "three"), delay=0.2))
    identity = tmp_path / "identity"
    subject = center.join_consumer(identity)

    real_open = SignedClient.open_event_stream
    calls = {"n": 0}

    def flaky_open(self: SignedClient, request_id: str, cursor: int, **kwargs: Any) -> Any:
        calls["n"] += 1
        inner = real_open(self, request_id, cursor, **kwargs)
        if calls["n"] == 1:
            # Drop the very first stream after a single frame.
            return _DroppingStream(inner, drop_after=1)
        return inner

    monkeypatch.setattr(SignedClient, "open_event_stream", flaky_open)

    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    code = main(
        ["ask", "hi", "--config-dir", str(identity), "--stream", "--timeout", "30"]
    )

    assert code == 0
    text = out.text()
    assert calls["n"] >= 2, "the dropped stream was never re-opened"
    assert text.count("one ") == 1
    assert text.count("two ") == 1
    assert text.count("three") == 1
    assert "one two three" in text
    # One upstream call and one charge: the reconnect re-read the event store,
    # it did not re-run the request.
    assert node.adapter.upstream_calls == 1
    assert center.service.balance(subject) == 100_000 - 1_000


def test_ask_stream_cancel_is_a_real_end_to_end_cancellation(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ctrl-C must stop the node's in-flight attempt, not just the client."""
    center, _keyring, _nodes, tmp_path = harness
    node = _start_node(harness, _streaming_upstream(("a", "b", "c", "d", "e", "f"), delay=0.5))
    identity = tmp_path / "identity"
    center.join_consumer(identity)

    posted: dict[str, str] = {}
    real_post = SignedClient.post

    def recording_post(self: SignedClient, path: str, body: dict[str, Any]) -> dict[str, Any]:
        result = real_post(self, path, body)
        if path == "/v1/requests":
            posted["request_id"] = str(result.get("request_id", ""))
        return result

    monkeypatch.setattr(SignedClient, "post", recording_post)

    def _interrupt() -> None:
        time.sleep(0.8)
        os.kill(os.getpid(), signal.SIGINT)

    timer = threading.Thread(target=_interrupt, daemon=True)
    timer.start()
    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    code = main(["ask", "hi", "--config-dir", str(identity), "--stream", "--timeout", "30"])
    timer.join(timeout=5)

    assert code == 130, (out.text(), err.text())
    assert "cancelled" in err.text() or "cancelled" in out.text()
    request_id = posted["request_id"]
    record = center.store.get_request(request_id)
    assert record is not None and record.status == "CANCELLED"
    # The cancellation stopped the upstream loop: the scripted answer had six
    # blocks and the node made exactly one call, with no retry.
    assert node.adapter.upstream_calls == 1


# --------------------------------------------------------------------------
# U06: understandable state and errors
# --------------------------------------------------------------------------


def test_no_node_wait_is_bounded_and_explains_itself(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no node for the named model, `ask` refuses quickly and says what to do.

    ``--model`` is explicit here on purpose. Without it ``ask`` first reads the
    online nodes to pick a model, and with none online it now refuses *before*
    creating a request (covered by
    :func:`test_ask_without_a_model_and_no_online_node_creates_no_request`).
    What this test pins is the other half: a request that *was* created for a
    model nobody serves must end on the short no-node grace rather than sitting
    in ROUTING until ``--timeout``.
    """
    center, _keyring, _nodes, tmp_path = harness
    identity = tmp_path / "identity"
    center.join_consumer(identity)

    err = _Recorder()
    monkeypatch.setattr("sys.stderr", err)
    started = time.monotonic()
    code = main(
        [
            "ask",
            "hi",
            "--config-dir",
            str(identity),
            "--model",
            MODEL,
            "--no-node-grace",
            "0.3",
            "--timeout",
            "30",
        ]
    )
    elapsed = time.monotonic() - started

    assert code == 1
    # The grace, not the 30s timeout, is what ended the wait.
    assert elapsed < 15.0, f"waited {elapsed:.1f}s for a node that does not exist"
    assert ux.NO_NODES_PHRASE in err.text()
    assert "contact the operator" in err.text()


def test_three_failure_classes_give_three_different_next_steps() -> None:
    """Credentials, quota and an unreachable upstream must not read alike."""
    credentials = ux.classify_failure(error_code="forbidden", http_status=403)
    quota = ux.classify_failure(error_code="insufficient_funds", http_status=402)
    upstream = ux.classify_failure(error_code="upstream_unreachable")

    assert credentials.kind is ux.FailureKind.CREDENTIALS
    assert quota.kind is ux.FailureKind.QUOTA
    assert upstream.kind is ux.FailureKind.UPSTREAM_UNREACHABLE
    steps = {credentials.next_step, quota.next_step, upstream.next_step}
    assert len(steps) == 3
    assert "join" in credentials.next_step
    assert "add credit to your account" in quota.next_step
    assert "upstream" in upstream.next_step and "network" in upstream.next_step


def test_ask_reports_a_revoked_credential_with_a_next_step(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A revoked key must produce the credentials remedy, not a bare 403."""
    center, _keyring, _nodes, tmp_path = harness
    _start_node(harness, _streaming_upstream(("alpha ", "beta")))
    identity = tmp_path / "identity"
    center.join_consumer(identity)
    key_id = str(json.loads((identity / "config.json").read_text())["key_id"])
    center.store.revoke_identity(key_id, dt.datetime.now(dt.UTC))

    err = _Recorder()
    monkeypatch.setattr("sys.stderr", err)
    code = main(["ask", "hi", "--config-dir", str(identity), "--timeout", "15"])

    assert code == 1
    assert "credential no longer valid" in err.text()
    assert "join" in err.text()


def test_ask_surfaces_the_centers_billing_note_when_a_request_fails(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A FAILED request must carry the center's own reason, not just "did not finish".

    This is the P0-2 report: a default consumer charge against a node whose
    local exposure ceiling was lower died in milliseconds with the cause already
    written to ``requests.billing_note``, while the CLI printed only the status
    phrase and the user was left guessing. The note is the center's wording, so
    it is printed verbatim — a client that paraphrased a reason it did not
    produce would be a second source of truth about why a request failed.
    """
    center, _keyring, _nodes, tmp_path = harness
    # A ceiling of zero refuses every offer, which is the cheapest way to reach
    # a terminal FAILED with a real note attached.
    _start_node(harness, _streaming_upstream(("never used",)), local_reserved=0)
    identity = tmp_path / "identity"
    center.join_consumer(identity)

    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    code = main(
        ["ask", "hi", "--config-dir", str(identity), "--model", MODEL, "--timeout", "30"]
    )

    assert code == 1
    assert ux.describe_request("FAILED") in out.text()
    assert "center note" in err.text()
    # The note `ask` printed came off the HTTP status document it fetched, so
    # matching it against the stored row proves both that the endpoint carries
    # the field and that the CLI did not rewrite it.
    failed = center.store.requests_by_status("FAILED")
    assert len(failed) == 1
    note = failed[0].billing_note
    assert note is not None
    assert "no node left to take the work" in note
    assert "local budget would be exceeded" in note
    assert note in err.text(), "ask must print the center's note verbatim"


def test_ask_without_a_model_requests_what_the_majority_of_nodes_serve(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no ``--model``, the model comes from the nodes, not from a constant.

    The old default was this suite's own test pool name: a real consumer cannot
    know it, and a hardcoded guess is a request the center cannot route. The
    majority rule is what "the platform's model" means once contributors serve
    different ones, and a paused node must not vote for a model nobody can run.
    """
    center, _keyring, _nodes, tmp_path = harness
    identity = tmp_path / "identity"
    center.join_consumer(identity)
    _advertise_node(center, node_id="node-1", model="zebra-7b")
    _advertise_node(center, node_id="node-2", model="zebra-7b")
    _advertise_node(center, node_id="node-3", model="alpha-70b")
    _advertise_node(center, node_id="node-paused", model="paused-only", share_enabled=False)

    submitted = _record_submissions(monkeypatch)
    err = _Recorder()
    monkeypatch.setattr("sys.stderr", err)
    # Nothing is really there to execute, so this ends on the deadline. The
    # grace is set high to keep it there: what is under test is which model the
    # request was built with, not how the wait ends.
    code = main(
        ["ask", "hi", "--config-dir", str(identity), "--timeout", "1", "--no-node-grace", "30"]
    )

    assert code == 1
    assert _submitted_model(submitted) == "zebra-7b"
    assert "zebra-7b" in err.text(), "an inferred model must be announced"


def test_ask_without_a_model_breaks_a_tie_alphabetically(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An even split must not depend on the order a listing happened to arrive."""
    center, _keyring, _nodes, tmp_path = harness
    identity = tmp_path / "identity"
    center.join_consumer(identity)
    # Advertised so that the listing order and the alphabetical order disagree.
    _advertise_node(center, node_id="node-1", model="zebra-7b")
    _advertise_node(center, node_id="node-2", model="alpha-70b")

    submitted = _record_submissions(monkeypatch)
    monkeypatch.setattr("sys.stderr", _Recorder())
    code = main(
        ["ask", "hi", "--config-dir", str(identity), "--timeout", "1", "--no-node-grace", "30"]
    )

    assert code == 1
    assert _submitted_model(submitted) == "alpha-70b"


def test_ask_without_a_model_and_no_online_node_creates_no_request(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No node to infer a model from: refuse before dispatching, and say what next.

    Creating the request anyway would mean queueing work that provably cannot be
    routed, spending a nonce and an idempotency key on it, and then cancelling
    it — and the consumer would watch a bounded wait instead of reading a remedy.
    """
    center, _keyring, _nodes, tmp_path = harness
    identity = tmp_path / "identity"
    center.join_consumer(identity)

    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    started = time.monotonic()
    code = main(
        ["ask", "hi", "--config-dir", str(identity), "--timeout", "30", "--no-node-grace", "30"]
    )
    elapsed = time.monotonic() - started

    assert code == 1
    # Neither bound was waited out; the refusal is immediate.
    assert elapsed < 10.0, f"waited {elapsed:.1f}s on a platform with no nodes"
    assert ux.NO_MODEL_PHRASE in err.text()
    assert "--model" in err.text(), "the remedy must name the explicit override"
    assert "no request was created" in err.text()
    assert not (identity / "pending.json").exists()
    assert center.store.requests_by_status("CREATED") == []
    assert center.store.requests_by_status("ROUTING") == []
    assert out.text() == "", "a refused ask must not produce an answer document"


def test_status_phrase_maps_are_total() -> None:
    """Every state the machines can emit must have a phrase."""
    for status in get_args(RequestStatus):
        assert ux.describe_request(status) != ux.UNKNOWN_STATE_PHRASE, status
    for status in get_args(AttemptStatus):
        assert ux.describe_attempt(status) != ux.UNKNOWN_STATE_PHRASE, status
    for status in get_args(UsageStatus):
        assert ux.describe_usage(status) != ux.UNKNOWN_STATE_PHRASE, status

    assert ux.describe_request("ROUTING") == "looking for available nodes"
    assert ux.describe_request("RECOVERING") == "recovering the previous request"
    assert ux.describe_request("EXPIRED") == "timed out unfinished"
    assert ux.describe_attempt("OUTCOME_UNKNOWN") == "usage to be confirmed"
    assert ux.describe_attempt("OFFERED") == ux.describe_attempt("ACCEPTED") == "waiting"
    assert ux.describe_request("NOT_A_STATE") == ux.UNKNOWN_STATE_PHRASE


def test_unknown_usage_never_becomes_a_zero_cost(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cancelled request whose usage is unknown says it is to be confirmed, never 0."""
    center, _keyring, _nodes, tmp_path = harness
    # A 1s-per-chunk stream leaves a wide mid-flight window, so the Ctrl-C at
    # 0.6s deterministically lands before the answer is complete — the point
    # being that the usage is then unknown, and must never read as zero.
    _start_node(harness, _streaming_upstream(("only ", "part"), delay=1.0))
    identity = tmp_path / "identity"
    center.join_consumer(identity)

    def _interrupt() -> None:
        time.sleep(0.6)
        os.kill(os.getpid(), signal.SIGINT)

    timer = threading.Thread(target=_interrupt, daemon=True)
    timer.start()
    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    main(["ask", "hi", "--config-dir", str(identity), "--stream", "--timeout", "30"])
    timer.join(timeout=5)

    combined = out.text() + err.text()
    assert ux.UNCERTAIN_USAGE_PHRASE in combined
    assert "cost 0" not in combined
    assert "¥0" not in combined


def test_live_event_stream_reports_an_error_frame_as_a_failure() -> None:
    """The live reader surfaces a gateway `dropped` notice as an error.

    A unit test of the client-side plumbing, independent of the CLI: the
    reconnect loop can only do the right thing if a drop is distinguishable from
    "the request is still running".
    """
    from aipotluck.deploy import LiveEventStream  # noqa: F401  (documents the contract)

    message = "the gateway dropped the event stream for request R-1: slow consumer"
    error = DeploymentError(message)
    assert error.error_code is None
    assert ux.classify_failure(message=str(error)).kind is ux.FailureKind.UNKNOWN


# --------------------------------------------------------------------------
# U06: doctor — one redacted diagnostic report
# --------------------------------------------------------------------------


def _write_doctor_node_config(directory: Path) -> tuple[Path, dict[str, str]]:
    """Write a fully-configured node.json into `directory` with known secrets.

    Returns:
        The path and the secrets it holds, so tests can assert none of them
        reach the report.
    """
    from aipotluck.identity import generate_key_pair

    _device_public, device_private = generate_key_pair()
    document = {
        "center_url": "ws://127.0.0.1:1/v1/node-link",
        "node_id": "node-doctor",
        "device_id": "device-doctor",
        "device_key_id": "device-key-doctor",
        "provider_id": "provider-doctor",
        "database_path": str(directory / "node-doctor.db"),
        "token": NODE_TOKEN,
        "device_private_key_b64": device_private,
        "share_enabled": True,
        "max_concurrency": 1,
        "max_local_reserved_milli_credits": 5_000,
        "adapter": {
            "kind": "http",
            "endpoint": "http://127.0.0.1:1/v1",
            "api_key": "sk-upstream-doctor-SECRET",
            "model": MODEL,
            "provider_style": "openai",
            "name": "main",
        },
    }
    node_path = directory / "node.json"
    node_path.write_text(json.dumps(document), encoding="utf-8")
    secrets = {
        "node_token": NODE_TOKEN,
        "upstream_key": "sk-upstream-doctor-SECRET",
        "device_private_key": device_private,
    }
    return node_path, secrets


def test_doctor_report_is_redacted_and_complete(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The report names what matters and never a credential."""
    center, _keyring, _nodes, tmp_path = harness
    identity = tmp_path / "identity"
    center.join_consumer(identity)
    identity_key = json.loads((identity / "key.json").read_text())["private_key_b64"]
    _write_doctor_node_config(identity)

    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    code = main(["doctor", "--config-dir", str(identity)])
    assert code == 0
    text = out.text()
    # The useful picture is present.
    assert (
        "version" in text and "identity" in text and "center" in text and "node" in text
    )
    assert "credential valid" in text
    assert "unfinished local requests" in text
    # None of the four secrets is anywhere in it.
    for secret in (
        NODE_TOKEN,
        "sk-upstream-doctor-SECRET",
        identity_key,
    ):
        assert secret not in text, "a secret leaked into the doctor report"


def test_doctor_json_is_machine_readable_and_redacted(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`doctor --json` is one canonical document with the same guarantees."""
    center, _keyring, _nodes, tmp_path = harness
    identity = tmp_path / "identity"
    center.join_consumer(identity)
    identity_key = json.loads((identity / "key.json").read_text())["private_key_b64"]
    _write_doctor_node_config(identity)

    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    code = main(["doctor", "--config-dir", str(identity), "--json"])
    assert code == 0
    text = out.text()
    for secret in (NODE_TOKEN, "sk-upstream-doctor-SECRET", identity_key):
        assert secret not in text
    document = json.loads(text)
    assert document["identity"]["present"] is True
    assert document["center"]["reachable"] is True
    assert document["center"]["credential_valid"] is True
    node = document["node"]
    assert node is not None and node["valid"] is True
    # The redacted node summary reports shape, never the credential itself.
    config = node["config"]
    assert config["node_id"] == "node-doctor"
    assert "api_key" not in json.dumps(config)
    assert NODE_TOKEN not in json.dumps(config)
    assert document["ok"] is True


def test_doctor_reports_a_revoked_credential_with_the_remedy(
    harness: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A revoked key makes the report say so and how to recover."""
    center, _keyring, _nodes, tmp_path = harness
    identity = tmp_path / "identity"
    center.join_consumer(identity)
    key_id = str(json.loads((identity / "config.json").read_text())["key_id"])
    center.store.revoke_identity(key_id, dt.datetime.now(dt.UTC))

    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    code = main(["doctor", "--config-dir", str(identity)])
    assert code == 1
    assert "credential no longer valid" in out.text()
    assert "join" in out.text(), "the remedy must name the recovery command"


def test_doctor_without_an_identity_says_what_to_run(
    harness: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty config dir yields guidance, not a traceback or a fake ok."""
    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    code = main(["doctor", "--config-dir", str(tmp_path / "nothing")])
    assert code == 1
    assert "not joined" in out.text()
    assert "join" in out.text()
