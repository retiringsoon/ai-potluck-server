"""U05: the contributor wizard, and pause/resume without editing JSON by hand.

What each test pins, and why:

* ``join --node`` must derive the identity **server-side** and stop at a
  resumable state: the wizard's secrets arrive later, from a file or the
  environment, never a command line (a value on ``ps`` is not a secret).
* The invite path must need **no token anybody copies**. ``join --node``
  receives the node's platform credential from the center and saves it 0600;
  the wizard reads it back. An operator-provisioned token still overrides it,
  and losing it fails with the recovery path named rather than a dead prompt.
* The shipped defaults must agree with each other, or the first request of an
  all-default deployment is refused by the node's own local policy.
* The wizard's node.json must be 0600, conservative by default, and its
  secrets must never reach stdout/stderr — the self-check prints conclusions,
  not configuration.
* The self-check's upstream step is TCP-only by default. A billable live probe
  exists behind an explicit flag *and* a confirmation; a non-interactive
  refusal must have sent nothing.
* ``share pause``/``resume`` must reach a **running** node through its config
  file: the center stops offering, an in-flight task finishes normally, and
  resume re-accepts without a restart. The negative path (a malformed config
  file) must keep the last good policy rather than silently pausing or
  unpausing a node.
"""

from __future__ import annotations

import datetime as dt
import http.client
import io
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from aipotluck.adapters import FakeResponse, FakeUpstream, FakeUpstreamAdapter
from aipotluck.canonical import loads_strict
from aipotluck.cli import (
    ASK_DEFAULT_MAX_CHARGE,
    NODE_DEFAULT_MAX_CONCURRENCY,
    NODE_DEFAULT_MAX_LOCAL_RESERVED_MILLI_CREDITS,
    NODE_TOKEN_ENV,
    UPSTREAM_KEY_ENV,
    main,
)
from aipotluck.connector import Connector, ConnectorConfig
from aipotluck.metering import NormalizedUsage
from aipotluck.persistence import NodeStore
from aipotluck.wire import user_message
from conftest import Keyring, signed_authorization

from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import CenterStore

BASE = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
REGISTERED_AT = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
MODEL = "coding-pool"
TENANT = "tenant-a"
CONSUMER_TOKEN = "consumer-token-wizard"
NODE_TOKEN = "node-token-wizard"
UPSTREAM_KEY = "sk-live-wizard-SECRET-1"
NODE_PLATFORM_TOKEN = "platform-node-token-SECRET-2"

UPSTREAM_KEY_ENV_NAME = UPSTREAM_KEY_ENV
NODE_TOKEN_ENV_NAME = NODE_TOKEN_ENV
#: The one conversation every e2e admission uses; the authorization must bind it.
PROMPT = "write a haiku about sockets"
MESSAGES = (user_message(PROMPT),)


def _wait_until(condition: Any, *, timeout: float = 10.0, what: str = "condition") -> None:
    """Block until `condition()` is truthy, failing with a readable message."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


def _assert_absent_for(condition: Any, *, duration: float, what: str) -> None:
    """Assert `condition()` stays falsy for `duration` seconds."""
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        assert not condition(), f"{what} happened"
        time.sleep(0.05)


class _Recorder(io.TextIOBase):
    """A stdout/stderr stand-in that records every write."""

    def __init__(self) -> None:
        super().__init__()
        self._chunks: list[str] = []

    def write(self, text: str) -> int:
        self._chunks.append(text)
        return len(text)

    def flush(self) -> None:
        """Nothing to flush; writes are recorded immediately."""

    def isatty(self) -> bool:
        """Never a terminal, so the CLI takes its non-interactive paths."""
        return False

    def text(self) -> str:
        """Return everything written so far."""
        return "".join(self._chunks)


class _TcpHold:
    """A bare TCP listener, used to prove reachability without an HTTP peer."""

    def __init__(self) -> None:
        self._socket = socket.socket()
        self._socket.bind(("127.0.0.1", 0))
        self._socket.listen(4)

    @property
    def url(self) -> str:
        """A base URL pointing at the listener."""
        host, port = self._socket.getsockname()
        return f"http://{host}:{port}"

    def close(self) -> None:
        """Release the port."""
        self._socket.close()


class _RecordingUpstream:
    """A minimal OpenAI-shaped HTTP upstream that records every request."""

    def __init__(self) -> None:
        self.requests: list[tuple[str, bytes]] = []
        self._lock = threading.Lock()
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("content-length", "0"))
                body = self.rfile.read(length)
                with outer._lock:
                    outer.requests.append(
                        (self.headers.get("authorization", ""), body)
                    )
                payload = json.dumps(
                    {
                        "choices": [
                            {"message": {"role": "assistant", "content": "pong"}}
                        ],
                        "usage": {
                            "prompt_tokens": 1,
                            "completion_tokens": 1,
                            "total_tokens": 2,
                        },
                    }
                ).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args: Any) -> None:
                """Keep the test output clean."""

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        """The base URL of the fake upstream."""
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/v1"

    @property
    def request_count(self) -> int:
        """How many requests have reached the upstream."""
        return len(self.requests)

    def close(self) -> None:
        """Shut the server down."""
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class _Center:
    """A real gateway with a consumer invite, a node invite and funded accounts."""

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
        self.now = dt.datetime.now(dt.UTC)
        self.store.add_invite(
            "invite-consumer-wizard",
            "consumer",
            "auto",
            max_uses=1,
            created_at=self.now,
            expires_at=self.now + dt.timedelta(hours=1),
            quota_milli_credits=quota,
        )
        self.store.add_invite(
            "invite-node-wizard",
            "node",
            "auto",
            max_uses=1,
            created_at=self.now,
            expires_at=self.now + dt.timedelta(hours=1),
        )

    @property
    def url(self) -> str:
        """The real base URL."""
        return self.server.url

    def stop(self) -> None:
        """Shut the listener down."""
        self.server.stop()
        self.store.close()


@pytest.fixture
def center(tmp_path: Path) -> Any:
    """Provide a real center, torn down afterwards."""
    keyring = Keyring()
    harness = _Center(tmp_path, keyring)
    yield harness
    harness.stop()


def _join_node_stopped(
    center: _Center, identity: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Run `join --node --no-setup` with the secrets held in the environment."""
    monkeypatch.setenv(UPSTREAM_KEY_ENV_NAME, UPSTREAM_KEY)
    monkeypatch.setenv(NODE_TOKEN_ENV_NAME, NODE_PLATFORM_TOKEN)
    assert (
        main(
            [
                "join",
                "--center",
                center.url,
                "--invite",
                "invite-node-wizard",
                "--node",
                "--no-setup",
                "--config-dir",
                str(identity),
            ]
        )
        == 0
    )


# --------------------------------------------------------------------------
# join --node: server-derived identity, resumable stop
# --------------------------------------------------------------------------


def test_join_node_derives_the_identity_and_stops_at_a_resumable_state(
    center: _Center, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The node identity is derived by the center; the wizard can resume later."""
    identity = tmp_path / "node-identity"
    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    _join_node_stopped(center, identity, monkeypatch)

    config = json.loads((identity / "config.json").read_text(encoding="utf-8"))
    assert config["role"] == "node"
    # Every identity field is server-derived: the CLI never sent one.
    for field in ("subject_id", "device_id", "device_key_id", "provider_id"):
        assert isinstance(config[field], str) and config[field], field
    key_document = json.loads((identity / "key.json").read_text(encoding="utf-8"))
    # The device key pair was generated locally and only its public half sent.
    assert key_document["device_private_key_b64"]
    assert key_document["device_public_key_b64"]

    # No secret may appear in either stream: not the upstream key, not the
    # platform token, not a private key.
    for secret in (
        UPSTREAM_KEY,
        NODE_PLATFORM_TOKEN,
        key_document["device_private_key_b64"],
        key_document["private_key_b64"],
    ):
        assert secret not in out.text(), "a secret leaked to stdout"
        assert secret not in err.text(), "a secret leaked to stderr"


# --------------------------------------------------------------------------
# the wizard: config, self-check, and the billable-probe gate
# --------------------------------------------------------------------------


def _run_share_setup(
    monkeypatch: pytest.MonkeyPatch, identity: Path, *extra: str
) -> int:
    """Run `share setup` against the joined identity, secrets in the env."""
    monkeypatch.setenv(UPSTREAM_KEY_ENV_NAME, UPSTREAM_KEY)
    monkeypatch.setenv(NODE_TOKEN_ENV_NAME, NODE_PLATFORM_TOKEN)
    return main(
        [
            "share",
            "setup",
            "--config-dir",
            str(identity),
            "--upstream-endpoint",
            "http://127.0.0.1:1/v1",
            "--upstream-model",
            MODEL,
            *extra,
        ]
    )


def test_wizard_writes_a_conservative_0600_config_and_reports_the_failed_upstream(
    center: _Center, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A dead upstream fails the self-check with a remedy; config is still safe."""
    identity = tmp_path / "node-identity"
    _join_node_stopped(center, identity, monkeypatch)

    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    code = _run_share_setup(monkeypatch, identity)
    monkeypatch.delenv(UPSTREAM_KEY_ENV_NAME)
    monkeypatch.delenv(NODE_TOKEN_ENV_NAME)

    # 127.0.0.1:1 is refused, so the self-check must fail and say why.
    assert code == 1
    assert "upstream unreachable" in err.text()
    assert "network" in err.text(), "the upstream remedy must name the local network"
    # The check order is the wizard's promise: three numbered conclusions.
    assert "self-check 1/3" in out.text() and "self-check 2/3" in out.text()

    node_path = identity / "node.json"
    assert node_path.exists()
    assert (node_path.stat().st_mode & 0o777) == 0o600, "node.json must be 0600"
    document = loads_strict(node_path.read_text(encoding="utf-8"))
    assert document["share_enabled"] is True
    assert document["max_concurrency"] == NODE_DEFAULT_MAX_CONCURRENCY == 1
    assert (
        document["max_local_reserved_milli_credits"]
        == NODE_DEFAULT_MAX_LOCAL_RESERVED_MILLI_CREDITS
    )
    assert document["adapter"]["api_key"] == UPSTREAM_KEY  # local only
    assert document["token"] == NODE_PLATFORM_TOKEN  # local only

    # Neither secret may appear in any output the wizard produced.
    for secret in (UPSTREAM_KEY, NODE_PLATFORM_TOKEN):
        assert secret not in out.text()
        assert secret not in err.text()


def test_wizard_self_check_passes_when_upstream_and_center_are_reachable(
    center: _Center, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a reachable upstream, all three checks pass and the CLI says so."""
    identity = tmp_path / "node-identity"
    _join_node_stopped(center, identity, monkeypatch)
    hold = _TcpHold()
    try:
        monkeypatch.setenv(UPSTREAM_KEY_ENV_NAME, UPSTREAM_KEY)
        monkeypatch.setenv(NODE_TOKEN_ENV_NAME, NODE_PLATFORM_TOKEN)
        out = _Recorder()
        err = _Recorder()
        monkeypatch.setattr("sys.stdout", out)
        monkeypatch.setattr("sys.stderr", err)
        code = main(
            [
                "share",
                "setup",
                "--config-dir",
                str(identity),
                "--upstream-endpoint",
                f"{hold.url}/v1",
                "--upstream-model",
                MODEL,
            ]
        )
    finally:
        hold.close()
    monkeypatch.delenv(UPSTREAM_KEY_ENV_NAME)
    monkeypatch.delenv(NODE_TOKEN_ENV_NAME)

    assert code == 0, err.text()
    assert "configuration complete" in out.text()
    assert "upstream reachable" in out.text()
    assert (
        "TCP only, no credential sent" in out.text()
    ), "the TCP check must say it is credential-free"
    assert "center reachable" in out.text()
    assert "[step 3] ready" in out.text()


def test_default_self_check_sends_nothing_and_live_probe_needs_confirmation(
    center: _Center, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default check is credential-free; the live probe is gated twice."""
    identity = tmp_path / "node-identity"
    _join_node_stopped(center, identity, monkeypatch)
    upstream = _RecordingUpstream()
    try:
        # Default: TCP-only. Nothing billable, nothing credential-bearing.
        out = _Recorder()
        err = _Recorder()
        monkeypatch.setattr("sys.stdout", out)
        monkeypatch.setattr("sys.stderr", err)
        code = main(
            [
                "share",
                "setup",
                "--config-dir",
                str(identity),
                "--upstream-endpoint",
                upstream.url,
                "--upstream-model",
                MODEL,
            ]
        )
        assert code == 0
        assert upstream.request_count == 0, "the default check must not send a request"

        # Live probe requested but not confirmed, on a non-terminal: refused,
        # and still nothing has been sent.
        out = _Recorder()
        err = _Recorder()
        monkeypatch.setattr("sys.stdout", out)
        monkeypatch.setattr("sys.stderr", err)
        code = _run_share_setup(
            monkeypatch, identity, "--upstream-endpoint", upstream.url, "--probe-upstream-live"
        )
        monkeypatch.delenv(UPSTREAM_KEY_ENV_NAME)
        monkeypatch.delenv(NODE_TOKEN_ENV_NAME)
        assert code == 1
        assert "not confirmed" in err.text() or "confirm" in err.text()
        assert upstream.request_count == 0

        # Explicitly confirmed: one real request, carrying the credential,
        # reported in plain words.
        out = _Recorder()
        err = _Recorder()
        monkeypatch.setattr("sys.stdout", out)
        monkeypatch.setattr("sys.stderr", err)
        code = _run_share_setup(
            monkeypatch,
            identity,
            "--upstream-endpoint",
            upstream.url,
            "--probe-upstream-live",
            "--yes",
        )
        monkeypatch.delenv(UPSTREAM_KEY_ENV_NAME)
        monkeypatch.delenv(NODE_TOKEN_ENV_NAME)
        assert code == 0, err.text()
        assert upstream.request_count == 1
        authorization, _body = upstream.requests[0]
        assert authorization == f"Bearer {UPSTREAM_KEY}"
        assert "live probe succeeded" in out.text()
        # The probe's own report must not echo the credential either.
        assert UPSTREAM_KEY not in out.text()
    finally:
        upstream.close()


# --------------------------------------------------------------------------
# share status / pause / resume: the local control surface
# --------------------------------------------------------------------------


def test_share_status_pause_and_resume_flip_the_switch_redacted(
    center: _Center, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pause/resume edit node.json only, and status never prints a secret."""
    identity = tmp_path / "node-identity"
    _join_node_stopped(center, identity, monkeypatch)
    upstream = _RecordingUpstream()
    try:
        monkeypatch.setenv(UPSTREAM_KEY_ENV_NAME, UPSTREAM_KEY)
        monkeypatch.setenv(NODE_TOKEN_ENV_NAME, NODE_PLATFORM_TOKEN)
        assert (
            main(
                [
                    "share",
                    "setup",
                    "--config-dir",
                    str(identity),
                    "--upstream-endpoint",
                    upstream.url,
                    "--upstream-model",
                    MODEL,
                ]
            )
            == 0
        )
    finally:
        upstream.close()
    monkeypatch.delenv(UPSTREAM_KEY_ENV_NAME)
    monkeypatch.delenv(NODE_TOKEN_ENV_NAME)

    node_path = identity / "node.json"
    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    assert main(["share", "status", "--config-dir", str(identity)]) == 0
    assert "sharing: enabled" in out.text()
    assert UPSTREAM_KEY not in out.text() and NODE_PLATFORM_TOKEN not in out.text()

    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    assert (
        main(["share", "status", "--config-dir", str(identity), "--json"]) == 0
    )
    document = json.loads(out.text().splitlines()[-1])
    assert document["share_enabled"] is True
    assert document["max_concurrency"] == 1
    assert UPSTREAM_KEY not in out.text() and NODE_PLATFORM_TOKEN not in out.text()

    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    assert main(["share", "pause", "--config-dir", str(identity)]) == 0
    assert "sharing paused" in out.text()
    assert loads_strict(node_path.read_text(encoding="utf-8"))["share_enabled"] is False

    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    assert main(["share", "status", "--config-dir", str(identity)]) == 0
    assert "sharing: paused" in out.text()

    out = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    assert main(["share", "resume", "--config-dir", str(identity)]) == 0
    assert loads_strict(node_path.read_text(encoding="utf-8"))["share_enabled"] is True


def test_share_pause_without_a_config_explains_what_to_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pausing an unconfigured machine is an actionable error, not a traceback."""
    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    code = main(["share", "pause", "--config-dir", str(tmp_path / "nothing")])
    assert code == 1
    assert "share setup" in err.text() or "join --node" in err.text()


# --------------------------------------------------------------------------
# pause/resume reaching a *running* node, without a restart
# --------------------------------------------------------------------------


class _Centered:
    """The e2e harness: a funded consumer, a node credential, real HTTP."""

    def __init__(self, tmp_path: Path, keyring: Keyring) -> None:
        self.keyring = keyring
        self.tmp_path = tmp_path
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
        self.store.add_credential(
            CONSUMER_TOKEN, TENANT, "consumer-X", "consumer", REGISTERED_AT
        )
        self.store.add_credential(NODE_TOKEN, TENANT, "node-A", "node", REGISTERED_AT)
        self.service.fund_account(
            account_id="consumer-X", kind="consumer_available", amount=100_000, now=BASE
        )

    @property
    def port(self) -> int:
        """The real bound port."""
        return int(self.server.url.rsplit(":", 1)[1])

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

    def get(self, path: str) -> tuple[int, dict[str, Any]]:
        """GET an authenticated resource."""
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        connection.request("GET", path, headers={"authorization": f"Bearer {CONSUMER_TOKEN}"})
        response = connection.getresponse()
        raw = response.read()
        connection.close()
        return response.status, (loads_strict(raw) if raw else {})

    def admit(self, request_id: str, idempotency_key: str) -> dict[str, Any]:
        """Submit one buffered request through the real API."""
        moment = dt.datetime.now(dt.UTC)
        record = signed_authorization(
            self.keyring,
            request_id=request_id,
            issued_at=moment - dt.timedelta(minutes=1),
            expires_at=moment + dt.timedelta(minutes=10),
            max_charge_milli_credits=4_000,
            messages=MESSAGES,
            model=MODEL,
        )
        status, document = self.post(
            "/v1/requests",
            {
                "idempotency_key": idempotency_key,
                "messages": [message.to_payload() for message in MESSAGES],
                "model": MODEL,
                "delivery_mode": "buffered_complete",
                "max_attempts": 2,
                "deadline_ms": 60_000,
                # Below the node's own conservative exposure ceiling, so the
                # local reserve admits it (0 + charge must fit the cap).
                "max_charge_milli_credits": 4_000,
                "authorization": {
                    "schema": record.schema,
                    "record_id": record.record_id,
                    "revision": record.revision,
                    "signed_at": record.signed_at.isoformat(),
                    "signer_key_id": record.signer_key_id,
                    "signer_id": record.signer_id,
                    "signature": record.signature,
                    "payload": dict(record.payload),
                    "previous_record_hash": record.previous_record_hash,
                },
            },
        )
        assert status == 200, document
        return document

    def status_of(self, request_id: str) -> dict[str, Any]:
        """Return the status document for a request."""
        _code, document = self.get(f"/v1/requests/{request_id}")
        return document

    def stop(self) -> None:
        """Shut the listener down."""
        self.server.stop()
        self.store.close()


class _GatedAdapter(FakeUpstreamAdapter):
    """A fake adapter whose buffered call waits for a test-owned gate.

    The gate holds the "in-flight" window open while the pause travels, which
    is the whole point of the acceptance: a pause must not disturb work that
    has already been accepted.
    """

    def __init__(self, *, upstream: FakeUpstream, model: str) -> None:
        super().__init__(upstream=upstream, model=model)
        self.entered = threading.Event()
        self.gate = threading.Event()

    def complete(self, messages: Any, *, request_digest: str, parameters: Any) -> Any:
        """Signal entry, wait for the gate, then run the scripted response."""
        self.entered.set()
        assert self.gate.wait(timeout=30), "the test never released the in-flight call"
        return super().complete(
            messages, request_digest=request_digest, parameters=parameters
        )


def _wait_until_share_registered(
    center: _Centered, *, enabled: bool, what: str
) -> None:
    """Wait until the center's node record advertises the given share state."""
    _wait_until(
        lambda: (
            (record := center.store.get_node("node-A")) is not None
            and record.connected
            and record.share_enabled is enabled
        ),
        what=what,
    )


def test_pause_reaches_a_running_node_without_a_restart(tmp_path: Path) -> None:
    """pause stops new offers, the in-flight task finishes, resume re-accepts."""
    keyring = Keyring()
    center = _Centered(tmp_path, keyring)
    node_json = tmp_path / "node.json"
    node_json.write_text(
        json.dumps(
            {
                "share_enabled": True,
                "max_concurrency": 1,
                "max_local_reserved_milli_credits": 5_000,
            }
        ),
        encoding="utf-8",
    )
    upstream = FakeUpstream()
    upstream.queue(
        FakeResponse(
            text_chunks=("first ", "answer"),
            usage=NormalizedUsage(input_total=800, output_total=200),
        )
    )
    upstream.queue(
        FakeResponse(
            text_chunks=("second ", "answer"),
            usage=NormalizedUsage(input_total=800, output_total=200),
        )
    )
    adapter = _GatedAdapter(upstream=upstream, model=MODEL)
    config = ConnectorConfig(
        center_url=f"ws://127.0.0.1:{center.port}/v1/node-link",
        node_id="node-A",
        device_id="device-A",
        device_key_id="device-key-A",
        provider_id="provider-A",
        database_path=str(tmp_path / "node.db"),
        token=NODE_TOKEN,
        adapter_name="fake-adapter",
        model=MODEL,
        device_private_key_b64=keyring.private_b64["device-key-A"],
        heartbeat_interval_s=3600,
        config_path=str(node_json),
    )
    store = NodeStore.open(tmp_path / "node.db")
    connector = Connector(config, adapter=adapter, store=store)
    stop = threading.Event()
    thread = threading.Thread(
        target=connector.run_forever, kwargs={"stop_event": stop}, daemon=True
    )
    thread.start()
    try:
        _wait_until(
            lambda: bool(center.store.connected_nodes()), what="the node to register"
        )

        # 1. An in-flight task is executing when the pause lands.
        document = center.admit("R-wiz-1", "idem-wiz-1")
        request_id = document["request_id"]
        _wait_until(lambda: adapter.entered.is_set(), what="the upstream call to start")
        assert (
            main(["share", "pause", "--config", str(node_json)]) == 0
        ), "share pause failed"

        # The pause reaches the center through the polled file, not a restart:
        # the node stays connected the whole time.
        _wait_until_share_registered(center, enabled=False, what="the pause to register")

        # 2. The in-flight task finishes normally and settles.
        adapter.gate.set()
        _wait_until(
            lambda: center.status_of(request_id).get("settlement") is not None,
            what="the in-flight request to settle despite the pause",
        )
        assert center.status_of(request_id)["status"] == "SUCCEEDED"
        assert upstream.call_count == 1

        # 3. No new work while paused.
        document = center.admit("R-wiz-2", "idem-wiz-2")
        paused_id = document["request_id"]
        _assert_absent_for(
            lambda: center.store.attempts_for_request(paused_id),
            duration=1.5,
            what="an attempt offered to a paused node",
        )
        assert center.status_of(paused_id)["status"] == "ROUTING"
        assert upstream.call_count == 1

        # 4. Resume re-accepts without a restart.
        assert main(["share", "resume", "--config", str(node_json)]) == 0
        _wait_until_share_registered(center, enabled=True, what="the resume to register")
        _wait_until(
            lambda: bool(center.store.attempts_for_request(paused_id)),
            what="the resumed node to take the queued request",
        )
        _wait_until(
            lambda: center.status_of(paused_id)["status"] == "SUCCEEDED",
            what="the resumed request to finish",
        )
        assert upstream.call_count == 2
    finally:
        stop.set()
        connector.stop()
        thread.join(timeout=5)
        store.close()
        center.stop()


# --------------------------------------------------------------------------
# the polling mechanism itself: conservative on broken input
# --------------------------------------------------------------------------


def _connector_for(tmp_path: Path, node_json: Path) -> tuple[Connector, NodeStore]:
    """Build an unstarted connector whose policy file is `node_json`."""
    keyring = Keyring()
    config = ConnectorConfig(
        center_url="ws://127.0.0.1:1/v1/node-link",
        node_id="node-A",
        device_id="device-A",
        device_key_id="device-key-A",
        provider_id="provider-A",
        database_path=str(tmp_path / "node.db"),
        token=NODE_TOKEN,
        adapter_name="fake-adapter",
        model=MODEL,
        device_private_key_b64=keyring.private_b64["device-key-A"],
        # The unit tests call refresh_policy twice in quick succession, which a
        # real node never does (the pump loop paces the polls), so the throttle
        # is disabled here rather than waited out.
        policy_poll_interval_s=0.0,
        config_path=str(node_json),
    )
    store = NodeStore.open(tmp_path / "node.db")
    adapter = FakeUpstreamAdapter(upstream=FakeUpstream(), model=MODEL)
    return Connector(config, adapter=adapter, store=store), store


def test_refresh_policy_applies_a_valid_switch(tmp_path: Path) -> None:
    """A well-formed file changes the policy immediately, on the next poll."""
    node_json = tmp_path / "node.json"
    node_json.write_text(json.dumps({"share_enabled": True}), encoding="utf-8")
    connector, store = _connector_for(tmp_path, node_json)
    try:
        assert connector.refresh_policy(force=True) is False
        assert connector.policy.share_enabled is True

        node_json.write_text(
            json.dumps(
                {
                    "share_enabled": False,
                    "max_concurrency": 3,
                    "max_local_reserved_milli_credits": 900,
                }
            ),
            encoding="utf-8",
        )
        assert connector.refresh_policy() is True
        assert connector.policy.share_enabled is False
        assert connector.policy.max_concurrency == 3
        assert connector.policy.max_local_reserved_milli_credits == 900
    finally:
        store.close()


def test_refresh_policy_ignores_a_malformed_or_switchless_file(tmp_path: Path) -> None:
    """A broken file keeps the last good policy instead of flipping the node."""
    node_json = tmp_path / "node.json"
    node_json.write_text(json.dumps({"share_enabled": False}), encoding="utf-8")
    connector, store = _connector_for(tmp_path, node_json)
    try:
        assert connector.refresh_policy(force=True) is True
        assert connector.policy.share_enabled is False

        # A truncated (mid-write) document changes nothing.
        node_json.write_text('{"share_en', encoding="utf-8")
        assert connector.refresh_policy(force=True) is False
        assert connector.policy.share_enabled is False

        # A valid document without the switch changes nothing either.
        node_json.write_text(json.dumps({"other": 1}), encoding="utf-8")
        assert connector.refresh_policy(force=True) is False

        # And a missing file changes nothing.
        node_json.unlink()
        assert connector.refresh_policy(force=True) is False
        assert connector.policy.share_enabled is False
    finally:
        store.close()


# --------------------------------------------------------------------------
# P0-1: the invite path needs no token anybody copies by hand
# --------------------------------------------------------------------------


def _write_upstream_key_file(tmp_path: Path) -> Path:
    """Put the upstream key in a file, the only way the wizard takes a secret."""
    path = tmp_path / "upstream.key"
    path.write_text(UPSTREAM_KEY + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _join_node_by_invite(
    center: _Center,
    identity: Path,
    *,
    endpoint: str,
    monkeypatch: pytest.MonkeyPatch,
    key_file: Path,
    setup: bool = True,
) -> int:
    """Run `join --node` with every input except a platform token.

    Neither ``--node-token-file`` nor ``AIPOTLUCK_NODE_TOKEN`` is set, and stdin is
    not a terminal, so if the center does not hand the node its own credential
    this command has nowhere to get one — which is exactly the property under
    test. The pre-fix build stopped here and asked for a token no invite flow
    could produce.
    """
    monkeypatch.delenv(NODE_TOKEN_ENV_NAME, raising=False)
    monkeypatch.delenv(UPSTREAM_KEY_ENV_NAME, raising=False)
    argv = [
        "join",
        "--center",
        center.url,
        "--invite",
        "invite-node-wizard",
        "--node",
        "--config-dir",
        str(identity),
        "--upstream-endpoint",
        endpoint,
        "--upstream-model",
        MODEL,
        "--upstream-key-file",
        str(key_file),
        "--yes",
    ]
    if not setup:
        argv.append("--no-setup")
    return main(argv)


def _tracked_connectors(monkeypatch: pytest.MonkeyPatch) -> list[Connector]:
    """Make `share run` hand back the connector it built, so a test can stop it.

    `share run` blocks inside ``Connector.run_forever`` and installs no signal
    handlers off the main thread, so a test thread that started one would
    otherwise have no handle on it. Subclassing records the instance and changes
    nothing else: the real ``load_node`` still parses node.json, and the link is
    still dialled with the token from that file.
    """
    started: list[Connector] = []

    class _Tracked(Connector):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            started.append(self)

    monkeypatch.setattr("aipotluck.cli.Connector", _Tracked)
    return started


def _start_share_run(
    monkeypatch: pytest.MonkeyPatch, node_path: Path
) -> tuple[threading.Thread, list[Connector], list[int]]:
    """Run `share run` on a thread, returning it, its connectors, and its codes."""
    started = _tracked_connectors(monkeypatch)
    codes: list[int] = []
    thread = threading.Thread(
        target=lambda: codes.append(main(["share", "run", "--config", str(node_path)])),
        daemon=True,
    )
    thread.start()
    return thread, started, codes


def _stop_share_run(
    thread: threading.Thread, started: list[Connector]
) -> None:
    """Stop a `share run` started by `_start_share_run`."""
    for connector in started:
        connector.stop()
    thread.join(timeout=15)


def test_invited_node_needs_no_token_and_serves_a_routed_ask(
    center: _Center, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The P0-1 acceptance: invite → join → share run → a routed ask, zero tokens.

    Nothing here is provisioned by hand. The center's ``credentials[]`` is empty
    (the `_Center` fixture mints invites and nothing else), no token is passed to
    any command, no JSON is edited, and the consumer's ``ask`` omits ``--model``
    and ``--max-charge`` — so both sides run on their shipped defaults. What has
    to happen is that the center issues the node its own link credential during
    the join, the wizard writes it into node.json, the node's upgrade is
    accepted, and the first request is executed by it.
    """
    upstream = _RecordingUpstream()
    key_file = _write_upstream_key_file(tmp_path)
    node_dir = tmp_path / "node"
    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    thread: threading.Thread | None = None
    started: list[Connector] = []
    try:
        code = _join_node_by_invite(
            center,
            node_dir,
            endpoint=f"{upstream.url}/chat/completions",
            monkeypatch=monkeypatch,
            key_file=key_file,
        )
        assert code == 0, err.text()
        node_path = node_dir / "node.json"
        assert "[step 3] ready" in out.text(), out.text()

        # The center issued the token and the CLI saved it 0600, never printing
        # it. node.json's token is that same value: nothing was copied by hand.
        token_path = node_dir / "node_token.json"
        assert (token_path.stat().st_mode & 0o777) == 0o600
        saved = loads_strict(token_path.read_text(encoding="utf-8"))["node_token"]
        assert isinstance(saved, str) and saved
        node_document = loads_strict(node_path.read_text(encoding="utf-8"))
        assert node_document["token"] == saved
        assert saved not in out.text(), "the node token leaked to stdout"
        assert saved not in err.text(), "the node token leaked to stderr"

        thread, started, codes = _start_share_run(monkeypatch, node_path)
        _wait_until(
            lambda: bool(center.store.connected_nodes()),
            what="the invited node's hello to be acknowledged",
        )
        record = center.store.connected_nodes()[0]
        config_document = json.loads((node_dir / "config.json").read_text(encoding="utf-8"))
        assert record.node_id == node_document["node_id"]
        assert record.provider_id == config_document["provider_id"]
        assert record.model == MODEL

        # The consumer side, on defaults: no --model, no --max-charge.
        consumer_dir = tmp_path / "consumer"
        assert (
            main(
                [
                    "join",
                    "--center",
                    center.url,
                    "--invite",
                    "invite-consumer-wizard",
                    "--config-dir",
                    str(consumer_dir),
                ]
            )
            == 0
        )
        ask_code = main(["ask", PROMPT, "--config-dir", str(consumer_dir), "--timeout", "30"])
        assert ask_code == 0, err.text()
        assert "pong" in out.text(), out.text()
        assert upstream.request_count == 1
        assert codes == [], "share run should still be holding the link"
    finally:
        if thread is not None:
            _stop_share_run(thread, started)
        upstream.close()


def test_wizard_uses_the_token_join_saved(
    center: _Center, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`share setup` on its own reads the token back; it does not ask for one."""
    upstream = _RecordingUpstream()
    key_file = _write_upstream_key_file(tmp_path)
    identity = tmp_path / "node"
    out = _Recorder()
    err = _Recorder()
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr("sys.stderr", err)
    try:
        assert (
            _join_node_by_invite(
                center,
                identity,
                endpoint=f"{upstream.url}/chat/completions",
                monkeypatch=monkeypatch,
                key_file=key_file,
                setup=False,
            )
            == 0
        )
        saved = loads_strict(
            (identity / "node_token.json").read_text(encoding="utf-8")
        )["node_token"]
        # No --node-token-file, no AIPOTLUCK_NODE_TOKEN, no terminal to prompt on.
        code = main(
            [
                "share",
                "setup",
                "--config-dir",
                str(identity),
                "--upstream-endpoint",
                f"{upstream.url}/chat/completions",
                "--upstream-model",
                MODEL,
                "--upstream-key-file",
                str(key_file),
            ]
        )
        assert code == 0, err.text()
        document = loads_strict((identity / "node.json").read_text(encoding="utf-8"))
        assert document["token"] == saved
        assert saved not in out.text() and saved not in err.text()
    finally:
        upstream.close()


def test_wizard_token_file_overrides_the_saved_token(
    center: _Center, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator-pre-registration route still works, and still wins.

    ``--node-token-file``/``AIPOTLUCK_NODE_TOKEN`` exist for a center whose
    operator provisioned ``credentials[]`` by hand. An explicit instruction has
    to outrank the token ``join`` saved, or it would override nothing.
    """
    hold = _TcpHold()
    key_file = _write_upstream_key_file(tmp_path)
    identity = tmp_path / "node"
    try:
        assert (
            _join_node_by_invite(
                center,
                identity,
                endpoint=f"{hold.url}/v1/chat/completions",
                monkeypatch=monkeypatch,
                key_file=key_file,
                setup=False,
            )
            == 0
        )
        saved = loads_strict(
            (identity / "node_token.json").read_text(encoding="utf-8")
        )["node_token"]
        override_path = tmp_path / "operator-token"
        override_path.write_text(NODE_PLATFORM_TOKEN + "\n", encoding="utf-8")
        code = main(
            [
                "share",
                "setup",
                "--config-dir",
                str(identity),
                "--upstream-endpoint",
                f"{hold.url}/v1/chat/completions",
                "--upstream-model",
                MODEL,
                "--upstream-key-file",
                str(key_file),
                "--node-token-file",
                str(override_path),
            ]
        )
        assert code == 0
        document = loads_strict((identity / "node.json").read_text(encoding="utf-8"))
        assert document["token"] == NODE_PLATFORM_TOKEN
        assert document["token"] != saved
        # The override is a file the wizard read; the saved token is untouched.
        assert (
            loads_strict((identity / "node_token.json").read_text(encoding="utf-8"))[
                "node_token"
            ]
            == saved
        )
    finally:
        hold.close()


def test_wizard_with_no_token_anywhere_names_both_ways_out(
    center: _Center, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lost token is a dead end only if the error does not name the exit.

    The center keeps a digest, so it cannot show the token again; the recovery
    path is a revoke plus a fresh invite. That has to be in the message, because
    the alternative is a contributor staring at a prompt they cannot fill in.
    """
    hold = _TcpHold()
    key_file = _write_upstream_key_file(tmp_path)
    identity = tmp_path / "node"
    err = _Recorder()
    monkeypatch.setattr("sys.stderr", err)
    try:
        assert (
            _join_node_by_invite(
                center,
                identity,
                endpoint=f"{hold.url}/v1/chat/completions",
                monkeypatch=monkeypatch,
                key_file=key_file,
                setup=False,
            )
            == 0
        )
        (identity / "node_token.json").unlink()
        code = main(
            [
                "share",
                "setup",
                "--config-dir",
                str(identity),
                "--upstream-endpoint",
                f"{hold.url}/v1/chat/completions",
                "--upstream-model",
                MODEL,
                "--upstream-key-file",
                str(key_file),
            ]
        )
        assert code == 1
        assert "not an interactive terminal" in err.text()
        assert "join --node" in err.text()
        assert NODE_TOKEN_ENV_NAME in err.text()
        assert "revoke-key" in err.text()
        # Nothing was written: a node.json with no token would be a broken node.
        assert not (identity / "node.json").exists()
    finally:
        hold.close()


def test_rejoin_keeps_the_saved_token_usable(
    center: _Center, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-joining is idempotent all the way down to the credential.

    A second `join --node` must not mint a second token (the center could not
    reproduce the first anyway), must not spend another invite use, must not drop
    the device binding it derived the first time, and must leave the token the
    node already holds working — proved here by that node actually connecting
    with it afterwards.
    """
    upstream = _RecordingUpstream()
    key_file = _write_upstream_key_file(tmp_path)
    identity = tmp_path / "node"
    endpoint = f"{upstream.url}/chat/completions"
    thread: threading.Thread | None = None
    started: list[Connector] = []
    try:
        kwargs = {
            "endpoint": endpoint,
            "monkeypatch": monkeypatch,
            "key_file": key_file,
            "setup": False,
        }
        assert _join_node_by_invite(center, identity, **kwargs) == 0
        token_bytes = (identity / "node_token.json").read_bytes()
        config_bytes = (identity / "config.json").read_bytes()
        saved = loads_strict(token_bytes.decode("utf-8"))["node_token"]

        assert _join_node_by_invite(center, identity, **kwargs) == 0

        # No new token, no new invite use, no lost device binding.
        assert (identity / "node_token.json").read_bytes() == token_bytes
        assert json.loads((identity / "config.json").read_text(encoding="utf-8")) == (
            json.loads(config_bytes.decode("utf-8"))
        )
        assert center.store.get_invite("invite-node-wizard").used_count == 1
        assert (
            center.store.resolve_credential(str(saved), dt.datetime.now(dt.UTC))
            is not None
        ), "the token saved by the first join stopped resolving after a re-join"

        # And it still authenticates a real node link.
        assert (
            main(
                [
                    "share",
                    "setup",
                    "--config-dir",
                    str(identity),
                    "--upstream-endpoint",
                    endpoint,
                    "--upstream-model",
                    MODEL,
                    "--upstream-key-file",
                    str(key_file),
                ]
            )
            == 0
        )
        thread, started, _codes = _start_share_run(monkeypatch, identity / "node.json")
        _wait_until(
            lambda: bool(center.store.connected_nodes()),
            what="the re-joined node to connect with its original token",
        )
    finally:
        if thread is not None:
            _stop_share_run(thread, started)
        upstream.close()


# --------------------------------------------------------------------------
# P0-2: the shipped defaults agree, so the first request is not refused
# --------------------------------------------------------------------------


def test_the_three_exposure_defaults_are_one_number() -> None:
    """ask's ceiling, the wizard's node ceiling and the connector's must match.

    They were 20_000 / 5_000 / 20_000, which made the first request of an
    all-default deployment fail inside the node's own local policy — a
    wizard-configured node was more restrictive than a programmatic one, and a
    default consumer charge could never fit it. The three are asserted together
    so the next change to any of them has to be a change to all of them.
    """
    assert ASK_DEFAULT_MAX_CHARGE == 20_000
    assert NODE_DEFAULT_MAX_LOCAL_RESERVED_MILLI_CREDITS == ASK_DEFAULT_MAX_CHARGE
    assert ConnectorConfig.max_local_reserved_milli_credits == ASK_DEFAULT_MAX_CHARGE
    # A default ask must fit a default node's whole exposure on an idle node.
    assert 0 + ASK_DEFAULT_MAX_CHARGE <= NODE_DEFAULT_MAX_LOCAL_RESERVED_MILLI_CREDITS
