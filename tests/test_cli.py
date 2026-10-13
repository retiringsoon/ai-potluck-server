"""The consumer network commands of ``potluck`` against a real server.

These tests drive the client CLI's ``main()`` the way the installed ``potluck``
script uses it, over a real ``GatewayServer`` on loopback with a scripted
contribution node driven by a real ``Connector`` thread — the same pattern
``test_end_to_end_network.py`` uses. The pre-network ``request`` refusal
(no ``--auth-file``) needs no server and is covered in the ``ai-potluck``
repository's own ``test_cli.py``. They live here because the server they
drive against ships in this package. The offline tools (``keygen``/``sign``/
``verify``) and the pre-network refusals are covered in the ``ai-potluck``
repository's own ``test_cli.py``.

What is deliberately out of scope: running ``serve`` and ``connect`` as real
signal-handling processes, which needs process supervision and, for the
cross-machine guarantees of network contract v0.1 §8, two machines.
"""

from __future__ import annotations

import datetime as dt
import json
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from aipotluck.adapters import FakeResponse, FakeUpstream, FakeUpstreamAdapter
from aipotluck.canonical import canonicalize, loads_strict
from aipotluck.cli import main
from aipotluck.connector import Connector, ConnectorConfig
from aipotluck.metering import NormalizedUsage
from aipotluck.persistence import NodeStore
from aipotluck.wire import user_message
from conftest import Keyring, signed_authorization

from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import ServerStore

MODEL = "coding-pool"
TENANT = "tenant-cli"
CONSUMER_TOKEN = "consumer-token-cli"
NODE_TOKEN = "node-token-cli"
REQUEST_ID = "R-cli-1"
BASE = dt.datetime(2026, 10, 6, 12, 0, tzinfo=dt.UTC)
REGISTERED_AT = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)


# --------------------------------------------------------------------------
# Consumer network commands against a real server on loopback.
# --------------------------------------------------------------------------


def _wait_until(condition: Any, *, timeout: float = 10.0, what: str = "condition") -> None:
    """Block until `condition()` is truthy, failing with a readable message."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


class _CliServer:
    """A real gateway over a real store, with credentials and floats ready."""

    def __init__(self, tmp_path: Path, keyring: Keyring) -> None:
        self.tmp_path = tmp_path
        self.keyring = keyring
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
        self.store.add_credential(
            CONSUMER_TOKEN, TENANT, "consumer-X", "consumer", REGISTERED_AT
        )
        self.store.add_credential(NODE_TOKEN, TENANT, "node-A", "node", REGISTERED_AT)
        self.service.fund_account(
            account_id="consumer-X", kind="consumer_available", amount=100_000, now=BASE
        )
        self.consumer_config = self._write_consumer_config()

    def _write_consumer_config(self) -> Path:
        path = self.tmp_path / "consumer.json"
        path.write_text(
            json.dumps({"server_url": self.server.url, "token": CONSUMER_TOKEN}),
            encoding="utf-8",
        )
        return path

    @property
    def port(self) -> int:
        """The real bound port."""
        return int(self.server.url.rsplit(":", 1)[1])

    def stop(self) -> None:
        """Shut the listener down."""
        self.server.stop()
        self.store.close()


class _CliNode:
    """A scripted contribution node holding the outbound link like a real one."""

    def __init__(self, tmp_path: Path, keyring: Keyring, server_port: int) -> None:
        self.upstream = FakeUpstream()
        self.upstream.queue(
            FakeResponse(
                text_chunks=("Hello ", "from the scripted node"),
                usage=NormalizedUsage(input_total=800, output_total=200),
            )
        )
        self.adapter = FakeUpstreamAdapter(upstream=self.upstream, model=MODEL)
        self.store = NodeStore.open(tmp_path / "node.db")
        self.config = ConnectorConfig(
            server_url=f"ws://127.0.0.1:{server_port}/v1/node-link",
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


def _authorization_body(
    keyring: Keyring,
    request_id: str,
    *,
    messages: tuple[Any, ...] = (user_message("write a haiku about sockets"),),
) -> dict[str, Any]:
    """Build the serialized signed authorization a real client would POST.

    The window is anchored to the wall clock: this suite exercises the real
    server, so a just-signed authorization must be valid when it settles. The
    ``request_digest`` is computed for `messages`, which must match the
    ``--prompt`` the ``request`` command posts as its one user turn, because
    admission re-derives and compares it.
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


def _request_argv(consumer_config: Path, auth_file: Path | None, **overrides: Any) -> list[str]:
    """Build a ``request`` invocation with the shared fixtures' values."""
    argv = [
        "request",
        "--config",
        str(consumer_config),
        "--prompt",
        "write a haiku about sockets",
        "--model",
        MODEL,
        "--request-id",
        REQUEST_ID,
        "--idempotency-key",
        "idem-cli-1",
        "--max-charge",
        "20000",
    ]
    if auth_file is not None:
        argv += ["--auth-file", str(auth_file)]
    argv += overrides.pop("extra", [])
    return argv


def test_request_without_wait_prints_the_request_id(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], keyring: Keyring
) -> None:
    """A plain submission returns 0 and the id the server assigned."""
    server = _CliServer(tmp_path, keyring)
    try:
        auth_path = tmp_path / "auth.json"
        auth_path.write_text(
            json.dumps(_authorization_body(keyring, REQUEST_ID)), encoding="utf-8"
        )
        code = main(_request_argv(server.consumer_config, auth_path))
        captured = capsys.readouterr()
        assert code == 0
        assert captured.out.strip() == REQUEST_ID
        # The server actually stored the request under that id.
        assert server.store.get_request(REQUEST_ID) is not None
    finally:
        server.stop()


def test_request_wait_reaches_succeeded_and_status_and_events_are_readable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], keyring: Keyring
) -> None:
    """`request --wait` drives one upstream call and prints the receipt."""
    server = _CliServer(tmp_path, keyring)
    node = _CliNode(tmp_path, keyring, server.port)
    try:
        _wait_until(
            lambda: bool(server.store.connected_nodes()), what="the node to register"
        )
        auth_path = tmp_path / "auth.json"
        auth_path.write_text(
            json.dumps(_authorization_body(keyring, REQUEST_ID)), encoding="utf-8"
        )
        code = main(_request_argv(server.consumer_config, auth_path, extra=["--wait"]))
        captured = capsys.readouterr()
        assert code == 0, captured.err
        assert captured.out.splitlines()[0] == REQUEST_ID
        assert "SUCCEEDED" in captured.out
        # The receipt summary line is printed with concrete values.
        settlement = server.store.get_settlement(REQUEST_ID, 1)
        assert settlement is not None
        assert settlement.receipt_id in captured.out
        assert str(settlement.log_index) in captured.out
        # The settlement actually moved credit: 1000 tokens at face value.
        assert node.adapter.upstream_calls == 1
        assert server.service.balance("consumer-X") == 99_000
        assert server.service.balance("provider-A/pending") == 1_000

        # `status` prints exactly one canonical JSON document.
        code = main(
            ["status", "--config", str(server.consumer_config), "--request-id", REQUEST_ID]
        )
        status_out = capsys.readouterr().out
        assert code == 0
        document = loads_strict(status_out)
        assert document["request_id"] == REQUEST_ID
        assert document["status"] == "SUCCEEDED"
        assert document["settlement"]["receipt_id"] == settlement.receipt_id
        assert status_out.strip() == canonicalize(document).decode("utf-8")

        # `events` replays the stored events and stops after the terminal one.
        code = main(
            [
                "events",
                "--config",
                str(server.consumer_config),
                "--request-id",
                REQUEST_ID,
                "--cursor",
                "0",
            ]
        )
        events_out = capsys.readouterr().out
        assert code == 0
        frames = [loads_strict(line) for line in events_out.splitlines() if line.strip()]
        event_types = [frame["event_type"] for frame in frames if "event_type" in frame]
        assert event_types == ["output.delta", "usage.final", "attempt.completed"]
        usage_frame = next(frame for frame in frames if frame.get("event_type") == "usage.final")
        assert usage_frame["usage"]["input_total"] == 800
        assert usage_frame["usage"]["output_total"] == 200
        # The terminal done frame closes the stream.
        assert frames[-1] == {"request_id": REQUEST_ID, "status": "SUCCEEDED"}
    finally:
        node.stop()
        server.stop()
