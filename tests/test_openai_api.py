"""The OpenAI-compatible surface, over real loopback TCP against a real server.

Nothing here stubs the transport or the domain: the server is a real
`GatewayServer` over a real `ServerStore` and a real `GatewayService`, the
contribution node is a real `Connector` dialing it over a WebSocket, and the
consumer is a real HTTP client — for the SDK tests, the real `openai` package
pointed at this server's URL.

What that buys, and what these tests are for:

*An API key is a credential, not a signature.* The endpoint admits a request on
a key the server issued, and the spend still lands in the subject's own account
through the same settlement that a signed request uses. Both facts are asserted
here, because the second is the one that could silently break: a new admission
path that billed a different account, or none, would still return an answer.

*The conversation arrives intact.* The node is a proxy for one upstream call, so
the assertion that matters is on what the upstream received — every turn, in
order, with the parameters the caller named — not on the answer that came back.

*Refusals are honest and distinguishable.* An unknown key, a revoked key, an
expired key, a spent quota, a rate-limited key, a model nothing can run, and a
request that outlived the wait window each get their own status and code, in the
shape an OpenAI client already knows how to read.
"""

from __future__ import annotations

import datetime as dt
import http.client
import json
import logging
import socket
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from aipotluck.adapters import FakeResponse, FakeUpstream, FakeUpstreamAdapter
from aipotluck.connector import Connector, ConnectorConfig
from aipotluck.identity import generate_key_pair
from aipotluck.metering import NormalizedUsage
from aipotluck.persistence import NodeStore
from aipotluck.wire import SESSION_HEADER, user_message
from conftest import Keyring, signed_authorization

from aipotluck_server import gateway_server, gateway_service
from aipotluck_server.cli import main as server_main
from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import (
    API_KEY_PREFIX,
    JOIN_API_KEY_NAME,
    GatewayConfig,
    GatewayService,
)
from aipotluck_server.persistence import ServerStore

MODEL = "coding-pool"
TENANT = "tenant-openai"
SUBJECT = "consumer-X"
CONSUMER_TOKEN = "consumer-token-openai"
NODE_TOKEN = "node-token-openai"
BASE = dt.datetime(2026, 10, 6, 12, 0, tzinfo=dt.UTC)
REGISTERED_AT = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)

#: The answer the scripted upstream gives, and what it bills for it.
ANSWER = "Hello from the node"
BILLED_TOKENS = 1_000


def _wait_until(condition: Any, *, timeout: float = 20.0, what: str = "condition") -> None:
    """Block until `condition()` is truthy, failing with a readable message."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


def _scripted_response(text: tuple[str, ...] = ("Hello ", "from the node")) -> FakeResponse:
    """One scripted upstream answer billing 800 input and 200 output tokens."""
    return FakeResponse(
        text_chunks=text, usage=NormalizedUsage(input_total=800, output_total=200)
    )


class Server:
    """A real server: gateway, service, store, one provisioned consumer."""

    def __init__(self, tmp_path: Path, keyring: Keyring, **config: Any) -> None:
        self.keyring = keyring
        self.tmp_path = tmp_path
        self.database_path = tmp_path / "server.db"
        self.store = ServerStore.open(self.database_path)
        # `config` is the dispatch-queue policy a test wants to probe. The
        # defaults are the shipped ones, so a test that names none is driving what
        # an operator who wrote no queue field gets.
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(self.database_path),
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
        # One operator-provisioned consumer, whose account is funded below: the
        # subject an API key speaks for has to exist before a key can be minted.
        self.store.add_credential(
            CONSUMER_TOKEN, TENANT, SUBJECT, "consumer", REGISTERED_AT
        )
        self.store.add_credential(NODE_TOKEN, TENANT, "node-A", "node", REGISTERED_AT)
        self.service.fund_account(
            account_id=SUBJECT, kind="consumer_available", amount=100_000, now=BASE
        )
        self.config_path = self._write_server_config()

    def _write_server_config(self) -> Path:
        """Write the ``server.json`` the operator commands open the store with."""
        path = self.tmp_path / "server.json"
        path.write_text(
            json.dumps({"database_path": str(self.database_path)}), encoding="utf-8"
        )
        return path

    @property
    def port(self) -> int:
        """The real bound port."""
        return int(self.server.url.rsplit(":", 1)[1])

    def stop(self) -> None:
        """Shut the listener down and close the store."""
        self.server.stop()
        self.store.close()

    def join_consumer(
        self,
        invite_code: str = "code-openai",
        *,
        quota_milli_credits: int = 50_000,
        issues_api_key: bool = False,
    ) -> Any:
        """Join one consumer with an invite, and return the minted identity."""
        self.store.add_invite(
            invite_code,
            "consumer",
            "auto",
            max_uses=1,
            created_at=BASE,
            quota_milli_credits=quota_milli_credits,
            issues_api_key=issues_api_key,
        )
        public_b64, _private_b64 = generate_key_pair()
        return self.service.join(
            invite_code=invite_code,
            identity={"public_key_b64": public_b64},
            device=None,
            server_url=self.server.url,
            now=dt.datetime.now(dt.UTC),
        )


class Node:
    """A real connector dialing the server over loopback, over a fake upstream."""

    def __init__(
        self,
        server: Server,
        *,
        adapter: Any = None,
        max_concurrency: int = 1,
        max_local_reserved_milli_credits: int = 200_000,
    ) -> None:
        self.upstream = FakeUpstream()
        self.adapter = adapter if adapter is not None else FakeUpstreamAdapter(
            upstream=self.upstream, model=MODEL
        )
        self.store: Any = NodeStore.open(server.tmp_path / "node.db")
        self.config = ConnectorConfig(
            server_url=f"ws://127.0.0.1:{server.port}/v1/node-link",
            node_id="node-A",
            device_id="device-A",
            device_key_id="device-key-A",
            provider_id="provider-A",
            database_path=str(server.tmp_path / "node.db"),
            token=NODE_TOKEN,
            adapter_name="fake-adapter",
            model=MODEL,
            device_private_key_b64=server.keyring.private_b64["device-key-A"],
            heartbeat_interval_s=3600,
            max_concurrency=max_concurrency,
            max_concurrent_executions=max_concurrency,
            max_local_reserved_milli_credits=max_local_reserved_milli_credits,
        )
        self.connector = Connector(self.config, adapter=self.adapter, store=self.store)
        self.thread = threading.Thread(target=self.connector.run_once, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        """Stop the connector and join its session thread."""
        self.connector.stop()
        self.thread.join(timeout=10)


class _GatedAdapter(FakeUpstreamAdapter):
    """An adapter whose buffered call blocks until the test releases it.

    Used to hold requests in flight, which is the only way to reach a
    concurrency ceiling without a node that has stopped answering.
    """

    def __init__(self, *, upstream: FakeUpstream, model: str) -> None:
        """Wrap `upstream`, holding every buffered call on a test-owned gate."""
        super().__init__(upstream=upstream, model=model)
        self.entered = threading.Event()
        self.gate = threading.Event()

    def complete(self, messages: Any, *, request_digest: str, parameters: Any) -> Any:
        """Announce entry, wait for the gate, then return the scripted response."""
        self.entered.set()
        assert self.gate.wait(timeout=60), "the test never released the gated call"
        return super().complete(
            messages, request_digest=request_digest, parameters=parameters
        )


@pytest.fixture
def server(tmp_path: Path) -> Any:
    """A running server, stopped at the end of the test."""
    built = Server(tmp_path, Keyring())
    yield built
    built.stop()


@pytest.fixture(autouse=True)
def no_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep a machine's proxy configuration out of the loopback tests.

    The SDK's HTTP client honours the standard proxy variables, so on a machine
    that exports one, a request to ``127.0.0.1`` would be routed through it and
    the test would measure the proxy rather than this server.
    """
    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(name, raising=False)


def _mint_key(
    server: Server,
    capsys: pytest.CaptureFixture[str],
    *,
    subject: str = SUBJECT,
    quota: int = 100_000,
    name: str = "",
    expires_in: str | None = None,
    deadline_ms: int | None = None,
) -> str:
    """Mint an API key through the operator CLI and return its plaintext.

    The CLI is the only supported way to mint one, and it prints the plaintext
    exactly once — so reading it back from stdout is what an operator does, and
    what this helper asserts works.
    """
    argv = [
        "admin",
        "api-key",
        "--config",
        str(server.config_path),
        "--subject",
        subject,
        "--quota",
        str(quota),
    ]
    if name:
        argv += ["--name", name]
    if expires_in is not None:
        argv += ["--expires-in", expires_in]
    if deadline_ms is not None:
        argv += ["--deadline-ms", str(deadline_ms)]
    assert server_main(argv) == 0, capsys.readouterr().err
    return capsys.readouterr().out.strip().splitlines()[0]


def _post_chat(
    server: Server,
    body: Any,
    *,
    key: str | None,
    path: str = "/openai/v1/chat/completions",
    timeout: float = 130.0,
) -> tuple[int, Any, str]:
    """POST one request and return ``(status, headers, raw body text)``."""
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=timeout)
    headers = {"content-type": "application/json"}
    if key is not None:
        headers["authorization"] = f"Bearer {key}"
    raw = body if isinstance(body, str) else json.dumps(body)
    connection.request("POST", path, body=raw.encode("utf-8"), headers=headers)
    response = connection.getresponse()
    text = response.read().decode("utf-8")
    connection.close()
    return response.status, response.getheaders(), text


def _get(
    server: Server, path: str, *, key: str | None
) -> tuple[int, Any, str]:
    """GET one path and return ``(status, headers, raw body text)``."""
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=30)
    headers = {"authorization": f"Bearer {key}"} if key is not None else {}
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    text = response.read().decode("utf-8")
    connection.close()
    return response.status, response.getheaders(), text


def _chat_body(content: Any = "write a haiku about sockets", **extra: Any) -> dict[str, Any]:
    """One OpenAI-shaped chat-completions body with a single user turn."""
    body: dict[str, Any] = {
        "model": MODEL,
        "messages": [{"role": "user", "content": content}],
    }
    body.update(extra)
    return body


def _header(headers: Any, name: str) -> str:
    """Return one response header, case-insensitively as HTTP requires."""
    return dict((key.lower(), value) for key, value in headers)[name]


def _sse_frames(raw: str) -> list[Any]:
    """Parse an SSE body into its `data:` payloads, with `[DONE]` kept as-is."""
    frames: list[Any] = []
    for block in raw.split("\n\n"):
        for line in block.splitlines():
            if not line.startswith("data: "):
                continue
            payload = line[len("data: ") :]
            frames.append("[DONE]" if payload == "[DONE]" else json.loads(payload))
    return frames


def _content_of(frames: list[Any]) -> str:
    """Return the text a stream carried, in order, ignoring non-chunk frames."""
    return "".join(
        str(choice["delta"].get("content", ""))
        for frame in frames
        if isinstance(frame, dict)
        for choice in frame.get("choices", [])
        if isinstance(choice.get("delta"), dict)
    )


def _run(server: Server, key: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST one chat completion and assert it was answered with a document."""
    status, _headers, raw = _post_chat(server, body, key=key)
    document = json.loads(raw)
    assert status == 200, (status, document)
    return document


# --------------------------------------------------------------------------- #
# Minting
# --------------------------------------------------------------------------- #


def test_a_minted_key_is_printed_once_and_stored_as_a_digest(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI prints the plaintext once; the store keeps only a digest."""
    key = _mint_key(server, capsys, name="the IDE", quota=25_000)

    assert key.startswith("ak-")
    assert len(key) == len("ak-") + 43
    stored = server.store.list_api_keys()
    assert len(stored) == 1
    record = stored[0]
    assert record.name == "the IDE"
    assert record.subject_id == SUBJECT
    assert record.tenant_id == TENANT
    assert record.quota_milli_credits == 25_000
    assert record.used_milli_credits == 0
    assert record.status == "active"
    assert record.key_hash != key
    assert key not in record.key_hash
    # The listing is redacted by construction: only the digest was ever stored.
    assert server_main(["admin", "api-key-list", "--config", str(server.config_path)]) == 0
    listing = capsys.readouterr().out
    assert record.key_id in listing
    assert "the IDE" in listing
    assert key not in listing


def test_a_key_deadline_that_would_admit_nothing_is_refused_at_the_command(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """A window of zero expires every request before it can run.

    Refused where the only thing wasted is a command, exactly as ``--quota 0`` is:
    minting the key would succeed and every request on it would end EXPIRED, which
    reads as a broken server rather than as a bad flag.
    """
    for value in ("0", "-1"):
        assert (
            server_main(
                [
                    "admin",
                    "api-key",
                    "--config",
                    str(server.config_path),
                    "--subject",
                    SUBJECT,
                    "--quota",
                    "1000",
                    "--deadline-ms",
                    value,
                ]
            )
            == 1
        )
        assert "--deadline-ms must be >= 1" in capsys.readouterr().err
    assert server.store.list_api_keys() == []


def test_the_key_listing_shows_the_window_a_key_carries(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """An operator reading a listing can tell a long-task key from a default one.

    Both spellings are asserted because the honest answer for a key with no window
    of its own is "default", not a number this command would have to invent.
    """
    _mint_key(server, capsys, name="agent", deadline_ms=600_000)
    _mint_key(server, capsys, name="plain")

    assert server_main(["admin", "api-key-list", "--config", str(server.config_path)]) == 0
    listing = capsys.readouterr().out
    agent = next(line for line in listing.splitlines() if 'name="agent"' in line)
    plain = next(line for line in listing.splitlines() if 'name="plain"' in line)
    assert "deadline=600000ms" in agent
    assert "deadline=default" in plain


def test_session_list_can_be_narrowed_to_one_subject(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--subject` narrows the listing, and an empty one says why rather than printing nothing."""
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)
        status, _headers, raw = _post_chat_with_session(
            server, _chat_body(), key=key, session="sess-narrow"
        )
        assert status == 200, raw

        assert (
            server_main(
                [
                    "admin",
                    "session-list",
                    "--config",
                    str(server.config_path),
                    "--subject",
                    SUBJECT,
                ]
            )
            == 0
        )
        assert "sess-narrow" in capsys.readouterr().out

        # Another subject has no sessions, and the command says so on stderr with
        # the way a session comes to exist — silence would read as a broken
        # command rather than as an empty answer.
        assert (
            server_main(
                [
                    "admin",
                    "session-list",
                    "--config",
                    str(server.config_path),
                    "--subject",
                    "consumer-nobody",
                ]
            )
            == 0
        )
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "no agent session for subject consumer-nobody" in captured.err
    finally:
        node.stop()


def test_session_show_names_a_session_the_server_does_not_hold(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unknown session is an error, not an empty report that looks like a zero."""
    assert (
        server_main(
            [
                "admin",
                "session-show",
                "--config",
                str(server.config_path),
                "--session",
                "sess-never",
            ]
        )
        == 1
    )
    assert "no agent session 'sess-never'" in capsys.readouterr().err


def test_a_key_can_only_be_minted_for_a_consumer_the_server_knows(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """A subject that does not exist is refused, not minted a useless key."""
    argv = [
        "admin",
        "api-key",
        "--config",
        str(server.config_path),
        "--subject",
        "consumer-nobody",
        "--quota",
        "1000",
    ]
    assert server_main(argv) == 1
    error = capsys.readouterr().err
    assert "no consumer 'consumer-nobody'" in error
    assert server.store.list_api_keys() == []


def test_a_key_minted_for_a_joined_identity_spends_that_identitys_account(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """The invited-consumer path: the key speaks for the identity join minted."""
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        joined = server.join_consumer()
        key = _mint_key(server, capsys, subject=joined.subject_id, quota=10_000)

        document = _run(server, key, _chat_body())

        assert document["choices"][0]["message"]["content"] == ANSWER
        record = server.store.list_api_keys()[0]
        assert record.subject_id == joined.subject_id
        assert record.tenant_id == joined.tenant_id
        assert record.used_milli_credits == BILLED_TOKENS
        # The join funded this identity's own account, and that is what paid.
        assert server.service.balance(joined.subject_id) == 50_000 - BILLED_TOKENS
    finally:
        node.stop()


def test_an_invite_that_issues_a_key_carries_a_joiner_to_a_verified_receipt(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """The point of `--with-api-key`: one invite, and a tool can call the pool.

    Nothing happens between the join and the first request — no operator minting
    a key for a subject they read out of a listing — so the assertion that
    matters is that the key the join response carried is the key that
    authenticates here. And that it is a second *door*, not a second set of
    books: the request runs the same dispatch, settles through the same ledger,
    charges the account the join funded, counts against the quota the key
    inherited from that invite, and leaves a receipt the operator side verifies.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        joined = server.join_consumer(
            "code-keyed", quota_milli_credits=30_000, issues_api_key=True
        )
        assert joined.api_key is not None
        assert joined.api_key.startswith(API_KEY_PREFIX)

        status, headers, raw = _post_chat(server, _chat_body(), key=joined.api_key)
        document = json.loads(raw)

        assert status == 200, document
        assert document["choices"][0]["message"]["content"] == ANSWER
        assert document["usage"]["total_tokens"] == BILLED_TOKENS
        request_id = _header(headers, "x-request-id")

        record = server.store.list_api_keys()[0]
        assert record.subject_id == joined.subject_id
        assert record.name == JOIN_API_KEY_NAME
        assert record.quota_milli_credits == 30_000
        assert record.used_milli_credits == BILLED_TOKENS
        assert record.remaining_milli_credits == 30_000 - BILLED_TOKENS
        # The account the join funded is what paid, not the key.
        assert server.service.balance(joined.subject_id) == 30_000 - BILLED_TOKENS

        receipts = server.store.receipts()
        assert [receipt.request_id for receipt in receipts] == [request_id]
        verified = server_main([
            "verify", "receipt", "--config", str(_operator_config(server)),
            "--receipt-id", receipts[0].receipt_id,
        ])
        captured = capsys.readouterr()
        assert verified == 0, captured.out + captured.err
        # A key-admitted request is authorized by the server's own settlement
        # key, and the stored record says so: a key an invite issued is not a
        # stronger credential for having arrived beside an identity.
        stored = server.store.get_request_input(request_id)
        assert stored is not None
        assert stored["authorization"]["payload"]["auth_method"] == "gateway_authenticated"
        assert stored["authorization"]["signer_key_id"] == "settlement-key-1"
    finally:
        node.stop()


def test_a_key_an_invite_issued_is_revoked_without_touching_the_identity(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """Revoking the key withdraws one credential; the identity keeps working.

    This is the independence the flag is safe *because* of. A key handed to a
    tool has to be withdrawable on its own — otherwise the choice is between
    leaving a leaked key live and revoking the identity behind it, which would
    also kill every signed request that member makes. So: the revoked key is
    refused on a running server, the identity is still unrevoked in the store,
    and a replacement key minted for the same subject by hand is admitted and
    spends the balance the first request left behind.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        # One answer: the revoked key is refused at the door, so it never reaches
        # a node and never spends anything.
        node.upstream.queue(_scripted_response())
        joined = server.join_consumer("code-keyed", issues_api_key=True)
        assert joined.api_key is not None
        key_id = server.store.list_api_keys()[0].key_id

        assert server_main([
            "admin", "api-key-revoke", "--config", str(server.config_path),
            "--key-id", key_id,
        ]) == 0
        capsys.readouterr()

        status, _headers, raw = _post_chat(server, _chat_body(), key=joined.api_key)
        assert status == 401
        assert json.loads(raw)["error"]["code"] == "invalid_api_key"
        assert joined.api_key not in raw
        # The identity is untouched: what was revoked is a key, not a member.
        identity = server.store.get_identity(joined.key_id)
        assert identity is not None and identity.revoked_at is None

        replacement = _mint_key(server, capsys, subject=joined.subject_id, quota=20_000)
        status, _headers, raw = _post_chat(server, _chat_body(), key=replacement)
        assert status == 200, raw
        assert json.loads(raw)["choices"][0]["message"]["content"] == ANSWER
        # One request ran, so one was billed: the refused one cost nothing.
        assert server.service.balance(joined.subject_id) == 50_000 - BILLED_TOKENS
    finally:
        node.stop()


# --------------------------------------------------------------------------- #
# The happy paths
# --------------------------------------------------------------------------- #


def test_a_chat_completion_answers_with_content_usage_and_the_request_id(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """One key, one request, one `chat.completion`, billed through settlement."""
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)

        status, headers, raw = _post_chat(server, _chat_body(), key=key)
        document = json.loads(raw)

        assert status == 200
        assert document["object"] == "chat.completion"
        assert document["id"].startswith("chatcmpl-")
        assert document["model"] == MODEL
        assert isinstance(document["created"], int)
        assert document["choices"][0]["message"] == {
            "role": "assistant",
            "content": ANSWER,
            "refusal": None,
        }
        assert document["choices"][0]["finish_reason"] == "stop"
        # The counts come from the settlement, not from a guess: the total is the
        # billed amount, the halves are the node's own final measurement.
        assert document["usage"] == {
            "prompt_tokens": 800,
            "completion_tokens": 200,
            "total_tokens": BILLED_TOKENS,
        }
        request_id = _header(headers, "x-request-id")
        assert request_id.startswith("req-")
        # The spend went through the subject's own account, and the key's quota
        # counted it, in the same settlement that moved the credit.
        assert server.service.balance(SUBJECT) == 100_000 - BILLED_TOKENS
        assert server.service.balance("provider-A/pending") == BILLED_TOKENS
        stored = server.store.list_api_keys()[0]
        assert stored.used_milli_credits == BILLED_TOKENS
        assert stored.last_used_at is not None
        assert server.store.get_request(request_id) is not None
    finally:
        node.stop()


def test_a_multi_turn_conversation_reaches_the_upstream_verbatim(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """The upstream sees every turn, and the parameters the caller named.

    This is the assertion the whole surface exists for: a server that flattened
    the conversation into one prompt string would still return an answer, so the
    evidence has to be what the upstream received.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)
        messages = [
            {"role": "system", "content": "answer in one word"},
            {"role": "user", "content": "what settles a request?"},
            {"role": "assistant", "content": "a receipt"},
            {"role": "user", "content": "and what backs the receipt?"},
        ]

        document = _run(
            server,
            key,
            _chat_body(
                messages=messages,
                temperature=0.7,
                top_p=1,
                max_tokens=64,
                stop=["END"],
                user="consumer-X",
                # A field the platform has not decided to honour is dropped
                # rather than forwarded.
                logprobs=True,
            ),
        )

        assert document["choices"][0]["message"]["content"] == ANSWER
        call = node.upstream.calls[-1]
        assert [message.to_payload() for message in call.messages] == messages
        # The fraction survived the canonical wire encoding as a decimal string
        # and was restored to a number where the upstream body is built.
        assert call.parameters == {
            "max_tokens": 64,
            "stop": ["END"],
            "temperature": "0.7",
            "top_p": 1,
            "user": "consumer-X",
        }
    finally:
        node.stop()


def test_a_stream_renders_role_deltas_finish_and_done(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """`stream: true` answers as SSE chunks in OpenAI's own order."""
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)

        status, headers, raw = _post_chat(
            server, _chat_body(stream=True), key=key
        )
        frames = _sse_frames(raw)

        assert status == 200
        assert _header(headers, "content-type") == "text/event-stream"
        assert frames[-1] == "[DONE]"
        chunks = frames[:-1]
        assert all(chunk["object"] == "chat.completion.chunk" for chunk in chunks)
        assert len({chunk["id"] for chunk in chunks}) == 1, "one answer, one id"
        # The role frame comes first, then the content, then the finish reason.
        assert chunks[0]["choices"][0]["delta"]["role"] == "assistant"
        assert _content_of(chunks) == ANSWER
        assert chunks[-1]["choices"][0]["finish_reason"] == "stop"
        assert chunks[-1]["choices"][0]["delta"] == {}
        assert all("usage" not in chunk for chunk in chunks), (
            "usage is only sent when the caller asks for it"
        )
    finally:
        node.stop()


def test_include_usage_adds_one_terminal_usage_frame(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """`stream_options.include_usage` is honoured, with the settled counts."""
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)

        _status, _headers, raw = _post_chat(
            server,
            _chat_body(stream=True, stream_options={"include_usage": True}),
            key=key,
        )
        frames = _sse_frames(raw)

        assert frames[-1] == "[DONE]"
        usage_frames = [frame for frame in frames[:-1] if "usage" in frame]
        assert len(usage_frames) == 1
        assert usage_frames[0] is frames[-2], "the usage frame is the last chunk"
        assert usage_frames[0]["choices"] == []
        assert usage_frames[0]["usage"]["total_tokens"] == BILLED_TOKENS
    finally:
        node.stop()


def test_a_stream_from_a_node_that_streams_arrives_incrementally(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """`stream: true` is admitted as `stream_strict`, so increments really flow.

    The point is not that the text is right — the buffered test proves that — but
    that a stream request is not silently downgraded to a buffered one: the
    delivery mode the server admits is the one the caller asked for.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response(text=("alpha ", "beta ", "gamma")))
        key = _mint_key(server, capsys)

        _status, headers, _raw = _post_chat(server, _chat_body(stream=True), key=key)

        request_id = _header(headers, "x-request-id")
        stored = server.store.get_request(request_id)
        assert stored is not None
        assert stored.delivery_mode == "stream_strict"
        assert node.upstream.calls[-1].messages[0].content == "write a haiku about sockets"
    finally:
        node.stop()


# --------------------------------------------------------------------------- #
# Refusals
# --------------------------------------------------------------------------- #


def test_a_missing_or_unknown_key_is_401_in_openais_shape(server: Server) -> None:
    """No header, another scheme, and a key nobody issued all answer alike."""
    for headers_key in (None, "not-a-key", "ak-" + "A" * 43):
        status, _headers, raw = _post_chat(server, _chat_body(), key=headers_key)
        error = json.loads(raw)["error"]
        assert status == 401, (headers_key, error)
        assert error["type"] == "invalid_request_error"
        assert error["code"] == "invalid_api_key"
        assert error["param"] is None
        assert isinstance(error["message"], str) and error["message"]
    # A bearer token that is a *platform* credential is not an API key either.
    status, _headers, raw = _post_chat(server, _chat_body(), key=NODE_TOKEN)
    assert status == 401
    assert json.loads(raw)["error"]["code"] == "invalid_api_key"
    assert server.store.list_api_keys() == []


def test_a_revoked_key_stops_working_on_a_running_server(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """Revocation bites immediately, without a restart, and says so twice."""
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)
        key_id = server.store.list_api_keys()[0].key_id
        assert _post_chat(server, _chat_body(), key=key)[0] == 200

        argv = [
            "admin",
            "api-key-revoke",
            "--config",
            str(server.config_path),
            "--key-id",
            key_id,
        ]
        assert server_main(argv) == 0
        assert "revoked API key" in capsys.readouterr().out
        # Repeating a revocation is a safe no-op that says it was already done.
        assert server_main(argv) == 0
        assert "was already revoked" in capsys.readouterr().out

        status, _headers, raw = _post_chat(server, _chat_body(), key=key)
        assert status == 401
        assert json.loads(raw)["error"]["code"] == "invalid_api_key"
        record = server.store.list_api_keys()[0]
        assert record.status == "revoked"
        assert record.revoked_at is not None
        # What it spent stays on the books: revoking withdraws access, not history.
        assert record.used_milli_credits == BILLED_TOKENS
    finally:
        node.stop()


def test_an_expired_key_is_401(server: Server, capsys: pytest.CaptureFixture[str]) -> None:
    """A key whose lifetime has passed authenticates nothing."""
    key = _mint_key(server, capsys, expires_in="1s")
    record = server.store.list_api_keys()[0]
    assert record.expires_at is not None

    time.sleep(1.2)

    status, _headers, raw = _post_chat(server, _chat_body(), key=key)
    assert status == 401
    assert json.loads(raw)["error"]["code"] == "invalid_api_key"


def test_a_spent_quota_is_429_insufficient_quota(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """The quota is what the settlement charged, and spending it ends the key.

    One request bills exactly the scripted 1,000 milli-credits, so a quota of
    1,000 admits that request and no second one. The status is OpenAI's own for
    a spent quota — `429` with `insufficient_quota` — because that is what an
    existing client already knows how to report to its user.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys, quota=BILLED_TOKENS)

        assert _post_chat(server, _chat_body(), key=key)[0] == 200
        _wait_until(
            lambda: server.store.list_api_keys()[0].used_milli_credits == BILLED_TOKENS,
            what="the settlement to count against the key's quota",
        )

        status, _headers, raw = _post_chat(server, _chat_body(), key=key)
        error = json.loads(raw)["error"]
        assert status == 429
        assert error["code"] == "insufficient_quota"
        assert error["type"] == "insufficient_quota"
        assert str(BILLED_TOKENS) in error["message"]
        # The refusal created no request and made no upstream call.
        assert node.adapter.upstream_calls == 1
    finally:
        node.stop()


def test_the_per_request_ceiling_is_the_smaller_of_the_quota_and_the_default(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """A key with less left than the default ceiling cannot expose more than it has.

    Read back from the authorization the server signed and stored, which is the
    document settlement measures the bill against: the ceiling is a fact about
    the request, not about the response.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys, quota=1_500)

        status, headers, _raw = _post_chat(server, _chat_body(), key=key)
        assert status == 200

        request_id = _header(headers, "x-request-id")
        inputs = server.store.get_request_input(request_id)
        assert inputs is not None
        signed_cap = inputs["authorization"]["payload"]["max_charge_milli_credits"]
        assert signed_cap == "1500"
        assert int(signed_cap) < gateway_service.API_KEY_DEFAULT_MAX_CHARGE_MILLI_CREDITS
        # The default ceiling governs a key that has more left than that.
        assert gateway_service.API_KEY_DEFAULT_MAX_CHARGE_MILLI_CREDITS == 20_000
    finally:
        node.stop()


def _credential(server: Server) -> Any:
    """The credential an API key for the provisioned consumer stands for."""
    from aipotluck_server.persistence import Credential

    return Credential(tenant_id=TENANT, subject_id=SUBJECT, role="consumer", account_id=SUBJECT)


def test_the_rate_limit_answers_429(
    server: Server,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A key that floods the endpoint is shed, not served without limit."""
    monkeypatch.setattr(gateway_service, "API_KEY_RATE_LIMIT", 2)
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        for _ in range(3):
            node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)

        assert _post_chat(server, _chat_body(), key=key)[0] == 200
        assert _post_chat(server, _chat_body(), key=key)[0] == 200
        status, _headers, raw = _post_chat(server, _chat_body(), key=key)
        error = json.loads(raw)["error"]
        assert status == 429
        assert error["code"] == "rate_limit_exceeded"
        assert error["type"] == "rate_limit_error"
    finally:
        node.stop()


def test_the_concurrency_ceiling_answers_429(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """Four requests in flight is the ceiling; the fifth is shed.

    Counted from the durable request rows rather than from process state, so the
    limit means the same thing after a restart, and a request an interrupted
    server left running still occupies its slot.
    """
    adapter = _GatedAdapter(upstream=FakeUpstream(), model=MODEL)
    for _ in range(5):
        adapter.upstream.queue(_scripted_response())
    node = Node(server, adapter=adapter, max_concurrency=8)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        key = _mint_key(server, capsys)
        assert gateway_service.API_KEY_MAX_IN_FLIGHT == 4

        statuses: list[int] = []
        threads = [
            threading.Thread(
                target=lambda: statuses.append(_post_chat(server, _chat_body(), key=key)[0]),
                daemon=True,
            )
            for _ in range(4)
        ]
        for thread in threads:
            thread.start()
        _wait_until(
            lambda: server.store.count_in_flight_api_key_requests(
                server.store.list_api_keys()[0].key_id
            )
            == 4,
            what="four requests in flight",
        )

        status, _headers, raw = _post_chat(server, _chat_body(), key=key)
        error = json.loads(raw)["error"]
        assert status == 429
        assert error["code"] == "rate_limit_exceeded"
        assert "in flight" in error["message"]

        adapter.gate.set()
        for thread in threads:
            thread.join(timeout=60)
        assert statuses == [200, 200, 200, 200], statuses
    finally:
        adapter.gate.set()
        node.stop()


def test_a_model_no_node_runs_is_404_model_not_found(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """Refused before a request exists, rather than queued until its deadline."""
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        key = _mint_key(server, capsys)

        status, _headers, raw = _post_chat(
            server, _chat_body() | {"model": "no-such-model"}, key=key
        )
        error = json.loads(raw)["error"]
        assert status == 404
        assert error["code"] == "model_not_found"
        assert error["type"] == "invalid_request_error"
        assert MODEL in error["message"], "the answer names what the pool can run"
    finally:
        node.stop()


def test_a_request_still_running_when_the_window_closes_is_504(
    server: Server,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wait that ends with the work unfinished says so, and names the request.

    The request is still live at the server and may still settle, so the answer
    carries the id an operator can verify against rather than pretending the
    request is over. The node is held inside the upstream call, which is the only
    honest way to have a request that is running and not answering.
    """
    monkeypatch.setattr(gateway_server, "OPENAI_REQUEST_DEADLINE_MS", 100)
    monkeypatch.setattr(gateway_server, "OPENAI_WAIT_GRACE_FACTOR", 1.0)
    monkeypatch.setattr(gateway_server, "OPENAI_WAIT_GRACE_S", 0.3)
    adapter = _GatedAdapter(upstream=FakeUpstream(), model=MODEL)
    adapter.upstream.queue(_scripted_response())
    node = Node(server, adapter=adapter)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        key = _mint_key(server, capsys)

        status, _headers, raw = _post_chat(server, _chat_body(), key=key, timeout=30)
        error = json.loads(raw)["error"]

        assert status == 504
        assert error["code"] == "deadline_passed"
        assert error["request_id"].startswith("req-")
        assert "potluck-server verify receipt" in error["message"]
        # The wait window rides past the request's own deadline, so the server's
        # sweep ended it before the connection gave up: the 504 names a request
        # whose fate the server has already recorded.
        stored = server.store.get_request(error["request_id"])
        assert stored is not None
        assert stored.status == "EXPIRED"
        assert adapter.gate.wait(timeout=0) is False, "the call was still held open"
    finally:
        adapter.gate.set()
        node.stop()


def test_a_request_the_server_expired_is_504_with_its_own_reason(
    server: Server,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The server's own deadline ends the request, and the answer carries why.

    A shorter request deadline than the connection's wait window is the normal
    case, so this is the answer a caller gets in production: the server decided,
    recorded its reason, and the endpoint reports both.
    """
    monkeypatch.setattr(gateway_server, "OPENAI_REQUEST_DEADLINE_MS", 1_000)
    adapter = _GatedAdapter(upstream=FakeUpstream(), model=MODEL)
    adapter.upstream.queue(_scripted_response())
    node = Node(server, adapter=adapter)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        key = _mint_key(server, capsys)

        status, _headers, raw = _post_chat(server, _chat_body(), key=key, timeout=60)
        error = json.loads(raw)["error"]

        assert status == 504
        assert error["code"] == "deadline_passed"
        assert "EXPIRED" in error["message"]
        assert "deadline" in error["message"]
        stored = server.store.get_request(error["request_id"])
        assert stored is not None
        assert stored.status == "EXPIRED"
        # An expired request billed nothing.
        assert server.store.list_api_keys()[0].used_milli_credits == 0
        assert server.service.balance(SUBJECT) == 100_000
    finally:
        adapter.gate.set()
        node.stop()


def test_a_failed_request_is_502_and_carries_the_servers_reason(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """An upstream that fails is a `502`, with the billing note the server wrote."""
    upstream = FakeUpstream()
    upstream.fault = "error_before_output"
    node = Node(server, adapter=FakeUpstreamAdapter(upstream=upstream, model=MODEL))
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        key = _mint_key(server, capsys)

        status, _headers, raw = _post_chat(server, _chat_body(), key=key)
        error = json.loads(raw)["error"]

        assert status == 502
        assert error["code"] == "upstream_failed"
        assert error["type"] == "server_error"
        assert "FAILED" in error["message"]
        stored = server.store.get_request(error["request_id"])
        assert stored is not None
        assert stored.status == "FAILED"
        # Nothing was billed for an answer that never existed.
        assert server.service.balance(SUBJECT) == 100_000
        assert server.store.list_api_keys()[0].used_milli_credits == 0
    finally:
        node.stop()


def test_a_stream_request_that_never_produced_an_increment_is_a_plain_502(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """A failure before any output is an HTTP status, not an error inside a stream.

    The `200` and the SSE headers are held until there is something to stream, so
    a caller whose client only reads statuses still learns that the request
    failed, and a proxy in between is not told a broken answer is a good one.
    """
    upstream = FakeUpstream()
    upstream.fault = "error_before_output"
    node = Node(server, adapter=FakeUpstreamAdapter(upstream=upstream, model=MODEL))
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        key = _mint_key(server, capsys)

        status, _headers, raw = _post_chat(server, _chat_body(stream=True), key=key)
        frames = _sse_frames(raw)

        # No increment ever existed, so the headers were held and the status is
        # the real one rather than a 200 with an error inside it.
        assert status == 502
        assert json.loads(raw)["error"]["code"] == "upstream_failed"
        assert frames == []
    finally:
        node.stop()


def _raw_chat(server: Server, key: str, body: dict[str, Any]) -> tuple[bytes, bool]:
    """Send one chat completion over a bare socket and return every byte back.

    Nothing in between parses, reframes or retries, so this is exactly what a proxy
    in front of the server sees: the status line, the headers, the body, and the
    way the stream ends. The second value reports whether the connection was reset
    rather than closed.
    """
    payload = json.dumps(body).encode("utf-8")
    reset = False
    with socket.create_connection(("127.0.0.1", server.port), timeout=130) as sock:
        sock.sendall(
            b"POST /openai/v1/chat/completions HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Authorization: Bearer " + key.encode("utf-8") + b"\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(payload)).encode("utf-8") + b"\r\n"
            b"Connection: close\r\n\r\n" + payload
        )
        chunks: list[bytes] = []
        while True:
            try:
                data = sock.recv(65536)
            except ConnectionResetError:
                reset = True
                break
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks), reset


def _raw_header(head: bytes, name: str) -> str:
    """Return one header from a raw response head, case-insensitively as HTTP is."""
    for line in head.split(b"\r\n")[1:]:
        field, _, value = line.partition(b":")
        if field.strip().lower() == name.encode("ascii"):
            return value.strip().decode("ascii")
    raise AssertionError(f"no {name} header in {head!r}")


def test_a_502_is_written_whole_for_both_delivery_modes(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """A refusal is one complete response on the wire, in both delivery modes.

    The bytes are the whole answer a proxy judges: a status line, headers that end
    where they say they do, a `Content-Length` the body matches exactly, and a
    stream that ends rather than being cut. A server that closes the connection
    before those bytes are on their way is reported to an operator as an invalid
    response from the origin — which reads as an outage, not as the refusal it was.
    """
    upstream = FakeUpstream()
    upstream.fault = "error_before_output"
    node = Node(server, adapter=FakeUpstreamAdapter(upstream=upstream, model=MODEL))
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        key = _mint_key(server, capsys)

        for body in (_chat_body(), _chat_body(stream=True)):
            raw, reset = _raw_chat(server, key, body)
            head, separator, rest = raw.partition(b"\r\n\r\n")
            assert separator, f"the head never ended: {raw[:200]!r}"
            lines = head.split(b"\r\n")
            assert lines[0] == b"HTTP/1.1 502 Bad Gateway", lines[0]
            assert all(b": " in line for line in lines[1:]), lines
            # The body is exactly as long as the head declares: not truncated, and
            # not padded with the next response's first bytes.
            assert len(rest) == int(_raw_header(head, "content-length")), rest
            assert json.loads(rest)["error"]["code"] == "upstream_failed"
            assert reset is False, "the connection was reset, which is how an answer gets lost"
    finally:
        node.stop()


def test_a_stream_that_fails_midway_ends_with_an_error_frame_and_done(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """Once a frame is out, the failure travels in the stream — and it still ends.

    The `200` cannot be taken back, so the caller is told inside the stream. The
    terminator still follows, because `[DONE]` says the stream is over rather
    than that the answer is good, and a client whose read loop waits for it would
    otherwise sit on a closed socket wondering whether more was coming.
    """
    upstream = FakeUpstream()
    upstream.queue(_scripted_response())
    upstream.fault = "truncate_mid_stream"
    node = Node(server, adapter=FakeUpstreamAdapter(upstream=upstream, model=MODEL))
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        key = _mint_key(server, capsys)

        status, _headers, raw = _post_chat(server, _chat_body(stream=True), key=key)
        frames = _sse_frames(raw)

        assert status == 200, "the stream had already begun before the failure"
        assert frames[-1] == "[DONE]"
        error_frames = [frame for frame in frames if isinstance(frame, dict) and "error" in frame]
        assert len(error_frames) == 1
        assert error_frames[0] is frames[-2]
        assert error_frames[0]["error"]["code"] == "upstream_failed"
        assert error_frames[0]["error"]["request_id"].startswith("req-")
        assert _content_of(frames) == "Hello ", "only what really arrived is rendered"
    finally:
        node.stop()


def test_a_malformed_body_is_400_and_names_the_problem(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """The body is validated at the boundary, in OpenAI's error shape."""
    key = _mint_key(server, capsys)
    cases: list[tuple[Any, str]] = [
        ({}, "messages"),
        (_chat_body() | {"messages": []}, "at least one message"),
        (_chat_body() | {"messages": [{"role": "user"}]}, "content"),
        (_chat_body() | {"messages": [{"role": "caller", "content": "hi"}]}, "role"),
        (_chat_body() | {"model": ""}, "model"),
        (_chat_body(stream="yes"), "stream must be a boolean"),
        (_chat_body(temperature="hot"), "temperature"),
        (_chat_body(max_tokens=-1), "max_tokens"),
        ("{not json", "not valid JSON"),
    ]
    for body, needle in cases:
        status, _headers, raw = _post_chat(server, body, key=key)
        error = json.loads(raw)["error"]
        assert status == 400, (body, error)
        assert error["type"] == "invalid_request_error"
        assert error["code"] == "invalid_request"
        assert needle in error["message"], (body, error["message"])


def test_a_fractional_parameter_is_accepted_and_forwarded(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """`temperature: 0.7` works here, though the platform's own surface refuses it.

    The strict parser that guards every signed endpoint rejects fractions by
    design; an OpenAI client sends them in every request, so this surface parses
    with the standard library and canonicalizes what it forwards.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)

        status, _headers, _raw = _post_chat(
            server, _chat_body(temperature=0.7, top_p=0.95), key=key
        )

        assert status == 200
        assert node.upstream.calls[-1].parameters == {
            "temperature": "0.7",
            "top_p": "0.95",
        }
    finally:
        node.stop()


# --------------------------------------------------------------------------- #
# The model list
# --------------------------------------------------------------------------- #


def test_the_model_list_is_what_the_pool_can_run(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """Aggregated from the registrations, not from a maintained catalogue."""
    key = _mint_key(server, capsys)
    status, _headers, raw = _get(server, "/openai/v1/models", key=key)
    assert status == 200
    assert json.loads(raw) == {"object": "list", "data": []}

    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")

        status, _headers, raw = _get(server, "/openai/v1/models", key=key)
        listing = json.loads(raw)
        assert status == 200
        assert listing["object"] == "list"
        assert [entry["id"] for entry in listing["data"]] == [MODEL]
        entry = listing["data"][0]
        assert entry["object"] == "model"
        assert entry["owned_by"] == gateway_server.OPENAI_MODEL_OWNER
        assert entry["created"] > 0

        status, _headers, raw = _get(server, f"/openai/v1/models/{MODEL}", key=key)
        assert status == 200
        assert json.loads(raw)["id"] == MODEL

        status, _headers, raw = _get(server, "/openai/v1/models/nope", key=key)
        error = json.loads(raw)["error"]
        assert status == 404
        assert error["code"] == "model_not_found"
        assert MODEL in error["message"]
    finally:
        node.stop()


def test_the_model_list_needs_a_key(server: Server) -> None:
    """The list is authenticated like every other endpoint on this surface."""
    status, _headers, raw = _get(server, "/openai/v1/models", key=None)
    assert status == 401
    assert json.loads(raw)["error"]["code"] == "invalid_api_key"


def test_unimplemented_endpoints_say_so(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """Embeddings and the legacy completions endpoint are refused by name."""
    key = _mint_key(server, capsys)
    for path in ("/openai/v1/embeddings", "/openai/v1/completions"):
        status, _headers, raw = _post_chat(server, _chat_body(), key=key, path=path)
        error = json.loads(raw)["error"]
        assert status == 404, path
        assert error["type"] == "not_supported"
        assert path.rsplit("/", 1)[1] in error["message"]
        assert "chat/completions" in error["message"]
    # An unknown path under the same prefix answers in the same shape.
    status, _headers, raw = _get(server, "/openai/v1/audio/transcriptions", key=key)
    assert status == 404
    assert json.loads(raw)["error"]["type"] == "invalid_request_error"


# --------------------------------------------------------------------------- #
# The surface next to the platform's own
# --------------------------------------------------------------------------- #


def test_an_api_key_is_not_a_platform_credential(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """The two surfaces do not accept each other's material.

    A key that answered on ``/openai/v1`` authenticates nothing on ``/v1``, and a
    platform credential is not an API key. If either were accepted by the other
    surface, the API key's quota and its revocation would not be the whole of
    what a key can do.
    """
    key = _mint_key(server, capsys)

    status, _headers, raw = _post_chat(
        server,
        {
            "idempotency_key": "idem-1",
            "messages": [{"role": "user", "content": "hi"}],
            "model": MODEL,
            "max_charge_milli_credits": 100,
            "delivery_mode": "buffered_complete",
            "max_attempts": 1,
            "deadline_ms": 1000,
            "authorization": {},
        },
        key=key,
        path="/v1/requests",
    )
    assert status == 401
    assert json.loads(raw)["error"] == "unauthorized"

    status, _headers, raw = _post_chat(server, _chat_body(), key=NODE_TOKEN)
    assert status == 401
    assert json.loads(raw)["error"]["code"] == "invalid_api_key"

    # The consumer credential still works on its own surface, unchanged.
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=30)
    connection.request(
        "GET",
        "/v1/account/history",
        headers={"authorization": f"Bearer {CONSUMER_TOKEN}"},
    )
    response = connection.getresponse()
    body = response.read()
    connection.close()
    assert response.status == 200, body


def test_the_signed_path_still_admits_while_a_key_exists(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """The new admission path did not weaken the one it sits beside.

    A signed request is admitted on the consumer's own signature, settles through
    the same books, and leaves the API key's quota untouched: two ways to
    authorize one spend, not two sets of accounting.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        # A key exists beside this request; what follows asserts that the signed
        # path neither needs it nor spends it.
        _mint_key(server, capsys)
        request_id = "req-signed-1"
        moment = dt.datetime.now(dt.UTC)
        messages = (user_message("hi"),)
        authorization = signed_authorization(
            server.keyring,
            request_id=request_id,
            payer_account_id=SUBJECT,
            consumer_id=SUBJECT,
            key_id="consumer-key-1",
            issued_at=moment - dt.timedelta(minutes=1),
            expires_at=moment + dt.timedelta(minutes=10),
            messages=messages,
            model=MODEL,
        )

        result = server.service.admit_request(
            credential=_credential(server),
            idempotency_key="idem-signed-1",
            messages=messages,
            authorization=authorization,
            model=MODEL,
            max_charge_milli_credits=20_000,
            delivery_mode="buffered_complete",
            max_attempts=2,
            deadline_ms=60_000,
            now=moment,
        )
        assert result.request_id == request_id

        _wait_until(
            lambda: server.store.get_request(request_id).status == "SUCCEEDED",
            what="the signed request to settle",
        )
        settlement = server.store.get_settlement(request_id, 1)
        assert settlement is not None
        assert server.store.get_receipt(settlement.receipt_id) is not None
        assert server.service.balance(SUBJECT) == 100_000 - BILLED_TOKENS
        # The signed request is not counted against any key's quota, and it is
        # marked as no key's: the request row itself says which path admitted it.
        assert server.store.list_api_keys()[0].used_milli_credits == 0
        stored = server.store.get_request(request_id)
        assert stored is not None
        assert stored.api_key_id is None
    finally:
        node.stop()


def test_one_structured_log_line_per_request(
    server: Server, capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture
) -> None:
    """The observability line names the key, the tokens and the outcome.

    It is what an operator greps to answer "what did this key cost me today"
    without reading the books, so it carries the counts the settlement produced
    and never the key itself.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)
        key_id = server.store.list_api_keys()[0].key_id

        with caplog.at_level(logging.INFO, logger="aipotluck_server.gateway_server"):
            assert _post_chat(server, _chat_body(), key=key)[0] == 200

        lines = [
            json.loads(record.message)
            for record in caplog.records
            if record.name == "aipotluck_server.gateway_server"
        ]
        assert len(lines) == 1
        line = lines[0]
        assert line["endpoint"] == "openai_chat_completions"
        assert line["key_id"] == key_id
        assert line["subject_id"] == SUBJECT
        assert line["model"] == MODEL
        assert line["prompt_tokens"] == 800
        assert line["completion_tokens"] == 200
        assert line["total_tokens"] == BILLED_TOKENS
        assert line["outcome"] == "SUCCEEDED"
        assert line["status"] == 200
        assert line["request_id"].startswith("req-")
        assert line["latency_ms"] >= 0
        # The plaintext key is material: it appears in no log line.
        assert key not in json.dumps(line)
        assert all(key not in record.getMessage() for record in caplog.records)
    finally:
        node.stop()


def test_a_kept_alive_connection_answers_its_second_request_too(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """One connection, several requests, each answered — refusals included.

    Every OpenAI client reuses connections, so the second request on a socket is
    the normal case rather than an edge. A handler that kept the first request's
    "already answered" flag would close the connection instead of answering the
    second, and a client would see a transport failure where the server meant a
    `401`. The same connection is then reused on the platform's own surface, to
    show the fix is not specific to this one.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)
        connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=60)

        connection.request(
            "POST",
            "/openai/v1/chat/completions",
            body=json.dumps(_chat_body()).encode(),
            headers={"authorization": f"Bearer {key}"},
        )
        first = connection.getresponse()
        assert first.status == 200, first.read()
        first.read()

        connection.request(
            "POST",
            "/openai/v1/chat/completions",
            body=json.dumps(_chat_body()).encode(),
            headers={"authorization": "Bearer ak-not-a-key-" + "A" * 29},
        )
        second = connection.getresponse()
        body = json.loads(second.read())
        assert second.status == 401
        assert body["error"]["code"] == "invalid_api_key"

        connection.request(
            "GET", "/v1/nodes", headers={"authorization": f"Bearer {CONSUMER_TOKEN}"}
        )
        third = connection.getresponse()
        assert third.status == 200, third.read()
        third.read()

        connection.request("GET", "/v1/nodes", headers={"authorization": "Bearer x"})
        fourth = connection.getresponse()
        assert fourth.status == 401
        assert json.loads(fourth.read())["error"] == "unauthorized"
        connection.close()
    finally:
        node.stop()


# --------------------------------------------------------------------------- #
# The real OpenAI client
# --------------------------------------------------------------------------- #


def test_the_openai_python_client_can_use_the_server(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """A drop-in client: base URL, key, and no code that knows this server.

    The SDK is the strictest reader of this surface that exists, and it is not
    under this repository's control — so a completion it parses, a stream it
    iterates, and an error it classifies are the acceptance test that matters.
    """
    openai = pytest.importorskip("openai")
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        for _ in range(4):
            node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)
        client = openai.OpenAI(
            base_url=f"http://127.0.0.1:{server.port}/openai/v1",
            api_key=key,
            max_retries=0,
            timeout=120.0,
        )

        completion = client.chat.completions.create(
            model=MODEL, messages=[{"role": "user", "content": "hi"}]
        )
        assert completion.object == "chat.completion"
        assert completion.choices[0].message.content == ANSWER
        assert completion.choices[0].finish_reason == "stop"
        assert completion.usage.total_tokens == BILLED_TOKENS

        # A multi-turn conversation, which the upstream must receive whole.
        client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "answer in one word"},
                {"role": "user", "content": "what settles a request?"},
                {"role": "assistant", "content": "a receipt"},
                {"role": "user", "content": "and what backs it?"},
            ],
            temperature=0.3,
            max_tokens=32,
        )
        call = node.upstream.calls[-1]
        assert [message.to_payload() for message in call.messages] == [
            {"role": "system", "content": "answer in one word"},
            {"role": "user", "content": "what settles a request?"},
            {"role": "assistant", "content": "a receipt"},
            {"role": "user", "content": "and what backs it?"},
        ]
        assert call.parameters == {"max_tokens": 32, "temperature": "0.3"}

        stream = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": "hi"}],
            stream=True,
            stream_options={"include_usage": True},
        )
        parts: list[str] = []
        usage: Any = None
        for chunk in stream:
            if chunk.usage is not None:
                usage = chunk.usage
            for choice in chunk.choices:
                if choice.delta.content:
                    parts.append(choice.delta.content)
        assert "".join(parts) == ANSWER
        assert usage is not None and usage.total_tokens == BILLED_TOKENS

        models = client.models.list()
        assert [entry.id for entry in models.data] == [MODEL]
    finally:
        node.stop()


def test_the_openai_python_client_reads_refusals_as_its_own_errors(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """The codes are the ones the SDK classifies, not merely ones chosen here.

    A client's retry logic keys off the exception type the SDK raises, so an
    unrecognized shape would not be a cosmetic difference: a spent quota read as
    a server error would be retried instead of reported.
    """
    openai = pytest.importorskip("openai")
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        for _ in range(2):
            node.upstream.queue(_scripted_response())
        base_url = f"http://127.0.0.1:{server.port}/openai/v1"

        def client_for(api_key: str) -> Any:
            return openai.OpenAI(
                base_url=base_url, api_key=api_key, max_retries=0, timeout=60.0
            )

        with pytest.raises(openai.AuthenticationError) as denied:
            client_for("ak-" + "A" * 43).chat.completions.create(
                model=MODEL, messages=[{"role": "user", "content": "hi"}]
            )
        assert denied.value.status_code == 401
        # The SDK unwraps the error object, so `body` *is* the error.
        assert denied.value.body["code"] == "invalid_api_key"
        assert denied.value.body["type"] == "invalid_request_error"

        with pytest.raises(openai.NotFoundError) as missing:
            client_for(_mint_key(server, capsys)).chat.completions.create(
                model="no-such-model", messages=[{"role": "user", "content": "hi"}]
            )
        assert missing.value.status_code == 404
        assert missing.value.body["code"] == "model_not_found"

        # Spend the whole quota on one request, then ask again.
        spent = client_for(_mint_key(server, capsys, quota=BILLED_TOKENS))
        assert spent.chat.completions.create(
            model=MODEL, messages=[{"role": "user", "content": "hi"}]
        ).choices[0].message.content == ANSWER
        with pytest.raises(openai.RateLimitError) as exhausted:
            spent.chat.completions.create(
                model=MODEL, messages=[{"role": "user", "content": "hi"}]
            )
        assert exhausted.value.status_code == 429
        assert exhausted.value.body["code"] == "insufficient_quota"
        assert exhausted.value.body["type"] == "insufficient_quota"
    finally:
        node.stop()


# --------------------------------------------------------------------------- #
# A server upgraded in place from the flattened-prompt model
# --------------------------------------------------------------------------- #


def _precreate_prompt_era_request_inputs(path: Path) -> None:
    """Create the `request_inputs` table a server from before the conversation model holds.

    Only that table. `Server` then opens the store, which creates everything else
    and runs the migration — the exact sequence an in-place upgrade performs on a
    database the earlier build made.
    """
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE request_inputs (request_id TEXT PRIMARY KEY,"
            " prompt TEXT NOT NULL, model TEXT NOT NULL,"
            " authorization_json TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO request_inputs (request_id, prompt, model, authorization_json,"
            " created_at) VALUES (?, ?, ?, '{}', ?)",
            (
                "req-legacy-1",
                "write a haiku about ledgers",
                MODEL,
                BASE.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _operator_config(server: Server) -> Path:
    """Write the ``server.json`` the operator audit commands open.

    The audit commands load a full configuration rather than the one field the
    minting commands need, so this names the running server's own settings — the
    same settlement key, the same database — and nothing else.
    """
    path = server.tmp_path / "operator-server.json"
    document = {
        "host": server.config.host,
        "port": server.config.port,
        "database_path": server.config.database_path,
        "platform_id": server.config.platform_id,
        "settlement_key_id": server.config.settlement_key_id,
        "settlement_private_key_b64": server.config.settlement_private_key_b64,
        "certfile": None,
        "keyfile": None,
        "credentials": [],
        # The audit builds its own trusted registry from this file, and a
        # self-declared public key is never accepted: the device key that signed
        # the usage report has to be named here for `signature_valid` to mean
        # anything.
        "providers": [
            {
                "device_id": "device-A",
                "device_key_id": "device-key-A",
                "provider_id": "provider-A",
                "public_key_b64": server.keyring.public["device-key-A"],
                "demo_float_milli_credits": 0,
            }
        ],
        "consumer_floats": [],
    }
    path.write_text(json.dumps(document), encoding="utf-8")
    # The document carries the settlement private key, so it gets the mode a file
    # holding key material gets.
    path.chmod(0o600)
    return path


def test_an_upgraded_server_admits_an_api_key_request_to_a_verified_receipt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The production failure, end to end: an upgraded server, a real node, a real key.

    This is the hole the two-package gate had. The signed path was covered end to
    end and the API-key face was covered by an in-process fake, so nothing drove
    ``admit_api_key_request`` through a real store, a real connector and a real
    HTTP caller at once — and a server whose database could not hold a
    conversation answered every ``POST /openai/v1/chat/completions`` with a 502
    ``upstream_failed`` naming a request that "has no stored dispatch inputs",
    while leaving that request in ROUTING to hold its key's concurrency slot for
    good. Both delivery modes run to a receipt here, because a server that can
    admit one and not the other would still answer a caller.

    The terminal request the earlier build left behind is asserted on too: the
    migration carries such a row instead of losing it, and the books around it
    still reconcile and still verify.
    """
    openai = pytest.importorskip("openai")
    _precreate_prompt_era_request_inputs(tmp_path / "server.db")
    server = Server(tmp_path, Keyring())
    node = Node(server)
    try:
        _wait_until(
            lambda: bool(server.store.connected_nodes()), what="the node to register"
        )
        # The request row the legacy inputs row belongs to, terminal as production
        # held it: a failed request from before the upgrade.
        server.store.create_request(
            request_id="req-legacy-1",
            tenant_id=TENANT,
            subject_id=SUBJECT,
            idempotency_key="K-1",
            payload_digest="sha256:legacy",
            delivery_mode="buffered_complete",
            max_attempts=1,
            service_unit_id="req-legacy-1",
            created_at=BASE,
        )
        server.store.set_request_status(
            "req-legacy-1", "FAILED", billing_note="upstream failed", at=BASE
        )

        for _ in range(2):
            node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)
        client = openai.OpenAI(
            base_url=f"http://127.0.0.1:{server.port}/openai/v1",
            api_key=key,
            max_retries=0,
            timeout=120.0,
        )

        buffered = client.chat.completions.create(
            model=MODEL, messages=[{"role": "user", "content": "hi"}]
        )
        assert buffered.choices[0].message.content == ANSWER
        assert buffered.usage is not None and buffered.usage.total_tokens == BILLED_TOKENS

        stream = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": "hi"}],
            stream=True,
            stream_options={"include_usage": True},
        )
        parts: list[str] = []
        streamed_usage: Any = None
        for chunk in stream:
            if chunk.usage is not None:
                streamed_usage = chunk.usage
            for choice in chunk.choices:
                if choice.delta.content:
                    parts.append(choice.delta.content)
        assert "".join(parts) == ANSWER
        assert streamed_usage is not None and streamed_usage.total_tokens == BILLED_TOKENS

        # Both requests reached a terminal state, and neither holds a slot: the
        # concurrency budget the stuck rows used to eat is whole again.
        key_id = server.store.list_api_keys()[0].key_id
        assert server.store.count_in_flight_api_key_requests(key_id) == 0
        statuses = {
            record.request_id: record.status for record in server.store.requests()
        }
        assert statuses["req-legacy-1"] == "FAILED"
        admitted = [status for name, status in statuses.items() if name != "req-legacy-1"]
        assert admitted == ["SUCCEEDED", "SUCCEEDED"], statuses

        # Each settled request left a receipt an operator can verify.
        config_path = _operator_config(server)
        receipts = server.store.receipts()
        assert len(receipts) == 2
        for receipt in receipts:
            exit_code = server_main(
                [
                    "verify",
                    "receipt",
                    "--config",
                    str(config_path),
                    "--receipt-id",
                    receipt.receipt_id,
                ]
            )
            captured = capsys.readouterr()
            assert exit_code == 0, captured.out + captured.err
        # And the migrated legacy row breaks no invariant the audit checks.
        reconcile_exit = server_main(
            ["admin", "reconcile", "--config", str(config_path)]
        )
        reconciled = capsys.readouterr()
        assert reconcile_exit == 0, reconciled.out + reconciled.err
    finally:
        node.stop()
        server.stop()


# --------------------------------------------------------------------------- #
# Agent sessions over the OpenAI-compatible surface
# --------------------------------------------------------------------------- #


def _post_chat_with_session(
    server: Server, body: Any, *, key: str, session: str | None
) -> tuple[int, Any, str]:
    """POST one request carrying the session header an agent framework would set.

    Through `default_headers` on the real SDK, and through a plain header here: the
    point of putting the session in a header is that a caller driving this surface
    with an OpenAI client needs no change to the body it already sends.
    """
    connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=130.0)
    headers = {
        "content-type": "application/json",
        "authorization": f"Bearer {key}",
    }
    if session is not None:
        headers[SESSION_HEADER] = session
    raw = body if isinstance(body, str) else json.dumps(body)
    connection.request("POST", "/openai/v1/chat/completions", body=raw.encode(), headers=headers)
    response = connection.getresponse()
    text = response.read().decode("utf-8")
    connection.close()
    return response.status, response.getheaders(), text


def test_a_session_header_aggregates_the_turns_a_tool_made(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two turns under one header become one aggregate the operator can read.

    The evidence is the operator's own command rather than a store read, because
    what the feature promises is that an operator can ask what a run cost: the
    listing has to name the session, count the turns, and total the tokens and
    credit the books moved.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        for _ in range(2):
            node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)

        for _ in range(2):
            status, _headers, raw = _post_chat_with_session(
                server, _chat_body(), key=key, session="sess-agent-run"
            )
            assert status == 200, raw

        session = server.store.session(TENANT, SUBJECT, "sess-agent-run")
        assert session is not None
        assert session.request_count == 2
        assert session.total_tokens == 2 * BILLED_TOKENS
        assert session.total_milli_credits == 2 * BILLED_TOKENS
        assert session.last_node_id == "node-A"

        assert server_main(
            ["admin", "session-list", "--config", str(server.config_path)]
        ) == 0
        listing = capsys.readouterr().out
        assert "sess-agent-run" in listing
        assert f"subject={SUBJECT}" in listing
        assert "requests=2" in listing
        assert f"tokens={2 * BILLED_TOKENS}" in listing
    finally:
        node.stop()


def test_session_show_lists_the_receipts_behind_a_sessions_totals(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """A session's totals are a claim; the receipts named beside them are the account.

    Each id this command prints verifies on its own, which is what makes the
    aggregate auditable rather than merely convenient.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        for _ in range(2):
            node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)
        for _ in range(2):
            _post_chat_with_session(server, _chat_body(), key=key, session="sess-shown")

        config_path = _operator_config(server)
        assert (
            server_main(
                [
                    "admin",
                    "session-show",
                    "--config",
                    str(config_path),
                    "--session",
                    "sess-shown",
                ]
            )
            == 0
        )
        shown = capsys.readouterr().out
        assert "requests=2" in shown
        assert "receipts=2" in shown
        for receipt in server.store.receipts():
            assert receipt.receipt_id in shown
            assert (
                server_main(
                    [
                        "verify",
                        "receipt",
                        "--config",
                        str(config_path),
                        "--receipt-id",
                        receipt.receipt_id,
                    ]
                )
                == 0
            ), capsys.readouterr().err
    finally:
        node.stop()


def test_a_request_with_no_session_header_is_aggregated_nowhere(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """A session exists because a caller declared one, never by inference.

    Asserted because the alternative — attributing every request to an implicit
    session — would make `session-list` a list of callers rather than of runs, and
    would report a cost nobody asked to have aggregated.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)

        status, _headers, raw = _post_chat_with_session(
            server, _chat_body(), key=key, session=None
        )

        assert status == 200, raw
        assert server.store.sessions() == []
    finally:
        node.stop()


@pytest.mark.parametrize("session", ["two words", "x" * 129])
def test_a_session_header_this_platform_cannot_store_is_400(
    server: Server, capsys: pytest.CaptureFixture[str], session: str
) -> None:
    """Refused at the boundary, in the shape this surface answers everything else in.

    Not trimmed and not dropped: a caller that named a session and was silently
    given none would read an aggregate for a run it never joined.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        key = _mint_key(server, capsys)

        status, _headers, document = _post_chat_with_session(
            server, _chat_body(), key=key, session=session
        )

        assert status == 400
        assert json.loads(document)["error"]["code"] == "invalid_request"
        assert server.store.sessions() == []
    finally:
        node.stop()


def test_a_key_minted_with_a_longer_window_gives_its_requests_that_window(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """`--deadline-ms` is an operator's statement about the work a key is for.

    The surface admits every request with its own default budget; a key minted for
    an agent loop overrides it. What has to be observable is the request row's own
    deadline, because that is the instant the server's sweep will end the turn — a
    longer window that was not written down is not a longer window.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys, name="agent", deadline_ms=600_000)
        minted = server.store.list_api_keys()[0]
        assert minted.deadline_ms == 600_000

        status, _headers, raw = _post_chat(server, _chat_body(), key=key)
        assert status == 200, raw

        admitted = [
            record for record in server.store.requests() if record.api_key_id == minted.key_id
        ]
        assert len(admitted) == 1
        assert admitted[0].deadline_at is not None
        # Ten minutes from admission, not the thirty minutes the surface defaults to.
        now = dt.datetime.now(dt.UTC)
        assert admitted[0].deadline_at > now + dt.timedelta(seconds=500)
        assert admitted[0].deadline_at < now + dt.timedelta(seconds=700)

        # A key with no window of its own keeps the surface's, which is what makes
        # the flag an override rather than a second, always-present deadline.
        node.upstream.queue(_scripted_response())
        plain = _mint_key(server, capsys, name="plain")
        status, _headers, raw = _post_chat(server, _chat_body(), key=plain)
        assert status == 200, raw
        plain_key = next(
            record for record in server.store.list_api_keys() if record.key_id != minted.key_id
        )
        assert plain_key.deadline_ms is None
        plain_request = next(
            record
            for record in server.store.requests()
            if record.api_key_id == plain_key.key_id
        )
        assert plain_request.deadline_at is not None
        # The surface default is the agent-sized thirty minutes.
        assert plain_request.deadline_at > dt.datetime.now(dt.UTC) + dt.timedelta(seconds=1700)
        assert plain_request.deadline_at < dt.datetime.now(dt.UTC) + dt.timedelta(seconds=1900)
    finally:
        node.stop()


def test_a_full_dispatch_queue_answers_429_rather_than_holding_everything(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The bound is what keeps a wait from becoming a promise the server cannot keep.

    The scenario is a pool whose node went away: the model is still in the server's
    catalogue, so this is contention rather than a request nothing could ever run,
    and the first request is held instead of refused. With the queue at its bound
    the next one is refused with the status an OpenAI client already backs off on.

    The part that matters for the books is what the refusal does *not* do: it
    stores no request row, holds no key slot, and leaves nothing for the deadline
    sweep to end. A refusal that created a row to refuse would be a server holding
    work it just said it would not hold.
    """
    server = Server(tmp_path, Keyring(), max_queue_depth=1)
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.stop()
        _wait_until(
            lambda: not server.store.connected_nodes(), what="the node to disconnect"
        )
        assert server.store.catalogued_models() == {MODEL}, (
            "a node that lost its link has not withdrawn its model"
        )
        key = _mint_key(server, capsys, deadline_ms=8_000)

        held: list[int] = []
        thread = threading.Thread(
            target=lambda: held.append(_post_chat(server, _chat_body(), key=key)[0]),
            daemon=True,
        )
        thread.start()
        _wait_until(
            lambda: server.store.count_requests_by_status("ROUTING") == 1,
            what="the first request to be admitted and wait for a node",
        )

        status, _headers, raw = _post_chat(server, _chat_body(), key=key)

        error = json.loads(raw)["error"]
        assert status == 429, raw
        assert error["code"] == "rate_limit_exceeded"
        assert error["type"] == "rate_limit_error"
        assert "queue bound of 1" in error["message"]
        assert server.store.count_requests_by_status("ROUTING") == 1, (
            "a refused admission stores nothing to sweep"
        )

        thread.join(timeout=60)
        assert held == [504], "the held request ends on its own deadline, honestly"
    finally:
        node.stop()
        server.stop()


def test_a_model_no_node_of_the_server_runs_is_still_404_while_a_queue_holds_work(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Queueing does not turn a typo into a timeout.

    A server that held every request it could not dispatch would answer a model
    name it has never heard of with a 504 a hundred seconds later, naming nothing
    that was actually wrong. The catalogue check is what keeps the two refusals
    distinguishable: this model has no node here, so waiting cannot help.
    """
    server = Server(tmp_path, Keyring())
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        key = _mint_key(server, capsys)

        status, _headers, raw = _post_chat(
            server, _chat_body() | {"model": "no-such-model"}, key=key
        )

        error = json.loads(raw)["error"]
        assert status == 404
        assert error["code"] == "model_not_found"
        assert MODEL in error["message"]
        assert server.store.requests() == []
    finally:
        node.stop()
        server.stop()


def test_a_fractional_parameter_runs_the_whole_chain_to_a_verifiable_receipt(
    server: Server, capsys: pytest.CaptureFixture[str]
) -> None:
    """`temperature: 0.7`, from an OpenAI-shaped body to a receipt that verifies.

    The regression this guards is a real one that shipped: the canonical encoding
    carries a fraction as its shortest decimal string, and a server that could not
    re-encode the form it had itself produced refused the request at admission —
    so a parameter every OpenAI client sends by default could not cross the signed
    half of the platform at all. Existing tests here assert what the *upstream*
    received, which a defect in the digest or in the stored inputs would not show.
    This one drives the whole chain and checks the ends:

    * admission accepts it and stores the parameters it dispatched;
    * the node receives the fraction as the number it is;
    * the request settles, and the receipt an operator verifies afterwards is the
      receipt this request produced.
    """
    node = Node(server)
    try:
        _wait_until(lambda: bool(server.store.connected_nodes()), what="the node to register")
        node.upstream.queue(_scripted_response())
        key = _mint_key(server, capsys)

        status, headers, raw = _post_chat(
            server, _chat_body(temperature=0.7, top_p=0.95), key=key
        )
        assert status == 200, raw
        document = json.loads(raw)
        assert document["choices"][0]["message"]["content"] == ANSWER
        assert document["usage"]["total_tokens"] == BILLED_TOKENS

        # The fraction survived the wire as its decimal string and reached the
        # upstream as the number an upstream expects.
        assert node.upstream.calls[-1].parameters == {
            "temperature": "0.7",
            "top_p": "0.95",
        }

        # What the server stored to dispatch is what it signed for: the same
        # parameter set, in the canonical-safe encoding, behind the request.
        request_id = _header(headers, "x-request-id")
        inputs = server.store.get_request_input(request_id)
        assert inputs is not None
        assert inputs["parameters"] == {"temperature": "0.7", "top_p": "0.95"}
        stored = server.store.get_request(request_id)
        assert stored is not None
        assert stored.status == "SUCCEEDED"

        receipts = server.store.receipts()
        assert [receipt.request_id for receipt in receipts] == [request_id]
        config_path = _operator_config(server)
        assert (
            server_main(
                [
                    "verify",
                    "receipt",
                    "--config",
                    str(config_path),
                    "--receipt-id",
                    receipts[0].receipt_id,
                ]
            )
            == 0
        ), capsys.readouterr().err
        assert server_main(["admin", "reconcile", "--config", str(config_path)]) == 0
        capsys.readouterr()
    finally:
        node.stop()
