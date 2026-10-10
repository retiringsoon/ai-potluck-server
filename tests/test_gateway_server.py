"""Transport tests for the center gateway, over real loopback TCP.

Everything here drives a real `GatewayServer` on ``127.0.0.1`` with real
`http.client`, `ssl` and `websocket.ClientConnection` peers. The socket layer is
never mocked: the point of the transport is what actually goes over the wire.

The domain is a stub (`_StubService`) that records what the transport asked it
to do, which is how the plumbing is tested independently of the settlement
rules. One test additionally registers the real `aipotluck.gateway_service`
implementation against `GatewayServiceProtocol`, and skips cleanly while that
module does not exist.
"""

from __future__ import annotations

import datetime as dt
import http.client
import inspect
import json
import secrets
import socket
import ssl
import tempfile
import time
import urllib.parse
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest
from aipotluck.canonical import base64_decode, sign_payload, verify_payload
from aipotluck.errors import ConflictError, SignatureError, UnknownKeyError
from aipotluck.identity import generate_key_pair, load_private_key
from aipotluck.records import (
    DOMAIN_REQUEST_AUTH,
    SignedRecord,
    format_request_auth_header,
    request_auth_payload,
    request_body_digest,
)
from aipotluck.websocket import ClientConnection, WebSocketClosed, WebSocketProtocolError
from aipotluck.wire import Envelope, HelloAck, NodeHello, NodePolicy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aipotluck_server.gateway_server import (
    MAX_HTTP_BODY_BYTES,
    GatewayConfig,
    GatewayServer,
    GatewayServiceProtocol,
)
from aipotluck_server.persistence import Credential, NodeRecord, StoredEvent

NOW = dt.datetime(2026, 10, 8, 12, 0, tzinfo=dt.UTC)

CONSUMER_TOKEN = "consumer-token-0123456789abcdef"
NODE_TOKEN = "node-token-fedcba9876543210"
FOREIGN_TOKEN = "foreign-tenant-token-abcdef01"

CONSUMER = Credential(tenant_id="tenant-a", subject_id="consumer-a", role="consumer")
FOREIGN = Credential(tenant_id="tenant-b", subject_id="consumer-b", role="consumer")
NODE = Credential(tenant_id="tenant-a", subject_id="node-a", role="node")

#: Its own module-level constant so a test can name it without re-deriving it.
OVERSIZE_BYTES = MAX_HTTP_BODY_BYTES


# --------------------------------------------------------------------------- #
# Stub service
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _StubAdmitResult:
    """The one field the transport reads back from an admission."""

    request_id: str


@dataclass(frozen=True)
class _StubJoinResult:
    """The join document the transport renders back."""

    tenant_id: str
    subject_id: str
    role: str
    key_id: str
    center_url: str

    def to_payload(self) -> dict[str, str]:
        """Return the response document ``POST /v1/join`` answers with."""
        return {
            "tenant_id": self.tenant_id,
            "subject_id": self.subject_id,
            "role": self.role,
            "key_id": self.key_id,
            "center_url": self.center_url,
        }


class _StubStore:
    """A credential table and node registry, resolved only through the service."""

    def __init__(self, credentials: dict[str, Credential]) -> None:
        self._credentials = credentials
        self.nodes: list[NodeRecord] = []
        self.resolutions: list[str] = []

    def resolve_credential(self, token: str, at: dt.datetime) -> Credential | None:
        """Resolve a token the way the real store does: unknown means `None`."""
        self.resolutions.append(token)
        return self._credentials.get(token)

    def connected_nodes(self, *, model: str | None = None) -> list[NodeRecord]:
        """Return the registrations the store believes are still connected."""
        del model
        return [node for node in self.nodes if node.connected]


class _StubService:
    """A GatewayServiceProtocol implementation that records every call."""

    def __init__(self) -> None:
        """Build an empty service with one credential per role."""
        self.store = _StubStore(
            {CONSUMER_TOKEN: CONSUMER, NODE_TOKEN: NODE, FOREIGN_TOKEN: FOREIGN}
        )
        self.log = object()
        self.events: dict[str, list[StoredEvent]] = {}
        self.statuses: dict[str, str] = {}
        self.admissions: list[dict[str, Any]] = []
        self.cancel_origins: list[str] = []
        self.receipts: dict[str, dict[str, Any]] = {}
        #: What `node_attempts` answers with, so a test can stage the center's
        #: claim without a domain service behind it.
        self.node_attempts_served: list[dict[str, Any]] = []
        self.registered: list[NodeHello] = []
        self.disconnected: list[str] = []
        self.node_messages: list[tuple[str, Envelope]] = []
        self.node_enqueues: dict[str, Callable[[Envelope], None]] = {}
        self.replies: list[Envelope] = []
        self.ticks: list[tuple[str, Envelope]] = []
        self.handle_calls = 0
        self.poll_calls = 0
        self.handle_hook: Callable[[str, Envelope], list[Envelope]] | None = None
        #: key_id -> (public key object, the credential it authenticates).
        #: Populated by `add_signing_key`; empty means every signature is
        #: unknown, which is the fail-closed default.
        self.signing_keys: dict[str, tuple[Any, Credential]] = {}
        #: When true, every signature is refused before any lookup. A test uses
        #: this to prove the transport fails closed when the domain rejects.
        self.reject_signatures = False
        #: The (key_id, payload) pairs the transport asked the domain to verify.
        #: A replay to another path shows up here as a payload whose path or
        #: body digest differs from the one that was signed.
        self.verified_payloads: list[tuple[str, dict[str, Any]]] = []

    def add_signing_key(
        self, key_id: str, credential: Credential, public_key_b64: str
    ) -> None:
        """Register a public key the stub will really verify signatures with."""
        self.signing_keys[key_id] = (
            Ed25519PublicKey.from_public_bytes(base64_decode(public_key_b64)),
            credential,
        )

    def admit_request(
        self,
        *,
        credential: Credential,
        idempotency_key: str,
        prompt: str,
        authorization: SignedRecord,
        model: str,
        max_charge_milli_credits: int,
        delivery_mode: str,
        max_attempts: int,
        deadline_ms: int,
        now: dt.datetime | None = None,
    ) -> _StubAdmitResult:
        """Record the call and hand back a deterministic request id."""
        del now
        self.admissions.append(
            {
                "credential": credential,
                "idempotency_key": idempotency_key,
                "prompt": prompt,
                "authorization": authorization,
                "model": model,
                "max_charge_milli_credits": max_charge_milli_credits,
                "delivery_mode": delivery_mode,
                "max_attempts": max_attempts,
                "deadline_ms": deadline_ms,
            }
        )
        return _StubAdmitResult(request_id=f"req-{len(self.admissions)}")

    def request_status(self, *, credential: Credential, request_id: str) -> dict[str, Any]:
        """Return a status document, or raise for an unknown request."""
        if request_id not in self.statuses:
            raise ConflictError(f"no request {request_id}")
        return {
            "request_id": request_id,
            "tenant_id": credential.tenant_id,
            "status": self.statuses[request_id],
        }

    def request_events(
        self, *, credential: Credential, request_id: str, cursor: int, limit: int = 256
    ) -> list[StoredEvent]:
        """Return stored events after `cursor`."""
        self.poll_calls += 1
        if request_id not in self.statuses:
            raise ConflictError(f"no request {request_id}")
        return [event for event in self.events.get(request_id, []) if event.cursor > cursor][
            :limit
        ]

    def cancel_request(
        self,
        *,
        credential: Credential,
        request_id: str,
        origin: str,
        now: dt.datetime | None = None,
    ) -> dict[str, Any]:
        """Record the origin and report a cancellation."""
        del credential, now
        self.cancel_origins.append(origin)
        return {"request_id": request_id, "status": "CANCELLED", "origin": origin}

    def receipt_for(self, *, credential: Credential, receipt_id: str) -> dict[str, Any]:
        """Return a stored receipt."""
        del credential
        if receipt_id not in self.receipts:
            raise ConflictError(f"no receipt {receipt_id}")
        return self.receipts[receipt_id]

    def checkpoint(
        self, *, credential: Credential, now: dt.datetime | None = None
    ) -> dict[str, Any]:
        """Return a fixed checkpoint."""
        del credential, now
        return {"log_index": None, "signature": "stub-checkpoint"}

    def account_history(self, *, credential: Credential) -> dict[str, Any]:
        """Return the caller's own account history.

        The account is derived from the credential the transport resolved, which
        is the property under test: the request names no account, so the stub
        cannot be talked into answering about another one.
        """
        return {
            "account_id": credential.account_id or credential.subject_id,
            "entry_count": 0,
            "entries": [],
            "receipt_ids": [],
        }

    def node_attempts(self, *, credential: Credential) -> dict[str, Any]:
        """Return the attempts the center dispatched to the calling node."""
        return {
            "node_ids": [credential.subject_id],
            "attempts": self.node_attempts_served,
        }

    def register_node(
        self,
        *,
        credential: Credential,
        hello: NodeHello,
        enqueue: Callable[[Envelope], None],
        now: dt.datetime | None = None,
    ) -> None:
        """Record the node and answer its hello on the given sink."""
        del credential, now
        self.registered.append(hello)
        self.node_enqueues[hello.node_id] = enqueue
        enqueue(
            Envelope(
                type="hello.ack",
                payload=HelloAck(
                    node_id=hello.node_id, server_time=NOW, heartbeat_interval_s=5
                ).to_payload(),
            )
        )

    def node_disconnected(self, *, node_id: str, now: dt.datetime | None = None) -> None:
        """Record the disconnection."""
        del now
        self.disconnected.append(node_id)
        self.node_enqueues.pop(node_id, None)

    def handle_node_message(
        self, *, node_id: str, envelope: Envelope, now: dt.datetime | None = None
    ) -> list[Envelope]:
        """Record the message and return either the hook's or the canned replies."""
        del now
        self.node_messages.append((node_id, envelope))
        self.handle_calls += 1
        if self.handle_hook is not None:
            return self.handle_hook(node_id, envelope)
        return list(self.replies)

    def tick(self, *, now: dt.datetime | None = None) -> list[tuple[str, Envelope]]:
        """Hand over, and clear, the queued tick deliveries."""
        del now
        pending = list(self.ticks)
        self.ticks.clear()
        return pending

    def join(
        self,
        *,
        invite_code: str,
        identity: dict[str, Any],
        device: dict[str, Any] | None,
        center_url: str,
        now: dt.datetime | None = None,
    ) -> Any:
        """Record a join and return a minimal result the transport can render."""
        del now
        self.joins.append(
            {
                "invite_code": invite_code,
                "identity": identity,
                "device": device,
                "center_url": center_url,
            }
        )
        return _StubJoinResult(
            tenant_id=str(identity.get("subject_id", "")),
            subject_id=str(identity.get("subject_id", "")),
            role="consumer",
            key_id=str(identity.get("key_id", "")),
            center_url=center_url,
        )

    def authenticate_signed_request(
        self,
        *,
        payload: dict[str, Any],
        key_id: str,
        issued_at: dt.datetime,
        nonce: str,
        signature_b64: str,
        now: dt.datetime | None = None,
    ) -> Credential:
        """Verify a real signature over the payload the transport rebuilt.

        Unlike the previous stub, this actually checks the signature against a
        registered public key. That is what makes a transport-layer replay test
        meaningful: the payload the transport rebuilds from the *actual*
        method, path, query and body digest is what is signed, so a signature
        minted for one call does not verify for another.
        """
        del issued_at, nonce, now
        self.verified_payloads.append((key_id, dict(payload)))
        if self.reject_signatures:
            raise SignatureError("the stub was told to reject every signature")
        entry = self.signing_keys.get(key_id)
        if entry is None:
            raise UnknownKeyError(f"key {key_id!r} is not registered in the stub")
        public_key, credential = entry
        if not verify_payload(
            DOMAIN_REQUEST_AUTH, dict(payload), signature_b64, public_key
        ):
            raise SignatureError(f"the signature does not verify for {key_id!r}")
        return credential


# --------------------------------------------------------------------------- #
# Builders and HTTP helpers
# --------------------------------------------------------------------------- #


def _authorization_record() -> dict[str, Any]:
    """A signed authorization as it arrives in a request body."""
    return {
        "schema": "aipotluck.authorization.v1",
        "record_id": "auth-1",
        "revision": 1,
        "signed_at": NOW.isoformat(),
        "signer_key_id": "consumer-key-1",
        "signer_id": "consumer-a",
        "signature": "c2lnbmF0dXJl",
        "payload": {
            "authorization_id": "auth-1",
            "payer_account_id": "account-a",
            "consumer_id": "consumer-a",
            "max_charge_milli_credits": "1000",
        },
        "previous_record_hash": None,
    }


def _admission_body() -> dict[str, Any]:
    """A complete ``POST /v1/requests`` body."""
    return {
        "idempotency_key": "idem-1",
        "prompt": "hello",
        "model": "model-a",
        "max_charge_milli_credits": 100,
        "delivery_mode": "buffered_complete",
        "max_attempts": 1,
        "deadline_ms": 60_000,
        "authorization": _authorization_record(),
    }


def _stored_event(request_id: str, cursor: int, *, text: str = "delta") -> StoredEvent:
    """One stored event with a deterministic cursor."""
    return StoredEvent(
        cursor=cursor,
        request_id=request_id,
        attempt_id="att-1",
        attempt_seq=cursor,
        event_type="output.delta",
        payload={"text": text},
        created_at=NOW,
    )


def _hello_envelope(node_id: str) -> Envelope:
    """A well-formed `node.hello`."""
    return Envelope(
        type="node.hello",
        payload=NodeHello(
            node_id=node_id,
            device_id="device-a",
            device_key_id="device-key-a",
            provider_id="provider-a",
            adapter_name="fake",
            model="model-a",
            policy=NodePolicy(
                share_enabled=True,
                max_concurrency=1,
                max_local_reserved_milli_credits=1000,
            ),
        ).to_payload(),
    )


def _node_event_envelope() -> Envelope:
    """A well-formed `attempt.event` from a node."""
    return Envelope(
        type="attempt.event",
        payload={
            "request_id": "req-slow",
            "attempt_id": "att-1",
            "epoch": 1,
            "seq": 1,
            "event_type": "output.delta",
            "text": "hi",
        },
    )


@dataclass
class _Response:
    """A fully read HTTP response."""

    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> dict[str, Any]:
        """Decode the body as JSON."""
        decoded = json.loads(self.body)
        assert isinstance(decoded, dict)
        return decoded


def _port(server: GatewayServer) -> int:
    """The real bound port, read back from the server's own URL."""
    parts = urllib.parse.urlsplit(server.url)
    assert parts.port is not None
    return parts.port


def _http(
    server: GatewayServer,
    method: str,
    path: str,
    *,
    token: str | None = CONSUMER_TOKEN,
    body: dict[str, Any] | str | bytes | None = None,
    headers: dict[str, str] | None = None,
) -> _Response:
    """Send one request over loopback and read the whole answer."""
    connection = http.client.HTTPConnection("127.0.0.1", _port(server), timeout=10)
    request_headers = dict(headers or {})
    if token is not None:
        request_headers["Authorization"] = f"Bearer {token}"
    payload: bytes | None
    if isinstance(body, dict):
        payload = json.dumps(body).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    elif isinstance(body, str):
        payload = body.encode("utf-8")
    else:
        payload = body
    try:
        connection.request(method, path, body=payload, headers=request_headers)
        response = connection.getresponse()
        return _Response(
            status=response.status,
            headers={name.lower(): value for name, value in response.getheaders()},
            body=response.read(),
        )
    finally:
        connection.close()


def _head_status(head: bytes) -> int:
    """Parse the status code out of an HTTP response head."""
    return int(head.split(b"\r\n", 1)[0].split(b" ")[1])


def _content_length(head: bytes) -> int:
    """Parse Content-Length out of an HTTP response head."""
    for raw in head.split(b"\r\n")[1:]:
        name, _, value = raw.partition(b":")
        if name.strip().lower() == b"content-length":
            return int(value.strip())
    raise AssertionError(f"no Content-Length in response head: {head!r}")


def _raw_exchange(port: int, request: bytes) -> tuple[int, bytes]:
    """Send bytes to the gateway and read a response delimited by Content-Length."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.settimeout(10)
        sock.sendall(request)
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buffer += chunk
        head, _, body = buffer.partition(b"\r\n\r\n")
        expected = _content_length(head)
        while len(body) < expected:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body += chunk
        return _head_status(head), body


# --------------------------------------------------------------------------- #
# SSE helpers
# --------------------------------------------------------------------------- #


@dataclass
class _SseClient:
    """An open SSE stream read through `http.client`."""

    connection: http.client.HTTPConnection
    response: http.client.HTTPResponse

    def read_event(self) -> dict[str, str] | None:
        """Read one SSE frame, returning `None` at end of stream."""
        fields: dict[str, str] = {}
        while True:
            line = self.response.readline()
            if line == b"":
                return None
            text = line.decode("utf-8").rstrip("\n")
            if text == "":
                if fields:
                    return fields
                continue
            if text.startswith(":"):
                fields["comment"] = text
                continue
            name, separator, value = text.partition(": ")
            assert separator == ": ", f"malformed SSE line: {text!r}"
            fields[name] = value

    def close(self) -> None:
        """Drop the stream for real.

        `HTTPConnection.close` alone is not enough: the response holds a
        `makefile` duplicate of the socket, so the file descriptor stays open
        and no FIN is ever sent. Closing the response first is what makes this a
        disconnect the gateway can actually observe.
        """
        self.response.close()
        self.connection.close()


def _sse_open(
    server: GatewayServer,
    request_id: str,
    *,
    cursor: int = 0,
    token: str = CONSUMER_TOKEN,
    timeout: float = 10.0,
) -> _SseClient:
    """Open an SSE stream and read its response head."""
    connection = http.client.HTTPConnection("127.0.0.1", _port(server), timeout=timeout)
    connection.request(
        "GET",
        f"/v1/requests/{request_id}/events?cursor={cursor}",
        headers={"Authorization": f"Bearer {token}"},
    )
    response = connection.getresponse()
    return _SseClient(connection, response)


@dataclass
class _StalledConsumer:
    """An SSE peer that reads its response head and then never reads again."""

    sock: socket.socket
    head_status: int

    @classmethod
    def open(
        cls, server: GatewayServer, request_id: str, *, token: str = CONSUMER_TOKEN
    ) -> _StalledConsumer:
        """Connect, send the request, read only the head, and stall."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        sock.settimeout(10)
        sock.connect(("127.0.0.1", _port(server)))
        request = (
            f"GET /v1/requests/{request_id}/events?cursor=0 HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\n"
            f"Authorization: Bearer {token}\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode("ascii"))
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buffer += chunk
        head, _, _ = buffer.partition(b"\r\n\r\n")
        return cls(sock=sock, head_status=_head_status(head))

    def drain(self, timeout: float) -> tuple[bool, bytes]:
        """Read until the gateway closes the socket, returning what arrived.

        Args:
            timeout: Seconds to keep waiting before giving up.

        Returns:
            ``(closed, received)``; `closed` is True when the gateway's socket
            ended rather than the deadline passing.
        """
        deadline = time.monotonic() + timeout
        self.sock.settimeout(0.2)
        chunks: list[bytes] = []
        while time.monotonic() < deadline:
            try:
                chunk = self.sock.recv(65536)
            except TimeoutError:
                continue
            except OSError:
                return True, b"".join(chunks)
            if not chunk:
                return True, b"".join(chunks)
            chunks.append(chunk)
        return False, b"".join(chunks)

    def close(self) -> None:
        """Drop the socket."""
        self.sock.close()


@pytest.fixture
def gateway() -> Iterator[Callable[..., GatewayServer]]:
    """Return a factory that starts a gateway on an ephemeral loopback port."""
    servers: list[GatewayServer] = []

    def build(
        service: _StubService,
        *,
        config: GatewayConfig | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> GatewayServer:
        server = GatewayServer(
            service, config=config or GatewayConfig(port=0), ssl_context=ssl_context
        )
        server.start()
        servers.append(server)
        return server

    yield build
    for server in servers:
        server.stop()


# --------------------------------------------------------------------------- #
# 1. The endpoint table, 404, and 405 with Allow
# --------------------------------------------------------------------------- #


def test_every_contract_endpoint_is_routed(gateway: Callable[..., GatewayServer]) -> None:
    service = _StubService()
    service.statuses["req-1"] = "RUNNING"
    service.receipts["rcpt-1"] = {"receipt_id": "rcpt-1", "log_index": 0}
    server = gateway(service)

    health = _http(server, "GET", "/healthz", token=None)
    assert (health.status, health.json()) == (200, {"status": "ok"})

    created = _http(server, "POST", "/v1/requests", body=_admission_body())
    assert created.status == 200
    assert created.json() == {"request_id": "req-1"}

    status = _http(server, "GET", "/v1/requests/req-1")
    assert status.status == 200
    assert status.json()["status"] == "RUNNING"

    cancelled = _http(server, "POST", "/v1/requests/req-1/cancel")
    assert cancelled.status == 200
    # The origin must be the wire value the domain accepts. It used to be
    # "consumer", which the domain's `cancel_request` rejects as an unknown
    # origin, so the endpoint returned 400 and no cancellation ever reached a
    # node; this expectation pinned that defect. "consumer_cancel" is the value
    # `statemachine` and the ledger record, and it is what the stub now sees.
    assert service.cancel_origins == ["consumer_cancel"]

    receipt = _http(server, "GET", "/v1/receipts/rcpt-1")
    assert (receipt.status, receipt.json()) == (200, {"receipt_id": "rcpt-1", "log_index": 0})

    checkpoint = _http(server, "GET", "/v1/checkpoint")
    assert (checkpoint.status, checkpoint.json()) == (
        200,
        {"log_index": None, "signature": "stub-checkpoint"},
    )

    nodes = _http(server, "GET", "/v1/nodes")
    assert (nodes.status, nodes.json()) == (200, {"nodes": []})

    # The two read-only reconciliation endpoints. Neither takes an id: the
    # account and the node are the credential's own, so the transport has no
    # parameter to hand the service and the domain cannot be pointed elsewhere.
    history = _http(server, "GET", "/v1/account/history")
    assert (history.status, history.json()) == (
        200,
        {
            "account_id": "consumer-a",
            "entry_count": 0,
            "entries": [],
            "receipt_ids": [],
        },
    )

    attempts = _http(server, "GET", "/v1/node/attempts", token=NODE_TOKEN)
    assert (attempts.status, attempts.json()) == (
        200,
        {"node_ids": ["node-a"], "attempts": []},
    )

    stream = _sse_open(server, "req-1")
    assert stream.response.status == 200
    stream.close()

    link = _http(
        server, "GET", "/v1/node-link", token=NODE_TOKEN, headers={"Upgrade": "websocket"}
    )
    assert link.status == 400
    assert link.json()["error"] == "handshake_refused"


def test_unknown_paths_are_404_and_known_paths_with_a_wrong_method_are_405(
    gateway: Callable[..., GatewayServer],
) -> None:
    server = gateway(_StubService())
    assert _http(server, "GET", "/nope").status == 404
    assert _http(server, "POST", "/nope").status == 404
    assert _http(server, "GET", "/v1/requests/req-1/unknown").status == 404
    assert _http(server, "GET", "/v1/receipts").status == 404

    create_with_get = _http(server, "GET", "/v1/requests")
    assert create_with_get.status == 405
    assert create_with_get.headers["allow"] == "POST"
    assert create_with_get.json()["error"] == "method_not_allowed"

    health_with_post = _http(server, "POST", "/healthz", token=None)
    assert health_with_post.status == 405
    assert health_with_post.headers["allow"] == "GET"

    cancel_with_get = _http(server, "GET", "/v1/requests/req-1/cancel")
    assert cancel_with_get.status == 405
    assert cancel_with_get.headers["allow"] == "POST"

    stream_with_post = _http(server, "POST", "/v1/requests/req-1/events")
    assert stream_with_post.status == 405
    assert stream_with_post.headers["allow"] == "GET"

    history_with_post = _http(server, "POST", "/v1/account/history")
    assert history_with_post.status == 405
    assert history_with_post.headers["allow"] == "GET"

    attempts_with_post = _http(server, "POST", "/v1/node/attempts", token=NODE_TOKEN)
    assert attempts_with_post.status == 405
    assert attempts_with_post.headers["allow"] == "GET"


# --------------------------------------------------------------------------- #
# 2. Authentication and the token's containment
# --------------------------------------------------------------------------- #


def test_unknown_and_missing_tokens_are_401_without_echoing_the_token(
    gateway: Callable[..., GatewayServer], capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "unknown-token-that-must-never-be-echoed"
    service = _StubService()
    server = gateway(service)

    missing = _http(server, "GET", "/v1/requests/req-1", token=None)
    assert missing.status == 401
    assert missing.json()["error"] == "unauthorized"

    unknown = _http(server, "GET", "/v1/requests/req-1", token=secret)
    assert unknown.status == 401
    assert unknown.json()["error"] == "unauthorized"
    assert secret.encode() not in unknown.body
    assert service.store.resolutions == [secret]

    unreachable = _http(server, "GET", "/no/such/path", token=secret)
    assert unreachable.status == 404
    assert secret.encode() not in unreachable.body

    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err


def test_a_consumer_token_is_403_on_the_node_link_and_the_body_hides_it(
    gateway: Callable[..., GatewayServer],
) -> None:
    server = gateway(_StubService())
    refused = _http(
        server,
        "GET",
        "/v1/node-link",
        token=CONSUMER_TOKEN,
        headers={"Upgrade": "websocket", "Connection": "Upgrade"},
    )
    assert refused.status == 403
    assert refused.json()["error"] == "forbidden"
    assert CONSUMER_TOKEN.encode() not in refused.body


def test_a_node_token_is_403_on_consumer_endpoints(
    gateway: Callable[..., GatewayServer],
) -> None:
    server = gateway(_StubService())
    refused = _http(server, "GET", "/v1/requests/req-1", token=NODE_TOKEN)
    assert refused.status == 403
    assert refused.json()["detail"] == "this endpoint requires the consumer role"


def test_a_node_token_is_403_on_the_account_history_endpoint(
    gateway: Callable[..., GatewayServer],
) -> None:
    """A consumer's own books are not a node resource.

    The endpoint carries no account id, so the only thing standing between a
    node credential and a consumer's statement is this role check.
    """
    server = gateway(_StubService())
    refused = _http(server, "GET", "/v1/account/history", token=NODE_TOKEN)
    assert refused.status == 403
    assert refused.json()["detail"] == "this endpoint requires the consumer role"
    assert NODE_TOKEN.encode() not in refused.body


def test_a_consumer_token_is_403_on_the_node_attempts_endpoint(
    gateway: Callable[..., GatewayServer],
) -> None:
    """A node's dispatch history is not a consumer resource.

    The attempts it lists name requests other consumers paid for, so a consumer
    credential must not reach them through the reconciliation endpoint even
    though it can read its own requests one at a time.
    """
    server = gateway(_StubService())
    refused = _http(server, "GET", "/v1/node/attempts", token=CONSUMER_TOKEN)
    assert refused.status == 403
    assert refused.json()["detail"] == "this endpoint requires the node role"
    assert CONSUMER_TOKEN.encode() not in refused.body


def test_the_reconciliation_endpoints_are_401_without_a_usable_credential(
    gateway: Callable[..., GatewayServer],
) -> None:
    """Neither read-only endpoint is public, and neither echoes what was sent.

    Reconciliation reads money movements, so an unauthenticated caller must get
    the same constant ``401`` every other endpoint gives: no distinction between
    "no credential" and "unknown credential", which is what would otherwise let
    a caller probe which tokens exist.
    """
    server = gateway(_StubService())
    secret = "unknown-token-that-must-never-be-echoed"
    for path in ("/v1/account/history", "/v1/node/attempts"):
        missing = _http(server, "GET", path, token=None)
        assert missing.status == 401
        assert missing.json()["error"] == "unauthorized"

        unknown = _http(server, "GET", path, token=secret)
        assert unknown.status == 401
        assert unknown.json()["error"] == "unauthorized"
        assert secret.encode() not in unknown.body


def test_a_signature_with_the_node_role_is_403_on_the_account_history_endpoint(
    gateway: Callable[..., GatewayServer],
) -> None:
    """The signed path reaches the same role check as the bearer path.

    A credential that authenticates is not a credential that is allowed: both
    schemes end at one role test, so the reconciliation endpoints cannot be
    reached by switching scheme.
    """
    service = _StubService()
    server = gateway(service)
    key_id, private = _new_signing_key(service, credential=NODE)
    header = _signature_header(
        private, key_id, method="GET", path="/v1/account/history"
    )

    refused = _http(
        server, "GET", "/v1/account/history", token=None,
        headers={"Authorization": f"AIPotluck-Sig {header}"},
    )
    assert refused.status == 403
    assert refused.json()["error"] == "forbidden"


def test_a_node_credential_cannot_name_the_node_it_reads(
    gateway: Callable[..., GatewayServer],
) -> None:
    """The node ids in the answer come from the credential, not from the request.

    There is no query parameter or path segment to put a node id in, so the only
    way this could go wrong is a service that read the request instead of the
    credential. A caller that tries anyway gets its own answer, unchanged.
    """
    service = _StubService()
    service.node_attempts_served = [{"attempt_id": "att-1"}]
    server = gateway(service)

    answer = _http(server, "GET", "/v1/node/attempts?node_id=someone-else", token=NODE_TOKEN)
    assert answer.status == 200
    assert answer.json() == {
        "node_ids": ["node-a"],
        "attempts": [{"attempt_id": "att-1"}],
    }


def test_a_node_reads_only_its_own_attempts_when_two_share_a_tenant(
    tmp_path: Path,
) -> None:
    """Node B's token does not reach node A's attempts, shared tenant or not.

    The stub above can only show that the transport forwards a credential; whose
    data that credential buys is the domain's decision, so this drives the real
    `GatewayService` over a real store and a real socket.

    Both nodes are invited into one concrete tenant, which is the shape the
    deployment runbook mints for a friends community: every member gets
    ``admin invite --tenant friends``. A tenant is a trust group for *admission*,
    not a licence to read each other's books, so scoping this endpoint by tenant
    would hand every contributor in the community every other contributor's
    dispatch history — attempt ids, states, token counts and the receipts they
    settled into — with nothing but their own valid node token. The scoping has
    to come from the credential the transport authenticated, which is why the
    join binds a node's link credential to the device it derived.
    """
    from conftest import Keyring

    from aipotluck_server.gateway_service import GatewayConfig as DomainGatewayConfig
    from aipotluck_server.gateway_service import GatewayService
    from aipotluck_server.persistence import CenterStore

    keyring = Keyring()
    database = tmp_path / "center.db"
    store = CenterStore.open(database)
    service = GatewayService(
        config=DomainGatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(database),
            platform_id="platform-1",
            settlement_key_id="settlement-key-1",
            settlement_private_key_b64=keyring.private_b64["settlement-key-1"],
        ),
        store=store,
        registry=keyring.registry,
        now=NOW,
    )
    server = GatewayServer(service, config=GatewayConfig(port=0))
    server.start()
    try:
        tokens: dict[str, str] = {}
        devices: dict[str, str] = {}
        for name in ("a", "b"):
            store.add_invite(
                f"code-node-{name}", "node", "friends",
                max_uses=1, created_at=NOW, quota_milli_credits=0,
            )
            node_public, _node_private = generate_key_pair()
            device_public, _device_private = generate_key_pair()
            joined = service.join(
                invite_code=f"code-node-{name}",
                identity={"public_key_b64": node_public},
                device={"public_key_b64": device_public},
                center_url="http://center.test",
                now=NOW,
            )
            assert joined.tenant_id == "friends", "both nodes must share one tenant"
            assert joined.node_token is not None and joined.device_id is not None
            store.create_request(
                request_id=f"req-{name}", tenant_id="friends", subject_id="consumer-a",
                idempotency_key=f"key-{name}", payload_digest="sha256:digest",
                delivery_mode="buffered_complete", max_attempts=2,
                service_unit_id=f"req-{name}", created_at=NOW,
            )
            store.upsert_attempt(
                attempt_id=f"att-{name}", request_id=f"req-{name}",
                node_id=joined.device_id, resource_id="coding-pool",
                provider_id=str(joined.provider_id), dispatch_epoch=1, at=NOW,
            )
            tokens[name] = str(joined.node_token)
            devices[name] = str(joined.device_id)
        assert devices["a"] != devices["b"]

        for name, other in (("a", "b"), ("b", "a")):
            answer = _http(server, "GET", "/v1/node/attempts", token=tokens[name])
            assert answer.status == 200
            document = answer.json()
            assert document["node_ids"] == [devices[name]]
            attempts = document["attempts"]
            assert isinstance(attempts, list)
            assert [item["attempt_id"] for item in attempts] == [f"att-{name}"]
            # Neither the other node's attempt nor its identity is rendered
            # anywhere in the answer, including a field this test does not read.
            assert f"att-{other}".encode() not in answer.body
            assert devices[other].encode() not in answer.body
    finally:
        server.stop()
        store.close()


def _signature_header(
    private_key: Any,
    key_id: str,
    *,
    method: str,
    path: str,
    query: str = "",
    body: bytes | None = None,
) -> str:
    """Build an ``AIPotluck-Sig`` header covering exactly this call."""
    issued_at = dt.datetime.now(dt.UTC)
    nonce = secrets.token_urlsafe(24)
    payload = request_auth_payload(
        method=method, path=path, query=query, body_digest=request_body_digest(body),
        key_id=key_id, issued_at=issued_at, nonce=nonce,
    )
    return format_request_auth_header(
        key_id=key_id, issued_at=issued_at, nonce=nonce,
        signature_b64=sign_payload(DOMAIN_REQUEST_AUTH, payload, private_key),
    )


def _new_signing_key(
    service: _StubService, *, credential: Credential = CONSUMER, key_id: str = "sig-key-1"
) -> tuple[str, Any]:
    """Register a fresh key pair in the stub and return ``(key_id, private_key)``."""
    public_b64, private_b64 = generate_key_pair()
    service.add_signing_key(key_id, credential, public_b64)
    return key_id, load_private_key(private_b64)


def test_a_signature_for_one_path_does_not_authorise_another(
    gateway: Callable[..., GatewayServer],
) -> None:
    """A signature is bound to the request line; replaying it elsewhere is 401."""
    service = _StubService()
    service.statuses["req-1"] = "RUNNING"
    server = gateway(service)
    key_id, private = _new_signing_key(service)
    header = _signature_header(private, key_id, method="GET", path="/v1/requests/req-1")

    # The signature works for the path it signed.
    accepted = _http(
        server, "GET", "/v1/requests/req-1", token=None,
        headers={"Authorization": f"AIPotluck-Sig {header}"},
    )
    assert accepted.status == 200

    # The identical header presented at a different path must not verify.
    replay = _http(
        server, "GET", "/v1/checkpoint", token=None,
        headers={"Authorization": f"AIPotluck-Sig {header}"},
    )
    assert replay.status == 401
    assert replay.json()["error"] == "unauthorized"


def test_a_signature_is_bound_to_the_body_it_signed(
    gateway: Callable[..., GatewayServer],
) -> None:
    """Swapping the body under a valid signature is 401, not a free ride."""
    service = _StubService()
    server = gateway(service)
    key_id, private = _new_signing_key(service)
    original = json.dumps(_admission_body()).encode("utf-8")
    header = _signature_header(
        private, key_id, method="POST", path="/v1/requests", body=original
    )

    changed = _admission_body()
    changed["prompt"] = "a prompt nobody signed for"
    swapped = _http(
        server, "POST", "/v1/requests", token=None, body=changed,
        headers={"Authorization": f"AIPotluck-Sig {header}"},
    )
    assert swapped.status == 401
    assert swapped.json()["error"] == "unauthorized"


def test_a_valid_signature_with_the_wrong_role_is_403(
    gateway: Callable[..., GatewayServer],
) -> None:
    """A signature authenticates, but the endpoint still checks the role."""
    service = _StubService()
    server = gateway(service)
    key_id, private = _new_signing_key(service, credential=NODE)
    header = _signature_header(private, key_id, method="GET", path="/v1/requests/req-1")

    refused = _http(
        server, "GET", "/v1/requests/req-1", token=None,
        headers={"Authorization": f"AIPotluck-Sig {header}"},
    )
    assert refused.status == 403
    assert refused.json()["error"] == "forbidden"


def test_the_transport_fails_closed_when_the_domain_rejects(
    gateway: Callable[..., GatewayServer],
) -> None:
    """When the domain refuses a signature, the transport answers a bare 401."""
    service = _StubService()
    server = gateway(service)
    key_id, private = _new_signing_key(service)
    service.reject_signatures = True
    header = _signature_header(private, key_id, method="GET", path="/v1/requests/req-1")

    refused = _http(
        server, "GET", "/v1/requests/req-1", token=None,
        headers={"Authorization": f"AIPotluck-Sig {header}"},
    )
    assert refused.status == 401
    assert header.encode() not in refused.body


# --------------------------------------------------------------------------- #
# 3. A body can never name its own identity
# --------------------------------------------------------------------------- #


def test_a_body_claiming_another_tenant_does_not_change_the_credential(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    server = gateway(service)
    body = _admission_body()
    body["tenant_id"] = "tenant-b"
    body["subject_id"] = "consumer-b"
    body["payer_account_id"] = "account-b"

    assert _http(server, "POST", "/v1/requests", body=body).status == 200

    recorded = service.admissions[0]
    assert recorded["credential"] is CONSUMER
    assert recorded["credential"].tenant_id == "tenant-a"
    assert recorded["credential"].subject_id == "consumer-a"
    assert recorded["idempotency_key"] == "idem-1"
    assert recorded["authorization"].payload["payer_account_id"] == "account-a"
    assert service.store.resolutions == [CONSUMER_TOKEN]


def test_a_foreign_tenants_token_still_reads_only_through_that_tenant(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    service.statuses["req-1"] = "RUNNING"
    server = gateway(service)
    status = _http(server, "GET", "/v1/requests/req-1", token=FOREIGN_TOKEN)
    assert status.status == 200
    assert status.json()["tenant_id"] == "tenant-b"


# --------------------------------------------------------------------------- #
# 4. Body refusals at the boundary
# --------------------------------------------------------------------------- #


def test_a_float_in_the_body_is_400(gateway: Callable[..., GatewayServer]) -> None:
    server = gateway(_StubService())
    body = _admission_body()
    body["max_charge_milli_credits"] = 1.5
    refused = _http(server, "POST", "/v1/requests", body=body)
    assert refused.status == 400
    assert refused.json()["error"] == "bad_request"
    assert "fractional number" in refused.json()["detail"]


def test_a_duplicate_key_in_the_body_is_400(gateway: Callable[..., GatewayServer]) -> None:
    server = gateway(_StubService())
    raw = (
        '{"idempotency_key": "a", "idempotency_key": "b", "prompt": "p", "model": "m",'
        ' "max_charge_milli_credits": 1, "delivery_mode": "buffered_complete",'
        ' "max_attempts": 1, "deadline_ms": 1, "authorization": {}}'
    )
    refused = _http(server, "POST", "/v1/requests", body=raw)
    assert refused.status == 400
    assert "duplicate JSON key" in refused.json()["detail"]


def test_an_oversized_declared_body_is_refused_before_it_is_read(
    gateway: Callable[..., GatewayServer],
) -> None:
    server = gateway(_StubService())
    request = (
        f"POST /v1/requests HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        f"Authorization: Bearer {CONSUMER_TOKEN}\r\n"
        f"Content-Length: {OVERSIZE_BYTES + 1}\r\n\r\n"
        '{"prompt": "small"}'
    )
    status, body = _raw_exchange(_port(server), request.encode("ascii"))
    assert status == 400
    assert json.loads(body)["error"] == "payload_too_large"


def test_an_oversized_undeclared_body_is_refused_after_the_cap(
    gateway: Callable[..., GatewayServer],
) -> None:
    server = gateway(_StubService())
    head = (
        f"POST /v1/requests HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        f"Authorization: Bearer {CONSUMER_TOKEN}\r\n\r\n"
    ).encode("ascii")
    status, body = _raw_exchange(_port(server), head + b"x" * (OVERSIZE_BYTES + 1))
    assert status == 400
    assert json.loads(body)["error"] == "payload_too_large"


def test_a_body_that_is_not_an_object_is_400(gateway: Callable[..., GatewayServer]) -> None:
    server = gateway(_StubService())
    refused = _http(server, "POST", "/v1/requests", body="[1, 2, 3]")
    assert refused.status == 400
    assert refused.json()["detail"] == "the body must be a JSON object"


def test_a_bad_cursor_is_400(gateway: Callable[..., GatewayServer]) -> None:
    service = _StubService()
    service.statuses["req-1"] = "RUNNING"
    server = gateway(service)
    assert _http(server, "GET", "/v1/requests/req-1/events?cursor=-1").status == 400
    assert _http(server, "GET", "/v1/requests/req-1/events?cursor=x").status == 400
    assert _http(server, "GET", "/v1/requests/req-1/events?cursor=1&cursor=2").status == 400


def test_an_unknown_request_is_409_from_the_domain_conflict(
    gateway: Callable[..., GatewayServer],
) -> None:
    # The domain reports an unknown request as a ConflictError; the transport's
    # job is to map it faithfully rather than to invent a status of its own.
    server = gateway(_StubService())
    refused = _http(server, "GET", "/v1/requests/req-missing")
    assert refused.status == 409
    assert refused.json()["error"] == "conflict"


# --------------------------------------------------------------------------- #
# 5. SSE: ordering, replay, live tail, and a resume with no gap
# --------------------------------------------------------------------------- #


def test_sse_streams_the_contract_headers(gateway: Callable[..., GatewayServer]) -> None:
    service = _StubService()
    service.statuses["req-s"] = "RUNNING"
    server = gateway(service)
    stream = _sse_open(server, "req-s")
    try:
        assert stream.response.status == 200
        assert stream.response.getheader("Content-Type") == "text/event-stream"
        assert stream.response.getheader("Cache-Control") == "no-cache"
        assert stream.response.getheader("Content-Length") is None
        assert stream.response.getheader("Connection") == "close"
    finally:
        stream.close()


def test_sse_replays_then_streams_live_and_resumes_without_gap_or_duplicate(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    service.statuses["req-s"] = "RUNNING"
    service.events["req-s"] = [
        _stored_event("req-s", 1, text="a"),
        _stored_event("req-s", 2, text="b"),
    ]
    server = gateway(service)

    first = _sse_open(server, "req-s", cursor=0)
    event_one = first.read_event()
    event_two = first.read_event()
    assert event_one is not None
    assert event_two is not None
    assert (event_one["id"], event_one["event"]) == ("1", "output.delta")
    assert (event_two["id"], event_two["event"]) == ("2", "output.delta")
    assert json.loads(event_one["data"]) == {"text": "a"}
    # Disconnect mid-stream, before the request is terminal.
    first.close()

    service.events["req-s"].extend(
        [_stored_event("req-s", 3, text="c"), _stored_event("req-s", 4, text="d")]
    )
    service.statuses["req-s"] = "SUCCEEDED"

    second = _sse_open(server, "req-s", cursor=int(event_two["id"]))
    seen: list[int] = []
    while True:
        event = second.read_event()
        assert event is not None
        if event["event"] == "done":
            assert json.loads(event["data"]) == {
                "request_id": "req-s",
                "status": "SUCCEEDED",
            }
            break
        seen.append(int(event["id"]))
    second.close()

    assert seen == [3, 4]
    assert [int(event_one["id"]), int(event_two["id"]), *seen] == [1, 2, 3, 4]


def test_sse_delivers_new_events_appended_after_the_stream_is_open(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    service.statuses["req-s"] = "RUNNING"
    server = gateway(service)
    stream = _sse_open(server, "req-s")
    try:
        service.events["req-s"] = [_stored_event("req-s", 1, text="late")]
        event = stream.read_event()
        assert event is not None
        assert (event["id"], json.loads(event["data"])) == ("1", {"text": "late"})
    finally:
        stream.close()


def test_an_abandoned_stream_stops_being_polled(gateway: Callable[..., GatewayServer]) -> None:
    service = _StubService()
    service.statuses["req-s"] = "RUNNING"
    server = gateway(service)
    stream = _sse_open(server, "req-s")
    time.sleep(0.4)
    stream.close()

    # The request stays RUNNING forever, so only the peer's departure can stop
    # the producer. Wait for the poll count to stop moving on its own.
    stopped_at: int | None = None
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        time.sleep(0.2)
        before = service.poll_calls
        time.sleep(0.7)
        if service.poll_calls == before:
            stopped_at = before
            break
    assert stopped_at is not None, "the producer polled a dead stream until the deadline"
    assert stopped_at < 10


def test_sse_emits_a_heartbeat_comment_when_idle(gateway: Callable[..., GatewayServer]) -> None:
    service = _StubService()
    service.statuses["req-s"] = "RUNNING"
    server = gateway(service)
    server.tuning = replace(server.tuning, sse_heartbeat_interval_s=0.05)
    stream = _sse_open(server, "req-s")
    try:
        frame = stream.read_event()
        assert frame == {"comment": ":"}
    finally:
        stream.close()


def test_sse_ends_with_done_when_the_request_is_already_terminal(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    service.statuses["req-s"] = "FAILED"
    service.events["req-s"] = [_stored_event("req-s", 1, text="x")]
    server = gateway(service)
    stream = _sse_open(server, "req-s")
    try:
        first = stream.read_event()
        assert first is not None
        assert first["id"] == "1"
        done = stream.read_event()
        assert done is not None
        assert done["event"] == "done"
        assert json.loads(done["data"])["status"] == "FAILED"
    finally:
        stream.close()


# --------------------------------------------------------------------------- #
# 6. A stalled consumer cannot delay settlement or another stream
# --------------------------------------------------------------------------- #


def test_a_stalled_consumer_does_not_delay_settlement_or_another_stream(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    service.statuses["req-slow"] = "RUNNING"
    service.statuses["req-ok"] = "RUNNING"
    # Large frames, and more of them than any socket buffer can absorb, so the
    # stalled peer's writer is blocked in the kernel while its buffer fills.
    service.events["req-slow"] = [
        _stored_event("req-slow", cursor, text="s" * 16_384) for cursor in range(1, 257)
    ]
    service.events["req-ok"] = [_stored_event("req-ok", 1, text="ok")]

    def on_handle(node_id: str, envelope: Envelope) -> list[Envelope]:
        assert node_id == "node-1"
        service.events["req-ok"].append(_stored_event("req-ok", 2, text="from-node"))
        return [
            Envelope(type="event.ack", payload={"attempt_id": "att-1", "acked_seq": 1})
        ]

    service.handle_hook = on_handle
    server = gateway(service)

    stalled = _StalledConsumer.open(server, "req-slow")
    healthy = _sse_open(server, "req-ok")
    node = ClientConnection.connect(
        server.node_url, headers={"Authorization": f"Bearer {NODE_TOKEN}"}
    )
    try:
        assert stalled.head_status == 200
        assert healthy.response.status == 200
        first = healthy.read_event()
        assert first is not None
        assert first["id"] == "1"

        node.send_text(_hello_envelope("node-1").encode())
        assert Envelope.decode(node.recv_text(timeout=5.0)).type == "hello.ack"

        started = time.monotonic()
        node.send_text(_node_event_envelope().encode())
        ack = Envelope.decode(node.recv_text(timeout=10.0))
        elapsed = time.monotonic() - started

        # Settlement ran to completion while the stalled peer never read a byte.
        assert ack.type == "event.ack"
        assert elapsed < 5.0
        assert service.handle_calls == 1

        second = healthy.read_event()
        assert second is not None
        assert (second["id"], json.loads(second["data"])) == ("2", {"text": "from-node"})
    finally:
        node.close()
        healthy.close()

    # The stalled connection was dropped rather than left blocking the server,
    # and the peer was told why in a final frame it could read once it drained.
    try:
        closed, received = stalled.drain(10.0)
    finally:
        stalled.close()
    assert closed is True
    assert b"event: dropped" in received
    assert b'"reason":"the consumer is not reading fast enough"' in received
    # 256 events of 16 KiB were queued; the backlog was discarded rather than
    # delivered, so only what the socket buffer already held ever got through.
    assert len(received) < 1_000_000


# --------------------------------------------------------------------------- #
# 7. Node link: hello, round trip, and a first-message violation
# --------------------------------------------------------------------------- #


def test_node_link_round_trip_and_connected_node_count(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    service.replies = [Envelope(type="event.ack", payload={"attempt_id": "att-1", "acked_seq": 1})]
    server = gateway(service)
    assert server.connected_node_count == 0

    client = ClientConnection.connect(
        server.node_url, headers={"Authorization": f"Bearer {NODE_TOKEN}"}
    )
    assert server.connected_node_count == 0  # a link without a hello is not a node
    client.send_text(_hello_envelope("node-1").encode())
    ack = Envelope.decode(client.recv_text(timeout=5.0))
    assert ack.type == "hello.ack"
    assert ack.payload["node_id"] == "node-1"
    assert [hello.node_id for hello in service.registered] == ["node-1"]
    assert server.connected_node_count == 1

    client.send_text(_node_event_envelope().encode())
    reply = Envelope.decode(client.recv_text(timeout=5.0))
    assert reply.type == "event.ack"
    assert reply.payload == {"attempt_id": "att-1", "acked_seq": 1}
    assert [(node_id, envelope.type) for node_id, envelope in service.node_messages] == [
        ("node-1", "attempt.event")
    ]

    client.close()
    deadline = time.monotonic() + 5.0
    while server.connected_node_count != 0 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.connected_node_count == 0
    assert service.disconnected == ["node-1"]


def test_a_node_link_that_does_not_open_with_hello_is_told_and_closed(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    server = gateway(service)
    client = ClientConnection.connect(
        server.node_url, headers={"Authorization": f"Bearer {NODE_TOKEN}"}
    )
    try:
        client.send_text(
            Envelope(
                type="node.heartbeat",
                payload={"in_flight": 0, "share_enabled": True, "at": NOW.isoformat()},
            ).encode()
        )
        error = Envelope.decode(client.recv_text(timeout=5.0))
        assert error.type == "protocol.error"
        assert error.payload["code"] == "hello_required"

        with pytest.raises(WebSocketClosed) as raised:
            client.recv_text(timeout=5.0)
        assert raised.value.code == 1008
    finally:
        client.close()
    assert service.registered == []


def test_a_malformed_envelope_gets_a_protocol_error_and_the_link_survives(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    service.replies = [Envelope(type="event.ack", payload={"attempt_id": "att-1", "acked_seq": 1})]
    server = gateway(service)
    client = ClientConnection.connect(
        server.node_url, headers={"Authorization": f"Bearer {NODE_TOKEN}"}
    )
    try:
        client.send_text(_hello_envelope("node-1").encode())
        assert Envelope.decode(client.recv_text(timeout=5.0)).type == "hello.ack"

        client.send_text('{"schema": "aipotluck.envelope.v1", "type": "nonsense"}')
        error = Envelope.decode(client.recv_text(timeout=5.0))
        assert error.type == "protocol.error"
        assert error.payload["code"] == "malformed_message"

        # The link is still usable, so a bad message costs one round trip.
        client.send_text(_node_event_envelope().encode())
        assert Envelope.decode(client.recv_text(timeout=5.0)).type == "event.ack"
    finally:
        client.close()


def test_the_node_link_requires_a_node_token_over_a_real_handshake(
    gateway: Callable[..., GatewayServer],
) -> None:
    server = gateway(_StubService())
    with pytest.raises(WebSocketProtocolError, match="403"):
        ClientConnection.connect(
            server.node_url, headers={"Authorization": f"Bearer {CONSUMER_TOKEN}"}
        )


# --------------------------------------------------------------------------- #
# 7b. The ticker delivers to the node it names, and skips one that is gone
# --------------------------------------------------------------------------- #


def test_the_ticker_delivers_to_the_named_node_and_skips_a_missing_one(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    server = gateway(service)
    client = ClientConnection.connect(
        server.node_url, headers={"Authorization": f"Bearer {NODE_TOKEN}"}
    )
    try:
        client.send_text(_hello_envelope("node-1").encode())
        assert Envelope.decode(client.recv_text(timeout=5.0)).type == "hello.ack"

        service.ticks.append(("node-gone", Envelope(type="attempt.offer", payload={"n": 1})))
        service.ticks.append(("node-1", Envelope(type="attempt.offer", payload={"n": 2})))
        delivered = Envelope.decode(client.recv_text(timeout=5.0))
        assert delivered.type == "attempt.offer"
        assert delivered.payload == {"n": 2}
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# 8. Shutdown with a stalled consumer still connected
# --------------------------------------------------------------------------- #


def test_stop_returns_promptly_with_a_stalled_consumer_connected(
    gateway: Callable[..., GatewayServer],
) -> None:
    service = _StubService()
    service.statuses["req-slow"] = "RUNNING"
    service.events["req-slow"] = [
        _stored_event("req-slow", cursor, text="s" * 16_384) for cursor in range(1, 33)
    ]
    server = gateway(service)
    stalled = _StalledConsumer.open(server, "req-slow")
    try:
        assert stalled.head_status == 200
        assert server.connected_node_count == 0

        started = time.monotonic()
        server.stop()
        elapsed = time.monotonic() - started

        assert elapsed < 2.0
        closed, _ = stalled.drain(5.0)
        assert closed is True
    finally:
        stalled.close()


# --------------------------------------------------------------------------- #
# 9. TLS
# --------------------------------------------------------------------------- #


def test_tls_round_trip_over_https_and_wss(gateway: Callable[..., GatewayServer]) -> None:
    with tempfile.TemporaryDirectory() as directory:
        certificate, key = _write_self_signed_certificate(Path(directory))
        service = _StubService()
        server = gateway(
            service,
            config=GatewayConfig(host="localhost", port=0, certfile=certificate, keyfile=key),
        )
        assert server.url.startswith("https://")
        assert server.node_url == f"wss://localhost:{_port(server)}/v1/node-link"
        client_context = ssl.create_default_context(cafile=certificate)

        connection = http.client.HTTPSConnection(
            "localhost", _port(server), context=client_context, timeout=10
        )
        try:
            connection.request("GET", "/healthz")
            response = connection.getresponse()
            assert response.status == 200
            assert json.loads(response.read()) == {"status": "ok"}
        finally:
            connection.close()

        client = ClientConnection.connect(
            server.node_url,
            headers={"Authorization": f"Bearer {NODE_TOKEN}"},
            ssl_context=client_context,
        )
        try:
            client.send_text(_hello_envelope("node-tls").encode())
            ack = Envelope.decode(client.recv_text(timeout=5.0))
            assert ack.type == "hello.ack"
            assert [hello.node_id for hello in service.registered] == ["node-tls"]
        finally:
            client.close()


def test_an_explicit_ssl_context_is_used_when_the_config_names_no_certificate(
    gateway: Callable[..., GatewayServer],
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        certificate, key = _write_self_signed_certificate(Path(directory))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server = gateway(
            _StubService(),
            config=GatewayConfig(host="localhost", port=0),
            ssl_context=context,
        )
        assert server.node_url.startswith("wss://")
        client_context = ssl.create_default_context(cafile=certificate)
        connection = http.client.HTTPSConnection(
            "localhost", _port(server), context=client_context, timeout=10
        )
        try:
            connection.request("GET", "/healthz")
            assert connection.getresponse().status == 200
        finally:
            connection.close()


def test_a_half_configured_tls_pair_is_refused() -> None:
    service = _StubService()
    server = GatewayServer(
        service, config=GatewayConfig(port=0, certfile="/tmp/only-a-cert.pem")
    )
    with pytest.raises(ValueError, match="configured together"):
        server.start()


def test_url_is_unavailable_before_start() -> None:
    server = GatewayServer(_StubService(), config=GatewayConfig(port=0))
    with pytest.raises(RuntimeError, match="has not been started"):
        _ = server.url
    with pytest.raises(RuntimeError, match="has not been started"):
        _ = server.node_url


# --------------------------------------------------------------------------- #
# 10. The stub and the real service both satisfy the transport protocol
# --------------------------------------------------------------------------- #


def test_the_stub_registers_against_the_transport_protocol() -> None:
    assert isinstance(_StubService(), GatewayServiceProtocol)


def test_the_real_service_registers_against_the_transport_protocol() -> None:
    module = pytest.importorskip("aipotluck_server.gateway_service")
    candidates = [
        member
        for _, member in inspect.getmembers(module, inspect.isclass)
        if getattr(member, "admit_request", None) is not None
    ]
    if not candidates:
        pytest.skip("aipotluck_server.gateway_service defines no class with admit_request yet")
    assert len(candidates) == 1
    service_class = candidates[0]
    assert isinstance(service_class, GatewayServiceProtocol)
    for name in (
        "store",
        "log",
        "admit_request",
        "request_status",
        "request_events",
        "cancel_request",
        "receipt_for",
        "checkpoint",
        "register_node",
        "node_disconnected",
        "handle_node_message",
        "tick",
    ):
        assert hasattr(service_class, name), name


def _write_self_signed_certificate(directory: Path) -> tuple[str, str]:
    """Write a self-signed certificate and key for ``localhost`` into `directory`."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate_path = directory / "certificate.pem"
    key_path = directory / "key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    return str(certificate_path), str(key_path)
