"""HTTP/SSE/WebSocket transport for the center gateway.

This module is the *transport half* of the center: it terminates HTTPS for
consumers, serves the consumer event stream over SSE, and accepts the single
outbound WebSocket that each contribution node dials. It owns no domain
decision. It never decides whether a request may run, how much it costs, or
whether a receipt is valid; it parses bytes, checks credentials and roles,
calls exactly one service method per endpoint, and renders the answer.

Trust boundaries
----------------

* **Identity comes from the header, never from the body.** Two schemes are
  accepted. ``Authorization: Bearer <token>`` resolves through
  ``service.store.resolve_credential``; this is the node and administrator path,
  and the token is the credential store's business. ``Authorization:
  AIPotluck-Sig ...`` is a per-request signature that resolves through the
  service's trusted registry; it lets a consumer that joined with an invite
  authenticate with the key it holds. This module never reads the credential or
  identity tables itself and never treats a body field as an identity.
  ``tenant_id``, ``subject_id`` and ``payer_account_id`` in a request body are
  documented as ignored: a body that claims a foreign tenant is faithfully
  handed to the service under the credential the header resolved to.
* **``POST /v1/join`` is the one unauthenticated data endpoint**, because the
  invite code it carries *is* the credential. It is routed before the header
  check and its body is validated strictly; the domain `join` decides whether
  the code is usable. Only the joiner's public key is read from the body: the
  identity itself (subject, key id, tenant, device and provider ids) is derived
  by the server, so a body cannot name the identity it becomes.
* **The body is untrusted.** Every body is parsed with
  `canonical.loads_strict`, so floats, duplicate keys and ``NaN`` are refused at
  the boundary with a ``400`` rather than reaching domain code. Bodies are
  capped at `MAX_HTTP_BODY_BYTES` and refused, never truncated. Because a
  signature covers the body, a signed request's body is read once and buffered
  so the handler sees the same bytes the signature was checked against.
* **Material never leaves the connection.** A token and a signature are not
  echoed in a response body, not written to a log line, and not put into an
  exception message. The handler silences the access log entirely, and any
  detail rendered back is run through `_redact` with the presented material so a
  domain error that happened to quote it cannot leak it.
* **Fail closed.** A missing, unknown, revoked or unverifiable credential is
  ``401``; a credential with the wrong role is ``403``. The signature path's
  distinct reasons (unknown key, revoked key, bad signature, stale timestamp,
  spent nonce) are collapsed into the same ``401`` so the answer cannot be used
  to probe the registry.

Thread model
------------

* One accept loop, on a `http.server.ThreadingHTTPServer` serving in its own
  thread.
* One handler thread per HTTP connection, created by the server. The SSE
  handler thread owns the socket write side.
* Per SSE connection: one *producer* thread polls the service and offers
  rendered frames to a bounded outbound buffer; the handler thread drains that
  buffer onto the socket. A peer that stops reading fills the buffer, and the
  connection is dropped instead of blocking the producer, the settlement path,
  or any other connection.
* Per node link: the handler thread is the *reader* and one *writer* thread
  drains the connection's bounded outbound buffer. The reader never writes to
  the socket, so a node that stops reading cannot stall message handling;
  `websocket`'s separate read and write locks make that guarantee real, and
  `close()` wakes a blocked reader.
* One ticker thread for the whole server delivers `service.tick()` output to
  node queues, skipping nodes that have gone away.

Every bounded outbound buffer is a `_OutboundBuffer`; see its docstring for why
it is built on a condition variable rather than `queue.Queue`.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import http.server
import json
import logging
import secrets
import select
import socket
import ssl
import threading
import time
import urllib.parse
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Generic, Protocol, TypeVar, cast, runtime_checkable

from aipotluck.canonical import canonicalize, loads_strict
from aipotluck.errors import (
    AllocationError,
    CanonicalizationError,
    ConflictError,
    DelegationError,
    IdentityBindingError,
    InsufficientFundsError,
    KeyRevokedError,
    MeteringError,
    PotluckError,
    ProtocolError,
    SettlementError,
    SignatureError,
    StateTransitionError,
    UnknownKeyError,
    VerificationError,
)
from aipotluck.records import (
    SignedRecord,
    parse_request_auth_header,
    request_auth_payload,
    request_body_digest,
)
from aipotluck.statemachine import TERMINAL_REQUEST_STATES
from aipotluck.transparency import MerkleLog
from aipotluck.websocket import (
    HandshakeRefusal,
    ServerConnection,
    WebSocketError,
    WebSocketTimeout,
    handshake_server,
)
from aipotluck.wire import (
    SESSION_HEADER,
    ChatMessage,
    Envelope,
    NodeHello,
    check_session_id,
    encode_chat_parameters,
    error_envelope,
    parse_chat_messages,
)

from .errors import ApiKeyRateLimited, ApiKeyUnavailable, ModelUnavailable, QueueFull
from .persistence import ApiKeyRecord, CenterStore, Credential, NodeRecord, StoredEvent

logger = logging.getLogger(__name__)

#: How long an SSE connection waits between polls of the service.
DEFAULT_SSE_POLL_INTERVAL_S = 0.25

#: Outbound messages buffered for one node before the link is dropped.
DEFAULT_NODE_QUEUE_SIZE = 512

#: How long a node link blocks on a read before it checks whether to stop.
DEFAULT_READ_TIMEOUT_S = 30.0

#: Largest request body the gateway will read, in bytes.
MAX_HTTP_BODY_BYTES = 1024 * 1024

#: How long a closing connection spends discarding request bytes nobody read,
#: and waiting on a TLS peer's own `close_notify`. Short on purpose: this runs on
#: every connection the gateway ends, so it may not become a way for one peer to
#: hold a handler thread.
GRACEFUL_CLOSE_TIMEOUT_S = 0.5

#: How many still-incoming request bytes a closing connection discards before it
#: gives up and closes anyway. One full body: that is the most an honest peer can
#: still be sending, and a peer sending more has already been refused.
GRACEFUL_CLOSE_DRAIN_BYTES = MAX_HTTP_BODY_BYTES

#: Frames buffered for one SSE connection before it is dropped. Not part of the
#: frozen interface, but a named constant so the drop policy is one edit away
#: from being tuned, and so a test can shrink it deliberately.
SSE_QUEUE_SIZE = 64

#: Interval of the comment heartbeat that keeps a proxy from idling us out.
SSE_HEARTBEAT_INTERVAL_S = 15.0

#: How long a dropped SSE connection is given to flush its final frame before
#: its socket is torn down underneath the blocked writer.
SSE_DROP_GRACE_S = 2.0

#: How long the ticker sleeps between `service.tick()` calls.
_TICK_INTERVAL_S = 0.25

#: Events fetched from the store per SSE poll.
_SSE_REPLAY_BATCH = 256

#: How long a writer waits on an empty buffer before re-checking its stop flag.
_WRITER_POLL_S = 0.5

#: How long `stop()` waits, in total, for the threads it started.
_STOP_JOIN_TIMEOUT_S = 2.0

#: How long a node link waits for its writer to flush a final frame.
_WRITER_FLUSH_TIMEOUT_S = 5.0

#: How long a node link waits for its writer after the socket has been closed.
_WRITER_JOIN_TIMEOUT_S = 2.0

#: `serve_forever`'s poll interval, which bounds how fast `stop()` returns.
_SERVER_POLL_INTERVAL_S = 0.05

#: The close code a node link uses for a protocol violation it cannot recover
#: from, per RFC 6455 section 7.4.1 (policy violation).
_WS_POLICY_VIOLATION = 1008

#: The close code a node link uses when its outbound queue overflows: the peer
#: is asked to reconnect and resynchronise rather than slow the center down.
_WS_TRY_AGAIN_LATER = 1013

_T = TypeVar("_T")


@dataclass(frozen=True)
class GatewayConfig:
    """Where the gateway listens and how it terminates TLS.

    The gateway reads exactly these four attributes. The domain module's own
    `GatewayConfig` is accepted unchanged as long as it exposes the same names,
    which is why this dataclass is not imported from ``gateway_service``: a
    runtime import of that module would make this transport depend on the
    domain module it is supposed to be testable without, and a
    ``TYPE_CHECKING`` import would fail to type-check whenever the domain module
    happened to be absent from the tree.

    Attributes:
        host: Interface to bind, also used verbatim in `GatewayServer.url`.
        port: TCP port; ``0`` asks the OS for an ephemeral one.
        certfile: PEM certificate chain, or `None` for cleartext HTTP.
        keyfile: PEM private key, set together with `certfile`.
        consumer_queue_size: Frames buffered for one SSE consumer before its
            connection is dropped.
    """

    host: str = "127.0.0.1"
    port: int = 0
    certfile: str | None = None
    keyfile: str | None = None
    consumer_queue_size: int = SSE_QUEUE_SIZE


@runtime_checkable
class AdmitResult(Protocol):
    """What `GatewayServiceProtocol.admit_request` must hand back.

    The transport reads exactly one field from it: the identity of the request
    the admission produced. Everything else the client needs is fetched from
    the status and event endpoints, so the transport does not constrain the
    richer result the domain module chooses to return.
    """

    #: The request this admission refers to, new or idempotently reused.
    request_id: str


@runtime_checkable
class GatewayServiceProtocol(Protocol):
    """Everything the server may call. The domain module implements this.

    The transport calls exactly one method per endpoint, always with the
    credential the header resolved to. It never reaches around the service into
    the credential table. `log` is declared because it is part of the service's
    contract; the transport renders checkpoints and receipts through the
    methods below rather than reading the log itself.
    """

    @property
    def store(self) -> CenterStore:
        """The center's durable store, used here only to resolve credentials."""
        ...

    @property
    def log(self) -> MerkleLog:
        """The transparency log the service commits receipts into."""
        ...

    def admit_request(
        self,
        *,
        credential: Credential,
        idempotency_key: str,
        messages: Sequence[ChatMessage],
        authorization: SignedRecord,
        model: str,
        max_charge_milli_credits: int,
        parameters: Mapping[str, Any] | None = ...,
        delivery_mode: str,
        max_attempts: int,
        deadline_ms: int,
        session_id: str | None = ...,
        now: dt.datetime | None = ...,
    ) -> AdmitResult:
        """Admit a new request, idempotently on ``(tenant, idempotency_key)``."""
        ...

    def admit_api_key_request(
        self,
        *,
        api_key: ApiKeyRecord,
        messages: Sequence[ChatMessage],
        model: str,
        parameters: Mapping[str, Any] | None = ...,
        delivery_mode: str,
        deadline_ms: int,
        session_id: str | None = ...,
        now: dt.datetime | None = ...,
    ) -> AdmitResult:
        """Admit a request authenticated by an operator-issued API key.

        The second admission path: the spend is authorized by the platform's own
        signature over the terms it is admitting, because the caller proved it
        holds a key the center issued rather than a signature it produced. The
        request it produces is otherwise indistinguishable from a signed one, and
        runs the same dispatch, metering and settlement.
        """
        ...

    def request_status(self, *, credential: Credential, request_id: str) -> dict[str, Any]:
        """Return the status view of one request."""
        ...

    def request_events(
        self, *, credential: Credential, request_id: str, cursor: int, limit: int = ...
    ) -> list[StoredEvent]:
        """Return the stored events of a request whose cursor exceeds `cursor`."""
        ...

    def cancel_request(
        self,
        *,
        credential: Credential,
        request_id: str,
        origin: str,
        now: dt.datetime | None = ...,
    ) -> dict[str, Any]:
        """Cancel a request and return the resulting status view."""
        ...

    def receipt_for(self, *, credential: Credential, receipt_id: str) -> dict[str, Any]:
        """Return a signed receipt with its checkpoint and inclusion proof."""
        ...

    def checkpoint(
        self, *, credential: Credential, now: dt.datetime | None = ...
    ) -> dict[str, Any]:
        """Return the latest signed transparency checkpoint."""
        ...

    def account_history(self, *, credential: Credential) -> dict[str, Any]:
        """Return the calling consumer's own account history."""
        ...

    def node_attempts(self, *, credential: Credential) -> dict[str, Any]:
        """Return the attempts the center dispatched to the calling node."""
        ...

    def register_node(
        self,
        *,
        credential: Credential,
        hello: NodeHello,
        enqueue: Callable[[Envelope], None],
        now: dt.datetime | None = ...,
    ) -> None:
        """Accept a node's `node.hello` and bind its outbound sink."""
        ...

    def node_disconnected(self, *, node_id: str, now: dt.datetime | None = ...) -> None:
        """Report that a node link ended."""
        ...

    def handle_node_message(
        self, *, node_id: str, envelope: Envelope, now: dt.datetime | None = ...
    ) -> list[Envelope]:
        """Handle one inbound node message and return the envelopes to send back."""
        ...

    def tick(self, *, now: dt.datetime | None = ...) -> list[tuple[str, Envelope]]:
        """Return ``(node_id, envelope)`` pairs to deliver, and advance timers."""
        ...

    def join(
        self,
        *,
        invite_code: str,
        identity: dict[str, Any],
        device: dict[str, Any] | None,
        center_url: str,
        now: dt.datetime | None = ...,
    ) -> Any:
        """Redeem an invite and register the joiner's identity."""
        ...

    def authenticate_signed_request(
        self,
        *,
        payload: dict[str, Any],
        key_id: str,
        issued_at: dt.datetime,
        nonce: str,
        signature_b64: str,
        now: dt.datetime | None = ...,
    ) -> Credential:
        """Resolve a signed request to the credential it authenticates."""
        ...


#: Domain exception to HTTP status and machine-readable code. Ordered from the
#: most specific class to the least, because the first `isinstance` match wins:
#: a `DuplicateKeyError` must be a `400` even though it is a
#: `CanonicalizationError`, and a `KeyRevokedError` must be a `403` even though
#: it is a `SignatureError`. `errors.py` defines the hierarchy; this table is
#: where the transport decides what the caller sees.
#:
#: Known imprecision, from `errors.py` having no "not found" class. The domain
#: module reports an unknown request as a `StateTransitionError` (the same class
#: it uses for an illegal transition, hence the `409`), and an unknown receipt as
#: its own catch-all `GatewayError`, which falls through to the `PotluckError`
#: row's `400`. A dedicated not-found error in `errors.py` is what would let the
#: transport answer `404`; see the module report rather than working around it
#: by guessing at class names here.
_STATUS_BY_ERROR: tuple[tuple[type[PotluckError], int, str], ...] = (
    (ConflictError, 409, "conflict"),
    (StateTransitionError, 409, "conflict"),
    (SettlementError, 409, "conflict"),
    (InsufficientFundsError, 402, "insufficient_funds"),
    # `no_nodes` is the code the platform's own consumer client already maps to a
    # "nothing can run this" refusal, so the center names the condition the way
    # its client reads it rather than as a generic bad request.
    (ModelUnavailable, 404, "no_nodes"),
    (QueueFull, 503, "queue_full"),
    (CanonicalizationError, 400, "bad_request"),
    (ProtocolError, 400, "bad_request"),
    (MeteringError, 400, "bad_request"),
    (AllocationError, 400, "bad_request"),
    (UnknownKeyError, 403, "forbidden"),
    (KeyRevokedError, 403, "forbidden"),
    (DelegationError, 403, "forbidden"),
    (IdentityBindingError, 403, "forbidden"),
    (SignatureError, 403, "forbidden"),
    (VerificationError, 403, "forbidden"),
    (PotluckError, 400, "bad_request"),
)

#: Methods each known path answers. A known path with any other method is a
#: `405` carrying this set in its `Allow` header.
_ROUTE_METHODS: dict[str, frozenset[str]] = {
    "health": frozenset({"GET"}),
    "join": frozenset({"POST"}),
    "create_request": frozenset({"POST"}),
    "request_status": frozenset({"GET"}),
    "request_events": frozenset({"GET"}),
    "request_cancel": frozenset({"POST"}),
    "receipt": frozenset({"GET"}),
    "checkpoint": frozenset({"GET"}),
    "nodes": frozenset({"GET"}),
    "account_history": frozenset({"GET"}),
    "node_attempts": frozenset({"GET"}),
    "node_link": frozenset({"GET"}),
    # The OpenAI-compatible surface. `openai_unsupported` answers both verbs so
    # an endpoint this platform does not implement reports that, rather than
    # reporting only that the verb was wrong.
    "openai_chat_completions": frozenset({"POST"}),
    "openai_models": frozenset({"GET"}),
    "openai_model": frozenset({"GET"}),
    "openai_unsupported": frozenset({"GET", "POST"}),
}

#: The role each authenticated route demands. A route absent here is a consumer
#: route, which is the default because every data endpoint the platform started
#: with was one. The two node routes are spelled out so the role check cannot
#: drift when a route is added: an endpoint that answers to the wrong role hands
#: one party another party's books.
_ROUTE_ROLES: dict[str, str] = {
    "node_link": "node",
    "node_attempts": "node",
}

#: How long an OpenAI-compatible request waits for a terminal state before it
#: answers `504`. Deliberately longer than the request's own deadline, so the
#: center's deadline — which ends the request and records why — fires first, and
#: the answer names a request the caller can still verify instead of the
#: transport giving up on work the center is still doing.
OPENAI_WAIT_DEADLINE_S = 110.0

#: The wall-clock budget an OpenAI-compatible request is admitted with.
OPENAI_REQUEST_DEADLINE_MS = 100_000

#: Events fetched per poll while an OpenAI-compatible answer is rendered.
OPENAI_EVENT_BATCH = 256

#: What ``GET /openai/v1/models`` reports as the owner of a model. The pool
#: serves it and no single organisation does, so the platform names itself
#: rather than inventing a provider.
OPENAI_MODEL_OWNER = "ai-potluck"

#: OpenAI's error ``type`` for each code this surface answers with, following the
#: pairings OpenAI's own API reference documents: a condition the caller can act
#: on is an ``invalid_request_error`` carrying a specific ``code`` (that is how
#: OpenAI reports `invalid_api_key` and `model_not_found`), a spent quota is
#: `insufficient_quota`, and a fault of the platform's is a `server_error`. A
#: client reads the type to decide whether to re-authenticate, back off or give
#: up, so the mapping is part of the contract rather than a presentation detail.
#:
#: Two values here are this platform's own, and `docs/openai-endpoint.md` says so:
#: ``not_supported``, for an endpoint this center has decided not to implement —
#: borrowing `invalid_request_error` would suggest a different request could
#: succeed — and ``rate_limit_error`` for a per-key ceiling, where OpenAI's own
#: rate-limit errors name the dimension exceeded (`requests`, `tokens`) rather
#: than the condition, which does not describe a limit one key has hit.
_OPENAI_ERROR_TYPE: dict[str, str] = {
    "invalid_api_key": "invalid_request_error",
    "insufficient_quota": "insufficient_quota",
    "rate_limit_exceeded": "rate_limit_error",
    "model_not_found": "invalid_request_error",
    "not_supported": "not_supported",
    "not_found": "invalid_request_error",
    "method_not_allowed": "invalid_request_error",
    "invalid_request": "invalid_request_error",
    "upstream_failed": "server_error",
    "deadline_passed": "server_error",
    "internal_error": "server_error",
}

#: Domain exception to the status and code an OpenAI-compatible admission
#: answers with, most specific first. The codes are OpenAI's own where OpenAI
#: defines one: a spent quota is `insufficient_quota` at `429`, which is what an
#: existing client already knows how to report, rather than the `402` the
#: platform's own surface answers with.
_OPENAI_ADMISSION_ERROR: tuple[tuple[type[PotluckError], int, str], ...] = (
    (ApiKeyUnavailable, 401, "invalid_api_key"),
    (ApiKeyRateLimited, 429, "rate_limit_exceeded"),
    # A full dispatch queue and a per-key ceiling are different facts with the
    # same remedy, and the remedy is what an OpenAI client acts on: back off and
    # retry. `429` with this code is what makes an existing client's own retry
    # logic do the right thing without learning a new code, and the message still
    # says which of the two it hit.
    (QueueFull, 429, "rate_limit_exceeded"),
    (InsufficientFundsError, 429, "insufficient_quota"),
    (ModelUnavailable, 404, "model_not_found"),
    (CanonicalizationError, 400, "invalid_request"),
    (ProtocolError, 400, "invalid_request"),
    (PotluckError, 502, "upstream_failed"),
)

#: The OpenAI-compatible endpoints this platform has decided not to implement.
#: Answered with `404` and ``not_supported`` rather than left unrouted, so a
#: client pointed at the wrong surface is told what is missing instead of
#: reading a generic `404` as a misconfigured base URL.
_OPENAI_UNSUPPORTED_ENDPOINTS: frozenset[str] = frozenset({"completions", "embeddings"})


class _SessionRefused:
    """The marker a session read returns once it has already answered `400`.

    A distinct type rather than `None`, because `None` already means "this
    request named no session" and the two have opposite outcomes: one admits the
    request and one does not.
    """


_SESSION_REFUSED = _SessionRefused()


def _openai_admission_error(error: PotluckError) -> tuple[int, str]:
    """Map a domain exception to ``(http_status, openai_error_code)``.

    Args:
        error: The exception the service raised.

    Returns:
        The status and code to answer with.
    """
    for error_type, status, code in _OPENAI_ADMISSION_ERROR:
        if isinstance(error, error_type):
            return status, code
    return 502, "upstream_failed"


def _status_for_error(error: PotluckError) -> tuple[int, str]:
    """Map a domain exception to ``(http_status, machine_code)``.

    Args:
        error: The exception the service raised.

    Returns:
        The status and short code to answer with.
    """
    for error_type, status, code in _STATUS_BY_ERROR:
        if isinstance(error, error_type):
            return status, code
    return 500, "internal_error"


def _redact(text: str, secret: str | None) -> str:
    """Remove `secret` from `text`, if it appears at all.

    Used on every detail the gateway renders back or logs, so a domain error
    that happened to quote the bearer token cannot turn a response into a
    credential leak.

    Args:
        text: The message about to leave the gateway.
        secret: The token presented on this request, or `None`.

    Returns:
        `text` with the secret replaced by a placeholder.
    """
    if secret and secret in text:
        return text.replace(secret, "<redacted>")
    return text


def _match_route(path: str) -> tuple[str, str] | None:
    """Resolve a request path to a route name and its single path parameter.

    Args:
        path: The path component of the request target, already split from the
            query string.

    Returns:
        ``(route, parameter)``, or `None` when the path names no endpoint. The
        parameter is the empty string for routes that take none. Path segments
        are percent-decoded and empty segments are dropped, so an id is always a
        single decoded segment.
    """
    segments = [urllib.parse.unquote(part) for part in path.split("/") if part]
    if segments == ["healthz"]:
        return "health", ""
    if segments == ["v1", "checkpoint"]:
        return "checkpoint", ""
    if segments == ["v1", "join"]:
        return "join", ""
    if segments == ["v1", "nodes"]:
        return "nodes", ""
    if segments == ["v1", "node-link"]:
        return "node_link", ""
    if segments == ["v1", "account", "history"]:
        return "account_history", ""
    if segments == ["v1", "node", "attempts"]:
        return "node_attempts", ""
    if segments[:2] == ["v1", "requests"]:
        if len(segments) == 2:
            return "create_request", ""
        if len(segments) == 3:
            return "request_status", segments[2]
        if len(segments) == 4 and segments[3] == "events":
            return "request_events", segments[2]
        if len(segments) == 4 and segments[3] == "cancel":
            return "request_cancel", segments[2]
    if segments[:2] == ["v1", "receipts"] and len(segments) == 3:
        return "receipt", segments[2]
    if segments[:2] == ["openai", "v1"]:
        surface = segments[2:]
        if surface == ["chat", "completions"]:
            return "openai_chat_completions", ""
        if surface == ["models"]:
            return "openai_models", ""
        if len(surface) == 2 and surface[0] == "models":
            return "openai_model", surface[1]
        if len(surface) == 1 and surface[0] in _OPENAI_UNSUPPORTED_ENDPOINTS:
            return "openai_unsupported", surface[0]
        return None
    return None


def _bearer_token(header: str | None) -> str | None:
    """Extract the token from an ``Authorization: Bearer`` header value.

    Args:
        header: The raw header value, or `None` when absent.

    Returns:
        The token, or `None` when the header is absent, uses another scheme, or
        carries an empty token. A malformed header is never partially accepted.
    """
    if header is None:
        return None
    scheme, separator, value = header.partition(" ")
    if not separator or scheme.lower() != "bearer":
        return None
    token = value.strip()
    return token or None


def _require_body_str(body: dict[str, Any], key: str) -> str:
    """Return a required non-empty string field from a request body.

    Raises:
        ProtocolError: If the field is missing, empty, or not a string.
    """
    value = body.get(key)
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{key} must be a non-empty string")
    return value


def _require_body_int(body: dict[str, Any], key: str) -> int:
    """Return a required non-negative integer field from a request body.

    `bool` is rejected explicitly: it is an `int` subclass in Python, so
    accepting it would let a client send ``true`` where an amount belongs.

    Raises:
        ProtocolError: If the field is missing, not an integer, or negative.
    """
    value = body.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{key} must be an integer")
    if value < 0:
        raise ProtocolError(f"{key} must be non-negative")
    return value


def _signed_record_from_json(body: dict[str, Any]) -> SignedRecord:
    """Rebuild a `SignedRecord` from the JSON body of a request.

    The transport owns this boundary: the record arrives as plain JSON, is
    validated here, and is handed to the service as the record type the domain
    module already knows. Nothing in the body is trusted to be well formed, and
    the signature itself is checked by the domain, not here.

    Raises:
        ProtocolError: If a required field is missing, has the wrong type, or
            carries a naive timestamp.
    """
    payload = body.get("payload")
    if not isinstance(payload, dict):
        raise ProtocolError("authorization.payload must be a JSON object")
    revision = body.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int):
        raise ProtocolError("authorization.revision must be an integer")
    raw_signed_at = body.get("signed_at")
    if not isinstance(raw_signed_at, str):
        raise ProtocolError("authorization.signed_at must be an ISO 8601 string")
    try:
        signed_at = dt.datetime.fromisoformat(raw_signed_at)
    except ValueError as exc:
        raise ProtocolError(
            f"authorization.signed_at is not an ISO 8601 instant: {raw_signed_at!r}"
        ) from exc
    if signed_at.tzinfo is None:
        raise ProtocolError("authorization.signed_at must be timezone-aware")
    previous = body.get("previous_record_hash")
    if previous is not None and not isinstance(previous, str):
        raise ProtocolError("authorization.previous_record_hash must be a string or null")
    return SignedRecord(
        schema=_require_body_str(body, "schema"),
        record_id=_require_body_str(body, "record_id"),
        revision=revision,
        signed_at=signed_at.astimezone(dt.UTC),
        signer_key_id=_require_body_str(body, "signer_key_id"),
        signer_id=_require_body_str(body, "signer_id"),
        signature=_require_body_str(body, "signature"),
        payload=cast("dict[str, Any]", payload),
        previous_record_hash=previous,
    )


@dataclass(frozen=True)
class _AdmissionRequest:
    """The fields of a ``POST /v1/requests`` body the transport forwards.

    The body is read field by field, so identity fields a client may have put
    in it (``tenant_id``, ``subject_id``, ``payer_account_id``) are never read
    and can never influence the call: the effective tenant is the one the
    resolved credential carries.
    """

    idempotency_key: str
    messages: tuple[ChatMessage, ...]
    model: str
    parameters: dict[str, Any]
    max_charge_milli_credits: int
    delivery_mode: str
    max_attempts: int
    deadline_ms: int
    authorization: SignedRecord
    #: The agent session this turn belongs to, or `None`. Read from the body
    #: rather than from a header on this surface, because a signed request is one
    #: canonical document: the fields that describe the request travel together in
    #: it, and the signature over the rest of the body is what makes tampering
    #: with any of them visible.
    session_id: str | None

    @classmethod
    def from_json(cls, body: dict[str, Any]) -> _AdmissionRequest:
        """Parse an admission body.

        Raises:
            ProtocolError: If the ``authorization`` object is missing, the
                ``messages`` array is not a conversation this platform forwards,
                or any field is absent or of the wrong type.
        """
        authorization = body.get("authorization")
        if not isinstance(authorization, dict):
            raise ProtocolError("the body must carry an authorization object")
        raw_session = body.get("session_id")
        if raw_session is not None and not isinstance(raw_session, str):
            raise ProtocolError("session_id must be a string")
        return cls(
            idempotency_key=_require_body_str(body, "idempotency_key"),
            messages=parse_chat_messages(body.get("messages")),
            model=_require_body_str(body, "model"),
            parameters=encode_chat_parameters(body.get("parameters")),
            max_charge_milli_credits=_require_body_int(body, "max_charge_milli_credits"),
            delivery_mode=_require_body_str(body, "delivery_mode"),
            max_attempts=_require_body_int(body, "max_attempts"),
            deadline_ms=_require_body_int(body, "deadline_ms"),
            authorization=_signed_record_from_json(authorization),
            session_id=raw_session,
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Object hook that refuses a repeated key instead of silently keeping one.

    The OpenAI-compatible surface parses with the standard library, because a
    client sends fractional parameters the platform's strict parser refuses by
    design. Refusing duplicates here keeps the one guarantee of that parser this
    surface still needs: two parsers must not be able to read one body differently.

    Raises:
        ValueError: If a key appears twice, which `json.loads` reports as-is.
    """
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate JSON key: {key!r}")
        document[key] = value
    return document


@dataclass(frozen=True)
class _OpenAiChatRequest:
    """The parts of an OpenAI chat-completions body this platform acts on.

    ``messages`` is the caller's own conversation and reaches the upstream
    unchanged; ``parameters`` is the subset of the body the platform has decided
    to forward, in the canonical-safe encoding the wire carries. Every other
    field is ignored rather than refused: a client that sends something this
    center has no opinion about has not made a bad request, and a body it cannot
    honour is not a body it should reject.
    """

    model: str
    messages: tuple[ChatMessage, ...]
    parameters: dict[str, Any]
    stream: bool
    #: Whether the caller asked for a terminal usage frame in the stream, which
    #: is what ``stream_options.include_usage`` means upstream too.
    include_usage: bool

    @classmethod
    def from_json(cls, body: dict[str, Any]) -> _OpenAiChatRequest:
        """Parse an OpenAI chat-completions body.

        Raises:
            ProtocolError: If the model is missing, the messages are not a
                conversation, a forwarded parameter has the wrong type, `stream`
                or `stream_options.include_usage` is not a boolean, or the body
                carries a value the canonical encoder cannot forward.
        """
        messages = parse_chat_messages(body.get("messages"))
        parameters = encode_chat_parameters(body)
        stream = body.get("stream", False)
        if not isinstance(stream, bool):
            raise ProtocolError("stream must be a boolean")
        include_usage = False
        options = body.get("stream_options")
        if options is not None:
            if not isinstance(options, dict):
                raise ProtocolError("stream_options must be a JSON object")
            include_usage = options.get("include_usage", False)
            if not isinstance(include_usage, bool):
                raise ProtocolError("stream_options.include_usage must be a boolean")
        # The canonical encoder refuses a float, and a body may carry one inside
        # a content part or a structured parameter. Refusing it here answers
        # `400` and names the problem, instead of failing halfway through
        # dispatch with an answer that says nothing about the body.
        try:
            canonicalize([message.to_payload() for message in messages])
            canonicalize(parameters)
        except CanonicalizationError as exc:
            raise ProtocolError(
                f"the request carries a value this center cannot forward: {exc}"
            ) from exc
        return cls(
            model=_require_body_str(body, "model"),
            messages=messages,
            parameters=parameters,
            stream=stream,
            include_usage=include_usage,
        )


@dataclass(frozen=True)
class _OpenAiCompletion:
    """The identity of one rendered completion, fixed before its first frame.

    Every frame of one answer carries the same id, model and creation instant,
    which is what lets a client match a stream to the request that started it.
    """

    id: str
    created: int
    model: str

    @classmethod
    def new(cls, model: str) -> _OpenAiCompletion:
        """Mint the identity for one completion."""
        return cls(
            id=f"chatcmpl-{secrets.token_hex(12)}",
            created=int(time.time()),
            model=model,
        )


@dataclass(frozen=True)
class _OpenAiWaitResult:
    """How one OpenAI-compatible wait for a terminal state ended.

    The outcomes are kept apart because they answer differently: a request that
    failed is a `502`, one the center is still running when the window closes is
    a `504` naming the request to check later, a service that could not be read
    at all is a `502` carrying its own detail, and a caller that hung up is
    nobody's error and gets no answer at all.
    """

    #: The terminal request status, or `None` when the window closed first.
    status: str | None
    #: The settled token counts, or `None` when nothing was reported.
    usage: dict[str, int] | None
    #: The detail of a service failure that ended the wait, if any.
    error: str | None
    #: The answer rendered so far, complete only for a terminal success.
    content: str = ""
    #: The center's own reason for a terminal state, when it recorded one.
    billing_note: str | None = None
    #: Whether the caller hung up before the answer was rendered.
    abandoned: bool = False


def _openai_unfinished_message(
    status: str | None, billing_note: str | None, request_id: str
) -> str:
    """Explain a request this connection stopped waiting for.

    The request id is the point of the message: the work may still be running,
    it is charged only if it settles, and the id is what the center's own books,
    and an operator's `verify receipt`, answer against.
    """
    state = "did not reach a terminal state" if status is None else f"ended as {status}"
    note = f" ({billing_note})" if billing_note else ""
    return (
        f"request {request_id} {state} within "
        f"{int(OPENAI_WAIT_DEADLINE_S)}s{note}; it may still be running and is "
        "charged only if it settles. Quote this request id to the center's "
        "operator, who can verify what it cost with `potluck-server verify "
        "receipt`."
    )


def _openai_failed_message(billing_note: str | None, request_id: str) -> str:
    """Explain a request the center ended in failure.

    The center's own `billing_note` is carried through rather than replaced by a
    generic "upstream failure": the reason a request failed lives at the center,
    and hiding it is what makes an exhausted upstream quota look like an outage.
    """
    note = f": {billing_note}" if billing_note else ""
    return (
        f"the center reported request {request_id} as FAILED{note}. Nothing was "
        "charged for a request that produced no answer; the receipt for one that "
        "did is verifiable by this request id."
    )


def _openai_chunk(
    completion: _OpenAiCompletion,
    *,
    delta: dict[str, Any] | None,
    finish_reason: str | None,
    usage: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Render one ``chat.completion.chunk`` document.

    A terminal usage frame carries no choices, which is how OpenAI marks it as
    the totals rather than an empty increment.
    """
    choices: list[dict[str, Any]] = []
    if delta is not None or finish_reason is not None:
        choices.append(
            {
                "index": 0,
                "delta": delta or {},
                "finish_reason": finish_reason,
                "logprobs": None,
            }
        )
    document: dict[str, Any] = {
        "id": completion.id,
        "object": "chat.completion.chunk",
        "created": completion.created,
        "model": completion.model,
        "choices": choices,
    }
    if usage is not None:
        document["usage"] = usage
    return document


def _openai_completion_document(
    completion: _OpenAiCompletion, content: str, usage: dict[str, int] | None
) -> dict[str, Any]:
    """Render one ``chat.completion`` document.

    `finish_reason` is ``stop`` because this answer is complete: the center only
    renders a completion for a request that reached its terminal success, and a
    request that was cut short is an error rather than a short answer.
    """
    document: dict[str, Any] = {
        "id": completion.id,
        "object": "chat.completion",
        "created": completion.created,
        "model": completion.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content, "refusal": None},
                "finish_reason": "stop",
                "logprobs": None,
            }
        ],
    }
    if usage is not None:
        document["usage"] = usage
    return document


def _measurement_split(payload: dict[str, Any]) -> dict[str, int] | None:
    """Return the input/output token split of a stored ``usage.final`` payload.

    Returns `None` when the event carries no readable split, so a caller can
    leave the halves at zero rather than invent them from the billed total.
    """
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return None
    input_total = usage.get("input_total")
    output_total = usage.get("output_total")
    if not isinstance(input_total, int) or not isinstance(output_total, int):
        return None
    return {"prompt_tokens": input_total, "completion_tokens": output_total}


def _settled_tokens(status: dict[str, Any]) -> int | None:
    """Return the token total the center billed for the request's winning attempt."""
    selected = status.get("selected_attempt_id")
    attempts = status.get("attempts")
    if not isinstance(attempts, list):
        return None
    for attempt in attempts:
        if not isinstance(attempt, dict) or attempt.get("attempt_id") != selected:
            continue
        tokens = attempt.get("usage_tokens")
        return tokens if isinstance(tokens, int) else None
    return None


def _openai_usage(status: dict[str, Any], split: dict[str, int] | None) -> dict[str, int]:
    """Render the settlement's token counts as an OpenAI ``usage`` block.

    ``total_tokens`` is what the center actually billed — the settled total on
    the winning attempt's own row — rather than a sum of the two halves, so the
    number a caller reads is the number the receipt behind it names. The split
    comes from the node's final measurement, and stays zero when it reported
    none: guessing a proportion would be a fabricated number in a billing
    document.
    """
    prompt_tokens = split["prompt_tokens"] if split else 0
    completion_tokens = split["completion_tokens"] if split else 0
    settled = _settled_tokens(status)
    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": settled if settled is not None else prompt_tokens + completion_tokens,
    }


def _openai_model_documents(records: list[NodeRecord]) -> dict[str, dict[str, Any]]:
    """Aggregate the models the connected, sharing nodes advertise.

    A model no node is sharing is left out rather than listed: the list is what
    a client picks a model from, and advertising one nobody will run turns a
    typo into a request that waits for its deadline.

    ``created`` is the instant the pool last advertised the model. The center
    holds no model registration date, and a real timestamp it does have is more
    useful than a zero that only looks like one.
    """
    models: dict[str, dict[str, Any]] = {}
    for record in records:
        if not record.share_enabled:
            continue
        seen = int(record.last_seen_at.timestamp())
        existing = models.get(record.model)
        if existing is None or seen > int(existing["created"]):
            models[record.model] = {
                "id": record.model,
                "object": "model",
                "created": seen,
                "owned_by": OPENAI_MODEL_OWNER,
            }
    return models


def _node_to_json(record: NodeRecord) -> dict[str, Any]:
    """Render a stored node registration as JSON-safe values.

    Written out field by field rather than via `dataclasses.asdict`, because
    ``last_seen_at`` is a `datetime` and the response goes through
    `canonical.canonicalize`, which refuses anything it cannot encode
    deterministically.

    Args:
        record: The stored node row.

    Returns:
        A mapping of JSON scalars.
    """
    return {
        "node_id": record.node_id,
        "device_id": record.device_id,
        "provider_id": record.provider_id,
        "adapter_name": record.adapter_name,
        "model": record.model,
        "share_enabled": record.share_enabled,
        "max_concurrency": record.max_concurrency,
        "max_local_reserved_milli_credits": record.max_local_reserved_milli_credits,
        "policy_version": record.policy_version,
        "last_seen_at": record.last_seen_at.astimezone(dt.UTC).isoformat(),
    }


def _sse_event_frame(cursor: int, event_type: str, payload: dict[str, Any]) -> str:
    """Render one stored event as an SSE frame.

    Raises:
        ProtocolError: If the event type contains a line break, which would let
            a stored value inject additional SSE fields into the stream.
    """
    if "\n" in event_type or "\r" in event_type:
        raise ProtocolError(f"event type {event_type!r} cannot be framed as an SSE field")
    data = canonicalize(payload).decode("utf-8")
    return f"id: {cursor}\nevent: {event_type}\ndata: {data}\n\n"


def _sse_status_frame(event_name: str, body: dict[str, Any]) -> str:
    """Render a gateway-generated SSE frame that carries no cursor."""
    data = canonicalize(body).decode("utf-8")
    return f"event: {event_name}\ndata: {data}\n\n"


class _OutboundBuffer(Generic[_T]):
    """A bounded outbound buffer whose overflow is a signal, never a block.

    Built on a `threading.Condition` over a `deque` rather than
    `queue.Queue(maxsize=...)`, for one reason: the drop path must be able to
    append a final item to a buffer that is already full. `queue.Queue` cannot
    express "one more, then stop", so a full queue would silently lose exactly
    the notice that tells the peer why it was dropped. Here `offer` refuses on
    a full buffer and `finalize` owns a reserved terminal slot, so "we are
    dropping you, resume by cursor" is always deliverable.

    The producer side never blocks; the consumer side waits with a timeout so a
    shutdown is prompt even with nothing to drain.
    """

    def __init__(self, maxsize: int) -> None:
        """Create a buffer holding at most `maxsize` ordinary items.

        Args:
            maxsize: Capacity before `offer` starts refusing.

        Raises:
            ValueError: If `maxsize` is below one, which would make the buffered
                channel useless for anything but the terminal slot.
        """
        if maxsize < 1:
            raise ValueError(f"maxsize must be >= 1, got {maxsize}")
        self._maxsize = maxsize
        self._condition = threading.Condition()
        self._items: deque[_T] = deque()
        self._terminal: _T | None = None
        self._terminal_pending = False
        self._finished = False

    def offer(self, item: _T) -> bool:
        """Append one item without blocking.

        Args:
            item: The item to enqueue.

        Returns:
            True when it was buffered; False when the buffer is full, already
            finalised, or already finished, in which case the caller owns the
            overflow policy.
        """
        with self._condition:
            if self._finished or self._terminal_pending:
                return False
            if len(self._items) >= self._maxsize:
                return False
            self._items.append(item)
            self._condition.notify()
            return True

    def finish(self, terminal: _T) -> None:
        """Queue a final item that is delivered after everything already queued.

        The terminal lives in a slot of its own rather than in the queue, so it
        is accepted even when the queue is full: `queue.Queue(maxsize=...)`
        cannot express "one more, and then stop", and a full queue would then
        lose exactly the notice that tells the peer the stream ended. Queueing
        it after the backlog rather than instead of it is what keeps a terminal
        frame behind the last event instead of ahead of it.

        Args:
            terminal: The item the consumer will write last.
        """
        with self._condition:
            if self._finished:
                return
            self._terminal = terminal
            self._terminal_pending = True
            self._condition.notify_all()

    def discard_backlog(self) -> None:
        """Throw away the queued items, keeping any pending final item.

        Used by the drop path, where the point is to bound memory for a peer
        that is not reading. The stored events remain replayable by cursor, so
        nothing is lost that the peer cannot refetch.
        """
        with self._condition:
            self._items.clear()

    def cancel(self) -> None:
        """Abandon everything, including a pending final item."""
        with self._condition:
            self._items.clear()
            self._terminal = None
            self._terminal_pending = False
            self._finished = True
            self._condition.notify_all()

    def take(self, timeout: float) -> tuple[bool, _T | None]:
        """Take the next item, waiting up to `timeout` seconds.

        Args:
            timeout: Seconds to wait for an item.

        Returns:
            ``(True, item)`` when an item was available, otherwise
            ``(False, None)`` on timeout or after the buffer has finished.
            Callers distinguish the two with `finished`.
        """
        deadline = time.monotonic() + timeout
        with self._condition:
            while True:
                if self._items:
                    return True, self._items.popleft()
                if self._terminal_pending:
                    item = self._terminal
                    self._terminal = None
                    self._terminal_pending = False
                    self._finished = True
                    return True, item
                if self._finished:
                    return False, None
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False, None
                self._condition.wait(remaining)

    @property
    def finished(self) -> bool:
        """Whether a terminal item has been handed out, or the buffer cancelled."""
        with self._condition:
            return self._finished


def _peer_closed(sock: socket.socket) -> bool:
    """Report whether the peer has closed its half of the connection.

    An SSE stream is one-way, so the only reason its connection becomes
    readable is a FIN. Detecting that lets an abandoned stream retire instead of
    polling a request nobody is watching until the process stops.

    Args:
        sock: The connection socket, plain or TLS-wrapped.

    Returns:
        True when the peer is gone or the socket is no longer usable.
    """
    try:
        readable, _, _ = select.select([sock], [], [], 0)
    except (OSError, ValueError):
        return True
    if not readable:
        return False
    try:
        return sock.recv(1) == b""
    except ssl.SSLWantReadError:
        # A partial TLS record: readable at the socket layer, nothing decrypted
        # yet. That is not a close.
        return False
    except BlockingIOError:
        return False
    except OSError:
        return True


class _LinkCloser:
    """One daemon thread that closes node links off every other thread's path.

    `websocket.ServerConnection.close` writes a close frame under the
    connection's send lock, and a node that has stopped reading holds that lock
    inside a blocking write. Measured on this transport, a second thread calling
    ``close`` while a sender is stuck never returns. Calling `close` inline
    would therefore let one stalled node block `stop`, the ticker, or the reader
    that found the link dead -- the three places whose whole job is to stop a
    stalled peer from mattering. Closes are handed to this thread instead, whose
    only work is to wait.

    The pending list needs no overflow policy: the transport queues at most one
    close per node link, so its length is bounded by the number of links the
    server has accepted at once.
    """

    def __init__(self) -> None:
        """Create the closer; `start` runs its thread."""
        self._condition = threading.Condition()
        self._pending: deque[tuple[ServerConnection, int, str]] = deque()
        self._started = False

    def start(self) -> None:
        """Start the closing thread, once."""
        if self._started:
            return
        self._started = True
        thread = threading.Thread(
            target=self._run, name="potluck-link-closer", daemon=True
        )
        thread.start()

    def request_close(
        self, connection: ServerConnection, code: int = 1000, reason: str = ""
    ) -> None:
        """Ask for `connection` to be closed, without blocking the caller.

        Args:
            connection: The link to tear down.
            code: The close code to send.
            reason: The close reason to send.
        """
        with self._condition:
            self._pending.append((connection, code, reason))
            self._condition.notify()

    def _run(self) -> None:
        """Close queued links for as long as the process lives."""
        while True:
            with self._condition:
                while not self._pending:
                    self._condition.wait()
                connection, code, reason = self._pending.popleft()
            try:
                connection.close(code, reason)
            except (WebSocketError, OSError):
                # The link is being torn down either way, and a close that fails
                # because the peer is already gone has nothing left to report.
                continue


class _SseSession:
    """One live SSE connection: a bounded buffer and the flags that drop it.

    The session is the shared state between the producer thread, which polls
    the service, and the handler thread, which owns the socket. Dropping is
    triggered from whichever side notices first: the producer when a frame
    cannot be buffered, the writer when the peer has gone away, and the server
    when `stop()` runs.
    """

    def __init__(
        self,
        *,
        sock: socket.socket,
        credential: Credential,
        request_id: str,
        start_cursor: int,
        queue_size: int,
        grace_s: float,
    ) -> None:
        """Record the connection and create its outbound buffer.

        Args:
            sock: The connection socket, shut down to force a blocked writer out.
            credential: The consumer the stream was authorised for.
            request_id: The request being streamed.
            start_cursor: Highest cursor the client has already seen.
            queue_size: Frames buffered before the connection is dropped.
            grace_s: Seconds a dropped connection gets to flush its final frame.
        """
        self.sock = sock
        self.credential = credential
        self.request_id = request_id
        self.start_cursor = start_cursor
        self.buffer: _OutboundBuffer[str] = _OutboundBuffer(queue_size)
        self.stop_event = threading.Event()
        self.dropped = False
        self._grace_s = grace_s
        self._timer: threading.Timer | None = None

    def offer_event(self, event: StoredEvent) -> bool:
        """Buffer one stored event.

        Args:
            event: The event to render and enqueue.

        Returns:
            False when the buffer was full, in which case the connection has
            already been marked for dropping.
        """
        frame = _sse_event_frame(event.cursor, event.event_type, event.payload)
        if self.buffer.offer(frame):
            return True
        self.drop("the consumer is not reading fast enough")
        return False

    def offer_heartbeat(self) -> bool:
        """Buffer one comment heartbeat.

        Returns:
            False when the buffer was full, in which case the connection has
            already been marked for dropping.
        """
        if self.buffer.offer(":\n\n"):
            return True
        self.drop("the consumer is not reading fast enough")
        return False

    def offer_done(self, body: dict[str, Any]) -> None:
        """Queue the terminal ``done`` frame behind everything already queued.

        Args:
            body: The payload describing the terminal status.
        """
        self.buffer.finish(_sse_status_frame("done", body))

    def drop(self, reason: str) -> None:
        """Abandon the backlog, queue a final frame, and schedule the teardown.

        The final frame is queued in the buffer's reserved slot so it survives a
        full queue. It is deliverable only if the peer starts reading again
        inside the grace window; a peer that never reads is torn down and
        recovers purely from the cursor, which is why the stored events matter.

        Args:
            reason: Operator-facing explanation carried in the final frame.
        """
        if self.dropped:
            return
        self.dropped = True
        self.buffer.discard_backlog()
        self.buffer.finish(
            _sse_status_frame("dropped", {"request_id": self.request_id, "reason": reason})
        )
        timer = threading.Timer(self._grace_s, self.force_close)
        timer.daemon = True
        self._timer = timer
        timer.start()

    def force_close(self) -> None:
        """Tear the connection down now, waking a writer blocked on the socket."""
        self.stop_event.set()
        self.buffer.cancel()
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)

    def stop(self) -> None:
        """Ask the producer to finish without touching the socket."""
        self.stop_event.set()
        self.buffer.cancel()

    def dispose(self) -> None:
        """Cancel a pending drop timer, if one is armed."""
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None


class _NodeSession:
    """One accepted node link.

    The handler thread runs `read_loop` and never writes to the socket;
    `_write_loop` runs on its own thread and owns every outbound frame. That
    split is what keeps a node which has stopped reading from blocking
    `handle_node_message`, and it leans on ``websocket``'s separate read and
    write locks: a blocked reader cannot hold up a send, and `close` wakes a
    blocked reader.
    """

    def __init__(
        self,
        *,
        server: GatewayServer,
        credential: Credential,
        connection: ServerConnection,
        queue_size: int,
        read_timeout_s: float,
    ) -> None:
        """Bind a freshly upgraded connection to its owning server.

        Args:
            server: The gateway this link belongs to.
            credential: The node credential the handshake authenticated.
            connection: The upgraded server-side WebSocket.
            queue_size: Outbound envelopes buffered before the link is closed.
            read_timeout_s: How long a read blocks before re-checking the stop flag.
        """
        self._server = server
        self._credential = credential
        self._connection = connection
        self._read_timeout_s = read_timeout_s
        self._buffer: _OutboundBuffer[Envelope] = _OutboundBuffer(queue_size)
        #: Created by `start`, which hands the thread to the server so `stop`
        #: can join it; `None` until then.
        self._writer: threading.Thread | None = None
        self._node_id: str | None = None
        self._close_code: int | None = None
        self._close_reason = ""
        self._overflowed = False

    @property
    def node_id(self) -> str | None:
        """The node's advertised identity, or `None` before `node.hello`."""
        return self._node_id

    @property
    def connection(self) -> ServerConnection:
        """The underlying transport, exposed so the server can close it."""
        return self._connection

    def start(self) -> None:
        """Start the writer thread under the server's thread registry."""
        self._writer = self._server.spawn("potluck-node-writer", self._write_loop)

    def read_loop(self) -> None:
        """Read, decode and dispatch inbound messages until the link ends."""
        while not self._connection.closed:
            try:
                text = self._connection.recv_text(timeout=self._read_timeout_s)
            except WebSocketTimeout:
                continue
            except (WebSocketError, OSError):
                return
            try:
                envelope = Envelope.decode(text)
            except ProtocolError as exc:
                self.enqueue(error_envelope("malformed_message", str(exc)))
                continue
            node_id = self._node_id
            if node_id is None:
                if not self._accept_hello(envelope):
                    return
                continue
            self._dispatch(node_id, envelope)

    def enqueue(self, envelope: Envelope) -> None:
        """Buffer one outbound envelope. Never blocks the caller.

        Handed to the service as its sink, so it is called from the service's
        own threads as well as from the reader. A full queue ends the link,
        because a node that cannot keep up must reconnect and resynchronise
        rather than slow the caller down.

        Args:
            envelope: The message to send.
        """
        if self._overflowed:
            return
        if not self._buffer.offer(envelope):
            self._overflow()

    def finish(self) -> None:
        """Tear the link down, notify the service, and unregister the node.

        Runs in a ``finally``, so it must complete whatever the domain module
        does: the socket is closed and the node unregistered before the
        disconnection is reported, and a `PotluckError` from that report is
        dropped rather than allowed to leave the link half-torn-down. The node's
        own reconnect path is what repairs the service's view.

        The socket close is queued on the server's closer thread, because a
        writer stuck on a peer that stopped reading would otherwise hold this
        method -- and the reader thread running it -- open indefinitely.
        """
        writer = self._writer
        if writer is not None and self._close_code is not None:
            writer.join(timeout=_WRITER_FLUSH_TIMEOUT_S)
        self._buffer.cancel()
        self._server.close_link(self._connection)
        if writer is not None:
            writer.join(timeout=_WRITER_JOIN_TIMEOUT_S)
        try:
            node_id = self._node_id
            if node_id is not None:
                with contextlib.suppress(PotluckError):
                    self._server.service.node_disconnected(node_id=node_id)
        finally:
            self._server.unbind_node(self)

    def _accept_hello(self, envelope: Envelope) -> bool:
        """Validate and register the first message.

        Args:
            envelope: The first message received on the link.

        Returns:
            True when the link may continue, False when `read_loop` must stop.
        """
        if envelope.type != "node.hello":
            self._refuse(
                "hello_required",
                "the first message on a node link must be node.hello",
                "a node link must open with node.hello",
            )
            return False
        try:
            hello = NodeHello.from_payload(envelope.payload)
            self._server.service.register_node(
                credential=self._credential, hello=hello, enqueue=self.enqueue
            )
        except ProtocolError as exc:
            self._refuse("malformed_hello", str(exc), "node.hello is malformed")
            return False
        except PotluckError as exc:
            self._refuse("hello_refused", str(exc), "node.hello was refused")
            return False
        self._node_id = hello.node_id
        self._server.bind_node(self, hello.node_id)
        return True

    def _dispatch(self, node_id: str, envelope: Envelope) -> None:
        """Hand one message to the service and enqueue whatever it returns."""
        try:
            replies = self._server.service.handle_node_message(
                node_id=node_id, envelope=envelope
            )
        except PotluckError as exc:
            self.enqueue(error_envelope("domain_error", str(exc), reply_to=envelope.msg_id))
            return
        for reply in replies:
            self.enqueue(reply)

    def _refuse(self, code: str, detail: str, close_reason: str) -> None:
        """Queue a final `protocol.error` and mark the link for a policy close.

        The error is placed in the buffer's reserved slot, so it reaches the
        writer even if the queue is full, and the writer closes with
        `_WS_POLICY_VIOLATION` once it has been flushed.

        Args:
            code: Short machine-readable code for the peer.
            detail: Operator-facing explanation for the peer.
            close_reason: Reason string for the WebSocket close frame.
        """
        self._close_code = _WS_POLICY_VIOLATION
        self._close_reason = close_reason
        self._buffer.finish(error_envelope(code, detail))

    def _overflow(self) -> None:
        """Close a link whose outbound queue filled up.

        The close is handed to the server's closer thread rather than performed
        here, so a service or ticker thread is never held up by a node that has
        stopped reading.
        """
        self._overflowed = True
        self._buffer.cancel()
        self._server.close_link(
            self._connection, _WS_TRY_AGAIN_LATER, "the outbound queue is full"
        )

    def _write_loop(self) -> None:
        """Drain the outbound buffer onto the socket until it finishes."""
        while True:
            ok, envelope = self._buffer.take(_WRITER_POLL_S)
            if ok and envelope is not None:
                try:
                    self._connection.send_text(envelope.encode())
                except (WebSocketError, ProtocolError, OSError):
                    break
                if self._buffer.finished:
                    break
                continue
            if self._buffer.finished or self._connection.closed:
                break
        code = self._close_code
        if code is not None:
            self._connection.close(code, self._close_reason)


class _GatewayHTTPServer(http.server.ThreadingHTTPServer):
    """A threading HTTP server that owns the gateway and its TLS context.

    Threads are daemons, so a handler that is somehow still running cannot keep
    the process alive; `GatewayServer.stop` is what ends them, by closing the
    sockets they are blocked on.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        handler_class: type[http.server.BaseHTTPRequestHandler],
        gateway: GatewayServer,
        tls_context: ssl.SSLContext | None,
    ) -> None:
        """Bind and configure the listener.

        Args:
            address: Interface and port to bind.
            handler_class: The request handler to instantiate per connection.
            gateway: The gateway that owns this server.
            tls_context: The server-side TLS context, or `None` for cleartext.
        """
        self.gateway = gateway
        self._tls_context = tls_context
        super().__init__(address, handler_class)

    @property
    def tls_enabled(self) -> bool:
        """Whether this listener speaks TLS."""
        return self._tls_context is not None

    def server_activate(self) -> None:
        """Start listening, wrapping the listening socket in TLS when configured."""
        super().server_activate()
        if self._tls_context is not None:
            self.socket = self._tls_context.wrap_socket(self.socket, server_side=True)


class _GatewayRequestHandler(http.server.BaseHTTPRequestHandler):
    """One request, which is one connection for SSE and for a node link."""

    protocol_version = "HTTP/1.1"
    server_version = "potluck-gateway"
    sys_version = ""

    #: The token presented on this request, kept only so response details can be
    #: redacted against it. It is never rendered, logged, or passed to the
    #: service, which receives the resolved `Credential` instead.
    _presented_token: str | None = None

    #: Whether this request arrived on the OpenAI-compatible surface, which
    #: authenticates with an API key and answers errors in OpenAI's shape rather
    #: than the platform's.
    _openai_surface: bool = False

    #: The status and code of the refusal this request was answered with, so the
    #: structured log line names the real outcome rather than a guess.
    _openai_refusal: tuple[int, str] | None = None

    #: Whether a response status line has already left this handler.
    _answered: bool = False

    #: Whether this request still has body bytes nobody read, which decides
    #: whether closing the connection has to discard them first. See `finish`.
    _body_unread: bool = False

    #: The body read for this request, if any. A signed request must read the
    #: body before its handler does (the signature covers it), so the bytes are
    #: buffered here and handed back rather than read twice off the socket.
    _cached_body: bytes | None = None

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the access log: a request line carries no token, but the
        header would, and a transport that logs headers leaks credentials."""

    def handle(self) -> None:
        """Serve this connection, treating a peer reset as the connection ending.

        `BaseHTTPRequestHandler` reads the next request line at the top of its
        keep-alive loop and lets a socket error escape, which `socketserver`
        then prints as an unhandled exception. A peer that resets a finished
        connection is not an error anybody can act on: there is no request to
        answer and no client left to tell. Only `ConnectionError` is absorbed;
        every other failure still surfaces loudly.
        """
        with contextlib.suppress(ConnectionError):
            super().handle()

    def finish(self) -> None:
        """End the connection so the answer already written is what the peer reads.

        Two ways a complete, correctly framed answer still fails to reach a
        caller, both of which a reverse proxy reports to its operator as "origin
        sent an invalid response" and neither of which a test that reads the whole
        body over loopback sees:

        * closing a socket whose receive queue still holds request bytes makes
          the kernel answer with a reset rather than a FIN, and a peer that has
          not yet read the response loses it;
        * closing a TLS socket without a `close_notify` ends the record stream
          mid-session, which a TLS peer reads as a truncated response even though
          every byte of the body arrived.

        So the write side is half-closed first — unwrapping TLS, which is what
        emits `close_notify` — then anything still coming in is discarded within a
        bound, and only then does the base class close the socket.
        """
        self._half_close()
        self._discard_unread_request_body()
        super().finish()

    def _half_close(self) -> None:
        """Tell the peer this response is finished, instead of dropping the socket.

        Over TLS the signal is `close_notify`, which `unwrap` emits; over
        cleartext it is a FIN on the write side. Both leave the read side open, so
        what the peer still owes can be discarded afterwards.
        """
        with contextlib.suppress(OSError):
            self.wfile.flush()
        connection = self.connection
        previous = connection.gettimeout()
        try:
            # Bounded: a peer that sends no `close_notify` of its own must not be
            # able to hold this handler thread for the life of the connection.
            connection.settimeout(GRACEFUL_CLOSE_TIMEOUT_S)
            if isinstance(connection, ssl.SSLSocket):
                connection.unwrap()
            else:
                connection.shutdown(socket.SHUT_WR)
        except (OSError, ValueError):
            # Nothing is left to close gracefully: a peer already gone cannot be
            # told anything, and a socket whose TLS layer is already down has
            # nothing to send a `close_notify` with. The response was written.
            pass
        finally:
            with contextlib.suppress(OSError):
                connection.settimeout(previous)

    def _discard_unread_request_body(self) -> None:
        """Throw away request bytes nobody read, so the close is a FIN and not a reset.

        Bounded on both axes — `GRACEFUL_CLOSE_DRAIN_BYTES` and
        `GRACEFUL_CLOSE_TIMEOUT_S` — because the point is to leave the receive
        queue empty, not to buffer whatever a peer chooses to send. A peer that
        outruns either bound gets the reset it is causing, and by then the FIN
        from `_half_close` has already put this response on its way.
        """
        if not self._body_unread:
            return
        connection = self.connection
        previous = connection.gettimeout()
        deadline = time.monotonic() + GRACEFUL_CLOSE_TIMEOUT_S
        budget = GRACEFUL_CLOSE_DRAIN_BYTES
        try:
            while budget > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                connection.settimeout(remaining)
                try:
                    chunk = connection.recv(min(budget, 65536))
                except OSError:
                    break
                if not chunk:
                    break
                budget -= len(chunk)
        finally:
            with contextlib.suppress(OSError):
                connection.settimeout(previous)

    def do_GET(self) -> None:
        """Route the request before any endpoint-specific work happens."""
        self._dispatch()

    # Every other verb follows the same route, so a known path answers 405 with
    # an accurate Allow header instead of the base class's 501.
    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_HEAD = do_GET

    @property
    def _gw(self) -> GatewayServer:
        """The gateway that owns this connection."""
        return cast("_GatewayHTTPServer", self.server).gateway

    def _dispatch(self) -> None:
        """Resolve the route, authenticate, serve, and always answer."""
        # This handler object outlives one request: a kept-alive connection is
        # served by the same instance, so every piece of per-request state has to
        # be reset here or the next request inherits it. A stale `_answered` would
        # silence the refusal this request owes its caller, a stale buffered body
        # would be read as this request's own, and a stale presented token would
        # redact against the wrong material — which is how the credential *this*
        # request presented would survive into an error message.
        self._cached_body = None
        self._answered = False
        self._body_unread = False
        self._presented_token = None
        self._openai_refusal = None
        target = urllib.parse.urlsplit(self.path)
        self._openai_surface = target.path.startswith("/openai/")
        matched = _match_route(target.path)
        if matched is None:
            self._refuse(404, "not_found", "no endpoint matches this path")
            return
        route, parameter = matched
        allowed = _ROUTE_METHODS[route]
        if self.command not in allowed:
            self._refuse(
                405,
                "method_not_allowed",
                f"{self.command} is not allowed on this endpoint",
                headers={"Allow": ", ".join(sorted(allowed))},
            )
            return
        if route == "health":
            self._respond(200, {"status": "ok"})
            return
        try:
            if route == "join":
                # The invite code is its own credential: joining is the one
                # endpoint that must work before any identity exists.
                self._handle_join()
                return
            if self._openai_surface:
                # The OpenAI-compatible surface authenticates with an
                # operator-issued API key rather than with a credential or a
                # per-request signature, so it is routed before `_authenticate`
                # and owns its own error shape.
                self._serve_openai_route(route, parameter)
                return
            credential = self._authenticate(_ROUTE_ROLES.get(route, "consumer"))
            if credential is None:
                return
            if route == "node_link":
                self._serve_node_link(credential)
            else:
                self._serve_authenticated_route(route, parameter, credential, target.query)
        except OSError:
            # The peer went away mid-answer; there is nobody left to tell, and
            # the connection is finished either way.
            self.close_connection = True
        except Exception:
            # Last resort: the gateway answers every request it accepted. The
            # detail is a constant, so an unexpected failure cannot echo a
            # credential or an internal path back to the caller.
            self._refuse(
                500, "internal_error", "the gateway failed to answer the request"
            )

    def _handle_join(self) -> None:
        """Serve ``POST /v1/join``: redeem an invite for an identity.

        Unauthenticated by design — the invite code *is* the credential — so the
        body is validated strictly and the domain `join` owns every decision
        about whether the code is usable.

        Only ``identity.public_key_b64`` is read. Any ``subject_id``/``key_id``
        the body carries is deliberately **not** forwarded: the server derives
        the identity, so a body cannot name the identity it becomes.
        """
        body = self._json_object()
        if body is None:
            return
        try:
            invite_code = _require_body_str(body, "invite_code")
            identity_raw = body.get("identity")
            if not isinstance(identity_raw, dict):
                raise ProtocolError("identity must be a JSON object")
            identity = {
                "public_key_b64": _require_body_str(identity_raw, "public_key_b64"),
                "display_name": identity_raw.get("display_name"),
            }
            device_raw = body.get("device")
            if device_raw is not None and not isinstance(device_raw, dict):
                raise ProtocolError("device must be a JSON object or null")
            device = device_raw
        except ProtocolError as exc:
            self._fail(400, "bad_request", str(exc))
            return
        result = self._call_service(
            lambda: self._gw.service.join(
                invite_code=invite_code,
                identity=identity,
                device=device,
                center_url=self._gw.url,
            )
        )
        if result is None:
            return
        self._respond(200, result.to_payload())

    def _serve_authenticated_route(
        self, route: str, parameter: str, credential: Credential, query: str
    ) -> None:
        """Serve one authenticated, non-upgrade endpoint.

        Every route here has already passed the role check in `_dispatch`, so a
        consumer route is reached only by a consumer credential and
        ``node_attempts`` only by a node's. The domain method still re-derives
        whose data it returns from the credential, never from the request.

        Args:
            route: The route name resolved by `_match_route`.
            parameter: The path parameter for the route, empty when it has none.
            credential: The credential the header resolved to.
            query: The raw query string, for the SSE cursor.
        """
        if route == "create_request":
            self._handle_create_request(credential)
        elif route == "request_status":
            self._handle_request_status(credential, parameter)
        elif route == "request_events":
            self._handle_request_events(credential, parameter, query)
        elif route == "request_cancel":
            self._handle_request_cancel(credential, parameter)
        elif route == "receipt":
            self._handle_receipt(credential, parameter)
        elif route == "checkpoint":
            self._handle_checkpoint(credential)
        elif route == "account_history":
            self._handle_account_history(credential)
        elif route == "node_attempts":
            self._handle_node_attempts(credential)
        else:
            self._handle_nodes(credential)

    def _handle_create_request(self, credential: Credential) -> None:
        """Serve ``POST /v1/requests``."""
        body = self._json_object()
        if body is None:
            return
        try:
            admission = _AdmissionRequest.from_json(body)
        except ProtocolError as exc:
            self._fail(400, "bad_request", str(exc))
            return
        result = self._call_service(
            lambda: self._gw.service.admit_request(
                credential=credential,
                idempotency_key=admission.idempotency_key,
                messages=admission.messages,
                authorization=admission.authorization,
                model=admission.model,
                parameters=admission.parameters,
                max_charge_milli_credits=admission.max_charge_milli_credits,
                delivery_mode=admission.delivery_mode,
                max_attempts=admission.max_attempts,
                deadline_ms=admission.deadline_ms,
                session_id=admission.session_id,
            )
        )
        if result is None:
            return
        self._respond(200, {"request_id": result.request_id})

    def _handle_request_status(self, credential: Credential, request_id: str) -> None:
        """Serve ``GET /v1/requests/{id}``."""
        result = self._call_service(
            lambda: self._gw.service.request_status(credential=credential, request_id=request_id)
        )
        if result is None:
            return
        self._respond(200, result)

    def _handle_request_cancel(self, credential: Credential, request_id: str) -> None:
        """Serve ``POST /v1/requests/{id}/cancel``.

        The origin is ``consumer_cancel``, which is the wire value the domain
        accepts for a cancellation a person asked for. It is spelled out here
        rather than taken from the body: the origin decides how the ledger
        records the stop, so it must come from the endpoint, not from a caller
        that could label its own cancellation "deadline" and change what is
        billed. The domain module is what decides whether the request is still
        cancellable.
        """
        result = self._call_service(
            lambda: self._gw.service.cancel_request(
                credential=credential, request_id=request_id, origin="consumer_cancel"
            )
        )
        if result is None:
            return
        self._respond(200, result)

    def _handle_receipt(self, credential: Credential, receipt_id: str) -> None:
        """Serve ``GET /v1/receipts/{id}``."""
        result = self._call_service(
            lambda: self._gw.service.receipt_for(credential=credential, receipt_id=receipt_id)
        )
        if result is None:
            return
        self._respond(200, result)

    def _handle_checkpoint(self, credential: Credential) -> None:
        """Serve ``GET /v1/checkpoint``."""
        result = self._call_service(lambda: self._gw.service.checkpoint(credential=credential))
        if result is None:
            return
        self._respond(200, result)

    def _handle_account_history(self, credential: Credential) -> None:
        """Serve ``GET /v1/account/history``: the caller's own account history.

        The path carries no account id on purpose. An endpoint that named the
        account in the URL would have to authorise that name against the
        credential, and every such check is one more place a consumer's books
        could leak; deriving the account from the credential makes reading
        somebody else's history unexpressible rather than forbidden.
        """
        result = self._call_service(
            lambda: self._gw.service.account_history(credential=credential)
        )
        if result is None:
            return
        self._respond(200, result)

    def _handle_node_attempts(self, credential: Credential) -> None:
        """Serve ``GET /v1/node/attempts``: this node's own dispatch history."""
        result = self._call_service(
            lambda: self._gw.service.node_attempts(credential=credential)
        )
        if result is None:
            return
        self._respond(200, result)

    def _handle_nodes(self, credential: Credential) -> None:
        """Serve ``GET /v1/nodes``.

        The service contract has no node-listing method, so the operations view
        reads the registrations the service itself maintains through
        `CenterStore.connected_nodes`. The credential is still required: this is
        an authenticated view, not a public one.
        """
        del credential
        records = self._call_service(lambda: self._gw.service.store.connected_nodes())
        if records is None:
            return
        self._respond(200, {"nodes": [_node_to_json(record) for record in records]})

    def _handle_request_events(self, credential: Credential, request_id: str, query: str) -> None:
        """Serve ``GET /v1/requests/{id}/events`` as a server-sent event stream."""
        values = urllib.parse.parse_qs(query, keep_blank_values=True).get("cursor", ["0"])
        if len(values) != 1:
            self._fail(400, "bad_request", "cursor must be given at most once")
            return
        raw_cursor = values[0]
        if not raw_cursor.isdigit():
            self._fail(400, "bad_request", "cursor must be a non-negative integer")
            return
        cursor = int(raw_cursor)
        probe = self._call_service(
            lambda: self._gw.service.request_status(credential=credential, request_id=request_id)
        )
        if probe is None:
            return
        self._serve_events(credential, request_id, cursor)

    def _serve_events(self, credential: Credential, request_id: str, cursor: int) -> None:
        """Replay stored events, then stream new ones, in one SSE response."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        self._answered = True
        session = _SseSession(
            sock=self.connection,
            credential=credential,
            request_id=request_id,
            start_cursor=cursor,
            queue_size=self._gw.tuning.sse_queue_size,
            grace_s=SSE_DROP_GRACE_S,
        )
        self._gw.register_sse(session)

        def produce() -> None:
            self._sse_producer(session)

        producer = self._gw.spawn("potluck-sse-producer", produce)
        try:
            self._sse_write_loop(session)
        finally:
            session.stop()
            producer.join(timeout=_STOP_JOIN_TIMEOUT_S)
            self._gw.unregister_sse(session)
            session.dispose()

    def _sse_producer(self, session: _SseSession) -> None:
        """Poll the service and offer rendered frames to the session's buffer.

        The stream is replayed and then followed live by polling, which is why
        the interval is short and why the store, not this thread, is the source
        of truth: a reconnecting client resumes from its last cursor and cannot
        be handed a gap or a duplicate, even if this connection is dropped.

        Args:
            session: The connection to feed.
        """
        last = session.start_cursor
        last_heartbeat = time.monotonic()
        while not session.stop_event.is_set():
            now = time.monotonic()
            if now - last_heartbeat >= self._gw.tuning.sse_heartbeat_interval_s:
                if not session.offer_heartbeat():
                    return
                last_heartbeat = now
            events = self._sse_poll(session, last)
            if events is None:
                return
            if events:
                for event in events:
                    try:
                        buffered = session.offer_event(event)
                    except ProtocolError as exc:
                        session.drop(
                            _redact(
                                f"a stored event could not be framed: {exc}",
                                self._presented_token,
                            )
                        )
                        return
                    if not buffered:
                        return
                    last = event.cursor
                continue
            live, status = self._sse_status(session)
            if not live:
                return
            if status is not None:
                trailing = self._sse_poll(session, last)
                if trailing is None:
                    return
                if trailing:
                    for event in trailing:
                        if not session.offer_event(event):
                            return
                        last = event.cursor
                    continue
                session.offer_done({"request_id": session.request_id, "status": status})
                return
            if session.stop_event.wait(self._gw.tuning.sse_poll_interval_s):
                return

    def _sse_poll(self, session: _SseSession, cursor: int) -> list[StoredEvent] | None:
        """Fetch the next batch of stored events, or drop the stream on failure."""
        try:
            return self._gw.service.request_events(
                credential=session.credential,
                request_id=session.request_id,
                cursor=cursor,
                limit=_SSE_REPLAY_BATCH,
            )
        except PotluckError as exc:
            session.drop(
                _redact(f"the service failed while streaming: {exc}", self._presented_token)
            )
            return None

    def _sse_status(self, session: _SseSession) -> tuple[bool, str | None]:
        """Read the request's status for the live phase of the stream.

        Args:
            session: The connection being streamed.

        Returns:
            ``(keep_streaming, terminal_status)``. `keep_streaming` is False when
            the stream has been dropped, which is what distinguishes "the
            service failed" from "the request is still running"; conflating the
            two would leave a broken stream polling forever.
        """
        try:
            status = self._gw.service.request_status(
                credential=session.credential, request_id=session.request_id
            )
        except PotluckError as exc:
            session.drop(
                _redact(f"the service failed while streaming: {exc}", self._presented_token)
            )
            return False, None
        value = status.get("status")
        if not isinstance(value, str):
            session.drop("the request status did not report a string status field")
            return False, None
        return True, value if value in TERMINAL_REQUEST_STATES else None

    def _sse_write_loop(self, session: _SseSession) -> None:
        """Write frames to the socket until the stream ends.

        Runs on the handler thread, which is why the socket write side has
        exactly one owner. A peer that stops reading blocks this loop in the
        kernel and nothing else: the producer keeps its own buffer bounded, the
        settlement path never touches this socket, and every other connection
        has its own thread.
        """
        while True:
            ok, frame = session.buffer.take(_WRITER_POLL_S)
            if ok and frame is not None:
                try:
                    self.wfile.write(frame.encode("utf-8"))
                except OSError:
                    return
                if session.buffer.finished:
                    return
                continue
            if session.buffer.finished or session.stop_event.is_set():
                return
            if _peer_closed(self.connection):
                return

    def _serve_node_link(self, credential: Credential) -> None:
        """Upgrade an authenticated request and serve one node link."""
        try:
            connection = handshake_server(self)
        except HandshakeRefusal as refusal:
            self._fail(refusal.status, "handshake_refused", refusal.reason)
            return
        self._answered = True
        session = _NodeSession(
            server=self._gw,
            credential=credential,
            connection=connection,
            queue_size=self._gw.tuning.node_queue_size,
            read_timeout_s=self._gw.tuning.read_timeout_s,
        )
        self._gw.register_node_session(session)
        session.start()
        try:
            session.read_loop()
        finally:
            session.finish()

    def _authenticate(self, required_role: str) -> Credential | None:
        """Resolve the request's credential and check its role.

        Two schemes are accepted, and both end at the same role check:

        * ``Authorization: Bearer <token>`` — looked up through the service's
          store. This is the node and administrator path and is unchanged.
        * ``Authorization: AIPotluck-Sig ...`` — a per-request signature that
          resolves through the service's trusted registry, for a consumer that
          joined with an invite and holds only a key.

        The bearer path never reads the credential table here, and neither path
        trusts anything in the body. Every failure answers the same ``401`` with
        a constant message, so the answer cannot be used to probe which keys or
        tokens exist.

        Args:
            required_role: The role this endpoint demands.

        Returns:
            The resolved credential, or `None` after a response has been sent.
        """
        header = self.headers.get("Authorization")
        token = _bearer_token(header)
        if token is not None:
            self._presented_token = token
            credential = self._gw.service.store.resolve_credential(
                token, dt.datetime.now(dt.UTC)
            )
            if credential is None:
                self._fail(401, "unauthorized", "the presented credential is not usable")
                return None
            if credential.role != required_role:
                self._fail(403, "forbidden", f"this endpoint requires the {required_role} role")
                return None
            return credential
        parsed = parse_request_auth_header(header)
        if parsed is None:
            self._fail(
                401,
                "unauthorized",
                "an Authorization: Bearer token or AIPotluck-Sig signature is required",
            )
            return None
        return self._authenticate_signature(parsed, required_role)

    def _authenticate_signature(
        self, parsed: tuple[str, dt.datetime, str, str], required_role: str
    ) -> Credential | None:
        """Verify one ``AIPotluck-Sig`` header and resolve its credential.

        The signed payload is rebuilt here from the request line, the query and
        the body digest, so a signature cannot be re-pointed at another call.
        Every failure answers ``401`` with a constant message: the header's key
        id, nonce and signature are never echoed, and the distinct reasons the
        domain reports (unknown key, revoked key, bad signature, stale
        timestamp, spent nonce) are deliberately indistinguishable to the
        caller.

        Args:
            parsed: ``(key_id, issued_at, nonce, signature)`` from the header.
            required_role: The role this endpoint demands.

        Returns:
            The resolved credential, or `None` after a response has been sent.
        """
        key_id, issued_at, nonce, signature_b64 = parsed
        # The signature covers the body, so it must be read here. It is cached
        # for the handler, which would otherwise find the socket drained.
        if self.command in ("POST", "PUT", "PATCH"):
            body = self._read_body()
            if body is None:
                return None
        else:
            body = b""
        try:
            digest = request_body_digest(body)
        except CanonicalizationError as exc:
            self._fail(400, "bad_request", str(exc))
            return None
        target = urllib.parse.urlsplit(self.path)
        payload = request_auth_payload(
            method=self.command,
            path=target.path,
            query=target.query,
            body_digest=digest,
            key_id=key_id,
            issued_at=issued_at,
            nonce=nonce,
        )
        # Redact against the signature itself, in case a domain error ever
        # quotes it, exactly as the bearer path redacts against the token.
        self._presented_token = signature_b64
        try:
            credential = self._gw.service.authenticate_signed_request(
                payload=payload,
                key_id=key_id,
                issued_at=issued_at,
                nonce=nonce,
                signature_b64=signature_b64,
            )
        except PotluckError:
            self._fail(401, "unauthorized", "the request signature did not authenticate")
            return None
        if credential.role != required_role:
            self._fail(403, "forbidden", f"this endpoint requires the {required_role} role")
            return None
        return credential

    def _call_service(self, call: Callable[[], _T]) -> _T | None:
        """Run one service call, mapping a domain failure to a response.

        Args:
            call: The service call, capturing the credential the header resolved.

        Returns:
            The service's result, or `None` after a response has been sent.
        """
        try:
            return call()
        except PotluckError as exc:
            status, code = _status_for_error(exc)
            self._fail(status, code, str(exc))
            return None

    def _json_object(self) -> dict[str, Any] | None:
        """Read and parse the body as a strict JSON object.

        Returns:
            The parsed object, or `None` after a `400` has been sent.
        """
        body = self._read_body()
        if body is None:
            return None
        try:
            parsed = loads_strict(body)
        except CanonicalizationError as exc:
            self._fail(400, "bad_request", str(exc))
            return None
        if not isinstance(parsed, dict):
            self._fail(400, "bad_request", "the body must be a JSON object")
            return None
        return cast("dict[str, Any]", parsed)

    def _read_body(self) -> bytes | None:
        """Read the body under the size cap, refusing rather than truncating.

        An oversized body is refused before it is read when the declared length
        says so, and after at most one byte past the cap when it does not. With
        no ``Content-Length`` the body is delimited by the peer closing its
        write side, which is the only framing HTTP leaves available once chunked
        transfer coding is declined.

        The bytes are cached for this request: a signed request reads the body
        to verify its signature before the handler runs, and the handler must
        see the same bytes rather than an empty socket.

        Returns:
            The body, or `None` after a `400` has been sent.
        """
        if self._cached_body is not None:
            return self._cached_body
        declared = self.headers.get("Content-Length")
        limit = MAX_HTTP_BODY_BYTES + 1
        if declared is not None:
            text = declared.strip()
            if not text.isdigit():
                self._fail(400, "bad_request", "Content-Length must be a non-negative integer")
                return None
            if int(text) > MAX_HTTP_BODY_BYTES:
                self._fail(
                    400,
                    "payload_too_large",
                    f"the body exceeds the {MAX_HTTP_BODY_BYTES}-byte limit",
                )
                return None
            limit = int(text)
        body = self.rfile.read(limit)
        if len(body) > MAX_HTTP_BODY_BYTES:
            self._fail(
                400, "payload_too_large", f"the body exceeds the {MAX_HTTP_BODY_BYTES}-byte limit"
            )
            return None
        self._cached_body = body
        return body

    def _drain_unread_body(self) -> None:
        """Consume a request body no handler read, so keep-alive stays usable.

        A refusal can happen before anything read the body — an unknown
        credential, an unusable API key, a route that answers `405` — and those
        bytes are then still in the socket when the next request line is read,
        which parses as a malformed request rather than as the request it is.
        HTTP/1.1 leaves two ways out: drain the body, or close. Draining is the
        one that keeps a connection an SDK is reusing alive, so it is the default
        whenever the length says it is bounded; anything else closes.

        This never answers: a refusal has already been decided by the caller, and
        a second response on one connection is a protocol violation of its own.
        """
        if self.command not in ("POST", "PUT", "PATCH") or self._cached_body is not None:
            return
        declared = self.headers.get("Content-Length")
        if declared is None or not declared.strip().isdigit():
            # No length means the body is delimited by the peer closing its write
            # side, which is not something to wait for inside a response.
            self.close_connection = True
            self._body_unread = True
            return
        length = int(declared.strip())
        if length > MAX_HTTP_BODY_BYTES:
            # The handler already refused this body; its bytes are never coming
            # out of the socket in a bounded read, so the connection ends here.
            self.close_connection = True
            self._body_unread = True
            return
        try:
            drained = self.rfile.read(length)
        except OSError:
            drained = b""
        if len(drained) < length:
            # Still in the socket, and `finish` discards it before the close: a
            # refusal that leaves a peer's bytes unread is answered with a reset
            # that takes the refusal itself with it.
            self._body_unread = True

    def _respond(
        self, status: int, payload: Any, *, headers: dict[str, str] | None = None
    ) -> None:
        """Send a canonical JSON response.

        Args:
            status: The HTTP status to answer with.
            payload: The response body, which must survive canonicalization.
            headers: Extra response headers, such as ``Allow``.
        """
        self._drain_unread_body()
        body = canonicalize(payload)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self._answered = True
        if self.command != "HEAD":
            self.wfile.write(body)

    def _fail(
        self, status: int, code: str, detail: str, *, headers: dict[str, str] | None = None
    ) -> None:
        """Send an error response, or close if a response has already started.

        Args:
            status: The HTTP status to answer with.
            code: Short machine-readable error code.
            detail: Explanation, redacted against the presented token.
            headers: Extra response headers, such as ``Allow``.
        """
        if self._answered:
            self.close_connection = True
            return
        self._respond(
            status,
            {"error": code, "detail": _redact(detail, self._presented_token)},
            headers=headers,
        )

    def _refuse(
        self,
        status: int,
        code: str,
        detail: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Answer a refusal in the shape the surface it arrived on expects.

        One gateway serves two surfaces, and a client parses errors in the shape
        its own library emits: an OpenAI-compatible caller gets OpenAI's error
        object, a platform caller gets the platform's. The status and the reason
        are the same either way, so this is a rendering choice and not a second
        policy.
        """
        if self._openai_surface:
            self._openai_fail(status, code, detail, headers=headers)
        else:
            self._fail(status, code, detail, headers=headers)

    # -- the OpenAI-compatible surface ---------------------------------------

    def _serve_openai_route(self, route: str, parameter: str) -> None:
        """Serve one endpoint of the OpenAI-compatible surface.

        Every route here is authenticated by `_openai_api_key` inside the
        handler, because the material it presents is an API key rather than a
        credential or a signature and resolves to a different record.
        """
        if route == "openai_chat_completions":
            self._handle_openai_chat_completions()
        elif route == "openai_models":
            self._handle_openai_models(None)
        elif route == "openai_model":
            self._handle_openai_models(parameter)
        else:
            self._handle_openai_unsupported(parameter)

    def _openai_fail(
        self,
        status: int,
        code: str,
        message: str,
        *,
        request_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Send an error in OpenAI's shape, or close if a response has started.

        The `request_id` rides along in the body *and* in an ``x-request-id``
        header whenever the center has one, because the two answers a caller
        cannot act on are "it failed" and "it might still be running": a request
        that outlived this connection is still on the books, still settleable,
        and still verifiable by the id printed here.

        Args:
            status: The HTTP status to answer with.
            code: The machine-readable code, mapped to OpenAI's `type`.
            message: Explanation, redacted against the presented key.
            request_id: The center's request id, when one exists.
            headers: Extra response headers.
        """
        if self._answered:
            self.close_connection = True
            return
        error: dict[str, Any] = {
            "message": _redact(message, self._presented_token),
            "type": _OPENAI_ERROR_TYPE.get(code, "api_error"),
            "code": code,
            "param": None,
        }
        if request_id is not None:
            error["request_id"] = request_id
            headers = {**(headers or {}), "x-request-id": request_id}
        self._respond(status, {"error": error}, headers=headers)

    def _openai_error_frame(
        self, status: int, code: str, message: str, request_id: str | None
    ) -> None:
        """Write an error as the last frames of a stream that has already started.

        Once the `200` and the SSE headers have gone out there is no status left
        to answer with, so the failure is carried in the stream itself. `[DONE]`
        still terminates it, as it does for every other OpenAI-compatible server:
        the terminator says the stream is over, not that the completion succeeded,
        and a client whose read loop waits for it would otherwise sit on a closed
        socket wondering whether more was coming. The error frame before it is
        what says the answer is not.
        """
        error: dict[str, Any] = {
            "message": _redact(message, self._presented_token),
            "type": _OPENAI_ERROR_TYPE.get(code, "api_error"),
            "code": code,
            "param": None,
        }
        if request_id is not None:
            error["request_id"] = request_id
        with contextlib.suppress(OSError):
            self.wfile.write(b"data: " + canonicalize({"error": error}) + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n")
        self.close_connection = True

    def _openai_api_key(self) -> ApiKeyRecord | None:
        """Resolve the API key this request presented.

        Returns:
            The key record, or `None` after a `401` has been sent. One answer
            covers a missing header, another scheme, an unknown key, a revoked
            key, an expired one and one whose subject was revoked: the response
            cannot be used to probe which keys the center has issued.
        """
        token = _bearer_token(self.headers.get("Authorization"))
        if token is None:
            self._openai_fail(
                401,
                "invalid_api_key",
                "an Authorization: Bearer <api key> header is required; mint one "
                "with `potluck-server admin api-key`",
            )
            return None
        # Held only so a detail rendered back can be redacted against it. The
        # plaintext never reaches the service, which is handed the record.
        self._presented_token = token
        key = self._gw.service.store.resolve_api_key(token, dt.datetime.now(dt.UTC))
        if key is None:
            self._openai_fail(401, "invalid_api_key", "the presented API key is not usable")
            return None
        return key

    def _openai_session(self) -> str | _SessionRefused | None:
        """Read the agent session this request named, from its own header.

        A header rather than a body field, because this surface is OpenAI's and an
        agent framework driving it through the OpenAI SDK can add
        ``default_headers`` without touching anything else it sends. The
        identifier itself is the client package's: one spelling of the header name
        and one rule for what an identifier may contain, in the module both sides
        already share.

        The value is stripped before it is checked, and that is this transport's
        rule rather than leniency: RFC 9110 says whitespace around a field value
        is not part of it, while in the JSON body the signed surface reads the same
        identifier from, spaces inside a string are. Each door applies its own
        transport's parsing and then the one shared check, so an identifier that
        survives both is the same identifier whichever came in.

        Returns:
            The session identifier, `None` when the request named no session, or
            `_SESSION_REFUSED` after a `400` has been sent for one this platform
            cannot store.
        """
        raw = self.headers.get(SESSION_HEADER)
        if raw is None:
            return None
        try:
            return check_session_id(raw.strip())
        except ProtocolError as exc:
            self._openai_fail(400, "invalid_request", str(exc))
            return _SESSION_REFUSED

    def _openai_body(self) -> dict[str, Any] | None:
        """Read and parse an OpenAI-shaped request body.

        Parsed with the standard library rather than `canonical.loads_strict`.
        The strict parser refuses every fractional number, which is right for a
        payload somebody signs — an amount that can be encoded two ways is not an
        amount — and wrong for this surface, where `"temperature": 0.7` is what
        every OpenAI client sends. Duplicate keys are still refused, the body is
        still capped by `_read_body`, and anything the platform goes on to store,
        digest or forward is canonicalized at the boundary and refused there.

        Returns:
            The parsed object, or `None` after a `400` has been sent.
        """
        raw = self._read_body()
        if raw is None:
            return None
        try:
            parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
        except (ValueError, UnicodeDecodeError) as exc:
            self._openai_fail(400, "invalid_request", f"the body is not valid JSON: {exc}")
            return None
        if not isinstance(parsed, dict):
            self._openai_fail(400, "invalid_request", "the body must be a JSON object")
            return None
        return cast("dict[str, Any]", parsed)

    def _handle_openai_unsupported(self, endpoint: str) -> None:
        """Answer `404` for an OpenAI endpoint this platform does not implement.

        Named rather than left unrouted: a tool pointed at this center and asking
        for embeddings is told that the platform serves chat completions and the
        model list, instead of reading a generic `404` as a wrong base URL and
        retrying every path it can think of.
        """
        started = time.monotonic()
        key = self._openai_api_key()
        if key is None:
            self._log_openai_request(
                endpoint=f"openai_{endpoint}",
                key=None,
                model=None,
                outcome="refused:invalid_api_key",
                status=401,
                started_at=started,
            )
            return
        self._openai_fail(
            404,
            "not_supported",
            f"this center does not implement /openai/v1/{endpoint}; it serves "
            "POST /openai/v1/chat/completions and GET /openai/v1/models",
        )
        self._log_openai_request(
            endpoint=f"openai_{endpoint}",
            key=key,
            model=None,
            outcome="not_supported",
            status=404,
            started_at=started,
        )

    def _handle_openai_models(self, model_id: str | None) -> None:
        """Serve ``GET /openai/v1/models`` and ``GET /openai/v1/models/{id}``.

        The list is aggregated from the registrations the center actually holds,
        so it names what the pool can run right now rather than a catalogue
        somebody maintained. That is also why an unknown id is a `404` naming the
        models that do exist: a client that picks from this list and a client that
        guesses a name get the same truthful answer.
        """
        started = time.monotonic()
        key = self._openai_api_key()
        if key is None:
            self._log_openai_request(
                endpoint="openai_models",
                key=None,
                model=model_id,
                outcome="refused:invalid_api_key",
                status=401,
                started_at=started,
            )
            return
        records = self._call_openai_service(
            lambda: self._gw.service.store.connected_nodes()
        )
        if records is None:
            return
        models = _openai_model_documents(records)
        if model_id is not None:
            document = models.get(model_id)
            if document is None:
                self._openai_fail(
                    404,
                    "model_not_found",
                    f"no connected contribution node runs model {model_id!r}; the "
                    f"models this center can serve are {sorted(models)}",
                )
                self._log_openai_request(
                    endpoint="openai_models",
                    key=key,
                    model=model_id,
                    outcome="model_not_found",
                    status=404,
                    started_at=started,
                )
                return
            self._respond(200, document)
            self._log_openai_request(
                endpoint="openai_models",
                key=key,
                model=model_id,
                outcome="ok",
                status=200,
                started_at=started,
            )
            return
        self._respond(
            200, {"object": "list", "data": [models[name] for name in sorted(models)]}
        )
        self._log_openai_request(
            endpoint="openai_models",
            key=key,
            model=None,
            outcome="ok",
            status=200,
            started_at=started,
        )

    def _handle_openai_chat_completions(self) -> None:
        """Serve ``POST /openai/v1/chat/completions``.

        One admitted request, rendered either as a single ``chat.completion`` or
        as an SSE stream of ``chat.completion.chunk`` frames. The two differ only
        in how the same stored events are handed back: both wait for the center's
        own terminal state inside `OPENAI_WAIT_DEADLINE_S`, and both report the
        settled token counts, so a caller cannot get a different bill for asking
        for a stream.
        """
        started = time.monotonic()
        key = self._openai_api_key()
        if key is None:
            self._log_openai_request(
                endpoint="openai_chat_completions",
                key=None,
                model=None,
                outcome="refused:invalid_api_key",
                status=401,
                started_at=started,
            )
            return
        body = self._openai_body()
        if body is None:
            self._log_openai_request(
                endpoint="openai_chat_completions",
                key=key,
                model=None,
                outcome="refused:invalid_request",
                status=400,
                started_at=started,
            )
            return
        try:
            request = _OpenAiChatRequest.from_json(body)
        except ProtocolError as exc:
            self._openai_fail(400, "invalid_request", str(exc))
            self._log_openai_request(
                endpoint="openai_chat_completions",
                key=key,
                model=None,
                outcome="refused:invalid_request",
                status=400,
                started_at=started,
            )
            return
        session = self._openai_session()
        if isinstance(session, _SessionRefused):
            self._log_openai_request(
                endpoint="openai_chat_completions",
                key=key,
                model=request.model,
                outcome="refused:invalid_request",
                status=400,
                started_at=started,
            )
            return
        admitted = self._call_openai_service(
            lambda: self._gw.service.admit_api_key_request(
                api_key=key,
                messages=request.messages,
                model=request.model,
                parameters=request.parameters,
                delivery_mode="stream_strict" if request.stream else "buffered_complete",
                deadline_ms=OPENAI_REQUEST_DEADLINE_MS,
                session_id=session,
            )
        )
        if admitted is None:
            status, code = self._openai_refusal or (502, "upstream_failed")
            self._log_openai_request(
                endpoint="openai_chat_completions",
                key=key,
                model=request.model,
                outcome=f"refused:{code}",
                status=status,
                started_at=started,
            )
            return
        credential = Credential(
            tenant_id=key.tenant_id, subject_id=key.subject_id, role="consumer"
        )
        completion = _OpenAiCompletion.new(request.model)
        if request.stream:
            self._stream_openai_completion(
                credential=credential,
                completion=completion,
                request_id=admitted.request_id,
                include_usage=request.include_usage,
                key=key,
                started_at=started,
            )
        else:
            self._buffer_openai_completion(
                credential=credential,
                completion=completion,
                request_id=admitted.request_id,
                key=key,
                started_at=started,
            )


    def _call_openai_service(self, call: Callable[[], _T]) -> _T | None:
        """Run one service call for the OpenAI surface, mapping a failure to it.

        The platform's own surface maps a domain exception through
        `_status_for_error`; this one maps it through `_openai_admission_error`,
        because the codes a client reads here are OpenAI's. The status and code
        are recorded on the handler so the request's log line names the outcome it
        actually got rather than a guess.

        Returns:
            The service's result, or `None` after a response has been sent.
        """
        try:
            return call()
        except PotluckError as exc:
            status, code = _openai_admission_error(exc)
            self._openai_refusal = (status, code)
            self._openai_fail(status, code, str(exc))
            return None

    def _log_openai_request(
        self,
        *,
        endpoint: str,
        key: ApiKeyRecord | None,
        model: str | None,
        outcome: str,
        status: int,
        request_id: str | None = None,
        usage: dict[str, int] | None = None,
        started_at: float,
    ) -> None:
        """Emit the one structured line this request is represented by.

        A single canonical JSON document per request, so an operator can grep a
        center's log for one key, one subject or one model and read the token
        counts and the outcome without reconstructing them from the books. The
        key is named by its id and never by its value: the plaintext is
        credential material, and a log is exactly where such material must not
        accumulate. `latency_ms` is this connection's own view, from the first
        byte of the request to the moment the answer was decided.
        """
        counts = usage or {}
        document: dict[str, Any] = {
            "endpoint": endpoint,
            "request_id": request_id,
            "key_id": key.key_id if key is not None else None,
            "subject_id": key.subject_id if key is not None else None,
            "model": model,
            "prompt_tokens": counts.get("prompt_tokens"),
            "completion_tokens": counts.get("completion_tokens"),
            "total_tokens": counts.get("total_tokens"),
            "latency_ms": round((time.monotonic() - started_at) * 1000),
            "outcome": outcome,
            "status": status,
        }
        logger.info("%s", canonicalize(document).decode("utf-8"))

    def _openai_write_frame(self, document: dict[str, Any]) -> bool:
        """Write one SSE data frame.

        Returns:
            True when the frame went out, False when the peer is gone — which
            ends the wait rather than rendering an answer nobody is reading.
        """
        try:
            self.wfile.write(b"data: " + canonicalize(document) + b"\n\n")
            return True
        except OSError:
            return False

    def _openai_wait(
        self,
        credential: Credential,
        request_id: str,
        *,
        on_delta: Callable[[str], bool] | None,
    ) -> _OpenAiWaitResult:
        """Poll one request to a terminal state, rendering increments as they commit.

        The center's event store is the source of truth and the cursor is tracked
        here, so an increment is rendered exactly once however many polls it takes
        to notice it, and a request that produced its whole answer before the
        first poll is rendered exactly once too. Only events the center committed
        as this request's output are read: a superseded attempt's deltas are
        refused at commit time, so nothing here can splice two answers.

        Args:
            credential: The key's subject, which scopes the reads to its tenant.
            request_id: The admitted request.
            on_delta: Called with each committed increment; a `False` return
                means the peer is gone and the wait ends.

        Returns:
            How the wait ended.
        """
        deadline = time.monotonic() + OPENAI_WAIT_DEADLINE_S
        cursor = 0
        split: dict[str, int] | None = None
        parts: list[str] = []

        def drain() -> bool:
            """Render every committed event after the cursor.

            Returns:
                False when the peer has gone and the wait must end.
            """
            nonlocal cursor, split
            while True:
                events = self._gw.service.request_events(
                    credential=credential,
                    request_id=request_id,
                    cursor=cursor,
                    limit=OPENAI_EVENT_BATCH,
                )
                if not events:
                    return True
                for event in events:
                    cursor = event.cursor
                    if event.event_type == "output.delta":
                        text = str(event.payload.get("text", ""))
                        if not text:
                            continue
                        parts.append(text)
                        if on_delta is not None and not on_delta(text):
                            return False
                    elif event.event_type == "usage.final":
                        split = _measurement_split(event.payload) or split

        def ended(
            status: str | None = None,
            usage: dict[str, int] | None = None,
            error: str | None = None,
            billing_note: str | None = None,
            abandoned: bool = False,
        ) -> _OpenAiWaitResult:
            """Build the result, carrying the answer rendered so far."""
            return _OpenAiWaitResult(
                status=status,
                usage=usage,
                error=error,
                content="".join(parts),
                billing_note=billing_note,
                abandoned=abandoned,
            )

        while True:
            try:
                if not drain():
                    return ended(abandoned=True)
                status = self._gw.service.request_status(
                    credential=credential, request_id=request_id
                )
                value = status.get("status")
                if isinstance(value, str) and value in TERMINAL_REQUEST_STATES:
                    # The events committed together with the terminal state — a
                    # final delta, the usage report — are still ahead of the
                    # cursor, and an answer missing its last increment is a wrong
                    # answer rather than a short one.
                    if not drain():
                        return ended(abandoned=True)
                    note = status.get("billing_note")
                    return ended(
                        status=value,
                        usage=_openai_usage(status, split),
                        billing_note=note if isinstance(note, str) else None,
                    )
            except PotluckError as exc:
                return ended(
                    error=_redact(str(exc), self._presented_token),
                )
            if time.monotonic() >= deadline:
                return ended()
            if _peer_closed(self.connection):
                return ended(abandoned=True)
            time.sleep(DEFAULT_SSE_POLL_INTERVAL_S)

    def _buffer_openai_completion(
        self,
        *,
        credential: Credential,
        completion: _OpenAiCompletion,
        request_id: str,
        key: ApiKeyRecord,
        started_at: float,
    ) -> None:
        """Answer with one ``chat.completion`` once the request is terminal.

        The whole answer is held until the center reports it complete, which is
        what `stream: false` promises: calling this streaming would be a lie
        about how the answer was delivered.

        The log line is written before the response, so a caller that has an
        answer in hand is guaranteed the line describing it is already in the
        log. `latency_ms` therefore measures the work rather than the flush.
        """
        result = self._openai_wait(credential, request_id, on_delta=None)
        if result.abandoned:
            self.close_connection = True
            self._log_openai_request(
                endpoint="openai_chat_completions",
                key=key,
                model=completion.model,
                outcome="client_gone",
                status=0,
                request_id=request_id,
                started_at=started_at,
            )
            return
        if result.error is not None:
            status, code = 502, "upstream_failed"
            message, outcome = result.error, "refused:upstream_failed"
        elif result.status == "SUCCEEDED":
            status, code = 200, ""
            message, outcome = "", "SUCCEEDED"
        elif result.status == "FAILED":
            status, code = 502, "upstream_failed"
            message = _openai_failed_message(result.billing_note, request_id)
            outcome = "FAILED"
        else:
            status, code = 504, "deadline_passed"
            message = _openai_unfinished_message(
                result.status, result.billing_note, request_id
            )
            outcome = result.status or "deadline_passed"
        self._log_openai_request(
            endpoint="openai_chat_completions",
            key=key,
            model=completion.model,
            outcome=outcome,
            status=status,
            request_id=request_id,
            usage=result.usage,
            started_at=started_at,
        )
        if status == 200:
            self._respond(
                200,
                _openai_completion_document(completion, result.content, result.usage),
                headers={"x-request-id": request_id},
            )
        else:
            self._openai_fail(status, code, message, request_id=request_id)

    def _stream_openai_completion(
        self,
        *,
        credential: Credential,
        completion: _OpenAiCompletion,
        request_id: str,
        include_usage: bool,
        key: ApiKeyRecord,
        started_at: float,
    ) -> None:
        """Render the answer as an SSE stream of ``chat.completion.chunk`` frames.

        The `200` and the SSE headers are held until the first increment exists
        or the request is terminal, so a request that fails before producing
        anything is answered with the status it deserves — `502`, `504` — rather
        than a `200` carrying an error inside a stream. Once a frame has gone out
        there is no status left to change, and a later failure travels as an error
        frame followed by the stream's terminator.

        The frames are OpenAI's own order: the role, the content increments, the
        finish reason, and — only when the caller asked with
        `stream_options.include_usage` — a terminal frame carrying the settled
        counts.
        """
        started = False

        def begin() -> None:
            """Send the SSE headers and the role frame, once."""
            nonlocal started
            if started:
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.send_header("x-request-id", request_id)
            self.end_headers()
            self.close_connection = True
            self._answered = True
            started = True
            self._openai_write_frame(
                _openai_chunk(
                    completion,
                    delta={"role": "assistant", "content": ""},
                    finish_reason=None,
                )
            )

        def render(text: str) -> bool:
            """Write one content increment; False when the peer is gone."""
            begin()
            return self._openai_write_frame(
                _openai_chunk(completion, delta={"content": text}, finish_reason=None)
            )

        result = self._openai_wait(credential, request_id, on_delta=render)
        if result.abandoned:
            self.close_connection = True
            self._log_openai_request(
                endpoint="openai_chat_completions",
                key=key,
                model=completion.model,
                outcome="client_gone",
                status=200 if started else 0,
                request_id=request_id,
                started_at=started_at,
            )
            return
        if result.error is None and result.status == "SUCCEEDED":
            # Logged before the terminator is written, so a client that saw
            # `[DONE]` is reading a stream whose line is already in the log.
            self._log_openai_request(
                endpoint="openai_chat_completions",
                key=key,
                model=completion.model,
                outcome="SUCCEEDED",
                status=200,
                request_id=request_id,
                usage=result.usage,
                started_at=started_at,
            )
            begin()
            self._openai_write_frame(
                _openai_chunk(completion, delta={}, finish_reason="stop")
            )
            if include_usage and result.usage is not None:
                self._openai_write_frame(
                    _openai_chunk(
                        completion, delta=None, finish_reason=None, usage=result.usage
                    )
                )
            with contextlib.suppress(OSError):
                self.wfile.write(b"data: [DONE]\n\n")
            return
        if result.error is not None:
            status, code, message = 502, "upstream_failed", result.error
        elif result.status == "FAILED":
            status = 502
            code = "upstream_failed"
            message = _openai_failed_message(result.billing_note, request_id)
        else:
            status = 504
            code = "deadline_passed"
            message = _openai_unfinished_message(
                result.status, result.billing_note, request_id
            )
        if started:
            self._openai_error_frame(status, code, message, request_id)
        else:
            self._openai_fail(status, code, message, request_id=request_id)
        self._log_openai_request(
            endpoint="openai_chat_completions",
            key=key,
            model=completion.model,
            outcome=result.status or code,
            status=status,
            request_id=request_id,
            usage=result.usage,
            started_at=started_at,
        )


@dataclass(frozen=True)
class _Tuning:
    """Interval and queue sizes, read once when the server is constructed.

    Read from the module constants rather than each use, so a test can shrink an
    interval or a queue by patching the constant before building the server
    without every long-lived thread having to re-read it mid-run.
    """

    sse_poll_interval_s: float
    sse_heartbeat_interval_s: float
    sse_queue_size: int
    node_queue_size: int
    read_timeout_s: float
    tick_interval_s: float


class GatewayServer:
    """The center's HTTP, SSE and WebSocket front door.

    Construct it with the domain service, start it, and it holds the port; it
    owns no domain decision of its own. `stop` is the one method that must be
    safe to call at any moment: it closes the listener, closes every live
    connection (which wakes blocked readers and writers), stops the ticker, and
    joins its threads with bounded timeouts.
    """

    def __init__(
        self,
        service: GatewayServiceProtocol,
        *,
        config: GatewayConfig,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        """Prepare a server; nothing is bound until `start`.

        Args:
            service: The domain module's service, used through
                `GatewayServiceProtocol` only.
            config: Where to listen and how to terminate TLS. Any object
                exposing ``host``, ``port``, ``certfile`` and ``keyfile`` works,
                including the domain module's own configuration type.
            ssl_context: An explicit server-side TLS context, which takes
                precedence over ``config.certfile`` and lets a test present a
                self-signed certificate without writing it to disk.
        """
        self._service = service
        self._config = config
        self._ssl_context = ssl_context
        self._httpd: _GatewayHTTPServer | None = None
        self._stopping = threading.Event()
        self._state_lock = threading.Lock()
        self._threads: set[threading.Thread] = set()
        self._sse_sessions: set[_SseSession] = set()
        self._node_sessions: set[_NodeSession] = set()
        self._node_by_id: dict[str, _NodeSession] = {}
        self._closer = _LinkCloser()
        self.tuning = _Tuning(
            sse_poll_interval_s=DEFAULT_SSE_POLL_INTERVAL_S,
            sse_heartbeat_interval_s=SSE_HEARTBEAT_INTERVAL_S,
            sse_queue_size=self._consumer_queue_size(),
            node_queue_size=DEFAULT_NODE_QUEUE_SIZE,
            read_timeout_s=DEFAULT_READ_TIMEOUT_S,
            tick_interval_s=_TICK_INTERVAL_S,
        )

    @property
    def service(self) -> GatewayServiceProtocol:
        """The service every endpoint calls into."""
        return self._service

    @property
    def url(self) -> str:
        """Base URL of the listener, with the real port it bound.

        The host is the configured bind host, so a name that matches the
        certificate is reported as such; the port is whatever the socket
        actually bound, which is what makes ``port=0`` usable in tests.

        Raises:
            RuntimeError: If the server has not been started.
        """
        httpd = self._require_listener()
        return f"{'https' if httpd.tls_enabled else 'http'}://{self._config.host}:{self._port()}"

    @property
    def node_url(self) -> str:
        """The WebSocket URL a contribution node dials.

        Raises:
            RuntimeError: If the server has not been started.
        """
        httpd = self._require_listener()
        scheme = "wss" if httpd.tls_enabled else "ws"
        return f"{scheme}://{self._config.host}:{self._port()}/v1/node-link"

    @property
    def connected_node_count(self) -> int:
        """How many node links have completed `node.hello` and are still up."""
        with self._state_lock:
            return len(self._node_by_id)

    def start(self) -> None:
        """Bind the port, begin serving, and start the ticker.

        Raises:
            RuntimeError: If the server is already running.
            ValueError: If only one of ``certfile`` and ``keyfile`` is set.
        """
        if self._httpd is not None:
            raise RuntimeError("the gateway is already running")
        context = self._build_ssl_context()
        httpd = _GatewayHTTPServer(
            (self._config.host, self._config.port), _GatewayRequestHandler, self, context
        )
        self._httpd = httpd

        def accept() -> None:
            httpd.serve_forever(poll_interval=_SERVER_POLL_INTERVAL_S)

        self.spawn("potluck-gateway-accept", accept)
        self.spawn("potluck-gateway-ticker", self._tick_loop)
        self._closer.start()

    def stop(self) -> None:
        """Tear everything down, promptly and without raising.

        Safe to call twice, and safe to call with a stalled consumer and a node
        mid-execution: the listener stops, every live socket is shut down so the
        threads blocked on it wake, and the remaining threads are joined under a
        single bounded deadline. The closer thread is deliberately not joined:
        by construction it is the one thread that may be waiting on a peer that
        will never read again, and joining it would hand that wait back to
        `stop`. It is a daemon, so the process still exits.
        """
        self._stopping.set()
        httpd = self._httpd
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        with self._state_lock:
            sse_sessions = list(self._sse_sessions)
            node_sessions = list(self._node_sessions)
            threads = list(self._threads)
        for session in sse_sessions:
            session.force_close()
        for node in node_sessions:
            self.close_link(node.connection)
        deadline = time.monotonic() + _STOP_JOIN_TIMEOUT_S
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))

    def spawn(self, name: str, target: Callable[[], None]) -> threading.Thread:
        """Start a daemon thread that unregisters itself when it finishes.

        Args:
            name: Thread name, for a stack dump.
            target: The work to run.

        Returns:
            The started thread.
        """
        thread = threading.Thread(
            target=self._run_and_untrack, args=(target,), name=name, daemon=True
        )
        with self._state_lock:
            self._threads.add(thread)
        thread.start()
        return thread

    def register_sse(self, session: _SseSession) -> None:
        """Track an SSE connection so `stop` can close its socket."""
        with self._state_lock:
            self._sse_sessions.add(session)

    def unregister_sse(self, session: _SseSession) -> None:
        """Stop tracking an SSE connection."""
        with self._state_lock:
            self._sse_sessions.discard(session)

    def register_node_session(self, session: _NodeSession) -> None:
        """Track a node link so `stop` can close its socket."""
        with self._state_lock:
            self._node_sessions.add(session)

    def bind_node(self, session: _NodeSession, node_id: str) -> None:
        """Make `session` the owner of `node_id`.

        A second link claiming a node id takes it over and the older link is
        closed: routing by node id can only have one owner, and letting two
        links both stay open would leave the ticker guessing which one to feed.

        Args:
            session: The link that completed `node.hello`.
            node_id: The identity it advertised.
        """
        with self._state_lock:
            previous = self._node_by_id.get(node_id)
            self._node_by_id[node_id] = session
        if previous is not None and previous is not session:
            self.close_link(previous.connection)

    def close_link(
        self, connection: ServerConnection, code: int = 1000, reason: str = ""
    ) -> None:
        """Close a node link without ever blocking the calling thread.

        Args:
            connection: The link to tear down.
            code: The close code to send.
            reason: The close reason to send.
        """
        self._closer.request_close(connection, code, reason)

    def unbind_node(self, session: _NodeSession) -> None:
        """Forget a link, leaving any newer owner of the same id in place."""
        with self._state_lock:
            self._node_sessions.discard(session)
            node_id = session.node_id
            if node_id is not None and self._node_by_id.get(node_id) is session:
                del self._node_by_id[node_id]

    def _run_and_untrack(self, target: Callable[[], None]) -> None:
        """Run `target`, then drop this thread from the tracking set."""
        try:
            target()
        finally:
            with self._state_lock:
                self._threads.discard(threading.current_thread())

    def _tick_loop(self) -> None:
        """Deliver `service.tick()` output to the nodes it names, until stopped."""
        while not self._stopping.wait(self.tuning.tick_interval_s):
            try:
                deliveries = self._service.tick()
            except Exception:
                # A failing tick must not stop delivery for every other node,
                # and the transport has no second channel to report a domain
                # failure on. The next interval retries.
                continue
            for node_id, envelope in deliveries:
                with self._state_lock:
                    session = self._node_by_id.get(node_id)
                if session is not None:
                    session.enqueue(envelope)

    def _build_ssl_context(self) -> ssl.SSLContext | None:
        """Build the listener's TLS context, or `None` for cleartext.

        Raises:
            ValueError: If exactly one of ``certfile`` and ``keyfile`` is set.
        """
        if self._ssl_context is not None:
            return self._ssl_context
        certfile = self._config.certfile
        keyfile = self._config.keyfile
        if certfile is None and keyfile is None:
            return None
        if certfile is None or keyfile is None:
            raise ValueError("certfile and keyfile must be configured together")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile, keyfile)
        return context

    def _consumer_queue_size(self) -> int:
        """Return the SSE outbound queue bound.

        The frozen configuration surface names only the bind and TLS fields, but
        the domain module's configuration additionally carries the consumer
        queue bound, because the transport is the only thing that can honour it.
        It is read when present, and this module's default applies when it is
        not.

        Raises:
            ValueError: If the configured bound is below one.
        """
        size = int(getattr(self._config, "consumer_queue_size", SSE_QUEUE_SIZE))
        if size < 1:
            raise ValueError(f"consumer_queue_size must be >= 1, got {size}")
        return size

    def _require_listener(self) -> _GatewayHTTPServer:
        """Return the listener.

        Raises:
            RuntimeError: If the server has not been started.
        """
        if self._httpd is None:
            raise RuntimeError("the gateway has not been started")
        return self._httpd

    def _port(self) -> int:
        """Return the port the listener actually bound."""
        return int(self._require_listener().server_address[1])
