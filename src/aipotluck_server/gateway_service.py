"""Server gateway domain logic: admission, dispatch, events, and settlement.

This module holds every decision the server makes. It touches **no socket and
no HTTP object**: `register_node` receives an `enqueue` callback rather than a
connection, and consumer reads return plain documents. `aipotluck.gateway_server`
is the plumbing that maps HTTP and WebSocket traffic onto these calls, and it
owns no domain decisions of its own.

Trust boundaries enforced here
------------------------------
*Identity comes from the credential, never from the body.* A request body that
names another tenant or consumer is ignored, because a body is attacker
controlled and a token is not. The same holds at join time: an identity is
minted from a server-random token, so a join body that claims a ``subject_id``,
``key_id`` or tenant of its own is ignored outright.

*A valid signature is permission to speak, not permission to spend.* Before any
credit moves, the authorization's consumer must be the authenticated subject
(or a platform-signed gateway authorization), and its payer must be the account
the credential is *bound* to — its own consumer account for an invited identity,
or one covered by a live, revocable, capped `SpendGrant`. The same check runs at
admission and again inside settlement.

*Evidence is labelled, never upgraded.* A node-signed report settles as
`node_reported`; nothing here promotes it.

Restart behaviour
-----------------
Rebuilt from the store: requests, attempts, events, output commits, receipts,
settlements, the Merkle log, node records, dispatch inputs, and the ledger
(replayed from an ordered log, unless the caller injects one). Kept only in
memory and therefore lost on restart: the `enqueue` callbacks for live node
connections (restored when a node re-registers) and the offer terms map (so a
late acceptance after a restart is refused rather than trusted — the attempt row
and the request status survive, which is what lets a consumer read what
happened). Neither loss can move credit or double-bill: settlement idempotency
lives in the store.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import logging
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, cast

from aipotluck.allocation import AllocationContract
from aipotluck.canonical import (
    base64_encode,
    canonical_digest,
    canonicalize,
    loads_strict,
    verify_payload,
)
from aipotluck.errors import (
    ConflictError,
    GatewayError,
    IdentityBindingError,
    InsufficientFundsError,
    KeyRevokedError,
    PotluckError,
    ProtocolError,
    SignatureError,
    StateTransitionError,
)
from aipotluck.identity import IdentityRegistry, KeyPurpose, load_private_key
from aipotluck.ledger import Journal, Ledger, Posting
from aipotluck.records import (
    DOMAIN_REQUEST_AUTH,
    SCHEMA_AUTHORIZATION,
    BillingBasis,
    SignedRecord,
    SpendAuthorization,
    VerificationPolicy,
    new_nonce,
    signed_record_from_dict,
    verify_chain,
)
from aipotluck.settlement import SettlementEngine, SettlementResult
from aipotluck.statemachine import TERMINAL_REQUEST_STATES, RecoveryContext, decide_recovery
from aipotluck.transparency import MerkleLog
from aipotluck.wire import (
    AttemptDecision,
    AttemptEvent,
    AttemptOffer,
    AttemptRef,
    AttemptState,
    ChatMessage,
    DeliveryMode,
    Envelope,
    EventAck,
    HelloAck,
    NodeHeartbeat,
    NodeHello,
    ResumeDirective,
    check_session_id,
    compute_permit_hash,
    compute_request_digest,
    parse_chat_messages,
)

from .errors import ApiKeyRateLimited, ApiKeyUnavailable, ModelUnavailable, QueueFull
from .persistence import (
    ApiKeyRecord,
    AttemptRecord,
    Credential,
    NodeRecord,
    ReceiptRecord,
    RequestRecord,
    ServerStore,
    SettlementRecord,
    StoredEvent,
)

logger = logging.getLogger(__name__)

DEFAULT_HEARTBEAT_INTERVAL_S = 15
DEFAULT_OFFER_ACCEPT_TIMEOUT_S = 10.0
DEFAULT_DEADLINE_MS = 60_000

#: The only deadline ceiling, everywhere. Agent sessions want long windows and
#: get them — a key can carry 24 hours — but an unbounded deadline is how a
#: request that can never finish holds a concurrency slot forever, which is the
#: exact failure the terminal-state sweep exists to end. 24 hours matches the
#: industry's own batch ceilings; nothing interactive runs longer.
MAX_DEADLINE_MS = 86_400_000
DEFAULT_MAX_ATTEMPTS = 1
DEFAULT_CONSUMER_QUEUE_SIZE = 256

#: How many requests the server holds in its dispatch queue by default. A bound
#: rather than a policy: a queue with no bound is a promise to hold every request
#: that arrives until its deadline, which on a server with no nodes connected is
#: a promise to accept work it cannot do and to answer all of it with a timeout.
#: One hundred is comfortably above the per-key in-flight ceiling times any
#: plausible number of keys a small server has issued, and comfortably below the
#: point where the deadline sweep's own batch bound would stop covering the
#: queue in one pass.
DEFAULT_MAX_QUEUE_DEPTH = 100

#: How long a request that every candidate node declined waits before the server
#: asks them again, in seconds. Without it a waiting request would be re-offered
#: on every tick — four times a second — and each offer is a round trip to a node
#: that just said no. With it, a node that frees up takes the work within this
#: window, which is short against a deadline measured in tens of seconds.
QUEUE_REOFFER_BACKOFF_S = 2.0

#: The event types the server appends to a request's own stream for the dispatch
#: decisions it makes by itself. They ride the same ordered, replayable, never
#: rewritten stream a node's `output.delta` and `usage.final` do, so a consumer
#: reading ``GET /v1/requests/{id}/events`` sees the request wait and then get
#: dispatched rather than inferring it from a status change.
QUEUED_EVENT_TYPE = "request.queued"
DISPATCHED_EVENT_TYPE = "request.dispatched"

#: How many requests one deadline sweep examines per non-terminal status.
#: Bounded because the sweep runs both on the ticker's interval and at every
#: admission gate, so it must not become a full-table walk on a server with a
#: long history; a row one pass does not reach, the next one does.
DEADLINE_SWEEP_BATCH = 256

#: How far a signed request's `issued_at` may sit from the server's clock, in
#: seconds, in either direction. A window rather than a one-sided deadline so a
#: client whose clock runs slightly fast is not rejected as "from the future".
REQUEST_AUTH_WINDOW_S = 120

#: Capacity of the per-key nonce memory used to refuse a replayed request
#: signature. The memory is bucketed **by key id**: each key gets its own
#: bounded map, so a caller holding one valid key can neither evict another
#: key's spent nonce nor reopen a replay that way. The bound is per key, and a
#: replay is only possible after a key has itself presented this many distinct
#: valid signatures inside one 120s window — which is a documented limitation
#: but no longer a cross-key lever.
REQUEST_AUTH_NONCE_CAPACITY = 4096

#: Which purpose a key may carry to authenticate a request signature. Only
#: ``consumer`` qualifies: an ``operator`` purpose used to be listed here, but
#: no endpoint ever accepted it, so it was removed rather than left as a
#: capability the platform could not honour.
_REQUEST_AUTH_PURPOSES: frozenset[str] = frozenset({"consumer"})

#: The signing purpose a key gets when a join of each invite role succeeds.
_PURPOSE_BY_ROLE: dict[str, str] = {
    "consumer": "consumer",
    "node": "provider_device",
}

#: Entropy, in bytes, of the node-link token a node join mints. It matches the
#: magnitude of an operator-provisioned credential token (``openssl rand -hex
#: 24`` in the deployment runbook) and of the invite code ``admin invite``
#: prints, so an invited node's credential is no weaker than a hand-provisioned
#: one. Only its digest is ever stored.
NODE_TOKEN_BYTES = 24

#: The prefix of a plaintext API key, so a key is recognizable in a config file,
#: a client's environment, and a log line somebody is grepping for a leaked
#: secret. 43 characters of url-safe base64 follow it: 32 bytes of entropy,
#: which is what ``secrets.token_urlsafe(32)`` renders.
API_KEY_PREFIX = "ak-"

#: Entropy, in bytes, of an operator-issued API key. Only its digest is stored.
API_KEY_BYTES = 32

#: How many non-terminal requests one API key may have in flight. A ceiling
#: rather than a policy knob: the endpoint is shared by every key the server has
#: issued, so one key must not be able to occupy the server's whole dispatch.
API_KEY_MAX_IN_FLIGHT = 4

#: How many requests one API key may admit per `API_KEY_RATE_WINDOW_S`.
API_KEY_RATE_LIMIT = 60

#: The length of the rate-limit window, in seconds.
API_KEY_RATE_WINDOW_S = 60.0

#: The charge ceiling one API-key request exposes by default, in milli-credits.
#: The same default ceiling a joining consumer's own client signs for, and the
#: per-request cap is always the smaller of this and the key's remaining quota.
API_KEY_DEFAULT_MAX_CHARGE_MILLI_CREDITS = 20_000

#: The label an API key gets when a join mints it, rather than an operator
#: naming the tool that will hold it. `admin api-key-list` shows it, so an
#: operator auditing keys can tell the ones an invite issued at join from the
#: ones somebody minted by hand — which matters because only the second kind has
#: an operator who remembers choosing a quota and a deadline for it.
JOIN_API_KEY_NAME = "issued at join"

#: How much longer a server-signed authorization stays valid than the request's
#: own deadline. Settlement happens after the answer does, and an authorization
#: that expired in between would leave a node's tokens spent and unbillable.
AUTHORIZATION_SETTLEMENT_GRACE = dt.timedelta(minutes=10)

#: The pricing terms a server-signed authorization carries. These are the
#: platform's published defaults — the same rate card, billing basis and
#: evidence floor a consumer's own client signs — and a request admitted on an
#: API key cannot ask for weaker ones, because there is no consumer signature to
#: agree to them.
PRICING_VERSION = "flat-v1"
BILLING_BASIS: BillingBasis = "reported_native_usage"
MINIMUM_EVIDENCE_LEVEL: VerificationPolicy = "node_reported"
TRUST_POOL = "trusted-beta"


def _aware(moment: dt.datetime) -> dt.datetime:
    """Return `moment` as a UTC-aware instant.

    Raises:
        ValueError: If `moment` is naive, because a naive instant has no
            well-defined position on the timeline and comparing two would be
            arbitrary.
    """
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return moment.astimezone(dt.UTC)


def _dispatch_stream_id(request_id: str) -> str:
    """Return the event-stream identity for the server's own dispatch events.

    The event store orders every event by a per-request cursor but deduplicates
    replays by ``(attempt_id, attempt_seq)``, and a queue transition happens
    before any attempt exists. Rather than weaken that key, the server's own
    dispatch events are appended under one synthetic stream identity per request.

    The identity is deliberately not a row in the ``attempts`` table: no resume
    directive, no node read and no reconciliation pass can mistake it for an
    attempt a node owes work on, and its own sequences stay contiguous and
    replay-safe exactly like a real attempt's.
    """
    return f"{request_id}-dispatch"


_CANCEL_ORIGINS = frozenset(
    {
        "consumer_cancel",
        "consumer_disconnect_cancel",
        "provider_stop",
        "deadline",
        "budget_stop",
    }
)
_ACCOUNT_KINDS = frozenset(
    {
        "consumer_available",
        "consumer_reserved",
        "provider_pending",
        "provider_available",
        "platform_reserve_available",
        "settlement_payable",
        "provider_risk_reserved",
    }
)
_JOURNAL_KINDS = frozenset(
    {
        "adjustment",
        "success",
        "reservation",
        "release",
        "consumption",
        "platform_compensation",
        "refund",
    }
)
_LIVE_ATTEMPT_STATES = frozenset(
    {"OFFERED", "ACCEPTED", "AUTHORIZED", "SUBMITTING", "RUNNING"}
)


@dataclass(frozen=True)
class GatewayConfig:
    """Serializable server configuration."""

    host: str
    port: int
    database_path: str
    platform_id: str
    settlement_key_id: str
    settlement_private_key_b64: str
    offer_accept_timeout_s: float = DEFAULT_OFFER_ACCEPT_TIMEOUT_S
    consumer_queue_size: int = DEFAULT_CONSUMER_QUEUE_SIZE
    certfile: str | None = None
    keyfile: str | None = None
    #: Whether a request nothing can dispatch this instant waits instead of being
    #: refused. **On by default**, for three reasons.
    #:
    #: One: the two admission doors already disagreed. A request admitted on a
    #: signature has always waited — it is stored `ROUTING` and re-offered on
    #: every tick until a node takes it or its deadline passes — while one
    #: admitted on an API key was refused at the door. Same dispatch, same books,
    #: two different answers to the same fact about the pool. Defaulting this on
    #: is what makes the second door behave like the first rather than the
    #: reverse.
    #:
    #: Two: waiting is bounded by facts the server already keeps honest. The
    #: queue has a depth bound (`max_queue_depth`), each request still carries its
    #: own deadline, and the deadline sweep that ends an overdue request is the
    #: same sweep that has always run — so a queued request that nothing ever
    #: took still ends `EXPIRED` with the server's own reason on its billing
    #: note, and is neither billed nor reported as served.
    #:
    #: Three: contention is the condition an operator can fix, by running another
    #: node. Refusing at the door turns a two-second capacity dip into an error
    #: the caller has to notice, classify and retry, which is strictly more work
    #: for everybody and loses the requests that a short wait would have saved.
    #:
    #: Turning it off is the right answer for a server whose operator would rather
    #: shed load than hold it — a public one, where every waiting request is an
    #: open connection and a client's own backoff is a better place to decide than
    #: the server's memory. With it off, a request nothing can dispatch is refused
    #: immediately and nothing waits.
    queue_enabled: bool = True
    #: The most requests the server holds waiting for a node at once. Read at
    #: every admission gate; a request that would exceed it is refused with
    #: `QueueFull` rather than admitted to wait past any useful deadline.
    max_queue_depth: int = DEFAULT_MAX_QUEUE_DEPTH


@dataclass(frozen=True)
class AdmitResult:
    """Outcome of admitting one request."""

    request_id: str
    created: bool
    status: str
    delivery_mode: str


@dataclass(frozen=True)
class NewApiKey:
    """A freshly generated API key: its operator-facing id and its plaintext.

    The two are generated together so the two places that mint a key —
    ``admin api-key``, and a join redeeming an invite flagged
    ``InviteRecord.issues_api_key`` — cannot drift apart in either the id scheme
    or the key's entropy. The plaintext exists only in this value and in the one
    stdout line or join response that carries it away; the store keeps a digest.
    """

    key_id: str
    plaintext: str


def generate_api_key() -> NewApiKey:
    """Generate one API key, with `API_KEY_BYTES` of entropy behind the prefix."""
    return NewApiKey(
        key_id=f"apikey-{secrets.token_hex(6)}",
        plaintext=API_KEY_PREFIX + secrets.token_urlsafe(API_KEY_BYTES),
    )


@dataclass(frozen=True)
class JoinResult:
    """The identity a redeemed invite produced.

    Carries at most one secret per join role, and only once: `node_token` for a
    node, `api_key` for a consumer whose invite was minted ``--with-api-key``.
    Everything else is an identifier the server derived, which the joiner needs
    in order to know what identity (and, for a node, which device/provider ids)
    it now holds. The invite code is never echoed back, and neither is any
    private key — the joiner already holds the key it generated.
    """

    tenant_id: str
    subject_id: str
    role: str
    key_id: str
    server_url: str
    #: Derived device identifiers, present only for a node join. They are echoed
    #: back so the node can configure its connector with the ids the server
    #: actually minted.
    device_id: str | None = None
    device_key_id: str | None = None
    provider_id: str | None = None
    #: The plaintext node-link credential, present **only** on the node join that
    #: created the identity. The server stores its digest and cannot show it
    #: again, so this one response is the only channel it ever travels on — the
    #: same "shown once" contract an ``admin invite`` code has. An idempotent
    #: re-join leaves it `None` rather than minting a second credential.
    node_token: str | None = None
    #: The plaintext API key for the OpenAI-compatible surface, present **only**
    #: on the consumer join that redeemed an invite flagged ``issues_api_key``,
    #: and only on the join that created the identity. Minted here rather than
    #: pre-minted with the invite, so a code nobody has redeemed yet has no key
    #: behind it and an unredeemed invite carries no spending authority at all.
    #: Like `node_token`, only its digest is stored: this response is the one
    #: channel the plaintext ever travels on, inside the same TLS session the
    #: join arrived on, and an idempotent re-join leaves it `None` rather than
    #: minting a second key.
    api_key: str | None = None

    def to_payload(self) -> dict[str, str]:
        """Return the response document ``POST /v1/join`` answers with."""
        payload = {
            "tenant_id": self.tenant_id,
            "subject_id": self.subject_id,
            "role": self.role,
            "key_id": self.key_id,
            "server_url": self.server_url,
        }
        if self.device_id is not None:
            payload["device_id"] = self.device_id
        if self.device_key_id is not None:
            payload["device_key_id"] = self.device_key_id
        if self.provider_id is not None:
            payload["provider_id"] = self.provider_id
        if self.node_token is not None:
            payload["node_token"] = self.node_token
        if self.api_key is not None:
            payload["api_key"] = self.api_key
        return payload


def derive_allocation_contract(
    *, request_id: str, provider_id: str, epoch: int
) -> AllocationContract:
    """Derive the allocation contract for one attempt from persisted fields.

    This release gives the whole bill to the offered provider. Every input is
    stored — the request id is the requests primary key, and the provider and
    epoch live on the attempt row — so a rebuilt service hashes the same bytes a
    settlement replay expects.

    Args:
        request_id: The owning request.
        provider_id: The offered provider, who receives the credit.
        epoch: The attempt's dispatch epoch, which becomes the contract version.

    Returns:
        The contract.
    """
    return AllocationContract(
        contract_id=f"alloc-{request_id}",
        version=max(1, epoch),
        weights={provider_id: 100},
    )


class GatewayService:
    """Server-side domain logic over durable state.

    Deliberately not a dataclass: construction replays durable state into
    in-memory objects, which is behaviour worth owning in one place.
    """

    def __init__(
        self,
        *,
        config: GatewayConfig,
        store: ServerStore,
        registry: IdentityRegistry,
        ledger: Ledger | None = None,
        now: dt.datetime | None = None,
    ) -> None:
        """Build a service over durable state.

        Args:
            config: Server configuration.
            store: The durable authority for everything but live connections.
            registry: Trusted keys. The settlement key must already be
                registered under the platform settlement role.
            ledger: Injected ledger, for tests that fund their own books. When
                omitted the ledger is rebuilt from the store's replay log.
            now: The instant this service considers itself started, used as the
                fallback for operations that pass no time of their own.

        Raises:
            GatewayError: If the stored log leaves are not contiguous, which
                means the transparency log cannot be trusted.
        """
        self._config = config
        self._store = store
        self._registry = registry
        self._lock = threading.RLock()
        self._default_now = now
        #: node_id -> the enqueue callback of its live connection.
        self._enqueues: dict[str, Callable[[Envelope], None]] = {}
        #: request_id -> nodes that declined work on it, so a replacement offer
        #: goes somewhere it might be accepted. Lost on restart, which only
        #: risks sending a retry back to a refuser.
        self._declined: dict[str, set[str]] = {}
        #: key_id -> the nonces that key has spent, each map an LRU bounded by
        #: `REQUEST_AUTH_NONCE_CAPACITY`. Bucketing by key means a busy key can
        #: only evict its *own* nonces; it cannot push another key's spent nonce
        #: out and so reopen a replay. Deliberately in-memory: the 120s
        #: acceptance window makes a persistent table unnecessary for
        #: correctness within one process, and a restart only forgets nonces old
        #: enough to have fallen outside that window.
        self._nonces: dict[str, OrderedDict[str, None]] = {}
        self._nonce_lock = threading.Lock()
        #: key_id -> the monotonic instants of the requests that key admitted
        #: inside the rate window. Bounded by the window itself: an entry older
        #: than `API_KEY_RATE_WINDOW_S` is dropped before the count is read, so a
        #: key that stops calling costs nothing and a key that floods cannot grow
        #: this map past its own limit. Deliberately in-memory — a rate limit is a
        #: decision about the load arriving now, not a fact about the books.
        self._api_key_windows: dict[str, deque[float]] = {}
        self._api_key_rate_lock = threading.Lock()
        self._log = self._rebuild_log()
        self._ledger = ledger if ledger is not None else self._rebuild_ledger()
        self._settlement_key = load_private_key(config.settlement_private_key_b64)
        self._engine = self._build_engine()

    # -- construction -------------------------------------------------------

    def _build_engine(self) -> SettlementEngine:
        """Build a settlement engine over the current ledger, log and store.

        The receipt sequence continues across a rebuild instead of restarting:
        a receipt id is ``R-<counter>``, so an engine that began again at 1
        would mint ``R-1`` for a new request and collide with the receipt the
        previous run stored, refusing the settlement as a conflict. One
        settlement appends exactly one log leaf, so the durable count of issued
        receipts is the log size, and the previous receipt hash is the newest
        leaf's hash so the receipt hash chain stays unbroken.
        """
        leaves = self._store.log_leaves()
        engine = SettlementEngine(
            ledger=self._ledger,
            registry=self._registry,
            log=self._log,
            platform_id=self._config.platform_id,
            settlement_key_id=self._config.settlement_key_id,
            _receipt_counter=self._store.log_size(),
        )
        engine.resume_chain(leaves[-1].receipt_hash if leaves else None)
        return engine

    def _resync_books(self) -> None:
        """Rebuild the in-memory ledger, log and settlement engine from the store.

        `SettlementEngine.settle` mutates the in-memory ledger and log *before*
        the store records the result, so a persistence failure would otherwise
        leave the process ahead of its durable state: the next settlement would
        mint a log index and a receipt-hash chain link the store does not agree
        with, and `receipt_for` would serve a proof for the wrong leaf. Rebuilding
        from the store drops exactly the movement that was never recorded and
        re-derives the engine, whose settled-result cache is then empty so a
        retry re-runs settlement from scratch.

        Every ledger mutation this service makes is journalled in the store's
        replay log and the transparency log is rebuilt from its leaves, so the
        rebuilt books equal the durable ones; nothing else is needed to make the
        rebuild exact.
        """
        self._ledger = self._rebuild_ledger()
        self._log = self._rebuild_log()
        self._engine = self._build_engine()

    def _rebuild_log(self) -> MerkleLog:
        """Replay the stored leaves into a fresh log, refusing a gap.

        Raises:
            GatewayError: If the leaf indices are not exactly ``0..n-1``. A gap
                means part of the log is missing, and a proof over the rest
                would vouch for a history nobody can inspect.
        """
        leaves = self._store.log_leaves()
        indices = [leaf.log_index for leaf in leaves]
        if indices != list(range(len(indices))):
            raise GatewayError(
                f"stored log leaves are not contiguous: {indices[:8]}...; "
                "refusing to serve proofs over an incomplete log"
            )
        log = MerkleLog()
        for leaf in leaves:
            log.append(leaf.receipt_hash, leaf.committed_at)
        return log

    def _rebuild_ledger(self) -> Ledger:
        """Replay the ordered ledger log into a fresh ledger.

        Raises:
            GatewayError: If the log carries an event kind this build does not
                know. Skipping an unknown kind would silently replay a different
                set of books.
        """
        ledger = Ledger()
        for _seq, kind, payload in self._store.ledger_events():
            if kind == "issue":
                # `.get`, not `[...]`: a row written by an older build (or a
                # corrupted one) that lacks `account_kind` must fail closed as a
                # GatewayError this build can name, not as a bare KeyError —
                # exactly the defect a rebuild surfaced once when a provider
                # account's creation event omitted the kind.
                issue_kind = self._account_kind(payload.get("account_kind"))
                ledger.issue(
                    str(payload["account_id"]),
                    cast(Any, issue_kind),
                    int(payload["amount"]),
                )
            elif kind == "account":
                open_kind = self._account_kind(payload.get("account_kind"))
                ledger.account(str(payload["account_id"]), cast(Any, open_kind))
            elif kind == "fund_reserve":
                ledger.fund_reserve(int(payload["amount"]))
            elif kind == "journal":
                ledger.post(self._journal_from_payload(payload))
            else:
                raise GatewayError(
                    f"unknown ledger replay event kind {kind!r}; refusing to rebuild "
                    "books that this build cannot interpret"
                )
        return ledger

    def _account_kind(self, value: object) -> str:
        """Validate an account kind from the replay log.

        Raises:
            GatewayError: If the kind is not one this build recognises.
        """
        kind = str(value)
        if kind not in _ACCOUNT_KINDS:
            raise GatewayError(f"unknown account kind {kind!r} in the ledger replay log")
        return kind

    def _journal_from_payload(self, payload: dict[str, Any]) -> Journal:
        """Rebuild a journal from its stored payload.

        Raises:
            GatewayError: If the payload is malformed.
        """
        postings = tuple(Posting(str(a), int(d)) for a, d in payload["postings"])
        key = tuple(str(part) for part in payload["idempotency_key"])
        if len(key) != 3:
            raise GatewayError(f"malformed idempotency key {key!r}")
        kind = str(payload["kind"])
        if kind not in _JOURNAL_KINDS:
            raise GatewayError(f"unknown journal kind {kind!r}")
        return Journal(
            journal_id=str(payload["journal_id"]),
            idempotency_key=(key[0], key[1], int(key[2])),
            kind=cast(Any, kind),
            postings=postings,
            service_unit_id=payload.get("service_unit_id"),
        )

    # -- properties ---------------------------------------------------------

    @property
    def store(self) -> ServerStore:
        """The durable store."""
        return self._store

    @property
    def log(self) -> MerkleLog:
        """The transparency log, rebuilt across restarts."""
        return self._log

    @property
    def engine(self) -> SettlementEngine:
        """The settlement engine."""
        return self._engine

    def balance(self, account_id: str) -> int:
        """Return an account's balance, for operator views and status reads.

        The ledger is the authority for balances; this accessor exists so the
        HTTP layer never reaches into the service's private state.
        """
        return self._ledger.balance(account_id)
    # -- operator actions ---------------------------------------------------

    def fund_account(
        self,
        *,
        account_id: str,
        kind: str,
        amount: int,
        now: dt.datetime | None = None,
    ) -> None:
        """Mint demo credit into an account, as an explicit operator action.

        Args:
            account_id: The account to fund.
            kind: The account kind to create if absent.
            amount: Milli-credits to mint.
            now: Operation time; defaults to now.

        Raises:
            GatewayError: If `kind` is not an account kind this build recognises.
        """
        moment = now or self._moment()
        validated = self._account_kind(kind)
        with self._lock:
            self._ledger.issue(account_id, cast(Any, validated), amount)
            self._record_ledger(
                "issue",
                {"account_id": account_id, "account_kind": validated, "amount": amount},
                moment,
            )

    # -- admission identity: join and per-request signatures -----------------

    def join(
        self,
        *,
        invite_code: str,
        identity: dict[str, Any],
        device: dict[str, Any] | None,
        server_url: str,
        now: dt.datetime | None = None,
    ) -> JoinResult:
        """Redeem an invite and mint a server-derived identity for the joiner.

        Why the invite code and not a pre-provisioned token: the point of an
        invite is that the *only* thing an operator hands over is the code.

        **Identity is derived here, not accepted from the body.** The only
        authoritative input is the joiner's public key (and, for a node, the
        device's public key). ``subject_id``, ``key_id``, ``tenant_id``,
        ``device_id`` and ``provider_id`` are all minted from a fresh
        server-random token, so a caller who names another identity in the body
        gains nothing: a body that still carries ``subject_id`` or ``key_id`` is
        ignored outright. This is what closes the impersonation hole where a
        joiner could set ``subject_id`` to an existing, funded account name and
        receive that account's tenant.

        A consumer join also mints the identity's own credit account and funds
        it once, from the invite's quota, so the one-command ``join`` then
        ``ask`` path has something to spend without an operator funding each
        account by hand.

        A node join likewise mints the node's own link credential and registers
        it in the credential table, so the invited node can dial ``/v1/node-link``
        without an operator hand-writing a ``credentials[]`` entry and
        restarting the server. The plaintext is returned once, in this response,
        and only its digest is stored — an operator who lost it cannot read it
        back, and the recovery path is ``admin revoke-key`` plus a fresh invite.

        A consumer join on an invite flagged ``issues_api_key``
        (``admin invite --role consumer --with-api-key``) additionally mints an
        API key for the OpenAI-compatible surface, bound to the identity this
        join derived, capped by the invite's quota, and returned once in this
        response — so a tool that speaks OpenAI's API can be pointed at the pool
        with no operator round trip. Three properties are the security contract
        here, and none of them is incidental:

        * **An unredeemed invite can spend nothing.** The key is minted at this
          moment and not before; there is no key row, no subject and no quota
          behind a code nobody has joined with, so a leaked code is still only a
          way to join.
        * **The key is a separate credential from the identity.** Revoking it
          (``admin api-key-revoke``) withdraws one tool and leaves the identity
          signing requests; revoking the identity (``admin revoke-key``)
          withdraws the identity and every key it holds.
        * **Admission strength is unchanged.** A request on this key is
          authorized by the server's own settlement key as
          ``gateway_authenticated``, exactly like a key an operator minted by
          hand, and never as a consumer signature. Receipts keep telling the two
          apart; a key issued at join is not a stronger credential for having
          arrived with an identity.

        Idempotency is keyed on the public key, not on the invite's remaining
        uses: a re-join presenting a key this server already minted returns the
        existing identity and does **not** consume another use, re-fund the
        account, mint a second node credential, or mint a second API key. This
        holds even after a single-use code is spent — the identity, not the code,
        stays authoritative once it exists — while an unknown code still fails
        closed.

        Args:
            invite_code: The plaintext code from ``potluck admin invite``.
            identity: Mapping with ``public_key_b64`` and an optional
                ``display_name``. Any ``subject_id``/``key_id`` it carries is
                ignored.
            device: For a node invite, a mapping with ``public_key_b64`` (the
                device's key); `None` for consumer invites. Any ids it carries
                are ignored.
            server_url: The server's public URL, echoed back to the joiner.
            now: The join instant; defaults to the wall clock.

        Returns:
            The minted (or pre-existing) identity. `node_token` is set only on
            the node join that created it, and `api_key` only on the consumer
            join that redeemed a key-issuing invite and created the identity; a
            re-join carries neither, because the server kept the digest and
            cannot reproduce the plaintext.

        Raises:
            ProtocolError: If the invite is unusable, the identity names no
                public key, or the request shape does not match the invite role.
            ConflictError: If a store uniqueness invariant would be violated.
        """
        moment = now or dt.datetime.now(dt.UTC)
        public_key_b64 = str(identity.get("public_key_b64", ""))
        display_name_raw = identity.get("display_name")
        display_name = None if display_name_raw is None else str(display_name_raw)
        if not public_key_b64:
            raise ProtocolError(
                "identity needs a public_key_b64; every other identity field is "
                "derived by the server and never read from the body"
            )
        with self._lock:
            invite = self._store.get_invite(invite_code)
            if invite is None:
                raise ProtocolError("the invite code is not valid or is not usable")
            role = str(invite.role)
            if role not in _PURPOSE_BY_ROLE:
                raise ProtocolError(f"the invite names an unknown role {role!r}")
            self._check_join_shape(role=role, device=device)
            purpose = cast("KeyPurpose", _PURPOSE_BY_ROLE[role])
            # A re-join of an identity this server already minted is decided
            # before the invite's remaining uses are consulted, and is keyed on
            # the public key because the derived key id is fresh on every join.
            # The invite gates *creating* an identity; once created, the
            # identity (and the key revocation that governs it) is what stays
            # authoritative, so re-running `join` with a spent single-use code
            # is free rather than refused. An unknown code still fails closed.
            existing = self._store.find_identity_by_public_key(public_key_b64, role)
            if existing is not None:
                return JoinResult(
                    tenant_id=existing.tenant_id,
                    subject_id=existing.owner_id,
                    role=existing.role,
                    key_id=existing.key_id,
                    server_url=server_url,
                )
            if not invite.is_redeemable_at(moment):
                raise ProtocolError("the invite code is not valid or is not usable")
            token = secrets.token_hex(6)
            key_id = f"{role}-{token}"
            subject_id = f"{role}-{token}"
            tenant_id = (
                invite.tenant_scope if invite.tenant_scope != "auto" else f"t-{token}"
            )
            device_row = self._derive_device_row(
                role=role, device=device, token=token,
                joined_public_key_b64=public_key_b64,
            )
            # Register the keys, then consume the invite, then persist the
            # identity. A binding conflict therefore happens *before* the invite
            # is spent, so a refused join does not burn a use. Any failure after
            # a key is registered withdraws that key again, so a half-finished
            # join cannot leave a registry key with no identity row behind it.
            registered_key_ids: list[str] = []
            # The node's link credential, minted below. It stays `None` unless
            # `add_credential` returned, so a failed join never leaves a usable
            # token registered — and because that call is the *last* step of the
            # try block, a success has nothing after it that could fail and need
            # the token withdrawn again.
            node_token: str | None = None
            # The consumer's API key, minted below when the invite asked for one.
            # It stays `None` unless `add_api_key` returned, for the same reason
            # as the node token: a failed join must not leave a usable key
            # registered that no response ever showed anybody.
            api_key: str | None = None
            try:
                self._registry.register_key(
                    key_id, subject_id, purpose, public_key_b64, moment
                )
                registered_key_ids.append(key_id)
                if device_row is not None:
                    self._registry.register_device_key(
                        key_id=device_row["device_key_id"],
                        device_id=device_row["device_id"],
                        provider_id=device_row["provider_id"],
                        public_key_b64=device_row["public_key_b64"],
                        registered_at=moment,
                    )
                    registered_key_ids.append(device_row["device_key_id"])
                self._store.consume_invite(invite_code, at=moment)
                self._store.add_identity(
                    key_id=key_id,
                    owner_id=subject_id,
                    purpose=str(purpose),
                    public_key_b64=public_key_b64,
                    tenant_id=tenant_id,
                    role=role,
                    display_name=display_name,
                    provider_id=None,
                    registered_at=moment,
                    account_id=subject_id if role == "consumer" else None,
                    tenant_scope=invite.tenant_scope,
                )
                if device_row is not None:
                    self._store.add_identity(
                        key_id=device_row["device_key_id"],
                        owner_id=device_row["device_id"],
                        purpose="provider_device",
                        public_key_b64=device_row["public_key_b64"],
                        tenant_id=tenant_id,
                        role="node",
                        display_name=None,
                        provider_id=device_row["provider_id"],
                        registered_at=moment,
                        account_id=device_row["provider_id"],
                        tenant_scope=invite.tenant_scope,
                    )
                if role == "consumer" and invite.quota_milli_credits > 0:
                    self.fund_account(
                        account_id=subject_id,
                        kind="consumer_available",
                        amount=invite.quota_milli_credits,
                        now=moment,
                    )
                if role == "consumer" and invite.issues_api_key:
                    # The invite asked for a key, so the key is minted here, at
                    # the moment the identity it belongs to comes into existence
                    # — never before. Until this line runs there is no key row,
                    # no subject and no spending authority behind the code, which
                    # is what keeps an unredeemed invite (or a leaked one) worth
                    # exactly what it looks like: a way to join.
                    #
                    # The key is bound to the identity this join derived and
                    # capped by the invite's own quota, so it can spend only the
                    # account the join just funded. It is a separate credential
                    # from that identity: `admin api-key-revoke` withdraws this
                    # key alone, while `admin revoke-key` withdraws the identity
                    # and, through it, every key the identity holds. It carries no
                    # expiry and no deadline of its own, so it lives as long as
                    # the identity and each request on it gets the surface's own
                    # default window.
                    #
                    # This is the last step of the consumer path, exactly as the
                    # credential mint below is the last of the node path: nothing
                    # after it can fail and leave a plaintext key registered that
                    # no response ever carried away.
                    minted_key = generate_api_key()
                    self._store.add_api_key(
                        minted_key.plaintext,
                        key_id=minted_key.key_id,
                        name=JOIN_API_KEY_NAME,
                        subject_id=subject_id,
                        tenant_id=tenant_id,
                        quota_milli_credits=invite.quota_milli_credits,
                        created_at=moment,
                    )
                    api_key = minted_key.plaintext
                if role == "node":
                    # An invited node dials ``/v1/node-link`` with a bearer
                    # token, so the join that creates its identity also
                    # provisions that credential — bound to the identity this
                    # join derived, and stored as a digest only, exactly as the
                    # operator-provisioned `credentials[]` path stores one.
                    # Without it the invited node could authenticate nowhere and
                    # the operator would be back to hand-editing server.json.
                    #
                    # The device this join derived rides along in the row: this
                    # is the only moment the server knows the credential and the
                    # device belong together, since the two identity rows share
                    # nothing but a tenant, and a tenant is shared by every
                    # member an operator invited into it. A node-scoped read
                    # derives its scope from this binding, which is what keeps
                    # one contributor's token out of another contributor's books.
                    assert device_row is not None  # `_check_join_shape` guarantees this
                    minted = secrets.token_urlsafe(NODE_TOKEN_BYTES)
                    self._store.add_credential(
                        minted,
                        tenant_id,
                        subject_id,
                        "node",
                        moment,
                        device_id=device_row["device_id"],
                    )
                    node_token = minted
            except Exception:
                for registered in registered_key_ids:
                    with contextlib.suppress(PotluckError):
                        self._registry.revoke_key(registered, moment)
                raise
            return JoinResult(
                tenant_id=tenant_id,
                subject_id=subject_id,
                role=role,
                key_id=key_id,
                server_url=server_url,
                device_id=device_row["device_id"] if device_row else None,
                device_key_id=device_row["device_key_id"] if device_row else None,
                provider_id=device_row["provider_id"] if device_row else None,
                node_token=node_token,
                api_key=api_key,
            )

    def _check_join_shape(self, *, role: str, device: dict[str, Any] | None) -> None:
        """Refuse a join whose body does not match the invite's role.

        Raises:
            ProtocolError: If a node invite carries no device block, or a
                consumer invite carries one.
        """
        if role == "node":
            if device is None:
                raise ProtocolError("a node invite requires a device block")
        elif device is not None:
            raise ProtocolError("a consumer invite must not carry a device block")

    def _derive_device_row(
        self,
        *,
        role: str,
        device: dict[str, Any] | None,
        token: str,
        joined_public_key_b64: str,
    ) -> dict[str, str] | None:
        """Derive a node invite's device row from the joiner's device key.

        Every identifier is server-derived from the same token as the node's own
        identity, so a device block that names a ``device_id``/``provider_id``
        of its own has no effect. The device's public key is taken from the
        block when present, otherwise the node's own key is reused, so a node
        may contribute with one key.

        Args:
            role: The invite role.
            device: The device block, or `None`.
            token: The server-random token this join minted.
            joined_public_key_b64: The node's own public key, used when the
                device block names no key material of its own.

        Returns:
            The derived device row's fields, or `None` for a non-node invite.
        """
        if role != "node":
            return None
        assert device is not None  # `_check_join_shape` guarantees this
        return {
            "device_id": f"dev-{token}",
            "device_key_id": f"device-{token}",
            "provider_id": f"prov-{token}",
            "public_key_b64": str(device.get("public_key_b64") or joined_public_key_b64),
        }

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
        """Authenticate a request signed with the ``AIPotluck-Sig`` header.

        This is the second authentication path, alongside the bearer token. It
        exists so an invited consumer authenticates with the key it generated at
        join time rather than a token an operator must keep configuring. The
        checks are ordered cheapest-first and all fail closed:

        1. the key resolves in the trusted registry;
        2. its purpose is a request-signing one (``consumer``) and it is valid
           now (not revoked);
        3. the signature verifies over the canonical `payload`;
        4. `issued_at` is within `REQUEST_AUTH_WINDOW_S` of `now`;
        5. the nonce has not been spent by this key (bounded per-key LRU, see
           `REQUEST_AUTH_NONCE_CAPACITY`).

        Only then is the identity row read for the tenant and role. The nonce is
        claimed before the tenant/role are read, so a request that fails later
        still cannot be replayed. The row's own ``revoked_at`` is honoured too,
        so `potluck admin revoke-key` — which writes the store, not the running
        registry — stops a key without waiting for a restart.

        Args:
            payload: The canonical payload from
                `aipotluck.records.request_auth_payload`.
            key_id: The registry id the header named.
            issued_at: The instant the header claimed.
            nonce: The single-use value from the header.
            signature_b64: The base64 signature from the header.
            now: The server's clock; defaults to the wall clock.

        Returns:
            The credential the signature authenticates, carrying the account the
            identity is bound to so admission can bind the payer to it.

        Raises:
            UnknownKeyError: If the key is not registered.
            IdentityBindingError: If the key's purpose is not request-signing, or
                it has no matching identity row.
            KeyRevokedError: If the key is not valid at `now`.
            SignatureError: If the signature does not verify.
            ProtocolError: If `issued_at` is outside the window, or the nonce was
                already used.
        """
        moment = now or dt.datetime.now(dt.UTC)
        key = self._registry.get_key(key_id)
        if key.purpose not in _REQUEST_AUTH_PURPOSES:
            raise IdentityBindingError(
                f"key {key_id} is a {key.purpose!r} key and may not authenticate "
                "a consumer request"
            )
        if not key.is_valid_at(moment):
            raise KeyRevokedError(f"key {key_id} is not valid at {moment.isoformat()}")
        if not verify_payload(DOMAIN_REQUEST_AUTH, dict(payload), signature_b64, key.public_key()):
            raise SignatureError("the request signature does not verify")
        skew = abs((_aware(moment) - _aware(issued_at)).total_seconds())
        if skew > REQUEST_AUTH_WINDOW_S:
            raise ProtocolError(
                f"the request timestamp is {skew:.0f}s from the server clock, "
                f"outside the {REQUEST_AUTH_WINDOW_S}s window"
            )
        self._claim_nonce(key_id, nonce)
        identity = self._store.get_identity(key_id)
        if identity is None or identity.owner_id != key.owner_id:
            raise IdentityBindingError(
                f"key {key_id} has no registered identity this server trusts"
            )
        # The store row, not only the in-memory registry, governs revocation:
        # `potluck admin revoke-key` writes to the store, so reading the row's
        # `revoked_at` here is what makes a revocation bite a running server
        # without a restart. The registry check above still covers a key revoked
        # in memory (as a rebuilt server does when it replays a revoked row).
        if identity.revoked_at is not None and _aware(moment) >= _aware(identity.revoked_at):
            raise KeyRevokedError(f"key {key_id} is not valid at {moment.isoformat()}")
        return Credential(
            tenant_id=identity.tenant_id,
            subject_id=key.owner_id,
            role=cast(Any, identity.role),
            account_id=identity.account_id,
        )

    def _claim_nonce(self, key_id: str, nonce: str) -> None:
        """Record a nonce as spent for one key, refusing a replay.

        Each key has its own bounded, least-recently-used bucket, so a caller
        with one valid key cannot evict another key's spent nonce by flooding
        its own. A replayed nonce is moved to the end on first sight, so the
        entries dropped are the ones that key itself has not touched longest.

        Raises:
            ProtocolError: If this key already spent this nonce.
        """
        with self._nonce_lock:
            bucket = self._nonces.get(key_id)
            if bucket is None:
                bucket = OrderedDict()
                self._nonces[key_id] = bucket
            if nonce in bucket:
                raise ProtocolError("this nonce has already been used")
            bucket[nonce] = None
            bucket.move_to_end(nonce)
            while len(bucket) > REQUEST_AUTH_NONCE_CAPACITY:
                bucket.popitem(last=False)

    # -- consumer operations ------------------------------------------------

    def admit_request(
        self,
        *,
        credential: Credential,
        idempotency_key: str,
        messages: Sequence[ChatMessage],
        authorization: SignedRecord | dict[str, Any],
        model: str,
        max_charge_milli_credits: int,
        parameters: Mapping[str, Any] | None = None,
        delivery_mode: str = "buffered_complete",
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        deadline_ms: int = DEFAULT_DEADLINE_MS,
        session_id: str | None = None,
        now: dt.datetime | None = None,
    ) -> AdmitResult:
        """Admit one request, enforcing the authority chain before any dispatch.

        Args:
            credential: The authenticated consumer.
            idempotency_key: Client key, scoped to the tenant.
            messages: The conversation to run, forwarded to the upstream as it
                stands; nothing here flattens it into one prompt.
            authorization: The consumer's signed pre-authorization, either as a
                record or as the serialized form a client sent.
            model: The model being requested.
            max_charge_milli_credits: The ceiling this admission exposes; it may
                not exceed the cap the consumer signed.
            parameters: The forwarded request parameters, in the canonical-safe
                encoding `wire.encode_chat_parameters` produces.
            delivery_mode: `buffered_complete` or `stream_strict`.
            max_attempts: Hard attempt cap.
            deadline_ms: Wall-clock budget from admission.
            session_id: The agent session this turn belongs to, or `None`. A
                label rather than a credential, and deliberately outside the
                signed `request_digest`: the aggregate it feeds is keyed by the
                tenant and subject this credential authenticated, so naming
                somebody else's session attributes nothing to them.

        Returns:
            The admission result. `created=False` means an idempotent replay,
            which creates no attempt and re-offers nothing.

        Raises:
            IdentityBindingError: If the authorization names a consumer the
                credential does not authenticate, or the payer is not covered.
            ProtocolError: If the submitted ``messages``/``model``/
                ``delivery_mode``/``parameters`` do not reproduce the
                authorization's ``request_digest``, if `max_attempts` or
                `max_charge_milli_credits` exceeds the signed cap, if `model` is
                outside the signed allowlist, if the attempt budget and deadline
                are not positive, or if `session_id` is not an identifier the
                wire accepts.
            QueueFull: If the server's dispatch queue is at its bound and this
                idempotency key names no request the server already admitted.
            ConflictError: On a reused idempotency key with different content.
        """
        moment = now or self._moment()
        if max_attempts < 1:
            raise ProtocolError(f"max_attempts must be >= 1, got {max_attempts}")
        if deadline_ms < 1:
            raise ProtocolError(f"deadline_ms must be >= 1, got {deadline_ms}")
        if deadline_ms > MAX_DEADLINE_MS:
            raise ProtocolError(
                f"deadline_ms {deadline_ms} is beyond the {MAX_DEADLINE_MS} ms "
                "ceiling; a request that cannot finish inside a day cannot "
                "finish, and its slot would never free"
            )
        session = None if session_id is None else check_session_id(session_id)
        self._sweep_before_admission(moment)
        record = _coerce_record(authorization)
        if record.schema != SCHEMA_AUTHORIZATION:
            raise GatewayError(f"expected a spend authorization, got {record.schema}")
        payload = dict(record.payload)
        consumer_id = str(payload.get("consumer_id", ""))
        payer_account_id = str(payload.get("payer_account_id", ""))
        if not consumer_id:
            raise IdentityBindingError(
                "the authorization names no consumer_id, so it cannot be bound to "
                "a credential"
            )
        if not payer_account_id:
            raise IdentityBindingError("the authorization names no payer_account_id")
        auth_method = str(payload.get("auth_method", "consumer_signed"))
        # Identity comes from the token, never the body. The one documented
        # exception is a platform-authenticated legacy client, whose
        # authorization is still verified against the registry but whose
        # consumer need not be the credential's subject.
        if auth_method != "gateway_authenticated" and credential.subject_id != consumer_id:
            raise IdentityBindingError(
                f"the authorization names consumer {consumer_id!r} while the "
                f"credential authenticates {credential.subject_id!r}; identity "
                "comes from the credential, never the body"
            )
        # The payer must be the account this credential is *bound* to, which the
        # server itself recorded at join time — not any account the body names.
        # A credential provisioned from `server.json` predates per-identity
        # accounts and carries no `account_id`, so for those the historical
        # `subject_id` equality governs and no existing deployment changes
        # meaning.
        bound_account = credential.account_id or credential.subject_id
        if auth_method != "gateway_authenticated" and payer_account_id != bound_account:
            raise IdentityBindingError(
                f"the authorization would charge account {payer_account_id!r} "
                f"while credential {credential.subject_id!r} is bound to "
                f"{bound_account!r}; a signature proves who signed, not whose "
                "account may be charged"
            )
        # The authorization binds the exact work it was signed for. Recomputing
        # the digest from what was actually submitted, and comparing it to the
        # signed `request_digest`, is what stops a valid authorization for
        # "write a haiku" from being re-pointed at "read the secret file", or a
        # ceiling signed for a short answer from being spent on a long one.
        forwarded = dict(parameters or {})
        payload_digest = compute_request_digest(
            messages=tuple(messages),
            model=model,
            delivery_mode=delivery_mode,
            parameters=forwarded,
        )
        signed_request_digest = str(payload.get("request_digest", ""))
        if signed_request_digest != payload_digest:
            raise ProtocolError(
                "the submitted messages/model/delivery_mode/parameters do not "
                "match the request_digest the authorization was signed over"
            )
        signed_max_attempts = int(str(payload.get("max_attempts", "0")))
        if max_attempts > signed_max_attempts:
            raise ProtocolError(
                f"requested max_attempts {max_attempts} exceeds the authorized "
                f"cap of {signed_max_attempts}"
            )
        allowed_models = {str(entry) for entry in payload.get("allowed_models", [])}
        if model not in allowed_models:
            raise ProtocolError(
                f"model {model!r} is outside the authorized allowlist "
                f"{sorted(allowed_models)}"
            )
        signed_cap = int(str(payload.get("max_charge_milli_credits", "0")))
        if max_charge_milli_credits > signed_cap:
            raise ProtocolError(
                f"requested ceiling {max_charge_milli_credits} is outside the "
                f"signed cap of {signed_cap}"
            )
        verify_chain(
            self._registry, record, "consumer", owner_id=consumer_id, witnessed_at=moment
        )
        self._registry.check_spend_authority(
            spender_id=consumer_id,
            payer_account_id=payer_account_id,
            amount=max_charge_milli_credits,
            moment=moment,
        )
        request_id = str(payload.get("request_id", ""))
        if not request_id:
            raise IdentityBindingError("the authorization names no request_id")
        return self._admit_and_offer(
            credential=credential,
            request_id=request_id,
            idempotency_key=idempotency_key,
            payload_digest=payload_digest,
            messages=tuple(messages),
            parameters=forwarded,
            model=model,
            delivery_mode=delivery_mode,
            max_attempts=max_attempts,
            deadline_ms=deadline_ms,
            authorization=record,
            moment=moment,
            session_id=session,
        )

    def admit_api_key_request(
        self,
        *,
        api_key: ApiKeyRecord,
        messages: Sequence[ChatMessage],
        model: str,
        parameters: Mapping[str, Any] | None = None,
        delivery_mode: str = "buffered_complete",
        max_charge_milli_credits: int = API_KEY_DEFAULT_MAX_CHARGE_MILLI_CREDITS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        deadline_ms: int = DEFAULT_DEADLINE_MS,
        session_id: str | None = None,
        now: dt.datetime | None = None,
    ) -> AdmitResult:
        """Admit one request authenticated by an operator-issued API key.

        The second admission path, and the difference is exactly one thing: who
        authorized the spend. A signed request carries the consumer's own
        signature over the work and the ceiling; here the caller proved it holds
        a key the server issued, and the server signs the terms it is admitting
        with its own settlement key, labelled ``gateway_authenticated`` so
        settlement and every later audit read it as the platform's
        authorization and never as a consumer signature. Nothing else about the
        request is weakened: it runs the same dispatch, the same metering, the
        same settlement, and it charges the same account the subject's signed
        requests charge.

        What the key adds is a ceiling of its own. The per-request cap is the
        smaller of `max_charge_milli_credits` and the key's remaining quota, and
        a key that has spent its quota admits nothing, so a key handed to a tool
        can be capped and revoked without touching the identity behind it or any
        other key.

        Args:
            api_key: The key the transport resolved from the credential the
                request presented. The plaintext never reaches this module: as on
                the bearer path, the transport resolves the material and the
                domain receives the record.
            messages: The conversation to run, forwarded to the upstream as it
                stands.
            model: The model being requested.
            parameters: The forwarded request parameters, in the canonical-safe
                encoding `wire.encode_chat_parameters` produces.
            delivery_mode: `buffered_complete` or `stream_strict`.
            max_charge_milli_credits: The ceiling the caller asked for, capped
                here by the key's remaining quota.
            max_attempts: Hard attempt cap.
            deadline_ms: The wall-clock budget the surface asks for. A key minted
                with ``admin api-key --deadline-ms`` carries its own, and that one
                wins: it is the operator's statement about the work this key is
                for, which the surface cannot know.
            session_id: The agent session this turn belongs to, or `None`. On the
                OpenAI-compatible surface it arrives as the `wire.SESSION_HEADER`
                header, which an OpenAI SDK client can send through
                ``default_headers`` without any other change.
            now: The server's clock; defaults to the wall clock.

        Returns:
            The admission result, as for a signed request.

        Raises:
            ApiKeyUnavailable: If the key is no longer usable, or speaks for a
                subject this server holds no consumer for.
            ApiKeyRateLimited: If the key is at its concurrency ceiling or its
                request rate.
            InsufficientFundsError: If the key has spent its quota.
            ModelUnavailable: If no connected node runs `model` at all. A server
                that runs it but has nothing free this instant does not refuse
                here: the request is admitted and waits in the dispatch queue,
                unless the queue is at its bound.
            QueueFull: If the server's dispatch queue is at its bound.
            ProtocolError: If the conversation is empty, the ceiling is not
                positive, or `session_id` is not an identifier the wire accepts.
        """
        moment = now or self._moment()
        conversation = tuple(messages)
        if not conversation:
            raise ProtocolError("a request must carry at least one message")
        session = None if session_id is None else check_session_id(session_id)
        # The sweep runs before this key's own limits are read, because the slots
        # an overdue request still holds are counted against them: without it a
        # key whose slots nothing ever swept is refused at its ceiling forever.
        self._sweep_before_admission(moment)
        forwarded = dict(parameters or {})
        # Authenticating the key is the transport's resolution, exactly as on the
        # bearer path: the plaintext never reaches this module, and the record it
        # hands over is the server's own answer from a moment ago. What is
        # re-checked here is what this call owns — that the key is still inside
        # its window, and that its quota, its rate and its subject still permit
        # the spend.
        if not api_key.is_usable_at(moment):
            raise ApiKeyUnavailable("the presented API key is not usable")
        key = api_key
        self._check_api_key_limits(key)
        remaining = key.remaining_milli_credits
        if remaining <= 0:
            raise InsufficientFundsError(
                f"API key {key.key_id} has spent its {key.quota_milli_credits} "
                "milli-credit quota; mint another with `potluck-server admin "
                "api-key`, or raise this one's quota"
            )
        binding = self._store.find_consumer_binding(key.subject_id)
        if binding is None:
            raise ApiKeyUnavailable(
                f"API key {key.key_id} speaks for {key.subject_id!r}, which this "
                "server holds no consumer identity or credential for"
            )
        # A model this server has no node for is refused here rather than queued,
        # and the two refusals it could make are different facts. "No node of this
        # server runs that model" is a statement about the request: waiting cannot
        # make it true, so holding the request would only turn a typo into a
        # timeout that names nothing. "Nothing can take it right now" is a
        # statement about load, which ends, and that one `_admit_and_offer` decides
        # about below.
        #
        # The catalogue is read across every willing node rather than only the
        # connected ones, because a pool whose nodes are all mid-restart still
        # serves the models they advertise: answering `model_not_found` then would
        # be a false statement about the server, and would refuse the requests a
        # queue exists to hold.
        catalogue = sorted(self._store.catalogued_models())
        if model not in catalogue:
            raise ModelUnavailable(
                f"no contribution node of this server runs model {model!r}; the "
                f"models it has nodes for are {catalogue}"
            )
        # The key's own deadline wins over the surface default, because it is the
        # one fact an operator recorded about *this* key: a key minted for an
        # agent loop gets a window long enough for a long turn, and a key minted
        # for a one-shot question keeps the surface's own.
        budget_ms = key.deadline_ms if key.deadline_ms is not None else deadline_ms
        if budget_ms > MAX_DEADLINE_MS:
            raise ProtocolError(
                f"deadline_ms {budget_ms} is beyond the {MAX_DEADLINE_MS} ms "
                "ceiling; a request that cannot finish inside a day cannot "
                "finish, and its slot would never free"
            )
        credential = Credential(
            tenant_id=key.tenant_id,
            subject_id=key.subject_id,
            role="consumer",
            account_id=binding.account_id,
        )
        # The ceiling this request exposes is bounded by what the key has left,
        # so a single in-flight request can never spend past the quota. Requests
        # admitted concurrently are each bounded the same way but do not see one
        # another's spend until they settle, which is why the concurrency ceiling
        # exists: it bounds how far ahead of the books a key can run.
        ceiling = min(max_charge_milli_credits, remaining)
        if ceiling < 1:
            raise ProtocolError(f"a charge ceiling must be positive, got {ceiling}")
        request_id = f"req-{secrets.token_hex(16)}"
        authorization = self._mint_gateway_authorization(
            request_id=request_id,
            credential=credential,
            messages=conversation,
            model=model,
            parameters=forwarded,
            delivery_mode=delivery_mode,
            max_charge_milli_credits=ceiling,
            max_attempts=max_attempts,
            deadline_ms=budget_ms,
            moment=moment,
        )
        result = self._admit_and_offer(
            credential=credential,
            request_id=request_id,
            idempotency_key=f"api-key-{secrets.token_hex(16)}",
            payload_digest=compute_request_digest(
                messages=conversation,
                model=model,
                delivery_mode=delivery_mode,
                parameters=forwarded,
            ),
            messages=conversation,
            parameters=forwarded,
            model=model,
            delivery_mode=delivery_mode,
            max_attempts=max_attempts,
            deadline_ms=budget_ms,
            authorization=authorization,
            moment=moment,
            api_key_id=key.key_id,
            session_id=session,
        )
        self._store.mark_api_key_used(key.key_id, moment)
        return result

    def _check_api_key_limits(self, key: ApiKeyRecord) -> None:
        """Enforce one key's concurrency ceiling and its request rate.

        The concurrency count is read from the durable request rows, so it means
        the same thing after a restart as before one and a request an interrupted
        server left running still occupies its slot. The rate window is this
        process's own memory: a rate limit is a load-shedding decision about the
        requests arriving now, not a fact about the books, and a restart clearing
        it costs one window.

        Raises:
            ApiKeyRateLimited: If the key is at either limit.
        """
        in_flight = self._store.count_in_flight_api_key_requests(key.key_id)
        if in_flight >= API_KEY_MAX_IN_FLIGHT:
            raise ApiKeyRateLimited(
                f"API key {key.key_id} has {in_flight} requests in flight, at its "
                f"ceiling of {API_KEY_MAX_IN_FLIGHT}; wait for one to finish"
            )
        now = time.monotonic()
        with self._api_key_rate_lock:
            window = self._api_key_windows.setdefault(key.key_id, deque())
            while window and now - window[0] >= API_KEY_RATE_WINDOW_S:
                window.popleft()
            if len(window) >= API_KEY_RATE_LIMIT:
                raise ApiKeyRateLimited(
                    f"API key {key.key_id} admitted {len(window)} requests in the "
                    f"last {int(API_KEY_RATE_WINDOW_S)}s, at its ceiling of "
                    f"{API_KEY_RATE_LIMIT} per minute; retry later"
                )
            window.append(now)

    def _mint_gateway_authorization(
        self,
        *,
        request_id: str,
        credential: Credential,
        messages: Sequence[ChatMessage],
        model: str,
        parameters: Mapping[str, Any],
        delivery_mode: str,
        max_charge_milli_credits: int,
        max_attempts: int,
        deadline_ms: int,
        moment: dt.datetime,
    ) -> SignedRecord:
        """Sign the authorization for a request the server admitted itself.

        The server holds no consumer key — a joiner keeps its own — so the
        platform's settlement key signs the terms being admitted and the record
        says so through ``auth_method``. Settlement verifies that signature under
        the platform purpose, and the receipt keeps the label: this is real
        evidence of a different strength from a consumer signature, and nothing
        downstream may read it as one.

        The signature is verified here as well, against the same registry
        settlement will use. A settlement key that is not registered, or was
        revoked, then fails the request before any node spends tokens on it
        rather than at settlement time, when the work is already done and cannot
        be billed.

        Returns:
            The signed authorization to store with the request's inputs.

        Raises:
            SignatureError: If the platform's own key cannot sign an
                authorization this server can settle.
        """
        payer_account_id = credential.account_id or credential.subject_id
        self._registry.check_spend_authority(
            spender_id=credential.subject_id,
            payer_account_id=payer_account_id,
            amount=max_charge_milli_credits,
            moment=moment,
        )
        authorization = SpendAuthorization(
            authorization_id=f"auth-{request_id}",
            payer_account_id=payer_account_id,
            consumer_id=credential.subject_id,
            request_id=request_id,
            request_digest=compute_request_digest(
                messages=tuple(messages),
                model=model,
                delivery_mode=delivery_mode,
                parameters=parameters,
            ),
            max_charge_milli_credits=max_charge_milli_credits,
            pricing_version=PRICING_VERSION,
            billing_basis=BILLING_BASIS,
            minimum_evidence_level=MINIMUM_EVIDENCE_LEVEL,
            allowed_models=frozenset({model}),
            allowed_trust_pools=frozenset({TRUST_POOL}),
            max_attempts=max_attempts,
            duplicate_execution_policy="bounded_model_only",
            max_provider_fanout=max_attempts,
            nonce=new_nonce(),
            issued_at=moment,
            expires_at=(
                moment
                + dt.timedelta(milliseconds=deadline_ms)
                + AUTHORIZATION_SETTLEMENT_GRACE
            ),
            auth_method="gateway_authenticated",
            key_id=self._config.settlement_key_id,
        )
        record = authorization.sign(self._settlement_key, self._config.settlement_key_id)
        platform_id = self._registry.get_key(self._config.settlement_key_id).owner_id
        verify_chain(
            self._registry,
            record,
            "platform_settlement",
            owner_id=platform_id,
            witnessed_at=moment,
        )
        return record

    def _admit_and_offer(
        self,
        *,
        credential: Credential,
        request_id: str,
        idempotency_key: str,
        payload_digest: str,
        messages: Sequence[ChatMessage],
        parameters: Mapping[str, Any],
        model: str,
        delivery_mode: str,
        max_attempts: int,
        deadline_ms: int,
        authorization: SignedRecord,
        moment: dt.datetime,
        api_key_id: str | None = None,
        session_id: str | None = None,
    ) -> AdmitResult:
        """Store one admitted request, and offer its first attempt.

        The shared tail of both admission paths, which differ in how the spend
        was authorized and not in what an admitted request does next: one row,
        one stored conversation, one attempt cap, one dispatch. Every authority
        check has already run by the time this is called, so nothing here decides
        whether the request *may* run — only whether it may run now or wait.

        The API key is bound to the request row before the offer goes out, inside
        the same lock: settlement reads that binding to count the charge against
        the key's quota, and a server interrupted between dispatch and settlement
        must still find it. The queue bound is read under that same lock, so two
        concurrent admissions cannot each see room for one request.

        Raises:
            ModelUnavailable: If nothing can dispatch this request and the server
                is configured not to hold it.
            QueueFull: If nothing can dispatch it and the queue is at its bound.
            ConflictError: If the idempotency key names a request the server
                already admitted under a *different* request id. The replay is
                only idempotent when it replays the same request; a fresh
                signature over the same work is a second request wearing the
                first one's key, and answering it with the first one's id would
                report a dispatch the caller never asked for.
        """
        deliveries: list[tuple[str, Envelope]] = []
        with self._lock:
            # Decided before the row exists, so an admission this refuses creates
            # nothing to sweep, nothing to bill and nothing for a caller to poll.
            if self._pick_node(model, set(), moment) is None:
                self._refuse_or_make_room(
                    credential=credential,
                    idempotency_key=idempotency_key,
                    model=model,
                    moment=moment,
                )
            stored, created = self._store.create_request(
                request_id=request_id,
                tenant_id=credential.tenant_id,
                subject_id=credential.subject_id,
                idempotency_key=idempotency_key,
                payload_digest=payload_digest,
                delivery_mode=delivery_mode,
                max_attempts=max_attempts,
                service_unit_id=request_id,
                deadline_at=moment + dt.timedelta(milliseconds=deadline_ms),
                created_at=moment,
                session_id=session_id,
            )
            if not created and stored.request_id != request_id:
                raise ConflictError(
                    f"idempotency key {idempotency_key} already admitted request "
                    f"{stored.request_id}, which is not {request_id}; one key replays "
                    "one request, so either resubmit with the request id the server "
                    "returned or mint a fresh idempotency key for new work"
                )
            if created:
                if api_key_id is not None:
                    self._store.bind_request_api_key(request_id, api_key_id)
                if session_id is not None:
                    # Counted at admission rather than at settlement, so a turn
                    # that failed or expired is still a turn this session made.
                    self._store.touch_session(
                        tenant_id=credential.tenant_id,
                        subject_id=credential.subject_id,
                        session_id=session_id,
                        at=moment,
                    )
                # Only a request this admission created reaches here, so its
                # inputs are written once by construction: an idempotent replay
                # returns `created=False` and never touches what the first write
                # stored, which is what keeps a retry carrying a different
                # authorization from moving the settlement target. A write that
                # fails is fatal and is reported, never suppressed — a request row
                # with no inputs behind it can be neither dispatched nor settled.
                try:
                    self._store.set_request_input(
                        request_id,
                        messages=[message.to_payload() for message in messages],
                        model=model,
                        parameters=dict(parameters),
                        authorization=_signed_record_to_dict(authorization),
                        at=moment,
                    )
                except PotluckError as exc:
                    self._terminate_undispatchable(
                        request_id, "CANCELLED", f"dispatch inputs not stored: {exc}", moment
                    )
                    raise
                self._store.set_request_status(request_id, "ROUTING", at=moment)
                try:
                    deliveries.extend(self._offer_new_attempt(stored, moment))
                except PotluckError as exc:
                    self._terminate_undispatchable(
                        request_id, "FAILED", f"first attempt not offered: {exc}", moment
                    )
                    raise
                if not deliveries:
                    # Nothing took the work, so the request is now waiting. The
                    # wait is recorded on the request's own event stream rather
                    # than left for a caller to infer from a status that has not
                    # changed: a consumer reading the stream sees the request
                    # queue, and later sees it dispatched.
                    self._append_dispatch_event(
                        request_id,
                        QUEUED_EVENT_TYPE,
                        {"reason": "no node can take the work right now"},
                        moment,
                    )
            current = self._store.get_request(stored.request_id)
            assert current is not None
            result = AdmitResult(
                request_id=current.request_id,
                created=created,
                status=current.status,
                delivery_mode=current.delivery_mode,
            )
        self._deliver(deliveries)
        return result

    def _refuse_or_make_room(
        self,
        *,
        credential: Credential,
        idempotency_key: str,
        model: str,
        moment: dt.datetime,
    ) -> None:
        """Decide whether a request nothing can dispatch yet may wait for one.

        Called only when `_pick_node` found nothing, so the question is not
        whether this request can run now — it cannot — but whether the server
        holds it or refuses it. Both answers are honest; which one an operator
        wants is `GatewayConfig.queue_enabled`.

        A retry of a request the server already admitted is let through even at
        the bound, because the idempotency key's whole promise is that a retry is
        a no-op: refusing it would make the key stop meaning what it says exactly
        when a caller is retrying under load, and the request it would refuse is
        one the server is already holding.

        Raises:
            ModelUnavailable: If the server is configured not to hold work.
            QueueFull: If it is, and is already holding as much as it agreed to.
        """
        if not self._config.queue_enabled:
            raise ModelUnavailable(
                f"no connected contribution node can run model {model!r} right now, "
                "and this server is configured not to hold a request that nothing "
                "can dispatch (queue_enabled is false); retry, or run a node that "
                "serves it"
            )
        if self._queue_is_full():
            replay = self._store.request_by_idempotency_key(
                credential.tenant_id, idempotency_key
            )
            if replay is None:
                raise QueueFull(
                    f"this server is already holding {self._queue_depth()} request(s) "
                    f"waiting for a contribution node, at its queue bound of "
                    f"{max(0, self._config.max_queue_depth)}; nothing can run model "
                    f"{model!r} right now, so retry later or ask the operator to run "
                    "another node"
                )

    def _queue_depth(self) -> int:
        """How many requests are waiting for a node.

        The queue *is* this count: a request in `ROUTING` is one the server has
        admitted and has not yet placed with a node, so there is no separate queue
        structure to disagree with the request rows, and nothing to rebuild after a
        restart.
        """
        return self._store.count_requests_by_status("ROUTING")

    def _queue_is_full(self) -> bool:
        """Whether the server is holding as many waiting requests as it agreed to.

        Callers hold the service lock, so the depth read and the decision made from
        it see one consistent moment: two admissions cannot each find room for one
        request.
        """
        return self._queue_depth() >= max(0, self._config.max_queue_depth)

    def _append_dispatch_event(
        self,
        request_id: str,
        event_type: str,
        payload: dict[str, Any],
        moment: dt.datetime,
    ) -> None:
        """Append one of the server's own dispatch events to a request's stream.

        The stream is the same ordered, replayable, never-rewritten one a node's
        `output.delta` and `usage.final` ride, so a queue transition is as
        durable and as auditable as anything else that happened to the request —
        which is the standard the transparency log sets and the reason these are
        stored events rather than log lines.
        """
        stream = _dispatch_stream_id(request_id)
        self._store.append_event(
            request_id=request_id,
            attempt_id=stream,
            attempt_seq=self._store.last_attempt_seq(stream) + 1,
            event_type=event_type,
            payload=payload,
            at=moment,
        )

    def _terminate_undispatchable(
        self, request_id: str, status: str, reason: str, moment: dt.datetime
    ) -> None:
        """End a request that can never be dispatched, before its caller is told.

        No path may leave a request row non-terminal: a row sitting in ROUTING
        occupies its API key's concurrency slot until something ends it, so an
        admission that is about to raise ends the request it created first, with
        the reason in the `billing_note` the books and the caller both read.

        `status` is the terminal state the request's own state machine allows
        from where it got to: a request whose inputs could not be stored never
        left CREATED, which `aipotluck.statemachine` may cancel but not fail,
        while one that reached ROUTING and could not be offered is FAILED.
        """
        self._store.set_request_status(
            request_id, status, billing_note=reason, at=moment
        )

    def _expire_overdue_requests(
        self, moment: dt.datetime
    ) -> list[tuple[str, Envelope]]:
        """End every non-terminal request whose deadline has passed.

        One implementation, three callers: `tick` runs it on its interval, and
        both admission gates run it before they decide anything. The gate is not
        a redundancy — an overdue request still occupies its API key's
        concurrency slot, so without it a key whose slots are held by rows
        nothing swept is refused at its ceiling forever, and the admission that
        the ceiling blocks is the very one that would have ended them.

        The status is EXPIRED, the answer `tick` has always given for a passed
        deadline, so one condition keeps one meaning: the OpenAI surface reports
        it as a 504 carrying the server's own reason rather than as a 502.

        Returns:
            `(node_id, cancel)` pairs for the attempts those requests still held,
            for the caller to deliver outside the lock. The batch bound means one
            pass can leave rows for the next, which is why the gate and the
            ticker run the same sweep: neither is the only chance a row gets.
        """
        pairs: list[tuple[str, Envelope]] = []
        for status in ("CREATED", "ROUTING", "RUNNING", "RECOVERING"):
            for record in self._store.requests_by_status(
                status, limit=DEADLINE_SWEEP_BATCH
            ):
                deadline = record.deadline_at
                if deadline is None or moment < deadline:
                    continue
                self._store.set_request_status(
                    record.request_id,
                    "EXPIRED",
                    billing_note=f"deadline of {deadline.isoformat()} passed",
                    at=moment,
                )
                pairs.extend(self._cancel_pairs(record, "deadline", moment))
        return pairs

    def _sweep_before_admission(self, moment: dt.datetime) -> None:
        """Run the deadline sweep at an admission gate, and deliver what it ends."""
        with self._lock:
            deliveries = self._expire_overdue_requests(moment)
        self._deliver(deliveries)

    def _offer_isolated(
        self, record: RequestRecord, moment: dt.datetime, *, leaving_queue: bool = False
    ) -> list[tuple[str, Envelope]]:
        """Offer one request, reporting a failure instead of ending the round.

        One request that cannot be offered is that request's problem. Raised out
        of `tick` it becomes everybody's: the round aborts, so nothing else is
        offered, nothing else expires, and the ticker — which swallows the
        failure and retries — repeats that forever. That is how a single
        undispatchable row once stopped every overdue request on the server from
        ever being ended.
        """
        try:
            return self._offer_new_attempt(record, moment, leaving_queue=leaving_queue)
        except Exception:
            logger.exception(
                "request %s could not be offered; the rest of the round continues",
                record.request_id,
            )
            return []

    def request_status(self, *, credential: Credential, request_id: str) -> dict[str, Any]:
        """Return a request's status document.

        Raises:
            StateTransitionError: If the request is unknown.
            IdentityBindingError: If it belongs to another tenant.
        """
        record = self._require_request(credential, request_id)
        attempts = self._store.attempts_for_request(request_id)
        commit = self._store.output_commit(request_id)
        return {
            "request_id": record.request_id,
            "tenant_id": record.tenant_id,
            "status": record.status,
            "delivery_mode": record.delivery_mode,
            "selected_attempt_id": record.selected_attempt_id,
            "billing_note": record.billing_note,
            "output": {
                "committed": commit is not None,
                "attempt_id": commit.attempt_id if commit else None,
                "generation_id": commit.generation_id if commit else None,
                "committed_at_seq": commit.committed_at_seq if commit else None,
            },
            "attempts": [
                {
                    "attempt_id": attempt.attempt_id,
                    "provider_id": attempt.provider_id,
                    "node_id": attempt.node_id,
                    "status": attempt.status,
                    "usage_status": attempt.usage_status,
                    "usage_tokens": attempt.usage_tokens,
                    "settlement_status": attempt.settlement_status,
                }
                for attempt in attempts
            ],
            "settlement": self._settlement_summary(request_id),
        }

    def request_events(
        self, *, credential: Credential, request_id: str, cursor: int, limit: int = 256
    ) -> list[StoredEvent]:
        """Return stored events after `cursor`, authorising the tenant first.

        Raises:
            StateTransitionError: If the request is unknown.
            IdentityBindingError: If it belongs to another tenant.
        """
        self._require_request(credential, request_id)
        return self._store.events_after(request_id, cursor, limit=limit)

    def cancel_request(
        self,
        *,
        credential: Credential,
        request_id: str,
        origin: str,
        now: dt.datetime | None = None,
    ) -> dict[str, Any]:
        """Cancel a request and tell every live attempt to stop.

        Raises:
            ProtocolError: If `origin` is not one of the documented origins.
            StateTransitionError: If the request is unknown.
            IdentityBindingError: If it belongs to another tenant.
        """
        if origin not in _CANCEL_ORIGINS:
            raise ProtocolError(
                f"unknown cancel origin {origin!r}; expected one of {sorted(_CANCEL_ORIGINS)}"
            )
        moment = now or self._moment()
        self._require_request(credential, request_id)
        deliveries: list[tuple[str, Envelope]] = []
        with self._lock:
            note = f"cancelled by {origin}"
            self._store.set_request_status(
                request_id, "CANCELLED", billing_note=note, at=moment
            )
            for attempt in self._store.attempts_for_request(request_id):
                if attempt.status not in _LIVE_ATTEMPT_STATES or attempt.node_id is None:
                    continue
                ref = AttemptRef(
                    request_id=request_id,
                    attempt_id=attempt.attempt_id,
                    epoch=attempt.dispatch_epoch,
                )
                deliveries.append(
                    (
                        attempt.node_id,
                        Envelope(
                            type="attempt.cancel",
                            payload={**ref.to_payload(), "origin": origin},
                        ),
                    )
                )
            document = {
                "request_id": request_id,
                "status": "CANCELLED",
                "origin": origin,
                "note": note,
            }
        self._deliver(deliveries)
        return document

    def receipt_for(self, *, credential: Credential, receipt_id: str) -> dict[str, Any]:
        """Return a signed receipt with its inclusion proof and allocation contract.

        The contract rides along because it is the one input an offline verifier
        cannot derive on its own: recomputing the split needs the weights the
        platform actually settled under, and the receipt only carries their
        digest. Weights are not a secret — the beneficiary accounts are already
        in the receipt's postings — so publishing them turns "trust the server's
        arithmetic" into "check the server's arithmetic". It is ``None`` when the
        winning attempt row is gone, which is itself a finding the server-side
        reconciliation reports rather than something to paper over here.

        Scope: the receipt's *tenant*, not its payer. Every consumer credential in
        a tenant therefore reads every receipt of that tenant — postings and payer
        account names included — while `account_history` answers only for the
        credential asking. A tenant is a trust group for reading receipts as well
        as for admission, so an operator who has to keep two consumers' books
        apart invites them into two tenants.

        Raises:
            GatewayError: If the receipt is unknown.
            IdentityBindingError: If it belongs to another tenant.
        """
        stored = self._store.get_receipt(receipt_id)
        if stored is None:
            raise GatewayError(f"receipt {receipt_id} was never issued by this server")
        request = self._store.get_request(stored.request_id)
        if request is None or request.tenant_id != credential.tenant_id:
            raise IdentityBindingError(
                f"credential {credential.subject_id!r} may not read request "
                f"{stored.request_id}"
            )
        proof = self._log.inclusion_proof(stored.log_index)
        return {
            "receipt_id": stored.receipt_id,
            "request_id": stored.request_id,
            "receipt_hash": stored.receipt_hash,
            "log_index": stored.log_index,
            "receipt": loads_strict(stored.receipt_json),
            "inclusion_proof": proof.to_payload(),
            "allocation_contract": self._allocation_contract_for(stored),
        }

    def _allocation_contract_for(self, stored: ReceiptRecord) -> dict[str, Any] | None:
        """Return the allocation contract a stored receipt settled under.

        The contract is re-derived from the winner attempt's persisted provider
        and epoch — the same two fields settlement derived it from — so what is
        published is the contract the server would compute again, not a copy
        somebody could edit.

        Returns:
            The contract's canonical digest payload, or `None` when the receipt
            names no attempt this store still holds.
        """
        winner = _receipt_field(stored, "winner_attempt_id")
        attempt = self._store.get_attempt(winner) if winner is not None else None
        if attempt is None:
            return None
        contract = derive_allocation_contract(
            request_id=attempt.request_id,
            provider_id=attempt.provider_id,
            epoch=attempt.dispatch_epoch,
        )
        return cast("dict[str, Any]", contract.digest_payload())

    def checkpoint(
        self, *, credential: Credential, now: dt.datetime | None = None
    ) -> dict[str, Any]:
        """Return the newest signed transparency-log checkpoint.

        `log_index` is the index of the newest leaf, or None when the log is
        empty: inventing index 0 for an empty log would commit to a leaf that
        does not exist. `public_key_b64` is the public half of the settlement key
        that signs the checkpoint, published so a consumer can authenticate the
        root it is being handed instead of trusting it. A public key is not a
        secret; the private half never leaves ``server.json``. It is still the
        server's own claim about itself, so a consumer who wants a root the
        server cannot rewrite pins this key out of band and compares.
        """
        del credential
        moment = now or self._moment()
        checkpoint = self._engine.sign_checkpoint(self._settlement_key, int(moment.timestamp()))
        leaves = self._store.log_leaves()
        return {
            "platform_id": checkpoint.platform_id,
            "tree_size": checkpoint.tree_size,
            "root_hash": checkpoint.root_hash,
            "checkpoint_epoch": checkpoint.checkpoint_epoch,
            "issued_at": checkpoint.issued_at.isoformat(),
            "key_id": checkpoint.key_id,
            "signature": checkpoint.signature,
            "public_key_b64": base64_encode(
                self._settlement_key.public_key().public_bytes_raw()
            ),
            "log_index": leaves[-1].log_index if leaves else None,
        }

    def account_history(self, *, credential: Credential) -> dict[str, Any]:
        """Return the calling consumer's own account history.

        The account is derived from the resolved credential, never from the
        request: there is no account id in the path or the query, so this
        endpoint cannot be pointed at anybody else's books. It exists because
        `account_history_complete` is the one verification dimension a consumer
        cannot assess from a receipt alone — the receipt proves what one charge
        says, not that the server showed every charge.

        `entry_count` is reported next to `entries` rather than left to be
        inferred from the list's length, so a verifier can tell a history that
        arrived whole from one that was truncated or reordered in transit. Both
        come from the same ledger, which bounds what this proves: it catches a
        lost or duplicated entry, not a server that rewrote the books and the
        count together. Only the transparency log anchors that, and it is why
        `ledger_included` is a separate dimension.

        Raises:
            IdentityBindingError: If the credential is not a consumer's.
            LedgerError: If the credential names a sub-account rather than a root
                identity, which `Ledger.statement` refuses to reinterpret.
        """
        if credential.role != "consumer":
            raise IdentityBindingError(
                f"role {credential.role!r} has no consumer account history to read"
            )
        account_id = credential.account_id or credential.subject_id
        statement = self._ledger.statement(account_id)
        receipt_by_journal = self._receipt_ids_by_journal()
        raw_entries = [dict(entry) for entry in _statement_entries(statement)]
        entries = [
            {
                "seq": position,
                "journal_id": str(entry["journal_id"]),
                "kind": str(entry["kind"]),
                "delta": int(str(entry["delta"])),
                "receipt_id": receipt_by_journal.get(str(entry["journal_id"])),
            }
            for position, entry in enumerate(raw_entries, start=1)
        ]
        return {
            "account_id": account_id,
            "balances": {
                key: int(str(statement[key]))
                for key in (
                    "total",
                    "available",
                    "reserved",
                    "risk_reserved",
                    "pending",
                    "settlement_payable",
                )
            },
            "entry_count": len(entries),
            "entries": entries,
            "receipt_ids": [
                entry["receipt_id"] for entry in entries if entry["receipt_id"] is not None
            ],
        }

    def _receipt_ids_by_journal(self) -> dict[str, str]:
        """Map every stored receipt's journal id to its receipt id.

        Read straight from the durable receipt rows rather than from the in-memory
        books, so a journal the ledger lost still names the receipt that backs it.
        """
        mapping: dict[str, str] = {}
        for stored in self._store.receipts():
            journal_id = _receipt_field(stored, "journal_id")
            if journal_id is not None:
                mapping[journal_id] = stored.receipt_id
        return mapping

    def node_attempts(self, *, credential: Credential) -> dict[str, Any]:
        """Return the attempts the server dispatched to this credential's node.

        This is the server half of the contributor's reconciliation: the node
        holds what it signed and executed locally, and this is what the server
        claims about the same attempts. The node ids come from `_node_ids_for`,
        which derives them from the credential the transport authenticated;
        there is no node id in the path or the query, so a request cannot name
        one, and no tenant is consulted, so a node an operator invited into a
        shared tenant cannot read the others.

        Only the receipt's identity is returned — id, hash and log position —
        never its postings. A contributor needs to know that its attempt settled
        and where the receipt was logged; the consumer's account balances are not
        its business, and a receipt body would carry them.

        Raises:
            IdentityBindingError: If the credential is not a node's.
        """
        if credential.role != "node":
            raise IdentityBindingError(
                f"role {credential.role!r} has no node attempts to read"
            )
        node_ids = self._node_ids_for(credential)
        attempts = [
            attempt
            for node_id in sorted(node_ids)
            for attempt in self._store.attempts_for_node(node_id, unfinished_only=False)
        ]
        attempts.sort(key=lambda attempt: attempt.attempt_id)
        return {
            "node_ids": sorted(node_ids),
            "attempts": [self._node_attempt_view(attempt) for attempt in attempts],
        }

    def _bound_node_id(self, credential: Credential) -> str:
        """Return the one node id this credential speaks for.

        This is the platform's single spelling of "who is this credential", and
        both sides of a node link are held to it: `_node_ids_for` scopes a read
        by it and `_check_hello_identity` refuses a hello that claims anything
        else. Derived from the credential alone, never from the request:

        * a credential a *join* minted carries the device that join derived, and
          the connector dials as that device (``node.json``'s ``node_id`` is the
          ``device_id`` the wizard wrote), so the device id is the node id;
        * a credential an *operator* provisioned in ``server.json`` names no
          device; that path writes ``node.json`` by hand, and its documented
          sample dials with the credential's own subject as its ``node_id``.
        """
        return credential.device_id or credential.subject_id

    def _node_ids_for(self, credential: Credential) -> frozenset[str]:
        """Return the node ids this credential may read attempts for.

        A node's own credential is the one thing it cannot forge about somebody
        else, so it is the only input a scoped read may take; `_bound_node_id`
        states which id that is.

        Scoping by tenant instead — which is what the identity table would offer
        — is wrong wherever an operator invited more than one node into a
        concrete tenant, the shape the runbook mints for a friends community:
        every member would read every other member's dispatch history with their
        own valid token. A node that dials under a node id of its own choosing,
        matching neither binding, gets an empty answer, which `share reconcile`
        reports as ``server_does_not_know_this_node`` naming both ids.
        """
        return frozenset({self._bound_node_id(credential)})

    def _check_hello_identity(self, credential: Credential, hello: NodeHello) -> None:
        """Refuse a hello claiming an identity the credential does not carry.

        The transport authenticated the *credential*; every id in the hello is a
        claim the peer typed. Binding the two is what makes a node link
        attributable, and it must run before the server writes anything — a node
        record, an enqueue slot, a `hello.ack` — or a refused claim would
        already have displaced the node it named. Node ids key both the
        live-connection table and routing, so an unbound claim is also a way to
        take over another node's link and its task feed.

        Three checks, in the order `_bound_node_id` implies:

        * the hello's ``node_id`` must be the credential's own bound node id, so
          a credential can never dial as a node that is not it;
        * a credential a join minted carries its device, and the hello must name
          that device. An operator-provisioned credential carries none, and its
          ``node_id`` binding is the constraint that replaces it: a missing
          device binding is not a licence to claim any device;
        * either way, a device the server already bound to a credential may only
          be dialed by that credential, which is what closes the same
          impersonation from the provisioning path that has no device column.

        The device key and provider claims are checked by `register_node`
        against the registry once these hold.

        Raises:
            IdentityBindingError: If any claim disagrees with the credential.
        """
        bound = self._bound_node_id(credential)
        if hello.node_id != bound:
            raise IdentityBindingError(
                f"credential {credential.subject_id!r} speaks for node {bound!r}; "
                f"hello claims node {hello.node_id!r}"
            )
        if credential.device_id is not None and hello.device_id != credential.device_id:
            raise IdentityBindingError(
                f"credential {credential.subject_id!r} is bound to device "
                f"{credential.device_id!r}; hello claims device {hello.device_id!r}"
            )
        owner = self._store.find_credential_by_device(hello.device_id)
        if owner is not None and (
            owner.tenant_id != credential.tenant_id
            or owner.subject_id != credential.subject_id
        ):
            raise IdentityBindingError(
                f"device {hello.device_id!r} is bound to credential "
                f"{owner.subject_id!r}; {credential.subject_id!r} may not dial as it"
            )

    def _node_attempt_view(self, attempt: AttemptRecord) -> dict[str, Any]:
        """Render one attempt for its own node, plus the receipt it settled into.

        The receipt is looked up only for an attempt the server marked settled:
        a settlement row is keyed by the request, and attaching it to a losing or
        failed attempt of the same request would tell the node it was paid for
        work the server never billed. The lookup takes the highest stored
        revision, the same rule `reconcile_server` reads a settlement by, so a
        correction is what the contributor is shown rather than the revision it
        superseded.
        """
        receipt: dict[str, Any] | None = None
        if attempt.settlement_status == "SETTLED":
            settlement = self._store.latest_settlement(attempt.request_id)
            if settlement is not None:
                receipt = {
                    "receipt_id": settlement.receipt_id,
                    "receipt_hash": settlement.receipt_hash,
                    "log_index": settlement.log_index,
                }
        return {
            "attempt_id": attempt.attempt_id,
            "request_id": attempt.request_id,
            "dispatch_epoch": attempt.dispatch_epoch,
            "status": attempt.status,
            "usage_status": attempt.usage_status,
            "usage_tokens": attempt.usage_tokens,
            "settlement_status": attempt.settlement_status,
            "execution_state": attempt.execution_state,
            "updated_at": attempt.updated_at.isoformat(),
            "receipt": receipt,
        }

    # -- node lifecycle -----------------------------------------------------

    def register_node(
        self,
        *,
        credential: Credential,
        hello: NodeHello,
        enqueue: Callable[[Envelope], None],
        now: dt.datetime | None = None,
    ) -> None:
        """Register a node connection and tell it what to resume.

        Every identity check runs before the first write, so a refused hello
        leaves the store, the live-connection table and every other node exactly
        as they were: no node record is upserted, no enqueue slot is taken or
        displaced, and no `hello.ack` goes out. A reconnect, a resume and a link
        replacing an older one all arrive here as the same `node.hello`, so they
        carry the same constraints as a first connection.

        Raises:
            IdentityBindingError: If the credential is not a node credential, if
                the hello claims a node or a device the credential does not
                carry, or if the device key is not a provider-device key owned
                by the device the hello claims.
            GatewayError: If the device key is not registered, is not valid now,
                or its identity row is revoked.
        """
        moment = now or self._moment()
        if credential.role != "node":
            raise IdentityBindingError(
                f"role {credential.role!r} may not open a node link"
            )
        self._check_hello_identity(credential, hello)
        try:
            key = self._registry.get_key(hello.device_key_id)
        except PotluckError as exc:
            raise GatewayError(
                f"device key {hello.device_key_id!r} is not registered; a node must "
                "hold a key the server provisioned"
            ) from exc
        if key.purpose != "provider_device":
            raise IdentityBindingError(
                f"device key {hello.device_key_id!r} is registered for purpose "
                f"{key.purpose!r}, not provider_device"
            )
        if key.owner_id != hello.device_id:
            raise IdentityBindingError(
                f"hello claims device {hello.device_id!r} but key "
                f"{hello.device_key_id!r} is bound to {key.owner_id!r}"
            )
        if not key.is_valid_at(moment):
            raise GatewayError(f"device key {hello.device_key_id!r} is not valid now")
        # The store row, not only the registry copy, governs revocation, so a
        # device revoked by `admin revoke-key` cannot open a fresh link.
        self._reject_if_identity_revoked(hello.device_key_id, moment)
        self._registry.check_device_binding(hello.device_id, hello.provider_id)
        with self._lock:
            self._enqueues[hello.node_id] = enqueue
            unfinished = self._store.attempts_for_node(hello.node_id, unfinished_only=True)
            self._store.upsert_node(_node_record(hello, credential, moment, connected=True))
            resume = tuple(
                ResumeDirective(
                    request_id=attempt.request_id,
                    attempt_id=attempt.attempt_id,
                    epoch=attempt.dispatch_epoch,
                    # The server's own execution_state only records what it has
                    # SEEN. A node that died before its first event arrived is
                    # NULL here while its attempt was already accepted, so the
                    # safe instruction is always "replay and report": the node
                    # knows whether it executed, and the server does not.
                    action=(
                        "abandon" if attempt.status == "OFFERED" else "resend_spool"
                    ),
                )
                for attempt in unfinished
            )
            enqueue(
                Envelope(
                    type="hello.ack",
                    payload=HelloAck(
                        node_id=hello.node_id,
                        server_time=moment,
                        heartbeat_interval_s=DEFAULT_HEARTBEAT_INTERVAL_S,
                        resume=resume,
                    ).to_payload(),
                )
            )

    def node_disconnected(self, *, node_id: str, now: dt.datetime | None = None) -> None:
        """Mark a node offline; its unfinished attempts are re-offered by `tick`."""
        moment = now or self._moment()
        with self._lock:
            self._enqueues.pop(node_id, None)
            if self._store.get_node(node_id) is not None:
                self._store.set_node_connected(node_id, connected=False, at=moment)

    def handle_node_message(
        self, *, node_id: str, envelope: Envelope, now: dt.datetime | None = None
    ) -> list[Envelope]:
        """Apply one message from a node and return the replies addressed to it.

        Anything addressed to *another* node is delivered through that node's own
        enqueue callback, after this method has released its lock, so a slow peer
        cannot stall the server.

        Raises:
            GatewayError: If the node is not registered.
            ProtocolError: If the message is malformed or inconsistent with the
                stored attempt.
        """
        moment = now or self._moment()
        deliveries: list[tuple[str, Envelope]] = []
        with self._lock:
            if envelope.type == "node.hello":
                raise ProtocolError(
                    "node.hello must go through register_node; it is not a message "
                    "a node sends on an established link"
                )
            if self._store.get_node(node_id) is None:
                raise ProtocolError(
                    f"node {node_id!r} sent a message without a node.hello first"
                )
            if envelope.type == "attempt.accept":
                replies = self._on_accept(node_id, envelope, moment)
            elif envelope.type == "attempt.reject":
                replies = self._on_reject(node_id, envelope, moment, deliveries)
            elif envelope.type == "attempt.event":
                replies = self._on_event(node_id, envelope, moment, deliveries)
            elif envelope.type == "attempt.state":
                replies = self._on_state(node_id, envelope, moment, deliveries)
            elif envelope.type == "node.heartbeat":
                self._on_heartbeat(node_id, envelope, moment)
                replies = []
            elif envelope.type == "event.ack":
                raise ProtocolError("event.ack travels from the server to a node only")
            else:
                raise ProtocolError(
                    f"{envelope.type} is not a message a node sends to the server"
                )
        self._deliver(deliveries)
        return replies

    def tick(self, *, now: dt.datetime | None = None) -> list[tuple[str, Envelope]]:
        """Advance timers and return the messages to deliver.

        Three jobs, in order: expire requests past their deadline, offer requests
        that are waiting in the dispatch queue, and retire offers that waited past
        the accept timeout before offering again.

        The middle job *is* the queue: `requests_by_status` returns the waiting
        requests oldest-first, so the order they are offered in is the order they
        arrived in. That ordering is first-come-first-served on a best-effort
        basis and is not a promise about position — a request's own deadline, not
        its place in line, is what bounds its wait, and the server reports a wait
        it could not end as EXPIRED rather than pretending the queue guarantees
        anything.

        A request every candidate declined is re-offered to those same nodes once
        `QUEUE_REOFFER_BACKOFF_S` has passed, by dropping the declined set. That
        is how a node which freed up takes work it had already refused: the
        refusal was true when it was given and is not true forever. The backoff is
        what keeps it from being asked four times a second in the meantime.

        Expiry runs first and each offer is isolated, so one request that cannot
        be offered neither gets offered work it is already too late to run nor
        stops the sweep that ends it.
        """
        moment = now or self._moment()
        pairs: list[tuple[str, Envelope]] = []
        with self._lock:
            pairs.extend(self._expire_overdue_requests(moment))
            waiting = self._store.requests_by_status(
                "ROUTING", limit=max(1, self._config.max_queue_depth)
            )
            for record in waiting:
                if self._declined.get(record.request_id):
                    if moment - record.updated_at < dt.timedelta(
                        seconds=QUEUE_REOFFER_BACKOFF_S
                    ):
                        continue
                    self._declined.pop(record.request_id, None)
                pairs.extend(self._offer_isolated(record, moment, leaving_queue=True))
            for attempt in self._stuck_attempts(moment):
                ref = AttemptRef(
                    request_id=attempt.request_id,
                    attempt_id=attempt.attempt_id,
                    epoch=attempt.dispatch_epoch,
                )
                pairs.append(
                    (
                        attempt.node_id or "",
                        Envelope(type="attempt.query", payload=ref.to_payload()),
                    )
                )
            for attempt in self._stale_offers(moment):
                self._store.set_attempt_status(
                    attempt.attempt_id, "FAILED", at=moment, execution_state="FAILED"
                )
                owner = self._store.get_request(attempt.request_id)
                if owner is None:
                    continue
                self._store.set_request_status(
                    owner.request_id,
                    owner.status,
                    billing_note=(
                        f"offer not accepted within "
                        f"{self._config.offer_accept_timeout_s:g}s"
                    ),
                    at=moment,
                )
                pairs.extend(self._offer_isolated(owner, moment))
        return pairs

    # -- dispatch -----------------------------------------------------------

    def _offer_new_attempt(
        self, record: RequestRecord, moment: dt.datetime, *, leaving_queue: bool = False
    ) -> list[tuple[str, Envelope]]:
        """Open one attempt on the best available node and offer it.

        Args:
            record: The request to dispatch.
            moment: The server's clock.
            leaving_queue: Whether this request was waiting for a node when the
                offer went out. It decides whether the offer is recorded on the
                request's event stream as a queue exit: a request dispatched
                straight from its own admission never joined the queue, and an
                event saying it left one would be a frame about a transition that
                did not happen.

        Returns:
            `(node_id, offer)` pairs to deliver. An empty list means either that
            no node can take the work right now — the request stays live and
            `tick` offers again — that the attempt budget is spent, or that the
            request holds nothing dispatchable and has just been ended with the
            reason on its `billing_note`.
        """
        commit = self._store.output_commit(record.request_id)
        if (
            commit is not None
            or record.status in ("FAILED", "CANCELLED", "EXPIRED", "SUCCEEDED")
        ):
            return []
        attempts = self._store.attempts_for_request(record.request_id)
        # The budget counts executions, not offers. An offer a node refused
        # consumed no tokens, so it occupies no slot; see
        # `ServerStore.count_budget_attempts`.
        if self._store.count_budget_attempts(record.request_id) >= record.max_attempts:
            if record.status not in ("FAILED", "CANCELLED", "EXPIRED", "SUCCEEDED"):
                self._store.set_request_status(
                    record.request_id,
                    "FAILED",
                    billing_note="attempt budget exhausted",
                    at=moment,
                )
            return []
        try:
            inputs = self._store.get_request_input(record.request_id)
        except PotluckError as exc:
            # A row an earlier server version stored as a flattened prompt: it has
            # no conversation to offer and no digest to settle against, and it
            # never will. Ending it here rather than raising is what keeps one
            # such row from being offered again on every tick for as long as the
            # server runs.
            self._terminate_undispatchable(record.request_id, "FAILED", str(exc), moment)
            return []
        if inputs is None:
            # Nothing was ever stored to dispatch, so this request cannot make
            # progress: end it with the reason on the books instead of leaving it
            # occupying a slot and failing every caller that looks at it.
            self._terminate_undispatchable(
                record.request_id,
                "FAILED",
                f"request {record.request_id} has no stored dispatch inputs",
                moment,
            )
            return []
        node = self._pick_node(
            inputs["model"],
            self._declined.get(record.request_id, set()),
            moment,
            # A session's next turn goes back to the node that served its last
            # one when that node is still a candidate, and anywhere else when it
            # is not. Read per dispatch rather than cached, so a node that has
            # since disconnected or been revoked is not preferred.
            prefer=self._store.session_preference_for(record.request_id),
        )
        if node is None:
            return []
        index = len(attempts) + 1
        attempt_id = f"{record.request_id}-a{index}"
        for previous in attempts:
            # Opening a branch demotes the others, which is what makes a late
            # delta from a superseded attempt refuseable rather than spliceable.
            self._store.set_attempt_status(
                previous.attempt_id, previous.status, at=moment, output_eligible=False
            )
        self._store.upsert_attempt(
            attempt_id=attempt_id,
            request_id=record.request_id,
            node_id=node.node_id,
            resource_id=node.node_id,
            provider_id=node.provider_id,
            dispatch_epoch=index,
            at=moment,
        )
        self._store.set_attempt_status(attempt_id, "OFFERED", at=moment)
        self._store.set_request_status(
            record.request_id,
            "RUNNING",
            selected_attempt_id=attempt_id,
            at=moment,
        )
        # Leaving the queue is as much a fact about the request as joining it, so
        # it lands on the same stream: a consumer reading the events sees which
        # attempt the wait ended in without polling the status for it.
        if leaving_queue:
            self._append_dispatch_event(
                record.request_id,
                DISPATCHED_EVENT_TYPE,
                {"attempt_id": attempt_id, "node_id": node.node_id},
                moment,
            )
        attempt = self._store.get_attempt(attempt_id)
        assert attempt is not None
        return [(node.node_id, self._offer_envelope(attempt, moment))]

    def _offer_envelope(self, attempt: AttemptRecord, moment: dt.datetime) -> Envelope:
        """Build the offer for a stored attempt.

        Raises:
            GatewayError: If the request has no stored dispatch inputs.
        """
        inputs = self._store.get_request_input(attempt.request_id)
        if inputs is None:
            raise GatewayError(f"request {attempt.request_id} has no stored dispatch inputs")
        request = self._store.get_request(attempt.request_id)
        if request is None:
            raise GatewayError(f"unknown request {attempt.request_id}")
        authorization = signed_record_from_dict(inputs["authorization"])
        authorization_hash = canonical_digest(dict(authorization.payload))
        max_charge = int(str(authorization.payload.get("max_charge_milli_credits", "0")))
        messages = parse_chat_messages(inputs["messages"])
        parameters = dict(inputs["parameters"])
        # The same digest the authorization names, re-derived from what is
        # actually about to be dispatched: one definition of "the work", so a
        # node's permit and the consumer's signature cover the same bytes.
        request_digest = compute_request_digest(
            messages=messages,
            model=inputs["model"],
            delivery_mode=request.delivery_mode,
            parameters=parameters,
        )
        # The offer carries the request's own remaining budget, never a fixed
        # window. An agent session may legitimately hold a thirty-minute or a
        # twenty-four-hour deadline, and a node that honoured a sixty-second
        # offer deadline would abandon work the request explicitly paid for;
        # the contract names this field normative, so the number must mean the
        # request's real bound. The request's deadline stays the authoritative
        # end — the sweep enforces it either way — and this is the node-facing
        # expression of the same number, floored at zero because a request
        # whose deadline passed is ended by the sweep rather than offered.
        remaining_ms = DEFAULT_DEADLINE_MS
        if request.deadline_at is not None:
            remaining_ms = max(
                0, int((request.deadline_at - moment).total_seconds() * 1000)
            )
        offer = AttemptOffer(
            request_id=attempt.request_id,
            attempt_id=attempt.attempt_id,
            epoch=attempt.dispatch_epoch,
            resource_id=attempt.resource_id,
            model=inputs["model"],
            request_digest=request_digest,
            max_milli_credits=max_charge,
            deadline_ms=remaining_ms,
            delivery_mode=cast(DeliveryMode, request.delivery_mode),
            messages=messages,
            parameters=parameters,
            authorization_hash=authorization_hash,
            permit_hash=compute_permit_hash(
                request_id=attempt.request_id,
                attempt_id=attempt.attempt_id,
                epoch=attempt.dispatch_epoch,
                model=inputs["model"],
                request_digest=request_digest,
                max_milli_credits=max_charge,
                authorization_hash=authorization_hash,
            ),
        )
        return Envelope(type="attempt.offer", payload=offer.to_payload())

    def _pick_node(
        self,
        model: str,
        exclude: set[str],
        moment: dt.datetime,
        prefer: str | None = None,
    ) -> NodeRecord | None:
        """Return the connected node to run `model` on, or None.

        The rule is one candidate set and two ways of choosing inside it. A node
        is a candidate when it is connected, still shares, runs `model`, has not
        declined this request, and its device key is not revoked. Among the
        candidates, `prefer` wins when it is one of them; otherwise the lowest
        node id does.

        `prefer` is the node that served this session's last settled turn, and it
        is a *preference and never a constraint*. One session's turns are one
        conversation, and the node that already ran its earlier turns is the one
        whose upstream is most likely to still hold that context — so the
        preference is a cost saving, not a routing policy. The moment it is not
        also a candidate the ordinary rule applies: a node that disconnected, was
        revoked, paused sharing or declined this request is skipped rather than
        waited for, because a session that sticks to an unavailable node is a
        session that stops working.

        Deterministic on purpose: a test can predict the choice, and an operator
        reading a trace sees the same rule the code applies.

        A node whose device key ``admin revoke-key`` revoked is skipped too, so
        an already-connected session that has since been revoked is offered no
        new work: the revocation bites dispatch on the running server through a
        store re-read, not only the next reconnect. Skipping (rather than
        tearing the socket down here) keeps this on the dispatch decision alone;
        the revoked node's own next message or reconnect is refused elsewhere.
        """
        candidates = [
            record
            for record in self._store.connected_nodes(model=model)
            if record.share_enabled
            and record.node_id not in exclude
            and not self._store.identity_revoked(record.device_id, moment)
        ]
        if not candidates:
            return None
        if prefer is not None:
            for record in candidates:
                if record.node_id == prefer:
                    return record
        return min(candidates, key=lambda record: record.node_id)

    # -- node message handlers ---------------------------------------------

    def _ref_attempt(self, node_id: str, ref: AttemptRef) -> AttemptRecord:
        """Resolve an attempt reference, refusing a peer that does not own it.

        Raises:
            ProtocolError: If the attempt is unknown to the server's store, is
                assigned to another node, names another request, or the epoch is
                stale — each of which means the peer is speaking about work that
                is not its own.
        """
        attempt = self._store.get_attempt(ref.attempt_id)
        if attempt is None:
            raise ProtocolError(f"unknown attempt {ref.attempt_id}")
        if attempt.request_id != ref.request_id:
            raise ProtocolError(
                f"attempt {ref.attempt_id} belongs to request "
                f"{attempt.request_id}, not {ref.request_id}"
            )
        if attempt.node_id != node_id:
            raise ProtocolError(
                f"attempt {ref.attempt_id} is assigned to node "
                f"{attempt.node_id!r}, not {node_id!r}"
            )
        if attempt.dispatch_epoch != ref.epoch:
            raise ProtocolError(
                f"attempt {ref.attempt_id} has dispatch epoch "
                f"{attempt.dispatch_epoch}, not {ref.epoch}"
            )
        return attempt

    def _permit_hash_for(self, attempt: AttemptRecord, moment: dt.datetime) -> str:
        """Recompute the permit hash from durable rows.

        The hash a node signs its acceptance against is a pure function of the
        request's stored dispatch inputs and the attempt's own dispatch fields, so
        a restart that lost the in-memory offer can still verify it. Re-deriving
        here rather than reading ``self._offers`` is what lets an executed attempt
        settle after the server restarts, instead of being silently free.

        Raises:
            GatewayError: If the request or its dispatch inputs are missing.
        """
        request = self._store.get_request(attempt.request_id)
        if request is None:
            raise GatewayError(f"request {attempt.request_id} not found")
        inputs = self._store.get_request_input(attempt.request_id)
        if inputs is None:
            raise GatewayError(f"request {attempt.request_id} has no stored dispatch inputs")
        authorization = signed_record_from_dict(inputs["authorization"])
        authorization_hash = canonical_digest(dict(authorization.payload))
        max_charge = int(str(authorization.payload.get("max_charge_milli_credits", "0")))
        messages = parse_chat_messages(inputs["messages"])
        parameters = dict(inputs["parameters"])
        request_digest = compute_request_digest(
            messages=messages,
            model=inputs["model"],
            delivery_mode=request.delivery_mode,
            parameters=parameters,
        )
        return compute_permit_hash(
            request_id=attempt.request_id,
            attempt_id=attempt.attempt_id,
            epoch=attempt.dispatch_epoch,
            model=inputs["model"],
            request_digest=request_digest,
            max_milli_credits=max_charge,
            authorization_hash=authorization_hash,
        )

    def _on_accept(
        self, node_id: str, envelope: Envelope, moment: dt.datetime
    ) -> list[Envelope]:
        """Record an acceptance and authorise execution.

        The permit hash is re-derived from durable rows rather than read from the
        in-memory offer, so an acceptance that arrives after a restart — when that
        offer is gone — is still verified and still authorises execution. The
        acceptance commitment itself is persisted, because it folds the node's own
        accepted_at and cannot be recomputed; the matching usage report reads it
        back to settle.

        Raises:
            ProtocolError: If the acceptance does not match the offered terms,
                or the attempt was already accepted on different terms.
        """
        decision = AttemptDecision.from_payload(envelope.payload, accepted=True)
        attempt = self._ref_attempt(node_id, decision.ref)
        expected = self._permit_hash_for(attempt, moment)
        if decision.permit_hash != expected:
            self._store.set_attempt_status(
                attempt.attempt_id, "FAILED", at=moment, execution_state="FAILED"
            )
            raise ProtocolError(
                "acceptance does not match the offered terms; the attempt is abandoned"
            )
        # A re-ask under the same terms is idempotent: the node may legitimately
        # regenerate its acceptance commitment, because that digest covers the
        # instant it accepted. What it may not do is change the terms, and the
        # permit-hash check above already refuses that.
        self._store.set_attempt_status(
            attempt.attempt_id,
            "ACCEPTED",
            at=moment,
            acceptance_hash=decision.acceptance_hash,
        )
        return [Envelope(type="attempt.execute", payload=decision.ref.to_payload())]

    def _on_reject(
        self,
        node_id: str,
        envelope: Envelope,
        moment: dt.datetime,
        deliveries: list[tuple[str, Envelope]],
    ) -> list[Envelope]:
        """Handle a local-policy refusal by re-offering elsewhere, or by waiting.

        The refusal is a real fact about the node, so it is recorded on the
        request's billing note where the consumer can read it, and on the attempt
        row where the dispatch budget reads it: this offer consumed no tokens, so
        it occupies no slot in a budget that exists to bound executions.

        When nothing else can take the work the request goes back into the
        dispatch queue instead of being ended, provided the server holds a queue
        at all. That is the difference between a pool that is momentarily full and
        a request that can never run: the first ends when a node frees up, which
        `tick` discovers by asking the nodes that declined again, and the second
        is what `ModelUnavailable` at admission is for. A server configured not to
        hold work keeps the old answer and fails the request here.
        """
        decision = AttemptDecision.from_payload(envelope.payload, accepted=False)
        attempt = self._ref_attempt(node_id, decision.ref)
        reason = decision.reason or "no reason given"
        self._declined.setdefault(attempt.request_id, set()).add(node_id)
        self._store.set_attempt_status(
            attempt.attempt_id, "FAILED", at=moment, execution_state="FAILED"
        )
        self._store.mark_attempt_refused(attempt.attempt_id, at=moment)
        record = self._store.get_request(attempt.request_id)
        if record is None:
            return []
        self._store.set_request_status(
            record.request_id,
            record.status,
            billing_note=f"node {node_id} declined: {reason}",
            at=moment,
        )
        offered = self._offer_new_attempt(record, moment)
        deliveries.extend(offered)
        if offered:
            return []
        # The bound is checked here too, and not only at admission: a request
        # admitted while a node looked available joins the queue when that node
        # declines, so this is the door most queued requests actually come through.
        # A caller cannot be refused any more — it was told the request was
        # admitted — so a full queue ends the request with the reason on its books
        # instead of holding it past what the server agreed to hold.
        if not self._config.queue_enabled or self._queue_is_full():
            self._store.set_request_status(
                record.request_id,
                "FAILED",
                billing_note=f"no node left to take the work: {reason}",
                at=moment,
            )
            return []
        # Back in the queue, with the reason on both the books and the request's
        # own event stream. The status goes back to ROUTING because that is the
        # status `tick` offers from: leaving it RUNNING would hide a waiting
        # request from the very loop that is supposed to find it a node.
        self._store.set_request_status(
            record.request_id,
            "ROUTING",
            billing_note=f"waiting for a node: {node_id} declined: {reason}",
            at=moment,
        )
        self._append_dispatch_event(
            record.request_id,
            QUEUED_EVENT_TYPE,
            {"reason": f"node {node_id} declined: {reason}"},
            moment,
        )
        return []

    def _on_event(
        self,
        node_id: str,
        envelope: Envelope,
        moment: dt.datetime,
        deliveries: list[tuple[str, Envelope]],
    ) -> list[Envelope]:
        """Ingest one attempt event, commit output, and settle on final usage.

        The revoked-key check runs **before** the replay short-circuit below.
        A usage report is journalled before it is verified, so a report the
        server refused once would otherwise still be on file: a resent copy —
        or the same copy after a restart — would satisfy ``event.seq <=
        acked`` and be silently acknowledged, handing a revoked device a
        receipt it never earned. Checking first makes refusal the single
        outcome for its report, whenever it arrives.

        Raises:
            KeyRevokedError: If a ``usage.final`` report is signed by a key the
                store has revoked at `moment`.
        """
        event = AttemptEvent.from_payload(envelope.payload)
        attempt = self._ref_attempt(node_id, event.ref)
        if event.event_type == "usage.final" and event.report is not None:
            report = signed_record_from_dict(event.report)
            try:
                self._reject_if_identity_revoked(report.signer_key_id, moment)
            except KeyRevokedError:
                # The device was revoked before its final report landed. The
                # report still buys nothing — the refusal is re-raised so the
                # node is told and nothing settles — but the request must not
                # hang until its deadline or be re-offered to a second node that
                # would spend again. Give it a named terminal result first.
                self._terminate_revoked_report(attempt, moment)
                raise
        acked = self._store.last_attempt_seq(attempt.attempt_id)
        # An ACK promises that everything up to `acked` is durably *done*. For a
        # `usage.final` the event row is written before the usage is ingested, so
        # a crash — or a settlement the store refused — can leave the row on file
        # with the usage unrecorded and the request unsettled. A replay that the
        # plain sequence check would acknowledge must therefore be re-ingested
        # whenever the durable usage is not yet final; otherwise the request can
        # never settle and a rejected report would be silently accepted on resend.
        if event.seq <= acked and not self._usage_final_needs_ingest(event, attempt):
            return [_ack_envelope(attempt.attempt_id, acked)]
        # A superseded branch may not publish output. It is told to stop in the
        # same reply that acknowledges its event, so it can wind down without
        # the server re-reading the same stale delta forever. Its usage still
        # counts — real tokens were spent — it just is not the billed branch.
        superseded = not attempt.output_eligible
        if superseded and event.event_type == "output.delta":
            ref = AttemptRef(
                request_id=attempt.request_id,
                attempt_id=attempt.attempt_id,
                epoch=attempt.dispatch_epoch,
            )
            stop = Envelope(
                type="attempt.cancel",
                payload={**ref.to_payload(), "origin": "superseded"},
            )
            return [stop, _ack_envelope(attempt.attempt_id, acked)]
        if event.event_type == "output.delta":
            # Chunk-level atomic publish (network contract v0.1 §6): the delta and the
            # decision of whether this attempt still owns the request's output
            # stream share one transaction. A chunk that lost the race is
            # refused with nothing written — the consumer stream holds the
            # winner's text and nothing else — and the two-step "store the
            # delta, then decide the winner" crash window is gone by
            # construction.
            accepted, _cursor = self._store.commit_output_segment(
                request_id=attempt.request_id,
                attempt_id=attempt.attempt_id,
                expected_epoch=attempt.dispatch_epoch,
                event_seq=event.seq,
                payload=event.to_payload(),
                at=moment,
            )
            if not accepted:
                self._store.set_attempt_status(
                    attempt.attempt_id, "FAILED", at=moment, execution_state="FAILED"
                )
                ref = AttemptRef(
                    request_id=attempt.request_id,
                    attempt_id=attempt.attempt_id,
                    epoch=attempt.dispatch_epoch,
                )
                stop = Envelope(
                    type="attempt.cancel",
                    payload={**ref.to_payload(), "origin": "superseded"},
                )
                return [stop, _ack_envelope(attempt.attempt_id, acked)]
            return [
                _ack_envelope(
                    attempt.attempt_id, self._store.last_attempt_seq(attempt.attempt_id)
                )
            ]
        self._store.append_event(
            request_id=attempt.request_id,
            attempt_id=attempt.attempt_id,
            attempt_seq=event.seq,
            event_type=event.event_type,
            payload=event.to_payload(),
            at=moment,
        )
        if event.event_type == "usage.final":
            self._ingest_usage(attempt, event, moment)
        elif event.event_type == "attempt.failed":
            self._store.set_attempt_status(
                attempt.attempt_id, "FAILED", at=moment, execution_state="FAILED"
            )
            if superseded:
                return [
                    _ack_envelope(
                        attempt.attempt_id,
                        self._store.last_attempt_seq(attempt.attempt_id),
                    )
                ]
            self._record_uncertain_usage(attempt)
            action = self._recovery_action(attempt, moment, status="FAILED")
            if action == "retry_on_another_resource":
                record = self._store.get_request(attempt.request_id)
                if record is not None:
                    self._declined.setdefault(attempt.request_id, set()).add(node_id)
                    deliveries.extend(self._offer_new_attempt(record, moment))
                    if deliveries:
                        return [
                            _ack_envelope(
                                attempt.attempt_id,
                                self._store.last_attempt_seq(attempt.attempt_id),
                            )
                        ]
            self._store.set_request_status(
                attempt.request_id,
                "FAILED",
                billing_note=f"attempt failed: {event.detail or 'no detail given'}",
                at=moment,
            )
        elif event.event_type == "attempt.completed":
            self._store.set_attempt_status(
                attempt.attempt_id, "COMPLETED", at=moment, execution_state="SUBMITTED"
            )
            if superseded:
                return [
                    _ack_envelope(
                        attempt.attempt_id,
                        self._store.last_attempt_seq(attempt.attempt_id),
                    )
                ]
            settled = self._store.get_settlement(attempt.request_id, 1) is not None
            if settled:
                self._store.set_request_status(attempt.request_id, "SUCCEEDED", at=moment)
            else:
                self._record_uncertain_usage(attempt)
                self._store.set_request_status(
                    attempt.request_id,
                    "FAILED",
                    billing_note=(
                        "attempt completed but its usage stays unknown until a "
                        "final report arrives"
                    ),
                    at=moment,
                )
        return [
            _ack_envelope(attempt.attempt_id, self._store.last_attempt_seq(attempt.attempt_id))
        ]

    def _on_state(
        self,
        node_id: str,
        envelope: Envelope,
        moment: dt.datetime,
        deliveries: list[tuple[str, Envelope]],
    ) -> list[Envelope]:
        """Reconcile a node's report about an attempt it may or may not have run."""
        state = AttemptState.from_payload(envelope.payload)
        attempt = self._ref_attempt(node_id, state.ref)
        if state.certainty == "unknown":
            self._store.mark_usage_unknown(attempt.attempt_id, at=moment)
            self._store.set_attempt_status(
                attempt.attempt_id,
                "OUTCOME_UNKNOWN",
                at=moment,
                execution_state="UNKNOWN",
            )
            self._store.set_request_status(
                attempt.request_id,
                "FAILED",
                billing_note="execution outcome is unknown; usage stays unknown",
                at=moment,
            )
            return []
        never_started = (
            state.state == "FAILED"
            and state.certainty == "not_submitted"
            and state.upstream_calls == 0
        )
        if never_started:
            self._store.set_attempt_status(
                attempt.attempt_id, "FAILED", at=moment, execution_state="FAILED"
            )
            record = self._store.get_request(attempt.request_id)
            if record is not None:
                deliveries.extend(self._offer_new_attempt(record, moment))
        return []

    def _on_heartbeat(self, node_id: str, envelope: Envelope, moment: dt.datetime) -> None:
        """Refresh a node's liveness and its advertised sharing state."""
        heartbeat = NodeHeartbeat.from_payload(envelope.payload)
        record = self._store.get_node(node_id)
        if record is None:
            raise GatewayError(f"node {node_id!r} has never registered")
        self._store.upsert_node(
            replace(record, share_enabled=heartbeat.share_enabled, last_seen_at=moment)
        )

    # -- settlement ---------------------------------------------------------

    def _usage_final_needs_ingest(
        self, event: AttemptEvent, attempt: AttemptRecord
    ) -> bool:
        """Whether a replayed `usage.final` still has work the first delivery left undone.

        "Final" means the durable state proves the usage was recorded: either the
        request settled (the winning branch) or the attempt's usage is
        ``COMPLETE`` (a superseded branch, whose usage is counted but not billed).
        ``UNKNOWN`` deliberately does **not** count as final — it says the total
        is still unknown, so a later real report must be able to replace it.

        Only a well-formed `usage.final` (with both a usage total and a signed
        report) can be pending; anything else keeps the plain sequence
        short-circuit.
        """
        if event.event_type != "usage.final" or event.usage is None or event.report is None:
            return False
        if self._store.get_settlement(attempt.request_id, 1) is not None:
            return False
        return attempt.usage_status != "COMPLETE"

    def _ingest_usage(
        self, attempt: AttemptRecord, event: AttemptEvent, moment: dt.datetime
    ) -> None:
        """Record a final usage, settling only when the branch is the winner.

        Both branches may spend real tokens, so both are recorded; only the
        branch whose output was committed is billed.

        Before anything is recorded or settled, the reporting device key is
        checked against the **store**, not only the in-memory registry.
        `admin revoke-key` writes the store, so a device revoked while the
        server runs would otherwise keep reporting and settling until a
        restart; reading the row here is what makes the revocation bite on the
        reporting path exactly as it already does on the request-signature path.

        Raises:
            KeyRevokedError: If the report's signing key is revoked in the store
                at `moment`.
        """
        assert event.usage is not None
        report = signed_record_from_dict(event.report or {})
        self._reject_if_identity_revoked(report.signer_key_id, moment)
        if not attempt.output_eligible:
            self._store.record_usage(attempt.attempt_id, event.usage.total_tokens, at=moment)
            self._store.set_attempt_status(attempt.attempt_id, "COMPLETED", at=moment)
            return
        if self._store.get_settlement(attempt.request_id, 1) is not None:
            return
        measured = _report_total(report)
        if measured != event.usage.total_tokens:
            raise ProtocolError(
                f"the event announces {event.usage.total_tokens} tokens while its "
                f"signed report measures {measured}; refusing to settle either total"
            )
        expected = self._permit_hash_for(attempt, moment)
        if str(report.payload.get("permit_hash", "")) != expected:
            raise ProtocolError("the report's permit hash is not the one the server issued")
        stored = self._store.get_attempt(attempt.attempt_id)
        if stored is None or stored.acceptance_hash is None:
            raise GatewayError(
                f"attempt {attempt.attempt_id} has no stored acceptance; it was "
                "accepted before acceptance persistence existed, so its usage "
                "cannot be verified after a restart"
            )
        claimed = str(report.payload.get("acceptance_hash", ""))
        if stored.acceptance_hash != claimed:
            raise ProtocolError(
                "the report's acceptance hash is not the one the node accepted"
            )
        inputs = self._store.get_request_input(attempt.request_id)
        if inputs is None:
            raise GatewayError(f"request {attempt.request_id} has no stored dispatch inputs")
        self._ensure_provider_account(attempt.provider_id, moment)
        contract = derive_allocation_contract(
            request_id=attempt.request_id,
            provider_id=attempt.provider_id,
            epoch=attempt.dispatch_epoch,
        )
        # `engine.settle` moves the in-memory credit and appends to the in-memory
        # log before anything is durable. If the durable write then fails, the
        # process is ahead of the store, so the books are rebuilt from the store
        # and the failure re-raised: the intermediate state must never leak into
        # a later settlement's log index or receipt hash chain.
        try:
            result: SettlementResult = self._engine.settle(
                request_id=attempt.request_id,
                service_unit_id=attempt.request_id,
                authorization=signed_record_from_dict(inputs["authorization"]),
                report=report,
                contract=contract,
                contract_hash=canonical_digest(contract.digest_payload()),
                settlement_private_key=self._settlement_key,
                winner_attempt_id=attempt.attempt_id,
                settled_at=moment,
            )
            self._record_settlement(
                attempt, result, moment, settled_tokens=event.usage.total_tokens
            )
        except BaseException:
            self._resync_books()
            raise

    def _record_settlement(
        self,
        attempt: AttemptRecord,
        result: SettlementResult,
        moment: dt.datetime,
        *,
        settled_tokens: int,
    ) -> None:
        """Persist a settlement and everything backing it, in one transaction.

        The log leaf, receipt, settlement revision, ledger journal, attempt usage
        and request status commit together, so an interruption cannot leave a
        durable receipt with no journal behind the payment, nor a log leaf with
        no settlement. A retry with the same content writes nothing new, which is
        what makes the resend after a lost acknowledgement idempotent.

        `settled_tokens` is the node's own measured native total, carried beside
        the charge so the session aggregate can keep the two apart: what the
        upstream consumed and what the consumer was billed for it are different
        numbers and reporting one as the other would make a session's totals
        unreadable.
        """
        receipt = result.receipt
        receipt_text = _canonical_text(_signed_record_to_dict(receipt))
        self._store.record_settlement_bundle(
            settlement=SettlementRecord(
                service_unit_id=attempt.request_id,
                revision=1,
                fingerprint=canonical_digest(
                    {
                        "receipt_hash": receipt.hash,
                        "journal_id": result.journal.journal_id,
                        "billable": dict(sorted(result.allocations.items())),
                    }
                ),
                receipt_id=receipt.record_id,
                receipt_hash=receipt.hash,
                log_index=result.log_index,
                receipt_json=receipt_text,
                created_at=moment,
            ),
            receipt=ReceiptRecord(
                receipt_id=receipt.record_id,
                request_id=attempt.request_id,
                receipt_hash=receipt.hash,
                log_index=result.log_index,
                receipt_json=receipt_text,
                created_at=moment,
            ),
            journal_kind="journal",
            journal_payload={
                "journal_id": result.journal.journal_id,
                "kind": result.journal.kind,
                "idempotency_key": list(result.journal.idempotency_key),
                "postings": [[p.account, p.delta] for p in result.journal.postings],
                "service_unit_id": result.journal.service_unit_id,
            },
            attempt_id=attempt.attempt_id,
            usage_tokens=sum(result.allocations.values()),
            at=moment,
            settled_tokens=settled_tokens,
        )

    def _ensure_provider_account(self, provider_id: str, moment: dt.datetime) -> None:
        """Create a provider's earnings bucket before crediting it.

        The first settlement for a provider opens its ``/pending`` account and
        records the creation in the replay log, so a rebuilt ledger opens it at
        the same point. Skipping the log entry would leave a rebuilt ledger
        without the account and every later replay would fail.
        """
        account_id = f"{provider_id}/pending"
        with self._lock:
            recorded = any(
                kind == "account" and payload.get("account_id") == account_id
                for _seq, kind, payload in self._store.ledger_events()
            )
            if recorded:
                return
            self._ledger.account(account_id, cast(Any, "provider_pending"))
            # `_rebuild_ledger` reopens this account from the `account_kind` in
            # this payload; recording only the id leaves a rebuilt ledger unable
            # to interpret it, so a restart after a first settlement would fail.
            self._record_ledger(
                "account",
                {"account_id": account_id, "account_kind": "provider_pending"},
                moment,
            )

    def _recovery_action(
        self, attempt: AttemptRecord, moment: dt.datetime, *, status: str
    ) -> str:
        """Run the recovery decision table for a failed attempt.

        Every input is derived from persisted state: the delivery mode and the
        deadline come from the request, output commitment from the store, and
        the failure facts from the node's report.
        """
        request = self._store.get_request(attempt.request_id)
        if request is None:
            return "fail_explicitly"
        deadline = request.deadline_at
        remaining = 0 if deadline is None else int((deadline - moment).total_seconds() * 1000)
        return decide_recovery(
            RecoveryContext(
                attempt_status=cast(Any, status),
                execution_certainty="submitted",
                output_committed=self._store.output_commit(attempt.request_id) is not None,
                buffered_mode=request.delivery_mode == "buffered_complete",
                original_execution_resumable=False,
                input_replayable=True,
                deadline_remaining_ms=remaining,
                has_external_side_effects=False,
                duplicate_execution_policy="bounded_model_only",
            )
        )

    def _record_uncertain_usage(self, attempt: AttemptRecord) -> None:
        """Mark usage unknown when no final usage ever arrived.

        A component may exist unaccounted for; recording zero would make it free.
        """
        if attempt.usage_status in ("EMPTY", "PROVISIONAL"):
            self._store.mark_usage_unknown(attempt.attempt_id, at=self._moment())

    def _terminate_revoked_report(self, attempt: AttemptRecord, moment: dt.datetime) -> None:
        """End a request whose device was revoked before its final usage landed.

        The revoked device's report is refused by the caller, but the request it
        belongs to must still reach a named result: leaving it live would either
        hang it until its deadline or let `tick` re-offer the work to a second
        node that spends again on a request the first node may already have run.
        Usage is marked *unknown*, never zero — the server cannot know whether
        the revoked device called upstream — and the request goes to FAILED with
        a billing note, so it surfaces for hand reconciliation instead of
        silently billing nothing.

        Idempotent: a repeated late report, or the same report replayed after a
        restart, finds the request already terminal and writes nothing, so the
        refusal stays the single outcome however many times the node retries.
        """
        record = self._store.get_request(attempt.request_id)
        if record is None or record.status in TERMINAL_REQUEST_STATES:
            return
        if attempt.usage_status in ("EMPTY", "PROVISIONAL"):
            self._store.mark_usage_unknown(attempt.attempt_id, at=moment)
        self._store.set_attempt_status(
            attempt.attempt_id, "OUTCOME_UNKNOWN", at=moment, execution_state="UNKNOWN"
        )
        self._store.set_request_status(
            attempt.request_id,
            "FAILED",
            billing_note=(
                "reporting device was revoked before its final usage report; "
                "usage stays unknown pending reconciliation"
            ),
            at=moment,
        )

    # -- timers -------------------------------------------------------------

    def _stuck_attempts(self, moment: dt.datetime) -> list[AttemptRecord]:
        """Return accepted attempts the server has heard nothing about.

        A node that accepted work and then went quiet may have executed or may
        have died; only the node knows, so the server asks instead of guessing.
        Without this probe the unknown-usage reconciliation has no online path.
        """
        quiet_for = dt.timedelta(seconds=self._config.offer_accept_timeout_s)
        stuck: list[AttemptRecord] = []
        for status in ("ROUTING", "RUNNING", "RECOVERING"):
            for record in self._store.requests_by_status(status, limit=256):
                for attempt in self._store.attempts_for_request(record.request_id):
                    if attempt.status not in ("ACCEPTED", "AUTHORIZED", "SUBMITTING", "RUNNING"):
                        continue
                    if attempt.node_id is None:
                        continue
                    if moment - attempt.updated_at > quiet_for:
                        stuck.append(attempt)
        return stuck

    def _stale_offers(self, moment: dt.datetime) -> list[AttemptRecord]:
        """Return offered attempts that waited past the accept timeout."""
        timeout = dt.timedelta(seconds=self._config.offer_accept_timeout_s)
        stale: list[AttemptRecord] = []
        for status in ("ROUTING", "RUNNING", "RECOVERING"):
            for record in self._store.requests_by_status(status, limit=256):
                for attempt in self._store.attempts_for_request(record.request_id):
                    if attempt.status != "OFFERED":
                        continue
                    if moment - attempt.updated_at > timeout:
                        stale.append(attempt)
        return stale

    def _cancel_pairs(
        self, record: RequestRecord, origin: str, moment: dt.datetime
    ) -> list[tuple[str, Envelope]]:
        """Build cancel envelopes for every live attempt of a request."""
        pairs: list[tuple[str, Envelope]] = []
        for attempt in self._store.attempts_for_request(record.request_id):
            if attempt.status not in _LIVE_ATTEMPT_STATES or attempt.node_id is None:
                continue
            ref = AttemptRef(
                request_id=record.request_id,
                attempt_id=attempt.attempt_id,
                epoch=attempt.dispatch_epoch,
            )
            pairs.append(
                (
                    attempt.node_id,
                    Envelope(
                        type="attempt.cancel",
                        payload={**ref.to_payload(), "origin": origin},
                    ),
                )
            )
        return pairs

    # -- helpers ------------------------------------------------------------

    def _moment(self) -> dt.datetime:
        """Return the fallback instant for operations that pass no time."""
        return self._default_now or dt.datetime.now(dt.UTC)

    def _reject_if_identity_revoked(self, key_id: str, moment: dt.datetime) -> None:
        """Refuse a key the store has revoked, even if the registry has not.

        The running registry is only a projection of the store; `admin
        revoke-key` writes the store alone. Any trust decision that would
        otherwise rest on the registry copy therefore re-reads the row here,
        with the same inclusive-at-the-instant semantics as
        `authenticate_signed_request`. A key with no store row (a key
        provisioned from ``server.json``) has nothing to test and is allowed, so
        this never changes a pre-existing deployment's meaning.

        Raises:
            KeyRevokedError: If the row exists and was revoked at or before
                `moment`.
        """
        row = self._store.get_identity(key_id)
        if row is None or row.revoked_at is None:
            return
        if _aware(moment) >= _aware(row.revoked_at):
            raise KeyRevokedError(
                f"key {key_id} was revoked at {row.revoked_at.isoformat()}; "
                "refusing to trust work it reports"
            )

    def _deliver(self, deliveries: list[tuple[str, Envelope]]) -> None:
        """Deliver messages to nodes, always outside the service lock.

        A node's sink may block on a slow socket; if it did so while the lock was
        held, one stalled peer would freeze every other request.
        """
        for node_id, envelope in deliveries:
            callback = self._enqueues.get(node_id)
            if callback is not None:
                callback(envelope)

    def _require_request(self, credential: Credential, request_id: str) -> RequestRecord:
        """Return the request, refusing another tenant's or an unknown one.

        Raises:
            StateTransitionError: If the request is unknown.
            IdentityBindingError: If it belongs to another tenant.
        """
        record = self._store.get_request(request_id)
        if record is None:
            raise StateTransitionError(f"unknown request {request_id}")
        if record.tenant_id != credential.tenant_id:
            raise IdentityBindingError(
                f"credential {credential.subject_id!r} may not read request "
                f"{request_id}, which belongs to tenant {record.tenant_id!r}"
            )
        return record

    def _settlement_summary(self, request_id: str) -> dict[str, Any] | None:
        """Return the request's settlement summary, if it settled."""
        stored = self._store.get_settlement(request_id, 1)
        if stored is None:
            return None
        return {
            "receipt_id": stored.receipt_id,
            "receipt_hash": stored.receipt_hash,
            "log_index": stored.log_index,
        }

    def _record_ledger(self, kind: str, payload: dict[str, Any], moment: dt.datetime) -> None:
        """Append one ledger replay event."""
        self._store.append_ledger_event(kind, payload, at=moment)

def _node_record(
    hello: NodeHello, credential: Credential, moment: dt.datetime, *, connected: bool
) -> NodeRecord:
    """Build the node record a hello should be stored as."""
    return NodeRecord(
        node_id=hello.node_id,
        device_id=hello.device_id,
        provider_id=hello.provider_id,
        adapter_name=hello.adapter_name,
        model=hello.model,
        share_enabled=hello.policy.share_enabled,
        max_concurrency=hello.policy.max_concurrency,
        max_local_reserved_milli_credits=hello.policy.max_local_reserved_milli_credits,
        policy_version=hello.policy.policy_version,
        connected=connected,
        last_seen_at=moment,
    )


def _ack_envelope(attempt_id: str, acked_seq: int) -> Envelope:
    """Build a contiguous-prefix acknowledgement."""
    return Envelope(
        type="event.ack",
        payload=EventAck(attempt_id=attempt_id, acked_seq=acked_seq).to_payload(),
    )


def _report_total(report: SignedRecord) -> int:
    """Return a report's normalized token total.

    Raises:
        ProtocolError: If the measurement is missing or not integral.
    """
    measurement = report.payload.get("measurement")
    if not isinstance(measurement, dict):
        raise ProtocolError("usage report carries no measurement object")
    usage = measurement.get("usage")
    if not isinstance(usage, dict):
        raise ProtocolError("usage report measurement has no usage object")
    try:
        return int(str(usage["input_total"])) + int(str(usage["output_total"]))
    except (KeyError, ValueError) as exc:
        raise ProtocolError(f"usage report measurement is not integral: {exc}") from exc


def _receipt_field(stored: ReceiptRecord, field: str) -> str | None:
    """Read one string field out of a stored receipt's signed payload.

    Args:
        stored: The receipt row, whose ``receipt_json`` is the serialized record.
        field: The payload field to read, e.g. ``journal_id``.

    Returns:
        The field's value, or `None` when the stored JSON is not a record object
        or carries no such string. A malformed row is reported as "absent" here
        and named as a difference by the reconciliation that reads it, rather
        than raising inside a view whose job is to render what is stored.
    """
    document = loads_strict(stored.receipt_json)
    if not isinstance(document, dict):
        return None
    payload = document.get("payload")
    if not isinstance(payload, dict):
        return None
    value = payload.get(field)
    return value if isinstance(value, str) and value else None


def _statement_entries(statement: dict[str, object]) -> list[dict[str, object]]:
    """Return a ledger statement's entries as a list of mappings.

    `Ledger.statement` types its result as ``dict[str, object]`` because it mixes
    balances and a list, so the entries need one narrowing step at the boundary
    rather than a cast at every use.

    Raises:
        GatewayError: If the statement carries no entry list, which would mean
            this build and the ledger disagree about the statement's shape.
        """
    entries = statement.get("entries")
    if not isinstance(entries, list):
        raise GatewayError("the ledger statement returned no entry list")
    return [dict(cast("dict[str, object]", entry)) for entry in entries]


def _signed_record_to_dict(record: SignedRecord) -> dict[str, Any]:
    """Serialize a signed record for storage and the wire."""
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


def _coerce_record(value: SignedRecord | dict[str, Any]) -> SignedRecord:
    """Return `value` as a signed record.

    A client sends the serialized form; tests and internal callers hold the
    record itself. Accepting both keeps the boundary honest without forcing the
    server layer to know the field order.
    """
    if isinstance(value, SignedRecord):
        return value
    return signed_record_from_dict(value)


def _canonical_text(document: dict[str, Any]) -> str:
    """Render a document as canonical JSON text, for durable storage."""
    return canonicalize(document).decode("utf-8")
