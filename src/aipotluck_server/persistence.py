"""Durable persistence for the center.

The center keeps its whole world replayable: which attempt won the output
race, every stored event body a disconnected consumer can resume from, every
settlement, receipt and transparency-log leaf, and the ordered ledger replay
log a restart rebuilds the in-memory books from. These failures are impossible
because the store, not the process, is the authority.

The node's own store (``NodeStore``) and the shared record shapes both sides
speak (``ExecutionRecord``, ``SpoolRecord``, ``ReceiptRecord``) live in the
``ai-potluck`` package; this module holds the shared ``_Store`` plumbing
carved to the center's schema, ``CenterStore`` built on it, and the
center-side record types.

Only the standard library is used. The project has exactly one runtime
dependency (``cryptography``) and adding another is not allowed, so this module
speaks SQLite directly.

Concurrency strategy
--------------------
Each store instance gives every thread its own `sqlite3.Connection` through
`threading.local()`, and every mutating operation runs inside
``BEGIN IMMEDIATE``. The alternative — one connection shared by all threads and
guarded by a single `RLock` — is simpler, but it would (a) require disabling
``check_same_thread`` and (b) serialize every read behind the writers' lock. The
per-thread design keeps the default ``check_same_thread=True`` (a connection is
created and used by exactly one thread) and pushes the critical section down to
SQLite's own write lock, so the compare-and-set in
:meth:`CenterStore.commit_output` is correct at the database level rather than
only within one process. With WAL enabled, readers do not block behind the
single writer.

Pragmas and why each matters
----------------------------
* ``busy_timeout=5000`` — a second writer that reaches ``BEGIN IMMEDIATE`` waits
  for the first to commit instead of failing immediately with ``SQLITE_BUSY``.
  Without it, a concurrent commit race would surface as a spurious error rather
  than a clean win/lose outcome.
* ``journal_mode=WAL`` — lets readers proceed while a writer holds the write
  lock, and keeps the database consistent across a crash. Restart durability is
  the entire point of the module, so this is not optional.
* ``foreign_keys=ON`` — SQLite disables foreign keys by default. We rely on
  ``attempts``/``events`` referencing an existing request so a half-written
  graph is rejected at the boundary instead of accumulating.

Timestamps
----------
Every instant is stored as ISO 8601 UTC text in a fixed format
(``%Y-%m-%dT%H:%M:%S.%f%z``), so lexical order equals chronological order and a
``WHERE created_at > ?`` predicate is a plain string comparison.

Digests
-------
Content digests and credential digests both go through
``aipotluck.canonical.canonical_digest`` (SHA-256 over the RFC 8785 canonical
encoding), with the same ``{"type": ..., "payload": ...}`` shape the in-memory
event store uses, so a replay that the coordinator accepts is the same replay
this store deduplicates. Credential lookup uses an unsalted digest on purpose: a
salt would have to be stored and would only re-derive the same lookup value, and
the raw token is a high-entropy secret, so a per-credential salt buys nothing
while breaking the constant-time-ish equality lookup. The raw token is never
written.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Self, cast

from aipotluck.canonical import canonical_digest, canonicalize, loads_strict
from aipotluck.errors import (
    ConflictError,
    PotluckError,
    ProtocolError,
    StateTransitionError,
)

# Explicit re-export: the shared record shape is defined once, in the client
# package, and center code and tests import it from here as well as from there.
from aipotluck.persistence import ReceiptRecord as ReceiptRecord
from aipotluck.statemachine import TERMINAL_REQUEST_STATES

#: Attempt states that mean "this attempt will never produce more work".
TERMINAL_ATTEMPT_STATUSES: frozenset[str] = frozenset(
    {"COMPLETED", "FAILED", "CANCELLED", "OUTCOME_UNKNOWN", "REVOKED_BEFORE_SUBMIT"}
)

#: The event type written for the first committed output segment.
OUTPUT_EVENT_TYPE = "output.delta"

_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f%z"

_Role = Literal["consumer", "node"]


def _to_text(value: dt.datetime) -> str:
    """Render an instant as fixed-width ISO 8601 UTC text.

    Raises:
        ValueError: If the value is naive, because a naive instant has no
            well-defined position on the timeline and would make ordering depend
            on the host's local zone.
    """
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(dt.UTC).strftime(_TS_FORMAT)


def _from_text(value: str) -> dt.datetime:
    """Parse fixed-width ISO 8601 UTC text written by `_to_text`."""
    return dt.datetime.strptime(value, _TS_FORMAT).astimezone(dt.UTC)


def _opt_instant(value: Any) -> dt.datetime | None:
    return None if value is None else _from_text(str(value))


def _opt_int(value: Any) -> int | None:
    """Return an optional integer column as `int | None`."""
    return None if value is None else int(value)


def _opt_text(value: Any) -> str | None:
    """Return an optional text column as `str | None`."""
    return None if value is None else str(value)


def _dump_payload(payload: dict[str, Any]) -> str:
    """Serialize a stored JSON payload in canonical form."""
    return canonicalize(payload).decode("utf-8")


def _load_payload(text: str) -> dict[str, Any]:
    """Parse a stored payload back into a mapping.

    Raises:
        PotluckError: If the stored bytes are not a JSON object, which means the
            row was corrupted outside this module.
    """
    value = loads_strict(text)
    if not isinstance(value, dict):
        raise PotluckError("stored payload is not a JSON object")
    return cast("dict[str, Any]", value)


def _event_digest(event_type: str, payload: dict[str, Any]) -> str:
    """Return the content digest for an event, matching `InMemoryEventStore`."""
    return canonical_digest({"type": event_type, "payload": payload})



# --------------------------------------------------------------------------
# Frozen record shapes
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Credential:
    """A resolved credential. The raw token is never part of this record.

    ``account_id`` is the consumer account this credential may commit money
    from, and it exists so admission can bind the authorization's payer to an
    account the center itself recorded rather than to a string the caller sent.
    It is ``None`` for a credential provisioned from ``center.json`` (which
    predates per-identity accounts); for those the historical ``subject_id``
    equality still governs, so no pre-existing deployment changes meaning.

    ``device_id`` is the contribution device a *node* credential speaks for, and
    it exists so a read scoped to one node can be derived from the credential
    instead of from the request or from the tenant. A node join mints the
    identity, the device and the link credential in one operation, so it is the
    only place that knows the credential and the device belong together; without
    this column the two rows share nothing but a tenant, and a tenant is shared
    by every member an operator invited into it. It is ``None`` for a consumer
    credential and for a node credential an operator provisioned in
    ``center.json``, which names no device — that path writes ``node.json`` by
    hand, and its documented sample dials with the credential's own subject as
    its ``node_id``.
    """

    tenant_id: str
    subject_id: str
    role: Literal["consumer", "node"]
    account_id: str | None = None
    device_id: str | None = None


@dataclass(frozen=True)
class RequestRecord:
    """One logical request, keyed by `request_id` and deduplicated by
    ``(tenant_id, idempotency_key)``."""

    request_id: str
    tenant_id: str
    subject_id: str
    idempotency_key: str
    payload_digest: str
    delivery_mode: str
    max_attempts: int
    service_unit_id: str
    status: str
    selected_attempt_id: str | None
    deadline_at: dt.datetime | None
    billing_note: str | None
    created_at: dt.datetime
    updated_at: dt.datetime
    #: The API key that admitted this request, or `None` for one admitted on a
    #: signature. Settlement reads it to count the charge against that key's
    #: quota, so a key's spend is a fact about the request rather than a
    #: connection the books have to reconstruct.
    api_key_id: str | None = None


@dataclass(frozen=True)
class AttemptRecord:
    """One dispatch attempt. `usage_tokens` is `None` for unknown, never 0."""

    attempt_id: str
    request_id: str
    node_id: str | None
    resource_id: str
    provider_id: str
    dispatch_epoch: int
    status: str
    output_eligible: bool
    usage_status: str
    usage_tokens: int | None
    settlement_status: str
    execution_state: str | None
    updated_at: dt.datetime


@dataclass(frozen=True)
class OutputCommitRecord:
    """The single winning output commit for a request."""

    request_id: str
    attempt_id: str
    generation_id: str
    committed_at_seq: int
    committed_at: dt.datetime


@dataclass(frozen=True)
class StoredEvent:
    """One replayable event, ordered by a per-request `cursor` from 1."""

    cursor: int
    request_id: str
    attempt_id: str
    attempt_seq: int
    event_type: str
    payload: dict[str, Any]
    created_at: dt.datetime


@dataclass(frozen=True)
class SettlementRecord:
    """A frozen settlement revision. Never overwritten once recorded."""

    service_unit_id: str
    revision: int
    fingerprint: str
    receipt_id: str
    receipt_hash: str
    log_index: int
    receipt_json: str
    created_at: dt.datetime



@dataclass(frozen=True)
class LogLeafRecord:
    """One leaf of the append-only transparency log."""

    log_index: int
    receipt_hash: str
    committed_at: dt.datetime


@dataclass(frozen=True)
class NodeRecord:
    """A contribution node and its last advertised local policy."""

    node_id: str
    device_id: str
    provider_id: str
    adapter_name: str
    model: str
    share_enabled: bool
    max_concurrency: int
    max_local_reserved_milli_credits: int
    policy_version: int
    connected: bool
    last_seen_at: dt.datetime


@dataclass(frozen=True)
class OutboxRecord:
    """A queued message awaiting delivery to a peer."""

    outbox_id: int
    kind: str
    payload: dict[str, Any]
    created_at: dt.datetime
    delivered_at: dt.datetime | None



@dataclass(frozen=True)
class InviteRecord:
    """One single-use-or-capped invite that mints an identity.

    Only the *digest* of the invite code is stored; the plaintext code exists
    exactly once, in the operator's terminal, and is never written here. The
    code is therefore its own credential: holding it is the authority to join,
    so there is nothing else to check at ``POST /v1/join``.
    """

    code_digest: str
    role: Literal["consumer", "node"]
    #: ``"auto"`` gives the joiner a private, server-derived tenant; anything
    #: else is a concrete tenant the joiner shares with every other admittee.
    tenant_scope: str
    expires_at: dt.datetime | None
    max_uses: int
    used_count: int
    created_at: dt.datetime
    revoked_at: dt.datetime | None
    #: Milli-credits minted into the identity's own account at join time. A
    #: joiner's account is funded once, from this quota, so the one-command
    #: ``join`` then ``ask`` path has something to spend without an operator
    #: funding each account by hand.
    quota_milli_credits: int = 20_000

    @property
    def remaining_uses(self) -> int:
        """How many more joins this invite still permits."""
        return max(0, self.max_uses - self.used_count)

    def is_redeemable_at(self, moment: dt.datetime) -> bool:
        """Report whether the invite could admit a joiner at `moment`.

        Revocation and expiry are both inclusive of their instant: at the
        revocation instant and at the expiry instant the invite is already dead,
        matching how the registry treats key revocation.
        """
        if self.revoked_at is not None and _as_utc(moment) >= _as_utc(self.revoked_at):
            return False
        if self.expires_at is not None and _as_utc(moment) >= _as_utc(self.expires_at):
            return False
        return self.used_count < self.max_uses


@dataclass(frozen=True)
class IdentityRecord:
    """A dynamically registered identity, and the key that speaks for it.

    This row — not the ``center.json`` file — is the source of truth for an
    invited identity: it carries the key material, the tenant it belongs to, its
    role, the consumer account admission must bind a payer to, and (for a
    contribution device) the provider it may report for. On every startup
    `deploy.load_center` replays these rows into a fresh `IdentityRegistry`, so a
    joined identity keeps working across a restart with no config edit.
    """

    key_id: str
    owner_id: str
    purpose: Literal["consumer", "provider_device"]
    public_key_b64: str
    tenant_id: str
    role: Literal["consumer", "node"]
    display_name: str | None
    #: Set only for ``provider_device`` rows: the provider account the device is
    #: bound to, so the device->provider binding survives a restart.
    provider_id: str | None
    registered_at: dt.datetime
    revoked_at: dt.datetime | None
    #: The consumer account admission binds this credential's payer to. For a
    #: consumer it is the identity's own account; for a contribution device it is
    #: the provider account the device reports for. ``None`` only on legacy or
    #: device rows that never spend.
    account_id: str | None = None
    #: The invite scope the identity was minted under (``"auto"`` or the concrete
    #: tenant). Used by the store to enforce that two *auto* identities may not
    #: silently share one private tenant, while a concrete scope may share by
    #: design.
    tenant_scope: str = "auto"


@dataclass(frozen=True)
class ConsumerBinding:
    """The tenant and account a consumer subject spends through.

    Derived by the store from the rows it already holds — an invited identity's
    own row first, then a credential an operator provisioned in ``center.json``
    — so nothing has to be told twice and an API key can never be minted for a
    subject the center has no account for.
    """

    subject_id: str
    tenant_id: str
    #: The account admission binds a payer to. For every consumer the center
    #: mints today this is the subject's own account; the column is read rather
    #: than assumed so a subject whose account is not its own name keeps working.
    account_id: str


@dataclass(frozen=True)
class ApiKeyRecord:
    """One operator-issued API key, and the quota it spends against.

    Only the *digest* of the key is stored, exactly as for a credential token or
    an invite code: the plaintext exists once, in the operator's terminal, so
    neither this table nor a backup of it can leak a usable key.

    A key authenticates a subject the center already knows; it does not create an
    identity, and it never widens what that subject may spend. The subject's own
    account balance stays the authority on money, while ``quota_milli_credits``
    caps what this one key may draw from it — so a key handed to a tool can be
    capped and revoked without touching the identity or any other key.
    """

    key_id: str
    key_hash: str
    #: The operator's own label for the key ("the IDE on the laptop"), so a
    #: listing can be read without the plaintext anybody still holds.
    name: str
    subject_id: str
    tenant_id: str
    quota_milli_credits: int
    #: Milli-credits actually settled against this key. Written by the same
    #: transaction that writes a settlement, so it counts each request once.
    used_milli_credits: int
    status: Literal["active", "revoked"]
    created_at: dt.datetime
    expires_at: dt.datetime | None
    revoked_at: dt.datetime | None
    #: When the key last admitted a request. ``None`` until it does: a key that
    #: has never been used is the one thing an operator can revoke without
    #: wondering what it will break.
    last_used_at: dt.datetime | None

    @property
    def remaining_milli_credits(self) -> int:
        """How much of the quota is left, never negative."""
        return max(0, self.quota_milli_credits - self.used_milli_credits)

    def is_usable_at(self, moment: dt.datetime) -> bool:
        """Report whether this key may authenticate a request at `moment`.

        Revocation and expiry are both inclusive of their instant, matching how
        the registry treats key revocation and how an invite treats its expiry.
        The quota is deliberately *not* part of this answer: an exhausted key is
        still a key the center knows, and admission has to be able to tell "this
        is not yours" (401) from "you have spent it" (429) rather than collapsing
        the two into one refusal.
        """
        if self.status != "active":
            return False
        moment_utc = _as_utc(moment)
        revoked = self.revoked_at is not None and moment_utc >= _as_utc(self.revoked_at)
        expired = self.expires_at is not None and moment_utc >= _as_utc(self.expires_at)
        return not revoked and not expired


def _as_utc(value: dt.datetime) -> dt.datetime:
    """Return `value` as UTC, refusing a naive instant.

    Raises:
        ValueError: If the value is naive, because a naive instant has no
            well-defined position on the timeline.
    """
    if value.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(dt.UTC)



_SCHEMA = """
CREATE TABLE IF NOT EXISTS credentials (
    token_digest TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    device_id TEXT
);

CREATE TABLE IF NOT EXISTS requests (
    request_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    delivery_mode TEXT NOT NULL,
    max_attempts INTEGER NOT NULL,
    service_unit_id TEXT NOT NULL,
    status TEXT NOT NULL,
    selected_attempt_id TEXT,
    deadline_at TEXT,
    billing_note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (tenant_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS attempts (
    attempt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL REFERENCES requests(request_id),
    node_id TEXT,
    resource_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    dispatch_epoch INTEGER NOT NULL,
    status TEXT NOT NULL,
    output_eligible INTEGER NOT NULL,
    usage_status TEXT NOT NULL,
    usage_tokens INTEGER,
    settlement_status TEXT NOT NULL,
    execution_state TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_request ON attempts(request_id);
CREATE INDEX IF NOT EXISTS idx_attempts_node ON attempts(node_id);

CREATE TABLE IF NOT EXISTS events (
    request_id TEXT NOT NULL REFERENCES requests(request_id),
    cursor INTEGER NOT NULL,
    attempt_id TEXT NOT NULL,
    attempt_seq INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (request_id, cursor),
    UNIQUE (attempt_id, attempt_seq)
);
CREATE INDEX IF NOT EXISTS idx_events_attempt ON events(attempt_id, attempt_seq);

CREATE TABLE IF NOT EXISTS output_commits (
    request_id TEXT PRIMARY KEY REFERENCES requests(request_id),
    attempt_id TEXT NOT NULL,
    generation_id TEXT NOT NULL,
    committed_at_seq INTEGER NOT NULL,
    committed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settlements (
    service_unit_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    receipt_id TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    log_index INTEGER NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (service_unit_id, revision)
);

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    log_index INTEGER NOT NULL,
    receipt_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log_leaves (
    log_index INTEGER PRIMARY KEY,
    receipt_hash TEXT NOT NULL UNIQUE,
    committed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    node_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    adapter_name TEXT NOT NULL,
    model TEXT NOT NULL,
    share_enabled INTEGER NOT NULL,
    max_concurrency INTEGER NOT NULL,
    max_local_reserved_milli_credits INTEGER NOT NULL,
    policy_version INTEGER NOT NULL,
    connected INTEGER NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
    outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    delivered_at TEXT
);

-- Ordered replay log for the in-memory ledger. The gateway owns what an event
-- means; the store guarantees only that they come back in write order.
CREATE TABLE IF NOT EXISTS ledger_events (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Dispatch inputs: the conversation to execute, the parameters the platform
-- forwards with it, and the signed pre-authorization settlement is measured
-- against. All three must survive a restart, or a request can neither be
-- re-offered nor settled.
CREATE TABLE IF NOT EXISTS request_inputs (
    request_id TEXT PRIMARY KEY,
    messages_json TEXT NOT NULL,
    model TEXT NOT NULL,
    parameters_json TEXT NOT NULL DEFAULT '{}',
    authorization_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Invite records. Only the digest of the invite code is stored; the plaintext
-- code is printed once by `potluck admin invite` and is never written here, so
-- the table (and every backup of it) cannot leak a usable credential.
CREATE TABLE IF NOT EXISTS invites (
    code_digest TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    tenant_scope TEXT NOT NULL,
    expires_at TEXT,
    max_uses INTEGER NOT NULL,
    used_count INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    quota_milli_credits INTEGER NOT NULL DEFAULT 20000
);

-- Dynamic identities minted by an invite. This is the source of truth that a
-- restart replays into the identity registry, so a joined consumer needs no
-- config edit to keep authenticating. `provider_id` is set only for a
-- contribution device, and carries the device->provider binding. `account_id`
-- is the consumer account admission binds a payer to, so a signature can never
-- charge an account the identity does not own. `tenant_scope` records whether
-- the tenant was auto-derived (private) or concrete (shared).
CREATE TABLE IF NOT EXISTS identities (
    key_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    purpose TEXT NOT NULL,
    public_key_b64 TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    role TEXT NOT NULL,
    display_name TEXT,
    provider_id TEXT,
    registered_at TEXT NOT NULL,
    revoked_at TEXT,
    account_id TEXT,
    tenant_scope TEXT NOT NULL DEFAULT 'auto'
);

-- Operator-issued API keys for the OpenAI-compatible endpoint. Only the digest
-- of the key is stored; the plaintext is printed once by
-- `potluck-server admin api-key` and is never written here, so neither this
-- table nor a backup of it holds a usable credential. `used_milli_credits` is
-- written by the same transaction that writes a settlement, so a key's quota
-- counts each request exactly once however often a node replays its report.
CREATE TABLE IF NOT EXISTS api_keys (
    key_id TEXT PRIMARY KEY,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    subject_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    quota_milli_credits INTEGER NOT NULL,
    used_milli_credits INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_api_keys_subject ON api_keys(subject_id);
"""

#: Indexes are created after `_migrate` has added any column an older database
#: is missing, because a partial index that names a new column cannot be built
#: against a table that predates it.

_SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_identities_owner ON identities(owner_id);
-- One identity per (role, owner): two keys may never speak for one identity.
CREATE UNIQUE INDEX IF NOT EXISTS ux_identities_role_owner
    ON identities(role, owner_id);
-- One *auto* identity per (role, tenant): a private tenant is not shared. A
-- concrete scope is shared by design and is therefore excluded, as are device
-- rows, which legitimately share their node's tenant.
CREATE UNIQUE INDEX IF NOT EXISTS ux_identities_auto_tenant
    ON identities(role, tenant_id)
    WHERE tenant_scope = 'auto' AND provider_id IS NULL;
"""

#: Columns added after the first release, each as ``table -> (column, DDL)``.
#: ``_migrate`` adds the ones an existing database is missing, so an upgraded
#: center keeps its identities instead of failing to open.
_ADDED_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    "invites": (
        ("quota_milli_credits", "INTEGER NOT NULL DEFAULT 20000"),
    ),
    "identities": (
        ("account_id", "TEXT"),
        ("tenant_scope", "TEXT NOT NULL DEFAULT 'auto'"),
    ),
    "credentials": (
        ("device_id", "TEXT"),
    ),
    # A request admitted through an API key records which one, so the settlement
    # that bills it can also count it against that key's quota, and so an
    # operator can see what a key paid for. Both stay NULL for a request admitted
    # on a signature, which is every request a center written before this change
    # holds.
    "requests": (
        ("api_key_id", "TEXT"),
        ("api_key_charge_milli_credits", "INTEGER"),
    ),
    # `request_inputs` carried a flattened `prompt` before the request model
    # became a conversation. The column is added rather than renamed: the two
    # hold different shapes, and a row written by an older center is reported as
    # undispatchable rather than silently re-read as a one-message conversation.
    "request_inputs": (
        ("messages_json", "TEXT"),
        ("parameters_json", "TEXT NOT NULL DEFAULT '{}'"),
    ),
}




class _Store:
    """Shared plumbing: per-thread connections, pragmas, transactions, schema."""

    #: Milliseconds a writer waits for the SQLite write lock before giving up.
    #: Five seconds comfortably covers a competing commit that is merely slow,
    #: while still failing loudly rather than hanging forever.
    _BUSY_TIMEOUT_MS = 5000

    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        parent = Path(self._path).parent
        if str(parent) not in ("", "."):
            parent.mkdir(parents=True, exist_ok=True)
        self._tls = threading.local()
        self._registry_lock = threading.Lock()
        # Keyed by owning thread id: sqlite3 refuses to close a connection from a
        # thread other than the one that created it, so the registry identifies
        # which connections `close` may close directly and which it can only drop.
        self._connections: dict[int, sqlite3.Connection] = {}
        self._closed = False
        with self._immediate(self._connection()) as conn:
            conn.executescript(_SCHEMA)
            self._migrate(conn)
            conn.executescript(_SCHEMA_INDEXES)

    @staticmethod
    def _migrate(conn: sqlite3.Connection) -> None:
        """Add columns a database from an earlier release is missing.

        The schema is created with ``IF NOT EXISTS``, so a table that already
        exists is left untouched; without this step an upgraded center would not
        gain ``identities.account_id`` and every join would fail. Each addition
        is guarded by ``PRAGMA table_info`` so it is idempotent, and the added
        columns all carry a default, so existing rows stay valid.
        """
        for table, additions in _ADDED_COLUMNS.items():
            present = {
                str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")
            }
            for column, ddl in additions:
                if column not in present:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")

    @classmethod
    def open(cls, path: str | Path) -> Self:
        """Open (or create) the store at `path` and ensure the schema exists.

        Creating is what the process that *owns* a database needs — a center
        started by ``potluck serve``, a node started by ``potluck share run``.
        A command that only opens somebody else's database calls
        `open_existing` instead, so a path that names nothing reports that fact
        rather than manufacturing an empty database to look at.
        """
        return cls(path)

    @classmethod
    def open_existing(cls, path: str | Path) -> Self:
        """Open the store whose database file already exists at `path`.

        `open` creates the file — and the parent directory — it is pointed at,
        which is fatal for a command that reads one. A lost or mistyped
        ``database_path`` would come back as a freshly created empty database,
        and an empty database reports no differences: ``admin reconcile`` over a
        center whose database is entirely gone would print that both sides agree
        and exit 0, which is the one answer an audit must never give. The same
        applies to a node database rebuilt from nothing, which a later
        ``share run`` would then continue with as if the node had never worked.

        Refusing before any connection is made keeps a missing file missing: no
        file and no directory is created on the way to the error.

        A zero-byte file is refused for the same reason. SQLite reads it as a
        valid empty database, but this store writes its schema as it creates
        one, so an empty file is a creation that never finished rather than a
        database with nothing to report.

        Raises:
            PotluckError: If `path` is not an existing file with content in it.
        """
        candidate = Path(path)
        if not candidate.is_file():
            raise PotluckError(
                f"database {candidate} does not exist: this command opens a "
                "database, it does not create one — start the process that owns "
                "it (`potluck serve` for a center, `potluck share run` for a "
                f"node), or correct the database_path that names {candidate}"
            )
        if candidate.stat().st_size == 0:
            raise PotluckError(
                f"database {candidate} is empty (0 bytes): no schema was ever "
                "written to it, so it holds no records to open — restore it from "
                "a backup, or delete it and let the process that owns it "
                "(`potluck serve` for a center, `potluck share run` for a node) "
                "create a fresh one"
            )
        return cls(path)

    def close(self) -> None:
        """Release this store's connections.

        Idempotent. After this the store must not be used again. Only the
        calling thread's connection can be closed directly, because sqlite3 with
        ``check_same_thread=True`` refuses a cross-thread close; the connections
        belonging to other threads are released by dropping our reference, which
        lets them be finalized as those threads exit. Call it after the worker
        threads that used the store have joined.
        """
        with self._registry_lock:
            if self._closed:
                return
            self._closed = True
            mine = self._connections.pop(threading.get_ident(), None)
            self._connections.clear()
        if mine is not None:
            mine.close()
        self._tls = threading.local()

    def _connection(self) -> sqlite3.Connection:
        """Return this thread's connection, creating it on first use.

        Raises:
            PotluckError: If the store has already been closed.
        """
        if self._closed:
            raise PotluckError("the store is closed")
        conn: sqlite3.Connection | None = getattr(self._tls, "conn", None)
        if conn is not None:
            return conn
        # isolation_level=None disables sqlite3's implicit transaction handling
        # so this module controls every BEGIN/COMMIT explicitly.
        conn = sqlite3.connect(self._path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout={self._BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        self._tls.conn = conn
        with self._registry_lock:
            self._connections[threading.get_ident()] = conn
        return conn

    @contextmanager
    def _immediate(self, conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
        """Run a block inside a ``BEGIN IMMEDIATE`` write transaction.

        The immediate lock is taken before the first statement, so two
        concurrent callers cannot both read the pre-state and then both write:
        the second waits (up to the busy timeout) and then observes the first
        caller's committed result.
        """
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.rollback()
            raise
        conn.commit()

    def _next_cursor(self, conn: sqlite3.Connection, request_id: str) -> int:
        """Return the next per-request event cursor, starting at 1."""
        row = conn.execute(
            "SELECT COALESCE(MAX(cursor), 0) + 1 AS n FROM events WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        return int(row["n"])

    def _append_event_locked(
        self,
        conn: sqlite3.Connection,
        *,
        request_id: str,
        attempt_id: str,
        attempt_seq: int,
        event_type: str,
        payload: dict[str, Any],
        at: dt.datetime,
    ) -> tuple[int, bool]:
        """Insert an event, or return the existing one for an identical replay.

        Must be called inside a write transaction.

        Raises:
            ConflictError: If ``(attempt_id, attempt_seq)`` already holds
                different content.
        """
        digest = _event_digest(event_type, payload)
        existing = conn.execute(
            "SELECT cursor, content_digest FROM events WHERE attempt_id = ? AND attempt_seq = ?",
            (attempt_id, attempt_seq),
        ).fetchone()
        if existing is not None:
            if str(existing["content_digest"]) != digest:
                raise ConflictError(
                    f"attempt {attempt_id} sequence {attempt_seq} already holds different "
                    "content; a sequence number may not be reused with new data"
                )
            return int(existing["cursor"]), False
        cursor = self._next_cursor(conn, request_id)
        conn.execute(
            "INSERT INTO events (request_id, cursor, attempt_id, attempt_seq, event_type,"
            " payload_json, content_digest, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (request_id, cursor, attempt_id, attempt_seq, event_type, _dump_payload(payload),
             digest, _to_text(at)),
        )
        return cursor, True



class CenterStore(_Store):
    """The center's durable store: credentials, requests, attempts, events,
    output commits, settlements, receipts, log leaves, nodes and the outbox.

    All mutating methods are safe to call from multiple threads. Read methods
    return immutable snapshots.
    """

    # -- credentials --------------------------------------------------------

    def add_credential(
        self,
        token: str,
        tenant_id: str,
        subject_id: str,
        role: str,
        created_at: dt.datetime,
        *,
        device_id: str | None = None,
    ) -> None:
        """Register a credential by the digest of its raw token.

        Re-adding a known token is a no-op when the binding is identical and a
        `ConflictError` when it is not, so a token can never silently acquire a
        second identity. The raw token is never stored.

        Args:
            token: The raw credential; only its digest is kept.
            tenant_id: The tenant the credential authenticates into.
            subject_id: The identity the credential speaks for.
            role: ``consumer`` or ``node``.
            created_at: The instant the credential was minted.
            device_id: For a node credential a join minted, the contribution
                device the same join derived. This is what lets a node-scoped
                read be derived from the credential rather than from a tenant
                the operator may have invited other nodes into; ``None`` for a
                consumer credential and for one provisioned from
                ``center.json``, which names no device.

        Raises:
            ConflictError: If the token digest is known with a different binding.
        """
        digest = canonical_digest(token)
        conn = self._connection()
        with self._immediate(conn):
            row = conn.execute(
                "SELECT tenant_id, subject_id, role, device_id FROM credentials"
                " WHERE token_digest = ?",
                (digest,),
            ).fetchone()
            if row is not None:
                if (
                    str(row["tenant_id"]),
                    str(row["subject_id"]),
                    str(row["role"]),
                    _opt_text(row["device_id"]),
                ) != (tenant_id, subject_id, role, device_id):
                    raise ConflictError(
                        f"credential digest already bound to {row['tenant_id']}/"
                        f"{row['subject_id']}/{row['role']}, not "
                        f"{tenant_id}/{subject_id}/{role}"
                    )
                return
            conn.execute(
                "INSERT INTO credentials (token_digest, tenant_id, subject_id, role, created_at,"
                " device_id) VALUES (?, ?, ?, ?, ?, ?)",
                (digest, tenant_id, subject_id, role, _to_text(created_at), device_id),
            )

    def resolve_credential(self, token: str, at: dt.datetime) -> Credential | None:
        """Resolve a raw token to its credential, or `None`.

        `None` covers the cases that must be indistinguishable to a caller
        presenting a bad token: the token is unknown, it was revoked, it is
        being used before it was created, **or an identity it speaks for was
        revoked**. The last one is what makes ``admin revoke-key`` — which
        writes the ``identities`` table, never the ``credentials`` table —
        withdraw a node's link token on every bearer path at once, closing the
        gap where a node whose identity or device key was revoked could still
        authenticate and reconnect with its token. The historical identity rows
        are left in place, so a past signature still verifies against them.
        """
        digest = canonical_digest(token)
        conn = self._connection()
        row = conn.execute(
            "SELECT tenant_id, subject_id, role, created_at, revoked_at, device_id"
            " FROM credentials WHERE token_digest = ?",
            (digest,),
        ).fetchone()
        if row is None:
            return None
        if row["revoked_at"] is not None:
            return None
        if _from_text(str(row["created_at"])) > at:
            return None
        device_id = _opt_text(row["device_id"])
        if self._any_owner_revoked(conn, str(row["subject_id"]), device_id, at):
            return None
        return Credential(
            tenant_id=str(row["tenant_id"]),
            subject_id=str(row["subject_id"]),
            role=cast("_Role", str(row["role"])),
            device_id=device_id,
        )

    def find_credential_by_device(self, device_id: str) -> Credential | None:
        """Return the credential a join bound to `device_id`, or `None`.

        A node join is the only writer of ``credentials.device_id``, so a row
        here is the center's own record that this device and this credential
        belong together. `GatewayService.register_node` reads it to refuse a
        *different* credential — one an operator provisioned by hand, say —
        dialing as a device an invite already bound to somebody else.

        A revoked row is returned as well: which credential a device was minted
        for is a fact that outlives the credential, and a revoked credential
        cannot dial in the first place, so including it blocks nothing that
        `resolve_credential` would have allowed.
        """
        conn = self._connection()
        row = conn.execute(
            "SELECT tenant_id, subject_id, role, device_id FROM credentials"
            " WHERE device_id = ? ORDER BY created_at LIMIT 1",
            (device_id,),
        ).fetchone()
        if row is None:
            return None
        return Credential(
            tenant_id=str(row["tenant_id"]),
            subject_id=str(row["subject_id"]),
            role=cast("_Role", str(row["role"])),
            device_id=_opt_text(row["device_id"]),
        )

    def _any_owner_revoked(
        self,
        conn: sqlite3.Connection,
        owner_a: str,
        owner_b: str | None,
        at: dt.datetime,
    ) -> bool:
        """Return True if an identity owned by either owner was revoked by `at`.

        A node credential speaks for two identity rows — the node's own key
        (``owner_id == subject_id``) and its contribution device key
        (``owner_id == device_id``) — and revoking either withdraws the token.
        A consumer credential names no device, so `owner_b` is `None`, which
        matches no row. Revocation is judged inclusively at `at` (``revoked_at
        <= at``), the same rule `_reject_if_identity_revoked` and the signature
        path apply, so a token stays valid for an `at` before the revocation.
        """
        rows = conn.execute(
            "SELECT revoked_at FROM identities WHERE owner_id IN (?, ?)"
            " AND revoked_at IS NOT NULL",
            (owner_a, owner_b),
        ).fetchall()
        moment = _as_utc(at)
        return any(_from_text(str(row["revoked_at"])) <= moment for row in rows)

    def revoke_credential(self, token: str, at: dt.datetime) -> None:
        """Revoke a credential. The first revocation time is preserved, so a
        repeated revoke does not move the recorded instant. An unknown token is
        ignored."""
        digest = canonical_digest(token)
        conn = self._connection()
        with self._immediate(conn):
            conn.execute(
                "UPDATE credentials SET revoked_at = COALESCE(revoked_at, ?)"
                " WHERE token_digest = ?",
                (_to_text(at), digest),
            )

    # -- invites ------------------------------------------------------------

    def add_invite(
        self,
        code: str,
        role: str,
        tenant_scope: str,
        *,
        max_uses: int,
        created_at: dt.datetime,
        expires_at: dt.datetime | None = None,
        quota_milli_credits: int = 20_000,
    ) -> InviteRecord:
        """Register an invite by the digest of its plaintext code.

        The code is digested here and never stored, so the invite table carries
        no value an operator could replay. Re-adding an identical digest is a
        no-op; a different digest for the same code cannot happen (a digest is a
        function of its input), so there is no conflict case.

        Args:
            code: The single-use (or capped) invite code.
            role: The role the invite admits: ``consumer`` or ``node``.
            tenant_scope: ``"auto"`` for a private, server-derived tenant per
                joiner, or a concrete tenant id to share.
            max_uses: How many times the code may be redeemed. At least 1.
            created_at: When the invite was minted.
            expires_at: Optional expiry; `None` never expires.
            quota_milli_credits: Milli-credits minted into the identity's own
                account exactly once, at its first join.

        Returns:
            The stored invite.

        Raises:
            ValueError: If `max_uses` is not positive.
        """
        if max_uses < 1:
            raise ValueError("max_uses must be >= 1")
        if quota_milli_credits < 0:
            raise ValueError("quota_milli_credits must be >= 0")
        digest = canonical_digest(code)
        conn = self._connection()
        with self._immediate(conn):
            conn.execute(
                "INSERT OR IGNORE INTO invites (code_digest, role, tenant_scope,"
                " expires_at, max_uses, used_count, created_at, revoked_at,"
                " quota_milli_credits)"
                " VALUES (?, ?, ?, ?, ?, 0, ?, NULL, ?)",
                (
                    digest,
                    role,
                    tenant_scope,
                    None if expires_at is None else _to_text(expires_at),
                    max_uses,
                    _to_text(created_at),
                    quota_milli_credits,
                ),
            )
            row = conn.execute(
                "SELECT * FROM invites WHERE code_digest = ?", (digest,)
            ).fetchone()
        return _invite_from_row(row)

    def get_invite(self, code: str) -> InviteRecord | None:
        """Return the invite for `code`, or `None` when the code is unknown."""
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM invites WHERE code_digest = ?", (canonical_digest(code),)
        ).fetchone()
        return None if row is None else _invite_from_row(row)

    def list_invites(self) -> list[InviteRecord]:
        """Return every invite, oldest first.

        The returned records carry only the code *digest*, so an operator view
        built from this can never render a usable code.
        """
        conn = self._connection()
        rows = conn.execute("SELECT * FROM invites ORDER BY created_at").fetchall()
        return [_invite_from_row(row) for row in rows]

    def revoke_invite(self, code: str, at: dt.datetime) -> None:
        """Revoke an invite. The first revocation instant is preserved."""
        conn = self._connection()
        with self._immediate(conn):
            conn.execute(
                "UPDATE invites SET revoked_at = COALESCE(revoked_at, ?)"
                " WHERE code_digest = ?",
                (_to_text(at), canonical_digest(code)),
            )

    def consume_invite(self, code: str, *, at: dt.datetime) -> InviteRecord:
        """Atomically redeem one use of an invite.

        Validation and the increment happen in one ``BEGIN IMMEDIATE``
        transaction, so two concurrent joins cannot both observe the last
        remaining use: the second waits, then sees the incremented count and is
        refused. The caller is expected to have already checked idempotency, so
        a re-join of an existing identity does not reach here.

        Args:
            code: The plaintext invite code.
            at: The instant of the join.

        Returns:
            The invite after the increment.

        Raises:
            ProtocolError: If the code is unknown, revoked, expired, exhausted,
                or `at` is before `created_at`.
        """
        digest = canonical_digest(code)
        conn = self._connection()
        with self._immediate(conn):
            row = conn.execute(
                "SELECT * FROM invites WHERE code_digest = ?", (digest,)
            ).fetchone()
            if row is None:
                raise ProtocolError("the invite code is not valid or is not usable")
            invite = _invite_from_row(row)
            if _as_utc(at) < invite.created_at:
                raise ProtocolError("the invite code is not valid or is not usable")
            if not invite.is_redeemable_at(at):
                raise ProtocolError("the invite code is not valid or is not usable")
            conn.execute(
                "UPDATE invites SET used_count = used_count + 1 WHERE code_digest = ?",
                (digest,),
            )
            return invite

    # -- identities ---------------------------------------------------------

    def add_identity(
        self,
        *,
        key_id: str,
        owner_id: str,
        purpose: str,
        public_key_b64: str,
        tenant_id: str,
        role: str,
        display_name: str | None,
        provider_id: str | None,
        registered_at: dt.datetime,
        account_id: str | None = None,
        tenant_scope: str = "auto",
    ) -> IdentityRecord:
        """Persist a dynamically registered identity.

        Re-adding the identical binding is a no-op that returns the stored row;
        a *different* binding for a known `key_id` is refused, so a key can
        never silently come to speak for a second identity. The two unique
        indexes on the table — one identity per ``(role, owner_id)``, and one
        *auto* identity per ``(role, tenant_id)`` — are enforced here too, so a
        collision surfaces as a `ConflictError` rather than an opaque driver
        error.

        Args:
            key_id: The registry id the row is keyed by.
            owner_id: The identity (consumer or device) the key speaks for.
            purpose: ``consumer`` or ``provider_device``.
            public_key_b64: The identity's Ed25519 public key.
            tenant_id: The tenant the identity belongs to.
            role: ``consumer`` or ``node``.
            display_name: A purely cosmetic label; never authoritative.
            provider_id: The provider a device reports for; `None` otherwise.
            registered_at: When the identity was minted.
            account_id: The consumer account admission binds a payer to.
            tenant_scope: ``"auto"`` or the concrete shared tenant id.

        Returns:
            The stored row.

        Raises:
            ConflictError: If `key_id` is known with different material, or the
                binding would violate the owner or tenant uniqueness invariant.
        """
        conn = self._connection()
        with self._immediate(conn):
            row = conn.execute(
                "SELECT * FROM identities WHERE key_id = ?", (key_id,)
            ).fetchone()
            if row is not None:
                existing = _identity_from_row(row)
                if (
                    existing.owner_id,
                    existing.purpose,
                    existing.public_key_b64,
                    existing.tenant_id,
                    existing.role,
                    existing.account_id,
                    existing.tenant_scope,
                ) != (
                    owner_id,
                    purpose,
                    public_key_b64,
                    tenant_id,
                    role,
                    account_id,
                    tenant_scope,
                ):
                    raise ConflictError(
                        f"identity key {key_id} is already registered as "
                        f"{existing.owner_id}/{existing.purpose}; refusing to "
                        "rebind it"
                    )
                return existing
            try:
                conn.execute(
                    "INSERT INTO identities (key_id, owner_id, purpose, public_key_b64,"
                    " tenant_id, role, display_name, provider_id, registered_at,"
                    " revoked_at, account_id, tenant_scope)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
                    (
                        key_id,
                        owner_id,
                        purpose,
                        public_key_b64,
                        tenant_id,
                        role,
                        display_name,
                        provider_id,
                        _to_text(registered_at),
                        account_id,
                        tenant_scope,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError(
                    f"identity {key_id} violates the identity uniqueness "
                    f"invariant (role={role!r}, owner={owner_id!r}, "
                    f"tenant={tenant_id!r}): {exc}"
                ) from exc
            inserted = conn.execute(
                "SELECT * FROM identities WHERE key_id = ?", (key_id,)
            ).fetchone()
        return _identity_from_row(inserted)

    def get_identity(self, key_id: str) -> IdentityRecord | None:
        """Return the identity registered for `key_id`, or `None`."""
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM identities WHERE key_id = ?", (key_id,)
        ).fetchone()
        return None if row is None else _identity_from_row(row)

    def find_identity_by_public_key(
        self, public_key_b64: str, role: str
    ) -> IdentityRecord | None:
        """Return the live identity a public key already speaks for, if any.

        Join uses this to stay idempotent under server-derived ids: the derived
        key id is random per join, so the only stable handle a returning client
        has is the key it kept from its first join. Looking it up here lets a
        re-join return the existing identity rather than mint a second one, and
        a revoked row is returned as well so the caller can refuse it.
        """
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM identities WHERE public_key_b64 = ? AND role = ?"
            " AND provider_id IS NULL ORDER BY registered_at LIMIT 1",
            (public_key_b64, role),
        ).fetchone()
        return None if row is None else _identity_from_row(row)

    def identities(self) -> list[IdentityRecord]:
        """Return every dynamic identity, ordered by key id.

        `load_center` replays these rows into the registry on startup, so this
        is the one place a rebuild reads dynamic trust from. Revoked rows are
        included so their history is preserved.
        """
        conn = self._connection()
        rows = conn.execute("SELECT * FROM identities ORDER BY key_id").fetchall()
        return [_identity_from_row(row) for row in rows]

    def revoke_identity(self, key_id: str, at: dt.datetime) -> bool:
        """Revoke a dynamic identity. The first revocation instant is preserved.

        The row is never deleted, so the identity's public key stays on file for
        a historical signature to verify against; only ``revoked_at`` is set.

        Returns:
            True when this call recorded the revocation, False when the identity
            was already revoked. A repeated ``admin revoke-key`` is therefore a
            safe no-op the caller can report distinctly, rather than a silent
            re-stamp that moves the recorded instant.

        Raises:
            StateTransitionError: If no such identity exists.
        """
        conn = self._connection()
        with self._immediate(conn):
            row = conn.execute(
                "SELECT revoked_at FROM identities WHERE key_id = ?", (key_id,)
            ).fetchone()
            if row is None:
                raise StateTransitionError(f"unknown identity key {key_id}")
            if row["revoked_at"] is not None:
                return False
            conn.execute(
                "UPDATE identities SET revoked_at = ? WHERE key_id = ?",
                (_to_text(at), key_id),
            )
            return True

    def identity_revoked(self, owner_id: str, at: dt.datetime) -> bool:
        """Return True if the identity owned by `owner_id` was revoked by `at`.

        Dispatch consults this so a node whose device key ``admin revoke-key``
        revoked stops being offered new work on a center that is already
        running: the in-memory registry is only a projection of the store, so
        the row is re-read here, exactly as the authentication paths re-read it.
        An owner with no identity row (an operator-provisioned node that names
        no dynamic identity) is never revoked, so a pre-existing deployment is
        unaffected.
        """
        conn = self._connection()
        return self._any_owner_revoked(conn, owner_id, None, at)

    # -- API keys -----------------------------------------------------------

    def find_consumer_binding(self, subject_id: str) -> ConsumerBinding | None:
        """Return the tenant and account a consumer subject spends through.

        The identity row an invite minted is authoritative, because it is the row
        admission already binds a payer to; a credential an operator provisioned
        in ``center.json`` predates per-identity accounts, so for those the
        subject's own name is the account, exactly as `Credential.account_id`
        being `None` means the same thing on the bearer path.

        Returns `None` when the center holds neither row, which is what stops an
        operator from minting an API key for a subject that does not exist — a
        typo would otherwise produce a key that authenticates and then can never
        settle, and the failure would surface only when somebody tried to use it.
        """
        conn = self._connection()
        row = conn.execute(
            "SELECT tenant_id, account_id FROM identities WHERE owner_id = ?"
            " AND role = 'consumer' ORDER BY registered_at LIMIT 1",
            (subject_id,),
        ).fetchone()
        if row is not None:
            return ConsumerBinding(
                subject_id=subject_id,
                tenant_id=str(row["tenant_id"]),
                account_id=_opt_text(row["account_id"]) or subject_id,
            )
        row = conn.execute(
            "SELECT tenant_id FROM credentials WHERE subject_id = ?"
            " AND role = 'consumer' ORDER BY created_at LIMIT 1",
            (subject_id,),
        ).fetchone()
        if row is None:
            return None
        return ConsumerBinding(
            subject_id=subject_id, tenant_id=str(row["tenant_id"]), account_id=subject_id
        )

    def add_api_key(
        self,
        key: str,
        *,
        key_id: str,
        name: str,
        subject_id: str,
        tenant_id: str,
        quota_milli_credits: int,
        created_at: dt.datetime,
        expires_at: dt.datetime | None = None,
    ) -> ApiKeyRecord:
        """Register an API key by the digest of its plaintext.

        The plaintext is digested here and never stored, so the table carries no
        value a reader could replay. Re-adding an identical digest is a no-op;
        a different key cannot produce the same digest, so there is no conflict
        case to resolve.

        Args:
            key: The plaintext key; only its digest is kept.
            key_id: The operator-facing handle, used to list and revoke.
            name: The operator's own label for the key.
            subject_id: The consumer identity the key speaks for.
            tenant_id: The tenant that identity belongs to.
            quota_milli_credits: What this key may draw from the subject's
                account, in total.
            created_at: When the key was minted.
            expires_at: Optional expiry; `None` never expires.

        Returns:
            The stored key.

        Raises:
            ValueError: If the quota is negative.
        """
        if quota_milli_credits < 0:
            raise ValueError("quota_milli_credits must be >= 0")
        conn = self._connection()
        with self._immediate(conn):
            conn.execute(
                "INSERT OR IGNORE INTO api_keys (key_id, key_hash, name, subject_id,"
                " tenant_id, quota_milli_credits, used_milli_credits, status,"
                " created_at, expires_at, revoked_at, last_used_at)"
                " VALUES (?, ?, ?, ?, ?, ?, 0, 'active', ?, ?, NULL, NULL)",
                (
                    key_id,
                    canonical_digest(key),
                    name,
                    subject_id,
                    tenant_id,
                    quota_milli_credits,
                    _to_text(created_at),
                    None if expires_at is None else _to_text(expires_at),
                ),
            )
            row = conn.execute(
                "SELECT * FROM api_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
        return _api_key_from_row(row)

    def resolve_api_key(self, key: str, at: dt.datetime) -> ApiKeyRecord | None:
        """Resolve a plaintext API key to its record, or `None`.

        `None` covers every case that must be indistinguishable to a caller
        presenting a bad key: the key is unknown, it was revoked, it has expired,
        it is being used before it was minted, **or the identity it speaks for was
        revoked**. The last one is what makes ``admin revoke-key`` withdraw a
        subject's API keys as well as its signing key and link token, so revoking
        an identity really does withdraw the identity.

        An exhausted quota is *not* one of those cases: the record is returned
        with ``remaining_milli_credits`` at zero, and admission reports that as a
        spent quota rather than as an unknown key.
        """
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ?", (canonical_digest(key),)
        ).fetchone()
        if row is None:
            return None
        record = _api_key_from_row(row)
        if not record.is_usable_at(at):
            return None
        if record.created_at > _as_utc(at):
            return None
        if self._any_owner_revoked(conn, record.subject_id, None, at):
            return None
        return record

    def mark_api_key_used(self, key_id: str, at: dt.datetime) -> None:
        """Record that a key admitted a request at `at`.

        The latest instant wins, unlike a revocation: this column answers "when
        did this key last do something", so an operator deciding whether to
        revoke it sees the most recent use rather than the first.
        """
        conn = self._connection()
        with self._immediate(conn):
            conn.execute(
                "UPDATE api_keys SET last_used_at = ? WHERE key_id = ?",
                (_to_text(at), key_id),
            )

    def list_api_keys(self) -> list[ApiKeyRecord]:
        """Return every API key, oldest first.

        The records carry only the key *digest*, so an operator view built from
        this can never render a usable key.
        """
        conn = self._connection()
        rows = conn.execute(
            "SELECT * FROM api_keys ORDER BY created_at, key_id"
        ).fetchall()
        return [_api_key_from_row(row) for row in rows]

    def revoke_api_key(self, key_id: str, at: dt.datetime) -> bool:
        """Revoke an API key. The first revocation instant is preserved.

        The row is never deleted: what a key spent stays on the books, and the
        digest stays on file so a later lookup of the same plaintext resolves to
        a revoked record rather than to nothing at all.

        Returns:
            True when this call recorded the revocation, False when the key was
            already revoked, so driving a recovery checklist twice gives a clear,
            idempotent result.

        Raises:
            StateTransitionError: If no such key exists.
        """
        conn = self._connection()
        with self._immediate(conn):
            row = conn.execute(
                "SELECT revoked_at FROM api_keys WHERE key_id = ?", (key_id,)
            ).fetchone()
            if row is None:
                raise StateTransitionError(f"unknown API key {key_id}")
            if row["revoked_at"] is not None:
                return False
            conn.execute(
                "UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE key_id = ?",
                (_to_text(at), key_id),
            )
            return True

    def count_in_flight_api_key_requests(self, key_id: str) -> int:
        """How many requests this key has admitted that are not terminal yet.

        Counted from the durable request rows rather than from process state, so
        a per-key concurrency ceiling means the same thing after a restart as it
        did before one, and a request left running by an interrupted center still
        occupies its slot until the center's own recovery ends it.
        """
        conn = self._connection()
        placeholders = ", ".join("?" for _ in TERMINAL_REQUEST_STATES)
        row = conn.execute(
            f"SELECT COUNT(*) AS n FROM requests WHERE api_key_id = ?"
            f" AND status NOT IN ({placeholders})",
            (key_id, *sorted(TERMINAL_REQUEST_STATES)),
        ).fetchone()
        return int(row["n"])

    def bind_request_api_key(self, request_id: str, key_id: str) -> None:
        """Record that one request was admitted through one API key.

        The first binding wins, so a replayed admission cannot move a request
        onto another key's quota.
        """
        conn = self._connection()
        with self._immediate(conn):
            conn.execute(
                "UPDATE requests SET api_key_id = COALESCE(api_key_id, ?)"
                " WHERE request_id = ?",
                (key_id, request_id),
            )

    # -- requests -----------------------------------------------------------

    def create_request(
        self,
        *,
        request_id: str,
        tenant_id: str,
        subject_id: str,
        idempotency_key: str,
        payload_digest: str,
        delivery_mode: str,
        max_attempts: int,
        service_unit_id: str,
        deadline_at: dt.datetime | None = None,
        created_at: dt.datetime,
    ) -> tuple[RequestRecord, bool]:
        """Register a request, deduplicating on ``(tenant_id, idempotency_key)``.

        Returns ``(record, True)`` when a new row was inserted and
        ``(existing_record, False)`` when the key was already used with the same
        payload digest — a retry therefore creates nothing. A reused key with a
        different payload digest is refused.

        The dedup is enforced by a ``UNIQUE(tenant_id, idempotency_key)``
        constraint and the resulting integrity error, not by a read-then-write
        check, so concurrent callers cannot both insert.

        Raises:
            ConflictError: If the key is reused with a different payload digest.
        """
        conn = self._connection()
        with self._immediate(conn):
            try:
                conn.execute(
                    "INSERT INTO requests (request_id, tenant_id, subject_id,"
                    " idempotency_key, payload_digest, delivery_mode, max_attempts,"
                    " service_unit_id, status, selected_attempt_id, deadline_at,"
                    " billing_note, created_at, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'CREATED', NULL, ?, NULL, ?, ?)",
                    (
                        request_id,
                        tenant_id,
                        subject_id,
                        idempotency_key,
                        payload_digest,
                        delivery_mode,
                        max_attempts,
                        service_unit_id,
                        None if deadline_at is None else _to_text(deadline_at),
                        _to_text(created_at),
                        _to_text(created_at),
                    ),
                )
            except sqlite3.IntegrityError:
                existing = conn.execute(
                    "SELECT * FROM requests WHERE tenant_id = ? AND idempotency_key = ?",
                    (tenant_id, idempotency_key),
                ).fetchone()
                if existing is None:
                    # Not the idempotency constraint: the request_id primary key was
                    # reused. There is no "existing row for this key" to hand back.
                    raise ConflictError(
                        f"request {request_id} already exists; a request ID may not be reused"
                    ) from None
                if str(existing["payload_digest"]) != payload_digest:
                    raise ConflictError(
                        f"idempotency key {idempotency_key} was used for a different payload "
                        f"({existing['payload_digest']} vs {payload_digest})"
                    ) from None
                return _request_from_row(existing), False
            row = conn.execute(
                "SELECT * FROM requests WHERE request_id = ?", (request_id,)
            ).fetchone()
            return _request_from_row(row), True

    def get_request(self, request_id: str) -> RequestRecord | None:
        """Return the stored request, or `None`."""
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM requests WHERE request_id = ?", (request_id,)
        ).fetchone()
        return None if row is None else _request_from_row(row)

    def requests(self) -> list[RequestRecord]:
        """Return every request, ordered by request ID.

        Read-only whole-table view for the operator's reconciliation pass, which
        cross-checks requests against attempts and receipts and therefore cannot
        work from one status at a time.
        """
        conn = self._connection()
        rows = conn.execute("SELECT * FROM requests ORDER BY request_id").fetchall()
        return [_request_from_row(row) for row in rows]

    def requests_by_status(self, status: str, *, limit: int = 64) -> list[RequestRecord]:
        """Return requests in `status`, oldest first, bounded by `limit`."""
        conn = self._connection()
        rows = conn.execute(
            "SELECT * FROM requests WHERE status = ? ORDER BY created_at LIMIT ?",
            (status, max(0, limit)),
        ).fetchall()
        return [_request_from_row(row) for row in rows]

    def set_request_status(
        self,
        request_id: str,
        status: str,
        *,
        selected_attempt_id: str | None = None,
        billing_note: str | None = None,
        at: dt.datetime,
    ) -> None:
        """Update a request's status.

        `selected_attempt_id` and `billing_note` are left unchanged when not
        supplied.

        Raises:
            StateTransitionError: If no such request exists.
        """
        conn = self._connection()
        with self._immediate(conn):
            cur = conn.execute(
                "UPDATE requests SET status = ?, updated_at = ?,"
                " selected_attempt_id = COALESCE(?, selected_attempt_id),"
                " billing_note = COALESCE(?, billing_note)"
                " WHERE request_id = ?",
                (
                    status,
                    _to_text(at),
                    selected_attempt_id,
                    billing_note,
                    request_id,
                ),
            )
            if cur.rowcount == 0:
                raise StateTransitionError(f"unknown request {request_id}")

    # -- attempts -----------------------------------------------------------

    def upsert_attempt(
        self,
        *,
        attempt_id: str,
        request_id: str,
        node_id: str | None,
        resource_id: str,
        provider_id: str,
        dispatch_epoch: int,
        at: dt.datetime,
        output_eligible: bool = True,
    ) -> AttemptRecord:
        """Insert a new attempt or refresh the dispatch fields of a known one.

        An existing attempt keeps its status, usage and settlement state; only
        the dispatch fields, `output_eligible` and `updated_at` are rewritten.

        Raises:
            StateTransitionError: If `request_id` names no stored request.
        """
        conn = self._connection()
        with self._immediate(conn):
            try:
                conn.execute(
                    "INSERT INTO attempts (attempt_id, request_id, node_id, resource_id,"
                    " provider_id, dispatch_epoch, status, output_eligible, usage_status,"
                    " usage_tokens, settlement_status, execution_state, updated_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, 'PREPARED', ?, 'EMPTY', NULL, 'HELD', NULL, ?)"
                    " ON CONFLICT(attempt_id) DO UPDATE SET"
                    " node_id = excluded.node_id,"
                    " resource_id = excluded.resource_id,"
                    " provider_id = excluded.provider_id,"
                    " dispatch_epoch = excluded.dispatch_epoch,"
                    " output_eligible = excluded.output_eligible,"
                    " updated_at = excluded.updated_at",
                    (attempt_id, request_id, node_id, resource_id, provider_id, dispatch_epoch,
                     1 if output_eligible else 0, _to_text(at)),
                )
            except sqlite3.IntegrityError as exc:
                raise StateTransitionError(
                    f"attempt {attempt_id} references unknown request {request_id}"
                ) from exc
            row = conn.execute(
                "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
            ).fetchone()
            return _attempt_from_row(row)

    def get_attempt(self, attempt_id: str) -> AttemptRecord | None:
        """Return the stored attempt, or `None`."""
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM attempts WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        return None if row is None else _attempt_from_row(row)

    def attempts_for_request(self, request_id: str) -> list[AttemptRecord]:
        """Return every attempt of a request, ordered by attempt ID."""
        conn = self._connection()
        rows = conn.execute(
            "SELECT * FROM attempts WHERE request_id = ? ORDER BY attempt_id", (request_id,)
        ).fetchall()
        return [_attempt_from_row(row) for row in rows]

    def attempts(self) -> list[AttemptRecord]:
        """Return every attempt, ordered by attempt ID.

        Read-only whole-table view for reconciliation, which must see terminal
        attempts too: a settled attempt with no receipt is exactly the kind of
        difference `attempts_for_node`'s unfinished-only filter would hide.
        """
        conn = self._connection()
        rows = conn.execute("SELECT * FROM attempts ORDER BY attempt_id").fetchall()
        return [_attempt_from_row(row) for row in rows]

    def attempts_for_node(
        self, node_id: str, *, unfinished_only: bool = True
    ) -> list[AttemptRecord]:
        """Return attempts assigned to a node.

        With `unfinished_only` (the default) terminal attempts are excluded, so
        the caller sees only work that may still need reconciliation.
        """
        conn = self._connection()
        rows = conn.execute(
            "SELECT * FROM attempts WHERE node_id = ? ORDER BY attempt_id", (node_id,)
        ).fetchall()
        attempts = [_attempt_from_row(row) for row in rows]
        if unfinished_only:
            attempts = [a for a in attempts if a.status not in TERMINAL_ATTEMPT_STATUSES]
        return attempts

    def set_attempt_status(
        self,
        attempt_id: str,
        status: str,
        *,
        at: dt.datetime,
        execution_state: str | None = None,
        output_eligible: bool | None = None,
        settlement_status: str | None = None,
    ) -> None:
        """Update an attempt's status.

        `execution_state`, `output_eligible` and `settlement_status` are left
        unchanged when `None`, which is why the update is expressed with
        `COALESCE`.

        Raises:
            StateTransitionError: If no such attempt exists.
        """
        conn = self._connection()
        with self._immediate(conn):
            cur = conn.execute(
                "UPDATE attempts SET status = ?, updated_at = ?,"
                " execution_state = COALESCE(?, execution_state),"
                " output_eligible = COALESCE(?, output_eligible),"
                " settlement_status = COALESCE(?, settlement_status)"
                " WHERE attempt_id = ?",
                (
                    status,
                    _to_text(at),
                    execution_state,
                    None if output_eligible is None else (1 if output_eligible else 0),
                    settlement_status,
                    attempt_id,
                ),
            )
            if cur.rowcount == 0:
                raise StateTransitionError(f"unknown attempt {attempt_id}")

    def record_usage(self, attempt_id: str, tokens: int, *, at: dt.datetime) -> None:
        """Record a known token total for an attempt.

        A recorded value of ``0`` is a real zero and is stored as such, distinct
        from the `None` that `mark_usage_unknown` writes.

        Raises:
            StateTransitionError: If no such attempt exists.
        """
        conn = self._connection()
        with self._immediate(conn):
            cur = conn.execute(
                "UPDATE attempts SET usage_status = 'COMPLETE', usage_tokens = ?, updated_at = ?"
                " WHERE attempt_id = ?",
                (tokens, _to_text(at), attempt_id),
            )
            if cur.rowcount == 0:
                raise StateTransitionError(f"unknown attempt {attempt_id}")

    def mark_usage_unknown(self, attempt_id: str, *, at: dt.datetime) -> None:
        """Record that an attempt's final usage cannot be determined.

        The token total is set to `NULL`, never to 0, so a later grouping cannot
        mistake an unknown consumption for a free one.

        Raises:
            StateTransitionError: If no such attempt exists.
        """
        conn = self._connection()
        with self._immediate(conn):
            cur = conn.execute(
                "UPDATE attempts SET usage_status = 'UNKNOWN', usage_tokens = NULL,"
                " updated_at = ? WHERE attempt_id = ?",
                (_to_text(at), attempt_id),
            )
            if cur.rowcount == 0:
                raise StateTransitionError(f"unknown attempt {attempt_id}")

    # -- events -------------------------------------------------------------

    def append_event(
        self,
        *,
        request_id: str,
        attempt_id: str,
        attempt_seq: int,
        event_type: str,
        payload: dict[str, Any],
        at: dt.datetime,
    ) -> tuple[int, bool]:
        """Append an event and return ``(cursor, is_new)``.

        The cursor is per request, monotonic, and starts at 1; it is assigned in
        the same transaction as the insert. Replaying ``(attempt_id,
        attempt_seq)`` with identical content returns the existing cursor and
        inserts nothing.

        Raises:
            ConflictError: If the same sequence already holds different content.
        """
        conn = self._connection()
        with self._immediate(conn):
            return self._append_event_locked(
                conn,
                request_id=request_id,
                attempt_id=attempt_id,
                attempt_seq=attempt_seq,
                event_type=event_type,
                payload=payload,
                at=at,
            )

    def events_after(
        self, request_id: str, cursor: int, *, limit: int = 256
    ) -> list[StoredEvent]:
        """Return up to `limit` events of a request whose cursor exceeds `cursor`."""
        conn = self._connection()
        rows = conn.execute(
            "SELECT * FROM events WHERE request_id = ? AND cursor > ? ORDER BY cursor LIMIT ?",
            (request_id, cursor, max(0, limit)),
        ).fetchall()
        return [_event_from_row(row) for row in rows]

    def max_cursor(self, request_id: str) -> int:
        """Return the highest cursor stored for a request, or 0."""
        conn = self._connection()
        row = conn.execute(
            "SELECT COALESCE(MAX(cursor), 0) AS n FROM events WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        return int(row["n"])

    def last_attempt_seq(self, attempt_id: str) -> int:
        """Return the highest N such that every sequence 1..N exists.

        This is the contiguous prefix, not ``MAX(seq)``: if sequence 3 arrives
        before 2, the answer is 1, which is exactly the signal that the stream is
        incomplete and must not be presented as a finished answer.
        """
        conn = self._connection()
        rows = conn.execute(
            "SELECT attempt_seq FROM events WHERE attempt_id = ? ORDER BY attempt_seq",
            (attempt_id,),
        ).fetchall()
        prefix = 0
        for row in rows:
            seq = int(row["attempt_seq"])
            if seq == prefix + 1:
                prefix = seq
            elif seq > prefix + 1:
                break
        return prefix

    def has_event_gap(self, attempt_id: str) -> bool:
        """Report whether an attempt's stored sequences have a gap."""
        conn = self._connection()
        row = conn.execute(
            "SELECT COUNT(*) AS n, COALESCE(MAX(attempt_seq), 0) AS m FROM events"
            " WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        count = int(row["n"])
        return count > 0 and int(row["m"]) != count

    # -- output commit ------------------------------------------------------

    def commit_output(
        self,
        *,
        request_id: str,
        attempt_id: str,
        expected_epoch: int,
        generation_id: str,
        at: dt.datetime,
        event_seq: int,
        event_payload: dict[str, Any],
    ) -> tuple[bool, int | None]:
        """Publish the first output segment for a request, atomically.

        Succeeds only when, in one ``BEGIN IMMEDIATE`` transaction: the request
        has no output commit yet; the named attempt exists, belongs to that
        request and is `output_eligible`; and its `dispatch_epoch` equals
        `expected_epoch`. On success the commit row, the first-segment event and
        the request's `selected_attempt_id` are all written together.

        On any failed condition the result is ``(False, None)`` and the database
        is left completely unchanged — no commit row, no event, no selection.

        Returns:
            ``(committed, cursor)`` where `cursor` is the first segment's event
            cursor on success and `None` otherwise.
        """
        conn = self._connection()
        with self._immediate(conn):
            return self._first_segment_locked(
                conn,
                request_id=request_id,
                attempt_id=attempt_id,
                expected_epoch=expected_epoch,
                generation_id=generation_id,
                at=at,
                event_seq=event_seq,
                event_payload=event_payload,
            )

    def _first_segment_locked(
        self,
        conn: sqlite3.Connection,
        *,
        request_id: str,
        attempt_id: str,
        expected_epoch: int,
        generation_id: str,
        at: dt.datetime,
        event_seq: int,
        event_payload: dict[str, Any],
    ) -> tuple[bool, int | None]:
        """Run the first-segment winner CAS. Must be inside a write transaction."""
        committed = conn.execute(
            "SELECT 1 FROM output_commits WHERE request_id = ?", (request_id,)
        ).fetchone()
        if committed is not None:
            return False, None
        row = conn.execute(
            "SELECT request_id, output_eligible, dispatch_epoch FROM attempts"
            " WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        if row is None:
            return False, None
        if str(row["request_id"]) != request_id:
            return False, None
        if not int(row["output_eligible"]):
            return False, None
        if int(row["dispatch_epoch"]) != expected_epoch:
            return False, None
        conn.execute(
            "INSERT INTO output_commits (request_id, attempt_id, generation_id,"
            " committed_at_seq, committed_at) VALUES (?, ?, ?, ?, ?)",
            (request_id, attempt_id, generation_id, event_seq, _to_text(at)),
        )
        cursor, _ = self._append_event_locked(
            conn,
            request_id=request_id,
            attempt_id=attempt_id,
            attempt_seq=event_seq,
            event_type=OUTPUT_EVENT_TYPE,
            payload=event_payload,
            at=at,
        )
        conn.execute(
            "UPDATE requests SET selected_attempt_id = ?, updated_at = ?"
            " WHERE request_id = ?",
            (attempt_id, _to_text(at), request_id),
        )
        return True, cursor

    def commit_output_segment(
        self,
        *,
        request_id: str,
        attempt_id: str,
        expected_epoch: int,
        event_seq: int,
        payload: dict[str, Any],
        at: dt.datetime,
    ) -> tuple[bool, int | None]:
        """Publish one output chunk for a request, atomically.

        The chunk-level half of the stream_strict contract: every `output.delta`
        is written inside the same transaction that decides whether its attempt
        still owns the request's output stream. The first chunk runs the full
        first-segment winner CAS of `commit_output`; every later chunk is
        accepted only while the stored commit names the sending attempt, that
        attempt still belongs to the request at the expected epoch, and it is
        still output-eligible.

        On any refused condition the result is ``(False, None)`` and the
        database is completely unchanged — a losing branch's chunk never enters
        the consumer's event stream, and there is no crash window between
        "store the chunk" and "decide who won" in which a consumer could see
        text the center does not know it published.

        Returns:
            ``(accepted, cursor)`` where `cursor` is the chunk's event cursor on
            success and `None` otherwise.
        """
        conn = self._connection()
        with self._immediate(conn):
            row = conn.execute(
                "SELECT attempt_id FROM output_commits WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                return self._first_segment_locked(
                    conn,
                    request_id=request_id,
                    attempt_id=attempt_id,
                    expected_epoch=expected_epoch,
                    generation_id=f"gen-{attempt_id}",
                    at=at,
                    event_seq=event_seq,
                    event_payload=payload,
                )
            if str(row["attempt_id"]) != attempt_id:
                return False, None
            attempt = conn.execute(
                "SELECT request_id, output_eligible, dispatch_epoch FROM attempts"
                " WHERE attempt_id = ?",
                (attempt_id,),
            ).fetchone()
            if (
                attempt is None
                or str(attempt["request_id"]) != request_id
                or not int(attempt["output_eligible"])
                or int(attempt["dispatch_epoch"]) != expected_epoch
            ):
                return False, None
            cursor, _ = self._append_event_locked(
                conn,
                request_id=request_id,
                attempt_id=attempt_id,
                attempt_seq=event_seq,
                event_type=OUTPUT_EVENT_TYPE,
                payload=payload,
                at=at,
            )
            return True, cursor

    def output_commit(self, request_id: str) -> OutputCommitRecord | None:
        """Return the request's winning output commit, or `None`."""
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM output_commits WHERE request_id = ?", (request_id,)
        ).fetchone()
        return None if row is None else _commit_from_row(row)

    # -- settlement ---------------------------------------------------------

    def get_settlement(self, service_unit_id: str, revision: int) -> SettlementRecord | None:
        """Return a stored settlement revision, or `None`."""
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM settlements WHERE service_unit_id = ? AND revision = ?",
            (service_unit_id, revision),
        ).fetchone()
        return None if row is None else _settlement_from_row(row)

    def settlements(self) -> list[SettlementRecord]:
        """Return every settlement revision, ordered by service unit then revision."""
        conn = self._connection()
        rows = conn.execute(
            "SELECT * FROM settlements ORDER BY service_unit_id, revision"
        ).fetchall()
        return [_settlement_from_row(row) for row in rows]

    def latest_settlement(self, service_unit_id: str) -> SettlementRecord | None:
        """Return the highest stored revision for one service unit, or `None`.

        A revision is immutable once written, so the highest one is the current
        settlement and any below it are the ones it corrected. A caller that
        names the receipt a request settled into reads this rather than revision
        1: naming a superseded revision points at a receipt nothing else treats
        as current, and two readers of one database would then disagree about
        which receipt a request has.
        """
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM settlements WHERE service_unit_id = ?"
            " ORDER BY revision DESC LIMIT 1",
            (service_unit_id,),
        ).fetchone()
        return None if row is None else _settlement_from_row(row)

    def record_settlement(self, record: SettlementRecord) -> SettlementRecord:
        """Record a settlement revision, idempotent on ``(id, revision)``.

        A repeat with the same fingerprint returns the stored record untouched.
        A different fingerprint for an existing revision is refused: a settlement
        revision is immutable once written.

        Raises:
            ConflictError: If the revision exists with a different fingerprint.
        """
        conn = self._connection()
        with self._immediate(conn):
            row = conn.execute(
                "SELECT * FROM settlements WHERE service_unit_id = ? AND revision = ?",
                (record.service_unit_id, record.revision),
            ).fetchone()
            if row is not None:
                stored = _settlement_from_row(row)
                if stored.fingerprint != record.fingerprint:
                    raise ConflictError(
                        f"settlement {record.service_unit_id} revision {record.revision} already "
                        f"recorded with fingerprint {stored.fingerprint}, cannot overwrite with "
                        f"{record.fingerprint}"
                    )
                return stored
            try:
                conn.execute(
                    "INSERT INTO settlements (service_unit_id, revision, fingerprint, receipt_id,"
                    " receipt_hash, log_index, receipt_json, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (record.service_unit_id, record.revision, record.fingerprint,
                     record.receipt_id, record.receipt_hash, record.log_index,
                     record.receipt_json, _to_text(record.created_at)),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError(
                    f"settlement {record.service_unit_id} revision {record.revision} was "
                    "recorded concurrently"
                ) from exc
            return record

    def put_receipt(self, receipt: ReceiptRecord) -> None:
        """Store a receipt.

        Re-storing an identical receipt is a no-op; the same `receipt_id` with
        different content is refused.

        Raises:
            ConflictError: If `receipt_id` exists with different content.
        """
        conn = self._connection()
        with self._immediate(conn):
            row = conn.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?", (receipt.receipt_id,)
            ).fetchone()
            if row is not None:
                stored = _receipt_from_row(row)
                if (
                    stored.request_id != receipt.request_id
                    or stored.receipt_hash != receipt.receipt_hash
                    or stored.log_index != receipt.log_index
                    or stored.receipt_json != receipt.receipt_json
                ):
                    raise ConflictError(
                        f"receipt {receipt.receipt_id} already exists with different content"
                    )
                return
            conn.execute(
                "INSERT INTO receipts (receipt_id, request_id, receipt_hash, log_index,"
                " receipt_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (receipt.receipt_id, receipt.request_id, receipt.receipt_hash, receipt.log_index,
                 receipt.receipt_json, _to_text(receipt.created_at)),
            )

    def get_receipt(self, receipt_id: str) -> ReceiptRecord | None:
        """Return a stored receipt, or `None`."""
        conn = self._connection()
        row = conn.execute(
            "SELECT * FROM receipts WHERE receipt_id = ?", (receipt_id,)
        ).fetchone()
        return None if row is None else _receipt_from_row(row)

    def receipts(self) -> list[ReceiptRecord]:
        """Return every issued receipt, ordered by log index then receipt ID."""
        conn = self._connection()
        rows = conn.execute(
            "SELECT * FROM receipts ORDER BY log_index, receipt_id"
        ).fetchall()
        return [_receipt_from_row(row) for row in rows]

    def append_log_leaf(self, receipt_hash: str, committed_at: dt.datetime) -> int:
        """Append a receipt hash to the transparency log and return its index.

        Idempotent on `receipt_hash`: re-appending a hash that is already a leaf
        returns that leaf's index instead of creating a duplicate position, so a
        retried append cannot fork the log.
        """
        conn = self._connection()
        with self._immediate(conn):
            row = conn.execute(
                "SELECT log_index FROM log_leaves WHERE receipt_hash = ?", (receipt_hash,)
            ).fetchone()
            if row is not None:
                return int(row["log_index"])
            row = conn.execute(
                "SELECT COALESCE(MAX(log_index), -1) + 1 AS n FROM log_leaves"
            ).fetchone()
            index = int(row["n"])
            conn.execute(
                "INSERT INTO log_leaves (log_index, receipt_hash, committed_at) VALUES (?, ?, ?)",
                (index, receipt_hash, _to_text(committed_at)),
            )
            return index

    def log_leaves(self) -> list[LogLeafRecord]:
        """Return every leaf of the transparency log, ordered by index."""
        conn = self._connection()
        rows = conn.execute("SELECT * FROM log_leaves ORDER BY log_index").fetchall()
        return [_leaf_from_row(row) for row in rows]

    def log_size(self) -> int:
        """Return the number of leaves in the transparency log."""
        conn = self._connection()
        row = conn.execute("SELECT COUNT(*) AS n FROM log_leaves").fetchone()
        return int(row["n"])

    # -- settlement bundle --------------------------------------------------

    def record_settlement_bundle(
        self,
        *,
        settlement: SettlementRecord,
        receipt: ReceiptRecord,
        journal_kind: str,
        journal_payload: dict[str, Any],
        attempt_id: str,
        usage_tokens: int,
        at: dt.datetime,
    ) -> int:
        """Record a settled service unit and every fact that backs it, atomically.

        The transparency-log leaf, the receipt, the settlement revision, the
        ledger-replay journal, the attempt's final usage and settlement status,
        and the request's success all commit inside one ``BEGIN IMMEDIATE``
        transaction. Writing them as separate transactions left crash windows in
        which a durable receipt existed with no journal to back the money
        movement, or a log leaf existed with no settlement — an unrecoverable
        inconsistency, because a rebuild reads exactly those tables back as
        authority. One transaction makes the durable outcome all-or-nothing, so
        an interruption leaves either a complete settlement or an untouched
        request.

        Idempotent: re-running with the same content — the replay a node sends
        after a lost acknowledgement — returns the existing leaf index and
        writes nothing new. A different settlement for the same
        ``(service_unit_id, revision)``, or a leaf index that disagrees with the
        stored log, is refused.

        A request admitted through an API key also has its charge counted
        against that key's quota here, in the same transaction and once per
        request; see `_bundle_charge_api_key`.

        Args:
            settlement: The settlement revision. Its ``service_unit_id`` and
                ``log_index`` must agree with `receipt`.
            receipt: The signed receipt to store and to anchor in the log.
            journal_kind: The ledger-replay event kind (``"journal"``).
            journal_payload: The ledger-replay journal for the money movement.
            attempt_id: The winning attempt whose usage is finalized.
            usage_tokens: Milli-credits to record as the attempt's total usage.
            at: The instant every written row records.

        Returns:
            The transparency-log index the receipt occupies.

        Raises:
            ConflictError: If the settlement revision, the receipt, or the leaf
                already exists with different content.
            PotluckError: If `receipt.log_index` does not name the next position
                in the stored log, which would leave a gap this module's rebuild
                refuses to serve proofs over.
            StateTransitionError: If `attempt_id` names no stored attempt.
        """
        if settlement.service_unit_id != receipt.request_id:
            raise ConflictError(
                f"settlement {settlement.service_unit_id} does not name receipt "
                f"{receipt.receipt_id}'s request {receipt.request_id}"
            )
        if settlement.log_index != receipt.log_index:
            raise ConflictError(
                f"settlement {settlement.service_unit_id} revision {settlement.revision} "
                f"names log index {settlement.log_index} while its receipt names "
                f"{receipt.log_index}"
            )
        conn = self._connection()
        with self._immediate(conn):
            index = self._bundle_write_leaf(conn, receipt.receipt_hash, receipt.log_index, at)
            self._bundle_write_receipt(conn, receipt)
            self._bundle_write_settlement(conn, settlement)
            self._bundle_write_journal(conn, journal_kind, journal_payload, at)
            cur = conn.execute(
                "UPDATE attempts SET usage_status = 'COMPLETE', usage_tokens = ?, updated_at = ?"
                " WHERE attempt_id = ?",
                (usage_tokens, _to_text(at), attempt_id),
            )
            if cur.rowcount == 0:
                raise StateTransitionError(f"unknown attempt {attempt_id}")
            conn.execute(
                "UPDATE attempts SET status = 'COMPLETED', settlement_status = 'SETTLED',"
                " updated_at = ? WHERE attempt_id = ?",
                (_to_text(at), attempt_id),
            )
            conn.execute(
                "UPDATE requests SET status = 'SUCCEEDED', updated_at = ? WHERE request_id = ?",
                (_to_text(at), receipt.request_id),
            )
            self._bundle_charge_api_key(conn, receipt.request_id, usage_tokens)
            return index

    @staticmethod
    def _bundle_charge_api_key(
        conn: sqlite3.Connection, request_id: str, milli_credits: int
    ) -> None:
        """Count a settled charge against the API key that admitted it, once.

        Must be called inside the settlement transaction: a key's quota and the
        credit it just spent are one fact, and committing them apart would leave
        a window where a crash had moved the money but not the quota.

        Idempotent by construction. The guarded update is the marker — a request
        whose charge is already recorded writes nothing — so the replay a node
        sends after a lost acknowledgement, which re-runs this bundle with the
        same content, cannot spend the same tokens against the quota twice. A
        request admitted on a signature carries no key and is skipped.
        """
        charged = conn.execute(
            "UPDATE requests SET api_key_charge_milli_credits = ?"
            " WHERE request_id = ? AND api_key_id IS NOT NULL"
            " AND api_key_charge_milli_credits IS NULL",
            (milli_credits, request_id),
        )
        if charged.rowcount == 0:
            return
        conn.execute(
            "UPDATE api_keys SET used_milli_credits = used_milli_credits + ?"
            " WHERE key_id = (SELECT api_key_id FROM requests WHERE request_id = ?)",
            (milli_credits, request_id),
        )

    def _bundle_write_leaf(
        self,
        conn: sqlite3.Connection,
        receipt_hash: str,
        log_index: int,
        at: dt.datetime,
    ) -> int:
        """Write one transparency-log leaf at exactly `log_index`.

        Must be called inside a write transaction. Split out from the bundle so
        each durable fact it writes is a small, individually named step; the
        transaction around them is what makes the outcome atomic, not the steps
        themselves.

        Raises:
            ConflictError: If that position or that hash is already taken by
                different content.
            PotluckError: If `log_index` is not the next free position, which
                would leave a gap in the log.
        """
        row = conn.execute(
            "SELECT receipt_hash FROM log_leaves WHERE log_index = ?", (log_index,)
        ).fetchone()
        if row is not None:
            if str(row["receipt_hash"]) != receipt_hash:
                raise ConflictError(
                    f"log position {log_index} already holds a different receipt hash"
                )
            return log_index
        row = conn.execute(
            "SELECT log_index FROM log_leaves WHERE receipt_hash = ?", (receipt_hash,)
        ).fetchone()
        if row is not None:
            raise ConflictError(
                f"receipt hash {receipt_hash} is already logged at index {row['log_index']}, "
                f"not {log_index}"
            )
        expected = int(
            conn.execute(
                "SELECT COALESCE(MAX(log_index), -1) + 1 AS n FROM log_leaves"
            ).fetchone()["n"]
        )
        if expected != log_index:
            raise PotluckError(
                f"transparency log is missing positions before {log_index} "
                f"(next free is {expected}); refusing to leave a gap"
            )
        conn.execute(
            "INSERT INTO log_leaves (log_index, receipt_hash, committed_at) VALUES (?, ?, ?)",
            (log_index, receipt_hash, _to_text(at)),
        )
        return log_index

    @staticmethod
    def _bundle_write_receipt(conn: sqlite3.Connection, receipt: ReceiptRecord) -> None:
        """Store one receipt, idempotent on identical content.

        Must be called inside a write transaction.

        Raises:
            ConflictError: If the receipt id exists with different content.
        """
        row = conn.execute(
            "SELECT * FROM receipts WHERE receipt_id = ?", (receipt.receipt_id,)
        ).fetchone()
        if row is not None:
            stored = _receipt_from_row(row)
            if (
                stored.request_id != receipt.request_id
                or stored.receipt_hash != receipt.receipt_hash
                or stored.log_index != receipt.log_index
                or stored.receipt_json != receipt.receipt_json
            ):
                raise ConflictError(
                    f"receipt {receipt.receipt_id} already exists with different content"
                )
            return
        conn.execute(
            "INSERT INTO receipts (receipt_id, request_id, receipt_hash, log_index,"
            " receipt_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (receipt.receipt_id, receipt.request_id, receipt.receipt_hash, receipt.log_index,
             receipt.receipt_json, _to_text(receipt.created_at)),
        )

    @staticmethod
    def _bundle_write_settlement(
        conn: sqlite3.Connection, record: SettlementRecord
    ) -> None:
        """Store one settlement revision, refusing to overwrite a different one.

        Must be called inside a write transaction.

        Raises:
            ConflictError: If the revision exists with a different fingerprint.
        """
        row = conn.execute(
            "SELECT * FROM settlements WHERE service_unit_id = ? AND revision = ?",
            (record.service_unit_id, record.revision),
        ).fetchone()
        if row is not None:
            stored = _settlement_from_row(row)
            if stored.fingerprint != record.fingerprint:
                raise ConflictError(
                    f"settlement {record.service_unit_id} revision {record.revision} already "
                    f"recorded with fingerprint {stored.fingerprint}, cannot overwrite with "
                    f"{record.fingerprint}"
                )
            return
        conn.execute(
            "INSERT INTO settlements (service_unit_id, revision, fingerprint, receipt_id,"
            " receipt_hash, log_index, receipt_json, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.service_unit_id,
                record.revision,
                record.fingerprint,
                record.receipt_id,
                record.receipt_hash,
                record.log_index,
                record.receipt_json,
                _to_text(record.created_at),
            ),
        )

    @staticmethod
    def _bundle_write_journal(
        conn: sqlite3.Connection,
        kind: str,
        payload: dict[str, Any],
        at: dt.datetime,
    ) -> None:
        """Append one ledger-replay journal, idempotent on identical content.

        Must be called inside a write transaction. The journal repays the money
        movement the receipt promises; writing it in the same transaction is
        what stops a durable receipt from existing with no journal behind it.
        Deduplicating on the canonical payload keeps a replay from appending the
        same journal twice, which a rebuild would otherwise replay twice (it is
        harmless there, but the log should stay minimal).
        """
        text = _dump_payload(payload)
        row = conn.execute(
            "SELECT 1 FROM ledger_events WHERE kind = ? AND payload_json = ?",
            (kind, text),
        ).fetchone()
        if row is not None:
            return
        conn.execute(
            "INSERT INTO ledger_events (kind, payload_json, created_at) VALUES (?, ?, ?)",
            (kind, text, _to_text(at)),
        )

    # -- nodes --------------------------------------------------------------

    def upsert_node(self, record: NodeRecord) -> None:
        """Insert or fully replace a node's advertised state."""
        conn = self._connection()
        with self._immediate(conn):
            conn.execute(
                "INSERT INTO nodes (node_id, device_id, provider_id, adapter_name, model,"
                " share_enabled, max_concurrency, max_local_reserved_milli_credits,"
                " policy_version, connected, last_seen_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(node_id) DO UPDATE SET"
                " device_id = excluded.device_id,"
                " provider_id = excluded.provider_id,"
                " adapter_name = excluded.adapter_name,"
                " model = excluded.model,"
                " share_enabled = excluded.share_enabled,"
                " max_concurrency = excluded.max_concurrency,"
                " max_local_reserved_milli_credits = excluded.max_local_reserved_milli_credits,"
                " policy_version = excluded.policy_version,"
                " connected = excluded.connected,"
                " last_seen_at = excluded.last_seen_at",
                (record.node_id, record.device_id, record.provider_id, record.adapter_name,
                 record.model, 1 if record.share_enabled else 0, record.max_concurrency,
                 record.max_local_reserved_milli_credits, record.policy_version,
                 1 if record.connected else 0, _to_text(record.last_seen_at)),
            )

    def get_node(self, node_id: str) -> NodeRecord | None:
        """Return a stored node, or `None`."""
        conn = self._connection()
        row = conn.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
        return None if row is None else _node_from_row(row)

    def set_node_connected(self, node_id: str, connected: bool, *, at: dt.datetime) -> None:
        """Set a node's connection flag and last-seen instant.

        Raises:
            StateTransitionError: If no such node exists.
        """
        conn = self._connection()
        with self._immediate(conn):
            cur = conn.execute(
                "UPDATE nodes SET connected = ?, last_seen_at = ? WHERE node_id = ?",
                (1 if connected else 0, _to_text(at), node_id),
            )
            if cur.rowcount == 0:
                raise StateTransitionError(f"unknown node {node_id}")

    def connected_nodes(self, *, model: str | None = None) -> list[NodeRecord]:
        """Return connected nodes, optionally restricted to one model."""
        conn = self._connection()
        if model is None:
            rows = conn.execute(
                "SELECT * FROM nodes WHERE connected = 1 ORDER BY node_id"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM nodes WHERE connected = 1 AND model = ? ORDER BY node_id", (model,)
            ).fetchall()
        return [_node_from_row(row) for row in rows]

    # -- outbox -------------------------------------------------------------

    def enqueue_outbox(self, kind: str, payload: dict[str, Any], *, at: dt.datetime) -> int:
        """Queue an outbound message and return its outbox ID."""
        conn = self._connection()
        with self._immediate(conn):
            cur = conn.execute(
                "INSERT INTO outbox (kind, payload_json, created_at) VALUES (?, ?, ?)",
                (kind, _dump_payload(payload), _to_text(at)),
            )
            outbox_id = cur.lastrowid
            if outbox_id is None:
                raise PotluckError("sqlite did not assign an outbox ID")
            return int(outbox_id)

    def append_ledger_event(self, kind: str, payload: dict[str, Any], *, at: dt.datetime) -> int:
        """Append one ordered ledger-replay event and return its sequence.

        The gateway owns what these events mean; this store only guarantees that
        they come back in the order they were written, which is the only property
        a ledger replay can depend on.
        """
        conn = self._connection()
        with self._immediate(conn):
            cur = conn.execute(
                "INSERT INTO ledger_events (kind, payload_json, created_at) VALUES (?, ?, ?)",
                (kind, _dump_payload(payload), _to_text(at)),
            )
            seq = cur.lastrowid
            if seq is None:
                raise PotluckError("sqlite did not assign a ledger event sequence")
            return int(seq)

    def ledger_events(self) -> list[tuple[int, str, dict[str, Any]]]:
        """Return every ledger-replay event in write order."""
        conn = self._connection()
        rows = conn.execute(
            "SELECT seq, kind, payload_json FROM ledger_events ORDER BY seq"
        ).fetchall()
        return [
            (int(row["seq"]), str(row["kind"]), _load_payload(str(row["payload_json"])))
            for row in rows
        ]

    def set_request_input(
        self,
        request_id: str,
        *,
        messages: list[dict[str, Any]],
        model: str,
        parameters: dict[str, Any],
        authorization: dict[str, Any],
        at: dt.datetime,
    ) -> None:
        """Persist a request's dispatch inputs: conversation, model, parameters,
        and authorization.

        Written once. A second write is refused rather than overwritten, because
        the authorization is what settlement is measured against and silently
        replacing it would let a later caller move the goal posts.

        Args:
            request_id: The request these inputs belong to.
            messages: The conversation to execute, in order, as the payload dicts
                `wire.ChatMessage.to_payload` produces.
            model: The model requested.
            parameters: The forwarded parameters, in the canonical-safe encoding
                `wire.encode_chat_parameters` produces.
            authorization: The signed pre-authorization, serialized.
            at: The instant the row records.

        Raises:
            ConflictError: If inputs are already stored for the request.
        """
        conn = self._connection()
        with self._immediate(conn):
            try:
                conn.execute(
                    "INSERT INTO request_inputs (request_id, messages_json, model,"
                    " parameters_json, authorization_json, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        request_id,
                        _dump_payload({"messages": list(messages)}),
                        model,
                        _dump_payload(dict(parameters)),
                        _dump_payload(authorization),
                        _to_text(at),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError(
                    f"request {request_id} already has stored dispatch inputs"
                ) from exc

    def get_request_input(self, request_id: str) -> dict[str, Any] | None:
        """Return a request's stored dispatch inputs, or `None`.

        Returns:
            A dict with ``messages``, ``model``, ``parameters`` and
            ``authorization`` keys.

        Raises:
            PotluckError: If the row was written by a center that stored a
                flattened ``prompt`` instead of a conversation. Such a request
                can neither be re-offered nor settled — its authorization's
                request digest no longer has an input to be re-derived from — so
                it is reported rather than quietly re-read as a one-message
                conversation nobody signed for.
        """
        conn = self._connection()
        row = conn.execute(
            "SELECT messages_json, model, parameters_json, authorization_json"
            " FROM request_inputs WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if row is None:
            return None
        if row["messages_json"] is None:
            raise PotluckError(
                f"request {request_id} stores its dispatch input as a flattened "
                "prompt from an earlier center version, which this build cannot "
                "offer or settle; resubmit the request"
            )
        stored = _load_payload(str(row["messages_json"]))
        messages = stored.get("messages")
        if not isinstance(messages, list) or not messages:
            raise PotluckError(
                f"request {request_id} stores no conversation to dispatch"
            )
        return {
            "messages": cast("list[dict[str, Any]]", messages),
            "model": str(row["model"]),
            "parameters": _load_payload(str(row["parameters_json"])),
            "authorization": _load_payload(str(row["authorization_json"])),
        }

    def pending_outbox(self, *, limit: int = 64) -> list[OutboxRecord]:
        """Return undelivered outbox rows in enqueue order."""
        conn = self._connection()
        rows = conn.execute(
            "SELECT * FROM outbox WHERE delivered_at IS NULL ORDER BY outbox_id LIMIT ?",
            (max(0, limit),),
        ).fetchall()
        return [_outbox_from_row(row) for row in rows]

    def mark_outbox_delivered(self, outbox_id: int, at: dt.datetime) -> None:
        """Mark an outbox row delivered.

        The first delivery instant is preserved, so a repeated mark does not move
        the recorded instant. An unknown ID is ignored.
        """
        conn = self._connection()
        with self._immediate(conn):
            conn.execute(
                "UPDATE outbox SET delivered_at = COALESCE(delivered_at, ?) WHERE outbox_id = ?",
                (_to_text(at), outbox_id),
            )



# --------------------------------------------------------------------------
# Row -> record builders. `sqlite3.Row` values are `Any`; every field is
# coerced to its declared type here so the rest of the module is typed.
# --------------------------------------------------------------------------


def _request_from_row(row: Any) -> RequestRecord:
    return RequestRecord(
        request_id=str(row["request_id"]),
        tenant_id=str(row["tenant_id"]),
        subject_id=str(row["subject_id"]),
        idempotency_key=str(row["idempotency_key"]),
        payload_digest=str(row["payload_digest"]),
        delivery_mode=str(row["delivery_mode"]),
        max_attempts=int(row["max_attempts"]),
        service_unit_id=str(row["service_unit_id"]),
        status=str(row["status"]),
        selected_attempt_id=_opt_text(row["selected_attempt_id"]),
        deadline_at=_opt_instant(row["deadline_at"]),
        billing_note=_opt_text(row["billing_note"]),
        created_at=_from_text(str(row["created_at"])),
        updated_at=_from_text(str(row["updated_at"])),
        api_key_id=_opt_text(row["api_key_id"]),
    )


def _attempt_from_row(row: Any) -> AttemptRecord:
    return AttemptRecord(
        attempt_id=str(row["attempt_id"]),
        request_id=str(row["request_id"]),
        node_id=_opt_text(row["node_id"]),
        resource_id=str(row["resource_id"]),
        provider_id=str(row["provider_id"]),
        dispatch_epoch=int(row["dispatch_epoch"]),
        status=str(row["status"]),
        output_eligible=bool(int(row["output_eligible"])),
        usage_status=str(row["usage_status"]),
        usage_tokens=_opt_int(row["usage_tokens"]),
        settlement_status=str(row["settlement_status"]),
        execution_state=_opt_text(row["execution_state"]),
        updated_at=_from_text(str(row["updated_at"])),
    )


def _commit_from_row(row: Any) -> OutputCommitRecord:
    return OutputCommitRecord(
        request_id=str(row["request_id"]),
        attempt_id=str(row["attempt_id"]),
        generation_id=str(row["generation_id"]),
        committed_at_seq=int(row["committed_at_seq"]),
        committed_at=_from_text(str(row["committed_at"])),
    )


def _event_from_row(row: Any) -> StoredEvent:
    return StoredEvent(
        cursor=int(row["cursor"]),
        request_id=str(row["request_id"]),
        attempt_id=str(row["attempt_id"]),
        attempt_seq=int(row["attempt_seq"]),
        event_type=str(row["event_type"]),
        payload=_load_payload(str(row["payload_json"])),
        created_at=_from_text(str(row["created_at"])),
    )


def _settlement_from_row(row: Any) -> SettlementRecord:
    return SettlementRecord(
        service_unit_id=str(row["service_unit_id"]),
        revision=int(row["revision"]),
        fingerprint=str(row["fingerprint"]),
        receipt_id=str(row["receipt_id"]),
        receipt_hash=str(row["receipt_hash"]),
        log_index=int(row["log_index"]),
        receipt_json=str(row["receipt_json"]),
        created_at=_from_text(str(row["created_at"])),
    )


def _receipt_from_row(row: Any) -> ReceiptRecord:
    return ReceiptRecord(
        receipt_id=str(row["receipt_id"]),
        request_id=str(row["request_id"]),
        receipt_hash=str(row["receipt_hash"]),
        log_index=int(row["log_index"]),
        receipt_json=str(row["receipt_json"]),
        created_at=_from_text(str(row["created_at"])),
    )


def _leaf_from_row(row: Any) -> LogLeafRecord:
    return LogLeafRecord(
        log_index=int(row["log_index"]),
        receipt_hash=str(row["receipt_hash"]),
        committed_at=_from_text(str(row["committed_at"])),
    )


def _invite_from_row(row: Any) -> InviteRecord:
    return InviteRecord(
        code_digest=str(row["code_digest"]),
        role=cast("_Role", str(row["role"])),
        tenant_scope=str(row["tenant_scope"]),
        expires_at=_opt_instant(row["expires_at"]),
        max_uses=int(row["max_uses"]),
        used_count=int(row["used_count"]),
        created_at=_from_text(str(row["created_at"])),
        revoked_at=_opt_instant(row["revoked_at"]),
        quota_milli_credits=int(row["quota_milli_credits"]),
    )


def _identity_from_row(row: Any) -> IdentityRecord:
    return IdentityRecord(
        key_id=str(row["key_id"]),
        owner_id=str(row["owner_id"]),
        purpose=cast("Literal['consumer', 'provider_device']", str(row["purpose"])),
        public_key_b64=str(row["public_key_b64"]),
        tenant_id=str(row["tenant_id"]),
        role=cast("_Role", str(row["role"])),
        display_name=_opt_text(row["display_name"]),
        provider_id=_opt_text(row["provider_id"]),
        registered_at=_from_text(str(row["registered_at"])),
        revoked_at=_opt_instant(row["revoked_at"]),
        account_id=_opt_text(row["account_id"]),
        tenant_scope=str(row["tenant_scope"]),
    )


def _api_key_from_row(row: Any) -> ApiKeyRecord:
    return ApiKeyRecord(
        key_id=str(row["key_id"]),
        key_hash=str(row["key_hash"]),
        name=str(row["name"]),
        subject_id=str(row["subject_id"]),
        tenant_id=str(row["tenant_id"]),
        quota_milli_credits=int(row["quota_milli_credits"]),
        used_milli_credits=int(row["used_milli_credits"]),
        status=cast("Literal['active', 'revoked']", str(row["status"])),
        created_at=_from_text(str(row["created_at"])),
        expires_at=_opt_instant(row["expires_at"]),
        revoked_at=_opt_instant(row["revoked_at"]),
        last_used_at=_opt_instant(row["last_used_at"]),
    )


def _node_from_row(row: Any) -> NodeRecord:
    return NodeRecord(
        node_id=str(row["node_id"]),
        device_id=str(row["device_id"]),
        provider_id=str(row["provider_id"]),
        adapter_name=str(row["adapter_name"]),
        model=str(row["model"]),
        share_enabled=bool(int(row["share_enabled"])),
        max_concurrency=int(row["max_concurrency"]),
        max_local_reserved_milli_credits=int(row["max_local_reserved_milli_credits"]),
        policy_version=int(row["policy_version"]),
        connected=bool(int(row["connected"])),
        last_seen_at=_from_text(str(row["last_seen_at"])),
    )


def _outbox_from_row(row: Any) -> OutboxRecord:
    delivered = row["delivered_at"]
    return OutboxRecord(
        outbox_id=int(row["outbox_id"]),
        kind=str(row["kind"]),
        payload=_load_payload(str(row["payload_json"])),
        created_at=_from_text(str(row["created_at"])),
        delivered_at=None if delivered is None else _from_text(str(delivered)),
    )


