"""Command-line entry point for the center operator: ``potluck-server``.

The commands that open a center's own store or run a center. The consumer and
contributor commands (``join``, ``ask``, ``share`` and the rest) live in the
``ai-potluck`` package's ``potluck`` command; this CLI imports the shared
presentation and signal helpers from there rather than growing second copies.

* ``serve`` runs a center from ``center.json`` until SIGINT/SIGTERM. The
  startup lines name the bind URL, the node URL, and every provisioned
  provider. They carry no secret: the config's tokens are held by the store as
  digests, and the settlement private key never leaves the process.
* ``admin invite`` mints a single-use-or-capped invite code, printing the
  plaintext once; ``admin invite-list`` and ``admin revoke-key`` are the
  operator views, and neither ever renders a code or a private key.
* ``admin api-key`` mints a revocable, quota-bearing API key for the
  OpenAI-compatible endpoint and prints the plaintext once; ``admin
  api-key-list`` shows every key with what it has spent, and ``admin
  api-key-revoke`` withdraws one.
* ``admin session-list`` and ``admin session-show`` read the aggregate the center
  keeps per agent session — turns, tokens, milli-credits, the node that last
  served it — and ``session-show`` lists the receipts behind those totals so a
  summary can be checked against the records that back it.
* ``admin reconcile`` cross-checks the center's own tables — attempts,
  settlements, receipts, transparency-log leaves and the ledger replay log —
  in both directions, and names every record an invariant fails on.
* ``verify receipt`` runs :mod:`aipotluck.verify`'s five-dimension offline
  verification over one receipt against the center's own store, which also
  holds the signed usage report, so every dimension is assessable.
* ``version`` prints the package and protocol versions.

Every error path prints an actionable message on stderr and returns a non-zero
exit status. The console script's generated wrapper calls ``sys.exit(main())``,
so the integer returned here becomes the process exit code. No command prints
a token, an invite code, an API key, or a private key more than once, and the
listing commands print none at all.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.metadata
import logging
import secrets
import sys
import threading
from collections.abc import Callable, Sequence
from pathlib import Path

from aipotluck import canonical
from aipotluck.canonical import canonicalize
from aipotluck.cli import (
    PROTOCOL_VERSION,
    install_stop_handlers,
    print_differences,
    print_verification,
    read_text_file,
)
from aipotluck.errors import PotluckError
from aipotluck.reconcile import ReceiptVerification
from aipotluck.wire import SESSION_HEADER

from .deploy import CenterInspection, load_center, load_center_for_inspection
from .gateway_service import API_KEY_BYTES, API_KEY_PREFIX, MAX_DEADLINE_MS
from .persistence import CenterStore
from .reconcile import reconcile_center, verify_receipt_at_center

PROG = "potluck-server"

#: The installed distribution ``_package_version`` reads. Not ``PROG``: the
#: command name and the package name differ.
DIST_NAME = "ai-potluck-server"

#: The protocol version to report when the installed distribution metadata is
#: unavailable (for example when running from a source tree without an install).
_FALLBACK_VERSION = "0.0.0"


def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with the operator subcommands.

    Returns:
        The fully configured parser. Each subparser records its handler via
        ``set_defaults`` so dispatch needs no separate table.
    """
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Operator tooling for an AI potluck center: run the gateway, mint "
            "and revoke invites, reconcile the center's own tables, and verify "
            "a receipt against the center's books."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser(
        "verify",
        help="Verify one receipt against the center's books.",
        description=(
            "The operator view of the five-dimension receipt verification. "
            "`verify receipt` opens the center's own database read-only, where "
            "every dimension is assessable because the operator holds the "
            "signed usage report too. The consumer view that reads over HTTP "
            "under a joined identity is `potluck verify receipt --config-dir`."
        ),
    )
    verify_sub = verify.add_subparsers(dest="verify_command", required=True)

    verify_receipt = verify_sub.add_parser(
        "receipt",
        help="Run the five-dimension offline verification over one receipt.",
        description=(
            "Recompute one receipt against the records that back it and report "
            "five dimensions separately: signature_valid, metering_provenance, "
            "allocation_valid, ledger_included and account_history_complete. "
            "They fail independently, and a single green light would otherwise "
            "read as proof the upstream really consumed the tokens.\n\n"
            "The center's own database is opened read-only and every dimension "
            "is assessable, because the operator holds the signed usage report "
            "too. Nothing is written and nothing is frozen. Exit 0 when no "
            "dimension reported a contradiction, 1 when one did; `unknown` is "
            "not a contradiction."
        ),
    )
    _add_config_argument(verify_receipt)
    verify_receipt.add_argument(
        "--receipt-id",
        required=True,
        dest="receipt_id",
        metavar="ID",
        help="The receipt to verify, e.g. R-1 as printed by `potluck ask`.",
    )
    verify_receipt.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print the report as one canonical JSON document.",
    )
    verify_receipt.set_defaults(handler=_cmd_verify_receipt)

    serve = subparsers.add_parser(
        "serve",
        help="Run a center gateway from its center.json until SIGINT/SIGTERM.",
        description=(
            "Load, provision and start a center from its JSON configuration, "
            "print the bind URL and the node URL, and serve until interrupted."
        ),
    )
    serve.add_argument(
        "--config",
        required=True,
        type=Path,
        metavar="PATH",
        help="center.json produced for this deployment.",
    )
    serve.set_defaults(handler=_cmd_serve)


    admin = subparsers.add_parser(
        "admin",
        help="Operator actions on a center's store (invites, keys, revocation).",
        description=(
            "Offline operator actions that open the center's store directly. "
            "None of them prints a secret twice: `invite` and `api-key` each "
            "print a fresh plaintext exactly once, and the listing and "
            "revocation views are redacted."
        ),
    )
    admin_sub = admin.add_subparsers(dest="admin_command", required=True)

    invite = admin_sub.add_parser(
        "invite",
        help="Mint an invite code and print it once.",
        description=(
            "Generate a high-entropy invite code, store only its digest, and "
            "print the plaintext code to stdout exactly once."
        ),
    )
    _add_config_argument(invite)
    invite.add_argument(
        "--role",
        choices=["consumer", "node"],
        default="consumer",
        help="The role the invite admits (default consumer).",
    )
    invite.add_argument(
        "--tenant",
        default="auto",
        help=(
            "Tenant scope: 'auto' gives each joiner a private, server-derived "
            "tenant; any other value shares that tenant id (default auto)."
        ),
    )
    invite.add_argument(
        "--quota",
        type=int,
        default=20_000,
        metavar="MILLI_CREDITS",
        help=(
            "Milli-credits minted into each joiner's own account at first join "
            "(default 20000). The account is funded once, so a re-join adds nothing."
        ),
    )
    invite.add_argument(
        "--expires-in",
        default="7d",
        dest="expires_in",
        metavar="DURATION",
        help="Lifetime such as 30m, 12h or 7d (default 7d).",
    )
    invite.add_argument(
        "--max-uses",
        type=int,
        default=1,
        dest="max_uses",
        help="How many joins the code permits (default 1).",
    )
    invite.set_defaults(handler=_cmd_admin_invite)

    invite_list = admin_sub.add_parser(
        "invite-list",
        help="List invites, redacted.",
        description="List every invite with its digest prefix, never the code.",
    )
    _add_config_argument(invite_list)
    invite_list.set_defaults(handler=_cmd_admin_invite_list)

    revoke = admin_sub.add_parser(
        "revoke-key",
        help="Revoke a dynamically joined identity's key.",
        description="Revoke an identity key so it no longer authenticates.",
    )
    _add_config_argument(revoke)
    revoke.add_argument("--key-id", required=True, dest="key_id")
    revoke.set_defaults(handler=_cmd_admin_revoke_key)

    api_key = admin_sub.add_parser(
        "api-key",
        help="Mint an API key for the OpenAI-compatible endpoint, printed once.",
        description=(
            "Generate a high-entropy API key for one existing consumer subject, "
            "store only its digest, and print the plaintext to stdout exactly "
            "once. The key authenticates POST /openai/v1/chat/completions and "
            "GET /openai/v1/models; it spends the subject's own account, up to "
            "the quota named here, and can be revoked without touching the "
            "identity or any other key."
        ),
    )
    _add_config_argument(api_key)
    api_key.add_argument(
        "--subject",
        required=True,
        dest="subject_id",
        metavar="SUBJECT_ID",
        help=(
            "The consumer this key speaks for: an identity an invite minted, or "
            "a consumer credential provisioned in center.json. Its account is "
            "what the key spends."
        ),
    )
    api_key.add_argument(
        "--quota",
        required=True,
        type=int,
        metavar="MILLI_CREDITS",
        help=(
            "Total milli-credits this key may spend. A key that has spent it "
            "answers 429 insufficient_quota until it is replaced."
        ),
    )
    api_key.add_argument(
        "--name",
        default="",
        help="A label for the key, so a listing says which tool holds it.",
    )
    api_key.add_argument(
        "--expires-in",
        default=None,
        dest="expires_in",
        metavar="DURATION",
        help=(
            "Lifetime such as 30m, 12h or 90d. Omit for a key that does not "
            "expire, which stays revocable either way."
        ),
    )
    api_key.add_argument(
        "--deadline-ms",
        default=None,
        type=int,
        dest="deadline_ms",
        metavar="MILLISECONDS",
        help=(
            "Wall-clock budget every request on this key is given, in "
            "milliseconds. Omit for the endpoint's own default. Set it longer "
            "for a key an agent loop holds: a long turn needs a long window, and "
            "a request that outlives its budget ends EXPIRED whether or not an "
            "answer was on its way."
        ),
    )
    api_key.set_defaults(handler=_cmd_admin_api_key)

    api_key_list = admin_sub.add_parser(
        "api-key-list",
        help="List API keys with what each has spent, redacted.",
        description=(
            "List every API key by its id, subject, quota, spend and status. "
            "The plaintext is never printed: only its digest was stored, so no "
            "command can read one back."
        ),
    )
    _add_config_argument(api_key_list)
    api_key_list.set_defaults(handler=_cmd_admin_api_key_list)

    api_key_revoke = admin_sub.add_parser(
        "api-key-revoke",
        help="Revoke an API key.",
        description=(
            "Revoke an API key so it authenticates nothing, immediately and "
            "without a restart: every request on the OpenAI-compatible surface "
            "re-reads the key's row. What the key already spent stays on the "
            "books, and the subject's own identity and signing key are "
            "untouched — revoke those with `admin revoke-key`."
        ),
    )
    _add_config_argument(api_key_revoke)
    api_key_revoke.add_argument(
        "--key-id",
        required=True,
        dest="key_id",
        metavar="KEY_ID",
        help="The key to revoke, as `admin api-key-list` names it.",
    )
    api_key_revoke.set_defaults(handler=_cmd_admin_api_key_revoke)

    session_list = admin_sub.add_parser(
        "session-list",
        help="List agent sessions with what each has cost.",
        description=(
            "List every agent session the center has aggregated, most recently "
            "active first: the subject it belongs to, how many requests it made, "
            "the tokens and milli-credits its settled turns added up to, the node "
            "that served its last one, and when it was last seen. The totals count "
            "settled turns only, so they agree with the books rather than with what "
            "was asked for. A request that named no session appears nowhere here."
        ),
    )
    _add_config_argument(session_list)
    session_list.add_argument(
        "--subject",
        default=None,
        dest="subject_id",
        metavar="SUBJECT_ID",
        help="Only this consumer's sessions, instead of every session in the center.",
    )
    session_list.set_defaults(handler=_cmd_admin_session_list)

    session_show = admin_sub.add_parser(
        "session-show",
        help="Show one agent session, with the receipts behind its totals.",
        description=(
            "Show one agent session's aggregate and list every receipt its "
            "requests produced. The receipts are the point: the totals a listing "
            "prints are the aggregate's, and each receipt named here is a durable "
            "record an operator can verify on its own with "
            "`potluck-server verify receipt --receipt-id`.\n\n"
            "A session identifier is chosen by the caller, so two subjects may both "
            "have named one 'default'. This command reports every aggregate the "
            "identifier matches, each under its own subject, rather than picking "
            "one; pass --subject to narrow it."
        ),
    )
    _add_config_argument(session_show)
    session_show.add_argument(
        "--session",
        required=True,
        dest="session_id",
        metavar="SESSION_ID",
        help="The session to show, as `admin session-list` or a client names it.",
    )
    session_show.add_argument(
        "--subject",
        default=None,
        dest="subject_id",
        metavar="SUBJECT_ID",
        help="Only this consumer's aggregate for the session.",
    )
    session_show.set_defaults(handler=_cmd_admin_session_show)

    admin_reconcile = admin_sub.add_parser(
        "reconcile",
        help="Cross-check the center's own tables and list every difference.",
        description=(
            "Open the center's database read-only and check every invariant that "
            "ties attempts, settlements, receipts, transparency-log leaves and "
            "the ledger replay log together, in both directions: a settled "
            "attempt with no settlement row, a settlement whose receipt is gone, "
            "a receipt with no log leaf, a log leaf with no receipt, a gap or a "
            "duplicate in the log, a receipt whose stored body no longer hashes "
            "to its own hash, and a billable total that disagrees with the "
            "attempt's recorded usage or with the journal that posted it.\n\n"
            "Every difference names the record it is about. Nothing is written, "
            "nothing is frozen and no dispute is opened: this command makes a "
            "disagreement visible and a person decides what it means. Exit 0 "
            "when the books agree, 1 when any difference stands."
        ),
    )
    _add_config_argument(admin_reconcile)
    admin_reconcile.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print the differences as one canonical JSON document.",
    )
    admin_reconcile.set_defaults(handler=_cmd_admin_reconcile)

    version = subparsers.add_parser(
        "version",
        help="Print the package and protocol versions.",
        description="Print `potluck-server <version> (protocol <schema version>)`.",
    )
    version.set_defaults(handler=_cmd_version)

    return parser


def _add_config_argument(parser: argparse.ArgumentParser) -> None:
    """Add the shared ``--config`` argument an admin action needs."""
    parser.add_argument(
        "--config",
        required=True,
        type=Path,
        metavar="PATH",
        help="center.json whose database_path names the store to open.",
    )



def _configure_gateway_logging() -> None:
    """Send the gateway's per-request log lines to stderr.

    `serve` is a long-running process whose only other output is its startup
    lines, and the structured line the gateway emits per OpenAI-compatible
    request is operator-facing evidence: which key admitted which model, how many
    tokens it settled, how long it took, and how it ended. Python's own default
    handler prints warnings and above, so without this the lines would be
    written and dropped.

    The gateway's HTTP access log stays silenced: a request line carries no
    credential, but the headers do, and the structured line names a key by its id
    and never by its value.
    """
    logger = logging.getLogger("aipotluck_server")
    if logger.handlers:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def _cmd_serve(args: argparse.Namespace) -> int:
    """Run the ``serve`` subcommand: a center until SIGINT/SIGTERM.

    The startup lines name the bind URL, the node URL, and every provisioned
    provider. They carry no secret: the config's tokens are held by the store
    as digests, and the settlement private key never leaves the process.
    """
    config: Path = args.config
    _configure_gateway_logging()
    deployment = load_center(config, start=True)
    server = deployment.server
    print(
        f"{PROG}: center {deployment.config.platform_id} serving {server.url} "
        f"(node link {server.node_url})"
    )
    for provider_id in deployment.provider_ids:
        print(f"{PROG}: provider {provider_id} provisioned (demo float funded)")
    stop = threading.Event()
    install_stop_handlers(stop)
    try:
        stop.wait()
    finally:
        server.stop()
        deployment.store.close()
    return 0



# --------------------------------------------------------------------------
# version
# --------------------------------------------------------------------------


def _package_version() -> str:
    """Return the installed distribution version, or the fallback constant.

    ``importlib.metadata`` reads the version from the installed
    ``ai-potluck-server`` distribution's metadata, which is the version in
    ``pyproject.toml`` at build time. Running uninstalled from a source tree
    has no metadata, so the fallback keeps ``version`` working rather than
    raising.
    """
    try:
        return importlib.metadata.version(DIST_NAME)
    except importlib.metadata.PackageNotFoundError:
        return _FALLBACK_VERSION


def _cmd_version(args: argparse.Namespace) -> int:
    """Run the ``version`` subcommand."""
    del args
    print(f"{PROG} {_package_version()} (protocol {PROTOCOL_VERSION})")
    return 0


# --------------------------------------------------------------------------
# admin: invites and key revocation
# --------------------------------------------------------------------------


def _load_center_store(config: Path) -> CenterStore:
    """Open the store named by a ``center.json``'s ``database_path``.

    The store must already exist. Every ``admin`` command acts on the database
    of a center an operator deployed, and only ``potluck-server serve`` creates one: a
    ``database_path`` that points at nothing — a moved database, a typo, the
    wrong machine — has to be reported, not turned into an empty database that
    ``admin reconcile`` would then find nothing wrong with.

    Raises:
        PotluckError: If the file cannot be read, is not strict JSON, is not an
            object, names no ``database_path``, or names a database that is not
            there.
    """
    raw = read_text_file(config, what="center configuration")
    document = canonical.loads_strict(raw)
    if not isinstance(document, dict):
        raise PotluckError(f"center configuration {config} must be a JSON object")
    database_path = document.get("database_path")
    if not isinstance(database_path, str) or not database_path:
        raise PotluckError(f"center configuration {config} names no database_path")
    return CenterStore.open_existing(database_path)


def _parse_duration(text: str) -> dt.timedelta:
    """Parse a duration such as ``30s``, ``15m``, ``12h`` or ``7d``.

    Raises:
        PotluckError: If the text has no unit, a non-integer amount, an unknown
            unit, or a non-positive amount.
    """
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if len(text) < 2 or text[-1] not in units or not text[:-1].isdigit():
        raise PotluckError(f"a duration must look like 30m, 12h or 7d, not {text!r}")
    seconds = int(text[:-1]) * units[text[-1]]
    if seconds <= 0:
        raise PotluckError("a duration must be positive")
    return dt.timedelta(seconds=seconds)


def _cmd_admin_invite(args: argparse.Namespace) -> int:
    """Run ``admin invite``: mint a code, print it once, store only its digest."""
    if args.max_uses < 1:
        raise PotluckError("--max-uses must be >= 1")
    if args.quota < 0:
        raise PotluckError("--quota must be >= 0")
    now = dt.datetime.now(dt.UTC)
    expires_at = now + _parse_duration(args.expires_in)
    code = secrets.token_urlsafe(24)
    store = _load_center_store(args.config)
    try:
        store.add_invite(
            code,
            args.role,
            args.tenant,
            max_uses=args.max_uses,
            created_at=now,
            expires_at=expires_at,
            quota_milli_credits=args.quota,
        )
    finally:
        store.close()
    # The plaintext code goes to stdout exactly once; nothing else prints it and
    # only its digest was stored.
    print(code)
    print(
        f"{PROG}: invite minted (role {args.role}, tenant {args.tenant}, "
        f"max uses {args.max_uses}, quota {args.quota} milli-credits, "
        f"expires {expires_at.isoformat()}); shown once",
        file=sys.stderr,
    )
    return 0


def _cmd_admin_invite_list(args: argparse.Namespace) -> int:
    """Run ``admin invite-list``: a redacted view of every invite."""
    store = _load_center_store(args.config)
    try:
        invites = store.list_invites()
    finally:
        store.close()
    for invite in invites:
        expires = invite.expires_at.isoformat() if invite.expires_at else "never"
        state = "revoked" if invite.revoked_at else "active"
        print(
            f"{invite.code_digest[:23]}… role={invite.role} tenant={invite.tenant_scope} "
            f"uses={invite.used_count}/{invite.max_uses} expires={expires} {state}"
        )
    return 0


def _cmd_admin_revoke_key(args: argparse.Namespace) -> int:
    """Run ``admin revoke-key``: revoke a dynamically joined identity.

    Revocation is written to the store, which the signature path *and* the
    bearer ``resolve_credential`` consult on every request, so it takes effect
    on a running center without a restart and withdraws the identity's link
    token as well as its signing key. Revoking the device key of a node also
    stops dispatch from offering that already-connected session new work.

    Repeating the command is a safe no-op: the first revocation instant is
    preserved and the operator is told the key was already revoked, so driving
    a recovery checklist twice gives a clear, idempotent result.
    """
    store = _load_center_store(args.config)
    try:
        newly_revoked = store.revoke_identity(args.key_id, dt.datetime.now(dt.UTC))
    finally:
        store.close()
    if newly_revoked:
        print(f"{PROG}: revoked key {args.key_id}")
    else:
        print(f"{PROG}: key {args.key_id} was already revoked")
    return 0


# --------------------------------------------------------------------------
# admin: API keys for the OpenAI-compatible endpoint
# --------------------------------------------------------------------------


def _cmd_admin_api_key(args: argparse.Namespace) -> int:
    """Run ``admin api-key``: mint a key, print it once, store only its digest.

    The subject has to exist. A key minted for a name this center holds no
    consumer for would authenticate happily and then fail at settlement, after a
    node had spent real tokens on the request, so the typo is reported here
    instead — where the only thing wasted is a command.

    Raises:
        PotluckError: If the quota would admit nothing, the deadline would admit
            nothing either, or the subject is not a consumer this center knows.
    """
    if args.quota < 1:
        raise PotluckError(
            f"--quota must be >= 1 milli-credit, got {args.quota}: a key with no "
            "quota admits nothing, and minting one is a mistake worth reporting "
            "rather than a key worth holding"
        )
    deadline_ms: int | None = args.deadline_ms
    if deadline_ms is not None and deadline_ms > MAX_DEADLINE_MS:
        raise PotluckError(
            f"--deadline-ms {deadline_ms} is beyond the {MAX_DEADLINE_MS} ms "
            "(24 h) ceiling: an unbounded deadline is how a request that can "
            "never finish holds a concurrency slot forever"
        )
    if deadline_ms is not None and deadline_ms < 1:
        raise PotluckError(
            f"--deadline-ms must be >= 1 millisecond, got {deadline_ms}: a request "
            "with no budget expires before it can run, and a key that admits only "
            "expired requests is a mistake worth reporting rather than a key worth "
            "holding"
        )
    now = dt.datetime.now(dt.UTC)
    expires_at = None if args.expires_in is None else now + _parse_duration(args.expires_in)
    store = _load_center_store(args.config)
    try:
        binding = store.find_consumer_binding(args.subject_id)
        if binding is None:
            raise PotluckError(
                f"no consumer {args.subject_id!r} in this center: an API key "
                "speaks for a consumer that already exists, so join one with an "
                "invite first (`potluck-server admin invite --role consumer`, "
                "then `potluck join`) or name a consumer credential from "
                "center.json"
            )
        key_id = f"apikey-{secrets.token_hex(6)}"
        plaintext = API_KEY_PREFIX + secrets.token_urlsafe(API_KEY_BYTES)
        record = store.add_api_key(
            plaintext,
            key_id=key_id,
            name=str(args.name),
            subject_id=binding.subject_id,
            tenant_id=binding.tenant_id,
            quota_milli_credits=int(args.quota),
            created_at=now,
            expires_at=expires_at,
            deadline_ms=deadline_ms,
        )
    finally:
        store.close()
    # The plaintext goes to stdout exactly once; only its digest was stored, so
    # no command can read it back and a lost key is replaced rather than
    # recovered.
    print(plaintext)
    expires = "never" if record.expires_at is None else record.expires_at.isoformat()
    deadline = (
        "the endpoint's default" if record.deadline_ms is None else f"{record.deadline_ms}ms"
    )
    print(
        f"{PROG}: API key {record.key_id} minted for {record.subject_id} "
        f"(tenant {record.tenant_id}, quota {record.quota_milli_credits} "
        f"milli-credits, expires {expires}, per-request deadline {deadline}); "
        "shown once. Point a client at "
        "base_url <center-url>/openai/v1 with this key as its API key.",
        file=sys.stderr,
    )
    return 0


def _cmd_admin_session_list(args: argparse.Namespace) -> int:
    """Run ``admin session-list``: every session aggregate, most recent first.

    The listing is an operator view of the center's own books, so it prints what
    the aggregate holds and nothing it would have to invent: a session whose
    turns have not settled yet shows zero tokens and zero credit, which is the
    truth about what has been billed rather than an estimate of what will be.
    """
    store = _load_center_store(args.config)
    try:
        sessions = store.sessions(subject_id=args.subject_id)
    finally:
        store.close()
    for record in sessions:
        print(
            f"{record.session_id} subject={record.subject_id} "
            f"tenant={record.tenant_id} requests={record.request_count} "
            f"tokens={record.total_tokens} "
            f"milli_credits={record.total_milli_credits} "
            f"last_node={record.last_node_id or 'none'} "
            f"last_seen={record.last_seen_at.isoformat()}"
        )
    if not sessions:
        scope = f"for subject {args.subject_id}" if args.subject_id else "in this center"
        print(
            f"{PROG}: no agent session {scope}; a session exists once a request "
            "names one, which an OpenAI-compatible caller does with the "
            f"{SESSION_HEADER} header and a signed caller with the body's "
            "session_id field",
            file=sys.stderr,
        )
    return 0


def _cmd_admin_session_show(args: argparse.Namespace) -> int:
    """Run ``admin session-show``: one session's aggregate and its receipts.

    The receipts are listed rather than summarized away, because a total an
    operator cannot check against the records behind it is a claim rather than an
    account. Each id printed here verifies on its own with ``verify receipt``.

    Raises:
        PotluckError: If no session aggregate carries that identifier.
    """
    store = _load_center_store(args.config)
    try:
        sessions = store.sessions(subject_id=args.subject_id, session_id=args.session_id)
        receipts = store.receipts_for_session(args.session_id)
    finally:
        store.close()
    if not sessions:
        raise PotluckError(
            f"no agent session {args.session_id!r} in this center"
            + (
                f" for subject {args.subject_id!r}"
                if args.subject_id
                else "; a session exists once a request names one"
            )
        )
    for record in sessions:
        print(
            f"session={record.session_id} subject={record.subject_id} "
            f"tenant={record.tenant_id}"
        )
        print(f"  requests={record.request_count}")
        print(f"  tokens={record.total_tokens}")
        print(f"  milli_credits={record.total_milli_credits}")
        print(f"  last_node={record.last_node_id or 'none'}")
        print(f"  created_at={record.created_at.isoformat()}")
        print(f"  last_seen={record.last_seen_at.isoformat()}")
    print(f"  receipts={len(receipts)}")
    for receipt in receipts:
        print(
            f"    {receipt.receipt_id} request={receipt.request_id}"
            f" log_index={receipt.log_index}"
        )
    return 0


def _cmd_admin_api_key_list(args: argparse.Namespace) -> int:
    """Run ``admin api-key-list``: every key, with what it has spent."""
    store = _load_center_store(args.config)
    try:
        keys = store.list_api_keys()
    finally:
        store.close()
    for record in keys:
        expires = "never" if record.expires_at is None else record.expires_at.isoformat()
        last_used = "never" if record.last_used_at is None else record.last_used_at.isoformat()
        name = f' name="{record.name}"' if record.name else ""
        deadline = "default" if record.deadline_ms is None else f"{record.deadline_ms}ms"
        print(
            f"{record.key_id}{name} subject={record.subject_id} "
            f"tenant={record.tenant_id} "
            f"quota={record.used_milli_credits}/{record.quota_milli_credits} "
            f"remaining={record.remaining_milli_credits} "
            f"deadline={deadline} "
            f"expires={expires} last_used={last_used} {record.status}"
        )
    return 0


def _cmd_admin_api_key_revoke(args: argparse.Namespace) -> int:
    """Run ``admin api-key-revoke``: withdraw one key, immediately.

    Revocation is written to the store, and the OpenAI-compatible surface
    re-reads the key's row on every request, so a revoked key stops working on a
    center that is already running rather than at its next restart. What it
    spent stays on the books: revoking a key withdraws access, not history.

    Repeating the command is a safe no-op, and says so.
    """
    store = _load_center_store(args.config)
    try:
        newly_revoked = store.revoke_api_key(args.key_id, dt.datetime.now(dt.UTC))
    finally:
        store.close()
    if newly_revoked:
        print(f"{PROG}: revoked API key {args.key_id}")
    else:
        print(f"{PROG}: API key {args.key_id} was already revoked")
    return 0



def _verify_receipt_from_store(config: Path, receipt_id: str) -> ReceiptVerification:
    """Verify one receipt against the center store a ``center.json`` names.

    The store is opened through `load_center_for_inspection`, which builds the
    trusted-key registry a running center would use and writes nothing: no
    credential is provisioned, no float is funded, no socket is bound, and no
    in-memory book is rebuilt. An operator can therefore point this at a live
    center's database, and a defect in that database is reported instead of
    stopping the audit. A database that is not there is reported too rather than
    created, so "the whole store is gone" never reads as "this receipt is not in
    the receipt table".

    Raises:
        PotluckError: If the configuration is malformed, names no
            ``database_path``, or names a database file that does not exist.
    """
    inspection: CenterInspection = load_center_for_inspection(config)
    try:
        return verify_receipt_at_center(
            store=inspection.store, registry=inspection.registry, receipt_id=receipt_id
        )
    finally:
        inspection.close()



def _cmd_verify_receipt(args: argparse.Namespace) -> int:
    """Run ``verify receipt``: the five-dimension check over one receipt.

    The operator view reads the center's own store, so ``--config`` is
    required; the consumer view that reads over HTTP under a joined identity
    is ``potluck verify receipt --config-dir``.

    Returns:
        0 when no dimension contradicted the record, 1 when one did. ``unknown``
        is not a contradiction: a dimension reports it when the verifier holds no
        evidence either way.
    """
    verification = _verify_receipt_from_store(args.config, args.receipt_id)
    if args.json_output:
        print(canonicalize(verification.to_payload()).decode("utf-8"))
    else:
        print_verification(verification)
    return 1 if verification.failed else 0


def _cmd_admin_reconcile(args: argparse.Namespace) -> int:
    """Run ``admin reconcile``: the center's tables cross-checked against each other.

    Opens the store the same way ``admin invite-list`` does and reads only. The
    point is to make a one-sided edit or loss visible: any single table can be
    changed on its own, but every invariant here is asserted by two tables at
    once, so the disagreement names the record and the direction it points.

    A center database that is not there is refused instead of created, because
    the whole-store form of a loss is the one this command exists to surface:
    an empty database holds no rows, so it would report no differences and exit
    0 over a center that has nothing left.

    Returns:
        0 when every invariant held, 1 when any difference stands.
    """
    store = _load_center_store(args.config)
    try:
        differences = reconcile_center(store=store)
    finally:
        store.close()
    if args.json_output:
        print(
            canonicalize({"differences": [item.to_payload() for item in differences]}).decode(
                "utf-8"
            )
        )
    else:
        print_differences(
            title=f"{PROG} admin reconcile ({args.config})",
            differences=differences,
            left="this record",
            right="reconciliation result",
        )
    return 1 if differences else 0



def main(argv: Sequence[str] | None = None) -> int:
    """Run the ``potluck`` command-line interface.

    Args:
        argv: Argument list to parse, excluding the program name. Defaults to
            ``sys.argv[1:]`` when ``None``.

    Returns:
        The process exit code: 0 on success, 1 on any handled failure.
        Argument-parsing errors exit with argparse's own status 2.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    try:
        return handler(args)
    except PotluckError as exc:
        print(f"{PROG}: error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"{PROG}: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
