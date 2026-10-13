"""The operator's admin page: one loopback listener, read-only, no dependencies.

``potluck-server serve --admin-ui PORT`` starts this beside the gateway: a
second HTTP listener on the same process and the same database, serving one
hand-written page and five JSON aggregates an operator can read while the
server runs. It is a dashboard, not a console — every endpoint is a ``SELECT``,
and there is no route that changes anything.

Three invariants, each with a test that fails if it stops holding:

* **Loopback only.** The listener binds an IPv4 loopback literal and refuses to
  start on anything else, with `NonLoopbackAdminBindError` rather than a message
  a caller would have to parse. The page authenticates nobody: on a reachable
  interface it would publish every subject, node and receipt this server has
  settled for, over plain HTTP, to whoever can open the port. An operator who
  wants it from another machine tunnels it — ``ssh -L 9802:127.0.0.1:9802
  host`` — which authenticates with the key they already hold and keeps the
  listener off every interface but loopback.
* **Read-only.** The store is opened with `ServerStore.open_read_only`, a
  ``file:...?mode=ro`` URI, so a write is refused by SQLite rather than
  prevented by discipline. The dashboard runs in the same process as the single
  writer and must never become a second one: not by a bug, not by a later
  feature, not by a query that turns out to need a temporary table.
* **No dependencies.** ``GET /`` answers one HTML document with its CSS and
  JavaScript inline. No CDN, no framework, no font, no image: a server deployed
  on a machine with no route to the internet still gets its dashboard, and the
  page cannot be used to make an operator's browser fetch anything from a host
  the operator did not choose. The ``Content-Security-Policy`` it is served with
  says the same thing to the browser, so the invariant holds even against an
  edit that forgets it.

The data endpoints read the store's own aggregate views
(:meth:`aipotluck_server.persistence.ServerStore.admin_overview` and its
siblings), so a number on the page is a number the books hold, spelled the way
``admin reconcile`` and ``admin session-list`` spell it. The page re-reads them
every `REFRESH_INTERVAL_S` seconds; a poll that fails says so on the page and
leaves the last good numbers up rather than blanking them.
"""

from __future__ import annotations

import datetime as dt
import http.server
import ipaddress
import logging
import threading
import urllib.parse
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final, cast

from aipotluck.canonical import canonicalize
from aipotluck.errors import PotluckError

from .errors import AdminUiError, NonLoopbackAdminBindError
from .persistence import (
    AdminConsumer,
    AdminNode,
    AdminOverview,
    AdminReceipt,
    ServerStore,
    SessionRecord,
)

#: The address family and literal this listener binds. Not ``localhost``, which
#: is a name a host file answers, and not ``::1``, which is a second family.
ADMIN_LOOPBACK_HOST: Final = "127.0.0.1"

#: Seconds between two polls of the data endpoints. The page renders this number
#: into its own timer, so the interval is spelled once, here.
REFRESH_INTERVAL_S: Final = 10

#: Rows a listing returns when the caller does not ask for a count.
DEFAULT_ROW_LIMIT: Final = 50

#: The most rows one listing returns. A dashboard that polls every ten seconds
#: has no use for an unbounded table, and neither has the query behind it.
MAX_ROW_LIMIT: Final = 500

_INDEX_PATH: Final = "/"
_OVERVIEW_PATH: Final = "/admin/api/overview.json"
_CONSUMERS_PATH: Final = "/admin/api/consumers.json"
_NODES_PATH: Final = "/admin/api/nodes.json"
_SESSIONS_PATH: Final = "/admin/api/sessions.json"
_RECEIPTS_PATH: Final = "/admin/api/receipts.json"

#: Served with every response. ``default-src 'none'`` is the browser-side half
#: of the no-dependency invariant: the page cannot pull a script, a style, a
#: font or an image from anywhere, and the only fetches it may make are to the
#: origin that served it.
_SECURITY_HEADERS: Final = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline';"
        " connect-src 'self'; form-action 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
}

_logger = logging.getLogger(__name__)


def require_admin_loopback(host: str) -> str:
    """Validate an admin-page bind address against the loopback-only invariant.

    Args:
        host: The address a caller asked to bind.

    Returns:
        The same address, as an IPv4 literal.

    Raises:
        NonLoopbackAdminBindError: If the address is not an IPv4 loopback
            literal. ``0.0.0.0`` and ``::`` are refused because they mean every
            interface, a hostname is refused because resolving it is not
            something this process controls, and ``::1`` is refused because this
            listener is an IPv4 one.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise NonLoopbackAdminBindError(
            f"refusing to bind the admin page to {host!r}: it binds an IPv4 "
            "loopback address only, and a hostname is resolved through host "
            f"files this process does not control ({ADMIN_LOOPBACK_HOST} is the "
            "address ``serve --admin-ui`` binds)"
        ) from exc
    if address.version != 4 or not address.is_loopback:
        raise NonLoopbackAdminBindError(
            f"refusing to bind the admin page to {host!r}: it authenticates "
            "nobody, so it is reachable from this machine only — bind an IPv4 "
            f"loopback address such as {ADMIN_LOOPBACK_HOST}, and reach it from "
            "another machine through a tunnel (ssh -L "
            f"9802:{ADMIN_LOOPBACK_HOST}:9802 <host>) instead of publishing the "
            "server's books to every host that can route to this one"
        )
    return str(address)


def _instant(moment: dt.datetime) -> str:
    """Render an instant as ISO 8601 UTC text a browser's ``Date`` parses.

    The store's own text form ends in ``+0000``, which the ECMAScript date-time
    format does not describe; every instant this module emits goes through here
    so the page never has to guess at one.
    """
    return moment.astimezone(dt.UTC).isoformat()


def _bytes_text(count: int) -> str:
    """Render a byte count as a short decimal string, for the page's cards."""
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    size = float(count)
    for unit in units[:-1]:
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} {units[-1]}"


def overview_payload(
    overview: AdminOverview,
    *,
    platform_id: str,
    version: str,
    database_path: str,
    generated_at: dt.datetime,
) -> dict[str, Any]:
    """Return the health document the page's cards are rendered from.

    The throughput rates are derived here rather than stored: the window totals
    are facts from the books, and a rate is this page's way of showing one.
    """
    return {
        "generated_at": _instant(generated_at),
        "platform_id": platform_id,
        "version": version,
        "refresh_interval_s": REFRESH_INTERVAL_S,
        "database": {
            "path": database_path,
            "bytes": overview.database_bytes,
            "wal_bytes": overview.database_wal_bytes,
            "size": _bytes_text(overview.database_bytes),
            "wal_size": _bytes_text(overview.database_wal_bytes),
        },
        "consumers": {
            "total": overview.consumers_total,
            "active_7d": overview.consumers_active_7d,
        },
        "nodes": {
            "total": overview.nodes_total,
            "connected": overview.nodes_connected,
            "share_disabled": overview.nodes_share_disabled,
        },
        "requests": {"today": overview.requests_today, "days_7": overview.requests_7d},
        "tokens": {"today": overview.tokens_today, "days_7": overview.tokens_7d},
        "milli_credits": {
            "today": overview.milli_credits_today,
            "days_7": overview.milli_credits_7d,
        },
        "throughput": {
            # An integer rate, because canonical JSON refuses a float: the
            # window totals are the facts and a rate is this page's way of
            # showing one, where a token per hour is a whole token.
            "tokens_per_hour_1h": overview.tokens_last_hour,
            "tokens_per_hour_24h": round(overview.tokens_last_24h / 24),
            "tokens_last_24h": overview.tokens_last_24h,
        },
        "queue": {"depth": overview.queued, "in_flight": overview.in_flight},
    }


def consumers_payload(rows: list[AdminConsumer], *, limit: int) -> dict[str, Any]:
    """Return the consumer ranking document."""
    return {
        "limit": limit,
        "consumers": [
            {
                "subject_id": row.subject_id,
                "requests": row.requests,
                "tokens": row.tokens,
                "milli_credits": row.milli_credits,
                "sessions": row.sessions,
                "last_seen_at": None if row.last_seen_at is None else _instant(row.last_seen_at),
            }
            for row in rows
        ],
    }


def nodes_payload(rows: list[AdminNode], *, limit: int) -> dict[str, Any]:
    """Return the node ranking document."""
    return {
        "limit": limit,
        "nodes": [
            {
                "node_id": row.node_id,
                "model": row.model,
                "provider_id": row.provider_id,
                "connected": row.connected,
                "share_enabled": row.share_enabled,
                "requests_served": row.requests_served,
                "tokens": row.tokens,
                "milli_credits": row.milli_credits,
                "last_seen_at": _instant(row.last_seen_at),
            }
            for row in rows
        ],
    }


def sessions_payload(rows: list[SessionRecord], *, limit: int) -> dict[str, Any]:
    """Return the session aggregate document."""
    return {
        "limit": limit,
        "sessions": [
            {
                "session_id": row.session_id,
                "subject_id": row.subject_id,
                "tenant_id": row.tenant_id,
                "requests": row.request_count,
                "tokens": row.total_tokens,
                "milli_credits": row.total_milli_credits,
                "last_node_id": row.last_node_id,
                "created_at": _instant(row.created_at),
                "last_seen_at": _instant(row.last_seen_at),
            }
            for row in rows
        ],
    }


def receipts_payload(rows: list[AdminReceipt], *, limit: int) -> dict[str, Any]:
    """Return the recent-receipt document."""
    return {
        "limit": limit,
        "receipts": [
            {
                "receipt_id": row.receipt_id,
                "request_id": row.request_id,
                "subject_id": row.subject_id,
                "node_id": row.node_id,
                "tokens": row.tokens,
                "milli_credits": row.milli_credits,
                "status": row.request_status,
                "log_index": row.log_index,
                "settled_at": _instant(row.settled_at),
            }
            for row in rows
        ],
    }


def row_limit(query: str) -> int:
    """Return the row limit a listing request asks for.

    Args:
        query: The raw query string of the request.

    Returns:
        The requested limit, or `DEFAULT_ROW_LIMIT` when none was given.

    Raises:
        AdminUiError: If ``limit`` is not an integer, or is outside
            ``1..MAX_ROW_LIMIT``. A limit of zero is refused rather than
            honored, because an empty table and a server with nothing in it are
            the same picture and only one of them is true.
    """
    parameters = urllib.parse.parse_qs(query)
    if "limit" not in parameters:
        return DEFAULT_ROW_LIMIT
    raw = parameters["limit"][-1]
    try:
        limit = int(raw)
    except ValueError as exc:
        raise AdminUiError(f"limit must be an integer, got {raw!r}") from exc
    if limit < 1 or limit > MAX_ROW_LIMIT:
        raise AdminUiError(
            f"limit must be between 1 and {MAX_ROW_LIMIT}, got {limit}"
        )
    return limit


class _AdminUiHTTPServer(http.server.ThreadingHTTPServer):
    """A threading HTTP server that owns the admin page's state.

    Threads are daemons, so a handler still running when the operator stops the
    server cannot keep the process alive; `AdminUiServer.stop` closes the
    listener, which is what ends them.
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        handler_class: type[http.server.BaseHTTPRequestHandler],
        ui: AdminUiServer,
    ) -> None:
        """Bind the listener.

        Args:
            address: Loopback interface and port to bind.
            handler_class: The request handler to instantiate per connection.
            ui: The admin page that owns this server.
        """
        self.ui = ui
        super().__init__(address, handler_class)


class _AdminUiRequestHandler(http.server.BaseHTTPRequestHandler):
    """One request to the admin page: the document, or one aggregate.

    There is nothing to authenticate and nothing to authorize, because the
    listener is reachable from this machine only and every route is a read. That
    is the whole security argument, and it is why `require_admin_loopback` runs
    before a socket exists.
    """

    protocol_version = "HTTP/1.1"
    server_version = "potluck-admin-ui"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        """Silence the access log: the page polls five endpoints every ten
        seconds, and an operator reading the server's stderr wants the gateway's
        structured lines, not this listener's heartbeat."""

    def do_GET(self) -> None:
        """Serve the page or one aggregate."""
        self._dispatch()

    # Every other verb is refused with an accurate Allow header instead of the
    # base class's 501: a page that offers no action has exactly one method.
    def do_POST(self) -> None:
        """Refuse a write to a surface that has none."""
        self._method_not_allowed()

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST
    do_HEAD = do_POST

    @property
    def _ui(self) -> AdminUiServer:
        """The admin page that owns this connection."""
        return cast("_AdminUiHTTPServer", self.server).ui

    def _method_not_allowed(self) -> None:
        """Answer ``405`` naming the one method this surface has.

        The connection is closed rather than kept alive: a body this handler
        never read would still be in it, and the next request on that connection
        would be parsed out of the middle of somebody else's payload.
        """
        self.close_connection = True
        self._fail(
            405,
            "method_not_allowed",
            f"{self.command} is not allowed: the admin page is read-only",
            headers={"Allow": "GET"},
        )

    def _dispatch(self) -> None:
        """Resolve the route, read the store, and always answer."""
        target = urllib.parse.urlsplit(self.path)
        path = target.path
        try:
            if path == _INDEX_PATH:
                self._send_html(index_page())
            elif path == _OVERVIEW_PATH:
                self._send_json(self._ui.overview_document())
            elif path in _LISTING_DOCUMENTS:
                self._send_json(
                    _LISTING_DOCUMENTS[path](self._ui, row_limit(target.query))
                )
            else:
                self._fail(404, "not_found", f"no admin endpoint matches {path}")
        except (PotluckError, ValueError) as exc:
            # A refusal this listener owns: a limit nobody can read, a store that
            # cannot be read. The message is the caller's own input and the
            # store's own words, neither of which carries a credential.
            self._fail(400, "bad_request", str(exc))
        except OSError:
            # The peer went away mid-answer, or the database file vanished under
            # the reader. There is nobody left to tell, or nothing left to tell
            # them from; either way this connection is finished.
            _logger.warning("admin page request failed", exc_info=True)
            self.close_connection = True
        except Exception:
            # Last resort. The detail is a constant, so an unexpected failure
            # cannot echo a path or a value back to the caller; the traceback
            # goes to the server's own log, where the operator is already
            # reading the gateway's lines.
            _logger.exception("admin page failed to answer %s", self.command)
            self._fail(
                500, "internal_error", "the admin page failed to read the server's store"
            )

    def _send(
        self, status: int, content_type: str, body: bytes, *, extra: dict[str, str] | None = None
    ) -> None:
        """Write one complete response.

        Args:
            status: The HTTP status to answer with.
            content_type: The body's media type.
            body: The bytes to send, whose length is stated exactly.
            extra: Further headers for this response alone.
        """
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in _SECURITY_HEADERS.items():
            self.send_header(name, value)
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, payload: dict[str, Any]) -> None:
        """Send a canonical JSON document, spelled the way the wire spells one."""
        self._send(200, "application/json; charset=utf-8", canonicalize(payload))

    def _send_html(self, document: str) -> None:
        """Send the page."""
        self._send(200, "text/html; charset=utf-8", document.encode("utf-8"))

    def _fail(
        self, status: int, code: str, detail: str, *, headers: dict[str, str] | None = None
    ) -> None:
        """Send an error in the platform's own shape.

        Args:
            status: The HTTP status to answer with.
            code: Short machine-readable error code.
            detail: What went wrong, in words a caller can act on.
            headers: Extra response headers, such as ``Allow``.
        """
        self._send(
            status,
            "application/json; charset=utf-8",
            canonicalize({"error": code, "detail": detail}),
            extra=headers,
        )


#: The listing routes and the document each one answers with, so a path is
#: spelled once and a new listing is one entry here plus one method there.
_LISTING_DOCUMENTS: Final[dict[str, Callable[[AdminUiServer, int], dict[str, Any]]]] = {
    _CONSUMERS_PATH: lambda ui, limit: ui.consumers_document(limit=limit),
    _NODES_PATH: lambda ui, limit: ui.nodes_document(limit=limit),
    _SESSIONS_PATH: lambda ui, limit: ui.sessions_document(limit=limit),
    _RECEIPTS_PATH: lambda ui, limit: ui.receipts_document(limit=limit),
}


class AdminUiServer:
    """The admin page's listener: bind loopback, serve reads, stop cleanly.

    Construction is where both invariants are enforced — the address is checked
    and the store is opened read-only — so a programmatic caller cannot bind a
    reachable interface, and cannot hold a store that could write, no matter
    what it does afterwards.
    """

    def __init__(
        self,
        *,
        database_path: str | Path,
        platform_id: str,
        version: str,
        host: str = ADMIN_LOOPBACK_HOST,
        port: int = 0,
    ) -> None:
        """Prepare the listener; nothing is bound until `start`.

        Args:
            database_path: The server's database, which must already exist.
            platform_id: The platform the page names in its header.
            version: The server version the page reports.
            host: The interface to bind; `require_admin_loopback` accepts an
                IPv4 loopback literal and nothing else.
            port: The port to bind. ``0`` asks the OS for one, and `port` then
                reports what was bound.

        Raises:
            NonLoopbackAdminBindError: If the bind address is not IPv4 loopback.
            PotluckError: If the database is not an existing file with content
                in it, which is refused rather than created: a page over an
                empty database shows an operator a server with nothing in it.
        """
        self._host = require_admin_loopback(host)
        self._requested_port = port
        self._platform_id = platform_id
        self._version = version
        self._database_path = str(database_path)
        self._store = ServerStore.open_read_only(self._database_path)
        self._httpd: _AdminUiHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        """The loopback address this listener is bound to."""
        return self._host

    @property
    def port(self) -> int:
        """The port actually bound, which ``port=0`` leaves to the OS.

        Raises:
            RuntimeError: If the listener has not been started.
        """
        return self._require_listener().server_address[1]

    @property
    def url(self) -> str:
        """The page's URL, with the port actually bound.

        Raises:
            RuntimeError: If the listener has not been started.
        """
        return f"http://{self._host}:{self.port}/"

    def start(self) -> None:
        """Bind the port and begin serving in a daemon thread.

        Raises:
            RuntimeError: If the listener is already running.
            AdminUiError: If the port cannot be bound.
        """
        if self._httpd is not None:
            raise RuntimeError("the admin page is already running")
        try:
            httpd = _AdminUiHTTPServer(
                (self._host, self._requested_port), _AdminUiRequestHandler, self
            )
        except OSError as exc:
            raise AdminUiError(
                f"cannot bind the admin page to {self._host}:{self._requested_port}: {exc}"
                " — pick a port nothing else holds, or drop --admin-ui to serve"
                " without the page"
            ) from exc
        self._httpd = httpd
        thread = threading.Thread(
            target=httpd.serve_forever,
            kwargs={"poll_interval": 0.2},
            name="potluck-admin-ui",
            daemon=True,
        )
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        """Stop serving and release the read-only store. Safe to call twice.

        The listener is closed before the store, so no handler can be mid-read
        when its connection is dropped; the accept thread is joined under a
        bound, because a thread that will not stop must not stop the process.
        """
        httpd = self._httpd
        self._httpd = None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=5.0)
        self._store.close()

    def _require_listener(self) -> _AdminUiHTTPServer:
        """Return the running listener.

        Raises:
            RuntimeError: If the listener has not been started.
        """
        httpd = self._httpd
        if httpd is None:
            raise RuntimeError("the admin page is not running")
        return httpd

    # -- documents ----------------------------------------------------------

    def overview_document(self) -> dict[str, Any]:
        """Return the health document, read from the store at this instant.

        One instant names both the windows and the read's own timestamp, so the
        document cannot say it was generated at a moment its numbers exclude.
        """
        now = dt.datetime.now(dt.UTC)
        return overview_payload(
            self._store.admin_overview(now=now),
            platform_id=self._platform_id,
            version=self._version,
            database_path=self._database_path,
            generated_at=now,
        )

    def consumers_document(self, *, limit: int = DEFAULT_ROW_LIMIT) -> dict[str, Any]:
        """Return the consumer ranking document."""
        return consumers_payload(self._store.admin_consumers(limit=limit), limit=limit)

    def nodes_document(self, *, limit: int = DEFAULT_ROW_LIMIT) -> dict[str, Any]:
        """Return the node ranking document."""
        return nodes_payload(self._store.admin_nodes(limit=limit), limit=limit)

    def sessions_document(self, *, limit: int = DEFAULT_ROW_LIMIT) -> dict[str, Any]:
        """Return the session aggregate document."""
        return sessions_payload(self._store.admin_sessions(limit=limit), limit=limit)

    def receipts_document(self, *, limit: int = DEFAULT_ROW_LIMIT) -> dict[str, Any]:
        """Return the recent-receipt document."""
        return receipts_payload(self._store.admin_receipts(limit=limit), limit=limit)


#: The page: one document, its style and its script inline, no external
#: anything. `AdminUiServer` renders `REFRESH_INTERVAL_S` into the timer so the
#: interval is spelled once, in Python, and the table cells are built through
#: ``textContent`` rather than ``innerHTML``, so a subject id or a model name
#: that happens to look like markup is displayed instead of parsed.
_INDEX_HTML: Final = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>potluck server admin</title>
<style>
:root {
  --background: #101317;
  --panel: #171b21;
  --panel-border: #242a33;
  --text: #dfe4ea;
  --muted: #8b95a3;
  --accent: #6fb3ff;
  --good: #57c98a;
  --warn: #e0b341;
  --bad: #e2695f;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 24px; background: var(--background); color: var(--text);
  font: 14px/1.45 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
header { display: flex; flex-wrap: wrap; align-items: baseline; gap: 12px; }
h1 { font-size: 16px; margin: 0; letter-spacing: 0.04em; }
h2 { font-size: 13px; margin: 32px 0 8px; color: var(--muted); letter-spacing: 0.08em;
     text-transform: uppercase; font-weight: 600; }
.meta { color: var(--muted); font-size: 12px; }
#banner { display: none; margin-top: 16px; padding: 10px 12px; border: 1px solid var(--bad);
          border-radius: 6px; color: var(--bad); background: #1d1315; }
#banner.visible { display: block; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
         gap: 12px; margin-top: 20px; }
.card { background: var(--panel); border: 1px solid var(--panel-border); border-radius: 8px;
        padding: 12px 14px; }
.card .label { color: var(--muted); font-size: 11px; text-transform: uppercase;
               letter-spacing: 0.08em; }
.card .value { font-size: 22px; margin-top: 6px; }
.card .sub { color: var(--muted); font-size: 12px; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; background: var(--panel);
        border: 1px solid var(--panel-border); border-radius: 8px; overflow: hidden; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--panel-border);
         white-space: nowrap; }
th { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; }
td.number, th.number { text-align: right; }
tbody tr:last-child td { border-bottom: none; }
tbody tr:hover { background: #1c2129; }
.empty { color: var(--muted); padding: 10px; }
.on { color: var(--good); }
.off { color: var(--muted); }
.bad { color: var(--bad); }
footer { margin-top: 32px; color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<header>
  <h1>potluck server &mdash; admin</h1>
  <span class="meta" id="identity">loading&hellip;</span>
  <span class="meta" id="updated"></span>
</header>
<div id="banner"></div>
<div class="cards" id="cards"></div>

<h2>Consumers</h2>
<table><thead id="consumers-head"></thead><tbody id="consumers-body"></tbody></table>

<h2>Contribution nodes</h2>
<table><thead id="nodes-head"></thead><tbody id="nodes-body"></tbody></table>

<h2>Agent sessions</h2>
<table><thead id="sessions-head"></thead><tbody id="sessions-body"></tbody></table>

<h2>Recent receipts</h2>
<table><thead id="receipts-head"></thead><tbody id="receipts-body"></tbody></table>

<footer id="footer">read-only &middot; loopback-only</footer>

<script>
"use strict";
const REFRESH_MS = %%REFRESH_MS%%;
const ENDPOINTS = {
  overview: "/admin/api/overview.json",
  consumers: "/admin/api/consumers.json",
  nodes: "/admin/api/nodes.json",
  sessions: "/admin/api/sessions.json",
  receipts: "/admin/api/receipts.json"
};

function text(node, value) { node.textContent = value; return node; }

function number(value) {
  return value === null || value === undefined ? "\\u2014" : Number(value).toLocaleString("en-US");
}

function instant(value) {
  return value ? String(value).slice(0, 19).replace("T", " ") + " UTC" : "\\u2014";
}

function age(value) {
  if (!value) return "\\u2014";
  const moment = Date.parse(value);
  if (Number.isNaN(moment)) return "\\u2014";
  const seconds = Math.max(0, Math.round((Date.now() - moment) / 1000));
  if (seconds < 60) return seconds + "s ago";
  if (seconds < 3600) return Math.round(seconds / 60) + "m ago";
  if (seconds < 86400) return Math.round(seconds / 3600) + "h ago";
  return Math.round(seconds / 86400) + "d ago";
}

function since(value) {
  // A consumer who joined and never asked has no last activity to age, and
  // "never" says that in one word where a dash would only say "not shown".
  return value ? age(value) + " (" + instant(value) + ")" : "never";
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

function renderHead(headId, columns) {
  const head = document.getElementById(headId);
  clear(head);
  const row = document.createElement("tr");
  for (const column of columns) {
    const cell = document.createElement("th");
    if (column.number) cell.className = "number";
    row.appendChild(text(cell, column.header));
  }
  head.appendChild(row);
}

function renderRows(bodyId, rows, columns) {
  const body = document.getElementById(bodyId);
  clear(body);
  if (!rows.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.className = "empty";
    cell.colSpan = columns.length;
    row.appendChild(text(cell, "none recorded"));
    body.appendChild(row);
    return;
  }
  for (const item of rows) {
    const row = document.createElement("tr");
    for (const column of columns) {
      const cell = document.createElement("td");
      if (column.number) cell.className = "number";
      if (column.flag) cell.className = item[column.value] ? "on" : "off";
      row.appendChild(text(cell, String(column.render(item))));
    }
    body.appendChild(row);
  }
}

function renderCards(overview) {
  const cards = [
    { label: "consumers", value: number(overview.consumers.total),
      sub: number(overview.consumers.active_7d) + " active in 7d" },
    { label: "nodes", value: number(overview.nodes.connected) + " / " +
        number(overview.nodes.total),
      sub: number(overview.nodes.share_disabled) + " sharing off" },
    { label: "queue", value: number(overview.queue.depth),
      sub: number(overview.queue.in_flight) + " in flight" },
    { label: "requests", value: number(overview.requests.today),
      sub: number(overview.requests.days_7) + " in 7d" },
    { label: "tokens", value: number(overview.tokens.today),
      sub: number(overview.tokens.days_7) + " in 7d" },
    { label: "milli-credits", value: number(overview.milli_credits.today),
      sub: number(overview.milli_credits.days_7) + " in 7d" },
    { label: "tokens/hour", value: number(overview.throughput.tokens_per_hour_1h),
      sub: number(overview.throughput.tokens_per_hour_24h) + " avg over 24h" },
    { label: "database", value: overview.database.size,
      sub: "wal " + overview.database.wal_size }
  ];
  const host = document.getElementById("cards");
  clear(host);
  for (const card of cards) {
    const panel = document.createElement("div");
    panel.className = "card";
    const label = document.createElement("div");
    label.className = "label";
    panel.appendChild(text(label, card.label));
    const value = document.createElement("div");
    value.className = "value";
    panel.appendChild(text(value, card.value));
    const sub = document.createElement("div");
    sub.className = "sub";
    panel.appendChild(text(sub, card.sub));
    host.appendChild(panel);
  }
}

const CONSUMER_COLUMNS = [
  { header: "subject", value: "subject_id", render: (row) => row.subject_id },
  { header: "requests", number: true, value: "requests", render: (row) => number(row.requests) },
  { header: "tokens", number: true, value: "tokens", render: (row) => number(row.tokens) },
  { header: "milli-credits", number: true, value: "milli_credits",
    render: (row) => number(row.milli_credits) },
  { header: "sessions", number: true, value: "sessions", render: (row) => number(row.sessions) },
  { header: "last seen", value: "last_seen_at",
    render: (row) => since(row.last_seen_at) }
];

const NODE_COLUMNS = [
  { header: "node", value: "node_id", render: (row) => row.node_id },
  { header: "model", value: "model", render: (row) => row.model },
  { header: "link", flag: true, value: "connected",
    render: (row) => (row.connected ? "connected" : "offline") },
  { header: "sharing", flag: true, value: "share_enabled",
    render: (row) => (row.share_enabled ? "on" : "off") },
  { header: "served", number: true, value: "requests_served",
    render: (row) => number(row.requests_served) },
  { header: "tokens", number: true, value: "tokens", render: (row) => number(row.tokens) },
  { header: "milli-credits", number: true, value: "milli_credits",
    render: (row) => number(row.milli_credits) },
  { header: "last seen", value: "last_seen_at",
    render: (row) => since(row.last_seen_at) }
];

const SESSION_COLUMNS = [
  { header: "session", value: "session_id", render: (row) => row.session_id },
  { header: "subject", value: "subject_id", render: (row) => row.subject_id },
  { header: "requests", number: true, value: "requests", render: (row) => number(row.requests) },
  { header: "tokens", number: true, value: "tokens", render: (row) => number(row.tokens) },
  { header: "milli-credits", number: true, value: "milli_credits",
    render: (row) => number(row.milli_credits) },
  { header: "last node", value: "last_node_id",
    render: (row) => (row.last_node_id ? row.last_node_id : "\\u2014") },
  { header: "last seen", value: "last_seen_at",
    render: (row) => since(row.last_seen_at) }
];

const RECEIPT_COLUMNS = [
  { header: "receipt", value: "receipt_id", render: (row) => row.receipt_id },
  { header: "subject", value: "subject_id", render: (row) => row.subject_id },
  { header: "node", value: "node_id", render: (row) => (row.node_id ? row.node_id : "\\u2014") },
  { header: "tokens", number: true, value: "tokens", render: (row) => number(row.tokens) },
  { header: "milli-credits", number: true, value: "milli_credits",
    render: (row) => number(row.milli_credits) },
  { header: "request", value: "status", render: (row) => row.status },
  { header: "log", number: true, value: "log_index", render: (row) => number(row.log_index) },
  { header: "settled", value: "settled_at",
    render: (row) => since(row.settled_at) }
];

async function readDocument(name) {
  const response = await fetch(ENDPOINTS[name], { headers: { accept: "application/json" } });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    const detail = body && body.detail ? body.detail : response.statusText;
    throw new Error(name + ": " + response.status + " " + detail);
  }
  return response.json();
}

function banner(message) {
  const node = document.getElementById("banner");
  if (message === null) {
    node.className = "";
    clear(node);
    return;
  }
  node.className = "visible";
  text(node, message);
}

async function refresh() {
  try {
    const [overview, consumers, nodes, sessions, receipts] = await Promise.all([
      readDocument("overview"),
      readDocument("consumers"),
      readDocument("nodes"),
      readDocument("sessions"),
      readDocument("receipts")
    ]);
    text(document.getElementById("identity"),
      overview.platform_id + " \\u00b7 server " + overview.version);
    text(document.getElementById("updated"),
      "\\u00b7 read at " + instant(overview.generated_at));
    text(document.getElementById("footer"),
      "read-only \\u00b7 loopback-only \\u00b7 refreshes every " +
      overview.refresh_interval_s + "s \\u00b7 " + overview.database.path);
    renderCards(overview);
    renderHead("consumers-head", CONSUMER_COLUMNS);
    renderRows("consumers-body", consumers.consumers, CONSUMER_COLUMNS);
    renderHead("nodes-head", NODE_COLUMNS);
    renderRows("nodes-body", nodes.nodes, NODE_COLUMNS);
    renderHead("sessions-head", SESSION_COLUMNS);
    renderRows("sessions-body", sessions.sessions, SESSION_COLUMNS);
    renderHead("receipts-head", RECEIPT_COLUMNS);
    renderRows("receipts-body", receipts.receipts, RECEIPT_COLUMNS);
    banner(null);
  } catch (error) {
    // The last good numbers stay up: a poll that failed is a fact about the
    // poll, and blanking the page would hide the numbers an operator is
    // watching while telling them nothing about why they vanished.
    banner("refresh failed: " + error.message + " \\u2014 showing the last read");
  }
  setTimeout(refresh, REFRESH_MS);
}

renderHead("consumers-head", CONSUMER_COLUMNS);
renderHead("nodes-head", NODE_COLUMNS);
renderHead("sessions-head", SESSION_COLUMNS);
renderHead("receipts-head", RECEIPT_COLUMNS);
refresh();
</script>
</body>
</html>
"""


def index_page() -> str:
    """Return the page's HTML, with this build's refresh interval rendered in."""
    return _INDEX_HTML.replace("%%REFRESH_MS%%", str(REFRESH_INTERVAL_S * 1000))
