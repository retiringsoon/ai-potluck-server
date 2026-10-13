"""The operator's admin page: loopback-only, read-only, and honest about the books.

Three things are tested here, and each is a claim the page makes about itself:

* **the numbers.** Every endpoint is asserted against a store seeded with a
  known world — two consumers who asked, one who joined and never did, one who
  exists only as an identity row, three nodes in three different states,
  requests inside and outside every window, a settlement correction, and a
  receipt whose winning attempt has gone missing. A dashboard whose arithmetic
  nobody checks is decoration, so each figure is named.
* **the read-only invariant.** The store the page reads is opened through a
  ``mode=ro`` URI, a write through it is refused by SQLite rather than by
  discipline, and serving every endpoint leaves the database file and its
  write-ahead log byte-identical. The digest is taken with the server's own
  writer still holding the database open, which is how the page runs.
* **the loopback invariant.** A bind address that is not an IPv4 loopback
  literal is refused with its own error type before any socket exists, and
  ``serve`` without ``--admin-ui`` starts no second listener at all.

The end-to-end test at the bottom drives a real gateway and a real contribution
node through one settled request, then reads the page over HTTP: it is the check
that these aggregates read the JSON a real settlement writes, which no
hand-built receipt can prove.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from aipotluck.adapters import FakeResponse, FakeUpstream, FakeUpstreamAdapter
from aipotluck.canonical import canonicalize, loads_strict
from aipotluck.cli import main as client_main
from aipotluck.connector import Connector, ConnectorConfig
from aipotluck.errors import PotluckError
from aipotluck.identity import generate_key_pair
from aipotluck.metering import NormalizedUsage
from aipotluck.persistence import NodeStore, ReceiptRecord
from aipotluck.wire import user_message
from conftest import Keyring, signed_authorization

from aipotluck_server.admin_ui import (
    ADMIN_LOOPBACK_HOST,
    DEFAULT_ROW_LIMIT,
    MAX_ROW_LIMIT,
    REFRESH_INTERVAL_S,
    AdminUiServer,
    index_page,
    overview_payload,
    require_admin_loopback,
    row_limit,
)
from aipotluck_server.cli import _start_admin_ui
from aipotluck_server.cli import main as server_main
from aipotluck_server.deploy import load_server
from aipotluck_server.errors import AdminUiError, NonLoopbackAdminBindError
from aipotluck_server.gateway_server import GatewayServer
from aipotluck_server.gateway_service import GatewayConfig, GatewayService
from aipotluck_server.persistence import (
    AdminOverview,
    NodeRecord,
    ServerStore,
    SettlementRecord,
)

MODEL = "coding-pool"

#: Every window the page reports is anchored to this instant, so the seeded
#: world means the same thing in every run instead of drifting with the clock.
NOW = dt.datetime(2026, 10, 6, 12, 0, tzinfo=dt.UTC)

#: The seeded world's instants, named for the window each one lands in.
ADMITTED_THIS_HOUR = NOW - dt.timedelta(minutes=30)
SETTLED_THIS_HOUR = NOW - dt.timedelta(minutes=15)
QUEUED = NOW - dt.timedelta(minutes=5)
IN_FLIGHT = NOW - dt.timedelta(minutes=4)
ADMITTED_THIS_WEEK = NOW - dt.timedelta(days=3)
ADMITTED_BEFORE_THE_WINDOW = NOW - dt.timedelta(days=10)


# --------------------------------------------------------------------------
# Seeding: a world whose every number the tests below name.
# --------------------------------------------------------------------------


def _receipt_json(
    *, receipt_id: str, request_id: str, attempt_id: str, tokens: int, settled_at: dt.datetime
) -> str:
    """Build the stored form of a signed receipt carrying `tokens`.

    Shaped the way `gateway_service` stores one — a signed record whose payload
    holds the billable total and names the winning attempt — because that is the
    document these aggregates read. The end-to-end test at the bottom of this
    file checks the shape against a receipt a real settlement wrote.
    """
    return canonicalize(
        {
            "schema": "aipotluck.settlement.v1",
            "record_id": receipt_id,
            "revision": 1,
            "signed_at": settled_at.isoformat(),
            "signer_key_id": "settlement-key-1",
            "signer_id": "platform-1",
            "signature": "signature",
            "payload": {
                "receipt_id": receipt_id,
                "request_id": request_id,
                "service_unit_id": request_id,
                "winner_attempt_id": attempt_id,
                "billable_tokens": str(tokens),
                "currency": "milli-credit",
                "settled_at": settled_at.isoformat(),
            },
            "previous_record_hash": None,
        }
    ).decode("utf-8")


def _add_request(
    store: ServerStore,
    *,
    request_id: str,
    subject_id: str,
    tenant_id: str,
    created_at: dt.datetime,
    status: str,
    session_id: str | None = None,
) -> None:
    """Register one request and walk it to `status` through legal transitions."""
    store.create_request(
        request_id=request_id,
        tenant_id=tenant_id,
        subject_id=subject_id,
        idempotency_key=f"key-{request_id}",
        payload_digest=f"digest-{request_id}",
        delivery_mode="buffered_complete",
        max_attempts=2,
        service_unit_id=request_id,
        created_at=created_at,
        session_id=session_id,
    )
    if session_id is not None:
        store.touch_session(
            tenant_id=tenant_id, subject_id=subject_id, session_id=session_id, at=created_at
        )
    if status == "CREATED":
        return
    store.set_request_status(request_id, "ROUTING", at=created_at)
    if status == "ROUTING":
        return
    store.set_request_status(request_id, status, at=created_at)


def _settle(
    store: ServerStore,
    *,
    request_id: str,
    attempt_id: str,
    node_id: str,
    tokens: int,
    milli_credits: int,
    log_index: int,
    at: dt.datetime,
    revision: int = 1,
) -> None:
    """Record one settlement and everything backing it, as the gateway does.

    `tokens` is the receipt's own measured total and `milli_credits` is what the
    winning attempt records, which is the pair `admin reconcile` cross-checks;
    they are passed separately here so a test can say the two differ.
    """
    store.upsert_attempt(
        attempt_id=attempt_id,
        request_id=request_id,
        node_id=node_id,
        resource_id=f"resource-{node_id}",
        provider_id=f"provider-{node_id}",
        dispatch_epoch=1,
        at=at,
    )
    receipt_id = f"RC-{request_id}-v{revision}"
    text = _receipt_json(
        receipt_id=receipt_id,
        request_id=request_id,
        attempt_id=attempt_id,
        tokens=tokens,
        settled_at=at,
    )
    store.record_settlement_bundle(
        settlement=SettlementRecord(
            service_unit_id=request_id,
            revision=revision,
            fingerprint=f"fingerprint-{receipt_id}",
            receipt_id=receipt_id,
            receipt_hash=f"hash-{receipt_id}",
            log_index=log_index,
            receipt_json=text,
            created_at=at,
        ),
        receipt=ReceiptRecord(
            receipt_id=receipt_id,
            request_id=request_id,
            receipt_hash=f"hash-{receipt_id}",
            log_index=log_index,
            receipt_json=text,
            created_at=at,
        ),
        journal_kind="journal",
        journal_payload={
            "journal_id": f"J-{receipt_id}",
            "kind": "settlement",
            "idempotency_key": [request_id, str(revision)],
            "postings": [["consumer-X", -milli_credits], ["provider-A/pending", milli_credits]],
            "service_unit_id": request_id,
        },
        attempt_id=attempt_id,
        usage_tokens=milli_credits,
        at=at,
        settled_tokens=tokens,
    )


def _add_node(
    store: ServerStore,
    *,
    node_id: str,
    model: str,
    connected: bool,
    share_enabled: bool,
    last_seen_at: dt.datetime = NOW,
) -> None:
    """Advertise one contribution node's state."""
    store.upsert_node(
        NodeRecord(
            node_id=node_id,
            device_id=f"device-{node_id}",
            provider_id=f"provider-{node_id}",
            adapter_name="fake-adapter",
            model=model,
            share_enabled=share_enabled,
            max_concurrency=2,
            max_local_reserved_milli_credits=0,
            policy_version=1,
            connected=connected,
            last_seen_at=last_seen_at,
        )
    )


def _seeded_store(tmp_path: Path) -> ServerStore:
    """Return an open store holding the world the aggregate tests assert against.

    Four consumers, known by the three routes a consumer can be known by:
    a credential and requests (X), a credential and requests (Y), a credential
    and nothing else (Z), and an identity row alone (I). Three nodes cover the
    states the page distinguishes — connected and serving, offline with sharing
    off, and connected with nothing settled. The requests land inside and
    outside each window the overview reports, and one settled request belongs to
    an agent session.
    """
    store = ServerStore.open(tmp_path / "server.db")
    store.add_credential("token-x", "tenant-a", "consumer-X", "consumer", NOW)
    store.add_credential("token-y", "tenant-b", "consumer-Y", "consumer", NOW)
    store.add_credential("token-z", "tenant-c", "consumer-Z", "consumer", NOW)
    public_key, _private_key = generate_key_pair()
    store.add_identity(
        key_id="consumer-key-I",
        owner_id="consumer-I",
        purpose="consumer",
        public_key_b64=public_key,
        tenant_id="tenant-i",
        role="consumer",
        display_name=None,
        provider_id=None,
        registered_at=NOW,
        account_id="consumer-I",
    )
    _add_node(store, node_id="node-A", model=MODEL, connected=True, share_enabled=True)
    _add_node(
        store,
        node_id="node-B",
        model="research-pool",
        connected=False,
        share_enabled=False,
        last_seen_at=ADMITTED_THIS_WEEK,
    )
    _add_node(store, node_id="node-C", model=MODEL, connected=True, share_enabled=True)

    _add_request(
        store,
        request_id="R-today",
        subject_id="consumer-X",
        tenant_id="tenant-a",
        created_at=ADMITTED_THIS_HOUR,
        status="RUNNING",
        session_id="session-x",
    )
    _settle(
        store,
        request_id="R-today",
        attempt_id="A-today",
        node_id="node-A",
        tokens=1000,
        milli_credits=1000,
        log_index=0,
        at=SETTLED_THIS_HOUR,
    )
    _add_request(
        store,
        request_id="R-week",
        subject_id="consumer-X",
        tenant_id="tenant-a",
        created_at=ADMITTED_THIS_WEEK,
        status="RUNNING",
    )
    _settle(
        store,
        request_id="R-week",
        attempt_id="A-week",
        node_id="node-B",
        tokens=500,
        milli_credits=400,
        log_index=1,
        at=ADMITTED_THIS_WEEK,
    )
    _add_request(
        store,
        request_id="R-old",
        subject_id="consumer-Y",
        tenant_id="tenant-b",
        created_at=ADMITTED_BEFORE_THE_WINDOW,
        status="RUNNING",
    )
    _settle(
        store,
        request_id="R-old",
        attempt_id="A-old",
        node_id="node-A",
        tokens=7,
        milli_credits=7,
        log_index=2,
        at=ADMITTED_BEFORE_THE_WINDOW,
    )
    _add_request(
        store,
        request_id="R-queued",
        subject_id="consumer-Y",
        tenant_id="tenant-b",
        created_at=QUEUED,
        status="ROUTING",
    )
    _add_request(
        store,
        request_id="R-running",
        subject_id="consumer-Y",
        tenant_id="tenant-b",
        created_at=IN_FLIGHT,
        status="RUNNING",
    )
    return store


def _database_digest(database: Path) -> str:
    """Hash the database file and its write-ahead log as one digest.

    The shared-memory sidecar is deliberately excluded: SQLite rewrites it while
    a reader reads, and it holds no record — it is an index into a log whose
    bytes are hashed here.
    """
    digest = hashlib.sha256()
    for suffix in ("", "-wal"):
        candidate = Path(f"{database}{suffix}")
        digest.update(candidate.read_bytes() if candidate.is_file() else b"")
    return digest.hexdigest()


def _fetch(port: int, path: str, *, method: str = "GET") -> tuple[int, bytes, dict[str, str]]:
    """Make one request to an admin listener and report what came back."""
    request = urllib.request.Request(
        f"http://{ADMIN_LOOPBACK_HOST}:{port}{path}", method=method
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        # A refusal is the answer these tests are asking for, not a failure.
        return error.code, error.read(), dict(error.headers)


def _document(body: bytes) -> dict[str, Any]:
    """Parse one JSON document an endpoint answered with."""
    parsed = loads_strict(body.decode("utf-8"))
    assert isinstance(parsed, dict)
    return parsed


def _json(port: int, path: str) -> dict[str, Any]:
    """Fetch one admin endpoint, require 200, and parse its document."""
    status, body, _headers = _fetch(port, path)
    assert status == 200, (status, body)
    return _document(body)


def _running_ui(tmp_path: Path) -> AdminUiServer:
    """Start an admin listener over the seeded database in `tmp_path`.

    The listener opens that file read-only while the test's own writer keeps it
    open, which is how the page runs beside a server.
    """
    ui = AdminUiServer(
        database_path=tmp_path / "server.db",
        platform_id="platform-1",
        version="9.9.9",
        port=0,
    )
    ui.start()
    return ui


def _server_document(tmp_path: Path) -> dict[str, Any]:
    """Build a valid ``server.json`` body with freshly generated key material."""
    _settlement_public, settlement_private = generate_key_pair()
    device_public, _device_private = generate_key_pair()
    return {
        "host": "127.0.0.1",
        "port": 0,
        "database_path": str(tmp_path / "server.db"),
        "platform_id": "platform-1",
        "settlement_key_id": "settlement-key-1",
        "settlement_private_key_b64": settlement_private,
        "certfile": None,
        "keyfile": None,
        "credentials": [],
        "providers": [
            {
                "device_id": "device-1",
                "device_key_id": "device-key-1",
                "provider_id": "provider-1",
                "public_key_b64": device_public,
                "demo_float_milli_credits": 5_000,
            }
        ],
        "consumer_floats": [],
    }


def _write_server_json(tmp_path: Path) -> Path:
    """Write a ``server.json`` a real ``serve`` can load."""
    path = tmp_path / "server.json"
    path.write_text(json.dumps(_server_document(tmp_path)), encoding="utf-8")
    return path


def _wait_until(condition: Any, *, timeout: float = 30.0, what: str) -> None:
    """Block until `condition()` is truthy, failing with a readable message."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


# --------------------------------------------------------------------------
# The aggregates: every number the seeded world implies.
# --------------------------------------------------------------------------


def test_overview_names_every_figure_the_seeded_world_implies(tmp_path: Path) -> None:
    """One pass over the books reports each card's number, exactly."""
    store = _seeded_store(tmp_path)
    try:
        overview = store.admin_overview(now=NOW)
        database = tmp_path / "server.db"
        write_ahead = Path(f"{database}-wal")
        expected_bytes = database.stat().st_size
        expected_wal_bytes = (
            write_ahead.stat().st_size if write_ahead.is_file() else 0
        )
    finally:
        store.close()

    assert expected_bytes > 0
    assert overview == AdminOverview(
        consumers_total=4,
        consumers_active_7d=2,
        nodes_total=3,
        nodes_connected=2,
        nodes_share_disabled=1,
        requests_today=3,
        requests_7d=4,
        tokens_today=1000,
        tokens_7d=1500,
        milli_credits_today=1000,
        milli_credits_7d=1400,
        tokens_last_hour=1000,
        tokens_last_24h=1000,
        queued=1,
        in_flight=1,
        database_bytes=expected_bytes,
        database_wal_bytes=expected_wal_bytes,
    )


def test_windows_count_a_request_where_it_was_admitted(tmp_path: Path) -> None:
    """The windows are a cohort: what a request cost follows when it was admitted.

    Each of the hour, day and week totals is read off a different request here,
    so a window that quietly widened or narrowed to its neighbour's boundary
    changes one number and fails.
    """
    store = ServerStore.open(tmp_path / "server.db")
    try:
        store.add_credential("token-x", "tenant-a", "consumer-X", "consumer", NOW)
        _add_node(store, node_id="node-A", model=MODEL, connected=True, share_enabled=True)
        for request_id, admitted, tokens, credits, log_index in (
            ("R-hour", NOW - dt.timedelta(minutes=30), 100, 100, 0),
            ("R-day", NOW - dt.timedelta(minutes=90), 200, 150, 1),
            ("R-week", NOW - dt.timedelta(hours=25), 400, 400, 2),
        ):
            _add_request(
                store,
                request_id=request_id,
                subject_id="consumer-X",
                tenant_id="tenant-a",
                created_at=admitted,
                status="RUNNING",
            )
            _settle(
                store,
                request_id=request_id,
                attempt_id=f"A-{request_id}",
                node_id="node-A",
                tokens=tokens,
                milli_credits=credits,
                log_index=log_index,
                at=NOW,
            )
        overview = store.admin_overview(now=NOW)
    finally:
        store.close()

    assert overview.tokens_last_hour == 100
    assert overview.tokens_last_24h == 300
    assert overview.tokens_today == 300
    assert overview.tokens_7d == 700
    assert overview.milli_credits_today == 250
    assert overview.milli_credits_7d == 650
    assert overview.requests_today == 2
    assert overview.requests_7d == 3


def test_a_settlement_landing_after_midnight_stays_in_the_day_it_was_admitted(
    tmp_path: Path,
) -> None:
    """Today's totals do not move when yesterday's request settles."""
    store = ServerStore.open(tmp_path / "server.db")
    try:
        store.add_credential("token-x", "tenant-a", "consumer-X", "consumer", NOW)
        _add_node(store, node_id="node-A", model=MODEL, connected=True, share_enabled=True)
        yesterday = NOW - dt.timedelta(hours=23)
        _add_request(
            store,
            request_id="R-late",
            subject_id="consumer-X",
            tenant_id="tenant-a",
            created_at=yesterday,
            status="RUNNING",
        )
        _settle(
            store,
            request_id="R-late",
            attempt_id="A-late",
            node_id="node-A",
            tokens=900,
            milli_credits=900,
            log_index=0,
            at=NOW,
        )
        overview = store.admin_overview(now=NOW)
    finally:
        store.close()

    assert overview.requests_today == 0
    assert overview.tokens_today == 0
    assert overview.milli_credits_today == 0
    assert overview.tokens_last_hour == 0
    assert overview.tokens_last_24h == 900
    assert overview.tokens_7d == 900


def test_consumers_rank_by_what_they_spent_and_include_who_never_asked(
    tmp_path: Path,
) -> None:
    """The ranking names every consumer, including the ones with nothing to rank."""
    store = _seeded_store(tmp_path)
    try:
        consumers = store.admin_consumers(limit=DEFAULT_ROW_LIMIT)
    finally:
        store.close()

    assert [
        (row.subject_id, row.requests, row.tokens, row.milli_credits, row.sessions)
        for row in consumers
    ] == [
        ("consumer-X", 2, 1500, 1400, 1),
        ("consumer-Y", 3, 7, 7, 0),
        ("consumer-I", 0, 0, 0, 0),
        ("consumer-Z", 0, 0, 0, 0),
    ]
    assert consumers[0].last_seen_at == SETTLED_THIS_HOUR
    assert consumers[1].last_seen_at == IN_FLIGHT
    # A consumer who never asked has no last activity to report, and the page
    # shows that instead of a zero that reads as an instant.
    assert consumers[2].last_seen_at is None
    assert consumers[3].last_seen_at is None


def test_a_listing_limit_caps_the_rows_and_zero_is_refused(tmp_path: Path) -> None:
    """`limit` bounds the read, and a limit that would show nothing is refused."""
    store = _seeded_store(tmp_path)
    try:
        assert [row.subject_id for row in store.admin_consumers(limit=1)] == ["consumer-X"]
        assert [row.node_id for row in store.admin_nodes(limit=2)] == ["node-A", "node-B"]
        assert [row.receipt_id for row in store.admin_receipts(limit=2)] == [
            "RC-R-old-v1",
            "RC-R-week-v1",
        ]
        with pytest.raises(PotluckError, match="limit >= 1"):
            store.admin_sessions(limit=0)
    finally:
        store.close()


def test_nodes_report_their_link_state_and_the_work_they_settled(tmp_path: Path) -> None:
    """A node's row is its advertised state beside the work the books billed it."""
    store = _seeded_store(tmp_path)
    try:
        nodes = store.admin_nodes(limit=DEFAULT_ROW_LIMIT)
    finally:
        store.close()

    assert [
        (
            row.node_id,
            row.model,
            row.connected,
            row.share_enabled,
            row.requests_served,
            row.tokens,
            row.milli_credits,
        )
        for row in nodes
    ] == [
        ("node-A", MODEL, True, True, 2, 1007, 1007),
        ("node-B", "research-pool", False, False, 1, 500, 400),
        ("node-C", MODEL, True, True, 0, 0, 0),
    ]
    assert nodes[0].provider_id == "provider-node-A"
    assert nodes[1].last_seen_at == ADMITTED_THIS_WEEK


def test_a_settlement_correction_is_counted_once_at_its_corrected_amount(
    tmp_path: Path,
) -> None:
    """A second revision replaces the first instead of adding to it.

    A correction's receipt states the corrected total, not the difference, so a
    listing that summed every revision would bill one request twice — the
    arithmetic mistake an operator would least expect from the books' own page.
    """
    store = _seeded_store(tmp_path)
    try:
        _settle(
            store,
            request_id="R-week",
            attempt_id="A-week",
            node_id="node-B",
            tokens=600,
            milli_credits=500,
            log_index=3,
            at=NOW,
            revision=2,
        )
        consumers = {row.subject_id: row for row in store.admin_consumers(limit=10)}
        nodes = {row.node_id: row for row in store.admin_nodes(limit=10)}
        receipts = store.admin_receipts(limit=10)
        overview = store.admin_overview(now=NOW)
    finally:
        store.close()

    assert consumers["consumer-X"].tokens == 1600
    assert consumers["consumer-X"].milli_credits == 1500
    assert nodes["node-B"].tokens == 600
    assert nodes["node-B"].milli_credits == 500
    assert overview.tokens_7d == 1600
    assert overview.milli_credits_7d == 1500
    # One row per request, and it is the corrected one.
    assert [(row.receipt_id, row.tokens, row.milli_credits) for row in receipts] == [
        ("RC-R-week-v2", 600, 500),
        ("RC-R-old-v1", 7, 7),
        ("RC-R-today-v1", 1000, 1000),
    ]


def test_sessions_are_listed_most_recently_active_first(tmp_path: Path) -> None:
    """The session table is the store's own aggregate, not a second opinion."""
    store = _seeded_store(tmp_path)
    try:
        _add_request(
            store,
            request_id="R-second-session",
            subject_id="consumer-Y",
            tenant_id="tenant-b",
            created_at=NOW,
            status="CREATED",
            session_id="session-y",
        )
        sessions = store.admin_sessions(limit=DEFAULT_ROW_LIMIT)
    finally:
        store.close()

    assert [
        (
            row.session_id,
            row.subject_id,
            row.request_count,
            row.total_tokens,
            row.total_milli_credits,
            row.last_node_id,
        )
        for row in sessions
    ] == [
        ("session-y", "consumer-Y", 1, 0, 0, None),
        ("session-x", "consumer-X", 1, 1000, 1000, "node-A"),
    ]


def test_receipts_carry_the_request_status_and_the_node_that_served_them(
    tmp_path: Path,
) -> None:
    """A receipt's row says who it bills, what it measured, and how it ended."""
    store = _seeded_store(tmp_path)
    try:
        receipts = store.admin_receipts(limit=DEFAULT_ROW_LIMIT)
    finally:
        store.close()

    assert [
        (
            row.receipt_id,
            row.request_id,
            row.subject_id,
            row.node_id,
            row.tokens,
            row.milli_credits,
            row.request_status,
            row.log_index,
        )
        for row in receipts
    ] == [
        ("RC-R-old-v1", "R-old", "consumer-Y", "node-A", 7, 7, "SUCCEEDED", 2),
        ("RC-R-week-v1", "R-week", "consumer-X", "node-B", 500, 400, "SUCCEEDED", 1),
        ("RC-R-today-v1", "R-today", "consumer-X", "node-A", 1000, 1000, "SUCCEEDED", 0),
    ]
    assert receipts[0].settled_at == ADMITTED_BEFORE_THE_WINDOW
    assert receipts[2].settled_at == SETTLED_THIS_HOUR


def test_a_receipt_whose_winning_attempt_is_gone_reports_a_hole_not_a_zero(
    tmp_path: Path,
) -> None:
    """A lost attempt row shows as no charge, not as a free request.

    Zero and missing are different claims: the first says the consumer was
    billed nothing, the second says the page cannot tell. Reporting the hole as
    a zero would hide exactly the defect `admin reconcile` exists to name.
    """
    store = _seeded_store(tmp_path)
    database = tmp_path / "server.db"
    try:
        connection = sqlite3.connect(database)
        try:
            connection.execute("DELETE FROM attempts WHERE attempt_id = 'A-today'")
            connection.commit()
        finally:
            connection.close()
        receipts = store.admin_receipts(limit=DEFAULT_ROW_LIMIT)
        nodes = {row.node_id: row for row in store.admin_nodes(limit=10)}
    finally:
        store.close()

    today = next(row for row in receipts if row.request_id == "R-today")
    assert today.tokens == 1000, "the receipt names its own total"
    assert today.milli_credits is None
    assert today.node_id is None
    # The node loses the work too: which node served a request is a fact about
    # the attempt row, so a page that showed it as node-A's would be guessing.
    assert nodes["node-A"].requests_served == 1
    assert nodes["node-A"].tokens == 7
    assert nodes["node-A"].milli_credits == 7


# --------------------------------------------------------------------------
# The payload the page renders.
# --------------------------------------------------------------------------


def test_the_overview_document_derives_its_rates_from_the_window_totals() -> None:
    """A rate is the page's rendering of a total, and it is an integer.

    Canonical JSON refuses a float, so the 24-hour average is rounded here
    rather than somewhere a caller cannot see.
    """
    overview = AdminOverview(
        consumers_total=2,
        consumers_active_7d=1,
        nodes_total=3,
        nodes_connected=2,
        nodes_share_disabled=1,
        requests_today=4,
        requests_7d=9,
        tokens_today=1000,
        tokens_7d=2000,
        milli_credits_today=900,
        milli_credits_7d=1800,
        tokens_last_hour=120,
        tokens_last_24h=2400,
        queued=1,
        in_flight=2,
        database_bytes=2048,
        database_wal_bytes=0,
    )
    document = overview_payload(
        overview,
        platform_id="platform-1",
        version="9.9.9",
        database_path="server.db",
        generated_at=NOW,
    )

    assert document["throughput"] == {
        "tokens_per_hour_1h": 120,
        "tokens_per_hour_24h": 100,
        "tokens_last_24h": 2400,
    }
    assert document["platform_id"] == "platform-1"
    assert document["version"] == "9.9.9"
    assert document["generated_at"] == "2026-10-06T12:00:00+00:00"
    assert document["refresh_interval_s"] == REFRESH_INTERVAL_S
    assert document["database"] == {
        "path": "server.db",
        "bytes": 2048,
        "wal_bytes": 0,
        "size": "2.0 KiB",
        "wal_size": "0 B",
    }
    assert document["consumers"] == {"total": 2, "active_7d": 1}
    assert document["nodes"] == {"total": 3, "connected": 2, "share_disabled": 1}
    assert document["requests"] == {"today": 4, "days_7": 9}
    assert document["tokens"] == {"today": 1000, "days_7": 2000}
    assert document["milli_credits"] == {"today": 900, "days_7": 1800}
    assert document["queue"] == {"depth": 1, "in_flight": 2}
    # Every instant the page parses is spelled the way ECMAScript's date-time
    # format describes, which the store's own `+0000` suffix is not, and the
    # whole document survives canonicalization — which is where a float, the
    # one value RFC 8785 refuses, would be caught.
    assert loads_strict(canonicalize(document).decode("utf-8")) == document


def test_a_row_limit_nobody_can_read_is_refused_with_its_reason() -> None:
    """`limit` is validated at the boundary, in words a caller can act on."""
    assert row_limit("") == DEFAULT_ROW_LIMIT
    assert row_limit("limit=5") == 5
    # The last value wins, so a repeated parameter cannot ask for a second read.
    assert row_limit("limit=5&limit=7") == 7
    assert row_limit(f"limit={MAX_ROW_LIMIT}") == MAX_ROW_LIMIT
    for query, fragment in (
        ("limit=0", "between 1 and"),
        ("limit=-1", "between 1 and"),
        (f"limit={MAX_ROW_LIMIT + 1}", "between 1 and"),
        ("limit=many", "must be an integer"),
    ):
        with pytest.raises(AdminUiError, match=fragment):
            row_limit(query)


# --------------------------------------------------------------------------
# The loopback invariant.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host", ["0.0.0.0", "::", "::1", "localhost", "10.0.0.5", "192.168.1.1", ""]
)
def test_a_non_loopback_bind_is_refused_before_anything_is_opened(
    tmp_path: Path, host: str
) -> None:
    """Every address but an IPv4 loopback literal is refused, as its own error.

    Checked against a database that does not exist, which also fixes the order:
    the address is refused before the store is opened, so a caller cannot get a
    page over a reachable interface even momentarily, and the refusal cannot
    depend on what is behind it.
    """
    with pytest.raises(NonLoopbackAdminBindError) as failure:
        AdminUiServer(
            database_path=tmp_path / "absent.db",
            platform_id="platform-1",
            version="9.9.9",
            host=host,
            port=0,
        )
    assert isinstance(failure.value, AdminUiError)
    assert not isinstance(failure.value, OSError)
    assert host in str(failure.value) or host == ""
    assert not (tmp_path / "absent.db").exists()


def test_every_ipv4_loopback_literal_is_accepted() -> None:
    """The invariant is loopback, not one address: all of 127.0.0.0/8 is local."""
    assert require_admin_loopback("127.0.0.1") == "127.0.0.1"
    assert require_admin_loopback("127.9.9.9") == "127.9.9.9"
    assert ADMIN_LOOPBACK_HOST == "127.0.0.1"


def test_a_database_that_is_not_there_is_refused_rather_than_created(tmp_path: Path) -> None:
    """The page reads a database; it does not manufacture an empty one to show."""
    missing = tmp_path / "absent.db"
    with pytest.raises(PotluckError, match="does not exist"):
        AdminUiServer(
            database_path=missing, platform_id="platform-1", version="9.9.9", port=0
        )
    assert not missing.exists()


# --------------------------------------------------------------------------
# The read-only invariant.
# --------------------------------------------------------------------------


def test_the_dashboard_store_cannot_write_even_when_it_is_asked_to(tmp_path: Path) -> None:
    """Read-only is SQLite's answer, not the reader's promise.

    The store the page holds is the same class the gateway writes with, so the
    guarantee has to live in the connection: a write through it is refused by
    the database engine, which is what makes a later feature that reaches for a
    write method fail loudly instead of quietly becoming a second writer.
    """
    database = tmp_path / "server.db"
    writer = _seeded_store(tmp_path)
    before = _database_digest(database)
    reader = ServerStore.open_read_only(database)
    try:
        with pytest.raises(sqlite3.OperationalError, match="readonly database"):
            reader.add_credential("token-new", "tenant-a", "consumer-N", "consumer", NOW)
        with pytest.raises(sqlite3.OperationalError, match="readonly database"):
            reader.set_node_connected("node-A", False, at=NOW)
        # Reading works, and changes nothing on disk.
        assert reader.admin_overview(now=NOW).consumers_total == 4
        assert reader.admin_consumers(limit=10)[0].subject_id == "consumer-X"
        assert _database_digest(database) == before
        # A read-only connection still reads what the writer commits afterwards,
        # which is what makes the page usable beside a running server.
        writer.add_credential("token-late", "tenant-d", "consumer-L", "consumer", NOW)
        assert reader.admin_overview(now=NOW).consumers_total == 5
        assert _database_digest(database) != before, "the writer's own row must land"
    finally:
        reader.close()
        writer.close()


def test_serving_every_endpoint_leaves_the_database_bytes_unchanged(tmp_path: Path) -> None:
    """A page read is not a write, proven against the file rather than asserted.

    The writer stays open throughout, which is how the page runs in production:
    the digest that must not move is a database a live server is serving from.
    """
    store = _seeded_store(tmp_path)
    database = tmp_path / "server.db"
    ui = _running_ui(tmp_path)
    try:
        before = _database_digest(database)
        for path in (
            "/",
            "/admin/api/overview.json",
            f"/admin/api/consumers.json?limit={MAX_ROW_LIMIT}",
            "/admin/api/nodes.json",
            "/admin/api/sessions.json",
            "/admin/api/receipts.json",
            "/admin/api/does-not-exist.json",
        ):
            _fetch(ui.port, path)
        after = _database_digest(database)
    finally:
        ui.stop()
        store.close()

    assert after == before


# --------------------------------------------------------------------------
# The HTTP surface.
# --------------------------------------------------------------------------


def test_the_page_is_one_document_that_loads_nothing_from_anywhere(tmp_path: Path) -> None:
    """No CDN, no framework, no font, no image: one HTML document, inline.

    A server deployed where nothing can reach the internet still owes its
    operator a dashboard, and a page that fetched a library from a third party
    would hand that party the operator's address and the shape of the server's
    books. The Content-Security-Policy is the browser-side half of the same
    rule, so an edit that forgets the rule still cannot load anything.
    """
    store = _seeded_store(tmp_path)
    ui = _running_ui(tmp_path)
    try:
        status, body, headers = _fetch(ui.port, "/")
    finally:
        ui.stop()
        store.close()

    page = body.decode("utf-8")
    assert status == 200
    assert headers["Content-Type"] == "text/html; charset=utf-8"
    assert headers["Cache-Control"] == "no-store"
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert "connect-src 'self'" in headers["Content-Security-Policy"]
    assert "<style>" in page
    assert "<script>" in page
    for forbidden in ("http://", "https://", "src=", "href=", "@import", "url("):
        assert forbidden not in page, forbidden
    assert f"const REFRESH_MS = {REFRESH_INTERVAL_S * 1000};" in page
    for endpoint in (
        "/admin/api/overview.json",
        "/admin/api/consumers.json",
        "/admin/api/nodes.json",
        "/admin/api/sessions.json",
        "/admin/api/receipts.json",
    ):
        assert endpoint in page
    assert index_page() == page


def test_every_endpoint_answers_canonical_json_the_page_can_read(tmp_path: Path) -> None:
    """Five endpoints, one spelling: canonical JSON over the same origin."""
    store = _seeded_store(tmp_path)
    database = tmp_path / "server.db"
    ui = _running_ui(tmp_path)
    try:
        overview_status, overview_body, overview_headers = _fetch(
            ui.port, "/admin/api/overview.json"
        )
        consumers = _json(ui.port, "/admin/api/consumers.json?limit=2")
        nodes = _json(ui.port, "/admin/api/nodes.json")
        sessions = _json(ui.port, "/admin/api/sessions.json")
        receipts = _json(ui.port, "/admin/api/receipts.json")
    finally:
        ui.stop()
        store.close()

    assert overview_status == 200
    assert overview_headers["Content-Type"] == "application/json; charset=utf-8"
    assert overview_headers["Cache-Control"] == "no-store"
    assert len(overview_body) == int(overview_headers["Content-Length"])
    document = _document(overview_body)
    # Canonical: the bytes on the wire are the canonicalization of the document.
    assert canonicalize(document) == overview_body

    assert document["platform_id"] == "platform-1"
    assert document["version"] == "9.9.9"
    assert document["refresh_interval_s"] == REFRESH_INTERVAL_S
    assert document["database"]["path"] == str(database)
    assert document["database"]["bytes"] == database.stat().st_size
    # The windowed figures are read against the wall clock, which a seeded world
    # anchored to `NOW` says nothing about; they are asserted exactly where the
    # instant is a parameter — `admin_overview` and `overview_payload` above.
    # What this layer owns is the document's shape and the clock-free numbers.
    assert set(document) == {
        "generated_at",
        "platform_id",
        "version",
        "refresh_interval_s",
        "database",
        "consumers",
        "nodes",
        "requests",
        "tokens",
        "milli_credits",
        "throughput",
        "queue",
    }
    assert set(document["requests"]) == {"today", "days_7"}
    assert set(document["tokens"]) == {"today", "days_7"}
    assert set(document["milli_credits"]) == {"today", "days_7"}
    assert set(document["throughput"]) == {
        "tokens_per_hour_1h",
        "tokens_per_hour_24h",
        "tokens_last_24h",
    }
    assert set(document["queue"]) == {"depth", "in_flight"}
    assert document["consumers"]["total"] == 4
    assert document["nodes"] == {"total": 3, "connected": 2, "share_disabled": 1}
    assert document["queue"] == {"depth": 1, "in_flight": 1}

    assert consumers["limit"] == 2
    assert consumers["consumers"] == [
        {
            "subject_id": "consumer-X",
            "requests": 2,
            "tokens": 1500,
            "milli_credits": 1400,
            "sessions": 1,
            "last_seen_at": "2026-10-06T11:45:00+00:00",
        },
        {
            "subject_id": "consumer-Y",
            "requests": 3,
            "tokens": 7,
            "milli_credits": 7,
            "sessions": 0,
            "last_seen_at": "2026-10-06T11:56:00+00:00",
        },
    ]
    assert nodes["limit"] == DEFAULT_ROW_LIMIT
    assert [row["node_id"] for row in nodes["nodes"]] == ["node-A", "node-B", "node-C"]
    assert nodes["nodes"][2]["requests_served"] == 0
    assert nodes["nodes"][0]["connected"] is True
    assert nodes["nodes"][1]["share_enabled"] is False
    assert [row["session_id"] for row in sessions["sessions"]] == ["session-x"]
    assert [row["receipt_id"] for row in receipts["receipts"]] == [
        "RC-R-old-v1",
        "RC-R-week-v1",
        "RC-R-today-v1",
    ]
    assert receipts["receipts"][-1]["status"] == "SUCCEEDED"
    assert receipts["receipts"][-1]["tokens"] == 1000


def test_an_unknown_path_is_not_found_and_a_write_verb_is_not_allowed(tmp_path: Path) -> None:
    """The surface is one page and five reads, and says so to anything else."""
    store = _seeded_store(tmp_path)
    ui = _running_ui(tmp_path)
    try:
        missing = _fetch(ui.port, "/admin/api/nothing.json")
        posted = _fetch(ui.port, "/admin/api/consumers.json", method="POST")
        deleted = _fetch(ui.port, "/", method="DELETE")
    finally:
        ui.stop()
        store.close()

    assert missing[0] == 404
    assert _document(missing[1]) == {
        "error": "not_found",
        "detail": "no admin endpoint matches /admin/api/nothing.json",
    }
    for status, body, headers in (posted, deleted):
        assert status == 405
        assert headers["Allow"] == "GET"
        assert _document(body)["error"] == "method_not_allowed"


def test_a_bad_limit_is_refused_over_http_with_the_reason(tmp_path: Path) -> None:
    """The boundary the page cannot cross answers 400 rather than an empty table."""
    store = _seeded_store(tmp_path)
    ui = _running_ui(tmp_path)
    try:
        zero = _fetch(ui.port, "/admin/api/consumers.json?limit=0")
        text = _fetch(ui.port, "/admin/api/nodes.json?limit=many")
        capped = _fetch(ui.port, f"/admin/api/receipts.json?limit={MAX_ROW_LIMIT + 1}")
    finally:
        ui.stop()
        store.close()

    assert zero[0] == 400
    assert _document(zero[1]) == {
        "error": "bad_request",
        "detail": f"limit must be between 1 and {MAX_ROW_LIMIT}, got 0",
    }
    assert text[0] == 400
    assert _document(text[1])["detail"] == "limit must be an integer, got 'many'"
    assert capped[0] == 400


# --------------------------------------------------------------------------
# `serve --admin-ui`.
# --------------------------------------------------------------------------


def test_serve_without_the_flag_starts_no_admin_page(tmp_path: Path) -> None:
    """Off means off: no second listener and no second open of the database."""
    deployment = load_server(_write_server_json(tmp_path), start=True)
    try:
        assert _start_admin_ui(deployment, None) is None
    finally:
        deployment.server.stop()
        deployment.store.close()


def test_serve_with_the_flag_starts_a_page_over_the_same_database(tmp_path: Path) -> None:
    """The flag binds a loopback port and the page reads the server's own books."""
    deployment = load_server(_write_server_json(tmp_path), start=True)
    ui: AdminUiServer | None = None
    try:
        ui = _start_admin_ui(deployment, 0)
        assert ui is not None
        assert ui.host == ADMIN_LOOPBACK_HOST
        assert ui.port != 0
        assert ui.url == f"http://{ADMIN_LOOPBACK_HOST}:{ui.port}/"
        document = _json(ui.port, "/admin/api/overview.json")
        assert document["platform_id"] == "platform-1"
        assert document["database"]["path"] == str(tmp_path / "server.db")
    finally:
        if ui is not None:
            ui.stop()
        deployment.server.stop()
        deployment.store.close()


def test_the_command_line_refuses_a_port_no_socket_can_bind(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A typo in the flag costs the command, not a half-started server."""
    config = _write_server_json(tmp_path)
    assert server_main(["serve", "--config", str(config), "--admin-ui", "70000"]) == 1
    assert "--admin-ui" in capsys.readouterr().err
    # The port is checked before the configuration is loaded, so the refusal
    # leaves no database behind it.
    assert not (tmp_path / "server.db").exists()


def test_serve_prints_the_admin_url_and_serves_the_page(tmp_path: Path) -> None:
    """The real process, started the way an operator starts it.

    A subprocess rather than a call into ``main``: ``serve`` installs signal
    handlers and then waits, which only a process of its own can do, and the
    operator's evidence is the URL that process prints.
    """
    process = subprocess.Popen(
        [
            sys.executable,
            # Unbuffered: the startup lines are the evidence this test reads, and
            # a pipe would otherwise hold them until the process exited.
            "-u",
            "-m",
            "aipotluck_server",
            "serve",
            "--config",
            str(_write_server_json(tmp_path)),
            "--admin-ui",
            "0",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines: list[str] = []
    try:
        port = _admin_port_from_startup(process, lines)
        status, body, _headers = _fetch(port, "/")
        assert status == 200
        assert b"<title>potluck server admin</title>" in body
        document = _json(port, "/admin/api/overview.json")
        assert document["platform_id"] == "platform-1"
        assert document["database"]["path"] == str(tmp_path / "server.db")
    finally:
        process.terminate()
        stdout, stderr = process.communicate(timeout=60)
    lines.extend(stdout.splitlines())
    assert process.returncode == 0, stderr
    assert any("loopback only, read-only" in line for line in lines), lines


def test_serve_without_the_flag_prints_no_admin_url(tmp_path: Path) -> None:
    """The startup lines name the page only when there is one."""
    process = subprocess.Popen(
        [
            sys.executable,
            "-u",
            "-m",
            "aipotluck_server",
            "serve",
            "--config",
            str(_write_server_json(tmp_path)),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    lines: list[str] = []
    try:
        _read_until(process, lines, "serving")
    finally:
        process.terminate()
        stdout, stderr = process.communicate(timeout=60)
    lines.extend(stdout.splitlines())
    assert process.returncode == 0, stderr
    assert not any("admin page" in line for line in lines), lines


def _read_until(process: subprocess.Popen[str], lines: list[str], fragment: str) -> None:
    """Block until a startup line containing `fragment` has been printed."""
    deadline = time.monotonic() + 60
    assert process.stdout is not None
    while time.monotonic() < deadline:
        if any(fragment in line for line in lines):
            return
        line = process.stdout.readline()
        if not line:
            raise AssertionError(f"the server stopped before printing {fragment!r}: {lines}")
        lines.append(line.rstrip("\n"))
    raise AssertionError(f"the server never printed {fragment!r}: {lines}")


def _admin_port_from_startup(process: subprocess.Popen[str], lines: list[str]) -> int:
    """Block until the process prints the admin page's URL, and return its port."""
    _read_until(process, lines, "admin page")
    line = next(line for line in lines if "admin page" in line)
    url = line.split("admin page", 1)[1].strip().split(" ", 1)[0]
    assert url.startswith(f"http://{ADMIN_LOOPBACK_HOST}:"), line
    return int(url.rsplit(":", 1)[1].rstrip("/"))


# --------------------------------------------------------------------------
# The end-to-end check: a real settlement, read back through the page.
# --------------------------------------------------------------------------


class _LivePlatform:
    """A real gateway, a real contribution node, and one settled request.

    Built the way `test_cli.py` builds one — the shipped service over a real
    store, a connector thread over a real WebSocket, a fake upstream — because
    the point is that these aggregates read the JSON a real settlement wrote,
    not the JSON a test imagined.
    """

    def __init__(self, tmp_path: Path, keyring: Keyring) -> None:
        self.tmp_path = tmp_path
        self.keyring = keyring
        self.database = tmp_path / "server.db"
        self.store = ServerStore.open(self.database)
        self.config = GatewayConfig(
            host="127.0.0.1",
            port=0,
            database_path=str(self.database),
            platform_id="platform-1",
            settlement_key_id="settlement-key-1",
            settlement_private_key_b64=keyring.private_b64["settlement-key-1"],
        )
        self.service = GatewayService(
            config=self.config, store=self.store, registry=keyring.registry
        )
        self.server = GatewayServer(self.service, config=self.config)
        self.upstream = FakeUpstream()
        self.connector: Connector | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()

    @property
    def port(self) -> int:
        """The gateway's bound port."""
        return int(self.server.url.rsplit(":", 1)[1])

    def start(self) -> None:
        """Start the gateway and a node's link, and fund the consumer."""
        moment = dt.datetime.now(dt.UTC)
        self.server.start()
        self.store.add_credential("consumer-token", "tenant-live", "consumer-X", "consumer", moment)
        self.store.add_credential("node-token", "tenant-live", "node-A", "node", moment)
        self.service.fund_account(
            account_id="consumer-X", kind="consumer_available", amount=100_000, now=moment
        )
        self.upstream.queue(
            FakeResponse(
                text_chunks=("Hello ", "from the node"),
                usage=NormalizedUsage(input_total=800, output_total=200),
            )
        )
        self.connector = Connector(
            ConnectorConfig(
                server_url=f"ws://127.0.0.1:{self.port}/v1/node-link",
                node_id="node-A",
                device_id="device-A",
                device_key_id="device-key-A",
                provider_id="provider-A",
                database_path=str(self.tmp_path / "node.db"),
                token="node-token",
                adapter_name="fake-adapter",
                model=MODEL,
                device_private_key_b64=self.keyring.private_b64["device-key-A"],
                heartbeat_interval_s=3600,
            ),
            adapter=FakeUpstreamAdapter(upstream=self.upstream, model=MODEL),
            store=NodeStore.open(self.tmp_path / "node.db"),
        )
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self.connector.run_forever,
            kwargs={"stop_event": self.stop_event},
            daemon=True,
        )
        self.thread.start()
        _wait_until(lambda: bool(self.store.connected_nodes()), what="the node to register")

    def ask(self, request_id: str) -> None:
        """Submit one signed request through the client CLI and wait for it."""
        consumer_config = self.tmp_path / "consumer.json"
        consumer_config.write_text(
            json.dumps({"server_url": self.server.url, "token": "consumer-token"}),
            encoding="utf-8",
        )
        moment = dt.datetime.now(dt.UTC)
        messages = (user_message("write a haiku about dashboards"),)
        record = signed_authorization(
            self.keyring,
            request_id=request_id,
            payer_account_id="consumer-X",
            consumer_id="consumer-X",
            issued_at=moment - dt.timedelta(minutes=1),
            expires_at=moment + dt.timedelta(minutes=10),
            messages=messages,
            model=MODEL,
        )
        auth_file = self.tmp_path / "auth.json"
        auth_file.write_text(
            json.dumps(
                {
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
            ),
            encoding="utf-8",
        )
        code = client_main(
            [
                "request",
                "--config",
                str(consumer_config),
                "--prompt",
                "write a haiku about dashboards",
                "--model",
                MODEL,
                "--request-id",
                request_id,
                "--idempotency-key",
                f"key-{request_id}",
                "--max-charge",
                "20000",
                "--auth-file",
                str(auth_file),
                "--wait",
            ]
        )
        assert code == 0, "the request the dashboard is about to report did not succeed"

    def stop(self) -> None:
        """Stop the node and the gateway, and close the store."""
        if self.connector is not None:
            self.connector.stop()
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=10)
        self.server.stop()
        self.store.close()


def test_the_page_reports_what_a_real_settlement_wrote(
    tmp_path: Path, keyring: Keyring
) -> None:
    """One real request, settled by a real node, read back through the page.

    This is the test that fails if a receipt stops carrying the fields these
    aggregates read, or if the winning attempt stops being named where they look
    for it: the worlds above build their receipts by hand, and a hand-built
    receipt always agrees with itself.
    """
    platform = _LivePlatform(tmp_path, keyring)
    platform.start()
    ui = AdminUiServer(
        database_path=platform.database,
        platform_id="platform-1",
        version="9.9.9",
        port=0,
    )
    ui.start()
    try:
        platform.ask("R-live-1")
        _wait_until(lambda: bool(platform.store.receipts()), what="the settlement to be durable")
        receipt = platform.store.receipts()[0]

        overview = _json(ui.port, "/admin/api/overview.json")
        consumers = _json(ui.port, "/admin/api/consumers.json")
        nodes = _json(ui.port, "/admin/api/nodes.json")
        sessions = _json(ui.port, "/admin/api/sessions.json")
        receipts = _json(ui.port, "/admin/api/receipts.json")
    finally:
        ui.stop()
        platform.stop()

    assert overview["consumers"]["total"] == 1
    assert overview["consumers"]["active_7d"] == 1
    assert overview["nodes"] == {"total": 1, "connected": 1, "share_disabled": 0}
    # The week and hour windows are asserted exactly; "today" is left to the
    # store-level tests, where the instant is a parameter, because a request
    # admitted seconds before UTC midnight would legitimately fall outside it.
    assert overview["requests"]["days_7"] == 1
    assert overview["tokens"]["days_7"] == 1000
    assert overview["milli_credits"]["days_7"] == 1000
    assert overview["throughput"] == {
        "tokens_per_hour_1h": 1000,
        "tokens_per_hour_24h": 42,
        "tokens_last_24h": 1000,
    }
    assert overview["queue"] == {"depth": 0, "in_flight": 0}

    # The client's `request` command names no session, so nothing is aggregated
    # into one; the session numbers themselves are asserted above, where the
    # world that produces them is built.
    assert sessions["sessions"] == []

    assert len(consumers["consumers"]) == 1
    consumer = consumers["consumers"][0]
    assert consumer["subject_id"] == "consumer-X"
    assert consumer["requests"] == 1
    assert consumer["tokens"] == 1000
    assert consumer["milli_credits"] == 1000
    assert consumer["sessions"] == 0
    assert consumer["last_seen_at"] is not None

    assert len(nodes["nodes"]) == 1
    node = nodes["nodes"][0]
    assert node["node_id"] == "node-A"
    assert node["model"] == MODEL
    assert node["provider_id"] == "provider-A"
    assert node["connected"] is True
    assert node["share_enabled"] is True
    assert node["requests_served"] == 1
    assert node["tokens"] == 1000
    assert node["milli_credits"] == 1000
    assert node["last_seen_at"] is not None

    assert len(receipts["receipts"]) == 1
    row = receipts["receipts"][0]
    assert row["receipt_id"] == receipt.receipt_id
    assert row["request_id"] == "R-live-1"
    assert row["subject_id"] == "consumer-X"
    assert row["node_id"] == "node-A"
    assert row["tokens"] == 1000
    assert row["milli_credits"] == 1000
    assert row["status"] == "SUCCEEDED"
    assert row["log_index"] == receipt.log_index
