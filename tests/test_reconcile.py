"""Two-sided reconciliation: the three read-only commands, and the tampering they catch.

The bar is the release-readiness review's §3 acceptance line: after any one side
loses or edits a single record, a reconciliation command must name that record,
and on a clean chain all three commands must exit 0. So the end-to-end tests here
drive `aipotluck.cli.main` the way the installed console script does, against a
real center on a real loopback socket with a real connector and a fake upstream —
no mocked transport and no hand-built books, because a reconciliation tool tested
against fixtures proves only that it agrees with the fixtures.

Covered:

* the clean chain — `verify receipt` from the operator side *and* the consumer
  side, plus `share reconcile` and `admin reconcile`, all exit 0;
* a database that is not there — every command that opens one refuses and says
  so, instead of creating an empty database whose emptiness would read as "no
  differences";
* a settlement correction — the receipt a node is shown for a settled attempt is
  the latest revision, the same one the center side reconciles by;
* a receipt edited in ``center.db`` — `verify receipt` fails the signature and
  names the receipt, `admin reconcile` names it too;
* a receipt deleted from ``center.db`` — `verify receipt` reports the missing
  record, `admin reconcile` names the settlement, the leaf and the request that
  lost it;
* a transparency-log leaf dropped — `verify receipt` reports ``ledger_included``
  as ``fail``;
* a node's own ``executions`` row edited or deleted — `share reconcile` names the
  attempt;
* the center-side invariants and the node-side difference kinds in isolation, so
  a check that stops firing is caught by name instead of only by an end-to-end
  test going quietly green.

Authentication negative cases for the two new read-only endpoints live in
``test_gateway_server.py``, beside the role tests they extend.

Deliberately out of scope: automatic freezing, dispute opening, and arbitration.
This round only makes a difference visible (release-readiness review §3).
"""

from __future__ import annotations

import datetime as dt
import sqlite3
import threading
import time
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
from aipotluck.adapters import FakeResponse, FakeUpstream, FakeUpstreamAdapter
from aipotluck.canonical import canonicalize, loads_strict
from aipotluck.cli import main
from aipotluck.connector import Connector
from aipotluck.identity import IdentityRegistry
from aipotluck.metering import NormalizedUsage
from aipotluck.reconcile import Difference

from aipotluck_server.cli import main as server_main
from aipotluck_server.deploy import CenterInspection, load_center, load_center_for_inspection
from aipotluck_server.persistence import CenterStore, SettlementRecord
from aipotluck_server.reconcile import reconcile_center

MODEL = "coding-pool"
PROMPT = "write a haiku about reconciliation"
SETTLEMENT_KEY_ID = "settlement-key-1"
CONSUMER_INVITE = "consumer-invite-code-for-reconcile-tests"
NODE_INVITE = "node-invite-code-for-reconcile-tests"
#: Milli-credits minted into the consumer's own account at first join. Well
#: above one request's billable total so the chain never fails on budget.
QUOTA = 100_000


def _wait_until(condition: Any, *, timeout: float = 15.0, what: str) -> None:
    """Block until `condition()` is truthy, failing with a readable message."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {what}")


def _execute(database: Path, statement: str, *parameters: Any) -> None:
    """Run one statement against a database file, the way a one-sided edit would.

    A separate connection on purpose: the tampering these tests inject has to be
    visible to every other reader without anybody's in-memory book being told,
    which is exactly the situation a lost or edited record creates in production.
    """
    connection = sqlite3.connect(database)
    try:
        connection.execute(statement, parameters)
        connection.commit()
    finally:
        connection.close()


def _read_json(path: Path) -> dict[str, Any]:
    """Read a JSON object a CLI command wrote."""
    document = loads_strict(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


class Platform:
    """A whole platform on loopback, joined the way a real deployment joins.

    Built through the shipped commands rather than assembled from library calls:
    ``keygen`` writes the settlement key, ``load_center`` starts the gateway,
    ``join`` mints the consumer and node identities on the center and saves them
    locally, and ``ask`` produces the receipt every test then reconciles. What
    the tests tamper with afterwards is therefore the same set of files and rows
    an operator would have.
    """

    def __init__(self, tmp_path: Path) -> None:
        self.tmp_path = tmp_path
        self.center_dir = tmp_path / "center"
        self.consumer_dir = tmp_path / "consumer"
        self.node_dir = tmp_path / "node"
        for directory in (self.center_dir, self.consumer_dir, self.node_dir):
            directory.mkdir(mode=0o700, parents=True)
        self.center_json = self.center_dir / "center.json"
        self.center_db = self.center_dir / "center.db"
        self.node_json = self.node_dir / "node.json"
        self.node_db = self.node_dir / "node.db"
        self.deployment: Any = None
        self.upstream = FakeUpstream()
        self.connector: Connector | None = None
        self._thread: threading.Thread | None = None
        self._requests = 0

    # -- setup ------------------------------------------------------------

    @property
    def center_url(self) -> str:
        """The center's bound HTTP URL."""
        return str(self.deployment.server.url)

    @property
    def store(self) -> CenterStore:
        """The center's store, held open by the running gateway."""
        return self.deployment.store

    def start(self) -> None:
        """Bring the whole platform up and join both parties."""
        self._write_center_config()
        self.deployment = load_center(self.center_json, start=True)
        now = dt.datetime.now(dt.UTC)
        self.store.add_invite(
            CONSUMER_INVITE, "consumer", "friends",
            max_uses=1, created_at=now, quota_milli_credits=QUOTA,
        )
        self.store.add_invite(
            NODE_INVITE, "node", "friends",
            max_uses=1, created_at=now, quota_milli_credits=0,
        )
        assert main([
            "join", "--center", self.center_url, "--invite", CONSUMER_INVITE,
            "--config-dir", str(self.consumer_dir),
        ]) == 0
        assert main([
            "join", "--node", "--center", self.center_url, "--invite", NODE_INVITE,
            "--config-dir", str(self.node_dir), "--no-setup",
        ]) == 0
        self._write_node_config()
        self._start_node()

    def stop(self) -> None:
        """Stop the connector and the gateway, and close the store."""
        if self.connector is not None:
            self.connector.stop()
        if self._thread is not None:
            self._thread.join(timeout=10)
        if self.deployment is not None:
            self.deployment.server.stop()
            self.deployment.store.close()

    def _write_center_config(self) -> None:
        """Write a minimal ``center.json`` over a freshly generated settlement key."""
        key_path = self.center_dir / "settlement.key"
        assert main(["keygen", "--out", str(key_path)]) == 0
        document = {
            "host": "127.0.0.1",
            "port": 0,
            "database_path": str(self.center_db),
            "platform_id": "platform-reconcile-test",
            "settlement_key_id": SETTLEMENT_KEY_ID,
            "settlement_private_key_b64": key_path.read_text(encoding="utf-8").strip(),
            "certfile": None,
            "keyfile": None,
            "credentials": [],
            "providers": [],
            "consumer_floats": [],
        }
        # The settlement private key is written by `keygen` at 0600 and this file
        # carries it, so the configuration gets the same mode: a test fixture is
        # still a file on disk holding key material.
        self.center_json.write_text(canonicalize(document).decode("utf-8"), encoding="utf-8")
        self.center_json.chmod(0o600)

    def _write_node_config(self) -> None:
        """Write ``node.json`` from what ``join --node`` saved, with a fake upstream.

        The contributor wizard normally writes this file, and it needs a real
        HTTP upstream to self-check against. The identity half is copied verbatim
        from what `join` saved — device id, device key id, provider id, device
        private key and the one-time node token — so the node that connects is
        the node the center provisioned; only the adapter block differs, and a
        ``fake`` adapter carries no credential at all.
        """
        identity = _read_json(self.node_dir / "config.json")
        keys = _read_json(self.node_dir / "key.json")
        token = _read_json(self.node_dir / "node_token.json")
        parts = self.center_url.split("://", 1)[1]
        document = {
            "center_url": f"ws://{parts}/v1/node-link",
            "node_id": identity["device_id"],
            "device_id": identity["device_id"],
            "device_key_id": identity["device_key_id"],
            "provider_id": identity["provider_id"],
            "database_path": str(self.node_db),
            "token": token["node_token"],
            "device_private_key_b64": keys["device_private_key_b64"],
            "adapter": {
                "kind": "fake",
                "endpoint": None,
                "api_key": None,
                "model": MODEL,
                "provider_style": "openai",
                "name": "fake-adapter",
            },
            "share_enabled": True,
            "max_concurrency": 1,
            "max_local_reserved_milli_credits": 20_000,
        }
        self.node_json.write_text(canonicalize(document).decode("utf-8"), encoding="utf-8")
        self.node_json.chmod(0o600)

    def _start_node(self) -> None:
        """Connect the contributor's node over the real WebSocket link."""
        from aipotluck.deploy import load_node

        node_config, _ = load_node(self.node_json)
        adapter = FakeUpstreamAdapter(upstream=self.upstream, model=MODEL)
        self.connector = Connector(node_config, adapter=adapter)
        self._thread = threading.Thread(target=self.connector.run_forever, daemon=True)
        self._thread.start()
        _wait_until(lambda: bool(self.store.connected_nodes()), what="the node to register")

    # -- driving ----------------------------------------------------------

    def settle_one_request(self) -> str:
        """Ask one question, wait for it to settle, and return its receipt id."""
        self.upstream.queue(
            FakeResponse(
                text_chunks=("reconcile ", "everything"),
                usage=NormalizedUsage(input_total=800, output_total=200),
            )
        )
        before = len(self.store.receipts())
        self._requests += 1
        assert main([
            "ask", PROMPT, "--config-dir", str(self.consumer_dir), "--model", MODEL,
        ]) == 0, "the consumer's request must succeed for there to be anything to reconcile"
        _wait_until(
            lambda: len(self.store.receipts()) > before, what="the request to settle"
        )
        return self.store.receipts()[-1].receipt_id

    def consumer_documents(self, receipt_id: str) -> dict[str, dict[str, Any]]:
        """Fetch the three documents the consumer side of `verify receipt` reads.

        Fetched through the shipped `SignedClient`, so the ``AIPotluck-Sig`` path
        and the new endpoints are exercised as a consumer really reaches them.
        """
        from aipotluck.cli import load_joined_identity, signed_client_for

        config_document, key_document = load_joined_identity(self.consumer_dir)
        client = signed_client_for(config_document, key_document)
        return {
            "receipt": client.get(f"/v1/receipts/{receipt_id}"),
            "checkpoint": client.get("/v1/checkpoint"),
            "history": client.get("/v1/account/history"),
        }


@pytest.fixture
def platform(tmp_path: Path) -> Iterator[Platform]:
    """A running platform, torn down at the end of the test."""
    built = Platform(tmp_path)
    built.start()
    try:
        yield built
    finally:
        built.stop()


@pytest.fixture
def settled(platform: Platform) -> Platform:
    """A running platform with exactly one settled request behind it."""
    platform.settle_one_request()
    return platform


def _kinds(differences: Sequence[Difference]) -> list[str]:
    """The difference kinds, for asserting which check fired."""
    return [item.kind for item in differences]


def _subjects(differences: Sequence[Difference]) -> list[str]:
    """The records the differences name."""
    return [item.subject for item in differences]


# ---------------------------------------------------------------------------
# (d) the clean chain: all three commands exit 0
# ---------------------------------------------------------------------------


def test_the_clean_chain_exits_zero_from_the_operator_side(settled: Platform) -> None:
    """§3 acceptance: a clean center and a clean node reconcile without a difference.

    Driven through `main` rather than the reconcile library, because the
    acceptance criterion is about exit codes a person sees.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id

    assert server_main([
        "verify", "receipt", "--config", str(settled.center_json),
        "--receipt-id", receipt_id,
    ]) == 0
    assert server_main(["admin", "reconcile", "--config", str(settled.center_json)]) == 0
    assert main(["share", "reconcile", "--config", str(settled.node_json)]) == 0


def test_the_clean_chain_reports_all_five_dimensions_passing_from_the_store(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """The operator holds every record, so all five dimensions are assessable.

    This is the strongest form of the check: the settlement key, the consumer's
    authorization, the device's signed usage report, the journal and the log leaf
    are all in one database, so nothing has to degrade to ``unknown``.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id
    assert server_main([
        "verify", "receipt", "--config", str(settled.center_json),
        "--receipt-id", receipt_id,
    ]) == 0
    out = capsys.readouterr().out
    for dimension in (
        "signature_valid", "metering_provenance", "allocation_valid",
        "ledger_included", "account_history_complete",
    ):
        assert f"{dimension}" in out
    assert out.count(": pass") == 5, out
    assert "all_pass (summary)        : true" in out
    # The provenance caveat must survive a fully passing report: a signature
    # proves who reported the numbers, not that the upstream consumed them.
    assert "not that the upstream consumed them" in out


def test_the_clean_chain_exits_zero_from_the_consumer_side(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """A consumer's own identity verifies its receipt over HTTP, and exits 0.

    `metering_provenance` is ``unknown`` here and must stay that way: a consumer
    holds no signed usage report, and substituting the receipt's declared level
    would be the false comfort the five separate dimensions exist to prevent.
    ``unknown`` is not a contradiction, so the command still exits 0.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id
    assert main([
        "verify", "receipt", "--config-dir", str(settled.consumer_dir),
        "--receipt-id", receipt_id,
    ]) == 0
    out = capsys.readouterr().out
    assert "signature_valid           : pass" in out
    assert "allocation_valid          : pass" in out
    assert "ledger_included           : pass" in out
    assert "account_history_complete  : pass" in out
    assert "metering_provenance       : unknown" in out
    assert "all_pass (summary)        : false" in out
    assert "no usage reports held" in out


def test_verify_receipt_json_mode_reports_the_same_verdicts(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--json`` is the same verification, machine-readable and canonical."""
    receipt_id = settled.store.receipts()[-1].receipt_id
    assert server_main([
        "verify", "receipt", "--config", str(settled.center_json),
        "--receipt-id", receipt_id, "--json",
    ]) == 0
    document = loads_strict(capsys.readouterr().out.strip().encode("utf-8"))
    assert isinstance(document, dict)
    assert document["receipt_id"] == receipt_id
    assert document["source"] == "center-store"
    assert document["failed"] is False
    assert document["all_pass"] is True
    verdicts = document["verdicts"]
    assert isinstance(verdicts, dict)
    assert set(verdicts) == {
        "signature_valid", "metering_provenance", "allocation_valid",
        "ledger_included", "account_history_complete",
    }
    assert set(verdicts.values()) == {"pass"}


def test_share_reconcile_json_mode_lists_no_difference_on_a_clean_node(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """The node side reports one local execution and one matching center attempt."""
    assert main(["share", "reconcile", "--config", str(settled.node_json), "--json"]) == 0
    document = loads_strict(capsys.readouterr().out.strip().encode("utf-8"))
    assert isinstance(document, dict)
    assert document["executions"] == 1
    assert document["remote_attempts"] == 1
    assert document["differences"] == []


def test_the_three_commands_leave_both_databases_untouched(settled: Platform) -> None:
    """Read-only is a property of the commands, not of their documentation.

    §3 asks for reconciliation that only *shows* a difference: no freeze, no
    dispute, no row. Every table of both databases is digested before and after
    all four invocations — the operator's and the consumer's `verify receipt`,
    `admin reconcile` and `share reconcile` — so a command that journaled an
    event, stamped a row or funded an account while auditing would fail here
    rather than in production, where the audit trail it silently changed is the
    thing somebody is trying to trust.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id
    center_before = _database_digest(settled.center_db)
    node_before = _database_digest(settled.node_db)

    assert server_main([
        "verify", "receipt", "--config", str(settled.center_json),
        "--receipt-id", receipt_id,
    ]) == 0
    assert main([
        "verify", "receipt", "--config-dir", str(settled.consumer_dir),
        "--receipt-id", receipt_id,
    ]) == 0
    assert server_main(["admin", "reconcile", "--config", str(settled.center_json)]) == 0
    assert main(["share", "reconcile", "--config", str(settled.node_json)]) == 0

    assert _database_digest(settled.center_db) == center_before
    assert _database_digest(settled.node_db) == node_before


# ---------------------------------------------------------------------------
# (b) a database that is not there is refused, never created
# ---------------------------------------------------------------------------


def test_a_center_database_that_was_lost_is_reported_and_not_rebuilt(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """The one loss an audit must never wash clean: the whole center database gone.

    ``sqlite3`` creates the file it is pointed at, so both operator commands used
    to open an empty database when ``database_path`` named nothing. An empty
    database holds no rows, so it holds no discrepancies either: `admin reconcile`
    printed that both sides agree and exited 0 over a center with nothing left,
    and `verify receipt --config` reported a receipt as missing from the receipt
    table when in fact the whole store was. "The database is gone" and "the
    database is empty and clean" have to be different answers.

    The file is moved aside rather than deleted because the running gateway still
    holds it open; from a reconciling command's side the two are the same fact —
    the configured path names nothing.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id
    moved_aside = settled.center_db.parent / "center.db.moved-aside"
    settled.center_db.rename(moved_aside)
    try:
        assert server_main(["admin", "reconcile", "--config", str(settled.center_json)]) == 1
        assert server_main([
            "verify", "receipt", "--config", str(settled.center_json),
            "--receipt-id", receipt_id,
        ]) == 1

        error = capsys.readouterr().err
        assert error.count("does not exist") == 2, error
        assert str(settled.center_db) in error
        assert "potluck serve" in error, "the message must say what to do next"
        assert not settled.center_db.exists(), "a lost database must not be rebuilt"
    finally:
        if not settled.center_db.exists():
            moved_aside.rename(settled.center_db)


# ---------------------------------------------------------------------------
# (a) a receipt deleted or edited: `verify receipt` and `admin reconcile` each name it
# ---------------------------------------------------------------------------


def test_an_edited_receipt_is_named_by_verify_receipt_and_by_admin_reconcile(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """One edited byte in a receipt body is a named failure on both commands.

    The edit rewrites ``billable_tokens`` inside the stored JSON, which is inside
    the signed payload — so the receipt's own hash changes and its signature no
    longer covers it. Both commands must name *this* receipt rather than report
    a general unease.
    """
    stored = settled.store.receipts()[-1]
    receipt_id = stored.receipt_id
    document = loads_strict(stored.receipt_json.encode("utf-8"))
    assert isinstance(document, dict)
    payload = document["payload"]
    assert isinstance(payload, dict)
    payload["billable_tokens"] = str(int(str(payload["billable_tokens"])) + 999)
    _execute(
        settled.center_db,
        "UPDATE receipts SET receipt_json = ? WHERE receipt_id = ?",
        canonicalize(document).decode("utf-8"),
        receipt_id,
    )

    assert server_main([
        "verify", "receipt", "--config", str(settled.center_json),
        "--receipt-id", receipt_id,
    ]) == 1
    out = capsys.readouterr().out
    assert "signature_valid           : fail" in out
    assert receipt_id in out
    assert "was edited" in out

    assert server_main(["admin", "reconcile", "--config", str(settled.center_json)]) == 1
    out = capsys.readouterr().out
    assert f"receipt {receipt_id}" in out
    assert "receipt_hash_mismatch" in out


def test_a_deleted_receipt_is_named_by_verify_receipt_and_by_admin_reconcile(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """A receipt row that vanishes is reported, not silently verified as clean.

    Three other tables still point at it — the settlement revision, the log leaf
    and the request's success — so `admin reconcile` names the record from each
    direction, which is what tells an operator the receipt is what is missing
    rather than the settlement.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id
    _execute(settled.center_db, "DELETE FROM receipts WHERE receipt_id = ?", receipt_id)

    assert server_main([
        "verify", "receipt", "--config", str(settled.center_json),
        "--receipt-id", receipt_id,
    ]) == 1
    out = capsys.readouterr().out
    assert receipt_id in out
    assert "not in the center's receipts table" in out

    assert server_main(["admin", "reconcile", "--config", str(settled.center_json)]) == 1
    out = capsys.readouterr().out
    assert receipt_id in out
    assert "settlement_without_receipt" in out
    assert "log_leaf_without_receipt" in out
    assert "succeeded_request_without_receipt" in out


# ---------------------------------------------------------------------------
# (b) a dropped log leaf: `verify receipt` reports ledger_included as fail
# ---------------------------------------------------------------------------


def test_a_dropped_log_leaf_fails_ledger_included(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """Losing the leaf loses the proof of presence, and says so by dimension.

    The receipt, its settlement and its journal all survive; only the
    transparency-log leaf is gone. That is the exact case `ledger_included`
    exists for — the charge is on the books but nothing publishes it — so the
    verdict must be ``fail`` and not ``unknown``.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id
    _execute(settled.center_db, "DELETE FROM log_leaves WHERE log_index = 0")

    assert server_main([
        "verify", "receipt", "--config", str(settled.center_json),
        "--receipt-id", receipt_id,
    ]) == 1
    out = capsys.readouterr().out
    assert "ledger_included           : fail" in out
    assert receipt_id in out
    assert "no inclusion proof" in out

    # The center-side cross-check sees the same loss from the other direction.
    assert server_main(["admin", "reconcile", "--config", str(settled.center_json)]) == 1
    out = capsys.readouterr().out
    assert "receipt_without_log_leaf" in out


def test_a_leaf_moved_to_another_index_fails_ledger_included(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """Re-indexing a leaf breaks the receipt's claim to its own position.

    A rewrite that keeps the log the same length is the harder case: nothing is
    missing, so a count-based check would pass. The receipt still names index 0,
    and the leaf now sitting there is a different commitment.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id
    _execute(settled.center_db, "UPDATE log_leaves SET log_index = 7 WHERE log_index = 0")

    assert server_main([
        "verify", "receipt", "--config", str(settled.center_json),
        "--receipt-id", receipt_id,
    ]) == 1
    out = capsys.readouterr().out
    assert "ledger_included           : fail" in out
    assert receipt_id in out

    assert server_main(["admin", "reconcile", "--config", str(settled.center_json)]) == 1
    out = capsys.readouterr().out
    assert "log_gap" in out
    assert "receipt_log_index_mismatch" in out
    assert receipt_id in out


# ---------------------------------------------------------------------------
# (c) a node's own record edited: `share reconcile` names the attempt
# ---------------------------------------------------------------------------


def test_an_edited_node_execution_is_named_by_share_reconcile(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """A contributor's edited local row is named by attempt, with both sides shown.

    The state is flipped from ``SUBMITTED`` to ``FAILED``: the node's own record
    then says the attempt failed while the center says it completed and settled,
    which is the disagreement a contributor needs to see before arguing about a
    payment.
    """
    attempt_id = _only_attempt_id(settled)
    _execute(
        settled.node_db, "UPDATE executions SET state = 'FAILED' WHERE attempt_id = ?",
        attempt_id,
    )

    assert main(["share", "reconcile", "--config", str(settled.node_json)]) == 1
    out = capsys.readouterr().out
    assert attempt_id in out
    assert "settled_after_local_failure" in out
    assert "state=FAILED" in out
    assert "status=COMPLETED" in out


def test_a_deleted_node_execution_is_named_by_share_reconcile(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """A node that lost its own record of an attempt is told which attempt.

    The other direction from the edit above: the center still has the attempt and
    settled it, and this machine has no row for it at all.
    """
    attempt_id = _only_attempt_id(settled)
    _execute(settled.node_db, "DELETE FROM executions WHERE attempt_id = ?", attempt_id)

    assert main(["share", "reconcile", "--config", str(settled.node_json)]) == 1
    out = capsys.readouterr().out
    assert attempt_id in out
    assert "missing_locally" in out


def test_an_edited_upstream_call_count_is_named_by_share_reconcile(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """A local claim of two upstream calls is reported even though the center cannot see it.

    `begin_execution` exists so a reconnect cannot issue a second upstream call,
    so a count above one means either that guarantee broke or the row was edited.
    Either way the contributor paid an upstream twice for one billed attempt, and
    only this node's own record can say so.
    """
    attempt_id = _only_attempt_id(settled)
    _execute(
        settled.node_db, "UPDATE executions SET upstream_calls = 2 WHERE attempt_id = ?",
        attempt_id,
    )

    assert main(["share", "reconcile", "--config", str(settled.node_json)]) == 1
    out = capsys.readouterr().out
    assert attempt_id in out
    assert "repeated_upstream_call" in out


def test_a_node_record_claiming_zero_upstream_calls_is_named(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """A center that bills for a call this node never made is a named difference."""
    attempt_id = _only_attempt_id(settled)
    _execute(
        settled.node_db, "UPDATE executions SET upstream_calls = 0 WHERE attempt_id = ?",
        attempt_id,
    )

    assert main(["share", "reconcile", "--config", str(settled.node_json)]) == 1
    out = capsys.readouterr().out
    assert attempt_id in out
    assert "usage_without_upstream_call" in out


def test_share_reconcile_never_prints_the_node_token(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """A difference table goes into a terminal and a ticket, so it carries no credential.

    The node token is in ``node.json`` and in the request header; neither the
    clean report nor a report full of differences may render it.
    """
    token = str(_read_json(settled.node_dir / "node_token.json")["node_token"])
    attempt_id = _only_attempt_id(settled)
    _execute(
        settled.node_db, "UPDATE executions SET state = 'FAILED' WHERE attempt_id = ?",
        attempt_id,
    )

    assert main(["share", "reconcile", "--config", str(settled.node_json)]) == 1
    captured = capsys.readouterr()
    assert token not in captured.out
    assert token not in captured.err


def _only_attempt_id(platform: Platform) -> str:
    """Return the single attempt the center dispatched to this node."""
    attempts = platform.store.attempts()
    assert len(attempts) == 1, "the harness settles exactly one request"
    return attempts[0].attempt_id


# ---------------------------------------------------------------------------
# The consumer side sees a center-side loss too
# ---------------------------------------------------------------------------


def test_a_consumer_reading_a_receipt_the_center_lost_is_told(
    settled: Platform, capsys: pytest.CaptureFixture[str]
) -> None:
    """The HTTP path reports a missing receipt as a failure, not an empty verdict.

    The gateway answers 404-ish domain error for an unknown receipt, which `main`
    renders and exits 1 on. What matters is that the receipt id is named: a
    consumer who paid must be able to point at the charge that disappeared.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id
    _execute(settled.center_db, "DELETE FROM receipts WHERE receipt_id = ?", receipt_id)

    assert main([
        "verify", "receipt", "--config-dir", str(settled.consumer_dir),
        "--receipt-id", receipt_id,
    ]) == 1
    err = capsys.readouterr().err
    assert receipt_id in err


def test_a_consumer_reading_a_receipt_somebody_edited_is_told(
    settled: Platform,
) -> None:
    """The consumer side of an edited receipt fails the signature and names it.

    The operator-side twin of this check reads the same row out of the database;
    this one reads what the center *serves* over HTTP, which is the copy a
    consumer can actually hold anybody to. The edit is inside the signed payload,
    so the receipt the center hands over no longer hashes to the commitment its
    own signature covers — the one thing a consumer can check without trusting
    the center's arithmetic.
    """
    from aipotluck.reconcile import verify_receipt_from_center

    stored = settled.store.receipts()[-1]
    document = loads_strict(stored.receipt_json.encode("utf-8"))
    assert isinstance(document, dict)
    payload = document["payload"]
    assert isinstance(payload, dict)
    payload["billable_tokens"] = str(int(str(payload["billable_tokens"])) + 999)
    _execute(
        settled.center_db,
        "UPDATE receipts SET receipt_json = ? WHERE receipt_id = ?",
        canonicalize(document).decode("utf-8"),
        stored.receipt_id,
    )

    documents = settled.consumer_documents(stored.receipt_id)
    verification = verify_receipt_from_center(
        receipt_document=documents["receipt"],
        checkpoint_document=documents["checkpoint"],
        history_document=documents["history"],
    )
    assert verification.verdicts()["signature_valid"] == "fail"
    assert verification.failed
    assert any(stored.receipt_id in finding for finding in verification.findings)


def test_a_consumer_history_that_omits_the_receipt_is_a_named_finding(
    settled: Platform,
) -> None:
    """A receipt served but absent from the account's own history contradicts itself.

    This is the check `account_history_complete` exists for on the consumer side:
    the center can serve a receipt for a charge its books never recorded against
    this account, and the two answers disagree.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id
    documents = settled.consumer_documents(receipt_id)
    documents["history"]["receipt_ids"] = []

    from aipotluck.reconcile import verify_receipt_from_center

    verification = verify_receipt_from_center(
        receipt_document=documents["receipt"],
        checkpoint_document=documents["checkpoint"],
        history_document=documents["history"],
    )
    assert verification.failed
    assert any("does not appear in account" in finding for finding in verification.findings)


def test_a_consumer_history_truncated_against_its_own_count_fails(
    settled: Platform,
) -> None:
    """An entry list shorter than the count the same response carried is a gap."""
    from aipotluck.reconcile import verify_receipt_from_center

    receipt_id = settled.store.receipts()[-1].receipt_id
    documents = settled.consumer_documents(receipt_id)
    documents["history"]["entry_count"] = int(documents["history"]["entry_count"]) + 1

    verification = verify_receipt_from_center(
        receipt_document=documents["receipt"],
        checkpoint_document=documents["checkpoint"],
        history_document=documents["history"],
    )
    assert verification.verdicts()["account_history_complete"] == "fail"
    assert verification.failed


def test_a_consumer_served_a_contract_that_is_not_the_promised_one_fails(
    settled: Platform,
) -> None:
    """A served allocation contract must hash to the digest bound into the receipt.

    Without this the center could hand a verifier weights that justify any split
    at all, and `allocation_valid` would pass on the strength of its own answer.
    """
    from aipotluck.reconcile import verify_receipt_from_center

    receipt_id = settled.store.receipts()[-1].receipt_id
    documents = settled.consumer_documents(receipt_id)
    contract = documents["receipt"]["allocation_contract"]
    assert isinstance(contract, dict)
    contract["weights"] = {"someone-else": 100}

    verification = verify_receipt_from_center(
        receipt_document=documents["receipt"],
        checkpoint_document=documents["checkpoint"],
        history_document=documents["history"],
    )
    assert verification.failed
    assert any("not the promised one" in finding for finding in verification.findings)


def test_a_consumer_verdict_without_a_checkpoint_key_does_not_pass_blindly(
    settled: Platform,
) -> None:
    """No published settlement key means no signature check and no trusted root.

    Both dimensions degrade rather than pass: `signature_valid` fails because the
    registry holds no key to check against, and `ledger_included` cannot reach
    ``pass`` without an authenticated root. Silently passing either would be the
    failure mode the whole module exists to avoid.
    """
    from aipotluck.reconcile import verify_receipt_from_center

    receipt_id = settled.store.receipts()[-1].receipt_id
    documents = settled.consumer_documents(receipt_id)
    del documents["checkpoint"]["public_key_b64"]

    verification = verify_receipt_from_center(
        receipt_document=documents["receipt"],
        checkpoint_document=documents["checkpoint"],
        history_document=documents["history"],
    )
    verdicts = verification.verdicts()
    assert verdicts["signature_valid"] == "fail"
    assert verdicts["ledger_included"] != "pass"
    assert verification.failed


# ---------------------------------------------------------------------------
# The center-side invariants, one at a time
# ---------------------------------------------------------------------------


def _inspection(platform: Platform) -> CenterInspection:
    """Open the platform's center for reading, the way the CLI does."""
    return load_center_for_inspection(platform.center_json)


def test_admin_reconcile_reports_an_orphan_receipt(settled: Platform) -> None:
    """A receipt no settlement names points at a mint outside the settlement path."""
    stored = settled.store.receipts()[-1]
    _execute(
        settled.center_db,
        "DELETE FROM settlements WHERE receipt_id = ?", stored.receipt_id,
    )
    differences = _center_differences(settled)
    assert "orphan_receipt" in _kinds(differences)
    assert f"receipt {stored.receipt_id}" in _subjects(differences)


def test_admin_reconcile_reports_a_settled_attempt_with_no_settlement(
    settled: Platform,
) -> None:
    """The attempt says it was billed; the settlements table has nothing to show."""
    attempt_id = _only_attempt_id(settled)
    _execute(settled.center_db, "DELETE FROM settlements")
    differences = _center_differences(settled)
    kinds = _kinds(differences)
    assert "settled_attempt_without_settlement" in kinds
    assert f"attempt {attempt_id}" in _subjects(differences)
    # The same loss seen from the request that was marked succeeded.
    assert "succeeded_request_without_settlement" in kinds


def test_admin_reconcile_reports_a_receipt_whose_journal_disagrees_on_amount(
    settled: Platform,
) -> None:
    """Three tables carry the amount; editing one is a named disagreement.

    The billable total in the receipt, the usage the winner attempt recorded and
    the sum the ledger journal posted all have to be the same number. Editing the
    attempt row alone leaves the receipt and the journal agreeing with each other
    and contradicting it, which is exactly the shape a quiet rewrite takes.
    """
    receipt_id = settled.store.receipts()[-1].receipt_id
    attempt_id = _only_attempt_id(settled)
    _execute(
        settled.center_db,
        "UPDATE attempts SET usage_tokens = usage_tokens + 500 WHERE attempt_id = ?",
        attempt_id,
    )
    differences = _center_differences(settled)
    assert "receipt_usage_amount_mismatch" in _kinds(differences)
    assert f"receipt {receipt_id}" in _subjects(differences)


def test_admin_reconcile_reports_an_unbalanced_journal(settled: Platform) -> None:
    """A journal that does not sum to zero is money created or destroyed."""
    stored = settled.store.receipts()[-1]
    document = loads_strict(stored.receipt_json.encode("utf-8"))
    assert isinstance(document, dict)
    journal_id = document["payload"]["journal_id"]
    _execute(
        settled.center_db,
        "UPDATE ledger_events SET payload_json = ? WHERE kind = 'journal'",
        _unbalanced_journal(settled, str(journal_id)),
    )
    differences = _center_differences(settled)
    assert "unbalanced_journal" in _kinds(differences)


def _unbalanced_journal(platform: Platform, journal_id: str) -> str:
    """Return the stored journal payload with one posting's amount changed."""
    for _seq, kind, payload in platform.store.ledger_events():
        if kind == "journal" and payload.get("journal_id") == journal_id:
            postings = payload["postings"]
            assert isinstance(postings, list) and postings
            first = postings[0]
            assert isinstance(first, list)
            postings[0] = [first[0], int(first[1]) + 1]
            return canonicalize(payload).decode("utf-8")
    raise AssertionError(f"no stored journal {journal_id}")


def test_admin_reconcile_reports_a_receipt_with_no_winner_attempt(
    settled: Platform,
) -> None:
    """A receipt pointing at an attempt the table lost cannot be checked at all."""
    attempt_id = _only_attempt_id(settled)
    _execute(settled.center_db, "DELETE FROM attempts WHERE attempt_id = ?", attempt_id)
    differences = _center_differences(settled)
    assert "receipt_without_winner_attempt" in _kinds(differences)


def test_admin_reconcile_reports_a_duplicate_receipt_hash(settled: Platform) -> None:
    """Two receipt rows under one hash mean one commitment was logged twice."""
    stored = settled.store.receipts()[-1]
    _execute(
        settled.center_db,
        "INSERT INTO receipts (receipt_id, request_id, receipt_hash, log_index,"
        " receipt_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        f"{stored.receipt_id}-copy",
        stored.request_id,
        stored.receipt_hash,
        stored.log_index,
        stored.receipt_json,
        stored.created_at.isoformat(),
    )
    differences = _center_differences(settled)
    assert "duplicate_receipt_hash" in _kinds(differences)


def _center_differences(platform: Platform) -> list[Difference]:
    """Run the center-side cross-check against the platform's database."""
    store = CenterStore.open(platform.center_db)
    try:
        return reconcile_center(store=store)
    finally:
        store.close()


def test_a_clean_center_has_no_differences(settled: Platform) -> None:
    """The invariant list is empty on an untouched chain, so it can gate on emptiness."""
    assert _center_differences(settled) == []
    inspection = _inspection(settled)
    try:
        assert reconcile_center(store=inspection.store) == []
    finally:
        inspection.close()


def test_inspection_writes_nothing(settled: Platform) -> None:
    """Opening a center for inspection must not change a byte of its books.

    `load_center` funds floats and provisions credentials; the inspection handle
    deliberately does neither, because an audit command that altered what it
    audited would be unusable on a live center.
    """
    before = _database_digest(settled.center_db)
    inspection = _inspection(settled)
    try:
        reconcile_center(store=inspection.store)
    finally:
        inspection.close()
    assert _database_digest(settled.center_db) == before


def _database_digest(database: Path) -> str:
    """Return a digest over every row of every table, for a before/after comparison."""
    from aipotluck.canonical import canonical_digest

    connection = sqlite3.connect(database)
    try:
        names = [
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        ]
        dump: dict[str, list[list[Any]]] = {}
        for name in names:
            rows = connection.execute(f"SELECT * FROM {name} ORDER BY 1").fetchall()
            dump[name] = [[_cell(value) for value in row] for row in rows]
    finally:
        connection.close()
    return canonical_digest(dump)


def _cell(value: Any) -> Any:
    """Coerce one SQLite cell to a canonicalizable value."""
    if isinstance(value, bytes):
        return value.hex()
    return value


# ---------------------------------------------------------------------------
# The two sides agree about the same clean chain
# ---------------------------------------------------------------------------


def test_the_registry_learned_from_a_center_can_verify_its_own_receipt(
    settled: Platform,
) -> None:
    """An inspection registry is the same trust set a running center uses.

    Pinned because the whole operator-side verification rests on it: if the
    replay dropped the joined consumer's key or the device binding, `signature_valid`
    would fail on a clean chain and the command would be useless.
    """
    from aipotluck_server.reconcile import verify_receipt_at_center

    receipt_id = settled.store.receipts()[-1].receipt_id
    inspection = _inspection(settled)
    try:
        verification = verify_receipt_at_center(
            store=inspection.store, registry=inspection.registry, receipt_id=receipt_id
        )
    finally:
        inspection.close()
    assert verification.findings == ()
    assert set(verification.verdicts().values()) == {"pass"}
    assert not verification.failed


def test_a_receipt_id_nobody_ever_issued_is_reported(settled: Platform) -> None:
    """An unknown id is a finding, not an exception: the answer is still about a record."""
    from aipotluck_server.reconcile import verify_receipt_at_center

    inspection = _inspection(settled)
    try:
        verification = verify_receipt_at_center(
            store=inspection.store,
            registry=inspection.registry,
            receipt_id="R-never-issued",
        )
    finally:
        inspection.close()
    assert verification.failed
    assert "R-never-issued" in verification.findings[0]


def test_an_empty_registry_cannot_verify_a_receipt(settled: Platform) -> None:
    """A verifier holding no trusted keys fails the signature dimension.

    Fail closed: without the settlement key there is nothing to check the
    receipt against, and passing would mean trusting the center's own claim.
    """
    from aipotluck_server.reconcile import verify_receipt_at_center

    receipt_id = settled.store.receipts()[-1].receipt_id
    store = CenterStore.open(settled.center_db)
    try:
        verification = verify_receipt_at_center(
            store=store, registry=IdentityRegistry(), receipt_id=receipt_id
        )
    finally:
        store.close()
    assert verification.verdicts()["signature_valid"] == "fail"


def test_two_settled_requests_reconcile_together(settled: Platform) -> None:
    """A second request must not disturb the first one's clean verdict.

    Two leaves, two receipts, two journals: the log positions, the receipt hash
    chain and each account's history all have to stay consistent, which is the
    case a single-request chain cannot reach.
    """
    settled.settle_one_request()
    receipts = settled.store.receipts()
    assert len(receipts) == 2
    assert _center_differences(settled) == []
    for stored in receipts:
        assert server_main([
            "verify", "receipt", "--config", str(settled.center_json),
            "--receipt-id", stored.receipt_id,
        ]) == 0
    assert main(["share", "reconcile", "--config", str(settled.node_json)]) == 0


# ---------------------------------------------------------------------------
# The receipt a node is shown is the revision the center itself reads
# ---------------------------------------------------------------------------


def test_a_node_view_names_the_latest_settlement_revision(settled: Platform) -> None:
    """A settlement correction is what the contributor sees, not the revision it replaced.

    `reconcile_center` reads a settlement by its highest revision, because a
    revision is immutable and a later one supersedes the earlier. The node
    endpoint reads the same rows for the same question — which receipt did this
    attempt settle into — so it has to apply the same rule, or one reconciliation
    would compare the node against revision 2 while naming revision 1's receipt to
    the node itself.
    """
    stored = settled.store.receipts()[-1]
    request_id = stored.request_id
    first = settled.store.latest_settlement(request_id)
    assert first is not None and first.revision == 1
    settled.store.record_settlement(
        SettlementRecord(
            service_unit_id=request_id,
            revision=2,
            fingerprint="fingerprint-of-the-correction",
            receipt_id=f"{stored.receipt_id}-corrected",
            receipt_hash=first.receipt_hash,
            log_index=first.log_index,
            receipt_json=first.receipt_json,
            created_at=dt.datetime.now(dt.UTC),
        )
    )

    # The node's own link credential, resolved the way the transport resolves it.
    token = _read_json(settled.node_json)["token"]
    credential = settled.store.resolve_credential(str(token), dt.datetime.now(dt.UTC))
    assert credential is not None
    attempts = settled.deployment.service.node_attempts(credential=credential)["attempts"]
    settled_views = [view for view in attempts if view["receipt"] is not None]

    assert len(settled_views) == 1, attempts
    receipt = settled_views[0]["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["receipt_id"] == f"{stored.receipt_id}-corrected"
