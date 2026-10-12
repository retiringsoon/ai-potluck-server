"""Tests for the durable center store.

The node store's own half of this suite lives in the ``ai-potluck``
repository, beside ``NodeStore``.

These tests are written to fail if the behaviour they pin is removed: the
idempotency rules assert concrete before/after values, the commit and
create-request races run two real threads against one store, and the restart
test closes and reopens from the same file rather than reading back a value that
was never written out.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from aipotluck.canonical import canonical_digest
from aipotluck.errors import ConflictError, PotluckError, StateTransitionError
from aipotluck.persistence import NodeStore, ReceiptRecord

from aipotluck_server.persistence import (
    AttemptRecord,
    CenterStore,
    LogLeafRecord,
    NodeRecord,
    OutboxRecord,
    RequestRecord,
    SettlementRecord,
)
from aipotluck_server.reconcile import reconcile_center

T0 = dt.datetime(2026, 10, 6, 12, 0, 0, tzinfo=dt.UTC)
T1 = T0 + dt.timedelta(seconds=1)
T2 = T0 + dt.timedelta(seconds=2)

#: The model a stored dispatch input names; the store keeps it as given.
MODEL = "coding-pool"


@pytest.fixture
def center(tmp_path: Path) -> Iterator[CenterStore]:
    """A center store on a fresh file, closed at the end of the test."""
    store = CenterStore.open(tmp_path / "center.db")
    yield store
    store.close()


def _create_request(
    store: CenterStore,
    *,
    request_id: str = "R1",
    tenant_id: str = "T1",
    idempotency_key: str = "K1",
    payload_digest: str = "sha256:aaaa",
    max_attempts: int = 2,
    service_unit_id: str = "SU1",
    at: dt.datetime = T0,
) -> Any:
    """Create a request with sensible defaults for one test."""
    return store.create_request(
        request_id=request_id,
        tenant_id=tenant_id,
        subject_id="subject-1",
        idempotency_key=idempotency_key,
        payload_digest=payload_digest,
        delivery_mode="stream_strict",
        max_attempts=max_attempts,
        service_unit_id=service_unit_id,
        created_at=at,
    )


def _add_attempt(
    store: CenterStore,
    *,
    attempt_id: str = "A1",
    request_id: str = "R1",
    node_id: str | None = "N1",
    dispatch_epoch: int = 0,
    output_eligible: bool = True,
    at: dt.datetime = T0,
) -> Any:
    """Upsert an attempt with sensible defaults for one test."""
    return store.upsert_attempt(
        attempt_id=attempt_id,
        request_id=request_id,
        node_id=node_id,
        resource_id="res-1",
        provider_id="provider-1",
        dispatch_epoch=dispatch_epoch,
        at=at,
        output_eligible=output_eligible,
    )


# -- 1. request idempotency -------------------------------------------------


def test_create_request_inserts_and_reports_created(center: CenterStore) -> None:
    record, created = _create_request(center)

    assert created is True
    assert record.request_id == "R1"
    assert record.tenant_id == "T1"
    assert record.status == "CREATED"
    assert record.selected_attempt_id is None
    assert record.created_at == T0
    assert record.updated_at == T0
    assert center.get_request("R1") == record


def test_create_request_retry_returns_existing_and_creates_nothing(
    center: CenterStore,
) -> None:
    first, created_first = _create_request(center, request_id="R1")
    second, created_second = _create_request(center, request_id="R9")

    assert created_first is True
    assert created_second is False
    # The retry's own request_id is ignored: the stored winner comes back.
    assert second == first
    assert second.request_id == "R1"
    assert center.get_request("R9") is None


def test_create_request_same_key_different_digest_conflicts(center: CenterStore) -> None:
    _create_request(center, payload_digest="sha256:aaaa")

    with pytest.raises(ConflictError) as excinfo:
        _create_request(center, request_id="R2", payload_digest="sha256:bbbb")

    message = str(excinfo.value)
    assert "sha256:aaaa" in message
    assert "sha256:bbbb" in message
    # The refused request left nothing behind.
    assert center.get_request("R2") is None


def test_create_request_same_key_is_scoped_per_tenant(center: CenterStore) -> None:
    first, created_first = _create_request(center, tenant_id="T1", request_id="R1")
    second, created_second = _create_request(center, tenant_id="T2", request_id="R2")

    assert created_first is True
    assert created_second is True
    assert first.request_id == "R1"
    assert second.request_id == "R2"


def test_create_request_different_key_same_digest_creates(center: CenterStore) -> None:
    _, created_first = _create_request(center, idempotency_key="K1", request_id="R1")
    _, created_second = _create_request(center, idempotency_key="K2", request_id="R2")

    assert created_first is True
    assert created_second is True


def test_create_request_idempotency_error_is_not_integrity_error(center: CenterStore) -> None:
    _create_request(center, payload_digest="sha256:aaaa")

    with pytest.raises(ConflictError) as excinfo:
        _create_request(center, request_id="R2", payload_digest="sha256:bbbb")

    assert not isinstance(excinfo.value, sqlite3.IntegrityError)


# -- 2. restart durability --------------------------------------------------


def test_center_restart_reads_everything_back(tmp_path: Path) -> None:
    path = tmp_path / "center.db"
    store = CenterStore.open(path)
    _create_request(store, request_id="R1")
    _add_attempt(store, attempt_id="A1", request_id="R1")
    store.set_attempt_status("A1", "RUNNING", at=T1, execution_state="SUBMITTED")
    store.record_usage("A1", 42, at=T1)
    cursor, _ = store.append_event(
        request_id="R1",
        attempt_id="A1",
        attempt_seq=1,
        event_type="output.delta",
        payload={"text": "hello"},
        at=T1,
    )
    receipt = ReceiptRecord(
        receipt_id="RC1",
        request_id="R1",
        receipt_hash="sha256:r1",
        log_index=0,
        receipt_json='{"receipt":true}',
        created_at=T1,
    )
    store.put_receipt(receipt)
    store.append_log_leaf("sha256:r1", T1)
    settlement = SettlementRecord(
        service_unit_id="SU1",
        revision=1,
        fingerprint="fp-1",
        receipt_id="RC1",
        receipt_hash="sha256:r1",
        log_index=0,
        receipt_json='{"receipt":true}',
        created_at=T1,
    )
    store.record_settlement(settlement)
    node = NodeRecord(
        node_id="N1",
        device_id="dev-1",
        provider_id="prov-1",
        adapter_name="ollama",
        model="llama",
        share_enabled=True,
        max_concurrency=2,
        max_local_reserved_milli_credits=500,
        policy_version=3,
        connected=True,
        last_seen_at=T1,
    )
    store.upsert_node(node)
    outbox_id = store.enqueue_outbox("attempt.offer", {"attempt_id": "A1"}, at=T1)
    store.close()

    reopened = CenterStore.open(path)
    try:
        assert reopened.get_request("R1") == RequestRecord(
            request_id="R1",
            tenant_id="T1",
            subject_id="subject-1",
            idempotency_key="K1",
            payload_digest="sha256:aaaa",
            delivery_mode="stream_strict",
            max_attempts=2,
            service_unit_id="SU1",
            status="CREATED",
            selected_attempt_id=None,
            deadline_at=None,
            billing_note=None,
            created_at=T0,
            updated_at=T0,
        )
        assert reopened.get_attempt("A1") == AttemptRecord(
            attempt_id="A1",
            request_id="R1",
            node_id="N1",
            resource_id="res-1",
            provider_id="provider-1",
            dispatch_epoch=0,
            status="RUNNING",
            output_eligible=True,
            usage_status="COMPLETE",
            usage_tokens=42,
            settlement_status="HELD",
            execution_state="SUBMITTED",
            updated_at=T1,
        )
        events = reopened.events_after("R1", 0)
        assert len(events) == 1
        assert events[0].cursor == cursor == 1
        assert events[0].payload == {"text": "hello"}
        assert reopened.get_receipt("RC1") == receipt
        assert reopened.log_leaves() == [LogLeafRecord(0, "sha256:r1", T1)]
        assert reopened.log_size() == 1
        assert reopened.get_settlement("SU1", 1) == settlement
        assert reopened.get_node("N1") == node
        pending = reopened.pending_outbox()
        assert len(pending) == 1
        assert pending[0] == OutboxRecord(
            outbox_id, "attempt.offer", {"attempt_id": "A1"}, T1, None
        )
    finally:
        reopened.close()


# -- 3. commit_output: conditions, atomicity, race --------------------------


def test_commit_output_success_writes_commit_event_and_selection(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1", dispatch_epoch=0)

    committed, cursor = center.commit_output(
        request_id="R1",
        attempt_id="A1",
        expected_epoch=0,
        generation_id="gen-1",
        at=T1,
        event_seq=1,
        event_payload={"text": "first"},
    )

    assert committed is True
    assert cursor == 1
    commit = center.output_commit("R1")
    assert commit is not None
    assert commit.attempt_id == "A1"
    assert commit.generation_id == "gen-1"
    assert commit.committed_at_seq == 1
    assert center.get_request("R1").selected_attempt_id == "A1"
    events = center.events_after("R1", 0)
    assert [(e.attempt_id, e.attempt_seq, e.payload) for e in events] == [
        ("A1", 1, {"text": "first"})
    ]


def test_commit_output_is_refused_once_already_committed(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1", dispatch_epoch=0)
    _add_attempt(center, attempt_id="A2", request_id="R1", dispatch_epoch=1)
    assert center.commit_output(
        request_id="R1", attempt_id="A1", expected_epoch=0, generation_id="gen-1",
        at=T1, event_seq=1, event_payload={"text": "first"},
    ) == (True, 1)

    committed, cursor = center.commit_output(
        request_id="R1", attempt_id="A2", expected_epoch=1, generation_id="gen-2",
        at=T2, event_seq=1, event_payload={"text": "second"},
    )

    assert (committed, cursor) == (False, None)
    assert center.output_commit("R1").attempt_id == "A1"
    # The loser's event must not exist.
    assert [e.attempt_id for e in center.events_after("R1", 0)] == ["A1"]


@pytest.mark.parametrize(
    ("eligible", "epoch", "commit_epoch"),
    [(False, 0, 0), (True, 0, 1)],
    ids=["not-output-eligible", "stale-epoch"],
)
def test_commit_output_refused_leaves_database_unchanged(
    center: CenterStore, eligible: bool, epoch: int, commit_epoch: int
) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(
        center, attempt_id="A1", request_id="R1", dispatch_epoch=epoch, output_eligible=eligible
    )

    committed, cursor = center.commit_output(
        request_id="R1", attempt_id="A1", expected_epoch=commit_epoch, generation_id="gen-1",
        at=T1, event_seq=1, event_payload={"text": "first"},
    )

    assert (committed, cursor) == (False, None)
    assert center.output_commit("R1") is None
    assert center.events_after("R1", 0) == []
    assert center.get_request("R1").selected_attempt_id is None


def test_commit_output_refused_for_foreign_attempt(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _create_request(center, request_id="R2", idempotency_key="K2")
    _add_attempt(center, attempt_id="A2", request_id="R2", dispatch_epoch=0)

    committed, cursor = center.commit_output(
        request_id="R1", attempt_id="A2", expected_epoch=0, generation_id="gen-1",
        at=T1, event_seq=1, event_payload={"text": "first"},
    )

    assert (committed, cursor) == (False, None)
    assert center.output_commit("R1") is None
    assert center.events_after("R1", 0) == []


def test_commit_output_refused_for_unknown_attempt(center: CenterStore) -> None:
    _create_request(center, request_id="R1")

    committed, cursor = center.commit_output(
        request_id="R1", attempt_id="ghost", expected_epoch=0, generation_id="gen-1",
        at=T1, event_seq=1, event_payload={"text": "first"},
    )

    assert (committed, cursor) == (False, None)
    assert center.output_commit("R1") is None
    assert center.events_after("R1", 0) == []


def test_commit_output_race_has_exactly_one_winner(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1", dispatch_epoch=0)
    _add_attempt(center, attempt_id="A2", request_id="R1", dispatch_epoch=0)

    barrier = threading.Barrier(2)
    results: dict[str, tuple[bool, int | None]] = {}

    def attempt_commit(attempt_id: str, text: str) -> None:
        barrier.wait()
        results[attempt_id] = center.commit_output(
            request_id="R1",
            attempt_id=attempt_id,
            expected_epoch=0,
            generation_id=f"gen-{attempt_id}",
            at=T1,
            event_seq=1,
            event_payload={"text": text},
        )

    threads = [
        threading.Thread(target=attempt_commit, args=("A1", "one")),
        threading.Thread(target=attempt_commit, args=("A2", "two")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    winners = [attempt_id for attempt_id, (ok, _) in results.items() if ok]
    losers = [attempt_id for attempt_id, (ok, _) in results.items() if not ok]
    assert len(winners) == 1
    assert len(losers) == 1
    assert results[losers[0]] == (False, None)

    commit = center.output_commit("R1")
    assert commit is not None
    assert commit.attempt_id == winners[0]
    events = center.events_after("R1", 0)
    assert [e.attempt_id for e in events] == [winners[0]]
    assert center.get_request("R1").selected_attempt_id == winners[0]


# -- 3b. commit_output_segment: chunk-level atomic publish -------------------


def test_segment_first_chunk_runs_the_full_winner_cas(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1", dispatch_epoch=0)

    accepted, cursor = center.commit_output_segment(
        request_id="R1", attempt_id="A1", expected_epoch=0,
        event_seq=1, payload={"text": "one"}, at=T1,
    )

    assert (accepted, cursor) == (True, 1)
    commit = center.output_commit("R1")
    assert commit is not None
    assert commit.attempt_id == "A1"
    assert commit.generation_id == "gen-A1"
    assert commit.committed_at_seq == 1
    assert center.get_request("R1").selected_attempt_id == "A1"
    assert [(e.attempt_id, e.attempt_seq, e.payload) for e in center.events_after("R1", 0)] == [
        ("A1", 1, {"text": "one"})
    ]


def test_segment_later_chunks_of_the_winner_append(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1", dispatch_epoch=0)
    assert center.commit_output_segment(
        request_id="R1", attempt_id="A1", expected_epoch=0,
        event_seq=1, payload={"text": "one"}, at=T1,
    ) == (True, 1)

    accepted, cursor = center.commit_output_segment(
        request_id="R1", attempt_id="A1", expected_epoch=0,
        event_seq=2, payload={"text": "two"}, at=T2,
    )

    assert (accepted, cursor) == (True, 2)
    assert [e.payload["text"] for e in center.events_after("R1", 0)] == ["one", "two"]


def test_segment_refused_for_a_foreign_attempt_writes_nothing(center: CenterStore) -> None:
    """A chunk from a branch that lost the output race never reaches the stream."""
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1", dispatch_epoch=0)
    _add_attempt(center, attempt_id="A2", request_id="R1", dispatch_epoch=1)
    assert center.commit_output_segment(
        request_id="R1", attempt_id="A1", expected_epoch=0,
        event_seq=1, payload={"text": "one"}, at=T1,
    ) == (True, 1)

    accepted, cursor = center.commit_output_segment(
        request_id="R1", attempt_id="A2", expected_epoch=1,
        event_seq=1, payload={"text": "stolen"}, at=T2,
    )

    assert (accepted, cursor) == (False, None)
    assert center.output_commit("R1").attempt_id == "A1"
    assert [e.attempt_id for e in center.events_after("R1", 0)] == ["A1"]
    assert center.max_cursor("R1") == 1


def test_segment_refused_once_the_winner_is_demoted(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1", dispatch_epoch=0)
    assert center.commit_output_segment(
        request_id="R1", attempt_id="A1", expected_epoch=0,
        event_seq=1, payload={"text": "one"}, at=T1,
    ) == (True, 1)
    center.set_attempt_status("A1", "RUNNING", at=T2, output_eligible=False)

    accepted, cursor = center.commit_output_segment(
        request_id="R1", attempt_id="A1", expected_epoch=0,
        event_seq=2, payload={"text": "two"}, at=T2,
    )

    assert (accepted, cursor) == (False, None)
    assert center.max_cursor("R1") == 1


def test_segment_refused_for_unknown_attempt(center: CenterStore) -> None:
    _create_request(center, request_id="R1")

    accepted, cursor = center.commit_output_segment(
        request_id="R1", attempt_id="ghost", expected_epoch=0,
        event_seq=1, payload={"text": "one"}, at=T1,
    )

    assert (accepted, cursor) == (False, None)
    assert center.output_commit("R1") is None
    assert center.events_after("R1", 0) == []


# -- 4. event append: dedup, conflict, cursors, gaps ------------------------


def test_append_event_assigns_monotonic_per_request_cursor(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1")

    first = center.append_event(
        request_id="R1", attempt_id="A1", attempt_seq=1, event_type="output.delta",
        payload={"text": "a"}, at=T0,
    )
    second = center.append_event(
        request_id="R1", attempt_id="A1", attempt_seq=2, event_type="output.delta",
        payload={"text": "b"}, at=T1,
    )

    assert first == (1, True)
    assert second == (2, True)
    assert center.max_cursor("R1") == 2


def test_append_event_identical_replay_is_a_no_op(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1")
    center.append_event(
        request_id="R1", attempt_id="A1", attempt_seq=1, event_type="output.delta",
        payload={"text": "a"}, at=T0,
    )

    cursor, is_new = center.append_event(
        request_id="R1", attempt_id="A1", attempt_seq=1, event_type="output.delta",
        payload={"text": "a"}, at=T2,
    )

    assert (cursor, is_new) == (1, False)
    assert center.max_cursor("R1") == 1
    assert len(center.events_after("R1", 0)) == 1


def test_append_event_same_seq_different_content_conflicts(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1")
    center.append_event(
        request_id="R1", attempt_id="A1", attempt_seq=1, event_type="output.delta",
        payload={"text": "a"}, at=T0,
    )

    with pytest.raises(ConflictError):
        center.append_event(
            request_id="R1", attempt_id="A1", attempt_seq=1, event_type="output.delta",
            payload={"text": "CHANGED"}, at=T1,
        )

    events = center.events_after("R1", 0)
    assert len(events) == 1
    assert events[0].payload == {"text": "a"}


def test_last_attempt_seq_returns_prefix_not_max(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1")
    center.append_event(
        request_id="R1", attempt_id="A1", attempt_seq=1, event_type="output.delta",
        payload={"n": 1}, at=T0,
    )
    center.append_event(
        request_id="R1", attempt_id="A1", attempt_seq=3, event_type="output.delta",
        payload={"n": 3}, at=T2,
    )

    # Sequence 3 arrived before 2: the prefix stops at 1 even though the highest
    # attempt_seq is 3. The per-request cursor is independent of attempt_seq, so
    # it is 2 (two events stored), not 3.
    assert center.max_cursor("R1") == 2
    assert center.last_attempt_seq("A1") == 1
    assert center.has_event_gap("A1") is True

    center.append_event(
        request_id="R1", attempt_id="A1", attempt_seq=2, event_type="output.delta",
        payload={"n": 2}, at=T1,
    )

    assert center.last_attempt_seq("A1") == 3
    assert center.has_event_gap("A1") is False


def test_last_attempt_seq_is_zero_for_unknown_attempt(center: CenterStore) -> None:
    assert center.last_attempt_seq("never") == 0
    assert center.has_event_gap("never") is False


def test_events_after_respects_cursor_and_limit(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1")
    for seq in range(1, 5):
        center.append_event(
            request_id="R1", attempt_id="A1", attempt_seq=seq, event_type="output.delta",
            payload={"n": seq}, at=T0,
        )

    after = center.events_after("R1", 1, limit=2)

    assert [e.cursor for e in after] == [2, 3]
    assert center.events_after("R1", 100) == []


# -- 3b. create_request race -------------------------------------------------


def test_create_request_race_inserts_exactly_once(center: CenterStore) -> None:
    barrier = threading.Barrier(2)
    outcomes: dict[str, tuple[Any, bool]] = {}

    def call(request_id: str) -> None:
        barrier.wait()
        outcomes[request_id] = _create_request(
            center, request_id=request_id, tenant_id="T1", idempotency_key="K1",
            payload_digest="sha256:same",
        )

    threads = [
        threading.Thread(target=call, args=("R1",)),
        threading.Thread(target=call, args=("R2",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    created_flags = sorted(created for _, created in outcomes.values())
    assert created_flags == [False, True]
    records = {record.request_id for record, _ in outcomes.values()}
    # Both callers observe the single stored winner.
    assert len(records) == 1
    winner_id = records.pop()
    loser_id = "R2" if winner_id == "R1" else "R1"
    assert center.get_request(winner_id) is not None
    assert center.get_request(loser_id) is None


# -- 7. credentials: no raw token at rest -----------------------------------


def _all_bytes(path: Path) -> bytes:
    """Concatenate the database file and any WAL sidecars."""
    blob = b""
    for candidate in sorted(path.parent.glob(path.name + "*")):
        blob += candidate.read_bytes()
    return blob


def test_raw_token_never_appears_in_database_file(tmp_path: Path) -> None:
    path = tmp_path / "center.db"
    token = "raw-token-9f3a1c7e-do-not-store"
    store = CenterStore.open(path)
    store.add_credential(token, "T1", "subject-1", "consumer", T0)

    on_disk = _all_bytes(path)
    assert token.encode() not in on_disk
    assert canonical_digest(token).encode() in on_disk

    store.close()
    after_close = _all_bytes(path)
    assert token.encode() not in after_close


def test_resolve_credential_accepts_raw_token_and_rejects_bad_ones(center: CenterStore) -> None:
    center.add_credential("token-active", "T1", "subject-1", "node", T0)

    resolved = center.resolve_credential("token-active", T1)
    assert resolved is not None
    assert (resolved.tenant_id, resolved.subject_id, resolved.role) == ("T1", "subject-1", "node")
    assert center.resolve_credential("token-other", T1) is None
    # Before the credential was created it does not yet exist.
    assert center.resolve_credential("token-active", T0 - dt.timedelta(seconds=1)) is None


def test_revoked_credential_resolves_to_none(center: CenterStore) -> None:
    center.add_credential("token-active", "T1", "subject-1", "consumer", T0)
    center.revoke_credential("token-active", T1)

    assert center.resolve_credential("token-active", T2) is None
    # Revoking again keeps the first revocation instant.
    center.revoke_credential("token-active", T2)
    assert center.resolve_credential("token-active", T2) is None


def test_add_credential_conflict_is_conflict_error(center: CenterStore) -> None:
    center.add_credential("token-1", "T1", "subject-1", "consumer", T0)

    with pytest.raises(ConflictError):
        center.add_credential("token-1", "T2", "subject-2", "node", T1)


def test_a_node_credential_keeps_the_device_it_was_bound_to(center: CenterStore) -> None:
    """The device a node credential speaks for survives the round trip.

    A node-scoped read derives its scope from this column rather than from the
    tenant, so it has to come back exactly as it went in — and a credential an
    operator provisioned in ``center.json``, which names no device, has to come
    back without one instead of acquiring a device it was never bound to.
    """
    center.add_credential("token-joined", "T1", "node-1", "node", T0, device_id="dev-1")
    center.add_credential("token-provisioned", "T1", "node-2", "node", T0)

    joined = center.resolve_credential("token-joined", T1)
    provisioned = center.resolve_credential("token-provisioned", T1)
    assert joined is not None and joined.device_id == "dev-1"
    assert provisioned is not None and provisioned.device_id is None


def test_add_credential_conflict_covers_the_device_binding(center: CenterStore) -> None:
    """One token cannot be re-registered against a second device.

    Re-adding the identical binding stays a no-op, so an idempotent re-provision
    is still free; only a *different* device is a conflict.
    """
    center.add_credential("token-1", "T1", "node-1", "node", T0, device_id="dev-1")

    with pytest.raises(ConflictError):
        center.add_credential("token-1", "T1", "node-1", "node", T0, device_id="dev-2")

    center.add_credential("token-1", "T1", "node-1", "node", T0, device_id="dev-1")
    resolved = center.resolve_credential("token-1", T1)
    assert resolved is not None and resolved.device_id == "dev-1"


def test_a_database_from_before_the_device_binding_gains_the_column(
    tmp_path: Path,
) -> None:
    """An upgraded center keeps the credentials it already issued.

    ``_migrate`` adds a column an existing database is missing; without its entry
    for ``credentials.device_id``, every resolve against a database an earlier
    release created would raise on a column that is not there — and the failure
    would land on authentication, not on the reconciliation that needs it. A row
    written before the column existed resolves with no device binding, which is
    the honest answer: the center that minted it never recorded one.
    """
    path = tmp_path / "center.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE credentials (token_digest TEXT PRIMARY KEY,"
            " tenant_id TEXT NOT NULL, subject_id TEXT NOT NULL, role TEXT NOT NULL,"
            " created_at TEXT NOT NULL, revoked_at TEXT)"
        )
        connection.execute(
            "INSERT INTO credentials (token_digest, tenant_id, subject_id, role, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                canonical_digest("token-legacy"), "T1", "node-legacy", "node",
                T0.strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
            ),
        )
        connection.commit()
    finally:
        connection.close()

    store = CenterStore.open(path)
    try:
        legacy = store.resolve_credential("token-legacy", T1)
        assert legacy is not None
        assert (legacy.subject_id, legacy.role, legacy.device_id) == ("node-legacy", "node", None)

        store.add_credential("token-new", "T1", "node-new", "node", T1, device_id="dev-9")
        fresh = store.resolve_credential("token-new", T1)
        assert fresh is not None and fresh.device_id == "dev-9"
    finally:
        store.close()


def _legacy_request_inputs(path: Path, rows: tuple[tuple[str, str], ...]) -> None:
    """Write the `request_inputs` table a center from before the conversation model holds.

    Only that table: opening the store creates everything else, exactly as it did
    for the centers that upgraded in place.
    """
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE request_inputs (request_id TEXT PRIMARY KEY,"
            " prompt TEXT NOT NULL, model TEXT NOT NULL,"
            " authorization_json TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        for request_id, prompt in rows:
            connection.execute(
                "INSERT INTO request_inputs (request_id, prompt, model,"
                " authorization_json, created_at) VALUES (?, ?, ?, ?, ?)",
                (request_id, prompt, MODEL, "{}", T0.strftime("%Y-%m-%dT%H:%M:%S.%f%z")),
            )
        connection.commit()
    finally:
        connection.close()


def _request_input_columns(path: Path) -> list[tuple[Any, ...]]:
    """Return `request_inputs`' columns as SQLite describes them, in order."""
    connection = sqlite3.connect(path)
    try:
        return [tuple(row) for row in connection.execute("PRAGMA table_info(request_inputs)")]
    finally:
        connection.close()


def test_a_database_from_before_the_conversation_model_is_rebuilt_to_the_current_shape(
    tmp_path: Path,
) -> None:
    """An upgraded center ends up with the one shape a new center is created with.

    The table an earlier release created carries ``prompt TEXT NOT NULL``, and no
    conversation write can satisfy that constraint. SQLite cannot drop a column
    constraint, so the table is rebuilt; without the rebuild every
    `set_request_input` on an upgraded center failed, and because the failure was
    reported as a duplicate and suppressed, the center admitted requests it could
    never dispatch and left each one in ROUTING with nothing behind it.
    """
    fresh = tmp_path / "fresh.db"
    CenterStore.open(fresh).close()

    upgraded = tmp_path / "upgraded.db"
    _legacy_request_inputs(upgraded, (("R-1", "write a haiku about ledgers"),))
    store = CenterStore.open(upgraded)
    try:
        assert _request_input_columns(upgraded) == _request_input_columns(fresh)
        assert "prompt" not in {str(column[1]) for column in _request_input_columns(upgraded)}
        # The failure the rebuild exists to end: a conversation can be stored.
        store.set_request_input(
            "R-2",
            messages=[{"role": "user", "content": "write a haiku about sockets"}],
            model=MODEL,
            parameters={"temperature": "0.7"},
            authorization={"schema": "auth"},
            at=T1,
        )
        stored = store.get_request_input("R-2")
        assert stored is not None
        assert stored["messages"] == [{"role": "user", "content": "write a haiku about sockets"}]
        assert stored["parameters"] == {"temperature": "0.7"}
    finally:
        store.close()

    # The rebuild is idempotent, and a second open changes nothing about the shape.
    reopened = CenterStore.open(upgraded)
    try:
        assert _request_input_columns(upgraded) == _request_input_columns(fresh)
        assert reopened.get_request_input("R-2") is not None
    finally:
        reopened.close()


def test_a_row_an_earlier_center_stored_as_a_prompt_is_kept_and_reported(
    tmp_path: Path,
) -> None:
    """A legacy row survives the rebuild and is still reported, never re-read.

    The rebuild carries every row over rather than deleting it, so the answer an
    operator gets for a request an earlier center admitted is the same after the
    upgrade as before it: this build cannot offer or settle it, and it says so
    instead of inventing a one-message conversation nobody signed for.
    """
    path = tmp_path / "center.db"
    _legacy_request_inputs(path, (("R-1", "write a haiku about ledgers"),))
    store = CenterStore.open(path)
    try:
        with pytest.raises(PotluckError, match="earlier center version"):
            store.get_request_input("R-1")
        # Reported, not mistaken for a row that was never written.
        assert store.get_request_input("R-never") is None
    finally:
        store.close()


def test_a_terminal_legacy_request_keeps_an_upgraded_center_reconcilable(
    tmp_path: Path,
) -> None:
    """The migration touches one table, and the books still agree afterwards.

    A center that ran the earlier build holds terminal requests whose inputs it
    stored as a flattened prompt. Reconcile, and every receipt path it audits,
    reads those requests the same way after the rebuild as before it: dropping the
    retired prompt text changes no billing truth, because what a request cost
    lives in the receipts, the ledger and the transparency log.
    """
    path = tmp_path / "center.db"
    _legacy_request_inputs(path, (("R-legacy", "write a haiku about ledgers"),))
    store = CenterStore.open(path)
    try:
        _create_request(store, request_id="R-legacy", idempotency_key="K-legacy")
        store.set_request_status("R-legacy", "FAILED", billing_note="upstream failed", at=T1)

        assert reconcile_center(store=store) == []

        # And a request admitted after the upgrade reconciles beside it.
        _create_request(store, request_id="R-new", idempotency_key="K-new")
        store.set_request_input(
            "R-new",
            messages=[{"role": "user", "content": "write a haiku about sockets"}],
            model=MODEL,
            parameters={},
            authorization={"schema": "auth"},
            at=T1,
        )
        assert reconcile_center(store=store) == []
    finally:
        store.close()


def test_a_write_the_table_cannot_hold_is_reported_as_itself_not_as_a_duplicate(
    center: CenterStore, tmp_path: Path
) -> None:
    """A genuine duplicate conflicts; anything else is named as what it is.

    Both arrive as the same `sqlite3.IntegrityError`, and reporting both as a
    duplicate is what let a store that could not hold a request's inputs look
    like a request that already had them — which the caller then suppressed.
    """
    messages = [{"role": "user", "content": "hi"}]
    center.set_request_input(
        "R-dup", messages=messages, model=MODEL, parameters={}, authorization={}, at=T0
    )
    with pytest.raises(ConflictError, match="already has stored dispatch inputs"):
        center.set_request_input(
            "R-dup", messages=messages, model=MODEL, parameters={}, authorization={}, at=T0
        )

    # Put the table back into the shape that broke in production — a legacy
    # `prompt TEXT NOT NULL` beside the conversation columns, which no INSERT this
    # build writes can satisfy — and the failure must be named as itself.
    connection = sqlite3.connect(tmp_path / "center.db")
    try:
        connection.execute("DROP TABLE request_inputs")
        connection.execute(
            "CREATE TABLE request_inputs (request_id TEXT PRIMARY KEY,"
            " prompt TEXT NOT NULL, model TEXT NOT NULL, messages_json TEXT,"
            " parameters_json TEXT NOT NULL DEFAULT '{}',"
            " authorization_json TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(PotluckError, match="could not be stored") as failure:
        center.set_request_input(
            "R-broken", messages=messages, model=MODEL, parameters={}, authorization={}, at=T0
        )
    assert not isinstance(failure.value, ConflictError)
    assert center.get_request_input("R-broken") is None


# -- settlement, receipts, log ----------------------------------------------


def test_record_settlement_is_idempotent_and_never_overwrites(center: CenterStore) -> None:
    first = SettlementRecord(
        service_unit_id="SU1", revision=1, fingerprint="fp-A", receipt_id="RC1",
        receipt_hash="sha256:r1", log_index=0, receipt_json="A", created_at=T0,
    )
    stored = center.record_settlement(first)
    assert stored == first

    second = SettlementRecord(
        service_unit_id="SU1", revision=1, fingerprint="fp-A", receipt_id="RC1",
        receipt_hash="sha256:r1", log_index=0, receipt_json="B", created_at=T1,
    )
    assert center.record_settlement(second) == first
    assert center.get_settlement("SU1", 1).receipt_json == "A"


def test_record_settlement_different_fingerprint_conflicts(center: CenterStore) -> None:
    center.record_settlement(
        SettlementRecord(
            service_unit_id="SU1", revision=1, fingerprint="fp-A", receipt_id="RC1",
            receipt_hash="sha256:r1", log_index=0, receipt_json="A", created_at=T0,
        )
    )

    with pytest.raises(ConflictError):
        center.record_settlement(
            SettlementRecord(
                service_unit_id="SU1", revision=1, fingerprint="fp-B", receipt_id="RC1",
                receipt_hash="sha256:r1", log_index=0, receipt_json="B", created_at=T1,
            )
        )

    assert center.get_settlement("SU1", 1).fingerprint == "fp-A"


def test_record_settlement_new_revision_is_accepted(center: CenterStore) -> None:
    for revision in (1, 2):
        center.record_settlement(
            SettlementRecord(
                service_unit_id="SU1", revision=revision, fingerprint=f"fp-{revision}",
                receipt_id="RC1", receipt_hash="sha256:r1", log_index=revision - 1,
                receipt_json="{}", created_at=T0,
            )
        )

    assert center.get_settlement("SU1", 2).fingerprint == "fp-2"


def test_latest_settlement_returns_the_highest_revision(center: CenterStore) -> None:
    """The current settlement is the highest revision, whichever order they came in.

    A caller that names the receipt a request settled into — a node reading its
    own attempts — has to read the revision `reconcile_center` reads, or the two
    sides of one reconciliation name different receipts for the same request. The
    revisions are written out of order here so the answer cannot come from
    insertion order.
    """
    assert center.latest_settlement("SU1") is None

    for revision in (2, 1):
        center.record_settlement(
            SettlementRecord(
                service_unit_id="SU1", revision=revision, fingerprint=f"fp-{revision}",
                receipt_id=f"RC-{revision}", receipt_hash=f"sha256:r{revision}",
                log_index=revision - 1, receipt_json="{}", created_at=T0,
            )
        )

    latest = center.latest_settlement("SU1")
    assert latest is not None
    assert (latest.revision, latest.receipt_id) == (2, "RC-2")


def test_put_receipt_idempotent_and_conflicting(center: CenterStore) -> None:
    receipt = ReceiptRecord("RC1", "R1", "sha256:r1", 0, '{"a":1}', T0)
    center.put_receipt(receipt)
    center.put_receipt(receipt)
    assert center.get_receipt("RC1") == receipt

    with pytest.raises(ConflictError):
        center.put_receipt(ReceiptRecord("RC1", "R1", "sha256:r2", 1, '{"a":2}', T1))


def test_append_log_leaf_is_idempotent_by_hash(center: CenterStore) -> None:
    first = center.append_log_leaf("sha256:r1", T0)
    second = center.append_log_leaf("sha256:r2", T1)
    duplicate = center.append_log_leaf("sha256:r1", T2)

    assert first == 0
    assert second == 1
    assert duplicate == 0
    assert center.log_size() == 2
    assert center.log_leaves() == [
        LogLeafRecord(0, "sha256:r1", T0),
        LogLeafRecord(1, "sha256:r2", T1),
    ]


# -- nodes and outbox -------------------------------------------------------


def _node(**overrides: Any) -> NodeRecord:
    base: dict[str, Any] = {
        "node_id": "N1",
        "device_id": "dev-1",
        "provider_id": "prov-1",
        "adapter_name": "ollama",
        "model": "llama",
        "share_enabled": True,
        "max_concurrency": 2,
        "max_local_reserved_milli_credits": 500,
        "policy_version": 1,
        "connected": True,
        "last_seen_at": T0,
    }
    base.update(overrides)
    return NodeRecord(**base)


def test_upsert_node_and_connected_filter(center: CenterStore) -> None:
    center.upsert_node(_node(node_id="N1", model="llama"))
    center.upsert_node(_node(node_id="N2", model="mistral", connected=False))

    assert center.get_node("N1") == _node(node_id="N1", model="llama")
    assert [n.node_id for n in center.connected_nodes()] == ["N1"]
    assert [n.node_id for n in center.connected_nodes(model="llama")] == ["N1"]
    assert center.connected_nodes(model="mistral") == []


def test_upsert_node_replaces_and_set_connected(center: CenterStore) -> None:
    center.upsert_node(_node(node_id="N1", share_enabled=True))
    center.upsert_node(_node(node_id="N1", share_enabled=False, policy_version=2))

    stored = center.get_node("N1")
    assert stored is not None
    assert stored.share_enabled is False
    assert stored.policy_version == 2

    center.set_node_connected("N1", False, at=T1)
    assert center.get_node("N1").connected is False
    assert center.connected_nodes() == []


def test_set_node_connected_unknown_raises(center: CenterStore) -> None:
    with pytest.raises(StateTransitionError):
        center.set_node_connected("ghost", True, at=T0)


def test_outbox_enqueue_pending_deliver(center: CenterStore) -> None:
    first = center.enqueue_outbox("attempt.offer", {"attempt_id": "A1"}, at=T0)
    second = center.enqueue_outbox("attempt.cancel", {"attempt_id": "A1"}, at=T1)

    pending = center.pending_outbox()
    assert [o.outbox_id for o in pending] == [first, second]
    assert pending[0] == OutboxRecord(first, "attempt.offer", {"attempt_id": "A1"}, T0, None)

    center.mark_outbox_delivered(first, T2)
    remaining = center.pending_outbox()
    assert [o.outbox_id for o in remaining] == [second]
    assert center.pending_outbox(limit=1) == remaining


def test_pending_outbox_respects_limit(center: CenterStore) -> None:
    for index in range(3):
        center.enqueue_outbox("k", {"i": index}, at=T0)

    assert len(center.pending_outbox(limit=2)) == 2


# -- attempt status, usage, request status ----------------------------------


def test_set_attempt_status_updates_selected_fields(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1")

    center.set_attempt_status("A1", "RUNNING", at=T1, execution_state="SUBMITTED")

    attempt = center.get_attempt("A1")
    assert attempt is not None
    assert attempt.status == "RUNNING"
    assert attempt.execution_state == "SUBMITTED"
    assert attempt.output_eligible is True
    assert attempt.updated_at == T1

    center.set_attempt_status("A1", "FAILED", at=T2, output_eligible=False)
    attempt = center.get_attempt("A1")
    assert attempt.status == "FAILED"
    assert attempt.output_eligible is False
    assert attempt.execution_state == "SUBMITTED"


def test_set_attempt_status_unknown_raises(center: CenterStore) -> None:
    with pytest.raises(StateTransitionError):
        center.set_attempt_status("ghost", "RUNNING", at=T0)


def test_record_usage_zero_is_distinct_from_unknown(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1")
    _add_attempt(center, attempt_id="A2", request_id="R1")

    center.record_usage("A1", 0, at=T1)
    center.mark_usage_unknown("A2", at=T1)

    first = center.get_attempt("A1")
    second = center.get_attempt("A2")
    assert (first.usage_status, first.usage_tokens) == ("COMPLETE", 0)
    assert (second.usage_status, second.usage_tokens) == ("UNKNOWN", None)


def test_attempts_for_request_and_node(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1", node_id="N1")
    _add_attempt(center, attempt_id="A2", request_id="R1", node_id="N1")
    _add_attempt(center, attempt_id="A3", request_id="R1", node_id="N2")
    center.set_attempt_status("A2", "COMPLETED", at=T1)

    assert [a.attempt_id for a in center.attempts_for_request("R1")] == ["A1", "A2", "A3"]
    assert [a.attempt_id for a in center.attempts_for_node("N1")] == ["A1"]
    assert [a.attempt_id for a in center.attempts_for_node("N1", unfinished_only=False)] == [
        "A1",
        "A2",
    ]


def test_upsert_attempt_for_unknown_request_raises(center: CenterStore) -> None:
    with pytest.raises(StateTransitionError):
        _add_attempt(center, attempt_id="A1", request_id="ghost")


def test_set_request_status_unknown_raises(center: CenterStore) -> None:
    with pytest.raises(StateTransitionError):
        center.set_request_status("ghost", "RUNNING", at=T0)


def test_set_request_status_updates_and_keeps_selection(center: CenterStore) -> None:
    _create_request(center, request_id="R1")
    _add_attempt(center, attempt_id="A1", request_id="R1")
    center.commit_output(
        request_id="R1", attempt_id="A1", expected_epoch=0, generation_id="g", at=T1,
        event_seq=1, event_payload={"text": "x"},
    )

    center.set_request_status("R1", "SUCCEEDED", at=T2)

    request = center.get_request("R1")
    assert request.status == "SUCCEEDED"
    assert request.selected_attempt_id == "A1"
    assert request.updated_at == T2


# -- timestamp handling -----------------------------------------------------


def test_timestamps_normalize_to_utc(center: CenterStore) -> None:
    offset = dt.timezone(dt.timedelta(hours=2))
    local = dt.datetime(2026, 10, 6, 14, 0, 0, tzinfo=offset)

    record, _ = _create_request(center, request_id="R1", at=local)

    assert record.created_at == T0
    assert record.created_at.tzinfo == dt.UTC


def test_naive_timestamp_is_refused(center: CenterStore) -> None:
    with pytest.raises(ValueError):
        _create_request(center, request_id="R1", at=dt.datetime(2026, 10, 6, 12, 0, 0))


def test_closed_store_refuses_use(tmp_path: Path) -> None:
    store = CenterStore.open(tmp_path / "center.db")
    store.close()
    store.close()  # idempotent

    with pytest.raises(PotluckError):
        _create_request(store, request_id="R1")


# -- opening a database that must already be there --------------------------


def test_open_existing_refuses_a_database_that_is_not_there(tmp_path: Path) -> None:
    """A store that reads somebody else's database must not bring one into being.

    `open` creates the file — and the parent directory — it is pointed at, which
    is what the process that owns a database needs. The commands that only read
    one go through `open_existing`, so a path that names nothing raises before a
    connection is made and leaves the filesystem exactly as it was: a created
    file would be an empty database, and an empty database reports no
    differences, which is how a whole lost store reads as a clean one.
    """
    missing = tmp_path / "never-created" / "center.db"

    with pytest.raises(PotluckError, match="does not exist"):
        CenterStore.open_existing(missing)
    with pytest.raises(PotluckError, match="does not exist"):
        NodeStore.open_existing(missing)

    assert not missing.exists()
    assert not missing.parent.exists()
    assert [path.name for path in tmp_path.iterdir()] == []


def test_open_existing_refuses_a_database_whose_creation_never_finished(
    tmp_path: Path,
) -> None:
    """A zero-byte file is a crash, not an empty database with nothing to report.

    SQLite reads a zero-length file as a valid empty database, so `open` would
    happily write a schema into it; but this store writes its schema as it
    creates one, so an empty file means the creation stopped halfway. Refusing it
    keeps "half a database" from reconciling as a clean one.
    """
    truncated = tmp_path / "center.db"
    truncated.write_bytes(b"")

    with pytest.raises(PotluckError, match="empty"):
        CenterStore.open_existing(truncated)

    assert truncated.read_bytes() == b"", "the refusal must not write a schema"


# -- agent sessions ---------------------------------------------------------


def _session_request(
    store: CenterStore,
    *,
    request_id: str,
    session_id: str | None,
    idempotency_key: str | None = None,
    tenant_id: str = "T1",
    at: dt.datetime = T0,
) -> None:
    """Create one request that belongs to a session, as an admission would."""
    store.create_request(
        request_id=request_id,
        tenant_id=tenant_id,
        subject_id="subject-1",
        idempotency_key=idempotency_key or f"K-{request_id}",
        payload_digest=f"sha256:{request_id}",
        delivery_mode="buffered_complete",
        max_attempts=1,
        service_unit_id=request_id,
        created_at=at,
        session_id=session_id,
    )
    if session_id is not None:
        store.touch_session(
            tenant_id=tenant_id, subject_id="subject-1", session_id=session_id, at=at
        )


def _settle_request(
    store: CenterStore,
    *,
    request_id: str,
    attempt_id: str,
    receipt_id: str,
    log_index: int,
    charge: int,
    tokens: int,
    at: dt.datetime = T1,
) -> None:
    """Run one request's settlement bundle, as the gateway's settlement does."""
    store.upsert_attempt(
        attempt_id=attempt_id,
        request_id=request_id,
        node_id="N1",
        resource_id="res-1",
        provider_id="provider-1",
        dispatch_epoch=1,
        at=at,
    )
    store.record_settlement_bundle(
        settlement=SettlementRecord(
            service_unit_id=request_id,
            revision=1,
            fingerprint=f"fp-{receipt_id}",
            receipt_id=receipt_id,
            receipt_hash=f"sha256:{receipt_id}",
            log_index=log_index,
            receipt_json="{}",
            created_at=at,
        ),
        receipt=ReceiptRecord(
            receipt_id=receipt_id,
            request_id=request_id,
            receipt_hash=f"sha256:{receipt_id}",
            log_index=log_index,
            receipt_json="{}",
            created_at=at,
        ),
        journal_kind="journal",
        journal_payload={"journal_id": f"J-{receipt_id}", "kind": "success"},
        attempt_id=attempt_id,
        usage_tokens=charge,
        at=at,
        settled_tokens=tokens,
    )


def test_touch_session_counts_admissions_and_keeps_the_first_instant(
    center: CenterStore,
) -> None:
    """One row per session, counted up, with both instants it needs to be useful.

    `created_at` is when the run started and `last_seen_at` is when it last did
    something: an operator reading a listing sorts by the second and reads the
    first to tell a long run from a stale one.
    """
    _session_request(center, request_id="R1", session_id="sess-1", at=T0)
    _session_request(center, request_id="R2", session_id="sess-1", at=T2)

    session = center.session("T1", "subject-1", "sess-1")
    assert session is not None
    assert session.request_count == 2
    assert session.created_at == T0
    assert session.last_seen_at == T2
    assert (session.total_tokens, session.total_milli_credits) == (0, 0)


def test_a_settlement_adds_its_tokens_and_charge_to_the_session_once(
    center: CenterStore,
) -> None:
    """The totals are the settlement's own numbers, and a replay adds nothing.

    Written inside the settlement transaction and guarded by the settlement row
    itself, so the resend a node makes after a lost acknowledgement cannot count
    the same credit twice — the same idempotency the key's quota relies on.
    """
    _session_request(center, request_id="R1", session_id="sess-1")
    arguments: dict[str, Any] = {
        "request_id": "R1",
        "attempt_id": "A1",
        "receipt_id": "RC1",
        "log_index": 0,
        "charge": 1_000,
        "tokens": 800,
    }

    _settle_request(center, **arguments)
    _settle_request(center, **arguments)

    session = center.session("T1", "subject-1", "sess-1")
    assert session is not None
    assert session.total_milli_credits == 1_000
    assert session.total_tokens == 800, "native tokens and credit are different quantities"
    assert session.last_node_id == "N1"


def test_a_settlement_of_a_request_with_no_session_updates_no_aggregate(
    center: CenterStore,
) -> None:
    """A session exists because a request declared one, never by inference."""
    _session_request(center, request_id="R1", session_id=None)

    _settle_request(
        center,
        request_id="R1",
        attempt_id="A1",
        receipt_id="RC1",
        log_index=0,
        charge=1_000,
        tokens=800,
    )

    assert center.sessions() == []


def test_two_subjects_may_name_one_session_without_sharing_it(
    center: CenterStore,
) -> None:
    """The identifier is caller-chosen, so the key has to carry the identity too.

    Without the subject in the key, one consumer naming a session another already
    used would spend into — and be reported under — somebody else's run.
    """
    center.create_request(
        request_id="R1",
        tenant_id="T1",
        subject_id="subject-1",
        idempotency_key="K1",
        payload_digest="sha256:R1",
        delivery_mode="buffered_complete",
        max_attempts=1,
        service_unit_id="R1",
        created_at=T0,
        session_id="shared",
    )
    center.touch_session(tenant_id="T1", subject_id="subject-1", session_id="shared", at=T0)
    center.create_request(
        request_id="R2",
        tenant_id="T1",
        subject_id="subject-2",
        idempotency_key="K2",
        payload_digest="sha256:R2",
        delivery_mode="buffered_complete",
        max_attempts=1,
        service_unit_id="R2",
        created_at=T1,
        session_id="shared",
    )
    center.touch_session(tenant_id="T1", subject_id="subject-2", session_id="shared", at=T1)

    rows = center.sessions(session_id="shared")
    assert sorted(row.subject_id for row in rows) == ["subject-1", "subject-2"]
    assert all(row.request_count == 1 for row in rows)
    assert center.sessions(subject_id="subject-2")[0].session_id == "shared"
    # Dispatch reads the preference through the request, so it can only ever reach
    # the aggregate of the subject that request belongs to.
    assert center.session_preference_for("R1") is None
    assert center.session_preference_for("R2") is None


def test_receipts_for_session_are_the_records_behind_its_totals(
    center: CenterStore,
) -> None:
    """A session listing is a claim; the receipts are what an operator checks it against."""
    _session_request(center, request_id="R1", session_id="sess-1")
    _session_request(center, request_id="R2", session_id="sess-1", at=T1)
    _session_request(center, request_id="R3", session_id="sess-2", at=T1)
    _settle_request(
        center, request_id="R1", attempt_id="A1", receipt_id="RC1",
        log_index=0, charge=1_000, tokens=800,
    )
    _settle_request(
        center, request_id="R2", attempt_id="A2", receipt_id="RC2",
        log_index=1, charge=2_000, tokens=900, at=T2,
    )
    _settle_request(
        center, request_id="R3", attempt_id="A3", receipt_id="RC3",
        log_index=2, charge=4_000, tokens=100, at=T2,
    )

    assert [receipt.receipt_id for receipt in center.receipts_for_session("sess-1")] == [
        "RC1",
        "RC2",
    ]
    assert [receipt.receipt_id for receipt in center.receipts_for_session("sess-2")] == ["RC3"]
    session = center.session("T1", "subject-1", "sess-1")
    assert session is not None
    assert (session.total_tokens, session.total_milli_credits) == (1_700, 3_000)


# -- the dispatch queue's own reads -----------------------------------------


def test_waiting_requests_are_read_oldest_first_and_counted_whole(
    center: CenterStore,
) -> None:
    """The queue is this ordering, so the ordering is the fairness claim.

    `requests_by_status` is bounded because one tick must not walk a center's whole
    history; `count_requests_by_status` is not, because a bound that undercounted
    would let the queue grow past what the operator set. The ordering reads
    `created_at`, which is the arrival instant an admission wrote, so what
    first-come-first-served means here is arrival order and nothing else.
    """
    arrivals = [("R1", "ROUTING"), ("R2", "RUNNING"), ("R3", "ROUTING"), ("R4", "ROUTING")]
    for index, (request_id, status) in enumerate(arrivals):
        _create_request(
            center,
            request_id=request_id,
            idempotency_key=f"K{index}",
            at=T0 + dt.timedelta(seconds=index),
        )
        center.set_request_status(request_id, status, at=T0 + dt.timedelta(seconds=index))

    waiting = center.requests_by_status("ROUTING", limit=2)
    assert [record.request_id for record in waiting] == ["R1", "R3"], (
        "oldest first, and bounded so one tick cannot walk the center's history"
    )
    assert center.count_requests_by_status("ROUTING") == 3
    assert center.count_requests_by_status("SUCCEEDED") == 0


def test_a_refused_offer_occupies_no_slot_in_the_attempt_budget(
    center: CenterStore,
) -> None:
    """The budget bounds executions, and a refusal executed nothing.

    Counting refusals would let one busy node spend a request's whole budget on
    zero work, and then have the center report the request as exhausted rather
    than as waiting for a node that frees up.
    """
    _create_request(center, request_id="R1", max_attempts=1)
    _add_attempt(center, attempt_id="A1", request_id="R1", node_id="N1")
    center.set_attempt_status("A1", "FAILED", at=T1)
    center.mark_attempt_refused("A1", at=T1)
    _add_attempt(center, attempt_id="A2", request_id="R1", node_id="N2", dispatch_epoch=2)

    assert center.count_budget_attempts("R1") == 1
    attempts = center.attempts_for_request("R1")
    assert {attempt.attempt_id: attempt.refused_before_execution for attempt in attempts} == {
        "A1": True,
        "A2": False,
    }


def test_mark_attempt_refused_names_an_attempt_it_does_not_hold(
    center: CenterStore,
) -> None:
    """A mark that could be written against nothing would be a silent no-op."""
    with pytest.raises(StateTransitionError):
        center.mark_attempt_refused("A-missing", at=T0)


def test_request_by_idempotency_key_is_scoped_to_its_tenant(
    center: CenterStore,
) -> None:
    """The read an admission gate uses to honour a retry must not cross tenants."""
    _create_request(center, request_id="R1", tenant_id="T1", idempotency_key="K1")
    center.create_request(
        request_id="R2",
        tenant_id="T2",
        subject_id="subject-2",
        idempotency_key="K1",
        payload_digest="sha256:R2",
        delivery_mode="buffered_complete",
        max_attempts=1,
        service_unit_id="R2",
        created_at=T0,
    )

    assert center.request_by_idempotency_key("T1", "K1").request_id == "R1"
    assert center.request_by_idempotency_key("T2", "K1").request_id == "R2"
    assert center.request_by_idempotency_key("T3", "K1") is None


def test_the_catalogue_outlives_the_link_that_advertised_it(
    center: CenterStore,
) -> None:
    """A node that lost its socket has not withdrawn its model.

    This is what keeps ``model_not_found`` honest: it answers a model no node of
    this center runs, not a model whose nodes are all mid-restart — the second is
    contention, and contention is what the queue holds.
    """
    store_node = NodeRecord(
        node_id="N1",
        device_id="dev-1",
        provider_id="prov-1",
        adapter_name="ollama",
        model="llama",
        share_enabled=True,
        max_concurrency=2,
        max_local_reserved_milli_credits=500,
        policy_version=1,
        connected=True,
        last_seen_at=T0,
    )
    center.upsert_node(store_node)
    assert center.catalogued_models() == {"llama"}

    center.set_node_connected("N1", connected=False, at=T1)
    assert center.connected_nodes() == []
    assert center.catalogued_models() == {"llama"}

    center.upsert_node(
        NodeRecord(**{**store_node.__dict__, "share_enabled": False, "connected": True})
    )
    assert center.catalogued_models() == set(), "a node that paused withdrew its model"


def test_a_database_from_before_sessions_gains_the_columns_it_needs(
    tmp_path: Path,
) -> None:
    """An upgraded center keeps its requests, its keys and its attempts.

    Every column this release adds is read back by a path that runs on every
    request, so a database an earlier release created has to gain them at open
    rather than fail the first admission — and a row written before they existed
    has to read back as the honest absence: no session, no key window, no refusal.
    """
    path = tmp_path / "center.db"
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "CREATE TABLE requests (request_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL,"
            " subject_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,"
            " payload_digest TEXT NOT NULL, delivery_mode TEXT NOT NULL,"
            " max_attempts INTEGER NOT NULL, service_unit_id TEXT NOT NULL,"
            " status TEXT NOT NULL, selected_attempt_id TEXT, deadline_at TEXT,"
            " billing_note TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,"
            " UNIQUE (tenant_id, idempotency_key))"
        )
        connection.execute(
            "CREATE TABLE attempts (attempt_id TEXT PRIMARY KEY,"
            " request_id TEXT NOT NULL, node_id TEXT, resource_id TEXT NOT NULL,"
            " provider_id TEXT NOT NULL, dispatch_epoch INTEGER NOT NULL,"
            " status TEXT NOT NULL, output_eligible INTEGER NOT NULL,"
            " usage_status TEXT NOT NULL, usage_tokens INTEGER,"
            " settlement_status TEXT NOT NULL, execution_state TEXT,"
            " updated_at TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE api_keys (key_id TEXT PRIMARY KEY, key_hash TEXT NOT NULL UNIQUE,"
            " name TEXT NOT NULL DEFAULT '', subject_id TEXT NOT NULL,"
            " tenant_id TEXT NOT NULL, quota_milli_credits INTEGER NOT NULL,"
            " used_milli_credits INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,"
            " created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT,"
            " last_used_at TEXT)"
        )
        stamp = T0.strftime("%Y-%m-%dT%H:%M:%S.%f%z")
        connection.execute(
            "INSERT INTO requests (request_id, tenant_id, subject_id, idempotency_key,"
            " payload_digest, delivery_mode, max_attempts, service_unit_id, status,"
            " created_at, updated_at) VALUES ('R-legacy', 'T1', 'subject-1', 'K-legacy',"
            " 'sha256:legacy', 'buffered_complete', 1, 'R-legacy', 'SUCCEEDED', ?, ?)",
            (stamp, stamp),
        )
        connection.execute(
            "INSERT INTO attempts (attempt_id, request_id, node_id, resource_id,"
            " provider_id, dispatch_epoch, status, output_eligible, usage_status,"
            " settlement_status, updated_at)"
            " VALUES ('A-legacy', 'R-legacy', 'N1', 'res-1', 'provider-1', 1,"
            " 'COMPLETED', 1, 'COMPLETE', 'SETTLED', ?)",
            (stamp,),
        )
        connection.execute(
            "INSERT INTO api_keys (key_id, key_hash, name, subject_id, tenant_id,"
            " quota_milli_credits, status, created_at)"
            " VALUES ('apikey-legacy', ?, 'old', 'subject-1', 'T1', 5000, 'active', ?)",
            (canonical_digest("ak-legacy"), stamp),
        )
        connection.commit()
    finally:
        connection.close()

    store = CenterStore.open(path)
    try:
        legacy = store.get_request("R-legacy")
        assert legacy is not None
        assert legacy.session_id is None
        assert legacy.api_key_id is None
        attempt = store.get_attempt("A-legacy")
        assert attempt is not None
        assert attempt.refused_before_execution is False
        keys = store.list_api_keys()
        assert len(keys) == 1 and keys[0].deadline_ms is None
        assert store.sessions() == []
        assert store.count_budget_attempts("R-legacy") == 1
        # The upgraded store writes the new shape beside the old rows.
        _session_request(store, request_id="R-new", session_id="sess-new", at=T1)
        assert store.session("T1", "subject-1", "sess-new") is not None
    finally:
        store.close()
