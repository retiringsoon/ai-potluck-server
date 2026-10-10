"""Two-sided reconciliation, operator side: read the center's own books.

The platform's trust claim is that nobody can quietly rewrite history, because
each party keeps its own record of the same event. The center holds receipts,
settlements, ledger journals and a Merkle transparency log; any one of those
can be lost or edited on its own. Making the disagreement *visible* is what
this module does. It never freezes an account, never writes a row, and never
resolves a difference — it reports the difference and names the record, and a
person decides what to do.

Two views live here, both the operator's:

`verify_receipt_at_center`
    One receipt through `aipotluck.verify.verify_offline`'s five dimensions,
    read from the center's own store, which is the only view that holds the
    signed usage report, so every dimension is assessable.

`reconcile_center`
    Every invariant tying ``attempts``, ``settlements``, ``receipts``,
    ``log_leaves`` and the ledger replay log together, checked in both
    directions, because a record that points at a missing neighbour and a
    neighbour that points at a missing record are different defects with
    different culprits.

The consumer and contributor views (`verify_receipt_from_center`,
`reconcile_node`) and the shared verdict shapes (`Difference`,
`ReceiptVerification`) live in :mod:`aipotluck.reconcile` in the client
package; this module imports them, so one spelling of a verdict covers both
sides.

Every function here is read-only. Nothing opens a write transaction; callers
pass in stores they opened themselves and close them. A caller reading
somebody else's database opens it with `CenterStore.open_existing`, so a path
that names nothing is refused rather than created: an empty database holds no
rows, and no rows report no differences.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence
from typing import Any, cast

from aipotluck.allocation import AllocationContract
from aipotluck.canonical import loads_strict
from aipotluck.errors import PotluckError
from aipotluck.identity import IdentityRegistry
from aipotluck.ledger import Journal, Posting
from aipotluck.reconcile import Difference, ReceiptVerification, claimed_leaf_bytes
from aipotluck.records import SignedRecord, signed_record_from_dict
from aipotluck.transparency import InclusionProof, MerkleLog
from aipotluck.verify import VerificationInput, verify_offline

from .gateway_service import derive_allocation_contract
from .persistence import (
    AttemptRecord,
    CenterStore,
    LogLeafRecord,
    ReceiptRecord,
    RequestRecord,
    SettlementRecord,
)

# --------------------------------------------------------------------------
# Receipt verification, operator side: read the center's own store
# --------------------------------------------------------------------------


def verify_receipt_at_center(
    *, store: CenterStore, registry: IdentityRegistry, receipt_id: str
) -> ReceiptVerification:
    """Verify one receipt against the center store that issued it.

    Everything the five dimensions need is re-derived from durable rows rather
    than taken from an in-memory book: the log is rebuilt from ``log_leaves``,
    the inclusion proof is recomputed over that rebuild, the leaf bytes come from
    the receipt's own signed ``settled_at``, and the allocation contract is
    re-derived from the winner attempt's provider and epoch. A row somebody
    edited therefore contradicts a fact that is signed or recomputed, instead of
    agreeing with itself.

    The trusted root is the one the stored leaves fold to. That is the
    operator's own log, so it detects a leaf that was lost, moved or edited; it
    cannot detect a log that was rebuilt wholesale and re-checkpointed, which is
    what a consumer holding an older checkpoint is for.

    Args:
        store: The center's store, opened read-only by the caller.
        registry: The trusted keys, holding at least the settlement key and any
            device key whose usage report is checked here.
        receipt_id: The receipt to verify.

    Returns:
        The verification. A receipt the store does not hold comes back as a
        finding naming it, not as an exception: "this record is gone" is the
        answer an operator asked for, not a crash.
    """
    stored = store.get_receipt(receipt_id)
    if stored is None:
        return ReceiptVerification(
            receipt_id=receipt_id,
            source="center-store",
            findings=(
                f"receipt {receipt_id} is not in the center's receipts table, so the "
                "charge it would have proved has no record here",
            ),
        )
    findings: list[str] = []
    record = _stored_receipt_record(stored, findings)
    if record is None:
        return ReceiptVerification(
            receipt_id=receipt_id, source="center-store", findings=tuple(findings)
        )
    if record.hash != stored.receipt_hash:
        findings.append(
            f"receipt {receipt_id} is stored under hash {stored.receipt_hash} but its "
            f"own payload hashes to {record.hash}; the stored body was edited"
        )

    log, leaf_findings = _log_from_leaves(store.log_leaves())
    findings.extend(leaf_findings)
    proof = _proof_at(log, stored.log_index, receipt_id, findings)
    leaf_bytes = claimed_leaf_bytes(record, stored, findings)

    winner = _winner_attempt(store, record)
    contract = (
        derive_allocation_contract(
            request_id=winner.request_id,
            provider_id=winner.provider_id,
            epoch=winner.dispatch_epoch,
        )
        if winner is not None
        else None
    )
    if winner is None:
        findings.append(
            f"receipt {receipt_id} names winner attempt "
            f"{str(record.payload.get('winner_attempt_id'))!r}, which the attempts table "
            "does not hold, so its allocation contract cannot be re-derived"
        )

    journal = _journal_for_receipt(store, record)
    if journal is None:
        findings.append(
            f"receipt {receipt_id} names journal {str(record.payload.get('journal_id'))!r}, "
            "which the ledger replay log does not contain, so the money movement it "
            "promises is not on the books"
        )
    usage_reports = _usage_reports_for(store, record, winner)

    contracts: dict[str, AllocationContract] = {}
    if contract is not None:
        contracts[str(record.payload.get("allocation_contract_hash", ""))] = contract
    report = verify_offline(
        VerificationInput(
            registry=registry,
            authorizations=_authorizations_for(store, record),
            usage_reports=usage_reports,
            receipts=(record,),
            journals=() if journal is None else (journal,),
            contracts=contracts,
            inclusion_proofs={} if proof is None else {record.hash: proof},
            leaf_bytes={} if leaf_bytes is None else {record.hash: leaf_bytes},
            trusted_root=log.root() if log is not None and log.size() else None,
            # The center side promises exactly one receipt: the one named. The
            # whole-account cross-check is `reconcile_center`, which sees every
            # receipt at once; repeating it here would only restate it.
            expected_receipt_ids=(receipt_id,),
        )
    )
    return ReceiptVerification(
        receipt_id=receipt_id, source="center-store", report=report, findings=tuple(findings)
    )


def _stored_receipt_record(
    stored: ReceiptRecord, findings: list[str] | None = None
) -> SignedRecord | None:
    """Rebuild the signed record a receipt row carries.

    Args:
        stored: The receipt row.
        findings: Appended with the reason when the row cannot be read. `None`
            discards it, for a caller that reports the failure itself.

    Returns:
        The record, or `None` when the stored JSON is not one.
    """
    reported: list[str] = [] if findings is None else findings
    try:
        document = loads_strict(stored.receipt_json)
    except PotluckError as exc:
        reported.append(f"receipt {stored.receipt_id} is not readable JSON: {exc}")
        return None
    if not isinstance(document, dict):
        reported.append(
            f"receipt {stored.receipt_id} is stored as a JSON {type(document).__name__}, "
            "not an object"
        )
        return None
    try:
        return signed_record_from_dict(cast("dict[str, Any]", document))
    except PotluckError as exc:
        reported.append(
            f"receipt {stored.receipt_id} is not a complete signed record: {exc}"
        )
        return None


def _log_from_leaves(leaves: Sequence[LogLeafRecord]) -> tuple[MerkleLog | None, list[str]]:
    """Replay stored leaves into a log, or report why no log can be trusted.

    A leaf is appended at its stored index, so the rebuilt positions must equal
    the stored ones. When they do not — a lost, duplicated or re-indexed leaf —
    this returns no log at all rather than a compacted one. Compacting would fold
    the surviving leaves into a shorter tree and then serve a proof over it, and
    that proof would vouch for a history the center is not actually serving:
    exactly what `GatewayService._rebuild_log` refuses to do for the same reason.
    Returning nothing makes `ledger_included` fail on the receipt whose leaf is
    missing, which names the loss instead of hiding it behind a valid-looking
    proof.

    Args:
        leaves: The stored leaves, in index order.

    Returns:
        ``(log, findings)``. `log` is `None` when the stored leaves are not
        exactly ``0..n-1``.
    """
    findings: list[str] = []
    log = MerkleLog()
    for position, leaf in enumerate(leaves):
        if leaf.log_index != position:
            findings.append(
                f"log leaf at position {position} claims index {leaf.log_index}; the "
                "stored log is not contiguous, so no inclusion proof over it can be "
                "trusted and none is served here"
            )
            return None, findings
        log.append(leaf.receipt_hash, leaf.committed_at)
    return log, findings


def _proof_at(
    log: MerkleLog | None, index: int, receipt_id: str, findings: list[str]
) -> InclusionProof | None:
    """Build the inclusion proof for `index`, reporting why there is none.

    Args:
        log: The log rebuilt from the stored leaves, or `None` when it could not
            be rebuilt soundly.
        index: The position the receipt claims.
        receipt_id: Named in the finding so the report points at a record.
        findings: Appended when no proof can be built.

    Returns:
        The proof, or `None` when the claimed position is outside the log.
    """
    if log is None:
        return None
    if 0 <= index < log.size():
        return log.inclusion_proof(index)
    findings.append(
        f"receipt {receipt_id} claims log index {index} but the stored log holds "
        f"{log.size()} leaf/leaves; its leaf is missing from the transparency log"
    )
    return None



def _winner_attempt(store: CenterStore, record: SignedRecord) -> AttemptRecord | None:
    """Return the attempt a receipt names as its winner, if the store holds it."""
    attempt_id = record.payload.get("winner_attempt_id")
    if not isinstance(attempt_id, str) or not attempt_id:
        return None
    return store.get_attempt(attempt_id)


def _journal_for_receipt(store: CenterStore, record: SignedRecord) -> Journal | None:
    """Return the ledger journal a receipt names, replayed from the store's log.

    Args:
        store: The center's store.
        record: The receipt's signed record, whose payload names the journal.

    Returns:
        The journal, or `None` when the replay log does not carry it or carries it
        in a shape this build cannot read.
    """
    journal_id = record.payload.get("journal_id")
    if not isinstance(journal_id, str) or not journal_id:
        return None
    for _seq, kind, payload in store.ledger_events():
        if kind != "journal" or payload.get("journal_id") != journal_id:
            continue
        return _journal_from_payload(payload)
    return None


def _journal_from_payload(payload: Mapping[str, Any]) -> Journal | None:
    """Rebuild one journal from its ledger-replay payload.

    Returns:
        The journal, or `None when the payload is malformed. A malformed journal
        is reported by the caller as a missing one, which is the honest summary:
        the books cannot be replayed from it either.
    """
    try:
        postings = tuple(
            Posting(str(account), int(delta))
            for account, delta in cast("Sequence[Sequence[Any]]", payload["postings"])
        )
        key = tuple(str(part) for part in cast("Sequence[Any]", payload["idempotency_key"]))
        if len(key) != 3:
            return None
        return Journal(
            journal_id=str(payload["journal_id"]),
            idempotency_key=(key[0], key[1], int(key[2])),
            kind=cast("Any", str(payload["kind"])),
            postings=postings,
            service_unit_id=(
                str(payload["service_unit_id"])
                if payload.get("service_unit_id") is not None
                else None
            ),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _usage_reports_for(
    store: CenterStore, record: SignedRecord, winner: AttemptRecord | None
) -> tuple[SignedRecord, ...]:
    """Return the signed usage reports the center stored for a receipt's attempt.

    The report is what makes `metering_provenance` assessable at all, and the
    center keeps it in the ``events`` table because settlement refuses an
    unsigned total. Reading it back is what lets an operator see the evidence
    level a receipt actually rests on rather than the level somebody claims.

    Args:
        store: The center's store.
        record: The receipt's signed record.
        winner: The winning attempt, or `None` when the store no longer holds it.

    Returns:
        Every readable ``usage.final`` report for that attempt.
    """
    if winner is None:
        return ()
    reports: list[SignedRecord] = []
    events = store.events_after(
        winner.request_id, 0, limit=max(1, store.max_cursor(winner.request_id))
    )
    for event in events:
        if event.event_type != "usage.final" or event.attempt_id != winner.attempt_id:
            continue
        body = event.payload.get("report")
        if not isinstance(body, dict):
            continue
        try:
            reports.append(signed_record_from_dict(cast("dict[str, Any]", body)))
        except PotluckError:
            # An unreadable report is not silently dropped: its absence would
            # read as "no usage held", which is a different and weaker claim.
            reports.append(_unsigned_placeholder(cast("dict[str, Any]", body)))
    return tuple(reports)


def _unsigned_placeholder(body: Mapping[str, Any]) -> SignedRecord:
    """Return a record shape whose signature cannot verify.

    Used when a stored usage report is malformed. Handing `verify_offline` a
    record with an empty signature makes `signature_valid` fail and name the
    record, which is the truth; omitting it would report "no usage reports
    held" and hide a corrupted row behind an ``unknown``.
    """
    return SignedRecord(
        schema=str(body.get("schema", "")),
        record_id=str(body.get("record_id", "<unreadable>")),
        revision=0,
        signed_at=dt.datetime.now(dt.UTC),
        signer_key_id=str(body.get("signer_key_id", "")),
        signer_id=str(body.get("signer_id", "")),
        signature="",
        payload={},
    )


def _authorizations_for(store: CenterStore, record: SignedRecord) -> tuple[SignedRecord, ...]:
    """Return the signed spend authorization behind a receipt's request.

    Args:
        store: The center's store.
        record: The receipt's signed record.

    Returns:
        The authorization, or an empty tuple when the request's stored dispatch
        inputs are gone — which `reconcile_center` reports separately.
    """
    request_id = record.payload.get("request_id")
    if not isinstance(request_id, str) or not request_id:
        return ()
    inputs = store.get_request_input(request_id)
    if inputs is None:
        return ()
    body = inputs.get("authorization")
    if not isinstance(body, dict):
        return ()
    try:
        return (signed_record_from_dict(cast("dict[str, Any]", body)),)
    except PotluckError:
        return ()



# --------------------------------------------------------------------------
# Center-side reconciliation: invariants across the store's own tables
# --------------------------------------------------------------------------


def reconcile_center(*, store: CenterStore) -> list[Difference]:
    """Cross-check every durable invariant a center's tables assert about each other.

    This is the operator's inspection pass, and it reads only the store: no
    service, no in-memory book, no network. Each check runs in both directions
    where a direction exists, because the two point at different culprits — a
    settlement naming a receipt that is gone says something deleted the receipt,
    while a receipt no settlement names says something minted a receipt outside
    the settlement path.

    Covered: attempt/settlement agreement; settlement/receipt agreement on id,
    hash and log position; receipt/log-leaf agreement in both directions; log
    contiguity and duplicate leaves; receipt/request existence and status; the
    winner attempt behind a receipt; billable amount against the attempt's
    recorded usage and against the journal the receipt names; a stored receipt
    body that no longer hashes to its own stored hash; and a succeeded request
    with nothing to show for it.

    Args:
        store: The center's store, opened read-only by the caller.

    Returns:
        The differences, ordered so the same database renders the same report.
        Empty means every invariant held.
    """
    differences: list[Difference] = []
    attempts = store.attempts()
    settlements = store.settlements()
    receipts = store.receipts()
    leaves = store.log_leaves()
    requests = {request.request_id: request for request in store.requests()}
    journals = _replayed_journals(store)

    differences.extend(_check_settled_attempts(attempts, settlements))
    differences.extend(_check_settlements(settlements, receipts))
    differences.extend(_check_receipts(receipts, settlements, leaves, requests, journals, store))
    differences.extend(_check_leaves(leaves, receipts))
    differences.extend(_check_succeeded_requests(requests, settlements, receipts))
    return sorted(differences, key=lambda item: (item.subject, item.kind))


def _replayed_journals(store: CenterStore) -> dict[str, Journal]:
    """Return every journal in the ledger replay log, keyed by journal id."""
    journals: dict[str, Journal] = {}
    for _seq, kind, payload in store.ledger_events():
        if kind != "journal":
            continue
        journal = _journal_from_payload(payload)
        if journal is not None:
            journals[journal.journal_id] = journal
    return journals


def _settlement_by_unit(settlements: Sequence[SettlementRecord]) -> dict[str, SettlementRecord]:
    """Index settlement revisions by service unit, keeping the highest revision."""
    latest: dict[str, SettlementRecord] = {}
    for settlement in settlements:
        current = latest.get(settlement.service_unit_id)
        if current is None or settlement.revision > current.revision:
            latest[settlement.service_unit_id] = settlement
    return latest


def _check_settled_attempts(
    attempts: Sequence[AttemptRecord], settlements: Sequence[SettlementRecord]
) -> list[Difference]:
    """Report an attempt the center marked settled with no settlement behind it."""
    differences: list[Difference] = []
    by_unit = _settlement_by_unit(settlements)
    for attempt in attempts:
        if attempt.settlement_status != "SETTLED":
            continue
        settlement = by_unit.get(attempt.request_id)
        subject = f"attempt {attempt.attempt_id}"
        local = f"request={attempt.request_id} settlement_status={attempt.settlement_status}"
        if settlement is None:
            differences.append(
                Difference(
                    subject=subject,
                    kind="settled_attempt_without_settlement",
                    local=local,
                    remote="<no settlement revision for this request>",
                )
            )
            continue
        if settlement.receipt_id is None or not settlement.receipt_id:
            differences.append(
                Difference(
                    subject=subject,
                    kind="settled_attempt_without_receipt",
                    local=local,
                    remote=f"settlement revision {settlement.revision} names no receipt",
                )
            )
    return differences


def _check_settlements(
    settlements: Sequence[SettlementRecord], receipts: Sequence[ReceiptRecord]
) -> list[Difference]:
    """Report a settlement whose receipt is missing or disagrees with it."""
    differences: list[Difference] = []
    by_id = {receipt.receipt_id: receipt for receipt in receipts}
    for settlement in settlements:
        subject = f"settlement {settlement.service_unit_id} revision {settlement.revision}"
        local = (
            f"receipt={settlement.receipt_id} hash={settlement.receipt_hash} "
            f"log_index={settlement.log_index}"
        )
        receipt = by_id.get(settlement.receipt_id)
        if receipt is None:
            differences.append(
                Difference(
                    subject=subject,
                    kind="settlement_without_receipt",
                    local=local,
                    remote=f"<receipt {settlement.receipt_id} is not in the receipts table>",
                )
            )
            continue
        if receipt.receipt_hash != settlement.receipt_hash:
            differences.append(
                Difference(
                    subject=subject,
                    kind="settlement_receipt_hash_mismatch",
                    local=local,
                    remote=f"the receipt row hashes to {receipt.receipt_hash}",
                )
            )
        if receipt.log_index != settlement.log_index:
            differences.append(
                Difference(
                    subject=subject,
                    kind="settlement_receipt_log_index_mismatch",
                    local=local,
                    remote=f"the receipt row claims log index {receipt.log_index}",
                )
            )
    return differences


def _check_receipts(
    receipts: Sequence[ReceiptRecord],
    settlements: Sequence[SettlementRecord],
    leaves: Sequence[LogLeafRecord],
    requests: Mapping[str, RequestRecord],
    journals: Mapping[str, Journal],
    store: CenterStore,
) -> list[Difference]:
    """Report everything a receipt must have behind it, and every way it can lie."""
    differences: list[Difference] = []
    settlement_ids = {settlement.receipt_id for settlement in settlements}
    leaf_by_index = {leaf.log_index: leaf.receipt_hash for leaf in leaves}
    leaf_by_hash = {leaf.receipt_hash: leaf.log_index for leaf in leaves}
    seen_hashes: dict[str, str] = {}

    for stored in receipts:
        subject = f"receipt {stored.receipt_id}"
        local = (
            f"request={stored.request_id} hash={stored.receipt_hash} "
            f"log_index={stored.log_index}"
        )
        if stored.receipt_id not in settlement_ids:
            differences.append(
                Difference(
                    subject=subject,
                    kind="orphan_receipt",
                    local=local,
                    remote="<no settlement revision names this receipt>",
                )
            )
        previous = seen_hashes.get(stored.receipt_hash)
        if previous is not None:
            differences.append(
                Difference(
                    subject=subject,
                    kind="duplicate_receipt_hash",
                    local=local,
                    remote=f"receipt {previous} is stored under the same hash",
                )
            )
        else:
            seen_hashes[stored.receipt_hash] = stored.receipt_id

        logged_at = leaf_by_hash.get(stored.receipt_hash)
        if logged_at is None:
            differences.append(
                Difference(
                    subject=subject,
                    kind="receipt_without_log_leaf",
                    local=local,
                    remote="<the transparency log holds no leaf for this receipt hash>",
                )
            )
        elif logged_at != stored.log_index:
            differences.append(
                Difference(
                    subject=subject,
                    kind="receipt_log_index_mismatch",
                    local=local,
                    remote=f"the log holds this hash at index {logged_at}",
                )
            )
        elif leaf_by_index.get(stored.log_index) != stored.receipt_hash:
            differences.append(
                Difference(
                    subject=subject,
                    kind="log_leaf_holds_another_receipt",
                    local=local,
                    remote=(
                        f"log index {stored.log_index} holds "
                        f"{leaf_by_index[stored.log_index]}"
                    ),
                )
            )

        if stored.request_id not in requests:
            differences.append(
                Difference(
                    subject=subject,
                    kind="receipt_without_request",
                    local=local,
                    remote=f"<request {stored.request_id} is not in the requests table>",
                )
            )
        else:
            request = requests[stored.request_id]
            if request.status != "SUCCEEDED":
                differences.append(
                    Difference(
                        subject=subject,
                        kind="receipt_for_unsucceeded_request",
                        local=local,
                        remote=f"request {stored.request_id} has status {request.status}",
                    )
                )
        differences.extend(_check_receipt_payload(stored, journals, store))
    return differences


def _check_receipt_payload(
    stored: ReceiptRecord, journals: Mapping[str, Journal], store: CenterStore
) -> list[Difference]:
    """Report a receipt whose body disagrees with its hash, its attempt or its journal.

    The amount checks are the ones that catch a rewritten number rather than a
    deleted row: the billable total must equal the sum the receipt's own postings
    credit, must equal the usage the winner attempt recorded, and must equal what
    the ledger journal actually posted. Those three come from three different
    tables, so agreeing by accident is not available to an edit.
    """
    differences: list[Difference] = []
    subject = f"receipt {stored.receipt_id}"
    local = f"hash={stored.receipt_hash} log_index={stored.log_index}"
    record = _stored_receipt_record(stored)
    if record is None:
        return [
            Difference(
                subject=subject,
                kind="unreadable_receipt",
                local=local,
                remote="<the stored receipt_json is not a readable signed record>",
            )
        ]
    if record.hash != stored.receipt_hash:
        differences.append(
            Difference(
                subject=subject,
                kind="receipt_hash_mismatch",
                local=local,
                remote=f"the stored body hashes to {record.hash}; it was edited",
            )
        )
    payload = record.payload
    billable = _payload_int(payload.get("billable_tokens"))
    credited = 0
    for posting in _payload_postings(payload):
        if not isinstance(posting, Mapping):
            continue
        delta = _payload_int(posting.get("delta"))
        if delta is not None and delta > 0:
            credited += delta
    if billable is None:
        differences.append(
            Difference(
                subject=subject,
                kind="receipt_without_billable_total",
                local=local,
                remote="<the signed payload carries no billable_tokens>",
            )
        )
    elif credited != billable:
        differences.append(
            Difference(
                subject=subject,
                kind="receipt_postings_mismatch",
                local=f"billable_tokens={billable}",
                remote=f"its own postings credit {credited}",
            )
        )

    journal_id = payload.get("journal_id")
    journal = journals.get(str(journal_id)) if isinstance(journal_id, str) else None
    if journal is None:
        differences.append(
            Difference(
                subject=subject,
                kind="receipt_without_journal",
                local=f"journal_id={journal_id!r}",
                remote="<the ledger replay log holds no such journal>",
            )
        )
    elif billable is not None:
        posted = sum(posting.delta for posting in journal.postings if posting.delta > 0)
        if posted != billable:
            differences.append(
                Difference(
                    subject=subject,
                    kind="journal_receipt_amount_mismatch",
                    local=f"billable_tokens={billable}",
                    remote=f"journal {journal.journal_id} posted {posted}",
                )
            )
        if journal.total_delta() != 0:
            differences.append(
                Difference(
                    subject=subject,
                    kind="unbalanced_journal",
                    local=f"journal_id={journal.journal_id}",
                    remote=f"its postings sum to {journal.total_delta()}, not 0",
                )
            )

    winner_id = payload.get("winner_attempt_id")
    winner = store.get_attempt(str(winner_id)) if isinstance(winner_id, str) else None
    if winner is None:
        differences.append(
            Difference(
                subject=subject,
                kind="receipt_without_winner_attempt",
                local=f"winner_attempt_id={winner_id!r}",
                remote="<the attempts table holds no such attempt>",
            )
        )
    else:
        if winner.settlement_status != "SETTLED":
            differences.append(
                Difference(
                    subject=subject,
                    kind="winner_attempt_not_settled",
                    local=local,
                    remote=(
                        f"attempt {winner.attempt_id} has settlement_status "
                        f"{winner.settlement_status}"
                    ),
                )
            )
        if billable is not None and winner.usage_tokens != billable:
            differences.append(
                Difference(
                    subject=subject,
                    kind="receipt_usage_amount_mismatch",
                    local=f"billable_tokens={billable}",
                    remote=(
                        f"attempt {winner.attempt_id} recorded usage_tokens="
                        f"{winner.usage_tokens}"
                    ),
                )
            )
    return differences


def _check_leaves(
    leaves: Sequence[LogLeafRecord], receipts: Sequence[ReceiptRecord]
) -> list[Difference]:
    """Report a log leaf with no receipt behind it, and any gap in the log."""
    differences: list[Difference] = []
    receipt_by_hash = {receipt.receipt_hash: receipt.receipt_id for receipt in receipts}
    for position, leaf in enumerate(leaves):
        if leaf.log_index != position:
            differences.append(
                Difference(
                    subject=f"log index {position}",
                    kind="log_gap",
                    local=f"the stored leaf at position {position} claims index {leaf.log_index}",
                    remote="indices must run 0..n-1 with no gap or duplicate",
                )
            )
        receipt_id = receipt_by_hash.get(leaf.receipt_hash)
        if receipt_id is None:
            differences.append(
                Difference(
                    subject=f"log index {leaf.log_index}",
                    kind="log_leaf_without_receipt",
                    local=f"hash={leaf.receipt_hash}",
                    remote="<no receipt is stored under this hash>",
                )
            )
    return differences


def _check_succeeded_requests(
    requests: Mapping[str, RequestRecord],
    settlements: Sequence[SettlementRecord],
    receipts: Sequence[ReceiptRecord],
) -> list[Difference]:
    """Report a request marked succeeded with no settlement or no receipt to show."""
    differences: list[Difference] = []
    by_unit = _settlement_by_unit(settlements)
    receipt_ids = {receipt.receipt_id for receipt in receipts}
    for request_id, request in requests.items():
        if request.status != "SUCCEEDED":
            continue
        subject = f"request {request_id}"
        settlement = by_unit.get(request_id)
        if settlement is None:
            differences.append(
                Difference(
                    subject=subject,
                    kind="succeeded_request_without_settlement",
                    local="status=SUCCEEDED",
                    remote="<no settlement revision for this request>",
                )
            )
        elif settlement.receipt_id not in receipt_ids:
            differences.append(
                Difference(
                    subject=subject,
                    kind="succeeded_request_without_receipt",
                    local=f"status=SUCCEEDED settlement names {settlement.receipt_id}",
                    remote="<that receipt is not in the receipts table>",
                )
            )
    return differences


def _payload_int(value: Any) -> int | None:
    """Return a signed payload's integer field, which arrives as a decimal string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def _payload_postings(payload: Mapping[str, Any]) -> Sequence[Any]:
    """Return a receipt payload's postings array, empty when it has none."""
    postings = payload.get("postings")
    if isinstance(postings, Sequence) and not isinstance(postings, (str, bytes)):
        return postings
    return ()
