"""
v2 check engine — s19_app batch-07, increment E4.

This module is the **pure-function half** of HLR-004: it takes a v2 check
:class:`ChangeDocument` (``kind="check"`` — the same reader and rule table
as change documents, LLR-004.1) plus read-only snapshots of the loaded image
(``LoadedFile.mem_map`` / ``.ranges``) and the informative linkage sources
(``LoadedFile.mac_records`` / enriched A2L tags), and produces the §6.2 C-6
:class:`CheckRunResult` — comparing each entry's expected encoded bytes
against the image without writing anything (LLR-004.2: execution mutates
nothing in the memory map).

Gate semantics (batch-33 R-B02, §6.5 amendment — the apply-gate MIRROR is
RETIRED for checks per the operator decision 2026-07-09; the apply gate
itself is untouched): ``kind`` != ``"check"`` blocks the whole run with one
loud run-level reason (``doc-kind``); ERROR issues whose codes fall OUTSIDE
the entry-scoped non-blocking set block the run with a ``doc-fault`` reason
(fail-safe for envelope/unknown codes). A runnable document with
entry-scoped faults checks its HEALTHY entries normally — only entries
tainted by a taint-attribution code (today: a collision partner, matched by
start address) become ``uncheckable`` (``entry-fault``). Every
``uncheckable`` outcome carries a ``reason_code`` + display ``reason``;
the result still carries the document's collected issues (B-2).

The containment and linkage machinery is **reused** from ``changes/apply.py``
(``classify_containment`` plus the module-private linkage helpers) — one
classifier, never a duplicate.

Thread placement (the LLR-002.4 contract extended to E4): everything here is
a pure function over its arguments with **no Textual import** (LLR-004.4);
the TUI invokes it through the service layer's ``check_runner`` seam.

Per constraint C-9, issue messages name addresses, file names, and counts —
never raw byte or value content.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ...validation.model import ValidationSeverity
from .apply import (
    _a2l_linkage_source,
    _classify_linkage,
    _linkage_index,
    _mac_linkage_source,
    classify_containment,
)
from .io import (
    CHG_ADDRESS_SYNTAX,
    CHG_BYTES_SYNTAX,
    CHG_DECL_STRUCTURE,
    CHG_ENCODE_FAIL,
    CHG_VALUE_EMPTY,
    MF_ENTRY_LIMIT,
)
from .model import (
    CHECK_AGGREGATE_KEYS,
    CHECK_FAIL,
    CHECK_PASS,
    CHECK_REASON_DOC_FAULT,
    CHECK_REASON_DOC_KIND,
    CHECK_REASON_ENTRY_FAULT,
    CHECK_REASON_NO_IMAGE,
    CHECK_REASON_OUTSIDE,
    CHECK_REASON_PARTIAL,
    CHECK_UNCHECKABLE,
    ChangeDocument,
    CheckRunEntry,
    CheckRunResult,
    MemoryStatus,
)
from .validate import CHG_COLLISION

__all__ = ["run_check_document"]

#: Result token → aggregate-count key (LLR-004.3 — ``pass`` counts under
#: ``passed``, ``fail`` under ``failed``, ``uncheckable`` under itself).
_RESULT_TO_AGGREGATE = {
    CHECK_PASS: "passed",
    CHECK_FAIL: "failed",
    CHECK_UNCHECKABLE: "uncheckable",
}

#: batch-33 (LLR-050.1 set (a)) — ERROR codes that are ENTRY-SCOPED, so a
#: document carrying only these stays RUNNABLE (checks are read-only; the
#: apply-gate mirror is retired for checks per the operator decision
#: 2026-07-09). Any ERROR code OUTSIDE this set is document-blocking — the
#: fail-safe default for envelope faults and unknown/future codes.
_CHECK_NON_BLOCKING_CODES: frozenset[str] = frozenset(
    {
        CHG_ADDRESS_SYNTAX,
        CHG_BYTES_SYNTAX,
        CHG_VALUE_EMPTY,
        CHG_ENCODE_FAIL,
        MF_ENTRY_LIMIT,
        CHG_COLLISION,
        CHG_DECL_STRUCTURE,
    }
)

#: batch-33 (LLR-050.1 set (b), Phase-2 B-1) — the codes whose issues taint a
#: CONSTRUCTED entry by address equality. ONLY codes emitted AGAINST
#: constructed entries belong here (today exactly the collision fault,
#: ``validate.py`` — one finding per partner, ``address=entry.address``).
#: Reader skip-site codes are non-blocking AND non-tainting: a skipped
#: declaration must never taint a healthy constructed entry that happens to
#: share its address (the B-1 false-taint mode).
_CHECK_TAINT_ATTRIBUTION_CODES: frozenset[str] = frozenset({CHG_COLLISION})

#: batch-33 (LLR-051.3, Phase-2 F2): display bounds — ``{kind!r}`` is capped
#: to this many characters (with an ellipsis marker) and the doc-fault
#: ``{codes}`` list is deduplicated and capped to this many codes.
_REASON_KIND_DISPLAY_CAP = 64
_REASON_CODES_DISPLAY_CAP = 5

#: Containment verdict → (reason_code, display reason) for the per-entry
#: uncheckable outcomes (LLR-051.1; §1.3 taxonomy).
_CONTAINMENT_REASONS = {
    MemoryStatus.PARTIAL: (
        CHECK_REASON_PARTIAL,
        "range partially outside the loaded image [partial]",
    ),
    MemoryStatus.OUTSIDE: (
        CHECK_REASON_OUTSIDE,
        "range outside the loaded image [outside]",
    ),
    MemoryStatus.UNVALIDATED_NO_IMAGE: (
        CHECK_REASON_NO_IMAGE,
        "no image loaded",
    ),
}


def _display_kind(kind: str) -> str:
    """
    Summary:
        Render the document's ``kind`` for a reason string: ``repr`` (keeps
        control-character escaping) display-capped at
        :data:`_REASON_KIND_DISPLAY_CAP` characters with an ellipsis marker
        (LLR-051.3, Phase-2 F2 — a pathological kind string must not hang
        the render surfaces).

    Args:
        kind (str): The document's verbatim ``kind`` value (file-derived).

    Returns:
        str: The capped ``repr`` text.

    Data Flow:
        - Used only inside the ``doc-kind`` run-block reason template.

    Dependencies:
        Used by:
            - run_check_document
    """
    rendered = repr(kind)
    if len(rendered) <= _REASON_KIND_DISPLAY_CAP:
        return rendered
    return rendered[: _REASON_KIND_DISPLAY_CAP] + "…(capped)"


def _blocking_codes_display(codes: list[str]) -> str:
    """
    Summary:
        Render the blocking issue-code list for the ``doc-fault`` reason:
        sorted, DEDUPLICATED, capped at :data:`_REASON_CODES_DISPLAY_CAP`
        codes with a ``+N more`` marker (LLR-051.3, Phase-2 F2 — one
        pathological file must not produce a multi-MB reason).

    Args:
        codes (list[str]): The blocking ERROR codes, possibly duplicated.

    Returns:
        str: e.g. ``"MF-BAD-STRUCTURE, MF-JSON-PARSE"`` or
        ``"A, B, C, D, E +3 more"``.

    Data Flow:
        - Used only inside the ``doc-fault`` run-block reason template.

    Dependencies:
        Used by:
            - run_check_document
    """
    unique = sorted(set(codes))
    shown = unique[:_REASON_CODES_DISPLAY_CAP]
    suffix = (
        f" +{len(unique) - len(shown)} more" if len(unique) > len(shown) else ""
    )
    return ", ".join(shown) + suffix


def run_check_document(
    document: ChangeDocument,
    mem_map: Optional[Dict[int, int]],
    ranges: Optional[Sequence[Tuple[int, int]]],
    mac_records: Optional[Sequence[dict]],
    a2l_tags: Optional[Sequence[dict]],
    *,
    now_fn: Optional[Callable[[], datetime]] = None,
    variant_id: Optional[str] = None,
) -> CheckRunResult:
    """
    Summary:
        Execute a v2 check document against the loaded image's memory map
        and return the §6.2 C-6 :class:`CheckRunResult`
        (LLR-004.1..004.3) — a pure function over its arguments, no Textual
        anywhere (LLR-004.4), and **no mutation of the memory map**
        (LLR-004.2).

    Args:
        document (ChangeDocument): The check document to run. ``kind`` !=
            ``"check"`` or a blocking (non-entry-scoped) ERROR fault makes
            the RUN blocked: no comparisons, every entry ``uncheckable``
            with the run-level reason pair set (batch-33 LLR-050.1);
            entry-scoped faults leave the document runnable and taint only
            attributable entries. Collected issues always ride the result
            (B-2).
        mem_map (Optional[Dict[int, int]]): The loaded image's address-to-
            byte map (``LoadedFile.mem_map``) — **read-only**: actual bytes
            are read from it for fully-``INSIDE`` entries, nothing is ever
            written. May be ``None`` when no image is loaded.
        ranges (Optional[Sequence[Tuple[int, int]]]): The image's contiguous
            ranges (``LoadedFile.ranges``); ``None`` = no image, so every
            gate-passed entry is ``uncheckable``.
        mac_records (Optional[Sequence[dict]]): Parsed MAC records
            (``name`` / ``address`` / ``parse_ok`` keys) for the informative
            linkage classification (LLR-004.3).
        a2l_tags (Optional[Sequence[dict]]): Enriched A2L tags (``name`` /
            ``address`` / ``length`` keys) for the linkage classification.
        now_fn (Optional[Callable[[], datetime]]): Injectable UTC clock
            (B-4); ``None`` defaults to ``datetime.now(timezone.utc)``. The
            result records ``now_fn().isoformat()``.
        variant_id (Optional[str]): The project variant this run targets;
            recorded verbatim in the result (``None`` until US-005 lands).

    Returns:
        CheckRunResult: Result-level metadata (source path, timestamp,
        variant, all-three-keys ``aggregates``, the document's collected
        ``issues``) plus one :class:`CheckRunEntry` per document entry in
        document order — expected bytes always, actual bytes only when the
        range was fully readable, and exactly one of ``pass`` / ``fail`` /
        ``uncheckable`` per entry (LLR-004.2).

    Raises:
        KeyError: If an ``INSIDE`` entry addresses a byte missing from
            ``mem_map`` — impossible when ``ranges`` derive from the map's
            keys (the parse-layer contract); a programming error otherwise.

    Data Flow:
        - Build the MAC / A2L linkage indexes once via the sorted-range
          primitives (the LLR-002.6 machinery reused — never a linear scan).
        - Stamp containment via :func:`classify_containment` (LLR-001.6;
          the only state touched is each entry's ``status`` stamp — the
          established validation side effect, identical to apply/validate).
        - Gate (batch-33 LLR-050.1): wrong kind → ``doc-kind`` run block;
          blocking ERROR codes (outside the non-blocking set) →
          ``doc-fault`` run block; else runnable.
        - Taint attribution (LLR-050.2): taint-attribution-code issues
          (``CHG-COLLISION``) taint constructed entries by start-address
          equality → ``entry-fault``; skip-site codes never taint.
        - Otherwise per entry: ``INSIDE`` → read ``actual_bytes`` from
          ``mem_map`` and compare against ``encoded_bytes`` (equal →
          ``pass``, unequal → ``fail``); ``PARTIAL`` / ``OUTSIDE`` /
          ``UNVALIDATED_NO_IMAGE`` → ``uncheckable`` with its containment
          reason pair (LLR-051.1).
        - Linkage is classified for every entry regardless of result —
          informative only (LLR-004.3).

    Dependencies:
        Uses:
            - classify_containment (changes.apply)
            - _linkage_index / _classify_linkage (changes.apply — reused)
            - CheckRunResult / CheckRunEntry
        Used by:
            - services.change_service.ChangeService (the ``check_runner``
              seam default) and run_checks_for_project
            - tests/test_checks_engine.py

    Example:
        >>> doc = ChangeDocument(
        ...     format="s19app-changeset", version="2.0", kind="check",
        ...     encoding="utf-8", value_mode="text",
        ... )
        >>> result = run_check_document(doc, {0x100: 0xAA}, [(0x100, 0x101)], None, None)
        >>> result.aggregates
        {'passed': 0, 'failed': 0, 'uncheckable': 0}
    """
    clock: Callable[[], datetime] = (
        now_fn if now_fn is not None else (lambda: datetime.now(timezone.utc))
    )
    mac_index, mac_symbols = _linkage_index(_mac_linkage_source(mac_records))
    a2l_index, a2l_symbols = _linkage_index(_a2l_linkage_source(a2l_tags))

    classify_containment(document, ranges)

    # batch-33 gate (LLR-050.1, operator decision 2026-07-09): the collective
    # apply-gate mirror is retired for checks. Kind is evaluated FIRST; then
    # only ERROR codes OUTSIDE the entry-scoped non-blocking set block the
    # run (fail-safe for envelope/unknown codes). A runnable document with
    # entry-scoped faults checks its healthy entries normally.
    run_blocked_code: Optional[str] = None
    run_blocked_reason: Optional[str] = None
    if document.kind != "check":
        run_blocked_code = CHECK_REASON_DOC_KIND
        run_blocked_reason = (
            f"this is a change-set (kind {_display_kind(document.kind)}), "
            "not a check-set — Run checks needs kind 'check'"
        )
    else:
        blocking_codes = [
            issue.code
            for issue in document.issues
            if issue.severity is ValidationSeverity.ERROR
            and issue.code not in _CHECK_NON_BLOCKING_CODES
        ]
        if blocking_codes:
            run_blocked_code = CHECK_REASON_DOC_FAULT
            run_blocked_reason = (
                f"document carries {len(blocking_codes)} error-severity "
                f"declaration fault(s) [{_blocking_codes_display(blocking_codes)}]"
                " — fix the document before running checks"
            )

    # Taint attribution (LLR-050.2, Phase-2 B-1): ONLY taint-attribution
    # codes (emitted against constructed entries) taint, by start-address
    # equality. Skip-site issues share the address space but never taint.
    tainting_by_address: Dict[int, str] = {}
    if run_blocked_code is None:
        for issue in document.issues:
            if (
                issue.severity is ValidationSeverity.ERROR
                and issue.code in _CHECK_TAINT_ATTRIBUTION_CODES
                and isinstance(issue.address, int)
            ):
                tainting_by_address.setdefault(issue.address, issue.code)

    aggregates: Dict[str, int] = {key: 0 for key in CHECK_AGGREGATE_KEYS}
    result_entries: List[CheckRunEntry] = []
    for entry in document.entries:
        start, end = entry.addressed_range
        linkage, linkage_symbol = _classify_linkage(
            start, end, mac_index, mac_symbols, a2l_index, a2l_symbols
        )
        actual_bytes: Optional[Tuple[int, ...]] = None
        reason_code: Optional[str] = None
        reason: Optional[str] = None
        if run_blocked_code is not None:
            # A blocked run explains itself ONCE at run level; each row
            # carries only the short pointer (LLR-051.5 — bounded, so the
            # run reason is never multiplied by the row count, F2).
            result = CHECK_UNCHECKABLE
            reason_code = run_blocked_code
            reason = f"run blocked [{run_blocked_code}]"
        elif start in tainting_by_address:
            result = CHECK_UNCHECKABLE
            reason_code = CHECK_REASON_ENTRY_FAULT
            reason = (
                f"entry at 0x{start:X} carries "
                f"[{tainting_by_address[start]}] — see declaration faults"
            )
        elif entry.status is MemoryStatus.INSIDE:
            assert mem_map is not None  # INSIDE implies a loaded image
            actual_bytes = tuple(mem_map[addr] for addr in range(start, end))
            result = (
                CHECK_PASS
                if actual_bytes == entry.encoded_bytes
                else CHECK_FAIL
            )
        else:
            result = CHECK_UNCHECKABLE
            reason_code, reason = _CONTAINMENT_REASONS[entry.status]
        aggregates[_RESULT_TO_AGGREGATE[result]] += 1
        result_entries.append(
            CheckRunEntry(
                entry_type=entry.entry_type,
                address_start=start,
                address_end=end,
                expected_bytes=entry.encoded_bytes,
                actual_bytes=actual_bytes,
                result=result,
                linkage=linkage,
                linkage_symbol=linkage_symbol,
                reason_code=reason_code,
                reason=reason,
            )
        )

    return CheckRunResult(
        source_path=document.source_path,
        timestamp_utc=clock().isoformat(),
        variant_id=variant_id,
        aggregates=aggregates,
        entries=result_entries,
        issues=list(document.issues),
        run_blocked_reason_code=run_blocked_code,
        run_blocked_reason=run_blocked_reason,
    )
