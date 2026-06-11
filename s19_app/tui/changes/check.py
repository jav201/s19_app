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

Gate semantics (the apply-gate mirror, chosen per LLR-004.1's one-reader /
one-rule decision D-3): a document carrying any ERROR-severity issue, or
whose ``kind`` is not ``"check"``, is **not runnable** — no comparison is
performed, every entry's result is ``uncheckable`` with ``actual_bytes``
``None``, and the result object carries the document's collected issues so
the declaration faults reach the report (B-2). This mirrors
``apply_change_document``'s LLR-002.1 gate (ERROR or wrong kind → every
disposition ``blocked``).

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

from .apply import (
    _a2l_linkage_source,
    _classify_linkage,
    _linkage_index,
    _mac_linkage_source,
    classify_containment,
)
from .model import (
    CHECK_AGGREGATE_KEYS,
    CHECK_FAIL,
    CHECK_PASS,
    CHECK_UNCHECKABLE,
    ChangeDocument,
    CheckRunEntry,
    CheckRunResult,
    MemoryStatus,
)

__all__ = ["run_check_document"]

#: Result token → aggregate-count key (LLR-004.3 — ``pass`` counts under
#: ``passed``, ``fail`` under ``failed``, ``uncheckable`` under itself).
_RESULT_TO_AGGREGATE = {
    CHECK_PASS: "passed",
    CHECK_FAIL: "failed",
    CHECK_UNCHECKABLE: "uncheckable",
}


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
        document (ChangeDocument): The check document to run. Any
            ERROR-severity issue, or ``kind`` != ``"check"``, makes the
            document not runnable: no comparisons, every entry
            ``uncheckable`` with ``actual_bytes`` ``None`` — the
            apply-gate mirror of LLR-002.1, with the collected issues
            carried in the result (B-2).
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
        - Gate: ``document.has_errors or kind != "check"`` → every entry
          ``uncheckable``, no read, no comparison.
        - Otherwise per entry: ``INSIDE`` → read ``actual_bytes`` from
          ``mem_map`` and compare against ``encoded_bytes`` (equal →
          ``pass``, unequal → ``fail``); ``PARTIAL`` / ``OUTSIDE`` /
          ``UNVALIDATED_NO_IMAGE`` → ``uncheckable``, ``actual_bytes``
          ``None`` (LLR-004.2 — the three uncheckable provocations).
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
    not_runnable = document.has_errors or document.kind != "check"

    aggregates: Dict[str, int] = {key: 0 for key in CHECK_AGGREGATE_KEYS}
    result_entries: List[CheckRunEntry] = []
    for entry in document.entries:
        start, end = entry.addressed_range
        linkage, linkage_symbol = _classify_linkage(
            start, end, mac_index, mac_symbols, a2l_index, a2l_symbols
        )
        actual_bytes: Optional[Tuple[int, ...]] = None
        if not_runnable:
            result = CHECK_UNCHECKABLE
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
            )
        )

    return CheckRunResult(
        source_path=document.source_path,
        timestamp_utc=clock().isoformat(),
        variant_id=variant_id,
        aggregates=aggregates,
        entries=result_entries,
        issues=list(document.issues),
    )
