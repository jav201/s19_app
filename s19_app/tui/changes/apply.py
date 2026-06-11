"""
v2 apply engine — s19_app batch-07, increment E2.

This module is the **pure-function half** of HLR-002: it takes a validated
:class:`ChangeDocument` plus read-only snapshots of the loaded image
(``LoadedFile.mem_map`` / ``.ranges``) and the informative linkage sources
(``LoadedFile.mac_records`` / enriched A2L tags), and produces the §6.2 C-6
:class:`ChangeSummary` — writing entry bytes into the memory map only when
the apply gate and the per-entry containment verdict allow it.

The three public functions:

- :func:`classify_containment` — LLR-001.6: stamp every entry's
  :class:`MemoryStatus` against the loaded image ranges via the shared
  ``range_index`` binary-search primitives (the ``cdfx/memory_validate.py::
  _range_status`` logic, migrated; the cdfx original is untouched here —
  increment E3b performs the deletions).
- :func:`apply_change_document` — LLR-002.1..002.6: the apply gate (any
  ERROR issue or ``kind`` ≠ ``"change"`` → zero writes, every disposition
  ``blocked``), per-entry dispositions, before-capture, linkage
  classification, and the deterministic :class:`ChangeSummary`.
- :func:`save_patched_image` — the engine half of LLR-002.7 (D-1, S19-only
  this batch): sanitize the operator-provided filename (F-S-01), emit the
  patched image via ``changes.io.emit_s19_from_mem_map``, and place it
  through the staged-containment pattern (``.s19tool/workarea/temp/`` then
  ``workspace.copy_into_workarea``). Intel HEX is refused with one clear
  issue and no write.

Thread placement (LLR-002.4): everything here is a pure function over its
arguments with **no Textual import**; the TUI invokes it on the main UI
thread via the service layer at E3a.

Per constraint C-9, issue messages name addresses, file names, and counts —
never raw byte or value content.
"""

from __future__ import annotations

import bisect
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from ...range_index import (
    RangeIndex,
    build_sorted_range_index,
    range_in_sorted_ranges,
)
from ...validation.model import ValidationIssue, ValidationSeverity
from ..workspace import (
    WORKAREA_DIRNAME,
    WORKAREA_SUBDIR,
    WORKAREA_TEMP,
    WorkareaContainmentError,
    copy_into_workarea,
)
from .io import MF_WRITE_CONTAINMENT, _issue, emit_s19_from_mem_map
from .model import (
    DISPOSITION_APPLIED,
    DISPOSITION_BLOCKED,
    DISPOSITION_DOMAIN,
    DISPOSITION_SKIPPED_NO_IMAGE,
    DISPOSITION_SKIPPED_OUTSIDE,
    DISPOSITION_SKIPPED_PARTIAL,
    LINKAGE_A2L,
    LINKAGE_BOTH,
    LINKAGE_MAC,
    LINKAGE_STANDALONE,
    ChangeDocument,
    ChangeEntry,
    ChangeSummary,
    ChangeSummaryEntry,
    MemoryStatus,
)

__all__ = [
    "CHG_HEX_SAVE_UNSUPPORTED",
    "apply_change_document",
    "classify_containment",
    "save_patched_image",
]

#: Stable ``ValidationIssue.code`` for a save-back request on an Intel
#: HEX-loaded image — refused this batch (LLR-002.7 / D-1: S19-only;
#: an Intel HEX emitter is a batch-08 candidate). NEW — created in Phase 3.
CHG_HEX_SAVE_UNSUPPORTED = "CHG-HEX-SAVE-UNSUPPORTED"

#: Windows reserved device basenames (F-S-01): a filename whose first
#: dot-delimited segment matches one of these — with or without an extension
#: (``CON`` and ``CON.s19`` alike) — is rejected, never written.
_WINDOWS_RESERVED_BASENAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{digit}" for digit in range(1, 10)}
    | {f"LPT{digit}" for digit in range(1, 10)}
)

#: Containment-status → skip-disposition mapping (LLR-002.2). ``INSIDE`` is
#: deliberately absent: it is the single write path, handled explicitly.
_STATUS_TO_SKIP_DISPOSITION = {
    MemoryStatus.PARTIAL: DISPOSITION_SKIPPED_PARTIAL,
    MemoryStatus.OUTSIDE: DISPOSITION_SKIPPED_OUTSIDE,
    MemoryStatus.UNVALIDATED_NO_IMAGE: DISPOSITION_SKIPPED_NO_IMAGE,
}


def classify_containment(
    document: ChangeDocument,
    ranges: Optional[Sequence[Tuple[int, int]]],
) -> None:
    """
    Summary:
        Stamp every document entry's :class:`MemoryStatus` against the loaded
        image's contiguous ranges (LLR-001.6) — the migrated
        ``cdfx/memory_validate.py::_range_status`` classification on v2
        entries. Emits no issues in either branch.

    Args:
        document (ChangeDocument): The document whose entries are stamped in
            place.
        ranges (Optional[Sequence[Tuple[int, int]]]): The loaded image's
            half-open ``(start, end)`` ranges (``LoadedFile.ranges``).
            ``None`` means **no image is loaded** — every entry is stamped
            ``UNVALIDATED_NO_IMAGE`` with no issues. An empty sequence means
            a loaded-but-empty image: every entry is ``OUTSIDE``.

    Returns:
        None: Entries are mutated in place (``entry.status``).

    Data Flow:
        - No image → blanket ``UNVALIDATED_NO_IMAGE`` stamp, nothing else.
        - Otherwise build the sorted binary-search index once
          (``build_sorted_range_index``) and classify each entry's
          ``addressed_range``: fully contained in one range → ``INSIDE``
          (``range_in_sorted_ranges``); else any byte-level intersection
          with any range → ``PARTIAL`` (edge-straddle and gap-spanning
          alike); else ``OUTSIDE``.

    Dependencies:
        Uses:
            - build_sorted_range_index / range_in_sorted_ranges
            - MemoryStatus
        Used by:
            - apply_change_document
            - tests/test_changes_containment.py

    Example:
        >>> doc = ChangeDocument(
        ...     format="s19app-changeset", version="2.0", kind="change",
        ...     encoding="utf-8", value_mode="text",
        ...     entries=[ChangeEntry("bytes", 0x100, (0x01,))],
        ... )
        >>> classify_containment(doc, [(0x100, 0x110)])
        >>> doc.entries[0].status
        <MemoryStatus.INSIDE: 'inside'>
    """
    if ranges is None:
        for entry in document.entries:
            entry.status = MemoryStatus.UNVALIDATED_NO_IMAGE
        return
    image_ranges = list(ranges)
    index = build_sorted_range_index(image_ranges)
    for entry in document.entries:
        entry.status = _containment_status(entry, index, image_ranges)


def _containment_status(
    entry: ChangeEntry,
    index: RangeIndex,
    image_ranges: Sequence[Tuple[int, int]],
) -> MemoryStatus:
    """
    Summary:
        Classify one entry's addressed byte range as ``INSIDE`` / ``PARTIAL``
        / ``OUTSIDE`` against the loaded image ranges — the
        ``cdfx/memory_validate.py::_range_status`` logic migrated onto
        :class:`ChangeEntry` (LLR-001.6).

    Args:
        entry (ChangeEntry): The entry whose ``addressed_range`` is tested.
        index (RangeIndex): The sorted ``(starts, ends)`` binary-search index
            built from ``image_ranges``.
        image_ranges (Sequence[Tuple[int, int]]): The loaded image's
            contiguous half-open ranges — scanned only on the non-``INSIDE``
            path to distinguish ``PARTIAL`` from ``OUTSIDE``.

    Returns:
        MemoryStatus: ``INSIDE`` when the run fits one loaded range,
        ``PARTIAL`` when it intersects any range without being contained
        (edge-straddle and gap-spanning alike), else ``OUTSIDE``.

    Data Flow:
        - Binary-search fast path for the full-containment test; fall back to
          an intersection scan only when not contained.

    Dependencies:
        Uses:
            - range_in_sorted_ranges
        Used by:
            - classify_containment
    """
    start, end = entry.addressed_range
    if range_in_sorted_ranges(start, end - start, index):
        return MemoryStatus.INSIDE
    for range_start, range_end in image_ranges:
        if start < range_end and range_start < end:
            return MemoryStatus.PARTIAL
    return MemoryStatus.OUTSIDE


def apply_change_document(
    document: ChangeDocument,
    mem_map: Optional[Dict[int, int]],
    ranges: Optional[Sequence[Tuple[int, int]]],
    mac_records: Optional[Sequence[dict]],
    a2l_tags: Optional[Sequence[dict]],
    *,
    now_fn: Optional[Callable[[], datetime]] = None,
    variant_id: Optional[str] = None,
) -> ChangeSummary:
    """
    Summary:
        Apply a v2 change document to the loaded image's memory map and
        return the §6.2 C-6 :class:`ChangeSummary` (LLR-002.1..002.6) — a
        pure function over its arguments, no Textual anywhere (LLR-002.4).

    Args:
        document (ChangeDocument): The document to apply. Any ERROR-severity
            issue, or ``kind`` ≠ ``"change"``, trips the apply gate: zero
            writes, every disposition ``blocked`` (LLR-002.1).
        mem_map (Optional[Dict[int, int]]): The loaded image's address-to-
            byte map (``LoadedFile.mem_map``) — **mutated in place** at
            applied entries' addresses only (LLR-002.3); never read or
            written for skipped/blocked entries. May be ``None`` when no
            image is loaded.
        ranges (Optional[Sequence[Tuple[int, int]]]): The image's contiguous
            ranges (``LoadedFile.ranges``); ``None`` = no image, so every
            gate-passed entry is ``skipped-no-image``.
        mac_records (Optional[Sequence[dict]]): Parsed MAC records
            (``LoadedFile.mac_records`` — ``name`` / ``address`` /
            ``parse_ok`` keys, the ``validation/engine.py`` consumption
            pattern) for the informative linkage classification.
        a2l_tags (Optional[Sequence[dict]]): Enriched A2L tags (``name`` /
            ``address`` / ``length`` keys) for the linkage classification.
        now_fn (Optional[Callable[[], datetime]]): Injectable UTC clock
            (B-4); ``None`` defaults to ``datetime.now(timezone.utc)``. The
            summary records ``now_fn().isoformat()``.
        variant_id (Optional[str]): The project variant this apply targets;
            recorded verbatim in the summary (``None`` until US-005 lands).

    Returns:
        ChangeSummary: Summary-level metadata (source path, kind, encoding,
        value mode, timestamp, variant, all-five-keys disposition counts,
        the document's collected ``issues`` per LLR-002.8, ``saved_path``
        ``None`` — stamped later by the save-back flow) plus one
        :class:`ChangeSummaryEntry` per document entry in document order,
        each with exact ``before_bytes`` (applied entries only) /
        ``after_bytes`` and the informative linkage classification.

    Raises:
        KeyError: If an ``INSIDE`` entry addresses a byte missing from
            ``mem_map`` — impossible when ``ranges`` derive from the map's
            keys (the parse-layer contract); a programming error otherwise.

    Data Flow:
        - Build the MAC / A2L linkage indexes once via the sorted-range
          primitives (LLR-002.6 — never a linear scan per entry).
        - Stamp containment via :func:`classify_containment` (LLR-001.6).
        - Gate: ``document.has_errors or kind != "change"`` → every entry
          ``blocked``, ``mem_map`` untouched.
        - Otherwise per entry: ``INSIDE`` → capture ``before_bytes`` from
          ``mem_map``, then write the encoded run (LLR-002.3); ``PARTIAL`` /
          ``OUTSIDE`` / ``UNVALIDATED_NO_IMAGE`` → the matching skip
          disposition, unwritten (LLR-002.2).
        - Linkage is classified for every entry regardless of disposition —
          informative only, it never gates a write (LLR-002.6).

    Dependencies:
        Uses:
            - classify_containment
            - _linkage_index / _classify_linkage
            - ChangeSummary / ChangeSummaryEntry
        Used by:
            - The E3a change service (later increment)
            - tests/test_changes_apply.py / tests/test_changes_linkage.py

    Example:
        >>> doc = ChangeDocument(
        ...     format="s19app-changeset", version="2.0", kind="change",
        ...     encoding="utf-8", value_mode="text",
        ...     entries=[ChangeEntry("bytes", 0x100, (0xAA,))],
        ... )
        >>> mem = {0x100: 0x00}
        >>> summary = apply_change_document(doc, mem, [(0x100, 0x101)], None, None)
        >>> (summary.counts["applied"], mem[0x100])
        (1, 170)
    """
    clock: Callable[[], datetime] = (
        now_fn if now_fn is not None else (lambda: datetime.now(timezone.utc))
    )
    mac_index, mac_symbols = _linkage_index(_mac_linkage_source(mac_records))
    a2l_index, a2l_symbols = _linkage_index(_a2l_linkage_source(a2l_tags))

    classify_containment(document, ranges)
    blocked = document.has_errors or document.kind != "change"

    counts: Dict[str, int] = {token: 0 for token in DISPOSITION_DOMAIN}
    summary_entries: List[ChangeSummaryEntry] = []
    for entry in document.entries:
        start, end = entry.addressed_range
        linkage, linkage_symbol = _classify_linkage(
            start, end, mac_index, mac_symbols, a2l_index, a2l_symbols
        )
        before_bytes: Optional[Tuple[int, ...]] = None
        if blocked:
            disposition = DISPOSITION_BLOCKED
        elif entry.status is MemoryStatus.INSIDE:
            assert mem_map is not None  # INSIDE implies a loaded image
            before_bytes = tuple(mem_map[addr] for addr in range(start, end))
            for offset, byte_value in enumerate(entry.encoded_bytes):
                mem_map[start + offset] = byte_value
            disposition = DISPOSITION_APPLIED
        else:
            disposition = _STATUS_TO_SKIP_DISPOSITION[entry.status]
        counts[disposition] += 1
        summary_entries.append(
            ChangeSummaryEntry(
                entry_type=entry.entry_type,
                address_start=start,
                address_end=end,
                before_bytes=before_bytes,
                after_bytes=entry.encoded_bytes,
                disposition=disposition,
                linkage=linkage,
                linkage_symbol=linkage_symbol,
            )
        )

    return ChangeSummary(
        source_path=document.source_path,
        kind=document.kind,
        encoding=document.encoding,
        value_mode=document.value_mode,
        timestamp_utc=clock().isoformat(),
        variant_id=variant_id,
        counts=counts,
        entries=summary_entries,
        issues=list(document.issues),
        saved_path=None,
    )


def _mac_linkage_source(
    mac_records: Optional[Sequence[dict]],
) -> List[Tuple[int, int, Optional[str]]]:
    """
    Summary:
        Project parsed MAC records onto ``(start, end, symbol)`` point ranges
        for the linkage index — the ``validation/engine.py`` MAC consumption
        pattern (skip non-``parse_ok`` records and non-integer addresses).

    Args:
        mac_records (Optional[Sequence[dict]]): ``LoadedFile.mac_records``
            dicts (``name`` / ``address`` / ``parse_ok``); ``None`` or empty
            yields an empty source.

    Returns:
        List[Tuple[int, int, Optional[str]]]: One ``(address, address + 1,
        name)`` triple per usable record; ``name`` is ``None`` when blank.

    Dependencies:
        Used by:
            - apply_change_document
    """
    source: List[Tuple[int, int, Optional[str]]] = []
    for record in mac_records or []:
        if not record.get("parse_ok"):
            continue
        address = record.get("address")
        if not isinstance(address, int):
            continue
        name = str(record.get("name") or "").strip() or None
        source.append((address, address + 1, name))
    return source


def _a2l_linkage_source(
    a2l_tags: Optional[Sequence[dict]],
) -> List[Tuple[int, int, Optional[str]]]:
    """
    Summary:
        Project enriched A2L tags onto ``(start, end, symbol)`` ranges for
        the linkage index — the ``validation/engine.py`` A2L consumption
        pattern (non-integer address skipped; missing/non-integer length
        defaults to a 1-byte range).

    Args:
        a2l_tags (Optional[Sequence[dict]]): Enriched A2L tag dicts (``name``
            / ``address`` / ``length``); ``None`` or empty yields an empty
            source.

    Returns:
        List[Tuple[int, int, Optional[str]]]: One ``(address, address +
        max(1, length), name)`` triple per usable tag; ``name`` is ``None``
        when blank.

    Dependencies:
        Used by:
            - apply_change_document
    """
    source: List[Tuple[int, int, Optional[str]]] = []
    for tag in a2l_tags or []:
        address = tag.get("address")
        if not isinstance(address, int):
            continue
        length = tag.get("length")
        byte_length = int(length) if isinstance(length, int) else 1
        name = str(tag.get("name") or "").strip() or None
        source.append((address, address + max(1, byte_length), name))
    return source


def _linkage_index(
    source: List[Tuple[int, int, Optional[str]]],
) -> Tuple[RangeIndex, List[Optional[str]]]:
    """
    Summary:
        Build the sorted binary-search linkage index plus the aligned symbol
        list from ``(start, end, symbol)`` triples (LLR-002.6 — the
        ``build_sorted_range_index`` primitive, never a linear scan).

    Args:
        source (List[Tuple[int, int, Optional[str]]]): The MAC or A2L ranges
            with their symbol names.

    Returns:
        Tuple[RangeIndex, List[Optional[str]]]: The ``(starts, ends)`` index
        and the symbol list aligned with it. Alignment holds because the
        triples are pre-sorted by start with the same key
        ``build_sorted_range_index`` uses, and Python's stable sort leaves an
        already-sorted input in identity order.

    Dependencies:
        Uses:
            - build_sorted_range_index
        Used by:
            - apply_change_document
    """
    ordered = sorted(source, key=lambda triple: triple[0])
    index = build_sorted_range_index([(start, end) for start, end, _ in ordered])
    symbols = [symbol for _, _, symbol in ordered]
    return index, symbols


def _first_intersecting_symbol(
    start: int,
    end: int,
    index: RangeIndex,
    symbols: List[Optional[str]],
) -> Tuple[bool, Optional[str]]:
    """
    Summary:
        Binary-search test of whether the half-open ``[start, end)`` span
        intersects any indexed range, returning the matched range's symbol
        (LLR-002.6).

    Args:
        start (int): Span start (inclusive).
        end (int): Span end (exclusive).
        index (RangeIndex): The ``(starts, ends)`` linkage index.
        symbols (List[Optional[str]]): Symbol list aligned with ``index``.

    Returns:
        Tuple[bool, Optional[str]]: ``(True, symbol)`` on the first
        intersection found — the candidate at or before ``start``, else its
        immediate successor — or ``(False, None)``. Like the shared
        ``range_index`` primitives, the probe assumes the indexed ranges do
        not overlap each other (MAC addresses are points; image and tag
        ranges are normally disjoint); overlapping declared ranges may
        resolve to the nearest-start match only — acceptable for an
        informative-only annotation.

    Data Flow:
        - ``bisect_right`` on the starts vector locates the last range
          starting at or before ``start``; intersection holds when its end
          exceeds ``start``. Otherwise the next range intersects iff it
          starts before ``end``.

    Dependencies:
        Uses:
            - bisect.bisect_right
        Used by:
            - _classify_linkage
    """
    starts, ends = index
    if not starts:
        return False, None
    candidate = bisect.bisect_right(starts, start) - 1
    if candidate >= 0 and ends[candidate] > start:
        return True, symbols[candidate]
    successor = candidate + 1
    if successor < len(starts) and starts[successor] < end:
        return True, symbols[successor]
    return False, None


def _classify_linkage(
    start: int,
    end: int,
    mac_index: RangeIndex,
    mac_symbols: List[Optional[str]],
    a2l_index: RangeIndex,
    a2l_symbols: List[Optional[str]],
) -> Tuple[str, Optional[str]]:
    """
    Summary:
        Classify one entry's addressed range as ``standalone`` /
        ``mac-linked`` / ``a2l-linked`` / ``both`` and capture the matching
        symbol name (LLR-002.6 — informative only, never affects whether the
        entry is applied).

    Args:
        start (int): Entry range start (inclusive).
        end (int): Entry range end (exclusive).
        mac_index (RangeIndex): MAC point-address index.
        mac_symbols (List[Optional[str]]): Symbols aligned with
            ``mac_index``.
        a2l_index (RangeIndex): A2L tag-range index.
        a2l_symbols (List[Optional[str]]): Symbols aligned with
            ``a2l_index``.

    Returns:
        Tuple[str, Optional[str]]: ``(linkage, linkage_symbol)``. On a
        ``both`` classification the MAC symbol is preferred (falling back to
        the A2L symbol when the MAC record is unnamed) — one documented
        deterministic choice for the single ``linkage_symbol`` slot.

    Dependencies:
        Uses:
            - _first_intersecting_symbol
        Used by:
            - apply_change_document
    """
    mac_hit, mac_symbol = _first_intersecting_symbol(
        start, end, mac_index, mac_symbols
    )
    a2l_hit, a2l_symbol = _first_intersecting_symbol(
        start, end, a2l_index, a2l_symbols
    )
    if mac_hit and a2l_hit:
        return LINKAGE_BOTH, mac_symbol or a2l_symbol
    if mac_hit:
        return LINKAGE_MAC, mac_symbol
    if a2l_hit:
        return LINKAGE_A2L, a2l_symbol
    return LINKAGE_STANDALONE, None


def save_patched_image(
    mem_map: Dict[int, int],
    ranges: Sequence[Tuple[int, int]],
    dest_dir: Path,
    filename: str,
    *,
    source_kind: str,
) -> Tuple[Optional[Path], List[ValidationIssue]]:
    """
    Summary:
        Persist a patched image as S19 text under the project work area —
        the engine half of LLR-002.7 (D-1: S19-only this batch). The
        operator-provided ``filename`` passes the F-S-01 sanitizer; the
        bytes are staged under ``.s19tool/workarea/temp/`` and placed via
        ``workspace.copy_into_workarea`` (containment + reparse-point +
        dedup checks reused).

    Args:
        mem_map (Dict[int, int]): The post-apply address-to-byte map to
            serialize. Read-only here.
        ranges (Sequence[Tuple[int, int]]): The image's contiguous half-open
            ranges, driving record emission.
        dest_dir (Path): The project directory the file must land in —
            ``.s19tool/workarea/<project>/``. Must lie inside a
            ``.s19tool/workarea/`` tree; anything else is one
            ``MF-WRITE-CONTAINMENT`` issue and no write.
        filename (str): The operator-provided target name. Sanitized per
            F-S-01: reduced to its bare name (``PureWindowsPath(...).name``,
            so both separator styles and drive prefixes are stripped on any
            platform), the ``.s19`` suffix forced on, and rejected outright —
            one ``MF-WRITE-CONTAINMENT`` issue, nothing written — when empty
            after stripping, carrying a trailing dot or space, or matching a
            Windows reserved device basename (``CON`` / ``PRN`` / ``AUX`` /
            ``NUL`` / ``COM1``-``COM9`` / ``LPT1``-``LPT9``, with or without
            extension).
        source_kind (str): The loaded image's loader classification
            (``LoadedFile.file_type``). Anything but ``"s19"`` — i.e. Intel
            HEX — is refused with one ``CHG-HEX-SAVE-UNSUPPORTED`` issue
            stating HEX save-back is not supported this batch, and nothing
            is written (D-1).

    Returns:
        Tuple[Optional[Path], List[ValidationIssue]]: The absolute path of
        the written file (a name collision is dedup-suffixed by
        ``copy_into_workarea`` — never a silent clobber) and the collected
        issues, or ``(None, issues)`` when the request was refused or the
        placement failed containment. The caller records a non-``None`` path
        as ``ChangeSummary.saved_path``.

    Raises:
        None: Refusals and containment/I/O failures are collected
            ``ValidationIssue`` records (collect-don't-abort); messages name
            file names and reasons — never image byte content (C-9).

    Data Flow:
        - Refuse non-S19 sources (D-1); sanitize the filename (F-S-01).
        - Locate the ``.s19tool/workarea/`` ancestor of ``dest_dir``; emit
          the S19 text (``emit_s19_from_mem_map``); stage it under
          ``<workarea>/temp/``; place with ``copy_into_workarea``; unlink
          the staged file either way.

    Dependencies:
        Uses:
            - emit_s19_from_mem_map
            - copy_into_workarea
            - _sanitize_s19_filename / _find_workarea_ancestor
            - _issue
        Used by:
            - The E3a save-back prompt flow (later increment)
            - tests/test_changes_apply.py::test_save_back*

    Example:
        >>> path, issues = save_patched_image(
        ...     mem, ranges, project_dir, "patched.s19", source_kind="s19",
        ... )  # doctest: +SKIP
    """
    issues: List[ValidationIssue] = []

    if source_kind != "s19":
        issues.append(
            _issue(
                CHG_HEX_SAVE_UNSUPPORTED,
                "Intel HEX save-back is not supported this batch — only an "
                "S19-loaded image can be persisted; the patched image was "
                "not written",
                severity=ValidationSeverity.WARNING,
            )
        )
        return None, issues

    safe_name, rejection = _sanitize_s19_filename(filename)
    if safe_name is None:
        assert rejection is not None
        issues.append(rejection)
        return None, issues

    workarea_root = _find_workarea_ancestor(dest_dir)
    if workarea_root is None:
        issues.append(
            _issue(
                MF_WRITE_CONTAINMENT,
                f"the save-back destination is not inside a "
                f"{WORKAREA_DIRNAME}/{WORKAREA_SUBDIR}/ tree — the patched "
                f"image was not written: {dest_dir}",
                severity=ValidationSeverity.WARNING,
            )
        )
        return None, issues

    text = emit_s19_from_mem_map(dict(mem_map), list(ranges))
    staged = workarea_root / WORKAREA_TEMP / safe_name
    try:
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_text(text, encoding="ascii")
        target = copy_into_workarea(staged, dest_dir)
        return target, issues
    except (WorkareaContainmentError, OSError) as exc:
        issues.append(
            _issue(
                MF_WRITE_CONTAINMENT,
                f"the save-back target failed work-area containment "
                f"validation — the patched image was not written: {exc}",
                severity=ValidationSeverity.WARNING,
            )
        )
        return None, issues
    finally:
        try:
            staged.unlink()
        except OSError:
            pass


def _sanitize_s19_filename(
    filename: str,
) -> Tuple[Optional[str], Optional[ValidationIssue]]:
    """
    Summary:
        Reduce an operator-provided save-back filename to a contained bare
        ``.s19`` name, or reject it (F-S-01) — the ``_safe_name`` pattern
        generalized to preserve the S19 extension instead of forcing
        ``.json``.

    Args:
        filename (str): The typed target name — possibly carrying path
            separators (either style), traversal segments, a drive-qualified
            absolute prefix, a reserved device basename, or a trailing dot
            or space.

    Returns:
        Tuple[Optional[str], Optional[ValidationIssue]]: ``(name, None)``
        with directory components stripped and the ``.s19`` suffix forced
        on, or ``(None, issue)`` — one ``MF-WRITE-CONTAINMENT`` issue —
        when the bare name is empty, ends with a dot or space (Windows
        strips those at the filesystem layer, which would bypass later
        comparisons), or its first dot-delimited segment is a Windows
        reserved device basename.

    Data Flow:
        - ``PureWindowsPath(...).name`` strips both separator styles and any
          drive prefix on every platform (a POSIX ``Path`` would treat
          ``..\\evil.s19`` as one opaque name).
        - Reject empties and trailing dot/space; force the ``.s19`` suffix;
          reject reserved basenames case-insensitively, with or without
          extension.

    Dependencies:
        Uses:
            - _WINDOWS_RESERVED_BASENAMES
            - _issue
        Used by:
            - save_patched_image
    """
    bare = PureWindowsPath(str(filename)).name.strip()
    if not bare or bare != bare.rstrip(". "):
        return None, _issue(
            MF_WRITE_CONTAINMENT,
            f"the requested save-back filename is empty or ends with a dot "
            f"or space after sanitization — the patched image was not "
            f"written: {filename!r}",
            severity=ValidationSeverity.WARNING,
        )
    if not bare.lower().endswith(".s19"):
        bare = f"{bare}.s19"
    if bare.split(".", 1)[0].strip().upper() in _WINDOWS_RESERVED_BASENAMES:
        return None, _issue(
            MF_WRITE_CONTAINMENT,
            f"the requested save-back filename is a Windows reserved device "
            f"name — the patched image was not written: {filename!r}",
            severity=ValidationSeverity.WARNING,
        )
    return bare, None


def _find_workarea_ancestor(dest_dir: Path) -> Optional[Path]:
    """
    Summary:
        Walk ``dest_dir`` upwards looking for the ``.s19tool/workarea``
        directory it is contained in — the staging root for the
        temp-then-copy placement pattern.

    Args:
        dest_dir (Path): The requested destination directory.

    Returns:
        Optional[Path]: The ``<base>/.s19tool/workarea`` ancestor (possibly
        ``dest_dir`` itself), or ``None`` when no such ancestor exists —
        ``copy_into_workarea`` would refuse the placement anyway; this
        pre-check just yields a clearer issue without touching the disk.

    Dependencies:
        Used by:
            - save_patched_image
    """
    resolved = dest_dir.resolve()
    for candidate in (resolved, *resolved.parents):
        if (
            candidate.name == WORKAREA_SUBDIR
            and candidate.parent.name == WORKAREA_DIRNAME
        ):
            return candidate
    return None
