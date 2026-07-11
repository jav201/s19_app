"""
Report filter file: read / parse / resolve / match (batch-35 B-07, HLR-053).

Sources the operator-authored JSON whitelist that restricts the before/after
report and the project report to named symbols and address ranges. Envelope
``s19app-report-filter`` v1.0 (LLR-053.1); the module mirrors the
``crc_config`` operations-input discipline (§6.2 D-7):

- **read/parse split** — :func:`read_report_filter_text` resolves the path
  via ``workspace.resolve_input_path``, refuses symlinks / non-regular files
  AT READ TIME (S-F2), and enforces the filter-specific 4 MiB size cap
  BEFORE reading (LLR-053.2, S-F3);
- **collect-don't-abort, multi-error** — :func:`parse_report_filter` returns
  ``(ReportFilter | None, list[str])`` with one named diagnostic per fault
  (a file with N distinct faults yields >= N diagnostics, LLR-053.1) and
  NEVER raises;
- **resolved-matcher architecture (D-9)** — :func:`resolve_report_filter`
  builds a :class:`ReportFilterMatcher` ONCE per report run from the parsed
  filter plus the loaded A2L/MAC records; the matcher is the ONLY filter
  object that crosses the service boundary (LLR-053.7), and its
  classification methods never raise for any input shape (S-F4).

Headless: no Textual import, no file write-back. The filter FILE is
read-only, at parity with ``crc_config`` / ``read_change_document``.
"""

from __future__ import annotations

import bisect
import json
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Callable, Optional

from ...range_index import (
    RangeIndex,
    address_in_sorted_ranges,
    build_sorted_range_index,
)
from ..workspace import resolve_input_path

#: Envelope format id (LLR-053.1) — mirrors the ``changes/io.py``
#: ``FORMAT_ID = "s19app-changeset"`` precedent (``io.py:110``).
REPORT_FILTER_FORMAT_ID: str = "s19app-report-filter"

#: The only accepted envelope version (LLR-053.1).
REPORT_FILTER_FORMAT_VERSION: str = "1.0"

#: Filter-specific on-disk size cap, checked BEFORE the file is read
#: (LLR-053.2 / S-F3). 4 MiB — deliberately far below the shared
#: ``changes.io.READ_SIZE_CAP_BYTES`` (256 MB): a filter is hand-authored
#: JSON bounded by the 4096/4096 ceilings, and the parse+resolve step runs
#: SYNCHRONOUSLY on the UI thread, so the cap bounds the stall.
REPORT_FILTER_SIZE_CAP_BYTES: int = 4 * 1024 * 1024

#: Parse-time ceiling on ``include.symbols`` (LLR-053.3 / D-8), mirroring
#: ``crc_config.CRC_SPAN_COUNT_CEILING = 4096`` — same operator-JSON class
#: and cost profile.
SYMBOL_PATTERN_CEILING: int = 4096

#: Parse-time ceiling on ``include.addresses`` (LLR-053.3 / D-8).
ADDRESS_RANGE_CEILING: int = 4096

#: Exclusive upper bound of the 32-bit S19 address space — the pinned
#: address domain is ``0 <= start < end <= 2^32`` (LLR-053.1, crc_config
#: ``_ADDRESS_SPACE_END`` precedent).
_ADDRESS_SPACE_END: int = 0x1_0000_0000

#: The on-disk size-measurement seam (crc_config ``SizeProbe`` idiom) —
#: injectable so a test can report an over-cap size without manufacturing a
#: real 4 MiB file. ``None`` resolves to ``Path.stat().st_size`` at call
#: time.
SizeProbe = Callable[[Path], int]

_TOP_LEVEL_KEYS = ("format", "version", "include")
_INCLUDE_KEYS = ("symbols", "addresses")


@dataclass(frozen=True)
class ReportFilter:
    """
    Summary:
        The PARSED form of an operator report-filter file (LLR-053.1): the
        whitelist symbol patterns and explicit half-open address ranges.
        This object never crosses the service boundary — it exists only as
        the input to :func:`resolve_report_filter` (D-9).

    Args:
        symbols (tuple[str, ...]): The ``include.symbols`` patterns, in file
            order. Each matches per LLR-053.4(a): exact equality OR
            ``fnmatch.fnmatchcase``.
        addresses (tuple[tuple[int, int], ...]): The ``include.addresses``
            ranges, in file order. Each is inclusive-start / EXCLUSIVE-end
            (matching ``ChangeSummaryEntry.address_end``), domain-pinned to
            ``0 <= start < end <= 2^32``.

    Data Flow:
        - Built by :func:`parse_report_filter` from validated JSON.
        - Consumed by :func:`resolve_report_filter` to build the per-run
          :class:`ReportFilterMatcher`.

    Dependencies:
        Used by:
            - parse_report_filter (constructs it)
            - resolve_report_filter (consumes it)
    """

    symbols: tuple[str, ...]
    addresses: tuple[tuple[int, int], ...]


def _symbol_matches(symbol: str, patterns: tuple[str, ...]) -> bool:
    """
    Summary:
        LLR-053.4(a) symbol match: ``symbol == pattern`` OR
        ``fnmatchcase(symbol, pattern)`` for any pattern. The exact-equality
        short-circuit (F-2) guarantees a literal name containing fnmatch
        metacharacters (``PAR[0]``) matches itself; ``fnmatchcase`` (never
        ``fnmatch``) keeps A2L case sensitivity.

    Args:
        symbol (str): The candidate symbol name.
        patterns (tuple[str, ...]): The whitelist patterns.

    Returns:
        bool: True when any pattern matches under the (a) rule.

    Data Flow:
        - Per-pattern equality check, then ``fnmatchcase``; any per-pattern
          exception is swallowed (never-raise, S-F4).

    Dependencies:
        Uses:
            - fnmatch.fnmatchcase
        Used by:
            - ReportFilterMatcher.matches_symbol
            - resolve_report_filter (name-matching record extents)
    """
    for pattern in patterns:
        try:
            if symbol == pattern or fnmatchcase(symbol, pattern):
                return True
        except Exception:
            continue
    return False


@dataclass(frozen=True)
class ReportFilterMatcher:
    """
    Summary:
        The RESOLVED form of a report filter (LLR-053.7 / D-9): the symbol
        patterns plus the pre-built sorted matched-address ranges (explicit
        ``include.addresses`` ranges ∪ name-matched A2L/MAC record extents
        per LLR-053.4(c)/F-1), built ONCE per report run by
        :func:`resolve_report_filter`. This is the ONLY filter object that
        flows into composers, generators, ``ReportOptions``, and workers.
        Every classification method honours the never-raise contract for
        any input shape (S-F4).

    Args:
        patterns (tuple[str, ...]): The ``include.symbols`` patterns.
        matched_index (RangeIndex): ``build_sorted_range_index`` output over
            the MERGED (disjoint, sorted) matched address set. Merging is
            required because ``range_index`` membership checks assume
            non-overlapping ranges, while explicit ranges and record
            extents may overlap.

    Data Flow:
        - Built by :func:`resolve_report_filter`.
        - Queried per report item by the diff/project report generators
          (LLR-054.2 / LLR-055.2, later increments).

    Dependencies:
        Uses:
            - _symbol_matches (branch (a))
            - range_index.address_in_sorted_ranges (branch (b)/(c) point
              membership)
        Used by:
            - resolve_report_filter (constructs it)
            - report generators (consume it; batch-35 Inc-2+)
    """

    patterns: tuple[str, ...]
    matched_index: RangeIndex

    def matches_symbol(self, symbol: Any) -> bool:
        """
        Summary:
            Branch (a) of LLR-053.4: True when ``symbol`` is a string and
            some pattern matches it via equality OR ``fnmatchcase``.

        Args:
            symbol (Any): The item's linkage symbol; any non-``str`` value
                (including ``None``) is False, never an error.

        Returns:
            bool: True on a branch-(a) match. Never raises.

        Data Flow:
            - Non-str guard → delegate to :func:`_symbol_matches`.

        Dependencies:
            Uses:
                - _symbol_matches
            Used by:
                - matches_item
        """
        if not isinstance(symbol, str):
            return False
        return _symbol_matches(symbol, self.patterns)

    def matches_range(self, start: Any, end: Any) -> bool:
        """
        Summary:
            Branches (b)/(c) of LLR-053.4: True when the half-open range
            ``[start, end)`` intersects the pre-built matched address set
            (explicit ranges ∪ name-matched record extents).

        Args:
            start (Any): Inclusive range start; non-int (or bool) is False.
            end (Any): EXCLUSIVE range end; non-int (or bool) is False.

        Returns:
            bool: True when ``[start, end)`` intersects any matched range.
            Empty or inverted input ranges are False. Never raises.

        Data Flow:
            - Point membership of ``start`` via
              ``address_in_sorted_ranges`` (a matched range covers
              ``start``).
            - Otherwise, ``bisect`` over the merged-disjoint starts: any
              matched range STARTING inside ``[start, end)`` intersects.

        Dependencies:
            Uses:
                - range_index.address_in_sorted_ranges (consumed, engine
                  frozen — never modified)
                - bisect.bisect_right
            Used by:
                - matches_item
        """
        if isinstance(start, bool) or not isinstance(start, int):
            return False
        if isinstance(end, bool) or not isinstance(end, int):
            return False
        if start >= end:
            return False
        starts, _ends = self.matched_index
        if not starts:
            return False
        if address_in_sorted_ranges(start, self.matched_index):
            return True
        position = bisect.bisect_right(starts, start)
        return position < len(starts) and starts[position] < end

    def matches_item(self, symbol: Any, start: Any, end: Any) -> bool:
        """
        Summary:
            Full LLR-053.4 item classification: MATCHED when branch (a)
            accepts ``symbol`` OR branches (b)/(c) accept ``[start, end)``.

        Args:
            symbol (Any): The item's linkage symbol (``None`` = no symbol).
            start (Any): Inclusive item range start.
            end (Any): EXCLUSIVE item range end.

        Returns:
            bool: True when the item matches the filter. Never raises.

        Data Flow:
            - ``matches_symbol OR matches_range`` — both never-raise.

        Dependencies:
            Uses:
                - matches_symbol
                - matches_range
            Used by:
                - report generators (per linkage row / hex window / report
                  section row; batch-35 Inc-2+)
        """
        return self.matches_symbol(symbol) or self.matches_range(start, end)


def read_report_filter_text(
    raw_path: str,
    base_dir: Optional[Path] = None,
    size_probe: Optional[SizeProbe] = None,
) -> tuple[Optional[str], list[str]]:
    """
    Summary:
        Read an operator report-filter file's RAW TEXT into memory —
        resolve + read-time file-kind refusal + size-cap + ``read_text`` —
        WITHOUT parsing it, collecting any data-quality fault as a single
        named error string and NEVER raising (LLR-053.2, the ``crc_config``
        collect-don't-abort contract). The symlink / non-regular-file
        refusal happens AT READ TIME (S-F2) so a file swapped after
        selection is still refused, and the size cap is probed BEFORE the
        file is read.

    Args:
        raw_path (str): The user-supplied filter file path, resolved through
            ``workspace.resolve_input_path`` before the file is touched —
            an unresolvable path is one collected error and no file is
            opened.
        base_dir (Optional[Path]): The base directory a RELATIVE path is
            resolved against. ``None`` (the default) uses the current
            working directory.
        size_probe (Optional[SizeProbe]): The on-disk byte-size measurement
            seam. ``None`` (the default) resolves to ``Path.stat().st_size``
            at call time; injectable so a test can report an over-cap size
            without a real 4 MiB file (crc_config idiom).

    Returns:
        tuple[Optional[str], list[str]]: ``(raw_text, [])`` on success;
        ``(None, [one error string])`` on ANY read fault (unresolvable
        path, symlink, non-regular file, over the 4 MiB cap, unreadable,
        non-UTF-8 bytes). Never raises on a data fault. NB: the text is NOT
        parsed here — a readable-but-invalid-JSON file returns
        ``(raw_text, [])`` and the fault surfaces in
        :func:`parse_report_filter`.

    Raises:
        None: Every failure mode is a collected error string
            (collect-don't-abort).

    Data Flow:
        - Resolve ``raw_path`` via ``resolve_input_path``; unresolvable →
          one error.
        - Refuse ``is_symlink()`` and non-``is_file()`` paths (S-F2).
        - Probe the size; over :data:`REPORT_FILTER_SIZE_CAP_BYTES` → one
          error, the file is never read.
        - ``read_text(encoding="utf-8")``; ``OSError`` /
          ``UnicodeDecodeError`` → one error.

    Dependencies:
        Uses:
            - workspace.resolve_input_path (path resolution)
            - REPORT_FILTER_SIZE_CAP_BYTES (filter-specific 4 MiB cap)
        Used by:
            - the app-side filter resolution step at report trigger time
              (LLR-053.5/053.7; batch-35 Inc-2+)

    Example:
        >>> text, errors = read_report_filter_text("no/such/filter.json")
        >>> text is None
        True
        >>> len(errors)
        1
    """
    resolve_base = Path.cwd() if base_dir is None else base_dir
    resolved = resolve_input_path(Path(raw_path), resolve_base)
    if resolved is None:
        return None, [f"report filter path could not be resolved: {raw_path!r}"]

    try:
        if resolved.is_symlink():
            return None, [
                f"report filter path is a symlink and was refused: {raw_path!r}"
            ]
        if not resolved.is_file():
            return None, [
                f"report filter path is not a regular file: {raw_path!r}"
            ]

        probe: SizeProbe = (
            (lambda candidate: candidate.stat().st_size)
            if size_probe is None
            else size_probe
        )
        size_bytes = probe(resolved)
        if size_bytes > REPORT_FILTER_SIZE_CAP_BYTES:
            return None, [
                f"report filter file is {size_bytes} bytes, over the "
                f"{REPORT_FILTER_SIZE_CAP_BYTES}-byte read cap — the file "
                "was not read"
            ]

        raw_text = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return None, [f"report filter file is not valid UTF-8: {exc}"]
    except OSError as exc:
        return None, [f"report filter file could not be read: {exc}"]

    return raw_text, []


def _parse_address(value: Any, field_name: str, errors: list[str]) -> Optional[int]:
    """
    Summary:
        Parse one address field accepting a JSON integer or a
        ``"0x"``-prefixed hex string (LLR-053.1), collecting a named
        diagnostic on any other shape.

    Args:
        value (Any): The raw JSON value for the field.
        field_name (str): The dotted key path (e.g.
            ``include.addresses[3].start``) named in the diagnostic.
        errors (list[str]): The parse error accumulator, appended on fault.

    Returns:
        Optional[int]: The parsed integer, or ``None`` when a diagnostic
        was collected.

    Data Flow:
        - bool rejected (JSON true/false is not an address), int passed
          through, ``0x``-prefixed str parsed base-16; everything else →
          one named error.

    Dependencies:
        Used by:
            - parse_report_filter
    """
    if isinstance(value, bool):
        errors.append(
            f"'{field_name}' must be an integer or '0x' hex string, got a boolean"
        )
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value[:2].lower() == "0x":
        try:
            return int(value, 16)
        except ValueError:
            errors.append(f"'{field_name}' is not a parsable hex string: {value!r}")
            return None
    errors.append(
        f"'{field_name}' must be an integer or '0x' hex string, got {value!r}"
    )
    return None


def parse_report_filter(text: str) -> tuple[Optional[ReportFilter], list[str]]:
    """
    Summary:
        Parse already-in-memory report-filter JSON ``text`` against the
        ``s19app-report-filter`` v1.0 envelope (LLR-053.1), collecting ONE
        NAMED DIAGNOSTIC PER FAULT — a file with N distinct faults yields
        >= N diagnostics, each naming the offending key/index — and NEVER
        raising. Empty ``include`` lists are VALID and match nothing
        (D-10). A MISSING ``include`` key, or a missing ``symbols`` /
        ``addresses`` sub-key, is likewise accepted as the empty list
        (D-10a — same zero-match semantics; the realistic ``"includes"``
        typo is rejected as an unknown top-level key). An
        unbalanced-bracket pattern such as ``CAL_[`` is VALID
        (Q-10): ``fnmatchcase`` treats the lone ``[`` literally and the F-2
        equality branch keeps it inert-safe — never a parse rejection.

    Args:
        text (str): The raw JSON filter text (already read by
            :func:`read_report_filter_text`).

    Returns:
        tuple[Optional[ReportFilter], list[str]]: ``(filter, [])`` on
        success; ``(None, [one error per fault])`` on any envelope, key,
        type, domain, or ceiling fault. Never raises.

    Raises:
        None: Every failure mode is a collected error string.

    Data Flow:
        - ``json.loads``; malformed JSON / non-object top level → one
          error, parsing stops (no structure to walk).
        - Envelope: ``format`` / ``version`` equality, unknown top-level
          and ``include``-level keys → one error each.
        - ``include.symbols``: list of str, ceiling
          :data:`SYMBOL_PATTERN_CEILING`.
        - ``include.addresses``: list of ``{"start", "end"}`` objects,
          hex-or-int values, domain ``0 <= start < end <= 2^32``
          (:data:`_ADDRESS_SPACE_END`), ceiling
          :data:`ADDRESS_RANGE_CEILING`.

    Dependencies:
        Uses:
            - json (stdlib parse)
            - _parse_address
        Used by:
            - the app-side filter resolution step at report trigger time
              (LLR-053.5/053.7; batch-35 Inc-2+)
            - tests/test_report_filter.py (TC-307/308/309)

    Example:
        >>> flt, errors = parse_report_filter(
        ...     '{"format": "s19app-report-filter", "version": "1.0",'
        ...     ' "include": {"symbols": ["CAL_*"],'
        ...     ' "addresses": [{"start": "0x10", "end": 32}]}}'
        ... )
        >>> errors
        []
        >>> flt.addresses
        ((16, 32),)
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
        return None, [f"report filter is not valid JSON: {exc}"]

    if not isinstance(data, dict):
        return None, ["report filter top level must be a JSON object"]

    errors: list[str] = []

    if data.get("format") != REPORT_FILTER_FORMAT_ID:
        errors.append(
            f"'format' must be {REPORT_FILTER_FORMAT_ID!r}, "
            f"got {data.get('format')!r}"
        )
    if data.get("version") != REPORT_FILTER_FORMAT_VERSION:
        errors.append(
            f"'version' must be {REPORT_FILTER_FORMAT_VERSION!r}, "
            f"got {data.get('version')!r}"
        )
    for key in data:
        if key not in _TOP_LEVEL_KEYS:
            errors.append(f"unknown top-level key {key!r}")

    symbols: list[str] = []
    addresses: list[tuple[int, int]] = []

    include = data.get("include", {})
    if not isinstance(include, dict):
        errors.append("'include' must be a JSON object")
        include = {}

    for key in include:
        if key not in _INCLUDE_KEYS:
            errors.append(f"unknown 'include' key {key!r}")

    raw_symbols = include.get("symbols", [])
    if not isinstance(raw_symbols, list):
        errors.append("'include.symbols' must be a list")
    else:
        if len(raw_symbols) > SYMBOL_PATTERN_CEILING:
            errors.append(
                f"'include.symbols' declares {len(raw_symbols)} patterns, "
                f"over the {SYMBOL_PATTERN_CEILING}-pattern ceiling"
            )
        for index, pattern in enumerate(raw_symbols):
            if not isinstance(pattern, str):
                errors.append(
                    f"'include.symbols[{index}]' must be a string, "
                    f"got {pattern!r}"
                )
            else:
                symbols.append(pattern)

    raw_addresses = include.get("addresses", [])
    if not isinstance(raw_addresses, list):
        errors.append("'include.addresses' must be a list")
    else:
        if len(raw_addresses) > ADDRESS_RANGE_CEILING:
            errors.append(
                f"'include.addresses' declares {len(raw_addresses)} ranges, "
                f"over the {ADDRESS_RANGE_CEILING}-range ceiling"
            )
        for index, entry in enumerate(raw_addresses):
            entry_name = f"include.addresses[{index}]"
            if not isinstance(entry, dict):
                errors.append(f"'{entry_name}' must be a JSON object")
                continue
            start = _parse_address(entry.get("start"), f"{entry_name}.start", errors)
            end = _parse_address(entry.get("end"), f"{entry_name}.end", errors)
            if start is None or end is None:
                continue
            if start < 0:
                errors.append(
                    f"'{entry_name}.start' ({start}) is outside the pinned "
                    "address domain (must be >= 0)"
                )
                continue
            if end > _ADDRESS_SPACE_END:
                errors.append(
                    f"'{entry_name}.end' (0x{end:X}) is outside the pinned "
                    "address domain (must be <= 2^32)"
                )
                continue
            if start >= end:
                errors.append(
                    f"'{entry_name}': 'start' (0x{start:X}) must be less "
                    f"than 'end' (0x{end:X}) — 'end' is exclusive"
                )
                continue
            addresses.append((start, end))

    if errors:
        return None, errors
    return ReportFilter(symbols=tuple(symbols), addresses=tuple(addresses)), []


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """
    Summary:
        Merge possibly-overlapping half-open ranges into a disjoint sorted
        list, the precondition for correct ``range_index`` membership (its
        binary search assumes non-overlapping ranges).

    Args:
        ranges (list[tuple[int, int]]): Half-open ``(start, end)`` ranges
            in any order; empty/inverted ranges are dropped.

    Returns:
        list[tuple[int, int]]: Disjoint ranges sorted by start; touching
        ranges are coalesced.

    Data Flow:
        - Sort by start, then single-pass coalesce.

    Dependencies:
        Used by:
            - resolve_report_filter
    """
    merged: list[tuple[int, int]] = []
    for start, end in sorted(r for r in ranges if r[0] < r[1]):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def resolve_report_filter(
    report_filter: ReportFilter,
    a2l_records: Any,
    mac_records: Any,
) -> ReportFilterMatcher:
    """
    Summary:
        Build the per-run :class:`ReportFilterMatcher` (LLR-053.7 / D-9):
        the matched address set is the union of the filter's explicit
        ``include.addresses`` ranges and the address EXTENTS of loaded
        A2L/MAC records whose NAME matches an ``include.symbols`` pattern
        (LLR-053.4(c)). A record's extent is
        ``[address, address + byte_size)`` when ``byte_size`` is a positive
        integer, else ``[address, address + 1)`` (F-1: enriched A2L tags
        carry ``byte_size``; MAC records carry none → point). The
        never-raise contract extends to resolution for any record shape
        (S-F4): a non-dict record, a non-int address, or a hostile
        collection is skipped, never an error.

    Args:
        report_filter (ReportFilter): The parsed filter
            (:func:`parse_report_filter` success output).
        a2l_records (Any): The loaded enriched A2L tag records — dicts with
            ``'address'`` / ``'name'`` and optionally ``'byte_size'`` (the
            shapes consumed by ``_artifact_addresses_with_names``).
        mac_records (Any): The loaded MAC records — dicts with
            ``'address'`` / ``'name'``.

    Returns:
        ReportFilterMatcher: Patterns plus the merged, sorted
        matched-address index. Never raises.

    Raises:
        None: Hostile shapes are skipped (never-raise, S-F4).

    Data Flow:
        - Seed the range list with the filter's explicit address ranges.
        - Per record (both artifact lists): skip non-dict records and
          non-int addresses; name-match via :func:`_symbol_matches`; append
          the F-1 extent.
        - Merge to disjoint ranges (:func:`_merge_ranges`), then build the
          sorted index via ``build_sorted_range_index`` (consumed from the
          engine-frozen ``range_index`` module, never modified).

    Dependencies:
        Uses:
            - _symbol_matches (branch (a) on record names)
            - _merge_ranges
            - range_index.build_sorted_range_index
        Used by:
            - the app-side filter resolution step at report trigger time
              (LLR-053.5/053.7; batch-35 Inc-2+)
            - tests/test_report_filter.py (TC-310)

    Example:
        >>> flt, _ = parse_report_filter(
        ...     '{"format": "s19app-report-filter", "version": "1.0",'
        ...     ' "include": {"symbols": ["CAL_*"], "addresses": []}}'
        ... )
        >>> matcher = resolve_report_filter(
        ...     flt, [{"name": "CAL_X", "address": 16, "byte_size": 4}], []
        ... )
        >>> matcher.matches_range(19, 20)
        True
    """
    patterns: tuple[str, ...] = ()
    ranges: list[tuple[int, int]] = []
    try:
        patterns = tuple(p for p in report_filter.symbols if isinstance(p, str))
        ranges = [
            (start, end)
            for start, end in report_filter.addresses
            if isinstance(start, int) and isinstance(end, int)
        ]
    except Exception:
        patterns = patterns if isinstance(patterns, tuple) else ()
        ranges = []

    for records in (a2l_records, mac_records):
        try:
            for record in records or []:
                if not isinstance(record, dict):
                    continue
                address = record.get("address")
                if isinstance(address, bool) or not isinstance(address, int):
                    continue
                name = record.get("name")
                if not isinstance(name, str) or not _symbol_matches(name, patterns):
                    continue
                byte_size = record.get("byte_size")
                extent = (
                    byte_size
                    if (
                        isinstance(byte_size, int)
                        and not isinstance(byte_size, bool)
                        and byte_size > 0
                    )
                    else 1
                )
                ranges.append((address, address + extent))
        except Exception:
            continue

    matched_index = build_sorted_range_index(_merge_ranges(ranges))
    return ReportFilterMatcher(patterns=patterns, matched_index=matched_index)
