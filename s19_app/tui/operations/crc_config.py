"""
External CRC config reader (batch-12 CRC_F2, HLR-004 / LLR-004.1, increment I2).

Sources the CRC operation's algorithm parameters and region/output-address
geometry from an operator-supplied JSON file resolved via
``workspace.resolve_input_path`` (§6.2 D-3). Real per-firmware values are
never committed to the repo — only ``examples/crc_config.example.json``
(DUMMY values, format guidance) and synthetic test fixtures live in-tree.

This module mirrors the read-path contract of
``s19_app.tui.changes.io.read_change_document`` (``io.py:266``):

- resolve the path via ``resolve_input_path`` — an unresolvable path is one
  collected error and no file is opened;
- enforce the shared ``READ_SIZE_CAP_BYTES`` size cap BEFORE reading — an
  over-cap file is one collected error and is never read into memory;
- **collect-don't-abort:** every data-quality fault (unresolvable path,
  over-cap, malformed JSON, missing/invalid field) returns ``(None, [one
  error string])`` and NEVER raises.

Headless: no Textual import, no file write-back. The config FILE is read-only
and uncontained-by-design (F-S-02), at parity with ``read_change_document``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from ..changes.io import READ_SIZE_CAP_BYTES
from ..workspace import resolve_input_path

#: The on-disk size-measurement seam — the read path takes the byte-size
#: probe as an injectable callable so a test can report an over-cap size
#: without manufacturing a real 256 MB file. ``None`` (the default) resolves
#: to a real ``Path.stat().st_size`` at call time.
SizeProbe = Callable[[Path], int]

#: Dummy CRC config text used to pre-fill the TUI config editor for format
#: guidance (LLR-004.2). Byte-for-byte the committed
#: ``examples/crc_config.example.json`` dummy template — FAKE poly / init /
#: ranges / output-addresses only, never real per-firmware values (§1.2
#: out-of-scope, RK-5). It parses cleanly through :func:`parse_crc_config`,
#: so a TC can assert the pre-fill is itself valid config text.
DUMMY_CONFIG_TEXT: str = """{
  "polynomial": "0x04C11DB7",
  "init": "0xFFFFFFFF",
  "reverse": true,
  "final_xor": "0xFFFFFFFF",
  "regions": [
    { "start": "0x00010000", "end": "0x00020000", "output_address": "0x0001FFFC" },
    { "start": "0x00020000", "end": "0x00030000", "output_address": "0x0002FFFC" }
  ]
}
"""


#: Allowed values for a group's ``output_bytes`` field (batch-32
#: LLR-GRP-001.3 / R-CRC-WIDTH-001): the stored CRC field is 1, 2, 4, or 8
#: little-endian bytes; 4 is the default and matches the legacy fixed codec.
ALLOWED_OUTPUT_BYTES: tuple[int, ...] = (1, 2, 4, 8)

#: Parse-time ceiling on the TOTAL declared span count —
#: ``len(regions) + sum(len(group spans))`` (batch-32 LLR-GRP-001.14,
#: security F1). Each declared span costs a full ``mem_map`` scan in
#: ``region_segments`` (O(spans x image bytes) overall), so this ceiling is
#: deliberately TIGHTER than the change-document ``MF_ENTRY_COUNT_CEILING``
#: (whose entries are O(1) each): generous for any real firmware layout,
#: while bounding the compute a pathological config can demand.
CRC_SPAN_COUNT_CEILING: int = 4096

#: Exclusive upper bound of the 32-bit S19 address space (batch-32
#: LLR-GRP-001.15, security F2): group span/output ints must be
#: non-negative and fit the space, including the output WINDOW
#: (``output_address + output_bytes``), or the S19 emitter would produce a
#: structurally corrupt record that only surfaces as a baffling
#: verify-mismatch. Legacy ``regions`` keep their tolerant parse (strict
#: AT-044a compat) — the bound applies to groups only.
_ADDRESS_SPACE_END: int = 0x1_0000_0000


@dataclass(frozen=True)
class CrcRegion:
    """
    Summary:
        One configured CRC region: a half-open ``(start, end)`` address range
        whose present bytes are CRC'd, paired with the output address at which
        the 4-byte little-endian CRC is stored/written (§6.2 D-3).

    Args:
        start (int): Inclusive lower address bound of the region.
        end (int): Exclusive upper address bound (half-open, matching the
            ``LoadedFile.ranges`` ``(start, end)`` convention).
        output_address (int): The address at which this region's computed CRC
            is read (check) or written (inject).

    Data Flow:
        - Built by :func:`read_crc_config` from one JSON ``regions`` entry,
          each hex string parsed via ``int(s, 16)``.

    Dependencies:
        Used by:
            - read_crc_config (constructs the list)
            - the CRC engine / check / inject paths (consume start/end/output)
    """

    start: int
    end: int
    output_address: int


@dataclass(frozen=True)
class CrcGroup:
    """
    Summary:
        One configured CRC GROUP (batch-32, R-CRC-GROUP-001): an ordered
        list of half-open ``(start, end)`` spans whose present bytes are
        concatenated IN DECLARED ORDER and fed through ONE CRC computation,
        paired with the single output address and LE byte width at which
        that one CRC is read (check) or written (inject).

    Args:
        spans (tuple[tuple[int, int], ...]): The declared spans, in file
            order. Each is inclusive-start / exclusive-end, matching the
            ``CrcRegion`` convention. Declared order is authoritative —
            spans are never address-sorted or deduplicated (S-1/S-2).
        output_address (int): The single address the group's CRC occupies.
        output_bytes (int): The stored field width in little-endian bytes —
            one of :data:`ALLOWED_OUTPUT_BYTES`; defaults to 4 at parse.

    Data Flow:
        - Built by :func:`_build_group` from one JSON ``groups`` entry.

    Dependencies:
        Used by:
            - _build_config (constructs the list)
            - the CRC engine group compute / check / inject paths
    """

    spans: tuple[tuple[int, int], ...]
    output_address: int
    output_bytes: int


@dataclass(frozen=True)
class CrcConfig:
    """
    Summary:
        The typed CRC operation config parsed from the operator-supplied JSON:
        the algorithm parameter set (polynomial, init, reverse flag, final
        XOR), the list of legacy per-region CRC targets (§6.2 D-3), and the
        list of multi-span single-CRC groups (batch-32, R-CRC-GROUP-001).

    Args:
        regions (list[CrcRegion]): The configured legacy CRC regions, in file
            order. Optional in the JSON since batch-32 — but at least one of
            ``regions`` / ``groups`` must be present and non-empty.
        polynomial (int): The CRC32 polynomial.
        init (int): The CRC register initial value.
        reverse (bool): ``True`` selects standard reflected-input/output
            (refin/refout) semantics — the zlib/PKZIP convention.
        final_xor (int): The value XOR'd into the final register (xorout).
        groups (list[CrcGroup]): The configured multi-span groups, in file
            order; empty for a legacy-only config (byte-identical behavior
            to the pre-batch-32 system).

    Data Flow:
        - Returned by :func:`read_crc_config` on a successful parse; consumed
          by the CRC engine to compute one CRC per region and one per group.

    Dependencies:
        Used by:
            - read_crc_config (constructs it)
            - the CRC engine entry point (consumes params + regions + groups)
    """

    regions: list[CrcRegion]
    polynomial: int
    init: int
    reverse: bool
    final_xor: int
    groups: list[CrcGroup] = field(default_factory=list)


def _parse_int(value: Any) -> int:
    """
    Summary:
        Coerce a JSON scalar to an ``int``, accepting both a hex string
        (``"0x04C11DB7"`` → ``int(s, 16)``) and a native JSON integer.

    Args:
        value (Any): The raw JSON value for an int-typed config field.

    Returns:
        int: The parsed integer.

    Raises:
        ValueError: When ``value`` is neither an int nor a base-16-parseable
            string. Callers catch this and convert it to a collected error
            (the module never lets it escape).

    Data Flow:
        - Called per int-typed field by :func:`read_crc_config`.

    Dependencies:
        Used by:
            - read_crc_config
    """
    if isinstance(value, bool):
        raise ValueError("expected an integer, got a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16)
    raise ValueError(f"expected an int or hex string, got {type(value).__name__}")


def read_crc_config(
    raw_path: str,
    base_dir: Optional[Path] = None,
    size_probe: Optional[SizeProbe] = None,
) -> tuple[Optional[CrcConfig], list[str]]:
    """
    Summary:
        Read an operator-supplied CRC config JSON file into a typed
        :class:`CrcConfig`, collecting any data-quality fault as a single
        error string without ever raising (the ``read_change_document``
        collect-don't-abort contract, ``io.py:266``).

    Args:
        raw_path (str): The user-supplied config file path, resolved through
            ``workspace.resolve_input_path`` before the file is opened — an
            unresolvable path is one collected error and no file is opened.
        base_dir (Optional[Path]): The base directory ``resolve_input_path``
            resolves a RELATIVE path against (cwd of the resolver's caller).
            ``None`` (the default) uses the current working directory.
        size_probe (Optional[SizeProbe]): The on-disk byte-size measurement
            seam. ``None`` (the default) resolves to a real
            ``Path.stat().st_size`` at call time; injectable so a test can
            report an over-cap size without a real 256 MB file.

    Returns:
        tuple[Optional[CrcConfig], list[str]]: ``(config, [])`` on success;
        ``(None, [one error string])`` on ANY data-quality fault
        (unresolvable path, over-cap, malformed JSON, missing/invalid field).
        The list carries exactly one error on failure (LLR-004.1 numeric
        threshold) and is empty on success. Never raises on a data fault.

    Raises:
        None: Every failure mode is a collected error string
            (collect-don't-abort). The only paths to a raise are programming
            errors outside this contract.

    Data Flow:
        - Read the raw text via :func:`read_crc_config_text` (resolve +
          size-cap + ``read_text``); any read fault is returned verbatim as
          ``(None, [one error])`` — the file is never parsed.
        - On a clean read, delegate to :func:`parse_crc_config`; any
          parse/structure fault becomes one collected error.

    Dependencies:
        Uses:
            - read_crc_config_text (resolve + size-cap + raw read)
            - parse_crc_config (typed-build from the raw text)
        Used by:
            - the CRC operation config-sourcing path (HLR-004) and its TUI
              surface (LLR-004.2)

    Example:
        >>> config, errors = read_crc_config("examples/crc_config.example.json")
        >>> errors
        []
        >>> config.polynomial
        79764919
    """
    raw_text, errors = read_crc_config_text(raw_path, base_dir, size_probe)
    if errors:
        return None, errors
    assert raw_text is not None  # no errors ⇒ raw text present (read succeeded)
    return parse_crc_config(raw_text)


def read_crc_config_text(
    raw_path: str,
    base_dir: Optional[Path] = None,
    size_probe: Optional[SizeProbe] = None,
) -> tuple[Optional[str], list[str]]:
    """
    Summary:
        Read an operator-supplied CRC config file's RAW TEXT into memory —
        resolve + size-cap + ``read_text`` — WITHOUT parsing it, collecting any
        data-quality fault as a single error string and NEVER raising (the
        ``read_change_document`` collect-don't-abort contract, ``io.py:266``).
        This is the load seam the TUI "Load config" button (LLR-013.2) routes
        through to populate the editable ``#operation_config`` ``TextArea``:
        the editor stays the single source of truth, and the CRC run still
        parses that text on Execute via :func:`parse_crc_config`. It is the
        body of :func:`read_crc_config` minus the final parse delegation.

    Args:
        raw_path (str): The user-supplied config file path, resolved through
            ``workspace.resolve_input_path`` before the file is opened — an
            unresolvable path is one collected error and no file is opened.
        base_dir (Optional[Path]): The base directory ``resolve_input_path``
            resolves a RELATIVE path against. ``None`` (the default) uses the
            current working directory.
        size_probe (Optional[SizeProbe]): The on-disk byte-size measurement
            seam. ``None`` (the default) resolves to a real
            ``Path.stat().st_size`` at call time; injectable so a test can
            report an over-cap size without a real 256 MB file.

    Returns:
        tuple[Optional[str], list[str]]: ``(raw_text, [])`` on success;
        ``(None, [one error string])`` on ANY data-quality fault (unresolvable
        path, over-cap, unreadable). The list carries exactly one error on
        failure and is empty on success. Never raises on a data fault. NB: the
        raw text is NOT parsed here, so a syntactically-invalid-but-readable
        file still returns ``(raw_text, [])`` — the JSON fault surfaces later
        at parse-on-run.

    Raises:
        None: Every failure mode is a collected error string
            (collect-don't-abort), matching :func:`read_crc_config`'s fault
            shape and messages.

    Data Flow:
        - Resolve ``raw_path`` via ``resolve_input_path``; unresolvable → one
          error, ``None`` text.
        - Probe the on-disk size; over :data:`READ_SIZE_CAP_BYTES` → one
          error, ``None`` text — the file is never read.
        - ``read_text`` the file; an ``OSError`` → one error, ``None`` text.

    Dependencies:
        Uses:
            - workspace.resolve_input_path (path resolution)
            - changes.io.READ_SIZE_CAP_BYTES (shared 256 MB read cap)
        Used by:
            - read_crc_config (delegates here, then parses)
            - the CRC TUI "Load config" surface (LLR-013.2)

    Example:
        >>> text, errors = read_crc_config_text("examples/crc_config.example.json")
        >>> errors
        []
        >>> text.startswith("{")
        True
    """
    resolve_base = Path.cwd() if base_dir is None else base_dir
    resolved = resolve_input_path(Path(raw_path), resolve_base)
    if resolved is None:
        return None, [f"CRC config path could not be resolved: {raw_path!r}"]

    probe: SizeProbe = (
        (lambda candidate: candidate.stat().st_size)
        if size_probe is None
        else size_probe
    )
    size_bytes = probe(resolved)
    if size_bytes > READ_SIZE_CAP_BYTES:
        return None, [
            f"CRC config file is {size_bytes} bytes, over the "
            f"{READ_SIZE_CAP_BYTES}-byte read cap — the file was not read"
        ]

    try:
        raw_text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [f"CRC config file could not be read: {exc}"]

    return raw_text, []


def parse_crc_config(text: str) -> tuple[Optional[CrcConfig], list[str]]:
    """
    Summary:
        Parse already-in-memory CRC config JSON ``text`` into a typed
        :class:`CrcConfig`, under the same collect-don't-abort contract as
        :func:`read_crc_config` — every parse/structure fault returns
        ``(None, [one error string])`` and the function NEVER raises. This is
        the text-level seam the TUI editor surface (LLR-004.2) routes its
        edited config through, and the body :func:`read_crc_config` delegates
        to after it has resolved + size-capped + read the file.

    Args:
        text (str): The raw JSON config text (from the TUI editor or a file
            already read by :func:`read_crc_config`).

    Returns:
        tuple[Optional[CrcConfig], list[str]]: ``(config, [])`` on success;
        ``(None, [one error string])`` on any parse or structure fault. The
        list carries exactly one error on failure and is empty on success.

    Raises:
        None: Every failure mode is a collected error string
            (collect-don't-abort), matching :func:`read_crc_config`.

    Data Flow:
        - Parse ``text`` with stdlib ``json`` catching parse/decode errors →
          one error.
        - Reject a non-object top level → one error.
        - Build the typed :class:`CrcConfig`; any missing/invalid field →
          one error.

    Dependencies:
        Uses:
            - json (stdlib parse)
            - _build_config
        Used by:
            - read_crc_config (file path delegates here after read)
            - the CRC TUI config surface (LLR-004.2, edited-text parse)
            - tests/test_crc_config.py (parse_crc_config tests)

    Example:
        >>> config, errors = parse_crc_config(DUMMY_CONFIG_TEXT)
        >>> errors
        []
        >>> config.polynomial
        79764919
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, [f"CRC config is not valid JSON: {exc}"]

    if not isinstance(data, dict):
        return None, ["CRC config top level must be a JSON object"]

    try:
        config = _build_config(data)
    except (KeyError, TypeError, ValueError) as exc:
        return None, [f"CRC config is structurally invalid: {exc}"]

    return config, []


def _build_config(data: dict[str, Any]) -> CrcConfig:
    """
    Summary:
        Build a typed :class:`CrcConfig` from a parsed JSON object, parsing
        each int field from hex-string-or-int: the legacy ``regions`` (each
        region's three address fields, tolerant pre-batch-32 rules) and the
        batch-32 ``groups`` (strict rules via :func:`_build_group`), under
        the at-least-one-of presence rule and the total-span-count ceiling
        (:data:`CRC_SPAN_COUNT_CEILING`).

    Args:
        data (dict[str, Any]): The parsed top-level JSON object.

    Returns:
        CrcConfig: The fully-populated config.

    Raises:
        KeyError: A required field is missing.
        TypeError: A field has the wrong JSON type (e.g. ``reverse`` not a
            bool, ``regions``/``groups`` not a list, an entry not an object).
        ValueError: An int field is not a base-16-parseable string/int;
            neither ``regions`` nor ``groups`` is present and non-empty; a
            group rule violation (see :func:`_build_group`); or the total
            declared span count exceeds the ceiling — the ceiling applies to
            the COMBINED count, so a pathological >4096-region legacy-only
            config is now also rejected (recorded as part of the batch-32
            §6.5 amendment #1).

    Data Flow:
        - Called by :func:`parse_crc_config` inside its fault-collecting
          guard; any exception here becomes a single collected error string.

    Dependencies:
        Uses:
            - _parse_int
            - _build_group
        Used by:
            - parse_crc_config
    """
    reverse = data["reverse"]
    if not isinstance(reverse, bool):
        raise TypeError("field 'reverse' must be a boolean")

    raw_regions = data.get("regions", [])
    if not isinstance(raw_regions, list):
        raise TypeError("field 'regions' must be a list")
    raw_groups = data.get("groups", [])
    if not isinstance(raw_groups, list):
        raise TypeError("field 'groups' must be a list")
    # §6.5 amendment #1 (batch-32): the pre-batch-32 rule "field 'regions'
    # must contain at least one region" widens to at-least-one-of.
    if not raw_regions and not raw_groups:
        raise ValueError(
            "at least one of 'regions' / 'groups' must be present and non-empty"
        )

    regions: list[CrcRegion] = []
    for index, raw_region in enumerate(raw_regions):
        if not isinstance(raw_region, dict):
            raise TypeError(f"region {index} must be a JSON object")
        regions.append(
            CrcRegion(
                start=_parse_int(raw_region["start"]),
                end=_parse_int(raw_region["end"]),
                output_address=_parse_int(raw_region["output_address"]),
            )
        )

    groups: list[CrcGroup] = []
    for index, raw_group in enumerate(raw_groups):
        groups.append(_build_group(index, raw_group))

    total_spans = len(regions) + sum(len(group.spans) for group in groups)
    if total_spans > CRC_SPAN_COUNT_CEILING:
        raise ValueError(
            f"config declares {total_spans} spans, over the "
            f"{CRC_SPAN_COUNT_CEILING}-span ceiling"
        )

    return CrcConfig(
        regions=regions,
        polynomial=_parse_int(data["polynomial"]),
        init=_parse_int(data["init"]),
        reverse=reverse,
        final_xor=_parse_int(data["final_xor"]),
        groups=groups,
    )


def _build_group(index: int, raw_group: Any) -> CrcGroup:
    """
    Summary:
        Build one typed :class:`CrcGroup` from a JSON ``groups`` entry,
        enforcing the batch-32 group-strict validation rules (LLR-GRP-001.3
        / .15): span shape, N5 inverted-span rejection, N6 stray
        ``output_address`` rejection, the :data:`ALLOWED_OUTPUT_BYTES` set,
        and the 32-bit address-space bounds (including the output WINDOW
        ``output_address + output_bytes``). Legacy ``regions`` deliberately
        do NOT pass through these bounds (strict AT-044a compat).

    Args:
        index (int): The group's position in the ``groups`` list (used in
            error strings so the operator can find the offending entry).
        raw_group (Any): The raw JSON value for this ``groups`` entry.

    Returns:
        CrcGroup: The fully-validated group.

    Raises:
        KeyError: A required field (``regions``, ``output_address``, a span's
            ``start``/``end``) is missing.
        TypeError: A field has the wrong JSON type.
        ValueError: A rule violation — empty span list, inverted span (N5),
            stray ``output_address`` in a span (N6), ``output_bytes`` outside
            the allowed set, or an out-of-address-space value. Callers catch
            all three and convert to one collected error string.

    Data Flow:
        - Called per ``groups`` entry by :func:`_build_config` inside the
          fault-collecting guard of :func:`parse_crc_config`.

    Dependencies:
        Uses:
            - _parse_int
        Used by:
            - _build_config
    """
    if not isinstance(raw_group, dict):
        raise TypeError(f"group {index} must be a JSON object")

    raw_spans = raw_group["regions"]
    if not isinstance(raw_spans, list):
        raise TypeError(f"group {index}: field 'regions' must be a list")
    if not raw_spans:
        raise ValueError(f"group {index}: field 'regions' must not be empty")

    spans: list[tuple[int, int]] = []
    for span_index, raw_span in enumerate(raw_spans):
        if not isinstance(raw_span, dict):
            raise TypeError(f"group {index} span {span_index} must be a JSON object")
        if "output_address" in raw_span:
            # N6 tripwire: this key's presence is the signature of a legacy
            # region pasted into a group (its author expects per-span CRCs).
            # Targeted rejection on this ONE key only — general unknown-key
            # tolerance is unchanged.
            raise ValueError(
                f"group {index} span {span_index}: 'output_address' is not "
                "allowed inside a group span (a group has exactly one "
                "output_address)"
            )
        start = _parse_int(raw_span["start"])
        end = _parse_int(raw_span["end"])
        if start < 0:
            raise ValueError(
                f"group {index} span {span_index}: 'start' must be non-negative"
            )
        if end > _ADDRESS_SPACE_END:
            raise ValueError(
                f"group {index} span {span_index}: 'end' (0x{end:X}) exceeds "
                "the 32-bit address space"
            )
        if end <= start:
            # N5: an inverted/empty span is always a typo — if accepted, it
            # would contribute zero bytes AND zero absent-count, so no
            # coverage note could ever fire (a fully silent divergence).
            raise ValueError(
                f"group {index} span {span_index}: 'end' (0x{end:X}) must be "
                f"greater than 'start' (0x{start:X})"
            )
        spans.append((start, end))

    output_bytes_raw = raw_group.get("output_bytes", 4)
    try:
        output_bytes = _parse_int(output_bytes_raw)
    except ValueError:
        # Re-raise with the field named — _parse_int's raw message ("invalid
        # literal ...") gives the operator no field/group to look at.
        raise ValueError(
            f"group {index}: 'output_bytes' must be one of "
            f"{list(ALLOWED_OUTPUT_BYTES)}, got {output_bytes_raw!r}"
        ) from None
    if output_bytes not in ALLOWED_OUTPUT_BYTES:
        raise ValueError(
            f"group {index}: 'output_bytes' must be one of "
            f"{list(ALLOWED_OUTPUT_BYTES)}, got {output_bytes_raw!r}"
        )

    output_address = _parse_int(raw_group["output_address"])
    if output_address < 0:
        raise ValueError(f"group {index}: 'output_address' must be non-negative")
    if output_address + output_bytes > _ADDRESS_SPACE_END:
        raise ValueError(
            f"group {index}: output window [0x{output_address:X}, "
            f"0x{output_address:X}+{output_bytes}) exceeds the 32-bit "
            "address space"
        )

    return CrcGroup(
        spans=tuple(spans),
        output_address=output_address,
        output_bytes=output_bytes,
    )
