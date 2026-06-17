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
from dataclasses import dataclass
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
class CrcConfig:
    """
    Summary:
        The typed CRC operation config parsed from the operator-supplied JSON:
        the algorithm parameter set (polynomial, init, reverse flag, final
        XOR) and the list of CRC regions (§6.2 D-3).

    Args:
        regions (list[CrcRegion]): The configured CRC regions, in file order.
        polynomial (int): The CRC32 polynomial.
        init (int): The CRC register initial value.
        reverse (bool): ``True`` selects standard reflected-input/output
            (refin/refout) semantics — the zlib/PKZIP convention.
        final_xor (int): The value XOR'd into the final register (xorout).

    Data Flow:
        - Returned by :func:`read_crc_config` on a successful parse; consumed
          by the CRC engine to compute one CRC per region.

    Dependencies:
        Used by:
            - read_crc_config (constructs it)
            - the CRC engine entry point (consumes params + regions)
    """

    regions: list[CrcRegion]
    polynomial: int
    init: int
    reverse: bool
    final_xor: int


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
        - Resolve ``raw_path`` via ``resolve_input_path``; unresolvable → one
          error, ``None`` config.
        - Probe the on-disk size; over :data:`READ_SIZE_CAP_BYTES` → one
          error, ``None`` config — the file is never read.
        - Parse with stdlib ``json`` catching parse/decode errors → one error.
        - Build the typed :class:`CrcConfig`; any missing/invalid field
          (wrong type, un-parseable hex, malformed region) → one error.

    Dependencies:
        Uses:
            - workspace.resolve_input_path (path resolution)
            - changes.io.READ_SIZE_CAP_BYTES (shared 256 MB read cap)
            - json (stdlib parse)
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

    return parse_crc_config(raw_text)


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
        each int field from hex-string-or-int and each region's three address
        fields the same way.

    Args:
        data (dict[str, Any]): The parsed top-level JSON object.

    Returns:
        CrcConfig: The fully-populated config.

    Raises:
        KeyError: A required field is missing.
        TypeError: A field has the wrong JSON type (e.g. ``reverse`` not a
            bool, ``regions`` not a list, a region not an object).
        ValueError: An int field is not a base-16-parseable string/int.

    Data Flow:
        - Called by :func:`read_crc_config` inside its fault-collecting guard;
          any exception here becomes a single collected error string.

    Dependencies:
        Uses:
            - _parse_int
        Used by:
            - read_crc_config
    """
    reverse = data["reverse"]
    if not isinstance(reverse, bool):
        raise TypeError("field 'reverse' must be a boolean")

    raw_regions = data["regions"]
    if not isinstance(raw_regions, list):
        raise TypeError("field 'regions' must be a list")
    if not raw_regions:
        raise ValueError("field 'regions' must contain at least one region")

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

    return CrcConfig(
        regions=regions,
        polynomial=_parse_int(data["polynomial"]),
        init=_parse_int(data["init"]),
        reverse=reverse,
        final_xor=_parse_int(data["final_xor"]),
    )
