"""
CRC Algorithm Designer — template / job / coverage model (batch-52, HLR E3/E5/E6).

The typed building blocks the designer view is built on, and the JSON round-trip
(parse + emit) under the ``read_crc_config`` collect-don't-abort contract
(``crc_config.py`` / ``changes.io.read_change_document``): every data-quality
fault returns ``(None, [one error string])`` and NEVER raises.

Two artifacts (requirements §2 / §4):

- :class:`CrcTemplate` — a reusable, placement-free algorithm template
  (``*.crc.json``); wraps a :class:`~s19_app.tui.operations.crc_kernel.CrcAlgorithm`.
- :class:`CrcJob` — a per-firmware job: a resolved algorithm + one or more
  :class:`CrcTarget`, each a multi-range **coverage** (``intra_gap`` × ``join``
  gap policy) plus **serialization** (output address, store width/endianness).

:func:`gather_target` is the multi-range coverage primitive: it materializes a
target's byte window under the two independent gap policies. The pure algorithm
is exercised by the known-answer test; ``gather_target`` is exercised against
the verified oracles ``concat=0x9C5BCBBD`` / ``fill=0x2A8A3950`` (AT-CRC-DSN-013b).

Headless and ADDITIVE — no Textual import, no mutation of the shipped
``operations.crc`` engine. The file read reuses ``resolve_input_path`` +
``READ_SIZE_CAP_BYTES`` verbatim (no new untrusted-loader posture invented).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from ..changes.io import READ_SIZE_CAP_BYTES
from ..workspace import resolve_input_path
from .crc_kernel import CrcAlgorithm, preset_by_name

#: Exclusive upper bound of the 32-bit S19 address space (parity with
#: ``crc_config._ADDRESS_SPACE_END``): a target's range / output window must fit.
_ADDRESS_SPACE_END: int = 0x1_0000_0000

#: Parse-time ceiling on the total declared range count across all targets
#: (parity with ``crc_config.CRC_SPAN_COUNT_CEILING``, security F1): each range
#: costs a scan, so a pathological config is rejected rather than run.
RANGE_COUNT_CEILING: int = 4096

#: Allowed policy vocabularies — a value outside these is one collected error.
INTRA_GAP_VALUES: tuple[str, ...] = ("skip", "fill")
JOIN_VALUES: tuple[str, ...] = ("concat", "fill")
ENDIANNESS_VALUES: tuple[str, ...] = ("little", "big")
#: How the run path reacts when the actual image contradicts a gap the target
#: promised was empty (observation #2). ``abort`` is the default and the only
#: safe choice on the write path; ``warn`` proceeds with a diagnostic; ``ignore``
#: silences it (opt-in). Detection is :func:`gap_conflict`; enforcing the policy
#: is the caller's job (collect-don't-abort here, fail-loud at the write seam).
ON_GAP_CONFLICT_VALUES: tuple[str, ...] = ("abort", "warn", "ignore")

#: Injectable on-disk size probe (parity with ``crc_config.SizeProbe``).
SizeProbe = Callable[[Path], int]

#: Resolver from an ``algorithm_ref`` name to a :class:`CrcAlgorithm`. Defaults
#: to the seed presets; the TUI passes one that also searches the template lib.
AlgorithmResolver = Callable[[str], Optional[CrcAlgorithm]]


# ─────────────────────────────────────────────────────────────────────────────
# Typed model
# ─────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class CrcTarget:
    """
    Summary:
        One CRC target: an ordered list of memory ranges digested under two
        independent gap policies, plus where/how the result is stored
        (requirements §3.2 / §3.3). Superset of the shipped ``CrcGroup``
        (which is fixed at ``intra_gap="skip"``, ``join="concat"``).

    Args:
        ranges (tuple[tuple[int, int], ...]): Half-open ``(start, end)`` ranges
            in DECLARED order (never address-sorted).
        intra_gap (str): Holes INSIDE a range — ``"skip"`` (present bytes only)
            or ``"fill"`` (absent addresses take ``pad_byte``).
        join (str): Space BETWEEN consecutive ranges — ``"concat"`` (butt the
            present ranges together) or ``"fill"`` (pad the inter-range gap).
        pad_byte (int): Fill value for either policy (0..255).
        output_address (int): Where the CRC is read/written.
        store_width (int): Stored-field width in bytes (1..8).
        store_endianness (str): ``"little"`` or ``"big"``.
        on_gap_conflict (str): Safety policy (obs #2) — one of
            :data:`ON_GAP_CONFLICT_VALUES`. Governs how the caller reacts when
            the real image contradicts a gap this target promised was empty
            (see :func:`gap_conflict`). Defaults to ``"abort"``.

    Dependencies:
        Used by:
            - CrcJob, gather_target, compute_target_crc, store_word, gap_conflict
    """

    ranges: tuple[tuple[int, int], ...]
    intra_gap: str
    join: str
    pad_byte: int
    output_address: int
    store_width: int
    store_endianness: str
    on_gap_conflict: str = "abort"


@dataclass(frozen=True)
class CrcTemplate:
    """
    Summary:
        A reusable, placement-free algorithm template artifact — the pure math
        plus aliases, serialized as ``*.crc.json`` (requirements §4a).

    Args:
        algorithm (CrcAlgorithm): The parametric CRC.
        aliases (tuple[str, ...]): Alternate names (e.g. ``"zlib"``).
        schema_version (int): Template schema version.

    Dependencies:
        Uses:
            - CrcAlgorithm
        Used by:
            - parse_template / emit_template
    """

    algorithm: CrcAlgorithm
    aliases: tuple[str, ...] = ()
    schema_version: int = 1


@dataclass(frozen=True)
class CrcJob:
    """
    Summary:
        A per-firmware CRC job: a resolved algorithm + one or more targets
        (requirements §4b). The evolved ``crc_config`` shape.

    Args:
        algorithm (CrcAlgorithm): The resolved algorithm (from ``algorithm_ref``
            or an inline ``algorithm`` object).
        targets (tuple[CrcTarget, ...]): One CRC per target, in file order.
        schema_version (int): Job schema version.

    Dependencies:
        Uses:
            - CrcAlgorithm / CrcTarget
        Used by:
            - parse_job, the (future) CRC operation run path
    """

    algorithm: CrcAlgorithm
    targets: tuple[CrcTarget, ...]
    schema_version: int = 1


# ─────────────────────────────────────────────────────────────────────────────
# Coverage — the multi-range window & its two gap levels
# ─────────────────────────────────────────────────────────────────────────────
def _gather_range(mem_map: dict[int, int], start: int, end: int, target: CrcTarget) -> bytes:
    """Materialize one range under ``target.intra_gap`` (helper, no validation)."""
    if target.intra_gap == "fill":
        return bytes(mem_map.get(a, target.pad_byte) for a in range(start, end))
    return bytes(mem_map[a] for a in range(start, end) if a in mem_map)


def gather_target(mem_map: dict[int, int], target: CrcTarget) -> bytes:
    """
    Summary:
        Materialize a target's byte window over ``mem_map`` under its two
        independent gap policies (requirements §3.2): ``intra_gap`` governs
        holes inside each range; ``join`` governs the space between consecutive
        ranges. Ranges are processed in DECLARED order.

    Args:
        mem_map (dict[int, int]): Address-to-byte map (read only).
        target (CrcTarget): The coverage + policy.

    Returns:
        bytes: The ordered byte stream to digest.
        - ``join="concat"`` butts each range's gathered bytes together (the
          shipped group behavior).
        - ``join="fill"`` inserts ``(next_start - prev_end)`` ``pad_byte`` bytes
          between consecutive ranges, so the digest sees one contiguous window.

    Data Flow:
        - Per range: :func:`_gather_range` under ``intra_gap``; between ranges:
          optional pad run under ``join``; concatenate.

    Dependencies:
        Uses:
            - _gather_range
        Used by:
            - compute_target_crc
            - tests/test_crc_designer_model.py (concat/fill oracles)

    Example:
        >>> t = CrcTarget(((0, 2), (4, 6)), "skip", "fill", 0xFF, 0x10, 4, "little")
        >>> gather_target({0: 1, 1: 2, 4: 5, 5: 6}, t)
        b'\\x01\\x02\\xff\\xff\\x05\\x06'
    """
    segments: list[bytes] = []
    prev_end: Optional[int] = None
    for start, end in target.ranges:
        if target.join == "fill" and prev_end is not None and start > prev_end:
            segments.append(bytes([target.pad_byte]) * (start - prev_end))
        segments.append(_gather_range(mem_map, start, end, target))
        prev_end = end
    return b"".join(segments)


def compute_target_crc(
    mem_map: dict[int, int], algorithm: CrcAlgorithm, target: CrcTarget
) -> int:
    """
    Summary:
        Compute one target's CRC: gather its window (:func:`gather_target`)
        and digest it with ``algorithm`` (:meth:`CrcAlgorithm.compute`).

    Args:
        mem_map (dict[int, int]): Address-to-byte map (read only).
        algorithm (CrcAlgorithm): The CRC math.
        target (CrcTarget): The coverage + policy.

    Returns:
        int: The finalized CRC over the target's window.

    Data Flow:
        - gather_target → algorithm.compute.

    Dependencies:
        Uses:
            - gather_target / CrcAlgorithm.compute
        Used by:
            - the designer preview (R-CRC-DSN-009), the future run path
    """
    return algorithm.compute(gather_target(mem_map, target))


def gap_conflict(mem_map: dict[int, int], target: CrcTarget) -> list[int]:
    """
    Summary:
        Safety detector (observation #2): return the addresses that VIOLATE the
        target's emptiness assumption — real data sitting where the operator
        promised an erased/pad gap. This is the primitive behind
        ``target.on_gap_conflict``; the caller decides how to react (abort /
        warn / ignore).

    Args:
        mem_map (dict[int, int]): Address-to-byte map (read only).
        target (CrcTarget): The coverage + policy.

    Returns:
        list[int]: The offending addresses, ascending. Empty when the coverage
        is consistent with the image.
        - ``join="fill"``: :func:`gather_target` pads ``[prev_end, next_start)``
          with ``pad_byte`` WITHOUT consulting ``mem_map``. If any of those
          addresses is present AND differs from ``pad_byte``, the previewed CRC
          silently diverges from the device's — those addresses are returned.
        - ``join="concat"`` never fabricates bytes, so it yields ``[]``.

    Data Flow:
        - Walk consecutive ranges; for a ``fill`` join, probe the inter-range
          span for present non-pad bytes.

    Dependencies:
        Used by:
            - the run / preview path (enforces ``target.on_gap_conflict``)
            - tests/test_crc_designer_model.py (clean vs dirty gap)

    Example:
        >>> t = CrcTarget(((0, 2), (4, 6)), "skip", "fill", 0xFF, 0x10, 4, "little")
        >>> gap_conflict({0: 1, 1: 2, 3: 0x99, 4: 5, 5: 6}, t)
        [3]
    """
    conflicts: list[int] = []
    prev_end: Optional[int] = None
    for start, end in target.ranges:
        if target.join == "fill" and prev_end is not None and start > prev_end:
            conflicts.extend(
                addr
                for addr in range(prev_end, start)
                if addr in mem_map and mem_map[addr] != target.pad_byte
            )
        prev_end = end
    return conflicts


def store_word(value: int, target: CrcTarget) -> bytes:
    """
    Summary:
        Encode ``value`` into ``target.store_width`` bytes in the target's
        endianness (requirements §3.3). The low ``8 * store_width`` bits are
        emitted; a wider field zero-extends.

    Args:
        value (int): The CRC value.
        target (CrcTarget): Supplies ``store_width`` and ``store_endianness``.

    Returns:
        bytes: Exactly ``store_width`` bytes.

    Data Flow:
        - Mask to the field width, emit in the chosen byte order.

    Dependencies:
        Used by:
            - the designer "would store" preview, the future inject path

    Example:
        >>> t = CrcTarget(((0, 1),), "skip", "concat", 0xFF, 0x10, 4, "big")
        >>> store_word(0x04030201, t).hex(" ")
        '04 03 02 01'
    """
    mask = (1 << (8 * target.store_width)) - 1
    return (value & mask).to_bytes(target.store_width, target.store_endianness)


@dataclass(frozen=True)
class TargetEvaluation:
    """
    Summary:
        The outcome of evaluating one target under its gap-safety policy
        (obs #2 enforcement): the computed CRC (or ``None`` when the run was
        refused), the offending addresses, and plain-text diagnostics.

    Args:
        crc (Optional[int]): The computed CRC, or ``None`` when ``refused``.
        refused (bool): ``True`` only when ``on_gap_conflict="abort"`` AND a
            conflict exists — the write path must not emit a diverging CRC.
        conflicts (tuple[int, ...]): The offending addresses (ascending).
        diagnostics (tuple[str, ...]): Human-readable messages, plain text
            (interpolate only ints/hex — no file-derived text, markup-safe).

    Dependencies:
        Used by:
            - the run / preview path (the CRC operation, the Designer view)
            - tests/test_crc_designer_model.py (branch ATs)
    """

    crc: Optional[int]
    refused: bool
    conflicts: tuple[int, ...]
    diagnostics: tuple[str, ...]


def evaluate_target(
    mem_map: dict[int, int], algorithm: CrcAlgorithm, target: CrcTarget
) -> TargetEvaluation:
    """
    Summary:
        Evaluate a target's CRC UNDER its gap-safety policy (obs #2 / E8):
        detect gap conflicts (:func:`gap_conflict`) and apply
        ``target.on_gap_conflict`` — ``abort`` refuses the run (no CRC),
        ``warn`` proceeds with a diagnostic, ``ignore`` proceeds silently. A
        clean target computes normally under every policy.

    Args:
        mem_map (dict[int, int]): Address-to-byte map (read only).
        algorithm (CrcAlgorithm): The CRC math.
        target (CrcTarget): The coverage + serialization + policy.

    Returns:
        TargetEvaluation: ``refused=True`` / ``crc=None`` only for an ``abort``
        policy WITH a conflict; otherwise the computed CRC, plus the conflict
        addresses and any diagnostics.

    Raises:
        None: A conflict is data, handled by the policy — never an exception.

    Data Flow:
        - :func:`gap_conflict` → branch on ``on_gap_conflict`` → optionally
          :func:`compute_target_crc`.

    Dependencies:
        Uses:
            - gap_conflict, compute_target_crc
        Used by:
            - the run/preview path (R-CRC-DSN-011)
            - tests/test_crc_designer_model.py (abort/warn/ignore branch ATs)

    Example:
        >>> from .crc_kernel import SEED_ALGORITHM
        >>> t = CrcTarget(((0, 2), (4, 6)), "skip", "fill", 0xFF, 0x10, 4, "little", "abort")
        >>> ev = evaluate_target({0: 1, 1: 2, 3: 0x99, 4: 5, 5: 6}, SEED_ALGORITHM, t)
        >>> ev.refused, ev.crc, ev.conflicts
        (True, None, (3,))
    """
    conflicts = tuple(gap_conflict(mem_map, target))
    diagnostics: list[str] = []
    if conflicts:
        shown = ", ".join(f"0x{addr:X}" for addr in conflicts[:8])
        more = "" if len(conflicts) <= 8 else f" (+{len(conflicts) - 8} more)"
        detail = (
            f"gap-safety: {len(conflicts)} present byte(s) at {shown}{more} in a "
            f"filled gap differ from pad_byte 0x{target.pad_byte:02X}"
        )
        if target.on_gap_conflict == "abort":
            return TargetEvaluation(
                crc=None,
                refused=True,
                conflicts=conflicts,
                diagnostics=(f"{detail} — run refused (on_gap_conflict=abort)",),
            )
        if target.on_gap_conflict == "warn":
            diagnostics.append(f"{detail} — proceeding (on_gap_conflict=warn)")
    crc = compute_target_crc(mem_map, algorithm, target)
    return TargetEvaluation(
        crc=crc, refused=False, conflicts=conflicts, diagnostics=tuple(diagnostics)
    )


# ─────────────────────────────────────────────────────────────────────────────
# JSON parse / emit (collect-don't-abort)
# ─────────────────────────────────────────────────────────────────────────────
def _parse_int(value: Any) -> int:
    """Coerce a hex string (``"0x.."``) or JSON int to int (rejects bool)."""
    if isinstance(value, bool):
        raise ValueError("expected an integer, got a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16)
    raise ValueError(f"expected an int or hex string, got {type(value).__name__}")


def _require(cond: bool, message: str) -> None:
    if not cond:
        raise ValueError(message)


def _build_algorithm(data: dict[str, Any], name: str) -> CrcAlgorithm:
    """Build a validated :class:`CrcAlgorithm` from an ``algorithm`` object."""
    width = _parse_int(data["width"])
    _require(8 <= width <= 64, f"width {width} out of range [8, 64]")
    for flag in ("refin", "refout"):
        _require(isinstance(data[flag], bool), f"field '{flag}' must be a boolean")
    check = _parse_int(data["check"]) if data.get("check") is not None else None
    return CrcAlgorithm(
        name=name,
        width=width,
        poly=_parse_int(data["poly"]),
        init=_parse_int(data["init"]),
        refin=data["refin"],
        refout=data["refout"],
        xorout=_parse_int(data["xorout"]),
        check=check,
    )


def _build_target(index: int, raw: Any) -> CrcTarget:
    """Build a validated :class:`CrcTarget` from one ``targets`` entry."""
    _require(isinstance(raw, dict), f"target {index + 1} must be a JSON object")
    raw_ranges = raw["ranges"]
    _require(isinstance(raw_ranges, list) and bool(raw_ranges),
             f"target {index + 1}: 'ranges' must be a non-empty list")
    ranges: list[tuple[int, int]] = []
    for r_index, raw_range in enumerate(raw_ranges):
        _require(isinstance(raw_range, dict),
                 f"target {index + 1} range {r_index + 1} must be a JSON object")
        start = _parse_int(raw_range["start"])
        end = _parse_int(raw_range["end"])
        _require(start >= 0, f"target {index + 1} range {r_index + 1}: 'start' must be >= 0")
        _require(end <= _ADDRESS_SPACE_END,
                 f"target {index + 1} range {r_index + 1}: 'end' exceeds the 32-bit space")
        _require(end > start,
                 f"target {index + 1} range {r_index + 1}: 'end' must be > 'start'")
        ranges.append((start, end))

    intra_gap = raw.get("intra_gap", "skip")
    _require(intra_gap in INTRA_GAP_VALUES,
             f"target {index + 1}: 'intra_gap' must be one of {list(INTRA_GAP_VALUES)}")
    join = raw.get("join", "concat")
    _require(join in JOIN_VALUES,
             f"target {index + 1}: 'join' must be one of {list(JOIN_VALUES)}")
    pad_byte = _parse_int(raw.get("pad_byte", 0xFF))
    _require(0 <= pad_byte <= 0xFF, f"target {index + 1}: 'pad_byte' must be 0..255")
    store_width = _parse_int(raw.get("store_width", 4))
    _require(1 <= store_width <= 8, f"target {index + 1}: 'store_width' must be 1..8")
    endianness = raw.get("store_endianness", "little")
    _require(endianness in ENDIANNESS_VALUES,
             f"target {index + 1}: 'store_endianness' must be one of {list(ENDIANNESS_VALUES)}")
    on_gap_conflict = raw.get("on_gap_conflict", "abort")
    _require(on_gap_conflict in ON_GAP_CONFLICT_VALUES,
             f"target {index + 1}: 'on_gap_conflict' must be one of {list(ON_GAP_CONFLICT_VALUES)}")
    output_address = _parse_int(raw["output_address"])
    _require(output_address >= 0, f"target {index + 1}: 'output_address' must be >= 0")
    _require(output_address + store_width <= _ADDRESS_SPACE_END,
             f"target {index + 1}: output window exceeds the 32-bit space")

    return CrcTarget(
        ranges=tuple(ranges),
        intra_gap=intra_gap,
        join=join,
        pad_byte=pad_byte,
        output_address=output_address,
        store_width=store_width,
        store_endianness=endianness,
        on_gap_conflict=on_gap_conflict,
    )


def parse_template(text: str) -> tuple[Optional[CrcTemplate], list[str]]:
    """
    Summary:
        Parse ``*.crc.json`` algorithm-template text into a typed
        :class:`CrcTemplate`, collect-don't-abort (never raises).

    Args:
        text (str): The raw JSON template text.

    Returns:
        tuple[Optional[CrcTemplate], list[str]]: ``(template, [])`` on success;
        ``(None, [one error])`` on any parse/structure fault.

    Raises:
        None: Every fault is a collected error string.

    Data Flow:
        - ``json.loads`` → object guard → :func:`_build_algorithm` →
          :class:`CrcTemplate`.

    Dependencies:
        Uses:
            - json, _build_algorithm
        Used by:
            - the designer Load surface (R-CRC-DSN-005), tests

    Example:
        >>> tmpl, errs = parse_template(emit_template(
        ...     CrcTemplate(CrcAlgorithm("X", 16, 0x1021, 0xFFFF, False, False, 0, 0x29B1))))
        >>> errs
        []
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, [f"CRC template is not valid JSON: {exc}"]
    if not isinstance(data, dict):
        return None, ["CRC template top level must be a JSON object"]
    try:
        name = data["name"]
        _require(isinstance(name, str) and bool(name.strip()),
                 "field 'name' must be a non-empty string")
        algorithm = _build_algorithm(data["algorithm"], name)
        aliases = tuple(str(a) for a in data.get("aliases", []))
        schema_version = int(data.get("schema_version", 1))
    except (KeyError, TypeError, ValueError) as exc:
        return None, [f"CRC template is structurally invalid: {exc}"]
    return CrcTemplate(algorithm=algorithm, aliases=aliases, schema_version=schema_version), []


def parse_job(
    text: str, resolver: AlgorithmResolver = preset_by_name
) -> tuple[Optional[CrcJob], list[str]]:
    """
    Summary:
        Parse an evolved ``crc_config`` job into a typed :class:`CrcJob`,
        collect-don't-abort. The algorithm comes from an inline ``algorithm``
        object OR an ``algorithm_ref`` name resolved via ``resolver``.

    Args:
        text (str): The raw JSON job text.
        resolver (AlgorithmResolver): Maps an ``algorithm_ref`` name to a
            :class:`CrcAlgorithm`; defaults to the seed presets.

    Returns:
        tuple[Optional[CrcJob], list[str]]: ``(job, [])`` on success;
        ``(None, [one error])`` on any fault (bad JSON, unknown ref, over-ceiling
        range count, invalid target).

    Raises:
        None: Every fault is a collected error string.

    Data Flow:
        - ``json.loads`` → object guard → resolve algorithm → build each target
          (:func:`_build_target`) → range-count ceiling → :class:`CrcJob`.

    Dependencies:
        Uses:
            - json, _build_algorithm, _build_target, the resolver
        Used by:
            - the designer job authoring/preview (R-CRC-DSN-008/009), tests
    """
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, [f"CRC job is not valid JSON: {exc}"]
    if not isinstance(data, dict):
        return None, ["CRC job top level must be a JSON object"]
    try:
        if data.get("algorithm") is not None:
            inline = data["algorithm"]
            algorithm = _build_algorithm(inline, str(data.get("algorithm_name", inline.get("name", "custom"))))
        elif data.get("algorithm_ref") is not None:
            ref = str(data["algorithm_ref"])
            resolved = resolver(ref)
            _require(resolved is not None, f"unknown algorithm_ref {ref!r}")
            assert resolved is not None
            algorithm = resolved
        else:
            raise ValueError("job needs an 'algorithm' object or an 'algorithm_ref'")

        raw_targets = data["targets"]
        _require(isinstance(raw_targets, list) and bool(raw_targets),
                 "'targets' must be a non-empty list")
        targets = tuple(_build_target(i, t) for i, t in enumerate(raw_targets))
        total_ranges = sum(len(t.ranges) for t in targets)
        _require(total_ranges <= RANGE_COUNT_CEILING,
                 f"job declares {total_ranges} ranges, over the {RANGE_COUNT_CEILING} ceiling")
        schema_version = int(data.get("schema_version", 1))
    except (KeyError, TypeError, ValueError) as exc:
        return None, [f"CRC job is structurally invalid: {exc}"]
    return CrcJob(algorithm=algorithm, targets=targets, schema_version=schema_version), []


def _hex(value: int, nibbles: int) -> str:
    """Format ``value`` as a zero-padded ``0x``-prefixed hex string."""
    return f"0x{value:0{nibbles}X}"


def emit_template(template: CrcTemplate) -> str:
    """
    Summary:
        Serialize a :class:`CrcTemplate` to canonical ``*.crc.json`` text that
        round-trips: ``parse_template(emit_template(t))[0] == t``. Ints are
        emitted as width-appropriate ``0x`` hex strings.

    Args:
        template (CrcTemplate): The template to serialize.

    Returns:
        str: Pretty-printed JSON (2-space indent, trailing newline).

    Data Flow:
        - Build an ``OrderedDict``-shaped dict; ``json.dumps``.

    Dependencies:
        Uses:
            - json, _hex
        Used by:
            - the designer JSON preview (R-CRC-DSN-004) + Save (R-CRC-DSN-005)

    Example:
        >>> t = CrcTemplate(CrcAlgorithm("CRC-16/XMODEM", 16, 0x1021, 0, False, False, 0, 0x31C3))
        >>> parse_template(emit_template(t))[0].algorithm.name
        'CRC-16/XMODEM'
    """
    a = template.algorithm
    nib = a.store_bytes() * 2
    payload: dict[str, Any] = {
        "schema_version": template.schema_version,
        "name": a.name,
        "aliases": list(template.aliases),
        "operation": "crc",
        "algorithm": {
            "width": a.width,
            "poly": _hex(a.poly, nib),
            "init": _hex(a.init, nib),
            "refin": a.refin,
            "refout": a.refout,
            "xorout": _hex(a.xorout, nib),
            "check": _hex(a.check, nib) if a.check is not None else None,
        },
    }
    return json.dumps(payload, indent=2) + "\n"


def read_template(
    raw_path: str,
    base_dir: Optional[Path] = None,
    size_probe: Optional[SizeProbe] = None,
) -> tuple[Optional[CrcTemplate], list[str]]:
    """
    Summary:
        Read a ``*.crc.json`` template FILE into a typed :class:`CrcTemplate`,
        reusing the ``read_crc_config`` posture VERBATIM: resolve via
        ``resolve_input_path``, enforce ``READ_SIZE_CAP_BYTES`` BEFORE reading,
        collect-don't-abort (never raises). No new untrusted-loader posture.

    Args:
        raw_path (str): User-supplied path, resolved before the file is opened.
        base_dir (Optional[Path]): Base dir a relative path resolves against;
            ``None`` → cwd.
        size_probe (Optional[SizeProbe]): Injectable size seam; ``None`` →
            ``Path.stat().st_size``.

    Returns:
        tuple[Optional[CrcTemplate], list[str]]: ``(template, [])`` on success;
        ``(None, [one error])`` on any fault (unresolvable, over-cap, unreadable,
        malformed).

    Raises:
        None: Every fault is a collected error string.

    Data Flow:
        - resolve → size-cap → ``read_text`` → :func:`parse_template`.

    Dependencies:
        Uses:
            - workspace.resolve_input_path, changes.io.READ_SIZE_CAP_BYTES,
              parse_template
        Used by:
            - the designer Load surface (R-CRC-DSN-005)
    """
    resolve_base = Path.cwd() if base_dir is None else base_dir
    resolved = resolve_input_path(Path(raw_path), resolve_base)
    if resolved is None:
        return None, [f"CRC template path could not be resolved: {raw_path!r}"]
    probe: SizeProbe = (
        (lambda candidate: candidate.stat().st_size) if size_probe is None else size_probe
    )
    if probe(resolved) > READ_SIZE_CAP_BYTES:
        return None, [
            f"CRC template file is over the {READ_SIZE_CAP_BYTES}-byte read cap — not read"
        ]
    try:
        raw_text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        return None, [f"CRC template file could not be read: {exc}"]
    return parse_template(raw_text)


#: The seed template — the algorithm library's first entry (AT-CRC-DSN-010).
#: Built from the kernel's SEED_ALGORITHM so "first template = current
#: implementation" holds by construction.
def seed_template() -> CrcTemplate:
    """Return the seed CRC-32/ISO-HDLC template (aliases zlib/PKZIP/CRC-32)."""
    from .crc_kernel import SEED_ALGORITHM

    return CrcTemplate(
        algorithm=SEED_ALGORITHM, aliases=("zlib", "PKZIP", "CRC-32"), schema_version=1
    )
