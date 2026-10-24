"""Split / Join / Export — the shipped window (batch-95 change 4 / US-129,
HLR-135 + HLR-136; LLR-135.1..135.7, LLR-136.1..136.6).

The graft ships AS the screen (the operator's ruling, ``veredicto-final.json``):
V1's cockpit chassis — the segment-source chips, the range table (cursor +
``●``/``○`` selection + the coverage column), one control row per setting
(MODE / GAPS+PAD / FORMAT / DEST / NAMING), and the right PREVIEW pane
(output label · union visor band · legend · address ruler · stats + guard chip
· summary · ``EXPORT  e``) — plus V2's two graft deltas: at the MEASURED width
``>= 118`` the pane widens to 58 (band 54 cells), and split mode renders the
per-file gantt under the union map when 1..6 files are selected (hidden at the
floor and outside the cap). The preview visor is the entry point: one visual
variable per cell (the 2-colors-per-cell law, C-10) — OUTPUT CONTENT CLASS
encoded redundantly as glyph density + hue:

    ``▓`` data ``#91abec`` · ``░`` fill ``#6b7280`` · ``▒`` conflict
    ``#f6ff8f`` · ``·`` context ``#46557a`` · (space) absent

The window is a VIEW over :mod:`s19_app.segment_ops` (inc-001, HLR-137) — the
range slicer, the pad-byte fill emitter, the join and the S19/HEX/BIN emit
dispatch are the ENGINE's, called from here, never reimplemented. This module
owns the plan model (the band's class sweep, the guard arithmetic), the visor
renderers (run-economical by construction — one styled span per block) and the
thin export dispatch (``write_split_join_export``). The conflict class renders
exactly the bytes the engine's ``on_gap_conflict="abort"`` law would refuse
(present source bytes inside a padded join gap that differ from the pad byte),
so the band shows the abort before ``e`` names it.

The span guard (LLR-135.5): ``join=fill`` with span >= 1 MiB and fill >= 50%
of span renders the ``⚠ GUARD`` chip and arms a two-step confirm — the first
``e`` writes NOTHING; any state change (selection, mode, gap, pad, format,
destination) disarms; the second ``e`` while armed exports. Zero-coverage
files join the same confirm (LLR-136.6) — one arming naming every reason.

Palette-first, NO rail key (ruling Q6/7a): the ``^K`` palette entry named
"Split / Join / Export" opens the window; ``Esc`` closes it back to the rail
screen it replaced. The per-window usage-help chip and the focused-``?``
binding ride the inc-003c :class:`~s19_app.tui.window_help.WindowSection`
seam with the authored ``split_join_export`` section — zero new plumbing.

Coverage map (test -> TC -> LLR) lives in
``tests/test_segment_split_window.py`` (TC-708 the guard-threshold boundary
limbs · TC-709 the screen wrap audit · TC-710 the negative-control battery).
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.style import Style
from rich.text import Text
from textual import events
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.widgets import Button, Static
from textual.widgets import TextArea

from .a2l import extract_memory_segments
from .capped_text_area import CappedTextArea
from .open_folder_chip import titled_header
from .services.project_gather_service import scoped_home, scoped_home_target
from .window_help import WindowHelpChip, WindowSection

# NOTE (cyclic import): the engine (``s19_app.segment_ops``) imports
# ``s19_app.tui.changes.io``, whose package init (``s19_app.tui``) eagerly
# imports this module's owner ``app.py`` — so a TOP-LEVEL engine import here
# would close a cycle for any consumer that imports the engine first (the
# engine's headless contract, LLR-137, must stay independently importable).
# Every engine use below is therefore a RUNTIME import (sys.modules-cached;
# the values are needed at action time, not at module definition).


def _engine_attr(name: str):
    """Resolve an engine attribute lazily (see the cyclic-import note)."""
    from .. import segment_ops

    return getattr(segment_ops, name)

# ---------------------------------------------------------------------------
# Visor vocabulary — the Calm Dark tokens + the two verified context tints,
# copied 1:1 from styles.tcss ($accent-calm etc.) and the signed prototype's
# palette verification (design_notes.md §2).
# ---------------------------------------------------------------------------

_ACCENTS = {
    "data": "#91abec",
    "fill": "#6b7280",
    "conflict": "#f6ff8f",
    "ctx": "#46557a",
}
_DIM = "#969aad"
_FG = "#e9e9e9"
_RULE = "#1b233a"
_ODD = "#131a2c"
_OK = "#54efae"
_ERR = "#fd8383"
_AMBER = "#d9a35b"

S_DATA = Style(color=_ACCENTS["data"])
S_FILL = Style(color=_ACCENTS["fill"])
S_CONFLICT = Style(color=_ACCENTS["conflict"])
S_CTX = Style(color=_ACCENTS["ctx"])
S_ACCENT = Style(color=_ACCENTS["data"], bold=True)
S_ACCENT_N = Style(color=_ACCENTS["data"])
S_FG = Style(color=_FG)
S_DIM = Style(color=_DIM)
S_OK = Style(color=_OK)
S_ERR = Style(color=_ERR)
S_AMBER = Style(color=_AMBER)
S_WARN_B = Style(color=_ACCENTS["conflict"], bold=True)
S_ROW_CURSOR = Style(color=_FG, bold=True, bgcolor=_RULE)
S_ROW_ZEBRA = Style(color=_FG, bgcolor=_ODD)

#: The five visor classes: glyph per class, (space) for absent — one visual
#: variable per cell, density + hue two correlated encodings (C-10).
GLYPH = {"data": "▓", "fill": "░", "conflict": "▒", "ctx": "·"}
BAND_STYLES = {
    "data": S_DATA,
    "fill": S_FILL,
    "conflict": S_CONFLICT,
    "ctx": S_CTX,
}

#: The span guard thresholds (LLR-135.5) — the prototype's contract numbers.
GUARD_SPAN_MIN = 1 << 20  # 1 MiB
GUARD_FILL_MIN = 0.5  # fill fraction of span

#: The per-file gantt cap (LLR-135.4) — 1..6 files render, else the union map
#: carries the story alone.
GANTT_CAP = 6

#: The measured-width regimes (LLR-135.3): >= 118 the wide pane (58/54 cells),
#: < 100 the narrow floor (30), between them the base 40-column pane.
WIDE_WIDTH_MIN = 118
NARROW_WIDTH_MAX = 100

#: The segment sources (LLR-135.7) — ranges is the default in all cases.
TABS = ("a2l", "ranges", "manual")

#: The naming pattern (LLR-136.5): ``‹stem›_‹segment›.‹ext›`` per split file;
#: join resolves ``‹segment›`` to ``joined``.
DEFAULT_PATTERN = "‹stem›_‹segment›"

#: The change-1 scoped homes (LLR-136.5): project ``splits/`` (created on
#: demand through the containment-checked seam), else the COMMON
#: ``workarea/splits/``.
SPLITS_DIR = "splits"

#: The no-A2L neutral note (LLR-135.7, the contract's verbatim string).
NO_A2L_NOTE = "no A2L loaded — load one (^L) or use ranges/manual"

HEX8 = lambda n: f"0x{n:08X}"


def fmtB(n: float) -> str:
    """Human bytes: B / KiB / MiB — the prototype's formatter."""
    if n < 1024:
        return f"{int(n)} B"
    if n < 1 << 20:
        return f"{n / 1024:.1f} KiB"
    return f"{n / (1 << 20):.2f} MiB"


# ---------------------------------------------------------------------------
# Data model — segment rows and the manual parser (LLR-135.7)
# ---------------------------------------------------------------------------


@dataclass
class SegRow:
    """One selectable segment/range/locality row of the table."""

    name: str
    kind: str  # a2l | ranges | manual
    base: int
    size: int


def parse_manual(text: str) -> Tuple[List[SegRow], List[str]]:
    """Parse the manual-localities tab (LLR-135.7).

    One range per line, hex, INCLUSIVE end (``0x0000EB00-0x0000EBFF`` →
    ``base=0xEB00, size=0x100`` — the typed end IS the last byte, the ±1 trap
    the ruling closed); tolerates spaces, tabs, uppercase ``0X`` and bare hex.
    Unparsable lines are DROPPED and returned alongside (the window names them
    on the status line — they never crash the tab).
    """
    rows: List[SegRow] = []
    dropped: List[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        cleaned = line.replace(" ", "").replace("\t", "")
        low, sep, high = cleaned.partition("-")
        if not sep:
            dropped.append(raw)
            continue
        try:
            lo, hi = int(low, 16), int(high, 16)
        except ValueError:
            dropped.append(raw)
            continue
        if hi < lo:
            dropped.append(raw)
            continue
        rows.append(SegRow(f"locality_{len(rows):02d}", "manual", lo, hi - lo + 1))
    return rows, dropped


def coverage(
    base: int, size: int, src: List[Tuple[int, int]]
) -> List[Tuple[int, int]]:
    """Sub-ranges of ``[base, base+size)`` that actually exist in the source."""
    end = base + size
    out = []
    for s, e in src:
        a, b = max(base, s), min(end, e)
        if b > a:
            out.append((a, b))
    return out


# ---------------------------------------------------------------------------
# The output plan — what the export would write (LLR-136)
# ---------------------------------------------------------------------------


@dataclass
class Block:
    """One run of one visor class (``size`` bytes, coalesced)."""

    cls: str  # data | fill | conflict | ctx | none
    size: int


@dataclass
class OutFile:
    """One planned output file: its band blocks + the byte census."""

    label: str
    blocks: List[Block]
    packed: int  # real data bytes
    pad: int  # fill bytes
    conflicts: int  # conflict bytes (the engine's abort would fire)
    empty: bool


@dataclass
class Plan:
    """The full plan: per-file bands + the union annotated source map."""

    files: List[OutFile]
    map_blocks: List[Block]
    band_lo: int
    band_hi: int
    packed: int
    span: int
    fill: int
    conflicts: int
    empty_files: int
    address_preserving: bool
    nothing_selected: bool
    guard: bool


def _sweep(lo: int, hi: int, marks: List[Tuple[int, int, str]]) -> List[Block]:
    """Classify ``[lo, hi)`` by priority marks; merge adjacent equal classes.

    Priority: data > conflict > fill > ctx — a cell never mixes classes and
    adjacent equal classes coalesce BY CONSTRUCTION (one styled span per
    block, the run-economy law of LLR-135.2).
    """
    cuts = {lo, hi}
    for a, b, _ in marks:
        cuts.add(max(lo, min(a, hi)))
        cuts.add(max(lo, min(b, hi)))
    pts = sorted(cuts)
    prio = {"data": 4, "conflict": 3, "fill": 2, "ctx": 1}
    blocks: List[Block] = []
    for a, b in zip(pts, pts[1:]):
        if a >= b:
            continue
        best = "none"
        for s, e, cls in marks:
            if s < b and e > a and prio[cls] > prio.get(best, 0):
                best = cls
        if blocks and blocks[-1].cls == best:
            blocks[-1].size += b - a
        else:
            blocks.append(Block(best, b - a))
    return blocks


def _conflict_marks(
    mem_map: Dict[int, int],
    src: List[Tuple[int, int]],
    picked_spans: List[Tuple[int, int]],
    pad_byte: int,
) -> List[Tuple[int, int, str]]:
    """The ``▒`` marks: present source bytes inside a JOIN-fill padded gap
    that DIFFER from the pad byte — exactly the predicate of the shipped
    ``gap_conflict`` detector (the engine's abort law, ruling 8f), swept over
    the source∩gap intersections only (bounded by the SOURCE size, never the
    gap size — the guard case's 402 MiB gap must not be walked per byte).
    Equivalence with ``gap_conflict`` is pinned in tests/test_segment_ops.py's
    sibling (tests/test_segment_split_window.py, TC-710 battery).
    """
    spans = sorted(picked_spans)
    merged: List[Tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    marks: List[Tuple[int, int, str]] = []
    prev_end: Optional[int] = None
    for start, end in merged:
        if prev_end is not None and start > prev_end:
            g_lo, g_hi = prev_end, start
            for s, e in src:
                lo, hi = max(g_lo, s), min(g_hi, e)
                for addr in range(lo, hi):
                    if addr in mem_map and mem_map[addr] != pad_byte:
                        if marks and marks[-1][1] == addr:
                            marks[-1] = (marks[-1][0], addr + 1, "conflict")
                        else:
                            marks.append((addr, addr + 1, "conflict"))
        prev_end = end
    return marks


def build_plan(
    rows: List[SegRow],
    sel: set,
    src: List[Tuple[int, int]],
    mem_map: Dict[int, int],
    *,
    mode: str,
    gap: str,
    stem: str,
    ext: str,
    pad_byte: Optional[int] = None,
) -> Plan:
    """Plan the export (LLR-136) — bytes only, nothing written.

    Split plans one file per selected range (``intra_gap skip|fill`` — the fill
    pads only INSIDE the file's own span, the engine's ``fill_range`` law, so
    a split fill can never clobber and never conflicts). Join ``concat`` packs
    ascending from the lowest base (pure ``▓``, no addresses addressable);
    join ``fill`` keeps the original offsets and the union band renders the
    engine's conflict bytes as ``▒``. The guard fires only on the contracted
    thresholds (LLR-135.5).
    """
    if pad_byte is None:
        pad_byte = _engine_attr("DEFAULT_PAD_BYTE")
    picked = [rows[i] for i in sorted(sel) if 0 <= i < len(rows)]
    src_lo = min((s for s, _ in src), default=0)
    src_hi = max((e for _, e in src), default=0)

    if not picked:
        marks = [(s, e, "ctx") for s, e in src]
        blocks = _sweep(src_lo, src_hi, marks) if src_hi > src_lo else []
        return Plan([], blocks, src_lo, src_hi, 0, 0, 0, 0, 0, True, True, False)

    joined = mode == "join"
    if joined and gap == "concat":
        # Packed from the FIRST/lowest range's base: no addresses, no context
        # possible — the band covers [0, packed) as pure data (LLR-136.2).
        band: List[Block] = []
        packed = 0
        for r in sorted(picked, key=lambda r: r.base):
            n = sum(b - a for a, b in coverage(r.base, r.size, src))
            if n == 0:
                continue
            packed += n
            if band and band[-1].cls == "data":
                band[-1].size += n
            else:
                band.append(Block("data", n))
        label = f"{stem}_joined.{ext}"
        files = [OutFile(label, band, packed, 0, 0, packed == 0)]
        return Plan(
            files, [], 0, max(packed, 1), packed, packed, 0, 0, 0,
            False, False, False,
        )

    # Address-preserving: split (intra_gap skip|fill) or join=fill; the union
    # band covers the union of source + selected span — the source image
    # annotated by output class (LLR-136.1 / LLR-136.3).
    span_lo = min(r.base for r in picked)
    span_hi = max(r.base + r.size for r in picked)
    lo, hi = min(span_lo, src_lo), max(span_hi, src_hi)

    marks: List[Tuple[int, int, str]] = [(s, e, "ctx") for s, e in src]
    if joined:
        marks.append((span_lo, span_hi, "fill"))
        marks.extend(
            _conflict_marks(
                mem_map,
                src,
                [(r.base, r.base + r.size) for r in picked],
                pad_byte,
            )
        )
    else:
        for r in picked:  # split: each file pads only INSIDE its own span
            marks.append((r.base, r.base + r.size, "fill"))
    for r in picked:
        for a, b in coverage(r.base, r.size, src):
            marks.append((a, b, "data"))
    blocks = _sweep(lo, hi, marks) if hi > lo else []

    files: List[OutFile] = []
    total_packed = total_pad = total_conf = 0
    for r in picked:
        cov = coverage(r.base, r.size, src)
        data = sum(b - a for a, b in cov)
        pad = 0
        # Per-file band: the row's own span annotated (what THAT file
        # contains). The split fill keeps source bytes (engine law), so the
        # per-file sweep can only produce data/fill — never conflict.
        fmarks: List[Tuple[int, int, str]] = []
        if gap == "fill":
            fmarks.append((r.base, r.base + r.size, "fill"))
        for a, b in cov:
            fmarks.append((a, b, "data"))
        fblocks = (
            _sweep(r.base, r.base + r.size, fmarks)
            if r.base + r.size > r.base
            else []
        )
        if gap == "fill":
            # The file's pad bytes == its span minus the covered bytes (the
            # fill pads every uncovered address INSIDE the span, never across
            # files — LLR-136.1's byte assertion).
            pad = r.size - data
        label = f"{stem}_{r.name}.{ext}" if not joined else f"{stem}_joined.{ext}"
        files.append(OutFile(label, fblocks, data, pad, 0, data == 0))
        total_packed += data
        total_pad += pad
    if joined:
        # The joined file's band IS the union sweep; its conflict census is
        # the ▒ runs the engine's abort law would refuse (LLR-136.4).
        total_conf = sum(b.size for b in blocks if b.cls == "conflict")
        files = [
            OutFile(
                f"{stem}_joined.{ext}",
                blocks,
                total_packed,
                total_pad,
                total_conf,
                total_packed == 0,
            )
        ]

    span = span_hi - span_lo
    fill_bytes = sum(b.size for b in blocks if b.cls == "fill")
    guard = bool(
        joined
        and gap == "fill"
        and span >= GUARD_SPAN_MIN
        and fill_bytes / max(span, 1) >= GUARD_FILL_MIN
    )
    return Plan(
        files,
        blocks,
        lo,
        hi,
        total_packed,
        span,
        fill_bytes,
        total_conf,
        sum(1 for f in files if f.empty),
        True,
        False,
        guard,
    )


def resolve_sample(stem: str, seg: str, ext: str, pattern: str) -> str:
    """Resolve the naming pattern (LLR-136.5): ``‹stem›_‹segment›.‹ext›``."""
    return pattern.replace("‹stem›", stem).replace("‹segment›", seg) + "." + ext


# ---------------------------------------------------------------------------
# The export dispatch — thin composition over the engine (HLR-137)
# ---------------------------------------------------------------------------


def write_split_join_export(
    mem_map: Dict[int, int],
    rows: List[SegRow],
    *,
    mode: str,
    gap: str,
    pad_byte: int,
    fmt: str,
    stem: str,
    dest_dir: Path,
    zero_coverage_empty: bool = False,
) -> List[Path]:
    """Write the planned export (LLR-136) — the engine does the bytes.

    Split: one file per row via :func:`segment_ops.fill_range` (``intra_gap``
    policy inside the file's own span). Join: one ``‹stem›_joined.‹ext>`` via
    :func:`segment_ops.join_concat` / :func:`segment_ops.join_fill` — the
    latter raises :class:`GapConflictError` BEFORE a byte is emitted when a
    pad would clobber source (the fixed ``on_gap_conflict="abort"`` law), so
    a refused export writes nothing. S19/HEX ride the shipped mem_map
    emitters through :func:`segment_ops.emit_image`; BIN writes exactly
    ``size`` flat bytes plus the one-line ``.addr`` sidecar (LLR-137.2).

    ``zero_coverage_empty`` (the UI's LLR-136.6 limb, default off): a split
    row whose span holds no source bytes exports as the EMPTY image at its
    base (0-byte BIN + sidecar / header-only S19/HEX) instead of the
    intra_gap fill's fabricated all-pad run. Off, this function is pure
    engine composition (LLR-137.3's fill materializes every pad).
    """
    EXPORT_FORMATS = _engine_attr("EXPORT_FORMATS")
    emit_image = _engine_attr("emit_image")
    fill_range = _engine_attr("fill_range")
    join_concat = _engine_attr("join_concat")
    join_fill = _engine_attr("join_fill")
    write_bin_with_sidecar = _engine_attr("write_bin_with_sidecar")
    if fmt not in EXPORT_FORMATS:
        raise ValueError(f"fmt must be one of {list(EXPORT_FORMATS)}, got {fmt!r}")
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    def _write(name: str, planned_map, planned_ranges) -> None:
        if fmt == "bin":
            written.append(
                write_bin_with_sidecar(
                    planned_map, planned_ranges, dest_dir / f"{name}.bin"
                )[0]
            )
            return
        payload = emit_image(planned_map, planned_ranges, fmt)
        dest = dest_dir / f"{name}.{fmt}"
        dest.write_text(payload, encoding="ascii")
        written.append(dest)

    if mode == "split":
        for r in rows:
            if zero_coverage_empty and not any(
                r.base <= a < r.base + r.size for a in mem_map
            ):
                # The UI's LLR-136.6 limb: a confirmed zero-coverage file
                # exports AT its base as the empty image — BIN 0 bytes + the
                # .addr sidecar, S19/HEX header-only (the emitters' shipped
                # semantics) — never a fabricated all-pad run. The default
                # False keeps this module pure engine composition (the
                # intra_gap fill materializes pads, LLR-137.3).
                _write(f"{stem}_{r.name}", {}, [(r.base, r.base)])
                continue
            planned_map, planned_ranges = fill_range(
                mem_map, r.base, r.base + r.size, pad_byte, intra_gap=gap
            )
            _write(f"{stem}_{r.name}", planned_map, planned_ranges)
        return written

    ranges = [(r.base, r.base + r.size) for r in sorted(rows, key=lambda r: r.base)]
    if gap == "concat":
        planned_map, planned_ranges = join_concat(mem_map, ranges)
    else:
        planned_map, planned_ranges = join_fill(mem_map, ranges, pad_byte)
    _write(f"{stem}_joined", planned_map, planned_ranges)
    return written


# ---------------------------------------------------------------------------
# Visor renderers — width-driven, run-economical by construction (LLR-135.2)
# ---------------------------------------------------------------------------


def apportion(sizes: List[int], width: int) -> List[int]:
    """floor-one-then-largest-remainder, bounded by the MEASURED container.

    Rewritten from the shipped ``_allocate_band_widths``
    (``screens_directionb.py:610``, R-TUI-103/LLR-111.7): one column per
    block, the surplus apportioned by byte share, leftovers to the largest
    remainders. The bound lives HERE, in the producer, never in a predicate
    over emitted text — every block keeps >= 1 column (the 1-byte block
    inside a 57 KiB span stays visible).
    """
    n = len(sizes)
    if n == 0 or width <= 0:
        return []
    if width < n:
        return [1] * n
    surplus = width - n
    total = sum(sizes)
    if surplus <= 0 or total <= 0:
        return [1] * n
    quotas = [surplus * s / total for s in sizes]
    extra = [int(q) for q in quotas]
    leftover = surplus - sum(extra)
    ranked = sorted(range(n), key=lambda i: (-(quotas[i] - extra[i]), -sizes[i], i))
    for i in ranked[:leftover]:
        extra[i] += 1
    return [1 + e for e in extra]


def _append_blocks(text: Text, blocks: List[Block], width: int) -> None:
    for blk, w in zip(blocks, apportion([b.size for b in blocks], width)):
        text.append(GLYPH.get(blk.cls, " ") * w, style=BAND_STYLES.get(blk.cls))


def band_text(blocks: List[Block], width: int) -> Text:
    """One visor band row — one styled span per block (coalesced by
    construction, <= 14 runs at any width; empty selection renders the
    tick-a-row note, never a blank pane)."""
    t = Text()
    if width <= 0:
        return t
    if not blocks:
        t.append(
            "· nothing selected — tick a row with ␣ or press a for all",
            style=S_DIM,
        )
        return t
    _append_blocks(t, blocks, width)
    return t


def ruler_text(lo: int, hi: int, width: int) -> Text:
    """The address ruler: the ``0xXXXXXXXX`` ends (+ midpoint when it fits)."""
    t = Text()
    if width < 20 or hi <= lo:
        return t
    left, right = HEX8(lo), HEX8(hi - 1)
    mid = HEX8((lo + hi) // 2)
    t.append(left, style=S_DIM)
    rpos = width - len(right)
    mpos = (width - len(mid)) // 2
    if mpos > len(left) + 1:
        t.append(" " * (mpos - len(left)), style=S_DIM)
        t.append(mid, style=S_DIM)
    if rpos > max(len(left), mpos + len(mid)) + 1:
        cur = len(t)
        t.append(" " * (rpos - cur), style=S_DIM)
        t.append(right, style=S_DIM)
    return t


def gantt_text(plan: Plan, width: int) -> Text:
    """The split-mode per-file gantt (LLR-135.4): one row per output file —
    label · the file's own byte band · size; an empty file renders its
    ``∅ empty — 0 B of source in span`` row."""
    label_w = 24
    text = Text()
    band_w = max(width - label_w - 12, 8)
    for i, f in enumerate(plan.files):
        if i:
            text.append("\n")
        name = f.label if len(f.label) <= label_w - 2 else f.label[: label_w - 3] + "…"
        text.append(f"{name:<{label_w}} ", style=S_FG)
        if f.empty:
            text.append("∅ empty — 0 B of source in span", style=S_DIM)
            continue
        if not f.blocks:
            text.append("—", style=S_DIM)
            continue
        _append_blocks(text, f.blocks, band_w)
        text.append(" ")
        text.append(fmtB(f.packed + f.pad), style=S_DIM)
    if plan.nothing_selected:
        text.append(
            "· nothing selected — tick a row with ␣ or press a for all",
            style=S_DIM,
        )
    return text


# ---------------------------------------------------------------------------
# Widgets
# ---------------------------------------------------------------------------


class _BandBar(Static):
    """One visor band; re-apportions columns against its measured width."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self._blocks: List[Block] = []

    def set_blocks(self, blocks: List[Block]) -> None:
        self._blocks = blocks
        self._paint()

    def on_resize(self) -> None:
        self._paint()

    def _paint(self) -> None:
        # A zero-width paint is a degenerate pre-layout pass — keep the last
        # real paint (the settled re-sync repaints with true widths).
        if self.content_size.width <= 0:
            return
        self.update(band_text(self._blocks, self.content_size.width))


class _RulerBar(Static):
    def __init__(self, **kw):
        super().__init__(**kw)
        self._span: Tuple[int, int] = (0, 0)

    def set_span(self, lo: int, hi: int) -> None:
        self._span = (lo, hi)
        self._paint()

    def on_resize(self) -> None:
        self._paint()

    def _paint(self) -> None:
        # A zero-width paint is a degenerate pre-layout pass — keep the last
        # real paint (the settled re-sync repaints with true widths).
        if self.content_size.width <= 0:
            return
        lo, hi = self._span
        self.update(ruler_text(lo, hi, self.content_size.width))


class _GanttBar(Static):
    """The per-file gantt body; repaints on resize so the bands track the
    real width."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self._plan: Optional[Plan] = None

    def set_plan(self, plan: Plan) -> None:
        self._plan = plan
        self._paint()

    def on_resize(self) -> None:
        self._paint()

    def _paint(self) -> None:
        if self._plan is None:
            return
        width = self.content_size.width
        if width <= 0:
            # Pre-layout or just-unhidden pass (the wrap's display flip only
            # lands on the next reflow, and a direct _sync can be read before
            # that): paint against the screen width so the content is never
            # blank — the settled resize/sync repaints at the measured width.
            width = max(self.screen.size.width - 8, 24)
        self.update(gantt_text(self._plan, width))


class _SegTable(ScrollableContainer):
    """Focusable range table; the cursor row carries the selection state.

    The cursor keys REPLACE the container's scroll bindings on purpose: the
    table scrolls itself to the cursor on every paint (the prototype's
    idiom), so ``up``/``down`` move the cursor and the viewport follows —
    manual scroll keys would strand the cursor off-screen.
    """

    can_focus = True

    BINDINGS = [
        Binding("up", "cursor_move(-1)", show=False),
        Binding("down", "cursor_move(1)", show=False),
        Binding("k", "cursor_move(-1)", show=False),
        Binding("j", "cursor_move(1)", show=False),
    ]

    def action_cursor_move(self, d: int) -> None:
        for ancestor in self.ancestors:
            if isinstance(ancestor, SplitJoinWindow):
                ancestor.action_move(d)
                return

    def __init__(self, **kw):
        super().__init__(**kw)
        self._body = Static()
        self._rows: List[SegRow] = []
        self._sel: set = set()
        self._cursor = 0
        self._src: List[Tuple[int, int]] = []
        self._note: Optional[str] = None
        self._focused = False

    def compose(self) -> ComposeResult:
        yield self._body

    def set_data(
        self,
        rows: List[SegRow],
        sel: set,
        cursor: int,
        src: List[Tuple[int, int]],
        note: Optional[str] = None,
    ) -> None:
        self._rows, self._sel, self._cursor, self._src = rows, sel, cursor, src
        self._note = note
        self._paint()

    def on_resize(self) -> None:
        self._paint()

    def on_focus(self) -> None:
        self._focused = True
        self._paint()

    def on_blur(self) -> None:
        self._focused = False
        self._paint()

    def _line(
        self, i: int, r: SegRow, width: int, compact: bool, starved: bool
    ) -> Text:
        t = Text()
        cur = i == self._cursor
        sel = i in self._sel
        cov = coverage(r.base, r.size, self._src)
        have = sum(b - a for a, b in cov)
        base_style = S_ROW_CURSOR if cur else (S_ROW_ZEBRA if i % 2 else S_FG)
        glyph = "●" if sel else "○"
        if starved:
            # The shipped app carries a ~22-column activity rail the
            # standalone prototype lacked, so the wide regime leaves the
            # table ~37 columns (the floor ~26). The starved tier drops
            # the size column and reads coverage as ONE glyph — the cursor
            # row still carries its bold+rule background, so no mark column.
            t.append(glyph + " ", style=S_ACCENT_N if sel else base_style)
            name_w = 10
            name = r.name if len(r.name) <= name_w else r.name[: name_w - 1] + "…"
            t.append(f"{name:<{name_w}} ", style=base_style)
            t.append(f"{HEX8(r.base)} ", style=S_DIM if not cur else base_style)
            if have == 0:
                covs, covst = "✗", S_ERR
            elif have >= r.size:
                covs, covst = "✓", S_OK
            else:
                covs, covst = "◐", S_AMBER
            t.append(covs, style=covst if not cur else S_ROW_CURSOR)
        else:
            mark = "› " if (cur and self._focused) else "  "
            t.append(
                mark, style=S_ACCENT if cur and self._focused else base_style
            )
            t.append(glyph + " ", style=S_ACCENT_N if sel else base_style)
            name_w = 14 if compact else 20
            name = r.name if len(r.name) <= name_w else r.name[: name_w - 1] + "…"
            t.append(f"{name:<{name_w}} ", style=base_style)
            t.append(f"{HEX8(r.base)} ", style=S_DIM if not cur else base_style)
            sz_w = 8 if compact else 9
            t.append(f"{fmtB(r.size):>{sz_w}} ", style=base_style)
            if have == 0:
                covs = "✗ 0 B" if compact else f"✗ 0 B of {fmtB(r.size)}"
                covst = S_ERR
            elif have >= r.size:
                covs = "✓ full" if compact else f"✓ {fmtB(have)}"
                covst = S_OK
            else:
                covs = f"◐ {fmtB(have)}" if compact else f"◐ {fmtB(have)} of {fmtB(r.size)}"
                covst = S_AMBER
            t.append(covs, style=covst if not cur else S_ROW_CURSOR)
        if len(t) > width:
            t = Text(t.plain[: max(width - 1, 1)] + "…")
            t.stylize(base_style)
        return t

    def _paint(self) -> None:
        w = self.content_size.width
        # Three measured tiers: full (>= 58) · compact (>= 44: short name,
        # short coverage) · starved (< 44: the shipped app's rail leaves
        # ~35 columns in the wide regime, ~25 at the floor — the size
        # column and the mark column are dropped, coverage reads as one
        # glyph; every line is analytically sized to fit its measure).
        compact = w < 58
        starved = w < 44
        text = Text()
        for i, r in enumerate(self._rows):
            if i:
                text.append("\n")
            text.append_text(self._line(i, r, w, compact, starved))
        if not self._rows:
            # The neutral note is a CONTRACT STRING (LLR-135.7) — it renders
            # verbatim, never clamped (the `_fit` law binds the authored
            # chrome lines, not the contract's verbatim text).
            text = Text(self._note or "no rows — load an image (^L) or switch to manual", style=S_DIM)
        self._body.update(text)
        if 0 <= self._cursor < len(self._rows):
            self.scroll_to(y=max(0, self._cursor - 3), animate=False)


# ---------------------------------------------------------------------------
# Chip row builders — every line analytically sized; `_fit` is the clamp
# ---------------------------------------------------------------------------


def _opt(t: Text, label: str, active: bool) -> None:
    t.append(f"‹{label}›" if active else label, style=S_ACCENT if active else S_FG)


def _fit(t: Text, width: int) -> Text:
    if width > 0 and len(t) > width:
        return Text(t.plain[: max(width - 1, 1)] + "…", style=S_DIM)
    return t


def _fit_lines(t: Text, width: int) -> Text:
    """The house clamp applied to EVERY authored line of a (possibly
    multi-line) Text — the wrap audit's law is per line, never per Text."""
    if width <= 0 or len(t) <= width:
        return t
    out = Text()
    for i, line in enumerate(t.split("\n")):
        if i:
            out.append("\n")
        out.append_text(_fit(line, width))
    return out


def _chips_tabs(compact: bool, tab: str, counts: Dict[str, int]) -> Text:
    t = Text()
    t.append("SEG  " if compact else "SEGMENTS  ", style=S_DIM)
    for i, name in enumerate(TABS):
        if i:
            t.append(" ", style=S_FG)
        _opt(t, f"{name}({counts[name]})", name == tab)
    t.append("   [a]ll [n]one", style=S_DIM)
    return t


def _chips_mode(compact: bool, mode: str) -> Text:
    t = Text()
    t.append("MODE  ", style=S_DIM)
    _opt(t, "split", mode == "split")
    t.append(" ", style=S_FG)
    _opt(t, "join", mode == "join")
    return t


def _chips_gap(compact: bool, mode: str, gap: str, pad: str) -> Text:
    t = Text()
    t.append(
        "JOIN GAPS  " if (mode == "join" and not compact) else
        ("GAPS  " if compact else "INTRA GAP  "),
        style=S_DIM,
    )
    vals = ("concat", "fill") if mode == "join" else ("skip", "fill")
    for i, v in enumerate(vals):
        if i:
            t.append(" ", style=S_FG)
        _opt(t, v, gap == v)
    if gap == "fill":
        t.append("   PAD  ", style=S_DIM)
        t.append(f"‹{pad}›", style=S_ACCENT)
    return t


def _chips_fmt(compact: bool, fmt: str) -> Text:
    t = Text()
    t.append("FORMAT  ", style=S_DIM)
    for i, f in enumerate(_engine_attr("EXPORT_FORMATS")):
        if i:
            t.append(" ", style=S_FG)
        _opt(t, f.upper(), fmt == f)
    return t


def _chips_dest(compact: bool, dst: str) -> Text:
    t = Text()
    t.append("DEST  ", style=S_DIM)
    _opt(t, "project", dst == "project")
    t.append(" ", style=S_FG)
    _opt(t, "common", dst == "common")
    return t


def _chips_naming(pattern: str, sample: str) -> Text:
    t = Text()
    t.append("NAMING  ", style=S_DIM)
    t.append(pattern, style=S_FG)
    t.append(" → ", style=S_DIM)
    t.append(sample, style=S_ACCENT)
    return t


def _legend(compact: bool) -> Text:
    t = Text()
    if compact:
        t.append("▓", style=S_DATA)
        t.append("data ", style=S_DIM)
        t.append("░", style=S_FILL)
        t.append("pad ", style=S_DIM)
        t.append("▒", style=S_CONFLICT)
        t.append("clash ", style=S_DIM)
        t.append("·", style=S_CTX)
        t.append("src", style=S_DIM)
        return t
    t.append("▓", style=S_DATA)
    t.append(" data  ", style=S_DIM)
    t.append("░", style=S_FILL)
    t.append(" pad  ", style=S_DIM)
    t.append("▒", style=S_CONFLICT)
    t.append(" conflict  ", style=S_DIM)
    t.append("·", style=S_CTX)
    t.append(" source ctx", style=S_DIM)
    return t


# ---------------------------------------------------------------------------
# The window — the graft chassis (LLR-135.1)
# ---------------------------------------------------------------------------


class SplitJoinWindow(WindowSection):
    """The Split / Join / Export screen (the graft), riding the rail body.

    Palette-first, NO rail key (ruling Q6/7a): ``S19TuiApp`` shows/hides this
    container beside the ten rail screens; ``Esc`` closes it back to the rail
    screen it replaced. Window-scoped keys (cursor/selection/tabs/mode/gap/
    format/pad/export) shadow the app bindings ONLY while a widget of this
    window holds focus — the Textual ancestor-chain idiom the inc-003c ``?``
    binding already rides; printable keys typed into the manual-localities
    TextArea stay text (the widget stops them before any binding sees them).
    """

    BINDINGS = WindowSection.BINDINGS + [
        Binding("up", "move(-1)", "Up", show=False),
        Binding("down", "move(1)", "Down", show=False),
        Binding("k", "move(-1)", "Up", show=False),
        Binding("j", "move(1)", "Down", show=False),
        Binding("space", "toggle_row", "Tick", show=False),
        Binding("a", "select_all", "All", show=False),
        Binding("n", "select_none", "None", show=False),
        Binding("t", "cycle_tab", "Source", show=False),
        Binding("m", "toggle_mode", "Mode", show=False),
        Binding("g", "cycle_gap", "Gap", show=False),
        Binding("f", "cycle_format", "Format", show=False),
        Binding("p", "cycle_pad", "Pad", show=False),
        Binding("d", "cycle_dest", "Dest", show=False),
        Binding("e", "export", "Export", show=False),
        Binding("escape", "close_window", "Close", show=False),
    ]

    def __init__(self) -> None:
        super().__init__(
            "split_join_export",
            id="screen_split_join",
            classes="db-screen hidden",
        )
        self._tab = "ranges"  # LLR-135.7: ranges first in all cases
        self._sel: Dict[str, set] = {name: set() for name in TABS}
        self._cursor: Dict[str, int] = {name: 0 for name in TABS}
        self._mode = "split"
        self._gap = "skip"
        self._pad_int = _engine_attr("DEFAULT_PAD_BYTE")
        self._fmt = "s19"
        self._dest = "project"
        self._pattern = DEFAULT_PATTERN
        self._armed = False
        self._loaded_cache = None
        self._a2l_rows_cache_src: Optional[dict] = None
        self._a2l_rows_cache: List[SegRow] = []
        self._manual_dropped: Tuple[str, ...] = ()

    # ------------------------------------------------------------------ #
    # Compose — the graft chassis
    # ------------------------------------------------------------------ #

    def compose(self) -> ComposeResult:
        # The title row: title + the `?` usage-help chip ONLY — HLR-139
        # contracts exactly four windows with 📂 chips and this is not one
        # of them (LLR-135.6/HLR-140's no-orphan-seat rule rides the
        # authored split_join_export section shipped at inc-003c).
        yield titled_header(
            "Split / Join / Export",
            help_button=WindowHelpChip("split_join_export"),
        )
        with Horizontal(id="sje_body"):
            with Vertical(id="sje_left"):
                yield Static(id="sje_tabs", classes="sje-chips")
                yield _SegTable(id="sje_table")
                yield CappedTextArea("", id="sje_manual")
                yield Static(id="sje_mode", classes="sje-chips")
                yield Static(id="sje_gap", classes="sje-chips")
                yield Static(id="sje_fmt", classes="sje-chips")
                yield Static(id="sje_dest", classes="sje-chips")
                yield Static(id="sje_naming", classes="sje-chips")
            with Vertical(id="sje_right", classes="db-pane"):
                yield Static(id="sje_outlabel", classes="sje-outlabel")
                yield _BandBar(id="sje_band", classes="sje-band")
                with Vertical(id="sje_files_wrap"):
                    yield _GanttBar(id="sje_files")
                yield Static(id="sje_legend", classes="sje-legend")
                yield _RulerBar(id="sje_ruler", classes="sje-ruler")
                yield Static(id="sje_stats")
                yield Static(id="sje_summary")
                yield Button("EXPORT  e", id="sje_export")

    def on_mount(self) -> None:
        pane = self.query_one("#sje_right", Vertical)
        pane.border_title = " PREVIEW "
        self.query_one("#sje_manual", TextArea).add_class("hidden")
        self._sync()

    # ------------------------------------------------------------------ #
    # Live sources (read from the app on every sync — a VIEW, never a copy)
    # ------------------------------------------------------------------ #

    def _app(self):
        return self.app

    def _loaded(self):
        return getattr(self._app(), "current_file", None)

    def _mem_map(self) -> Dict[int, int]:
        loaded = self._loaded()
        return loaded.mem_map if loaded else {}

    def _src_ranges(self) -> List[Tuple[int, int]]:
        loaded = self._loaded()
        return list(loaded.ranges) if loaded else []

    def _range_rows(self) -> List[SegRow]:
        return [
            SegRow(f"range_{i:02d}", "ranges", s, e - s)
            for i, (s, e) in enumerate(self._src_ranges())
        ]

    def _a2l_rows(self) -> List[SegRow]:
        # The A2L can arrive two ways: the standalone A2L load stamps the
        # app's ``current_a2l_data``, while the image-load pipeline attaches
        # it to the LoadedFile itself (``loaded.a2l_data``) — the window
        # must read both or the A2L tab stays empty on the merge path.
        loaded = self._loaded()
        data = getattr(self._app(), "current_a2l_data", None) or (
            getattr(loaded, "a2l_data", None) if loaded is not None else None
        )
        if data is None:
            self._a2l_rows_cache_src = None
            self._a2l_rows_cache = []
            return []
        if data is self._a2l_rows_cache_src:
            return self._a2l_rows_cache
        rows: List[SegRow] = []
        for i, seg in enumerate(
            extract_memory_segments(data.get("sections") or [])
        ):
            base, size = seg.get("base"), seg.get("size")
            if base is None or size is None:
                continue
            name = str(seg.get("block_name") or f"segment_{i:02d}")
            rows.append(SegRow(name, "a2l", int(base), int(size)))
        self._a2l_rows_cache_src = data
        self._a2l_rows_cache = rows
        return rows

    def _manual_rows(self) -> Tuple[List[SegRow], List[str]]:
        try:
            text = self.query_one("#sje_manual", TextArea).text
        except Exception:
            text = ""
        return parse_manual(text)

    def _rows(self) -> List[SegRow]:
        if self._tab == "a2l":
            return self._a2l_rows()
        if self._tab == "manual":
            return self._manual_rows()[0]
        return self._range_rows()

    def _counts(self) -> Dict[str, int]:
        return {
            "a2l": len(self._a2l_rows()),
            "ranges": len(self._range_rows()),
            "manual": len(self._manual_rows()[0]),
        }

    def _stem(self) -> str:
        loaded = self._loaded()
        if loaded is not None and getattr(loaded.path, "stem", ""):
            return Path(loaded.path).stem
        return "output"

    def _pad_str(self) -> str:
        return f"0x{self._pad_int:02X}"

    def _dest_dir(self) -> Path:
        app = self._app()
        common = Path(app.workarea) / SPLITS_DIR
        if self._dest == "project":
            # The change-1 scoped homes (LLR-136.5): project splits/ via the
            # containment-checked seam; no project falls back to COMMON.
            return scoped_home(
                app.active_project_dir(), SPLITS_DIR, common
            )
        return common

    def _dest_dir_display(self) -> Path:
        """The destination LABEL only — resolved, never created.

        The paint path (``_summary_text``) must not mkdir: this window is
        mounted hidden from app startup and re-synced on every project
        load, so a creating resolution here would make ``splits/`` appear
        in the project dir with NO export ever run (the LLR-035.6 law: a
        switch/load alone touches no project file). The HLR-139 chip idiom
        applies verbatim — display rides ``scoped_home_target``, creation
        stays at the byte-writing seam (``_dest_dir`` in the export flow,
        LLR-136.5).
        """
        app = self._app()
        common = Path(app.workarea) / SPLITS_DIR
        if self._dest == "project":
            return scoped_home_target(
                app.active_project_dir(), SPLITS_DIR, common
            )
        return common

    def _valid_picked(self, rows: List[SegRow]) -> List[int]:
        """Selection indices that still exist (a stale seat never indexes)."""
        return [i for i in sorted(self._sel[self._tab]) if 0 <= i < len(rows)]

    def _sample(self, rows: List[SegRow]) -> str:
        picked = self._valid_picked(rows)
        seg = (
            "joined"
            if self._mode == "join"
            else (rows[picked[0]].name if picked else "segment")
        )
        return resolve_sample(self._stem(), seg, self._fmt, self._pattern)

    def _plan(self, rows: List[SegRow]) -> Plan:
        return build_plan(
            rows,
            self._sel[self._tab],
            self._src_ranges(),
            self._mem_map(),
            mode=self._mode,
            gap=self._gap,
            stem=self._stem(),
            ext=self._fmt,
            pad_byte=self._pad_int,
        )

    # ------------------------------------------------------------------ #
    # State -> screen
    # ------------------------------------------------------------------ #

    def refresh_window(self) -> None:
        """The app's one seam into this window: open + reload hook.

        A NEW loaded image invalidates the ranges/A2L row indices (the
        selections key into a table that just changed), so the seats reset
        on an image swap; the typed manual localities survive (they are the
        operator's own text, not image rows).
        """
        loaded = self._loaded()
        if loaded is not self._loaded_cache:
            self._loaded_cache = loaded
            for key in ("ranges", "a2l"):
                self._sel[key] = set()
                self._cursor[key] = 0
            self._armed = False
        self._sync()
        # One settled re-sync: the first pass may run before the freshly
        # unhidden window has real measured widths (content_size 0 — the
        # `_fit` guards stay unclamped); after the next refresh the widths
        # are true and every clamp lands (the wrap audit's law).
        self.call_after_refresh(self._sync)
        try:
            self.query_one("#sje_table", _SegTable).focus()
        except Exception:
            pass

    def on_resize(self, event: events.Resize) -> None:
        self._apply_regime()
        self._sync()

    def _apply_regime(self) -> None:
        # The thresholds read the MEASURED screen (LLR-135.3): run_test's
        # "120x36" hands the app a 118x34 screen — never the nominal size.
        width = self.screen.size.width
        self.set_class(width < NARROW_WIDTH_MAX, "narrow")
        self.set_class(width >= WIDE_WIDTH_MIN, "wide")

    def _table_note(self) -> Optional[str]:
        if self._tab == "a2l" and not self._a2l_rows():
            return NO_A2L_NOTE
        if self._tab == "manual":
            return "type localities (0xSTART-0xEND, one per line)"
        return "no ranges — load an image (^L) or switch to manual"

    def _state_text(self, plan: Plan) -> Tuple[Text, bool]:
        """The one state line shared by both stat layouts: the guard chip /
        conflict abort / empty-file gate / ready cue (LLR-135.5/136.4/136.6).

        Returns the line and whether it demands the two-step confirm.
        """
        t = Text()
        if plan.guard:
            t.append(f"⚠ GUARD  {fmtB(plan.span)} span", style=S_WARN_B)
            t.append(
                " — e again to confirm" if self._armed else " — e will ask",
                style=S_DIM,
            )
            return t, True
        if plan.conflicts:
            t.append(
                f"⚠ {fmtB(plan.conflicts)} would clobber source — abort on export",
                style=S_WARN_B,
            )
            return t, False
        if plan.empty_files:
            t.append(
                f"⚠ {plan.empty_files} empty file"
                f"{'s' if plan.empty_files > 1 else ''} — 0 B of source",
                style=S_WARN_B,
            )
            t.append(
                " — e again to confirm" if self._armed else " — e will ask",
                style=S_DIM,
            )
            return t, True
        t.append("ready — e exports", style=S_DIM)
        return t, False

    def _stats_text(self, plan: Plan, width: int) -> Text:
        compact = width < 32
        if compact:
            # The floor (pane content 26 cells, 8 rows in the shipped app's
            # 12-row body): ONE state line, no metrics — the metrics live in
            # the summary and the warning toast names everything (LLR-135.5).
            if plan.nothing_selected:
                t = Text()
                t.append("∅ nothing selected — ", style=S_WARN_B)
                t.append("tick a row (␣) or press a", style=S_DIM)
                return t
            state, _ = self._state_text(plan)
            return state
        t = Text()
        if plan.nothing_selected:
            t.append("∅ nothing selected — ", style=S_WARN_B)
            t.append("tick a row (␣) or press a", style=S_DIM)
            return t
        sep = "  ·  "
        if self._mode == "join":
            t.append(f"packed {fmtB(plan.packed)}", style=S_FG)
            if self._gap == "concat":
                t.append(sep + "concat: offsets remapped, no pads", style=S_DIM)
            else:
                t.append(sep + f"span {fmtB(plan.span)}", style=S_DIM)
                t.append(
                    sep + f"fill {100 * plan.fill / max(plan.span, 1):.2f}%",
                    style=S_DIM,
                )
        else:
            n = len(plan.files)
            bytes_ = sum(f.packed for f in plan.files)
            pads = sum(f.pad for f in plan.files)
            t.append(
                f"{n} file{'s' if n != 1 else ''} · {fmtB(bytes_)} data",
                style=S_FG,
            )
            if pads:
                t.append(sep + f"{fmtB(pads)} pad", style=S_DIM)
        t.append("\n")
        state, _ = self._state_text(plan)
        t.append_text(state)
        return t

    def _summary_text(self, plan: Plan, rows: List[SegRow]) -> Text:
        picked = self._valid_picked(rows)
        noun = {"a2l": "segments", "ranges": "ranges", "manual": "localities"}[
            self._tab
        ]
        dst = str(self._dest_dir_display())
        t = Text()
        if self._mode == "split":
            data = sum(f.packed for f in plan.files)
            gp = f" · intra_gap={self._gap}" + (
                f" (pad {self._pad_str()})" if self._gap == "fill" else ""
            )
            t.append(
                f"Selected {len(picked)}/{len(rows)} {noun} · {fmtB(data)}",
                style=S_FG,
            )
            t.append(
                f" · export → {self._fmt.upper()} × {len(picked)} file"
                f"{'s' if len(picked) != 1 else ''}{gp} → ",
                style=S_FG,
            )
            t.append(dst, style=S_DIM)
        else:
            if not picked:
                t.append(
                    "Join mode — select at least one range to join", style=S_DIM
                )
                return t
            if self._gap == "concat":
                sizing = f"{fmtB(plan.packed)} packed from base {HEX8(plan.band_lo)}"
            else:
                base0 = min(rows[i].base for i in picked)
                sizing = (
                    f"span {HEX8(base0)}–{HEX8(base0 + plan.span)}"
                    f" = {fmtB(plan.span)} (packed {fmtB(plan.packed)})"
                    f" · pad {self._pad_str()}"
                )
            t.append(
                f"Join {len(picked)} {noun} → 1 file · join={self._gap} · ",
                style=S_FG,
            )
            t.append(sizing, style=S_FG)
            t.append(f" · {self._fmt.upper()} → ", style=S_FG)
            t.append(dst, style=S_DIM)
        return t

    def _sync(self) -> None:
        if not self.is_mounted:
            return
        rows = self._rows()
        sel = self._sel[self._tab]
        cur = max(0, min(self._cursor[self._tab], max(len(rows) - 1, 0)))
        self._cursor[self._tab] = cur
        plan = self._plan(rows)
        # The chip vocabulary is measured on the LEFT pane (the shipped
        # rail eats ~22 columns the standalone prototype had) — before the
        # first layout the region is 0 and the screen regime answers.
        left_w = self.query_one("#sje_left").content_size.width
        compact = (
            left_w < 58
            if left_w > 0
            else self.screen.size.width < NARROW_WIDTH_MAX + 20
        )
        counts = self._counts()

        manual = self.query_one("#sje_manual", TextArea)
        manual.set_class(self._tab != "manual", "hidden")
        dropped = self._manual_rows()[1]
        if tuple(dropped) != self._manual_dropped:
            self._manual_dropped = tuple(dropped)
            if dropped:
                self._app().set_status(
                    "manual: dropped "
                    + ", ".join(d.strip() for d in dropped[:3])
                    + (f" (+{len(dropped) - 3} more)" if len(dropped) > 3 else "")
                )

        for wid, builder in (
            ("#sje_tabs", lambda: _chips_tabs(compact, self._tab, counts)),
            ("#sje_mode", lambda: _chips_mode(compact, self._mode)),
            (
                "#sje_gap",
                lambda: _chips_gap(compact, self._mode, self._gap, self._pad_str()),
            ),
            ("#sje_fmt", lambda: _chips_fmt(compact, self._fmt)),
            ("#sje_dest", lambda: _chips_dest(compact, self._dest)),
            (
                "#sje_naming",
                lambda: _chips_naming(self._pattern, self._sample(rows)),
            ),
        ):
            w = self.query_one(wid, Static)
            w.update(_fit(builder(), w.content_size.width))
        self.query_one("#sje_table", _SegTable).set_data(
            rows, sel, cur, self._src_ranges(), note=self._table_note()
        )
        first = self._valid_picked(rows)
        label = (
            f"{self._stem()}_joined.{self._fmt}"
            if self._mode == "join"
            else f"{len(first)} file{'s' if len(first) != 1 else ''}"
            + (f" · ‹{rows[first[0]].name}›" if first else "")
        )
        outlabel = self.query_one("#sje_outlabel", Static)
        outlabel.update(
            _fit_lines(Text(label, style=S_ACCENT), outlabel.content_size.width)
        )
        self.query_one("#sje_band", _BandBar).set_blocks(
            plan.map_blocks
            if plan.address_preserving
            else ([] if plan.nothing_selected else plan.files[0].blocks)
        )
        self.query_one("#sje_legend", Static).update(_legend(compact))
        self.query_one("#sje_ruler", _RulerBar).set_span(plan.band_lo, plan.band_hi)
        stats = self.query_one("#sje_stats", Static)
        stats_w = stats.content_size.width
        stats.update(_fit_lines(self._stats_text(plan, stats_w), stats_w))
        summary = self.query_one("#sje_summary", Static)
        summary.update(
            _fit_lines(self._summary_text(plan, rows), summary.content_size.width)
        )
        # The graft delta: split mode renders the per-file gantt only when
        # 1..6 files are selected (LLR-135.4); the floor hides the wrap by CSS.
        show = (
            self._mode == "split"
            and not plan.nothing_selected
            and 1 <= len(plan.files) <= GANTT_CAP
        )
        self.query_one("#sje_files_wrap").set_class(not show, "hidden")
        if show:
            self.query_one("#sje_files", _GanttBar).set_plan(plan)

    # ------------------------------------------------------------------ #
    # Actions — every state change disarms the confirm (LLR-135.5)
    # ------------------------------------------------------------------ #

    def _bump(self) -> None:
        self._armed = False
        self._sync()

    def action_move(self, d: int) -> None:
        rows = self._rows()
        if not rows:
            return
        cur = self._cursor[self._tab]
        self._cursor[self._tab] = max(0, min(len(rows) - 1, cur + d))
        self._sync()

    def action_toggle_row(self) -> None:
        rows = self._rows()
        if not rows:
            return
        cur = self._cursor[self._tab]
        sel = self._sel[self._tab]
        if cur in sel:
            sel.discard(cur)
        else:
            sel.add(cur)
        self._bump()

    def action_select_all(self) -> None:
        self._sel[self._tab] = set(range(len(self._rows())))
        self._bump()

    def action_select_none(self) -> None:
        self._sel[self._tab] = set()
        self._bump()

    def action_cycle_tab(self) -> None:
        order = list(TABS)
        self._tab = order[(order.index(self._tab) + 1) % len(order)]
        self._bump()
        # Keyboard-first: the manual tab edits the localities box directly.
        try:
            if self._tab == "manual":
                self.query_one("#sje_manual", TextArea).focus()
            else:
                self.query_one("#sje_table", _SegTable).focus()
        except Exception:
            pass

    def action_toggle_mode(self) -> None:
        self._mode = "join" if self._mode == "split" else "split"
        self._gap = "concat" if self._mode == "join" else "skip"
        self._bump()

    def action_cycle_gap(self) -> None:
        if self._mode == "join":
            self._gap = "fill" if self._gap == "concat" else "concat"
        else:
            self._gap = "fill" if self._gap == "skip" else "skip"
        self._bump()

    def action_cycle_format(self) -> None:
        order = list(_engine_attr("EXPORT_FORMATS"))
        self._fmt = order[(order.index(self._fmt) + 1) % len(order)]
        self._bump()

    def action_cycle_pad(self) -> None:
        self._pad_int = 0xFF if self._pad_int == 0x00 else 0x00
        self._bump()

    def action_cycle_dest(self) -> None:
        self._dest = "common" if self._dest == "project" else "project"
        self._bump()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "sje_export":
            self.action_export()

    def action_export(self) -> None:
        app = self._app()
        rows = self._rows()
        plan = self._plan(rows)
        if plan.nothing_selected:
            app.set_status("nothing selected — tick a row with ␣ or press a")
            return
        if plan.conflicts:
            # The engine's abort law would fire — refuse BEFORE the guard
            # gate and write nothing (LLR-136.4).
            app.set_status(
                f"export aborted — {fmtB(plan.conflicts)} would clobber "
                f"source (the ▒ bytes); the fill cannot overwrite real bytes"
            )
            app.notify(
                f"export aborted: {fmtB(plan.conflicts)} of source bytes sit "
                f"inside a padded gap (see the ▒ cells)",
                severity="error",
                markup=False,
            )
            return
        if (plan.guard or plan.empty_files) and not self._armed:
            # The two-step (LLR-135.5 + LLR-136.6): ONE arming naming every
            # reason; the first e writes nothing.
            self._armed = True
            self._sync()
            reasons = []
            if plan.guard:
                reasons.append(
                    f"span guard: {fmtB(plan.span)} span from "
                    f"{fmtB(plan.packed)} of data "
                    f"({100 * plan.fill / max(plan.span, 1):.2f}% pad)"
                )
            if plan.empty_files:
                reasons.append(
                    f"{plan.empty_files} empty file"
                    f"{'s' if plan.empty_files > 1 else ''} — 0 B of source"
                )
            app.notify(
                " — ".join(reasons) + " — press e again to confirm",
                severity="warning",
                markup=False,
            )
            return
        picked = [rows[i] for i in self._valid_picked(rows)]
        dest_dir = self._dest_dir()
        GapConflictError = _engine_attr("GapConflictError")
        try:
            written = write_split_join_export(
                self._mem_map(),
                picked,
                mode=self._mode,
                gap=self._gap,
                pad_byte=self._pad_int,
                fmt=self._fmt,
                stem=self._stem(),
                dest_dir=dest_dir,
                zero_coverage_empty=True,
            )
        except GapConflictError as exc:
            # The plan's ▒ sweep and the engine agreed to disagree (a racing
            # image edit) — the engine's reason names the offending span.
            self._armed = False
            app.set_status(f"export aborted: {exc}")
            app.notify(f"export aborted: {exc}", severity="error", markup=False)
            return
        except Exception as exc:
            self._armed = False
            app.set_status(f"export failed: {exc}")
            app.notify(f"export failed: {exc}", severity="error", markup=False)
            return
        self._armed = False
        names = ", ".join(p.name for p in written[:3])
        if len(written) > 3:
            names += ", …"
        app.set_status(f"exported {len(written)} file(s) → {dest_dir}")
        app.notify(
            f"wrote {names}",
            title="Split / Join / Export",
            severity="information",
            markup=False,
        )
        self._sync()

    def action_close_window(self) -> None:
        app = self._app()
        return_to = getattr(app, "_split_join_return_screen", "workspace")
        self.add_class("hidden")
        app.action_show_screen(return_to)

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        if event.text_area.id == "sje_manual":
            self._sync()
