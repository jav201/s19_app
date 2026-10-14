"""Split / Join / Export — the shipped window (batch-95 change 4 / US-129,
HLR-135 + HLR-136; LLR-135.1..135.7, LLR-136.1..136.6).

The window is a VIEW over the inc-001 engine (``s19_app.segment_ops``): this
module pins the plan model (the band's class sweep, the guard arithmetic, the
conflict census == the engine's ``gap_conflict`` detector), the visor
renderers (glyph/class mapping, run economy, floor-one apportioning), the
three segment sources with the ranges-first default, the graft chassis and
the two-regime reflow at the MEASURED geometries (the batch-93 frame
discipline: ``run_test(size=(120, 36))`` hands the app a 118x34 screen), the
palette-first entry with zero rail keys, the split/join export bytes on disk
in all three formats, the span guard's two-step, and the wrap audit.

Coverage map (test -> TC -> LLR):

- TC-708 / LLR-135.5 — ``test_tc708_guard_threshold_boundaries_both_sides``:
  span 1 MiB +/- 1 and fill fraction 0.5 +/- epsilon are tested inputs, both
  sides of each threshold (unit, over ``build_plan``).
  ``test_tc708_guard_two_step_arm_disarm_rearm_confirm``: the demo guard case
  (3 A2L segments, join=fill) renders the GUARD chip, the first ^E arms only
  and writes 0 bytes, a state change disarms, re-arm + second ^E writes
  exactly the planned file.
  ``test_tc708_below_thresholds_guard_never_fires``: just under both
  thresholds exports on the FIRST ^E with no arming.
- TC-709 / HLR-135 (the batch-93 wrap-audit idiom carried) —
  ``test_tc709_wrap_audit_zero_overflows_both_geometries``: every authored
  line of every painted surface fits its widget's measured width at 118x34
  and 80x24 across the split / join-conflict / guard states.
  ``test_tc709_wrap_audit_overlong_injection_reddens``: an injected over-long
  line reddens the same audit (an audit that cannot fail proves nothing).
- TC-710 / batch-95 5.2 (the change-4 limbs of the negative-control battery)
  — ``test_tc710_palette_entry_no_rail_key_esc_close``: the palette lists
  exactly one entry named "Split / Join / Export" and it opens the screen; 0
  rail bindings were added; Esc closes 1/1 from the table AND from the
  preview pane (these DOM assertions are RED on the pre-change tree — no
  screen). ``test_tc710_chassis_dom_order_and_preview_pane``: the graft
  chassis in the contracted order with the `` PREVIEW `` border title and the
  title row carrying title + ``?`` help chip only (no 📂 chip).
  ``test_tc710_plan_conflict_abort_matches_engine``: the plan's ▒ census ==
  the shipped ``gap_conflict`` detector byte-for-byte, the band renders ▒
  exactly at the engine's refused addresses, and the export aborts writing 0
  bytes (the two-step/abort battery limb, RED pre-change).
  ``test_tc710_split_from_each_source_naming``: one file per selected range
  named ``‹stem›_‹segment›.‹ext›`` from EACH of the three segment sources —
  A2L MEMORY_SEGMENT rows / image ranges / manual localities (LLR-135.7 +
  LLR-136.5, RED pre-change: no screen, no files).

The remaining LLR arms ride on plainly-named tests (the batch reserved
TC-708/709/710 for this change; no further ids were minted): the split
skip/fill limbs (LLR-136.1), join concat from the lowest base (LLR-136.2),
join fill at original offsets with the ``·`` context cells (LLR-136.3), pad
default 0x00 + configurable (LLR-136.4), zero coverage as a first-class state
behind an explicit confirm (LLR-136.6), the visor class system + run census +
ruler (LLR-135.2), the two-regime pilot (LLR-135.3), the per-file gantt
show/hide with the 6/7 cap and the empty-file row (LLR-135.4), the manual
parser's tolerant forms + inclusive end + dropped-line census (LLR-135.7),
and the S19/HEX/BIN byte-level export assertions in both modes
(LLR-136/LLR-137.2, re-parsing the written files through the shipped oracles).

Harness: the ``App.run_test(size=(120, 36))`` pilot pattern of
``tests/test_open_folder_chips.py`` / ``tests/test_window_usage_help.py`` —
the batch-93 pinning rule: the app hands the tests a 118x34 screen. The shot
path sanitizes NO_COLOR/TERM first (the design-notes' grey-frames incident)
so the SVG census sees the real class hexes.
"""
from __future__ import annotations

import asyncio
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest
from rich.cells import cell_len
from rich.style import Style
from rich.text import Text
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Label, Static

from s19_app.core import S19File
from s19_app.hexfile import IntelHexFile
from s19_app.segment_ops import (
    DEFAULT_PAD_BYTE,
    GapConflictError,
    join_concat,
    join_fill,
)
from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile
from s19_app.tui.operations.crc_designer_model import CrcTarget, gap_conflict
from s19_app.tui.open_folder_chip import HEADER_ROW_CLASS
from s19_app.tui.segment_split_view import (
    GANTT_CAP,
    GLYPH,
    GUARD_FILL_MIN,
    GUARD_SPAN_MIN,
    NO_A2L_NOTE,
    SegRow,
    SplitJoinWindow,
    _SegTable,
    apportion,
    band_text,
    build_plan,
    gantt_text,
    parse_manual,
    resolve_sample,
    ruler_text,
    write_split_join_export,
)
from s19_app.tui.window_help import WindowHelpChip, WindowSection

EXAMPLE_PRG = (
    Path(__file__).resolve().parents[1] / "examples" / "case_00_public" / "prg.s19"
)

#: The batch-95 demo A2L segments (the extracted rows the round signed on),
#: injected as parsed-A2L sections (the hardened extractor's input shape).
DEMO_A2L_SECTIONS = [
    {
        "name": "MEMORY_SEGMENT",
        "meta": "'AscetCode'",
        "lines": ["CODE FLASH 0x0 0x08000000 0xF800 0x0"],
        "children": [],
    },
    {
        "name": "MEMORY_SEGMENT",
        "meta": "'AscetCalibrationRom'",
        "lines": ["DATA ROM 0x0 0x0800F800 0x800 0x0"],
        "children": [],
    },
    {
        "name": "MEMORY_SEGMENT",
        "meta": "'Variables'",
        "lines": ["DATA RAM 0x0 0x20000000 0x2800 0x0"],
        "children": [],
    },
]


def _demo_loaded(a2l: bool = False) -> LoadedFile:
    """prg.s19 wrapped the way the load pipeline wraps it."""
    s19 = S19File(str(EXAMPLE_PRG))
    mem_map = s19.get_memory_map()
    ranges = s19.get_memory_ranges()
    return LoadedFile(
        path=EXAMPLE_PRG,
        file_type="s19",
        mem_map=mem_map,
        row_bases=[],
        ranges=ranges,
        range_validity=[True] * len(ranges),
        errors=[],
        a2l_path=None,
        a2l_data={"sections": DEMO_A2L_SECTIONS} if a2l else None,
    )


def _fix_color_env() -> None:
    """The shot path must see a color terminal or the SVG ships greyscale
    (the design-notes' incident: this shell exports NO_COLOR/TERM=dumb)."""
    os.environ.pop("NO_COLOR", None)
    os.environ.pop("CLICOLOR", None)
    os.environ["TERM"] = "xterm-256color"
    os.environ["COLORTERM"] = "truecolor"


async def _pause(pilot) -> None:
    for _ in range(4):
        await pilot.pause()


async def _open_window(app: S19TuiApp, pilot) -> SplitJoinWindow:
    """Open the screen the palette's way and return the mounted window."""
    app.action_open_split_join_export()
    await _pause(pilot)
    return app.query_one("#screen_split_join", SplitJoinWindow)


def _splits_dir(app: S19TuiApp) -> Path:
    return Path(app.workarea) / "splits"


def _reparsed_s19_map(path: Path) -> Dict[int, int]:
    """Re-parse written S19 through the shipped oracle (must be error-free)."""
    reread = S19File(str(path))
    assert reread.load_errors == []
    return reread.get_memory_map()


def _reparsed_hex_map(path: Path) -> Dict[int, int]:
    """Re-parse written HEX through the shipped oracle."""
    reread = IntelHexFile(str(path))
    assert reread.get_errors() == []
    return reread.memory


# ---------------------------------------------------------------------------
# Fixtures — small constructed images (no client data)
# ---------------------------------------------------------------------------

#: A sparse island image: 0x1000-0x1007 bytes i*7, a 24-byte hole, then
#: 0x1020-0x1027 bytes i*3 — the split fill/skip playground.
ISLAND_A = {0x1000 + i: (i * 7) & 0xFF for i in range(8)}
ISLAND_B = {0x1020 + i: (i * 3) & 0xFF for i in range(8)}
SPARSE_MAP: Dict[int, int] = {**ISLAND_A, **ISLAND_B}
SPARSE_SRC = [(0x1000, 0x1008), (0x1020, 0x1028)]


def _loaded_from(mem_map: Dict[int, int], name: str = "toy.s19") -> LoadedFile:
    addrs = sorted(mem_map)
    ranges: List[Tuple[int, int]] = []
    for a in addrs:
        if ranges and a == ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], a + 1)
        else:
            ranges.append((a, a + 1))
    return LoadedFile(
        path=Path(name),
        file_type="s19",
        mem_map=dict(mem_map),
        row_bases=[],
        ranges=ranges,
        range_validity=[True] * len(ranges),
        errors=[],
        a2l_path=None,
        a2l_data=None,
    )


# ---------------------------------------------------------------------------
# TC-708 / LLR-135.5 — the guard thresholds and the two-step
# ---------------------------------------------------------------------------


def _guard_case(
    span: int, fill_fraction: float
) -> Tuple[List[SegRow], Dict[int, int], List[Tuple[int, int]]]:
    """Build a join=fill plan input with an EXACT span and an exact fill
    fraction: two covered islands totalling ``span * (1 - fraction)`` bytes
    sit at the two ends of ``[base, base+span)`` — the pad sweep between
    them is exactly ``span * fraction`` bytes."""
    assert 0.0 < fill_fraction < 1.0
    data = max(int(span * (1.0 - fill_fraction)), 2)
    half = data // 2
    mem_map = {0x1000 + i: (0xA0 + i) & 0xFF for i in range(half)}
    end_lo = 0x1000 + span - (data - half)
    mem_map.update({end_lo + i: (0xB0 + i) & 0xFF for i in range(data - half)})
    rows = [
        SegRow("seg_a", "manual", 0x1000, half),
        SegRow("seg_b", "manual", end_lo, data - half),
    ]
    src = [(0x1000, 0x1000 + half), (end_lo, end_lo + data - half)]
    return rows, mem_map, src


def _plan_guard(rows, mem_map, src, mode="join", gap="fill"):
    return build_plan(
        rows, {0, 1}, src, mem_map, mode=mode, gap=gap, stem="t", ext="s19"
    )


def test_tc708_guard_threshold_boundaries_both_sides() -> None:
    """TC-708 (LLR-135.5 boundary catalog): span 1 MiB +/- 1 and fill
    fraction 0.5 +/- epsilon are TESTED INPUTS, both sides of each
    threshold — the guard fires exactly on (span >= 1 MiB, fill >= 50%)."""
    # Span limb at a high fill: 1 MiB - 1 does NOT fire, 1 MiB does.
    rows, mem_map, src = _guard_case(GUARD_SPAN_MIN - 1, 0.9)
    plan = _plan_guard(rows, mem_map, src)
    assert plan.span == GUARD_SPAN_MIN - 1 and not plan.guard

    rows, mem_map, src = _guard_case(GUARD_SPAN_MIN, 0.9)
    plan = _plan_guard(rows, mem_map, src)
    assert plan.span == GUARD_SPAN_MIN and plan.guard

    # Fill-fraction limb at a 1 MiB + 1 span: just under 0.5 does NOT fire.
    rows, mem_map, src = _guard_case(GUARD_SPAN_MIN + 1, GUARD_FILL_MIN - 0.01)
    plan = _plan_guard(rows, mem_map, src)
    assert not plan.guard, "fill 49% under a 1 MiB span must not arm the guard"

    rows, mem_map, src = _guard_case(GUARD_SPAN_MIN + 1, GUARD_FILL_MIN)
    plan = _plan_guard(rows, mem_map, src)
    assert plan.guard, "fill exactly 50% of a 1 MiB span is the contracted threshold"

    # A hair over each threshold fires.
    rows, mem_map, src = _guard_case(GUARD_SPAN_MIN + 1, 0.9)
    plan = _plan_guard(rows, mem_map, src)
    assert plan.guard

    # The guard is join=fill ONLY: split at the same span/fill never fires,
    # and join=concat never pads so it never fires.
    rows, mem_map, src = _guard_case(GUARD_SPAN_MIN, 0.9)
    plan = _plan_guard(rows, mem_map, src, mode="split")
    assert not plan.guard
    plan = _plan_guard(rows, mem_map, src, gap="concat")
    assert not plan.guard


def test_tc708_guard_two_step_arm_disarm_rearm_confirm(tmp_path: Path) -> None:
    """TC-708 (LLR-135.5 executed): on a guard case (join=fill over a span
    just past 1 MiB around a few bytes of data) the GUARD chip renders; the
    first ^E arms ONLY (0 bytes written) with a warning naming the span and
    the data size (the toast names the pad percentage too); a state change
    disarms; re-arm + the second ^E writes exactly the planned file pair.
    The demo-scale 384 MiB case rides on
    ``test_guard_chip_renders_on_the_demo_case`` (chip + arm only — no
    402 MB write in a unit test)."""

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            rows, mem_map, _src = _guard_case(GUARD_SPAN_MIN + 16, 0.9999)
            app.current_file = _loaded_from(mem_map)
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = {0, 1}
            window.action_toggle_mode()  # join (gap -> concat)
            window.action_cycle_gap()  # -> fill
            window.action_cycle_format()  # s19 -> hex
            window.action_cycle_format()  # -> bin (a 1 MiB write, not 400)
            await _pause(pilot)
            plan = window._plan(window._rows())
            assert plan.guard and plan.span == GUARD_SPAN_MIN + 16
            stats = str(app.query_one("#sje_stats").render())
            assert "GUARD" in stats

            dest = _splits_dir(app)
            await pilot.press("e")
            await _pause(pilot)
            armed_after_first = window._armed
            wrote_after_first = list(dest.iterdir()) if dest.exists() else []

            # A state change disarms (LLR-135.5's disarm limb) — the
            # destination cycle changes no planned byte.
            window.action_cycle_dest()
            disarmed = not window._armed

            # Re-arm and confirm.
            await pilot.press("e")
            await _pause(pilot)
            rearmed = window._armed
            await pilot.press("e")
            await _pause(pilot)
            wrote = sorted(p.name for p in dest.iterdir()) if dest.exists() else []
            return {
                "armed_after_first": armed_after_first,
                "wrote_after_first": wrote_after_first,
                "disarmed": disarmed,
                "rearmed": rearmed,
                "wrote": wrote,
                "guard_text": stats,
                "span": plan.span,
            }

    observed = asyncio.run(_drive())
    assert observed["armed_after_first"] is True, "the first ^E must arm only"
    assert observed["wrote_after_first"] == [], "the first ^E writes 0 bytes"
    assert f"{observed['span'] / (1 << 20):.2f} MiB" in observed["guard_text"], (
        "the chip names the span"
    )
    assert observed["disarmed"] is True, "a state change (format) disarms"
    assert observed["rearmed"] is True, "the re-asked ^E re-arms"
    assert observed["wrote"] == ["toy_joined.addr", "toy_joined.bin"], (
        f"the confirmed export writes exactly the planned pair: {observed['wrote']}"
    )
    sidecar = tmp_path / ".s19tool" / "workarea" / "splits" / "toy_joined.addr"
    assert sidecar.read_text(encoding="ascii") == "0x00001000\n"


def test_guard_chip_renders_on_the_demo_case(tmp_path: Path) -> None:
    """LLR-135.5/HHLR-135: the signed demo guard case — 3 A2L MEMORY_SEGMENT
    rows over prg.s19, join=fill, 0 B of 75,776 B covered — renders the
    GUARD chip naming the 384.01 MiB span from 0 B of data, and the first
    ^E arms without writing (no confirm: the write would be 402 MB)."""

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            loaded = _demo_loaded(a2l=True)
            app.current_file = loaded
            app.current_a2l_data = loaded.a2l_data
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window.action_cycle_tab()  # ranges -> manual
            window.action_cycle_tab()  # manual -> a2l
            await _pause(pilot)
            window.action_select_all()
            window.action_toggle_mode()  # join (gap -> concat)
            window.action_cycle_gap()  # -> fill
            await _pause(pilot)
            plan = window._plan(window._rows())
            stats = str(app.query_one("#sje_stats").render())
            await pilot.press("e")
            await _pause(pilot)
            dest = _splits_dir(app)
            return {
                "guard": plan.guard,
                "empty": plan.empty_files,
                "stats": stats,
                "armed": window._armed,
                "wrote": list(dest.iterdir()) if dest.exists() else [],
            }

    observed = asyncio.run(_drive())
    assert observed["guard"] and observed["empty"] == 1
    assert "GUARD" in observed["stats"]
    assert "384.01 MiB" in observed["stats"], "the chip names the span"
    assert "0 B" in observed["stats"], "the chip names the data size"
    assert "100.00%" in observed["stats"], "the stats name the pad percentage"
    assert observed["armed"] is True
    assert observed["wrote"] == [], "the armed demo case must not write"


def test_tc708_below_thresholds_guard_never_fires(tmp_path: Path) -> None:
    """TC-708 (LLR-135.5 negative control): just below the thresholds the
    guard NEVER fires — the export writes on the FIRST ^E with no arming."""

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            rows, mem_map, _src = _guard_case(GUARD_SPAN_MIN - 1, 0.9)
            app.current_file = _loaded_from(mem_map)
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = {0, 1}
            window.action_toggle_mode()
            window.action_cycle_gap()
            await _pause(pilot)
            await pilot.press("e")
            await _pause(pilot)
            dest = _splits_dir(app)
            return {
                "armed": window._armed,
                "wrote": sorted(p.name for p in dest.iterdir()) if dest.exists() else [],
            }

    observed = asyncio.run(_drive())
    assert observed["armed"] is False, "below the thresholds no arming happens"
    assert observed["wrote"] == ["toy_joined.s19"], (
        f"the first ^E writes immediately: {observed['wrote']}"
    )


# ---------------------------------------------------------------------------
# The visor class system (LLR-135.2) — glyphs, hexes, run economy, ruler
# ---------------------------------------------------------------------------


def test_visor_class_glyph_and_hex_mapping_exact() -> None:
    """LLR-135.2: class -> glyph -> hex mapping exact (5/5) — one visual
    variable per cell, density + hue two correlated encodings (C-10)."""
    from s19_app.tui.segment_split_view import Block

    expected = {
        "data": ("▓", "#91abec"),
        "fill": ("░", "#6b7280"),
        "conflict": ("▒", "#f6ff8f"),
        "ctx": ("·", "#46557a"),
        "none": (" ", None),
    }
    for cls, (glyph, hex_) in expected.items():
        assert GLYPH.get(cls, " ") == glyph, cls
        text = band_text([Block(cls, 10)], 20)
        if hex_ is None:
            # The absent class carries no styled span at all.
            assert all(span.style is None for span in text.spans), cls
            continue
        span = text.spans[0]
        assert span.style == Style(color=hex_), f"{cls}: {span.style!r} != {hex_}"
        assert text.plain == glyph * 20, cls


def test_visor_runs_coalesced_under_fourteen_at_hostile_widths() -> None:
    """LLR-135.2: one styled span per block — runs per band row <= 14 at
    every tested width (never one run per cell, the per-cell-markup failure
    mode), and the band width == the measured container (the bound lives in
    the producer)."""
    from s19_app.tui.segment_split_view import Block

    blocks = [
        Block("data", 3000),
        Block("fill", 2000),
        Block("conflict", 40),
        Block("fill", 5000),
        Block("ctx", 800),
        Block("data", 120),
        Block("none", 600),
        Block("ctx", 30),
        Block("fill", 9000),
        Block("data", 64),
        Block("conflict", 16),
        Block("ctx", 2048),
    ]
    for width in (13, 26, 36, 54, 74, 118):
        text = band_text(blocks, width)
        assert len(text.plain) == width, (
            f"width {width}: the band must fill its container exactly"
        )
        assert len(text.spans) <= 14, (
            f"width {width}: {len(text.spans)} runs — the coalescing law is 14"
        )
        assert len(text.spans) <= len(blocks)
    # Pathological widths (< one column per block): the floor-one law keeps
    # EVERY block >= 1 column — visibility wins over exact fill there (real
    # bands carry <= 14 blocks at >= 26 columns; the wrap audit polices the
    # real geometries).
    cramped = band_text(blocks, 8)
    assert len(cramped.plain) == len(blocks)
    assert len(cramped.spans) <= 14


def test_visor_one_byte_block_keeps_a_column_in_a_huge_span() -> None:
    """LLR-135.2 boundary: a 1-byte block keeps >= 1 column inside a 57 KiB
    span (linear address map, floor-one apportioning)."""
    from s19_app.tui.segment_split_view import Block

    widths = apportion([1, 57000], 54)
    assert widths[0] >= 1 and sum(widths) == 54
    text = band_text([Block("data", 1), Block("fill", 57000)], 54)
    assert text.plain[0] == "▓" and len(text.plain) == 54


def test_visor_ruler_renders_span_ends_and_midpoint() -> None:
    """LLR-135.2: the ruler renders the 0xXXXXXXXX ends (+ midpoint when it
    fits) of the band's real span."""
    text = ruler_text(0x000017E0, 0x00010000, 54)
    plain = text.plain
    assert plain.startswith("0x000017E0")
    assert "0x00008BF0" in plain  # midpoint
    assert plain.rstrip().endswith("0x0000FFFF")  # hi - 1, the last byte
    # Too narrow for any tick: an empty ruler, never a wrapped one.
    assert ruler_text(0x0, 0x100, 10).plain == ""


# ---------------------------------------------------------------------------
# LLR-136.1 — split mode and the per-file intra-gap
# ---------------------------------------------------------------------------


def _island_plan(gap: str, pad: Optional[int] = None):
    rows = [SegRow("isle", "manual", 0x1000, 0x28)]
    if pad is None:
        return build_plan(rows, {0}, SPARSE_SRC, SPARSE_MAP, mode="split", gap=gap, stem="t", ext="s19")
    return build_plan(rows, {0}, SPARSE_SRC, SPARSE_MAP, mode="split", gap=gap, stem="t", ext="s19", pad_byte=pad)


def test_split_skip_writes_only_the_covered_sub_ranges(tmp_path: Path) -> None:
    """LLR-136.1 skip: the file's bytes == the covered sub-ranges
    concatenated (0 pad bytes), in address order; the band reads the holes
    as ABSENT (the shipped vocabulary: skip gaps are holes, never fill)."""
    plan = _island_plan("skip")
    f = plan.files[0]
    assert f.packed == 16 and f.pad == 0 and not f.empty
    assert sum(b.size for b in f.blocks if b.cls == "data") == 16
    assert not any(b.cls in ("fill", "conflict", "ctx") for b in f.blocks)
    absent = sum(b.size for b in f.blocks if b.cls == "none")
    assert absent == 0x28 - 16 == 24

    written = write_split_join_export(
        SPARSE_MAP, [SegRow("isle", "manual", 0x1000, 0x28)],
        mode="split", gap="skip", pad_byte=0x00, fmt="bin", stem="t",
        dest_dir=tmp_path,
    )
    assert written[0].read_bytes() == bytes(
        list(ISLAND_A.values()) + list(ISLAND_B.values())
    )


def test_split_fill_pads_only_inside_the_files_own_span(tmp_path: Path) -> None:
    """LLR-136.1 fill: the file's bytes == size (pad bytes == the
    intra-span gaps, source bytes untouched) — never across files, never
    outside the span (the negative control is a second file whose bytes
    prove no cross-file padding)."""
    rows = [SegRow("a", "manual", 0x1000, 0x28), SegRow("b", "manual", 0x2000, 8)]
    plan = build_plan(rows, {0, 1}, SPARSE_SRC, SPARSE_MAP, mode="split", gap="fill", stem="t", ext="bin")
    a, b = plan.files
    assert a.packed == 16 and a.pad == 0x28 - 16 == 24
    assert b.packed == 0 and b.pad == 8 and b.empty

    written = write_split_join_export(
        SPARSE_MAP, rows, mode="split", gap="fill", pad_byte=0x5A, fmt="bin",
        stem="t", dest_dir=tmp_path,
    )
    assert [p.name for p in written] == ["t_a.bin", "t_b.bin"]
    blob = (tmp_path / "t_a.bin").read_bytes()
    assert len(blob) == 0x28, "fill: the file is exactly its span"
    assert blob[:8] == bytes(ISLAND_A.values())
    assert blob[8:0x20] == b"\x5A" * 0x18, "the intra-gap is all pad byte"
    assert blob[0x20:] == bytes(ISLAND_B.values())
    # The second file: 8 pad bytes, no byte of file a's data leaked in.
    assert (tmp_path / "t_b.bin").read_bytes() == b"\x5A" * 8
    # And the sidecar base is each file's own declared base.
    assert (tmp_path / "t_a.addr").read_text(encoding="ascii") == "0x00001000\n"
    assert (tmp_path / "t_b.addr").read_text(encoding="ascii") == "0x00002000\n"


def test_split_fill_per_file_pad_counts_match_the_bands() -> None:
    """LLR-136.1: each file's band renders the same classes the file will
    contain — per-file pad counts match the band fill runs."""
    plan = _island_plan("fill", pad=0x5A)
    f = plan.files[0]
    band_fill = sum(b.size for b in f.blocks if b.cls == "fill")
    band_data = sum(b.size for b in f.blocks if b.cls == "data")
    assert band_fill == f.pad and band_data == f.packed
    assert band_fill == 24 and f.pad == 24


# ---------------------------------------------------------------------------
# LLR-136.2 — join concat from the first range's base
# ---------------------------------------------------------------------------


def test_join_concat_packs_ascending_from_the_lowest_base(tmp_path: Path) -> None:
    """LLR-136.2: output bytes == the ranges' covered bytes in ascending-
    base order (0 reorder), the emitted base == the LOWEST range's base
    (ruling Q2 — not a chosen value), the band carries 0 fill/conflict/ctx
    cells (pure ▓, 'offsets remapped')."""
    mem_map = {}
    for i in range(4):
        mem_map[0x3000 + i] = 0x30 + i  # highest base, declared FIRST
    for i in range(4):
        mem_map[0x1000 + i] = 0x10 + i  # lowest base, declared second
    src = [(0x1000, 0x1004), (0x3000, 0x3004)]
    rows = [
        SegRow("high", "manual", 0x3000, 4),
        SegRow("low", "manual", 0x1000, 4),
    ]
    plan = build_plan(rows, {0, 1}, src, mem_map, mode="join", gap="concat", stem="t", ext="bin")
    f = plan.files[0]
    assert f.label == "t_joined.bin"
    assert f.packed == 8 and all(b.cls == "data" for b in f.blocks)
    assert not plan.address_preserving

    written = write_split_join_export(
        mem_map, rows, mode="join", gap="concat", pad_byte=0x00, fmt="bin",
        stem="t", dest_dir=tmp_path,
    )
    assert written[0].name == "t_joined.bin"
    assert written[0].read_bytes() == bytes([0x10, 0x11, 0x12, 0x13, 0x30, 0x31, 0x32, 0x33])
    assert (tmp_path / "t_joined.addr").read_text(encoding="ascii") == "0x00001000\n", (
        "the concat base is the FIRST/LOWEST range's base (ruling Q2)"
    )
    packed_map, packed_ranges = join_concat(mem_map, [(0x3000, 0x3004), (0x1000, 0x1004)])
    assert packed_ranges == [(0x1000, 0x1008)]


# ---------------------------------------------------------------------------
# LLR-136.3 — join fill at the original offsets
# ---------------------------------------------------------------------------


def test_join_fill_keeps_original_offsets_and_ctx_cells(tmp_path: Path) -> None:
    """LLR-136.3: the selection stays at its ORIGINAL offsets — span = last
    end - first base — the gaps take the pad byte, and the `·` cells cover
    exactly the unselected source bytes inside the BAND's span (the band is
    the union of source + selected span; unselected source outside the
    selected span renders as context, like the demo's ghost ranges)."""
    mem_map = dict(SPARSE_MAP)
    # Unselected source BEYOND the selected span: an island at 0x1040 that
    # extends the band to [0x1000, 0x1048) without being selected.
    mem_map.update({0x1040 + i: 0xC0 + i for i in range(4)})
    src = [(0x1000, 0x1008), (0x1020, 0x1028), (0x1040, 0x1044)]
    rows = [SegRow("a", "manual", 0x1000, 8), SegRow("b", "manual", 0x1020, 8)]
    plan = build_plan(rows, {0, 1}, src, mem_map, mode="join", gap="fill", stem="t", ext="bin", pad_byte=0x00)
    assert plan.span == 0x28 and plan.address_preserving
    assert plan.fill == 0x28 - 16 == 24
    assert plan.band_lo == 0x1000 and plan.band_hi == 0x1044

    # The `·` cells cover EXACTLY the unselected source bytes (the 0x1040
    # island) — nothing inside the selected span renders as context.
    ctx = sum(b.size for b in plan.map_blocks if b.cls == "ctx")
    assert ctx == 4, f"only the planted unselected island renders as context: {ctx}"

    written = write_split_join_export(
        mem_map, rows, mode="join", gap="fill", pad_byte=0x00, fmt="bin",
        stem="t", dest_dir=tmp_path,
    )
    blob = written[0].read_bytes()
    assert len(blob) == 0x28, "the written span is the SELECTED span only"
    assert blob[:8] == bytes(ISLAND_A.values())
    assert blob[8:0x20] == b"\x00" * 24, "the intra-span gap pads with the default 0x00"
    assert blob[0x20:] == bytes(ISLAND_B.values())
    # The engine agrees byte-for-byte (the view rides the engine, ruling 8d).
    engine_map, engine_ranges = join_fill(mem_map, [(0x1000, 0x1008), (0x1020, 0x1028)], 0x00)
    assert engine_ranges == [(0x1000, 0x1028)]
    assert bytes(engine_map[a] for a in range(0x1000, 0x1028)) == blob


def test_join_fill_rebases_red() -> None:
    """LLR-136.3 negative control (ruling Q4): a join=fill that re-based the
    output would shift every byte — the engine's original-offset law is the
    oracle the plan rides, so a re-based plan cannot be constructed from
    these parts; the offset preservation is asserted against the engine
    byte-for-byte in the positive limb above (0 diffs)."""
    mem_map = dict(SPARSE_MAP)
    engine_map, _ = join_fill(mem_map, [(0x1000, 0x1008), (0x1020, 0x1028)], 0x00)
    for offset, byte in list(ISLAND_A.items()) + list(ISLAND_B.items()):
        assert engine_map[offset] == byte, (
            f"source byte at 0x{offset:08X} moved — join=fill must keep the "
            "original offsets (ruling Q4)"
        )


# ---------------------------------------------------------------------------
# TC-710 / LLR-136.4 — the conflict abort rides the engine's law
# ---------------------------------------------------------------------------


def test_tc710_plan_conflict_abort_matches_engine(tmp_path: Path) -> None:
    """TC-710 (the change-4 battery limb, RED pre-change): a fill that would
    overwrite real source bytes aborts BEFORE a byte lands on disk. The
    plan's ▒ census matches the shipped ``gap_conflict`` detector
    byte-for-byte; the band renders ▒ exactly at the refused addresses; the
    export writes 0 bytes and the reason names the offending span."""
    # The engine's own demo: selecting {0,1,2,5,6,7} of prg.s19's 11 ranges
    # under join=fill plants 5 present bytes inside the padded gap.
    s19 = S19File(str(EXAMPLE_PRG))
    mem_map = s19.get_memory_map()
    ranges = s19.get_memory_ranges()
    src = list(ranges)
    rows = [
        SegRow(f"range_{i:02d}", "ranges", s, e - s) for i, (s, e) in enumerate(ranges)
    ]
    picked = [0, 1, 2, 5, 6, 7]
    plan = build_plan(
        rows, set(picked), src, mem_map,
        mode="join", gap="fill", stem="prg", ext="s19",
    )
    # The plan's conflict census == the shipped detector's list (equivalence
    # of the view's sweep with the engine's abort law, ruling 8f).
    probe = CrcTarget(
        ranges=tuple(sorted(ranges[i] for i in picked)),
        intra_gap="skip",
        join="fill",
        pad_byte=0x00,
        output_address=0,
        store_width=1,
        store_endianness="little",
    )
    engine_conflicts = gap_conflict(mem_map, probe)
    assert plan.conflicts == len(engine_conflicts) == 5, (
        f"plan {plan.conflicts} vs engine {len(engine_conflicts)}"
    )

    # The band renders ▒ runs covering exactly the refused bytes.
    conflict_cells = sum(b.size for b in plan.map_blocks if b.cls == "conflict")
    assert conflict_cells == plan.conflicts

    # The engine refuses the same export (the view's dispatch surfaces it).
    with pytest.raises(GapConflictError) as excinfo:
        join_fill(mem_map, [ranges[i] for i in picked], 0x00)
    assert "0x0000EB00" in str(excinfo.value), "the reason names the offending span"

    # The window refuses BEFORE writing: 0 bytes on disk.
    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded()
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = set(picked)
            window.action_toggle_mode()
            window.action_cycle_gap()
            await _pause(pilot)
            dest = _splits_dir(app)
            n_before = len(list(dest.iterdir())) if dest.exists() else 0
            await pilot.press("e")
            await _pause(pilot)
            n_after = len(list(dest.iterdir())) if dest.exists() else 0
            stats = str(app.query_one("#sje_stats").render())
            return {
                "wrote": n_after - n_before,
                "armed": window._armed,
                "stats": stats,
                "conflicts": window._plan(window._rows()).conflicts,
            }

    observed = asyncio.run(_drive())
    assert observed["conflicts"] == 5
    assert observed["wrote"] == 0, "the refused export writes 0 bytes"
    assert observed["armed"] is False, "an abort is not a confirm gate"
    assert "clobber" in observed["stats"]


def test_pad_byte_defaults_to_zero_and_is_configurable(tmp_path: Path) -> None:
    """LLR-136.4: the pad defaults to 0x00 at every entry path (ruling Q1/8a
    — deliberately NOT the CRC editor's 0xFF, P-9) and the PAD control
    cycles it."""
    plan = _island_plan("fill")
    assert plan.files[0].pad == 0x18  # == size - covered, counted not bytes

    written = write_split_join_export(
        SPARSE_MAP, [SegRow("isle", "manual", 0x1000, 0x28)],
        mode="split", gap="fill", pad_byte=DEFAULT_PAD_BYTE, fmt="bin",
        stem="t", dest_dir=tmp_path,
    )
    blob = written[0].read_bytes()
    assert blob[8] == 0x00 and blob[0x1F] == 0x00, "default pad is 0x00"

    written = write_split_join_export(
        SPARSE_MAP, [SegRow("isle", "manual", 0x1000, 0x28)],
        mode="split", gap="fill", pad_byte=0xFF, fmt="bin",
        stem="t", dest_dir=tmp_path / "ff",
    )
    assert written[0].read_bytes()[8] == 0xFF, "the pad byte is configurable"

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path / "ui")
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            window = await _open_window(app, pilot)
            before = window._pad_int
            await pilot.press("p")
            await _pause(pilot)
            return f"{before}->{window._pad_int}"

    assert asyncio.run(_drive()) == "0->255", "the p key cycles 0x00 -> 0xFF"


# ---------------------------------------------------------------------------
# LLR-136.6 — zero coverage as a first-class state
# ---------------------------------------------------------------------------


def test_zero_coverage_requires_confirm_then_writes(tmp_path: Path) -> None:
    """LLR-136.6: a selected range whose span holds no source bytes renders
    the ∅ state and its export requires an explicit confirm; with the
    confirm the empty file writes (0 bytes for BIN + the .addr sidecar /
    header-only S19 per the emitters' shipped semantics)."""
    # A range entirely outside the sparse image.
    rows = [SegRow("empty", "manual", 0x8000, 0x10)]

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.current_file = _loaded_from(SPARSE_MAP)
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._mode = "split"
            # The contracted empty-file limb is the sparse emitter's: with
            # intra_gap=skip a zero-coverage range emits 0 bytes for BIN
            # (with fill it would emit `size` pad bytes — its own span, the
            # LLR-136.1 law, not an empty file).
            window._gap = "skip"
            window._fmt = "bin"
            window._sel["ranges"] = {0}
            # The ranges tab of the toy image has one row per island; the
            # zero-coverage row comes from the MANUAL tab instead.
            window.action_cycle_tab()  # ranges -> manual
            window.action_cycle_tab()  # manual -> a2l
            window.action_cycle_tab()  # a2l -> ranges
            from textual.widgets import TextArea

            window.query_one("#sje_manual", TextArea).text = "0x00008000-0x0000800F"
            window.action_cycle_tab()  # ranges -> manual (parses the box)
            await _pause(pilot)
            mrows = window._rows()
            assert len(mrows) == 1 and mrows[0].base == 0x8000
            window._sel["manual"] = {0}
            window._sync()  # direct state set: re-plan before reading
            plan = window._plan(mrows)
            assert plan.files[0].empty and plan.empty_files == 1
            await _pause(pilot)  # the wrap unhid: let the layout tick repaint
            gantt_plain = str(app.query_one("#sje_files").render())
            assert "∅ empty — 0 B of source in span" in gantt_plain

            dest = _splits_dir(app)
            # The TextArea holds focus on the manual tab (a printable key is
            # text there — the export rides the action, the same handler
            # the ^E binding dispatches).
            window.action_export()
            await _pause(pilot)
            armed = window._armed
            wrote_armed = list(dest.iterdir()) if dest.exists() else []
            window.action_export()
            await _pause(pilot)
            wrote = sorted(p.name for p in dest.iterdir()) if dest.exists() else []
            blob = (
                (dest / "toy_locality_00.bin").read_bytes()
                if (dest / "toy_locality_00.bin").exists()
                else None
            )
            sidecar = (
                (dest / "toy_locality_00.addr").read_text(encoding="ascii")
                if (dest / "toy_locality_00.addr").exists()
                else None
            )
            return {
                "armed": armed,
                "wrote_armed": wrote_armed,
                "wrote": wrote,
                "blob": blob,
                "sidecar": sidecar,
            }

    observed = asyncio.run(_drive())
    assert observed["armed"] is True, "the empty file's export requires a confirm"
    assert observed["wrote_armed"] == [], "no silent empty export"
    assert observed["wrote"] == ["toy_locality_00.addr", "toy_locality_00.bin"]
    assert observed["blob"] == b"", "BIN: 0 bytes"
    assert observed["sidecar"] == "0x00008000\n", "the sidecar still carries the base"


# ---------------------------------------------------------------------------
# LLR-136.5 — naming, destination and the live sample
# ---------------------------------------------------------------------------


def test_naming_resolves_all_token_limbs_and_sample_follows_format(tmp_path: Path) -> None:
    """LLR-136.5: the resolver maps the three tokens for every mode/format
    limb (split → ‹stem›_‹segment›.‹ext›; join → ‹stem›_joined.‹ext›) and
    the sample updates live with the format — a stale sample reddens."""
    assert resolve_sample("prg", "range_00", "s19", "‹stem›_‹segment›") == "prg_range_00.s19"
    assert resolve_sample("prg", "joined", "hex", "‹stem›_‹segment›") == "prg_joined.hex"
    assert resolve_sample("prg", "joined", "bin", "‹stem›_‹segment›") == "prg_joined.bin"
    assert resolve_sample("fw", "locality_00", "s19", "‹stem›_‹segment›") == "fw_locality_00.s19"

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded()
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = {0}
            window._sync()  # direct state set: re-plan before reading
            sample_s19 = window._sample(window._rows())
            chip_s19 = str(app.query_one("#sje_naming").render())
            await pilot.press("f")  # s19 -> hex
            await _pause(pilot)
            sample_hex = window._sample(window._rows())
            chip_hex = str(app.query_one("#sje_naming").render())
            return {
                "s19": sample_s19,
                "hex": sample_hex,
                "chip_s19": chip_s19,
                "chip_hex": chip_hex,
            }

    observed = asyncio.run(_drive())
    assert observed["s19"] == "prg_range_00.s19"
    assert observed["hex"] == "prg_range_00.hex", (
        "the sample tracks the format change live (0 stale samples)"
    )
    # The chip shows the pattern + the resolved sample at its measured width
    # (the house `_fit` clamp may shorten the sample's TAIL at narrow
    # widths, never substitute another name).
    assert "‹stem›_‹segment›" in observed["chip_s19"]
    assert "‹stem›_‹segment›" in observed["chip_hex"]


def test_destination_follows_the_change1_scoped_homes(tmp_path: Path) -> None:
    """LLR-136.5: the destination follows the change-1 homes — project
    ``splits/`` (containment-checked) with a project, the COMMON
    ``workarea/splits/`` without one."""
    # No project: COMMON.
    async def _drive_common() -> List[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded()
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = {0}
            window._fmt = "bin"
            await pilot.press("e")
            await _pause(pilot)
            return [str(p) for p in _splits_dir(app).iterdir()]

    common_files = asyncio.run(_drive_common())
    assert common_files and all(str(tmp_path) in f for f in common_files)

    # Project: the project splits/ home.
    async def _drive_project() -> Tuple[List[str], str]:
        app = S19TuiApp(base_dir=tmp_path / "projmode")
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            project_dir = app.workarea / "proj1"
            project_dir.mkdir(parents=True, exist_ok=True)
            app.current_project = "proj1"
            app.update_project_labels()
            app.current_file = _demo_loaded()
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = {0}
            window._fmt = "bin"
            await pilot.press("e")
            await _pause(pilot)
            home = project_dir / "splits"
            return ([str(p) for p in home.iterdir()], str(home))

    project_files, home = asyncio.run(_drive_project())
    assert home.endswith(str(Path("proj1") / "splits"))
    assert project_files and all(home in f for f in project_files)


# ---------------------------------------------------------------------------
# LLR-135.7 — the manual parser and the three sources
# ---------------------------------------------------------------------------


def test_manual_parser_tolerant_forms_and_inclusive_end() -> None:
    """LLR-135.7: one range per line, hex, INCLUSIVE end — the typed end IS
    the last byte (size = hi - lo + 1, the ±1 trap) — tolerating spaces,
    uppercase 0X and bare hex; unparsable lines are dropped AND named."""
    text = "\n".join(
        [
            "0x0000EB00-0x0000EBFF",   # canonical
            "  0X1000 - 0X100F  ",      # spaces + uppercase 0X
            "2000-200F",               # bare hex
            "0x3000 - 0x3000",         # single byte, inclusive end
            "garbage line",            # dropped + named
            "0x4000",                  # no dash: dropped + named
            "0x5000-0x4FFF",           # inverted: dropped + named
        ]
    )
    rows, dropped = parse_manual(text)
    assert [(r.base, r.size) for r in rows] == [
        (0xEB00, 0x100),
        (0x1000, 0x10),
        (0x2000, 0x10),
        (0x3000, 0x1),
    ], "the inclusive end: 0x3000-0x3000 is ONE byte, not zero, not an error"
    assert dropped == ["garbage line", "0x4000", "0x5000-0x4FFF"]


def test_a2l_tab_without_a2l_renders_the_neutral_note_and_stays_clickable(
    tmp_path: Path,
) -> None:
    """LLR-135.7: with no A2L loaded the A2L tab renders the neutral note
    ``no A2L loaded — load one (^L) or use ranges/manual`` and stays
    focusable — never silently disabled."""

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded()  # no A2L
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window.action_cycle_tab()  # ranges -> manual
            window.action_cycle_tab()  # manual -> a2l
            await _pause(pilot)
            from textual.widgets import Static

            table = window.query_one("#sje_table", _SegTable)
            body = str(table.query_one(Static).render())
            tabs = str(app.query_one("#sje_tabs").render())
            return {"body": body, "tabs": tabs}

    observed = asyncio.run(_drive())
    assert NO_A2L_NOTE in observed["body"]
    assert "a2l(0)" in observed["tabs"]


def test_default_tab_is_ranges_with_and_without_an_a2l(tmp_path: Path) -> None:
    """LLR-135.7: the ranges source is the default tab at every entry path
    (ranges are always available and never empty with an image loaded)."""

    async def _drive(a2l: bool) -> str:
        app = S19TuiApp(base_dir=tmp_path / f"u{'a' if a2l else 'b'}")
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded(a2l=a2l)
            await _pause(pilot)
            window = await _open_window(app, pilot)
            return window._tab

    assert asyncio.run(_drive(False)) == "ranges"
    assert asyncio.run(_drive(True)) == "ranges"


# ---------------------------------------------------------------------------
# Export formats — byte-level, both modes (LLR-136 / LLR-137.2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["s19", "hex", "bin"])
def test_export_formats_split_byte_level(tmp_path: Path, fmt: str) -> None:
    """Split writes one file per range in S19/HEX/BIN and the bytes match
    the plan exactly (S19/HEX re-parsed through the shipped oracles; BIN is
    flat with the .addr sidecar)."""
    rows = [SegRow("isle", "manual", 0x1000, 0x28)]
    written = write_split_join_export(
        SPARSE_MAP, rows, mode="split", gap="fill", pad_byte=0x5A,
        fmt=fmt, stem="t", dest_dir=tmp_path,
    )
    assert len(written) == 1
    if fmt == "bin":
        assert written[0].read_bytes()[:8] == bytes(ISLAND_A.values())
        assert (tmp_path / "t_isle.addr").read_text(encoding="ascii") == "0x00001000\n"
        return
    expected = {a: 0x5A for a in range(0x1000, 0x1028)}
    expected.update(SPARSE_MAP)
    oracle = _reparsed_s19_map if fmt == "s19" else _reparsed_hex_map
    assert oracle(written[0]) == expected


@pytest.mark.parametrize("fmt", ["s19", "hex", "bin"])
@pytest.mark.parametrize("gap", ["concat", "fill"])
def test_export_formats_join_byte_level(tmp_path: Path, fmt: str, gap: str) -> None:
    """Join writes ONE ``‹stem›_joined.‹ext›`` in both gap policies; the
    bytes re-parse to the engine's own output for the same plan (0 drift —
    the view rides the engine)."""
    rows = [SegRow("a", "manual", 0x1000, 8), SegRow("b", "manual", 0x1020, 8)]
    written = write_split_join_export(
        SPARSE_MAP, rows, mode="join", gap=gap, pad_byte=0x00,
        fmt=fmt, stem="t", dest_dir=tmp_path,
    )
    assert [p.name for p in written] == [f"t_joined.{fmt}"]
    if gap == "concat":
        engine_map, engine_ranges = join_concat(SPARSE_MAP, [(0x1000, 0x1008), (0x1020, 0x1028)])
    else:
        engine_map, engine_ranges = join_fill(SPARSE_MAP, [(0x1000, 0x1008), (0x1020, 0x1028)], 0x00)
    if fmt == "bin":
        assert written[0].read_bytes() == bytes(
            engine_map[a] for a in range(engine_ranges[0][0], engine_ranges[0][1])
        )
        assert (tmp_path / "t_joined.addr").read_text(encoding="ascii") == "0x00001000\n"
        return
    oracle = _reparsed_s19_map if fmt == "s19" else _reparsed_hex_map
    assert oracle(written[0]) == engine_map


# ---------------------------------------------------------------------------
# TC-710 — split from each of the three sources (LLR-135.7 + LLR-136.5)
# ---------------------------------------------------------------------------


def test_tc710_split_from_each_source_naming(tmp_path: Path) -> None:
    """TC-710 (RED pre-change — no screen, no files): split from EACH of
    the three segment sources writes one file per selected range named
    ``‹stem›_‹segment›.‹ext›`` — A2L MEMORY_SEGMENT rows / the image's own
    contiguous ranges / manual localities — byte-matching the source."""
    dest_by_source: Dict[str, List[str]] = {}

    async def _drive_ranges() -> List[str]:
        app = S19TuiApp(base_dir=tmp_path / "r")
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded()
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = {0, 5}
            window._fmt = "bin"
            await pilot.press("e")
            await _pause(pilot)
            return sorted(p.name for p in _splits_dir(app).iterdir())

    async def _drive_manual() -> List[str]:
        app = S19TuiApp(base_dir=tmp_path / "m")
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded()
            await _pause(pilot)
            window = await _open_window(app, pilot)
            from textual.widgets import TextArea

            window.query_one("#sje_manual", TextArea).text = (
                "0x000017E0-0x000017FF\n0x0000FCB0-0x0000FCFF"
            )
            window.action_cycle_tab()  # ranges -> manual
            await _pause(pilot)
            window.action_select_all()
            window._fmt = "bin"
            # The TextArea holds focus here — a printable key would be text,
            # so the export rides the action (the ^E binding's handler).
            window.action_export()
            await _pause(pilot)
            return sorted(p.name for p in _splits_dir(app).iterdir())

    async def _drive_a2l() -> List[str]:
        app = S19TuiApp(base_dir=tmp_path / "a")
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            # One segment overlapping the image's dense range so the file
            # is non-empty; two more stay zero-coverage behind the confirm.
            sections = [
                {
                    "name": "MEMORY_SEGMENT",
                    "meta": "'PrgCode'",
                    "lines": ["CODE FLASH 0x0 0x0000EB00 0x1000 0x0"],
                    "children": [],
                }
            ]
            loaded = _demo_loaded()
            loaded.a2l_data = {"sections": sections}
            app.current_file = loaded
            app.current_a2l_data = loaded.a2l_data
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window.action_cycle_tab()  # ranges -> manual
            window.action_cycle_tab()  # manual -> a2l
            await _pause(pilot)
            window.action_select_all()
            window._fmt = "bin"
            await pilot.press("e")  # no gate: one non-empty segment
            await _pause(pilot)
            return sorted(p.name for p in _splits_dir(app).iterdir())

    dest_by_source["ranges"] = asyncio.run(_drive_ranges())
    dest_by_source["manual"] = asyncio.run(_drive_manual())
    dest_by_source["a2l"] = asyncio.run(_drive_a2l())

    assert dest_by_source["ranges"] == [
        "prg_range_00.addr",
        "prg_range_00.bin",
        "prg_range_05.addr",
        "prg_range_05.bin",
    ], dest_by_source["ranges"]
    assert dest_by_source["manual"] == [
        "prg_locality_00.addr",
        "prg_locality_00.bin",
        "prg_locality_01.addr",
        "prg_locality_01.bin",
    ], dest_by_source["manual"]
    # The A2L row name carries the quoted long identifier verbatim (the
    # hardened extractor's block_name).
    assert dest_by_source["a2l"] == ["prg_'PrgCode'.addr", "prg_'PrgCode'.bin"], (
        dest_by_source["a2l"]
    )

    # Byte-match: the ranges-source split file re-parses to the source bytes.
    blob = (tmp_path / "r" / ".s19tool" / "workarea" / "splits" / "prg_range_00.bin").read_bytes()
    s19 = S19File(str(EXAMPLE_PRG))
    start, _end = s19.get_memory_ranges()[0]
    assert blob == bytes(s19.get_memory_map()[start + i] for i in range(len(blob)))


# ---------------------------------------------------------------------------
# TC-710 — the graft chassis (LLR-135.1)
# ---------------------------------------------------------------------------


def test_tc710_chassis_dom_order_and_preview_pane(tmp_path: Path) -> None:
    """TC-710 (RED pre-change — no screen): the graft chassis composes the
    contracted surfaces in the contracted order — left: SEGMENTS chips, the
    range table, MODE / GAPS+PAD / FORMAT / DEST / NAMING; right: the
    output label, the union band, the gantt wrap, the legend, the ruler,
    the stats, the summary, EXPORT — inside the `` PREVIEW `` .db-pane."""
    expected_left = [
        "sje_tabs",
        "sje_table",
        "sje_manual",
        "sje_mode",
        "sje_gap",
        "sje_fmt",
        "sje_dest",
        "sje_naming",
    ]
    expected_right = [
        "sje_outlabel",
        "sje_band",
        "sje_files_wrap",
        "sje_legend",
        "sje_ruler",
        "sje_stats",
        "sje_summary",
        "sje_export",
    ]

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            window = await _open_window(app, pilot)
            left_ids = [w.id for w in window.query_one("#sje_left").children]
            right_ids = [w.id for w in window.query_one("#sje_right").children]
            pane = window.query_one("#sje_right", Vertical)
            return {
                "left": left_ids,
                "right": right_ids,
                "border_title": pane.border_title,
                "pane_classes": sorted(pane.classes),
            }

    observed = asyncio.run(_drive())
    assert observed["left"] == expected_left, observed["left"]
    assert observed["right"] == expected_right, observed["right"]
    assert observed["border_title"] == " PREVIEW "
    assert "db-pane" in observed["pane_classes"]


def test_title_row_carries_help_chip_but_no_folder_chip(tmp_path: Path) -> None:
    """HLR-139 contracts exactly four 📂 chips — this window's title row
    seats title + `?` usage-help chip ONLY (the ninth authored section's
    seat, never displacing a folder chip)."""
    from s19_app.tui.open_folder_chip import OpenFolderChip

    async def _drive() -> List[Optional[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            window = await _open_window(app, pilot)
            row = window.query_one(f".{HEADER_ROW_CLASS}", Horizontal)
            return [getattr(child, "id", None) for child in row.children]

    ids = asyncio.run(_drive())
    assert ids == [None, "window_help_split_join_export"], ids
    # And no OpenFolderChip anywhere under the window.
    async def _no_chip() -> int:
        app = S19TuiApp(base_dir=tmp_path / "n")
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            window = await _open_window(app, pilot)
            return len(window.query(OpenFolderChip))

    assert asyncio.run(_no_chip()) == 0


def test_help_chip_and_focused_question_mark_open_the_authored_section(
    tmp_path: Path,
) -> None:
    """The ninth seat rides the inc-003c seam with zero new plumbing: the
    chip press AND the focused-`?` binding both push the split_join_export
    section; Esc dismisses."""
    from s19_app.tui.window_help import WindowHelpScreen

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window.query_one("#window_help_split_join_export", WindowHelpChip).press()
            await _pause(pilot)
            via_chip = isinstance(app.screen, WindowHelpScreen)
            section = getattr(app.screen, "section_key", None)
            await pilot.press("escape")
            await _pause(pilot)
            window.query_one("#sje_table", _SegTable).focus()
            await pilot.pause()
            await pilot.press("question_mark")
            await _pause(pilot)
            via_key = isinstance(app.screen, WindowHelpScreen)
            await pilot.press("escape")
            await _pause(pilot)
            dismissed = not isinstance(app.screen, WindowHelpScreen)
            return {
                "via_chip": via_chip,
                "section": section,
                "via_key": via_key,
                "dismissed": dismissed,
            }

    observed = asyncio.run(_drive())
    assert observed["via_chip"] and observed["section"] == "split_join_export"
    assert observed["via_key"]
    assert observed["dismissed"]


# ---------------------------------------------------------------------------
# TC-710 / LLR-135.6 — palette-first, no rail key, Esc closes
# ---------------------------------------------------------------------------


def test_tc710_palette_entry_no_rail_key_esc_close(tmp_path: Path) -> None:
    """TC-710 (RED pre-change — no screen): the ^K palette lists EXACTLY
    ONE entry reaching the screen, named "Split / Join / Export"; ZERO rail
    bindings were added to the shipped 1-9/0 set; Esc closes 1/1 from the
    table AND from the preview pane."""
    from s19_app.tui.command_bar import CommandBar
    from s19_app.tui.rail import RAIL_ENTRIES

    # The entry exists exactly once in the app's palette list.
    entries = [
        label for label, _action in S19TuiApp.EXTRA_PALETTE_ENTRIES
    ]
    assert entries.count("Split / Join / Export") == 1
    # No rail key: the rail still carries exactly the ten shipped screens
    # and none of them routes here.
    assert len(RAIL_ENTRIES) == 10
    assert all(entry.key != "split_join" for entry in RAIL_ENTRIES)
    assert "split_join" not in S19TuiApp.SCREEN_CONTAINER_IDS
    for binding in S19TuiApp.BINDINGS:
        action = binding.action if isinstance(binding, Binding) else binding[1]
        assert "split_join" not in action

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            bar = app.query_one(CommandBar)
            matches = [
                entry.label
                for entry in bar._palette_entries
                if "split" in entry.label.lower() and "join" in entry.label.lower()
            ]
            window = await _open_window(app, pilot)

            # Esc from the table.
            window.query_one("#sje_table", _SegTable).focus()
            await pilot.pause()
            await pilot.press("escape")
            await _pause(pilot)
            closed_from_table = "hidden" in window.classes

            # Reopen, Esc from the preview pane (band static).
            app.action_open_split_join_export()
            await _pause(pilot)
            window.query_one("#sje_band").focus()
            await pilot.pause()
            await pilot.press("escape")
            await _pause(pilot)
            closed_from_pane = "hidden" in window.classes
            return {
                "matches": matches,
                "closed_from_table": closed_from_table,
                "closed_from_pane": closed_from_pane,
            }

    observed = asyncio.run(_drive())
    assert observed["matches"] == ["Split / Join / Export"], observed["matches"]
    assert observed["closed_from_table"] is True
    assert observed["closed_from_pane"] is True


def test_opening_the_window_hides_the_rail_screens_and_returns_on_esc(
    tmp_path: Path,
) -> None:
    """The window rides the rail BODY like the other screens: opening hides
    all ten rail containers; Esc restores the previously active rail
    screen; a rail key while open closes the window too."""

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.action_show_screen("map")
            await _pause(pilot)
            window = await _open_window(app, pilot)
            rail_hidden = all(
                "hidden" in app.query_one(f"#{cid}").classes
                for cid in app.SCREEN_CONTAINER_IDS.values()
            )
            # A rail key closes the palette-first window.
            await pilot.press("1")
            await _pause(pilot)
            closed_by_rail_key = "hidden" in window.classes
            workspace_back = "hidden" not in app.query_one(
                "#screen_workspace"
            ).classes
            # Reopen from the map and Esc back to the MAP (not workspace).
            app.action_show_screen("map")
            await _pause(pilot)
            app.action_open_split_join_export()
            await _pause(pilot)
            await pilot.press("escape")
            await _pause(pilot)
            map_back = "hidden" not in app.query_one("#screen_map").classes
            return {
                "rail_hidden": rail_hidden,
                "closed_by_rail_key": closed_by_rail_key,
                "workspace_back": workspace_back,
                "map_back": map_back,
            }

    observed = asyncio.run(_drive())
    assert observed["rail_hidden"] is True
    assert observed["closed_by_rail_key"] is True
    assert observed["workspace_back"] is True
    assert observed["map_back"] is True, "Esc returns to the screen it replaced"


# ---------------------------------------------------------------------------
# LLR-135.3 — the two-regime reflow pilot
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "size, pane, band, regime",
    [
        ((160, 48), 58, 54, "wide"),
        ((120, 36), 58, 54, "wide"),
        ((102, 30), 40, 36, "mid"),
        ((80, 24), 30, 26, "narrow"),
    ],
)
def test_two_regime_reflow_at_the_measured_thresholds(
    tmp_path: Path, size, pane, band, regime
) -> None:
    """LLR-135.3: the regime decision reads the MEASURED screen width —
    pane 58/band 54 at >= 118 (the run_test "120x36" hands the app
    118x34), the base 40 between, 30 at < 100; the gantt hides below 100.
    0 regime mismatches across the pilot."""
    app_dir = tmp_path / f"{size[0]}x{size[1]}"

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=app_dir)
        async with app.run_test(size=size) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded()
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = {0, 1, 2}
            window._mode = "split"
            window._gap = "fill"
            window._sync()  # direct state set: re-plan before measuring
            await _pause(pilot)
            right = window.query_one("#sje_right", Vertical)
            band_bar = window.query_one("#sje_band")
            wrap = window.query_one("#sje_files_wrap")
            gantt_hidden = ("hidden" in wrap.classes) or (wrap.display is False)
            return {
                "pane": right.region.width,
                "band": band_bar.content_size.width,
                "narrow": window.has_class("narrow"),
                "wide": window.has_class("wide"),
                "gantt_hidden": gantt_hidden,
            }

    observed = asyncio.run(_drive())
    assert observed["pane"] == pane, (size, observed)
    assert observed["band"] == band, (size, observed)
    assert observed["narrow"] == (regime == "narrow")
    assert observed["wide"] == (regime == "wide")
    # The split gantt (3 files, inside the cap) hides only below 100.
    assert observed["gantt_hidden"] == (regime == "narrow")


# ---------------------------------------------------------------------------
# LLR-135.4 — the split-mode per-file gantt
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("n_files", [1, 2, 6, 7])
def test_gantt_visible_exactly_for_split_with_one_to_six_files(
    tmp_path: Path, n_files: int
) -> None:
    """LLR-135.4: the gantt renders exactly when (split ∧ 1 <= files <= 6);
    at 7 files the union map carries the story alone."""
    app_dir = tmp_path / f"n{n_files}"

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=app_dir)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded()
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = set(range(n_files))
            window._mode = "split"
            window._gap = "fill"
            window._sync()  # direct state set: re-plan before measuring
            await _pause(pilot)
            hidden = "hidden" in window.query_one("#sje_files_wrap").classes
            rows = len(str(window.query_one("#sje_files").render()).splitlines())
            return {"hidden": hidden, "rows": rows}

    observed = asyncio.run(_drive())
    if 1 <= n_files <= GANTT_CAP:
        assert not observed["hidden"]
        assert observed["rows"] == n_files, "one gantt row per output file"
    else:
        assert observed["hidden"], "the 7th file hides the gantt (cap 6)"


def test_gantt_hidden_in_join_mode(tmp_path: Path) -> None:
    """LLR-135.4 negative control: a gantt rendering in join mode reddens."""
    app_dir = tmp_path / "join"

    async def _drive() -> bool:
        app = S19TuiApp(base_dir=app_dir)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded()
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = {0, 1}
            window.action_toggle_mode()  # join
            await _pause(pilot)
            return "hidden" in window.query_one("#sje_files_wrap").classes

    assert asyncio.run(_drive()) is True


def test_gantt_empty_file_row() -> None:
    """LLR-135.4 boundary: an empty file renders its
    ``∅ empty — 0 B of source in span`` row."""
    from s19_app.tui.segment_split_view import Block, OutFile, Plan

    plan = Plan(
        files=[
            OutFile("t_a.bin", [Block("data", 4)], 4, 0, 0, False),
            OutFile("t_b.bin", [], 0, 8, 0, True),
        ],
        map_blocks=[],
        band_lo=0,
        band_hi=1,
        packed=4,
        span=1,
        fill=0,
        conflicts=0,
        empty_files=1,
        address_preserving=True,
        nothing_selected=False,
        guard=False,
    )
    text = gantt_text(plan, 54)
    assert "∅ empty — 0 B of source in span" in text.plain
    assert "t_a.bin" in text.plain and "t_b.bin" in text.plain


# ---------------------------------------------------------------------------
# TC-709 / HLR-135 — the wrap audit over the new screen
# ---------------------------------------------------------------------------


def _audit_widget(widget) -> List[Tuple[str, str, int, int]]:
    """The no-wrap law for one widget: every authored line fits its width."""
    try:
        plain = widget.render().plain
    except Exception:
        return []
    width = widget.region.width
    defects = []
    for line in plain.splitlines() or [""]:
        cells = cell_len(line)
        if cells > width:
            ident = f"#{widget.id}" if widget.id else type(widget).__name__
            defects.append((ident, line, cells, width))
    return defects


def _audit_window(window: SplitJoinWindow) -> List[Tuple[str, str, int, int]]:
    defects: List[Tuple[str, str, int, int]] = []
    for widget in window.query(Static):
        if widget.region.height <= 0 or widget.region.width <= 0:
            continue
        defects.extend(_audit_widget(widget))
    return defects


_STATES = ("split_fill", "join_conflict", "guard")


async def _drive_state(app: S19TuiApp, pilot, state: str) -> None:
    loaded = _demo_loaded(a2l=(state == "guard"))
    app.current_file = loaded
    if loaded.a2l_data is not None:
        # The real load pipeline installs the parsed A2L on BOTH seats —
        # the window reads the canonical ``current_a2l_data`` (P-16).
        app.current_a2l_data = loaded.a2l_data
    await _pause(pilot)
    window = await _open_window(app, pilot)
    if state == "split_fill":
        window._sel["ranges"] = {0, 1, 2, 5}
        window._mode = "split"
        window._gap = "fill"
        window._sync()  # direct state set: re-plan before the audit
    elif state == "join_conflict":
        window._sel["ranges"] = {0, 1, 2, 5, 6, 7}
        window.action_toggle_mode()
        window.action_cycle_gap()
    else:  # guard
        window.action_cycle_tab()
        window.action_cycle_tab()
        window.action_select_all()
        window.action_toggle_mode()
        window.action_cycle_gap()
    await _pause(pilot)


@pytest.mark.parametrize("size", [(120, 36), (80, 24)])
@pytest.mark.parametrize("state", _STATES)
def test_tc709_wrap_audit_zero_overflows_both_geometries(
    tmp_path: Path, size, state
) -> None:
    """TC-709 (the batch-93 wrap-audit idiom over the new screen): at
    118x34 and 80x24, in the split-fill / join-conflict / guard states,
    EVERY authored line of every painted surface fits its widget's measured
    width — 0 defects."""
    app_dir = tmp_path / f"{size[0]}x{size[1]}-{state}"

    async def _drive() -> List[Tuple[str, str, int, int]]:
        app = S19TuiApp(base_dir=app_dir)
        async with app.run_test(size=size) as pilot:
            await _pause(pilot)
            await _drive_state(app, pilot, state)
            window = app.query_one("#screen_split_join", SplitJoinWindow)
            return _audit_window(window)

    defects = asyncio.run(_drive())
    assert not defects, (
        f"{size} {state}: the wrap audit found {len(defects)} overflowing "
        f"line(s):\n" + "\n".join(f"  {d}" for d in defects[:10])
    )


def test_tc709_wrap_audit_overlong_injection_reddens(tmp_path: Path) -> None:
    """TC-709 (C-43: an audit that cannot fail proves nothing): an injected
    over-long line through the public update() seam reddens the SAME audit
    at both geometries; removing it returns green."""
    app_dir = tmp_path / "inject"

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=app_dir)
        async with app.run_test(size=(120, 36)) as pilot:
            await _pause(pilot)
            await _drive_state(app, pilot, "split_fill")
            window = app.query_one("#screen_split_join", SplitJoinWindow)
            clean = len(_audit_window(window))
            app.query_one("#sje_summary", Static).update("X" * 400)
            injected = len(_audit_window(window))
            app.query_one("#sje_summary", Static).update("ok")
            await pilot.pause()
            restored = len(_audit_window(window))
            return {"clean": clean, "injected": injected, "restored": restored}

    observed = asyncio.run(_drive())
    assert observed["clean"] == 0
    assert observed["injected"] >= 1, "the injected over-long line must redden"
    assert observed["restored"] == 0


# ---------------------------------------------------------------------------
# HLR-135 numeric pass threshold — the four class hexes in the rendered frame
# ---------------------------------------------------------------------------


def test_visor_four_class_hexes_render_in_the_frame(tmp_path: Path) -> None:
    """HLR-135: at the 80x24 floor every one of the four visor class hexes
    is present in the RENDERED frame (the shot path runs color-sanitized —
    the grey-frames incident)."""
    _fix_color_env()
    app_dir = tmp_path / "hexes"

    async def _drive() -> str:
        app = S19TuiApp(base_dir=app_dir)
        async with app.run_test(size=(80, 24)) as pilot:
            await _pause(pilot)
            app.current_file = _demo_loaded()
            await _pause(pilot)
            window = await _open_window(app, pilot)
            window._sel["ranges"] = {0, 1, 2, 5, 6, 7}
            window.action_toggle_mode()
            window.action_cycle_gap()
            await _pause(pilot)
            return app.export_screenshot()

    svg = asyncio.run(_drive())  # export_screenshot() RETURNS the SVG text
    for hex_ in ("#91abec", "#6b7280", "#f6ff8f", "#46557a"):
        assert hex_ in svg, f"the rendered frame must carry {hex_}"
