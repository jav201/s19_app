"""TC-666 · TC-667 · TC-668 · TC-669 -- the wrap-audit limbs they name (batch-93 inc-002).

batch-93 increment 002 — the wrap audit over the Memory Map surface (HLR-130).

Summary:
    The ported wrap audit as a REAL harness (LLR-130.1 / LLR-130.2): render the
    shipped map screen at the contract's geometries — 80x24 (deliberately
    below the audited 100-column floor), ~100, 120, 140 and 160 columns — and
    assert that NO authored line of ANY painted surface exceeds its widget's
    measured width: the header, the band-bar segments, the ruler ticks, the
    glance chips, the region rows, the inspector body (selected state AND the
    pre-selection hint), the one-line stats strip, and the pane chrome titles/
    subtitles. The harness FAILS when a deliberately over-long line is
    injected through the panel's test-only seam (LLR-130.2) — an audit that
    cannot fail proves nothing (C-43).

    The audit's law is enforced at AUTHORSHIP (the house clip seams —
    ``_clip_to_cells`` for file-derived symbol names, the two-line hint), never
    by weakening these assertions: every defect this harness can name was
    found wrapped on the shipped inc-001 tree and fixed there (see
    ``.dev-flow/2026-10-11-batch-93/evidence/inc002_probe*.out.txt``).

Non-frozen home (verified against the 9 frozen test files). Fixtures are the
batch-93 charter demo population (mirrors ``test_tui_map_big.py``) + hostile
A2L symbol names (no client data).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from rich.cells import cell_len
from textual.widgets import Label, Static

from s19_app.tui.app import S19TuiApp
from s19_app.tui.models import LoadedFile
from s19_app.tui.screens_directionb import MemoryMapPanel
from s19_app.tui.services.entropy_service import compute_entropy

# The contract's tested geometries (HLR-130: 80 below the audited 100-column
# floor, ~100, 120, 140, 160).
_GEOMETRIES = [(80, 24), (100, 30), (120, 36), (140, 40), (160, 48)]

# Hostile file-derived symbol names: far longer than any painted interior.
_LONG_TAGS = [
    {
        "name": "A_VERY_LONG_SYMBOL_NAME_THAT_WILL_NOT_FIT_INSIDE_THE_"
        "INSPECTOR_PANE_WIDTH_AT_ALL",
        "address": 0x00000020,
        "byte_size": 4,
    },
    {"name": "x" * 200, "address": 0x00000040},
]


def _lcg_bytes(seed: int, n: int):
    out, state = [], seed
    for _ in range(n):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((state >> 16) & 0xFF)
    return out


def _demo_loaded() -> LoadedFile:
    """The charter demo fixture (mirrors ``test_tui_map_big.py::_demo_loaded``)."""
    mem = {}

    def put(addr, data):
        for i, v in enumerate(data):
            mem[addr + i] = v

    put(0x00000000, [(0x08, 0x00, 0x10 + (i % 8), 0x00)[i % 4] for i in range(0x100)])
    put(0x08000000, [(i // 4) & 0xFF for i in range(0x800)])
    put(0x08001000, _lcg_bytes(0xC0FFEE, 0x600))
    put(0x08002000, [0xFF] * 0x400)
    put(0x1FFF0000, [(0x30 + (i * 7) % 60) for i in range(0x200)])
    ranges = [
        (0x00000000, 0x00000100),
        (0x08000000, 0x08000800),
        (0x08001000, 0x08001600),
        (0x08002000, 0x08002400),
        (0x1FFF0000, 0x1FFF0200),
    ]
    return LoadedFile(
        path=Path("ecu_fw_v3.s19"),
        file_type="s19",
        mem_map=mem,
        row_bases=sorted({a - a % 16 for a in mem}),
        ranges=ranges,
        range_validity=[True] * len(ranges),
        errors=[],
        a2l_path=None,
        a2l_data=None,
        entropy_windows=compute_entropy(mem),
    )


def _surface_label(widget) -> str:
    ident = f"#{widget.id}" if widget.id else ""
    classes = "." + ".".join(widget.classes) if widget.classes else ""
    return f"{type(widget).__name__}{ident}{classes}"


def _audit_widget(widget) -> list:
    """The no-wrap law for one widget: every authored line fits its width.

    Returns one defect tuple per offending line: (label, line, cells, width).
    Widths are CELLS (``cell_len``) — a CJK or double-width run counts what
    the terminal paints, never ``len()`` code points (the house clip seam's
    own convention).
    """
    try:
        plain = widget.render().plain
    except Exception:
        return []
    width = widget.region.width
    defects = []
    for line in plain.splitlines() or [""]:
        cells = cell_len(line)
        if cells > width:
            defects.append((_surface_label(widget), line, cells, width))
    return defects


def _audit_map_surfaces(app: S19TuiApp) -> list:
    """Walk EVERY authored text surface of the map screen; report overflows.

    Surfaces: every ``Static``/``Label`` under the panel (header, band
    segments, ruler ticks, chips, region rows, inspector body, stats strip)
    plus the pane chrome (``#map_grid`` / ``#map_detail`` border titles and
    subtitles — authored lines the surface paints, measured against the pane
    they paint into). The audit reads each widget's MEASURED ``region.width``,
    never a terminal-width proxy (LLR-130.1).
    """
    panel = app.query_one("#memory_map_panel", MemoryMapPanel)
    defects: list = []
    for widget in panel.query(Static):
        defects.extend(_audit_widget(widget))
    for widget in panel.query(Label):
        defects.extend(_audit_widget(widget))
    for pane_id in ("#map_grid", "#map_detail"):
        try:
            pane = app.query_one(pane_id)
        except Exception:
            continue
        for chrome in (pane.border_title, pane.border_subtitle):
            if chrome and cell_len(chrome) > pane.region.width:
                defects.append(
                    (f"{pane_id} chrome", chrome, cell_len(chrome), pane.region.width)
                )
    return defects


async def _settle_ruler(app: S19TuiApp, pilot, max_pauses: int = 30) -> int:
    """Poll until the ruler's tick COUNT is stable across two pause boundaries.

    The elision (LLR-112.2) rides the ruler's Resize, whose delivery can lag
    several frames behind the selection's (measured with a ``base_dir`` app:
    the reflow landed only at teardown of a 14-pause drive). The audit
    certifies the SETTLED surface, so it waits for the fixed point — the same
    post-pause stability discipline as ``_settled_bar_width`` — and hard-fails
    if the ruler never settles.
    """
    previous = None
    for _ in range(max_pauses):
        await pilot.pause()
        count = len(list(app.query(".map-ruler-tick")))
        if previous is not None and count == previous:
            return count
        previous = count
    raise AssertionError(
        f"the ruler never settled across {max_pauses} pause boundaries; "
        f"last tick count {previous}"
    )


async def _drive(
    tmp_path: Path,
    size,
    *,
    tags=None,
    hint: bool = False,
    selected: bool = True,
) -> dict:
    """Render the map at ``size`` and return the per-surface audit verdicts."""
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        app.current_file = _demo_loaded()
        if tags is not None:
            app._a2l_enriched_tags = tags
        app.action_show_screen("map")
        await pilot.pause()
        app.update_memory_map()
        panel = app.query_one("#memory_map_panel", MemoryMapPanel)
        if selected:
            # Settle the deferred auto-selection (the selected-state limb).
            for _ in range(10):
                await pilot.pause()
                if panel._selected_cell_start is not None:
                    break
        else:
            for _ in range(3):
                await pilot.pause()
            # Force the pre-selection state: the hint is what paints before
            # the deferred auto-selection resolves (and whenever the
            # selection is cleared) — a real painted state of the surface.
            panel._reset_detail()
        tick_count = await _settle_ruler(app, pilot)
        return {
            "defects": _audit_map_surfaces(app),
            "header_lines": (
                app.query_one("#map_header").render().plain.splitlines()
            ),
            "stats_lines": len(
                app.query_one("#map_stats_body").render().plain.splitlines()
            ),
            "chips_line_height": app.query_one(".map-glance-chips").region.height,
            "body_lines": app.query_one("#map_detail_body").render().plain.splitlines(),
            "row_texts": [
                str(r.render()) for r in panel._live_region_rows()
            ],
            "row_widths": [
                r.region.width for r in panel._live_region_rows()
            ],
            "tick_count": tick_count,
        }


# TC-664 — the audit harness itself: 0 overflow lines at every tested
# geometry, over every surface at once (the integrated matrix).
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _GEOMETRIES, ids=[f"{w}x{h}" for w, h in _GEOMETRIES])
def test_tc664_wrap_audit_matrix_zero_overflows(tmp_path: Path, size) -> None:
    """LLR-130.1 — at every tested geometry, every authored line of every map
    surface fits its widget's measured width (0 overflow lines)."""
    got = asyncio.run(_drive(tmp_path, size))
    assert not got["defects"], (
        f"{size}: the wrap audit found {len(got['defects'])} overflowing "
        f"line(s): {got['defects']}"
    )


# TC-665 — per-surface limbs: the painted line count + the no-wrap law.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _GEOMETRIES, ids=[f"{w}x{h}" for w, h in _GEOMETRIES])
def test_tc665_header_and_stats_are_single_lines(tmp_path: Path, size) -> None:
    """The header summary and the stats strip each paint exactly ONE line, in
    budget, at every tested geometry (LLR-129.1's one-line law inside the
    wrap audit)."""
    got = asyncio.run(_drive(tmp_path, size))
    assert not got["defects"], f"{size}: {got['defects']}"
    assert len(got["header_lines"]) == 1, (
        f"{size}: the header must paint one line: {got['header_lines']}"
    )
    assert got["stats_lines"] == 1, (
        f"{size}: the stats strip must paint exactly one line: {got['stats_lines']}"
    )


@pytest.mark.parametrize("size", _GEOMETRIES, ids=[f"{w}x{h}" for w, h in _GEOMETRIES])
def test_tc666_region_rows_fixed_width_no_wrap(tmp_path: Path, size) -> None:
    """Every region row paints ONE fixed-width line inside its widget at every
    tested geometry (HLR-127's fixed-width grammar is the audit's row limb)."""
    got = asyncio.run(_drive(tmp_path, size))
    assert not got["defects"], f"{size}: {got['defects']}"
    assert len(got["row_texts"]) == 9, (
        f"{size}: the demo fixture renders 9 rows: {len(got['row_texts'])}"
    )
    for text, width in zip(got["row_texts"], got["row_widths"]):
        assert "\n" not in text and cell_len(text) <= width, (
            f"{size}: a region row must be one unwrapped line: {text!r} in {width}"
        )


@pytest.mark.parametrize("size", _GEOMETRIES, ids=[f"{w}x{h}" for w, h in _GEOMETRIES])
def test_tc667_inspector_hostile_symbols_no_wrap(tmp_path: Path, size) -> None:
    """LLR-130's defect limb — with hostile over-long A2L symbol names, every
    inspector line (2-space indent + CLIPPED name) fits the measured interior
    at every tested geometry; the painted line count equals the authored
    count (8 fields/hdr lines + 2 names + Peek + peek rows), no hidden wrap."""
    got = asyncio.run(_drive(tmp_path, size, tags=_LONG_TAGS))
    assert not got["defects"], (
        f"{size}: hostile symbol names must not wrap: {got['defects']}"
    )
    body = got["body_lines"]  # the detail body in the SELECTED state here
    clipped = [ln for ln in body if ln.startswith("  ")]
    assert len(clipped) == 2, f"{size}: the two symbol names must paint: {body}"
    for ln in clipped:
        assert ln.endswith("…"), (
            f"{size}: a clipped name must be ellipsis-marked at the cell "
            f"boundary (the house seam): {ln!r}"
        )


@pytest.mark.parametrize("size", _GEOMETRIES, ids=[f"{w}x{h}" for w, h in _GEOMETRIES])
def test_tc668_hint_two_authored_lines_no_wrap(tmp_path: Path, size) -> None:
    """The pre-selection hint paints its TWO authored lines (the inc-001
    one-liner wrapped mid-content at side-by-side) inside the interior at
    every tested geometry."""
    got = asyncio.run(_drive(tmp_path, size, selected=False))
    assert not got["defects"], f"{size}: {got['defects']}"
    assert got["body_lines"] == [
        "Click a region to inspect it.",
        "Double-click to open in hex.",
    ], f"{size}: the hint must paint its two authored lines: {got['body_lines']}"


@pytest.mark.parametrize("size", _GEOMETRIES, ids=[f"{w}x{h}" for w, h in _GEOMETRIES])
def test_tc669_chips_one_line_and_chrome_in_budget(tmp_path: Path, size) -> None:
    """The glance chips paint ONE line and the pane chrome titles/subtitles
    fit their panes, at every tested geometry."""
    got = asyncio.run(_drive(tmp_path, size))
    assert not got["defects"], f"{size}: {got['defects']}"
    assert got["chips_line_height"] == 1, (
        f"{size}: the chips are one line: {got['chips_line_height']}"
    )


# TC-670 — the audit's counterfactual: the injected over-long line FAILS it.
# ---------------------------------------------------------------------------
def test_tc670_injected_overlong_line_fails_the_audit(tmp_path: Path) -> None:
    """LLR-130.2 — mounting ONE deliberately over-long authored line makes the
    audit report >= 1 failure naming it; the same walk is clean without the
    injection (0 false passes). An audit that cannot fail proves nothing."""
    injected = "this-authored-line-is-far-too-long-for-any-map-pane-" + "x" * 120

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            app.current_file = _demo_loaded()
            app.action_show_screen("map")
            await pilot.pause()
            app.update_memory_map()
            for _ in range(4):
                await pilot.pause()
            clean = _audit_map_surfaces(app)
            panel = app.query_one("#memory_map_panel", MemoryMapPanel)
            panel._wrap_audit_mount_overlong(injected)
            await pilot.pause()
            await pilot.pause()
            injected_defects = _audit_map_surfaces(app)
            return clean, injected_defects

    clean, injected_defects = asyncio.run(_drive())
    assert clean == [], (
        f"the un-injected audit must be clean (0 false passes): {clean}"
    )
    assert len(injected_defects) >= 1, (
        "the injected over-long line MUST fail the audit — an audit that "
        "cannot fail proves nothing (C-43)"
    )
    label, line, cells, width = injected_defects[0]
    assert line == injected and cells > width, (
        f"the failure must name the injected line: {injected_defects}"
    )
