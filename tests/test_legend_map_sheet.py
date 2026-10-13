"""AT-293 -- the legend A acceptance (batch-93 inc-003).

batch-93 increment 003 — the map legend's spec sheet (HLR-132 / LLR-132.1-.4).

The operator ruling of 2026-08-06 (legend A): the map view's ``k``-legend is a
GROUPED SPEC SHEET — four bordered boxes (Entropy bands · Map anatomy ·
Region row · Keys), zero prose paragraphs, no wrapping line — with the band
key LIVE-SOURCED from the band domain (``build_band_key_rows()`` at render
time, never a hand-copied list). This module carries the contract's TC arms:

- **TC-676** — the four grouped boxes (LLR-132.1): box order + border titles,
  ``len(ENTROPY_BANDS) + 1`` band lines, four anatomy sample/meaning pairs,
  the region-row sample + field key, the Keys line, and the exact sheet line
  census (a stray prose paragraph cannot hide).
- **TC-677** — the band key stays live-sourced (LLR-132.4): a band domain
  mutated upstream in-fixture (rename + addition) appears in the sheet with
  zero legend-code change; the OLD label going absent is the hand-copy
  detector. The ``[lo,hi)`` ranges render ``markup=False``.
- **TC-680** — no wrap at the contract's geometries (LLR-132.2): every sheet
  line is one row tall and fits its measured width at 80x24 AND 120x36; the
  counterfactual mounts one over-long line and the audit reddens (C-43).
- **Esc** dismisses the modal (LLR-132.2), through the real key press.
- **TC-681** — the N8 scoping control (LLR-132.3): the OTHER views' legend
  content hashes byte-identical to the pre-change tree (pins taken on the
  inc-002 tree by ``.dev-flow/2026-10-11-batch-93/evidence/inc003_hash_probe.py``,
  over the SORTED line multiset — pane document order is layout, not content).

Replaces the retired N8 map-card arms (``AT-N8-03``'s map limb,
``TC-N8-05``'s map data pins): the map example card is gone — the sheet owns
the map path (HLR-132). The batch-72 two-pane suite keeps its mac/a2l teeth
(see ``tests/test_legend_two_pane.py``).
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from typing import Dict, List, Tuple

import pytest
from rich.cells import cell_len
from textual.content import Content
from textual.widgets import Static

from s19_app.tui import legend as L
from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import LegendScreen
from s19_app.tui.services.entropy_service import ENTROPY_BANDS, ENTROPY_WINDOW_BYTES

#: The contract's wrap-audit geometries for this surface (LLR-132.2).
_GEOMETRIES = [(80, 24), (120, 36)]


#: Pre-change legend content hashes for the OTHER views (+ the flow fallback),
#: taken on the inc-002 tree (see this module's docstring) — the SORTED line
#: multiset (pane document order is layout, not content).
_PRE_CHANGE_HASHES: Dict[str, str] = {
    "workspace": "f25a1d07a379c730f7240f06dcffee179262d232ef6c013422599b3721d21178",
    "a2l": "d0bb2297eea838060fac54af7a9404d58a1b2257fc43fd09299d83988f8ab12f",
    "mac": "70c0a9af224a7b8965ec630486b48e1d1b5a899f1dd2fa2b1430267a4cae9e8a",
    "issues": "954e7674e6091cd45b06cbfeb1aaee2ec96a3b282e9a51210cfedc23cc105e08",
    "flow": "cd108d8cf1ff8a3a0a0b4246ddda49ae8f841e026808c2c482337e4c65e24484",
}


async def _open_map_legend(app: S19TuiApp, pilot) -> LegendScreen:
    app.action_show_screen("map")
    await pilot.pause()
    app.action_show_legend()
    await pilot.pause()
    assert isinstance(app.screen, LegendScreen), f"legend did not open: {app.screen}"
    return app.screen


def _sheet_text(legend: LegendScreen) -> str:
    return " ".join(
        getattr(w.render(), "plain", str(w.render()))
        for w in legend.query("#legend_body Static")
    )


# ---------------------------------------------------------------------------
# TC-676 — the four grouped boxes (LLR-132.1).
# ---------------------------------------------------------------------------
def test_tc676_sheet_four_grouped_boxes(tmp_path: Path) -> None:
    """The sheet renders four bordered boxes in order — Entropy bands · Map
    anatomy · Region row · Keys — with the band census (len(ENTROPY_BANDS) +
    the gap row), four anatomy sample/meaning pairs, the region sample + field
    key, the Keys line, and EXACTLY those lines (zero prose paragraphs)."""

    async def _drive() -> Dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            legend = await _open_map_legend(app, pilot)
            boxes = list(legend.query(".legend-sheet-box"))
            per_box_lines = [
                [w for w in box.query(Static)] for box in boxes
            ]
            band_rows = list(
                legend.query("#legend_body .legend-row")
            )
            return {
                "titles": [box.border_title for box in boxes],
                "per_box_counts": [len(lines) for lines in per_box_lines],
                "sheet_text": _sheet_text(legend),
                "band_classes": [
                    sorted(
                        c for c in row.classes if c.startswith("band-")
                    )
                    for row in band_rows
                ],
                "markup_flags": [
                    row._render_markup for row in band_rows
                ],
                "n_statics": len(list(legend.query("#legend_body Static"))),
            }

    got = asyncio.run(_drive())
    titles = got["titles"]
    assert len(titles) == 4, f"expected 4 grouped boxes, got {titles}"
    assert titles[0] == (
        f"Entropy bands — {ENTROPY_WINDOW_BYTES} B windows, bits/byte"
    ), titles[0]
    assert titles[1:] == ["Map anatomy", "Region row", "Map keys"], titles  # batch-94: the title names what the line documents

    n_bands = len(ENTROPY_BANDS)
    assert got["per_box_counts"] == [n_bands + 1, 8, 2, 1], (
        f"box line census drifted (band+gap / anatomy pairs / region / keys): "
        f"{got['per_box_counts']}"
    )
    # Exact line census: a stray prose paragraph anywhere in the sheet reddens.
    assert got["n_statics"] == (n_bands + 1) + 8 + 2 + 1, got["n_statics"]

    text = got["sheet_text"]
    for band_label, _lo, _hi in ENTROPY_BANDS:
        assert band_label in text, f"live band label {band_label!r} missing"
    assert "unmapped gap" in text, "the gap pseudo-row is missing"
    for sample, meaning in L.build_map_anatomy_samples():
        assert sample in text, f"anatomy sample {sample!r} missing"
        assert meaning in text, f"anatomy meaning {meaning!r} missing"
    assert L.MAP_REGION_ROW_SAMPLE in text, "region-row sample missing"
    assert L.MAP_REGION_ROW_FIELD_KEY in text, "region-row field key missing"
    assert L.MAP_KEYS_LINE in text, "Keys line missing"
    # Negative control: the severity key must not leak into the map sheet.
    assert L.LEGEND_TABLE["A2L"]["Red"][1] not in text, (
        "an A2L severity row leaked into the map sheet"
    )
    # Band rows keep their band-* paint and render markup=False (literal [lo,hi)).
    flat_classes = {c for classes in got["band_classes"] for c in classes}
    assert flat_classes == {
        "band-constant",
        "band-low",
        "band-medium",
        "band-high",
    }, flat_classes
    assert len(got["markup_flags"]) == n_bands + 1
    assert all(flag is False for flag in got["markup_flags"]), (
        "a band row lost markup=False — the [lo,hi) brackets would parse"
    )


# ---------------------------------------------------------------------------
# TC-677 — the band key stays live-sourced (LLR-132.4).
# ---------------------------------------------------------------------------
def test_tc677_band_key_mutated_upstream_flows_through(tmp_path, monkeypatch) -> None:
    """The mutated-label law: a band domain re-cut upstream (one rename, one
    addition) appears in the sheet with ZERO legend-code change; the retired
    label's absence is the hand-copy detector (a copied list would still
    render it)."""

    mutated = (
        ("constant/padding", 0.0, 0.5),  # re-cut upstream
        ("sparse", 0.5, 1.0),  # added upstream
        ("structured", 1.0, 5.0),  # renamed upstream
        ("dense", 5.0, 7.2),  # renamed upstream
        ("high/random", 7.2, 8.000001),
    )
    monkeypatch.setattr(L, "ENTROPY_BANDS", mutated)

    async def _drive() -> Tuple[str, List[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            legend = await _open_map_legend(app, pilot)
            boxes = list(legend.query(".legend-sheet-box"))
            band_lines = [
                w.render().plain for w in boxes[0].query(Static)
            ]
            return _sheet_text(legend), band_lines

    text, band_lines = asyncio.run(_drive())
    assert len(band_lines) == len(mutated) + 1, (
        f"band box must track the live domain ({len(mutated)} rows + gap), "
        f"got {len(band_lines)}"
    )
    # The label column is glyph + two blanks + the live-derived label field —
    # parse it back and require EXACTLY the mutated domain, in order.
    label_w = max(len(label) for label, _lo, _hi in mutated) + 2
    rendered_labels = [
        line[3 : 3 + label_w].strip() for line in band_lines[: len(mutated)]
    ]
    assert rendered_labels == [label for label, _lo, _hi in mutated], (
        f"the band box does not track the live domain: {rendered_labels}"
    )
    assert any("sparse" in line and "[0.5,1)" in line for line in band_lines)
    # The hand-copy detector: the retired labels must be gone from the band box.
    assert "low" not in rendered_labels and "medium" not in rendered_labels, (
        "the band box still renders a retired label — the rows are "
        "hand-copied, not live-sourced"
    )
    # The anatomy box still renders (canonical vocabulary, no crash).
    assert "band bar — width ∝ mapped bytes; ╱ = folded gap" in text


def test_tc677_sheet_band_rows_equal_live_build(tmp_path: Path) -> None:
    """The drift-detector limb: the sheet's band rows are exactly
    ``build_band_key_rows()`` output for the live domain — never a second,
    legend-authored copy of the domain."""

    async def _drive() -> List[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            legend = await _open_map_legend(app, pilot)
            boxes = list(legend.query(".legend-sheet-box"))
            return [w.render().plain for w in boxes[0].query(Static)]

    band_lines = asyncio.run(_drive())
    live_rows = L.build_band_key_rows()
    assert len(band_lines) == len(live_rows) + 1
    for line, row in zip(band_lines, live_rows):
        assert row.label in line and row.range_text in line and row.meaning in line, (
            f"sheet band line {line!r} drifted from the live row {row!r}"
        )
    # Every line parses as markup (guards a future markup=True flip); the
    # rendered sheet is markup=False, so brackets must round-trip untouched.
    for line in band_lines:
        assert Content.from_markup(line).plain  # no MarkupError


# ---------------------------------------------------------------------------
# TC-680 — no wrap at the contract's geometries (LLR-132.2).
# ---------------------------------------------------------------------------
def _audit_sheet(legend: LegendScreen) -> List[Tuple[str, str, int, int]]:
    """The sheet no-wrap law: one row per line, cell width fits the measured
    width. Returns (where, line, cells, width) per defect."""
    defects: List[Tuple[str, str, int, int]] = []
    for box in legend.query(".legend-sheet-box"):
        title = box.border_title or ""
        if cell_len(title) > box.region.width:
            defects.append(("border title", title, cell_len(title), box.region.width))
        for line in box.query(Static):
            plain = line.render().plain
            if line.region.height != 1 or cell_len(plain) > line.region.width:
                defects.append(
                    ("line", plain, cell_len(plain), line.region.width)
                )
    return defects


@pytest.mark.parametrize("size", _GEOMETRIES, ids=[f"{w}x{h}" for w, h in _GEOMETRIES])
def test_tc680_sheet_no_wrapped_lines(tmp_path: Path, size) -> None:
    """LLR-132.2 — every authored sheet line fits its container's measured
    width (0 wrapped lines) at 80x24 and 120x36."""
    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            legend = await _open_map_legend(app, pilot)
            return _audit_sheet(legend)

    defects = asyncio.run(_drive())
    assert defects == [], (
        f"{size}: the sheet wrap audit found {len(defects)} overflowing "
        f"lines: {defects}"
    )


def test_tc680_sheet_audit_counterfactual_reddens(tmp_path: Path) -> None:
    """The audit must be able to FAIL (C-43): one over-long line mounted into
    a sheet box is named by the audit; the same walk is clean without it."""
    from textual.widgets import Static as _Static

    async def _drive(inject: bool) -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            legend = await _open_map_legend(app, pilot)
            clean = _audit_sheet(legend)
            if not inject:
                return clean
            box = legend.query(".legend-sheet-box").first()
            box.mount(_Static("X" * 400, markup=False))
            await pilot.pause()
            return _audit_sheet(legend)

    assert asyncio.run(_drive(inject=False)) == []
    defects = asyncio.run(_drive(inject=True))
    assert len(defects) >= 1 and defects[0][1] == "X" * 400, (
        f"the injected over-long line was not named: {defects}"
    )


def test_esc_dismisses_the_sheet(tmp_path: Path) -> None:
    """LLR-132.2 — Esc closes the modal (the screen-level binding, real key)."""

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 36)) as pilot:
            await pilot.pause()
            await _open_map_legend(app, pilot)
            await pilot.press("escape")
            await pilot.pause()
            return type(app.screen).__name__

    assert asyncio.run(_drive()) == "Screen", (
        "Esc did not dismiss the legend sheet"
    )


# ---------------------------------------------------------------------------
# TC-681 — the other views render byte-identical (LLR-132.3).
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", _GEOMETRIES, ids=[f"{w}x{h}" for w, h in _GEOMETRIES])
def test_tc681_other_views_legend_byte_identical(tmp_path: Path, size) -> None:
    """The N8 scoping control: the workspace / a2l / mac / issues legends (and
    the flow full-table fallback) render byte-identical content to the
    pre-change tree — a map-path leak into the shared rows reddens here."""

    async def _drive(view: str) -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen(view)
            await pilot.pause()
            app.action_show_legend()
            await pilot.pause()
            assert isinstance(app.screen, LegendScreen)
            parts = sorted(
                getattr(w.render(), "plain", str(w.render()))
                for w in app.screen.query("#legend_body Static")
            )
            return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()

    for view, expected in _PRE_CHANGE_HASHES.items():
        got = asyncio.run(_drive(view))
        assert got == expected, (
            f"{view} legend content drifted from the pre-change tree at "
            f"{size}: {got} != {expected} (a map-path leak into the shared "
            "rows?)"
        )
