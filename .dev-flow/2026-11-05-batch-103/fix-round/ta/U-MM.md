# U-MM — R-TUI-062.10.2 (Memory Map inspector subtitle) + R-TUI-062.10.3 test (DeepSeek v4-pro, product code)

**Launch only after the operator answers Q1 of `TA-REMAINING-DESIGN.md` with A.** This brief implements Q1 = A (the subtitle names what the keys do today). Q1 = B (Enter opens the hex view, D4-21) is a different, larger increment and is not designed here.

Appended after `frontB/FB-common.md` and `units2/TA2-common.md` (its apply_recite/lint sections do not apply: no row and no `Traces:` line is written; the new tests carry the row ids in their names). Tree 2a8ab75f.

**Launch note (orchestrator, relevo-21): operator answered Q1 = A (PENDING P-200). Your tree is `b103-fix-round` at `4f76d914` (this overrides TA2-common's HEAD line; STOP if `git rev-parse --short HEAD` differs). Facts re-grepped there: every line below holds except two shifts — the re-pin is at `tests/test_tui_map_big.py:3050` (not 3048) and the old-text comment at `s19_app/tui/styles.tcss:973` (not 969).**

## Fixed diagnosis (read at 2a8ab75f)
- R-TUI-062.10.2 (`REQUIREMENTS.md:2487`): "The system shall name in the Memory Map's inspector subtitle only keys that the Memory Map handles." The subtitle is set at `s19_app/tui/screens_directionb/memory_map.py:454`: `"↑↓ · ↵ hex"`. Enter on a region row does not open hex: `RegionRow.on_key` (`s19_app/tui/screens_directionb/map_parts.py:940-944`) posts `Activated(chain=1)`, the "inspect, do not navigate" value; `↑↓` move the focus only (`:946-960`). The key line already says so (CTX-LEGEND "Map keys" `REQUIREMENTS.md:2055`: `↑↓ move · click / ↵ inspect · double-click open hex · Esc close`; R-TUI-062.10.1, tested by `tests/test_b101_help_legend_docs.py:1100`). Recorded as not met by batch-101 (`inc-14/E1-rulings.md:47`, BL-I14-1 `.dev-flow/BACKLOG-CODE.md:1869`).
- R-TUI-062.10.3 (`:2488`, row glyphs) is met (each region row ends in `↵`, Enter is handled) but no test names it.
- One test pins the defect: `tests/test_tui_map_big.py:3048` `assert got["detail_sub"] == "↑↓ · ↵ hex", got` (TC-656, chrome titles). It is re-pinned, not retired: the requirement it checks (the inspector subtitle) is live; only its text changes.

## Files (exactly 3)
`s19_app/tui/screens_directionb/memory_map.py`, `tests/test_tui_map_big.py`, `tests/test_b101_help_legend_docs.py` (append only).

## Steps (append to `../REPORT.md` after each)
1. Header; N0.
2. **Tests first.** Append the block below to `tests/test_b101_help_legend_docs.py`. Run both new nodes on the unchanged product: `test_r_tui_062_10_2_1_…` RED (subtitle is `↑↓ · ↵ hex`), `test_r_tui_062_10_3_1_…` GREEN (already met). Paste.
3. **Product.** `memory_map.py:454` -> `        self.query_one("#map_detail").border_subtitle = "↑↓ move · ↵ inspect"`; in the docstring at `:249` replace ``subtitle ``↑↓ · ↵ hex``)`` with ``subtitle ``↑↓ move · ↵ inspect``)`` (text only).
4. **Re-pin.** `tests/test_tui_map_big.py:3048` -> `    assert got["detail_sub"] == "↑↓ move · ↵ inspect", got`.
5. Run: the 2 new nodes, `tests/test_tui_map_big.py::test_tc656_chrome_pane_titles_and_subtitles`, and the 3 `test_r_tui_062_10_1_*` nodes -> GREEN.
6. **Negative controls:** R-TUI-062.10.2: in a copy restore `"↑↓ · ↵ hex"` at `memory_map.py:454` -> `test_r_tui_062_10_2_1_…` RED. R-TUI-062.10.3: in a copy `map_parts.py:940` `if event.key == "enter":` -> `if event.key == "ctrl+enter":` -> `test_r_tui_062_10_3_1_…` RED.
7. After: N0 + 2. Do NOT regenerate snapshots: `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[map-comfortable-120x30].svg` paints the old subtitle, so the non-blocking snapshot job will show this one drift (the orchestrator regenerates it through the repo's snapshot-regen workflow). The comment at `s19_app/tui/styles.tcss:969` also quotes the old text: leave it, note it under Deviations. End per TA2-common.

## Code to append to `tests/test_b101_help_legend_docs.py`
```python


def test_r_tui_062_10_2_1_inspector_subtitle_names_only_handled_keys(tmp_path: Path) -> None:
    """R-TUI-062.10.2/1: the inspector subtitle reads ``↑↓ move · ↵ inspect`` and
    each key it names does that: Down moves the focus to the next region row, Enter
    shows that region in the inspector and opens no other window.

    Why: the old subtitle ``↑↓ · ↵ hex`` promised a hex jump that Enter never makes
    (BL-I14-1). Mutant: the old text -> RED.
    """
    from s19_app.tui.screens_directionb import RegionRow
    from tests.test_map_click_chain import _capture_nav, _map_ready

    loaded = _image_f()

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        out: dict = {}
        async with app.run_test(size=(120, 30)) as pilot:
            panel = await _map_ready(app, loaded, pilot)
            navs: List[int] = []
            _capture_nav(panel, navs)
            out["subtitle"] = str(app.query_one("#map_detail").border_subtitle)
            rows = list(app.query(RegionRow))
            assert len(rows) >= 2, "the image has four regions"
            rows[0].focus()
            await _pause(pilot)
            await pilot.press("down")
            await _pause(pilot)
            out["down_moves_focus"] = app.focused is rows[1]
            await pilot.press("enter")
            await _pause(pilot)
            detail = str(app.query_one("#map_detail_body").render())
            out["enter_inspects"] = f"0x{rows[1].region_start:08X}" in detail
            out["navs"] = list(navs)
            out["screen"] = app._active_screen_key
        return out

    out = asyncio.run(_drive())
    assert out["subtitle"] == "↑↓ move · ↵ inspect", out
    assert out["down_moves_focus"] and out["enter_inspects"], out
    assert out["navs"] == [] and out["screen"] == "map", out


def test_r_tui_062_10_3_1_row_glyph_is_enter_and_enter_inspects(tmp_path: Path) -> None:
    """R-TUI-062.10.3/1: every region row ends in the one key glyph ``↵`` and the
    Memory Map handles that key: Enter on the last row shows that region in the
    inspector and stays on the map.

    Mutant: Enter no longer handled by the row -> RED.
    """
    from s19_app.tui.screens_directionb import RegionRow
    from tests.test_map_click_chain import _capture_nav, _map_ready

    loaded = _image_f()

    async def _drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        out: dict = {}
        async with app.run_test(size=(120, 30)) as pilot:
            panel = await _map_ready(app, loaded, pilot)
            navs: List[int] = []
            _capture_nav(panel, navs)
            rows = list(app.query(RegionRow))
            out["glyph_ends"] = [str(row.render()).rstrip().endswith("↵") for row in rows]
            rows[-1].focus()
            await _pause(pilot)
            await pilot.press("enter")
            await _pause(pilot)
            detail = str(app.query_one("#map_detail_body").render())
            out["enter_inspects"] = f"0x{rows[-1].region_start:08X}" in detail
            out["navs"] = list(navs)
            out["screen"] = app._active_screen_key
        return out

    out = asyncio.run(_drive())
    assert out["glyph_ends"] and all(out["glyph_ends"]), out
    assert out["enter_inspects"] and out["navs"] == [] and out["screen"] == "map", out
```

## For the checker
Laws on the unit tree: no new RED. Regression: `tests/test_tui_map_big.py`, `tests/test_b101_help_legend_docs.py`, `tests/test_map_click_chain.py` same result as on 2a8ab75f except the re-pinned TC-656 assert. Capture (HT rule: real screenshot) of the Memory Map at 120x30 with the new subtitle for the operator's page.
