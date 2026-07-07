# Increment 002 — US-036 cell selection → detail pane

**BLUF:** Clicking/focusing a `.map-cell` now populates `#map_detail` (status chip, address window, covering region, cell-scoped issue list, region-issue count) and an "Open in Hex View" button drives `update_hex_view(focus_address=cell_start)`. LLR-041.4/.5/.6 + markup-safe detail (LLR-041.11). `code-reviewer`: **OK to advance, 0 HIGH.** Ledger 1039→1049.

## 1. What changed
- **`MapCell(Static)`** — focusable/clickable cell widget carrying `[cell_start, cell_end)` + status; posts `MapCell.Selected` on click/Enter.
- **Pure helpers** — `issues_in_window(issues, start, end)` (half-open join, `address is None` excluded) + `covering_range(...)` (invalid-preferred, `None` on gap).
- **`MemoryMapPanel`** — `render_ranges` gains `issues` param; `build_detail_text` (markup-safe `Text`, every issue `code`/`symbol`/`message` via `safe_text`); `on_map_cell_selected`; `OpenInHexRequested` message + button handler; `#map_detail_body` + hidden `#map_open_hex_button`.
- **`app.py`** — ONE call-site change `render_ranges(ranges, range_validity, self._validation_issues)` + `on_memory_map_panel_open_in_hex_requested` (switch to workspace screen + `update_hex_view`).
- **`styles.tcss`** — `.map-cell:focus`, `#map_detail_body`, `#map_open_hex_button`.

## 2. Files (4 ≤ 5)
`screens_directionb.py`, `app.py`, `styles.tcss`, `tests/test_tui_directionb.py`.

## 3/4. Tests
- **10 new pass** — AT-036a/b/c/d/e/f/g + TC-041.4/.5/.6. Ledger 1039→**1049** (D=0, A=10).
- directionb + engine guard **113 passed**; snapshot **30 passed / 1 xfailed** (map cell); ruff clean; mypy 0 new; **0 engine-frozen diffs**.
- Seed-issue ATs anchor at a REAL invalid-range start + resolve cell via `_cell_containing(addr)` → robust to F2 live-geometry drift.

## Code-review verdict (independent)
**OK to advance — 0 HIGH.** PASS: LLR-041.11 markup safety in live detail path (AT-036f literal `sensor[red]` through `#map_detail`); LLR-041.5 half-open join + `None` excluded from BOTH list and region count (AT-036g); LLR-041.6 `focus==cell_start`, panel renders no hex; app.py minimal (call-site + handler), no-file path safe; C-10 non-default + content-change.
- **F1 (MEDIUM):** AT-036a selects via `.focus()` not the arrow-key nav US-036 promises → grid focus-traversal unexercised. Fix = add one arrow-press hop. **Decision at gate.**
- F2/F3/F4 (LOW): dead-but-conventional button id-guard; idempotent re-select; `issues=()` default harmless. No action.

## 5. Risks / carries
- CARRY-F2 (Inc-1, MEDIUM) still open → fixed-cell-count Pilot test when map xfail retired (Inc 3 / snapshot-regen).
- F1 (this increment) — apply now or defer.

## 6. Pending (Inc 3, US-037)
`#map_stats` strip + TC-041.8; narrow reflow (LLR-041.10) + TC-041.10; `map-comfortable-80x24` snapshot cell + TC-041.9; baseline regen (canonical CI); REQUIREMENTS.md R-TUI-041 body (Phase 6).

## Follow-on: arrow-key navigation (F1 from Inc-2 review + operator directives)
The Inc-2 review's F1 ("AT-036a uses `.focus()` not arrow nav") + a live test run exposed a REAL gap: `MapCell.on_key` only handled `Enter`; Textual does no spatial arrow-focus by default → arrows didn't move focus, yet the docstring claimed "arrow-key navigable" and the prototype demoed it. **Operator chose: implement arrow-key nav** (+ two directives: no key conflict, discoverable).
- **Wired:** `MapCell.on_key` handles arrows → `MemoryMapPanel.focus_adjacent_cell` → pure `adjacent_cell_index(current,key,count,cols)` (Left/Right ±1, Up/Down ±cols, clamp `[0,count)`, no wrap, partial-last-row guarded). Arrows only MOVE focus; Enter selects. `MAP_GRID_COLS=16` tied to CSS `#map_grid { grid-size: 16 }`.
- **No key conflict (directive 1):** no arrow keys in app `BINDINGS` / command-bar suppression; handler scoped to the focused `MapCell` with `event.stop()` only on a handled arrow → no scroll leak to `#map_content` (proven: `scroll_offset.y` unchanged); non-arrows fall through (Tab preserved). No global arrow binding added.
- **Discoverable (directive 2):** `_DETAIL_HINT` = "Click a cell, or focus the grid and use arrows (<-/->/up/down) then Enter to inspect." — asserted present pre-selection.
- **Docstring overclaim fixed.** +3 tests (TC-041.4b arrow-index+clamp; hint-prompt; arrow-moves-without-scroll). AT-036a now black-box arrow traversal.
- **Ledger 1049→1052.** Files still the 4 Inc-2 set. **0 engine-frozen diffs.**
- **Arrow-nav review: OK, 0 HIGH/MEDIUM.** MAP_GRID_COLS==CSS grid-size verified. F1(compose hint via `safe_text`) FOLDED (uniform markup-safety); F2 (doctest readability) skipped. Re-run: 18 map tests pass, ruff clean.

## 7. Next: Increment 3 (US-037) — stats strip + reflow, closes R-TUI-041.
