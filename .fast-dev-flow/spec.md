# fast-dev-flow spec — batch 43 — A2L-symbol region names + Memory-Map per-cell tooltips (R-TUI-041 R-3)

- **Status:** closed 2026-07-13 (AC-1/2/3/4 green; full gate `1400 passed / 2 skipped / 3 xfailed / 0 failed`; RED-first shown for AC-1 + AC-2; 0 frozen diffs; C-27 dual-guard ×2; security-reviewer pass F1 mitigated; autonomous + self-merge)
- **Created:** 2026-07-13
- **Branch:** `claude/batch-43-a2l-region-tooltips` @ `d825e50` (= origin/main tip; RC-1 clean, merge-base == origin/main)
- **Route:** /fast-dev-flow (render-only, single-screen feature; precedent = batch-31 amended R-TUI-041 via fast-flow)
- **Run mode / merge:** TBD at Phase-A gate (operator: plan first). Scope = **both surfaces** (operator-chosen). Decisions → MEMORY.md at close.
- **security_required:** TRUE — renders **untrusted A2L symbol names** (`.name`, third-party firmware metadata) into the detail pane AND a new tooltip sink; the same class was a **batch-27 Phase-2 BLOCKER** (`sensor[red]` → Rich markup injection/crash). Mitigation: render only via markup-safe `Text`/`safe_text` (never markup strings), for BOTH sinks; security-reviewer pass before code.

## 1. Objective

Close R-TUI-041 **R-3** (deferred at batch-27): name a Memory-Map cell's covering region by the A2L symbol(s) that overlap it (detail pane), and add a per-cell hover tooltip listing the symbols intersecting each cell — render-only, over the already-computed `_a2l_enriched_tags` + `LoadedFile.ranges` (no new parse/coverage/validation).

## 2. User stories

- **US-⑥a (region naming):** As an operator inspecting the Memory Map, I want a selected cell's covering region labelled with the A2L symbol name(s) that fall in it (not just `0x..-0x..` bounds), so I can tell *what* lives at that address without opening the A2L Explorer.
- **US-⑥b (per-cell tooltip):** As an operator scanning the grid, I want to hover a cell and see the A2L symbol(s) intersecting it plus its address window/status, so I can survey symbol placement spatially without clicking each cell.

## 3. Acceptance criteria (observable)

Matching semantics (both surfaces): a tag overlaps a window `[w_start, w_end)` iff `addr < w_end and addr + size > w_start`, where `size = byte_size if a positive int else 1` (mirrors `resolve_report_filter` extent logic, S-F4 hostile-shape-safe: non-int address / non-dict tag skipped, never raised). Multi-symbol windows show the first **3** names (by ascending address) + `"+N more"`.

- **AC-1 (region naming — RED-first):** When a selected cell's covering region overlaps ≥1 A2L symbol, the detail-pane Region line includes the symbol name(s) (capped 3 + "+N more") after the bounds/size/status; when it overlaps none (or no A2L loaded), the Region line is the bounds-only form unchanged. Asserted via Pilot over a fixture with a known symbol at a known address. RED: pre-fix the Region line never contains the symbol name.
- **AC-2 (per-cell tooltip — RED-first):** When a `MapCell`'s window `[cell_start, cell_end)` overlaps ≥1 A2L symbol, the cell's `tooltip` lists those symbol name(s) (capped) + `0x{start:08X}-0x{end-1:08X}` + status; a cell overlapping none has no symbol tooltip (bounds/status only or unset per the chosen default). Asserted by reading `cell.tooltip` for a cell over a known symbol. RED: pre-fix `MapCell` has no symbol tooltip.
- **AC-3 (markup safety — security):** An A2L symbol named `evil[red]` (or `x[/]`, `y[link=…]`) renders **literally** in both the detail-pane Region line and the tooltip — no `rich.errors.MarkupError`, no style/hyperlink leak, screen loads normally. Asserted by loading a hostile-named fixture and reading the rendered detail text + tooltip.
- **AC-4 (no regression / fallback):** With no A2L loaded, the Memory Map grid + detail pane behave exactly as today (bounds-only region, no symbol tooltips) — the existing R-TUI-041 `tc041_*`/`at036*` tests stay green.

## 4. Validation strategy

RED-first Pilot ATs for AC-1/AC-2 (fixture: an S19 image + an A2L with a symbol at a known address inside a known cell/region), a hostile-name AT for AC-3, and the existing `test_tui_directionb.py` R-TUI-041 suite for AC-4. New unit test for the `symbols_in_window` helper (overlap/containment/point/hostile-shape). Full gate `pytest -q -m "not slow"` + C-27 dual-guard each increment (screens_directionb.py + app.py are NOT frozen — 0 frozen diffs expected). Coverage-claim discipline: confirm each named test exists on disk before closing.

## 5. Non-goals

- No new parse/coverage/validation; no modal; no change to cell colouring, geometry, stats strip, or Open-in-Hex.
- No A2L Explorer changes; no MAC-symbol naming (A2L only, per the item).
- No engine-frozen module (a2l.py is READ via `_a2l_enriched_tags` only; core/hexfile/range_index/validation/mac/color_policy untouched).
- REQUIREMENTS.md R-TUI-041 entry amended (as batch-31 did) — not a new R-* id.

## 6. Detected security flags

- [x] **Input / attack surface** — untrusted A2L symbol names rendered into the detail pane + a NEW tooltip sink. **`security_required: true`.**
- Others: none.

**Risk summary:** The one real risk is Rich-markup injection/crash from a hostile A2L `.name` (batch-27 BLOCKER class). The detail pane already renders via `Text.append(safe_text(...))` (safe); the NEW tooltip must likewise be a Rich `Text` built with `safe_text` — never a markup string. AC-3 locks this with a hostile-named fixture. security-reviewer mini-pass before code confirms both sinks + the tooltip rendering path.

## 7. Increment plan (≤5 files each, 2 increments)

1. **Inc-1 — data plumbing + region naming (US-⑥a, AC-1/AC-3/AC-4):** add `a2l_tags` param to `MemoryMapPanel.render_ranges` (stored as `self._a2l_tags`); new module helper `symbols_in_window(tags, start, end, cap=3)` in `screens_directionb.py` (sibling to `issues_in_window`); extend `_render_detail` to append overlapping symbol name(s) to the Region line via `safe_text`; `app.py::update_memory_map` passes `self._a2l_enriched_tags`. Files: `screens_directionb.py`, `app.py`, `tests/test_tui_directionb.py`. + hostile-name AT (AC-3 detail arm).
2. **Inc-2 — per-cell tooltips (US-⑥b, AC-2/AC-3):** in `render_ranges`, set each `MapCell.tooltip` to a markup-safe `Text` (symbols overlapping the cell + window + status); no symbol → window/status only. Files: `screens_directionb.py`, `tests/test_tui_directionb.py`. + hostile-name AT (AC-3 tooltip arm). Then amend REQUIREMENTS.md R-TUI-041 (R-3 shipped).

(2 increments; within the fast-flow ceiling.)

## 8. Batch status

| Field | Value |
|-------|-------|
| Current phase | closed |
| Started | 2026-07-13 |
| Closed | 2026-07-13 |
| Promoted to /dev-flow | no |
| Notes | RC-1 clean; branch in main repo dir; security F1 mitigated (tooltip = Text) |

## 9. Close

### What changed
Closed R-TUI-041 **R-3** (deferred at batch-27): the Memory-Map detail-pane covering region is now named by the A2L symbol(s) overlapping it (capped 3 + "+N more"), and each `MapCell` carries a hover tooltip listing the symbols intersecting the cell + its window/status. Render-only over `_a2l_enriched_tags` + `LoadedFile.ranges`. New helpers `symbols_in_window` (extent-overlap join `[addr, addr+byte_size)`, hostile-shape-safe) + `symbol_list_text` (capped, markup-safe) + `MemoryMapPanel._cell_tooltip`; `update_memory_map` passes `_a2l_enriched_tags` as the 4th `render_ranges` arg. `a2l.py` only READ (frozen, untouched).

### How it was tested
- Full gate `pytest -q -m "not slow"`: **1400 passed / 2 skipped / 3 xfailed / 0 failed** (31 snapshots; +5 tests).
- RED-first: AC-1 (`test_at_r3_detail_region_named_by_a2l_symbols` — region line was bounds-only pre-fix) and AC-2 (`test_at_r3_cell_tooltip_...` — `cell.tooltip` was `None` pre-fix), both shown failing via git-stash then green.
- AC-3 (security): hostile names `evil[red]`/`x[/]`/`y[bold`/`z[link=…]` render literally in the detail pane; the tooltip AC drives `Content.from_rich_text` to prove literal output (vs `Content.from_markup` which strips `[red]` — the counterfactual proving the `Text` type matters).
- AC-4: the full R-TUI-041 `tc041_*`/`at035`/`at036*`/`at037` suite stays green (no regression). C-27 dual-guard clean after both increments; C-26 census clean.

### Open risks / pending
- None. `a2l.py` untouched (read-only). All ATs green.

### Security flags — handling
`security_required: true` — untrusted A2L symbol names into two render sinks. security-reviewer pre-code pass (F1): a `str` tooltip is markup-parsed by Textual 8.2.8 (would inject/crash on hover); mitigation = tooltip is a Rich `Text` built via `safe_text`/`symbol_list_text`, never an f-string; detail pane uses `Text.append(safe_text(...))`. Both mitigations applied + locked by AC-3. Final pass: no residual risk.

### Suggested commit message
```
feat(tui): batch-43 — A2L-symbol region names + Memory-Map per-cell tooltips (R-TUI-041 R-3)
```
