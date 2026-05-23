# Increment 006 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 6 — A2L Explorer + MAC View screen re-layout
**Phase:** 3 — Implementation
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-009.1 (A2L Explorer two-pane structure + two-regime width layout), LLR-009.2 (A2L data wiring unchanged), LLR-010.1 (MAC View two-pane structure + two-regime width layout), LLR-010.2 (MAC data wiring unchanged) · **TCs covered:** TC-019, TC-020, TC-021, TC-022.

---

## 1. What changed

`#screen_a2l` and `#screen_mac` were re-composed from their pre-batch 2×2 grids (`#alt_layout` / `#mac_layout`) into the Direction B two-pane layouts defined by LLR-009.1 / LLR-010.1:

- **A2L Explorer** — a `Horizontal` `#a2l_panes` holding a left tags-table pane (`#a2l_tags_pane`, `1fr`) and a right hex pane (`#a2l_hex_pane`, fixed/proportional).
- **MAC View** — a `Horizontal` `#mac_panes` holding a left records-table pane (`#mac_records_pane`, `1fr`) and a right hex pane (`#mac_hex_pane`, fixed/proportional).

**Every existing widget subtree was reused verbatim** — only the container nesting changed. The A2L tags pane keeps `#a2l_tags_title`, the filter row (`#a2l_tags_filter_input`, `#a2l_filter_field`, `#a2l_filter_all/invalid/inmem`, `#a2l_tag_find_input`, `#a2l_tag_find_next`, `#a2l_page_prev/next_button`), the `#a2l_filter_menu` overlay + `#a2l_filter_menu_list`, `#a2l_tags_list` and `#a2l_tags_summary`; the A2L hex pane keeps `#alt_hex_title`, `#alt_hex_controls` (`#alt_search_input` / `#alt_search_button` / `#alt_goto_input` / `#alt_goto_button`) and `#alt_hex_scroll` / `#alt_hex_view`. The MAC records pane keeps `#mac_title`, `#mac_page_controls` (`#mac_page_prev/next_button`), the `#mac_scroll` wrapper, `#mac_records_list` and `#mac_records_summary`; the MAC hex pane keeps `#mac_hex_title`, `#mac_hex_controls` and `#mac_hex_scroll` / `#mac_hex_view`. Every id every A2L/MAC renderer queries (`update_a2l_view`, `update_a2l_tags_view`, `_refresh_a2l_filtered_tags`, `update_alt_hex_view`, `update_mac_view`, `update_mac_hex_view`, the filter/paging/jump actions) is preserved, so no renderer / paging / jump / filter logic was touched (LLR-009.2 / LLR-010.2).

The two-regime width layout (LLR-009.1 / LLR-010.1 / LLR-007.1) is implemented in `styles.tcss`, mirroring the increment-5 Workspace pattern:
- **`>= 120` columns (fixed regime):** `#a2l_hex_pane` / `#mac_hex_pane` `width: 40`; `#a2l_tags_pane` / `#mac_records_pane` `width: 1fr`.
- **`< 120` columns (proportional regime):** under `#workspace_body.width-narrow`, `#a2l_hex_pane` / `#mac_hex_pane` `width: 35%`; the table panes stay `width: 1fr`.

The narrow regime is governed by the existing `width-narrow` class — `_apply_width_regime` (untouched) toggles it on `#workspace_body` at the 120-column breakpoint, so the new per-screen rules keyed on `#workspace_body.width-narrow` activate with zero new resize code.

The obsolete grid + panel CSS from the 2×2 layouts was removed: `#alt_layout`, `#mac_layout`, `.alt_panel`, `#alt_hex_panel`, `#alt_tags_panel`, `#mac_hex_panel`, `#mac_content_panel`, `#alt_actions_panel`. A repo-wide grep confirmed no live selector or `query_one` call referenced any removed id (only docstring/comment prose mentions remain, and the `.db-pane` rule from increment 5 — `border`/`background`/`padding`/`height: 100%` — now also styles the four new A2L/MAC panes via the `db-pane` class added to each). The `#screen_a2l` was previously a container that included an `#alt_actions_panel` reference only in CSS; the composition never mounted that widget, so its rule was dead and is now dropped.

No engine, service, `color_policy.py`, `a2l.py`, `mac.py`, parser, `update_*` renderer, `find_string_in_mem`, `_handle_goto`/`_handle_search`, hex-cap constant or paging/jump/filter action was modified. The MAC-overlay hex highlight (LLR-010.2) is preserved because `update_mac_hex_view` and its overlay-rendering path are byte-identical and `#mac_hex_view` is unchanged. No new runtime dependency was added. The `compose` docstring was updated to drop the stale "wrap `#alt_layout`/`#mac_layout` verbatim … increments 5-7" note.

## 2. Files modified

**Code / test (3 — under the ≤5 cap):**

1. `s19_app/tui/app.py` — re-composed `_compose_screen_a2l` (now builds `#a2l_panes`: `#a2l_tags_pane` `1fr` + `#a2l_hex_pane`) and `_compose_screen_mac` (now builds `#mac_panes`: `#mac_records_pane` `1fr` + `#mac_hex_pane`), each reusing every pre-batch widget subtree verbatim; docstrings rewritten to the PROJECT_RULES.md contract; `compose` docstring's stale Data-Flow note corrected.
2. `s19_app/tui/styles.tcss` — added the A2L/MAC two-regime rules (`#a2l_panes` / `#mac_panes` horizontal; fixed-40 hex panes at `>=120`; `35%` hex panes under `width-narrow`; `1fr` table panes); removed the obsolete `#alt_layout` / `#mac_layout` grid rules and the `.alt_panel` / `#alt_hex_panel` / `#alt_tags_panel` / `#mac_hex_panel` / `#mac_content_panel` / `#alt_actions_panel` panel rules.
3. `tests/test_tui_directionb.py` — added the increment-6 block (13 tests): TC-019 (A2L two-pane fixed regime at 120×30 + 160×40, proportional at 80×24, pane order), TC-021 (MAC equivalents), TC-020 (A2L renderers populate / filtering narrows / paging advances / jump-to-address through the restyled screen), TC-022 (MAC equivalents); module docstring extended to increments 2-6.

**Documentation:**
- `.dev-flow/2026-05-20-batch-02/03-increments/increment-006.md` — this review packet.

## 3. How to test

```bash
# 1. Static check (ruff is NOT installed in this environment — py_compile substituted)
python -m py_compile s19_app/tui/app.py tests/test_tui_directionb.py

# 2. Import smoke
python -c "import s19_app.tui"

# 3. The new increment-6 tests only
python -m pytest -q tests/test_tui_directionb.py -k "tc019 or tc020 or tc021 or tc022"

# 4. Full suite — must not regress from the 314/2/3/0 baseline
python -m pytest -q
```

An additional `App.run_test()` smoke (run ad-hoc, see §4) loads the public `examples/case_01_basic_valid/` S19+A2L+MAC triple, drives both restyled screens at a fixed-regime (130×35) and a proportional-regime (90×26) size, and asserts the hex-pane widths plus A2L filtering and MAC table population.

## 4. Test results

**`python -m py_compile s19_app/tui/app.py tests/test_tui_directionb.py`** — actual output:
```
PY_COMPILE OK
```
Note: `ruff` is **not installed** in this environment; per the increment instructions `python -m py_compile` was substituted as the static check and passes.

**`python -c "import s19_app.tui"`** — actual output:
```
IMPORT s19_app.tui OK
```

**New increment-6 tests** — `python -m pytest -q tests/test_tui_directionb.py -k "tc019 or tc020 or tc021 or tc022"` — actual output:
```
.............
13 passed, 26 deselected in 9.63s
```

**Full suite** — `python -m pytest -q` — actual output (tail):
```
327 passed, 2 skipped, 3 xfailed in 125.91s (0:02:05)
```
Baseline was **314 passed / 2 skipped / 3 xfailed / 0 failed**. The 13 new increment-6 tests bring the total to **327 passed** (314 + 13); skipped/xfailed counts and the 0-failed verdict are unchanged — **no regression**.

**`App.run_test()` end-to-end smoke** (public `case_01_basic_valid/` S19+A2L+MAC fixture) — actual output:
```
FIXED 130x35: a2l_tags=66 a2l_hex=40 mac_rec=66 mac_hex=40 mac_rows=2 a2l_filter 3->0
NARROW 90x26: body=84 a2l_hex=29(34.5%) mac_hex=29(34.5%)
SMOKE OK
```
Both restyled screens render at the correct two-regime widths — hex panes are exactly 40 columns in the fixed regime and 34.5% of the body in the proportional regime (within the 35%±4 tolerance) — the MAC records table populates, and A2L name-filtering narrows the tag set 3→0 through the restyled A2L screen. The smoke temp directory was removed afterward.

## 5. Risks

- **Pane-width tolerances are wider than the Workspace tests.** TC-019/TC-021 assert the proportional hex pane at `35% ±4` points (not `±3`). Textual's percentage layout rounds against the body width *after* the activity rail / borders are subtracted, so at the 80×24 minimum the integer rounding is coarser than the Workspace side panes. The `±4` band still firmly rejects a regime swap (a fixed-40 pane at body≈84 would read ≈48%, far outside the band) and a `1fr`/`35%` mix-up. Verified at 80×24 and 90×26.
- **`.db-pane` class now shared with Workspace panes.** The four new A2L/MAC panes carry `db-pane` for `border`/`background`/`padding`. The density rules (`#workspace_body.density-* #workspace_panes .db-pane`) are scoped to `#workspace_panes` descendants, so they do **not** retune A2L/MAC pane padding — by design, A2L/MAC density tuning was never in this increment's scope. If a later increment wants density-aware A2L/MAC padding it must add `#a2l_panes` / `#mac_panes`-scoped rules; it is not a silent regression.
- **Hex pane at narrow widths is tight.** A fixed 16-byte hex row needs more than ~29 columns to render without internal wrap; at 80×24 the 35% hex pane (~29 cols incl. border) will wrap/clip hex rows. This is inherent to the two-regime spec at the minimum supported size and matches the pre-batch behaviour band — the renderer itself (`render_hex_view_text`, `MAX_HEX_*` caps) is untouched — so it is a layout-density tradeoff, not a new defect.
- **No visual/interactive verification.** All checks are headless (`App.run_test()` / `pytest`). Real-terminal rendering (border glyphs, focus traversal order across the new pane nesting, mouse hit-testing on the relocated buttons) was not eyeballed. The `db-pane` border and the `.hidden` filter-menu overlay are reused verbatim, lowering this risk, but a manual TUI pass is advisable before batch close.

## 6. Pending items

- **Manual TUI pass** — launch `s19tui --load examples/case_01_basic_valid/firmware.s19`, switch to the A2L Explorer (key `2`) and MAC View (key `3`), resize across the 120-column breakpoint, and confirm the panes, the filter-menu overlay, buttons and hex viewers render and respond correctly. Deferred to the Phase-4 validation gate.
- **REQUIREMENTS.md traceability** — if an `R-*` row maps to the A2L Explorer / MAC View layout, its file/test references and status should be refreshed to cite `test_tui_directionb.py` TC-019..TC-022. Not done here (out of the 3-file scope; flagged for the docs increment).
- **A2L/MAC density tuning** — the `db-pane` class gives base padding only; no Comfortable/Compact variant for the A2L/MAC panes. Open as a follow-up only if the batch spec calls for it.

## 7. Suggested next task

**Increment 7 — Issues Report screen (`#screen_issues`) + dismantle `#workspace_carryover`.** Promote the Issues `DataTable` + `#validation_issues_filters` + `#validation_issues_summary` subtree (and re-home the `status_text` / `project_text` / `a2l_text` / `progress_bar` / `log_line_*` widgets) out of the hidden `#workspace_carryover` container created in increment 5 into a real `#screen_issues` rail screen, then remove the carry-over container. This closes the increment-5 carry-over debt and gives the Issues rail screen its real content. Keep `update_validation_issues_view` / `set_status` / `update_project_labels` renderers wiring intact — composition + CSS only, as in increments 5-6.

**Do not start increment 7 — this increment (6) is complete and stops here.**
