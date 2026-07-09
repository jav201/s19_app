# Increment 004 — Retire the hidden `#validation_issues_list` DataTable (LLR-043.R1–.R7)

**Scope:** The removal. Delete the `display:none` legacy Issues `DataTable` and fix everything
that breaks, atomically, so `GroupedIssuesPanel` is the sole Issues surface. Product code
(`app.py` + `styles.tcss`) + the invert/retire of the DataTable-specific tests. The load-worker
`precompute_issue_datatable_payload` calls + caches are LEFT in place (dead-written, R-043-3).

## 1. What changed

**Product (`s19_app/tui/app.py`, `s19_app/tui/styles.tcss`):**
- **LLR-043.R1** — removed the `DataTable(id="validation_issues_list", …)` yield + its adjacent
  compat comment from `_compose_screen_issues`; `GroupedIssuesPanel(#validation_issues_groups)` is
  now the sole child of `#issues_list_stack` (wrapper id kept). Compose docstring (Returns /
  Data Flow) updated to drop the DataTable.
- **LLR-043.R2** — removed the `#validation_issues_list {…}` rule and the
  `#issues_columns #validation_issues_list { display:none }` rule + its compat comment from
  `styles.tcss`. `#validation_issues_summary` + all `.issue-*` grouped rules (incl. the Inc2
  `.issue-related`) preserved.
- **LLR-043.R3** — removed the `#validation_issues_list` column-init try/except; MAC + A2L
  column-init blocks untouched.
- **LLR-043.R4** — stripped the DataTable query/clear/populate + `_issue_row_key_to_index` reset +
  the `use_precomputed`/`_populate_issues_datatable(...)` block from `update_validation_issues_view`;
  kept the summary computation + `.update(...)` and BOTH `_render_validation_issues_groups()` calls
  (empty + populated paths). Removed the orphaned `_populate_issues_datatable` helper. Docstring
  (Summary / Data Flow / Dependencies) rewritten to the grouped-panel-only contract.
- **LLR-043.R5** — removed the `validation_issues_list` branch from `on_data_table_row_selected`,
  the `_issue_row_key_to_index` attribute, and the now-unreachable
  `_jump_to_validation_issue_by_index` method. Updated `on_data_table_row_selected`'s Data Flow /
  Dependencies docstring (dropped the removed path) and `_jump_to_validation_issue_object`'s
  `Used by` list. MAC + A2L branches preserved.
- Trailing stale references scrubbed so `#validation_issues_list` no longer appears in `s19_app/`:
  the `on_list_view_highlighted` comment, and the `_render_validation_issues_groups` docstring
  ("two surfaces stay in lock-step" / "DataTable-only unit tests").
- `DataTable` import **kept** — still used by the MAC + A2L tables (`on_data_table_row_selected`
  signature, column init, `query_one`).

**Tests — invert/retire the DataTable-specific tests:**
- `test_tui_directionb.py`: inverted `test_tc023_issues_table_is_primary_content` →
  `test_tc023_grouped_panel_is_primary_content_of_screen_issues` (asserts DataTable **absent** +
  `GroupedIssuesPanel` is the primary descendant). Added **AT-043a/b/c**. `_seed_issue_objects`
  docstring corrected (no longer "renders both the DataTable and the grouped panel").
- `test_tui_app.py`: census #4 (empty), #5 (paging-large → summary + window-bounds), #6
  (paging-actions), #8 (dispatches-by-id) re-pointed; #7 (worker-precomputed-cells) **retired**;
  #9 `_query_issues_panel_codes` re-pointed to `str(chip.render())` over `.issue-code-chip`.
  **Extra (census gap):** `test_populate_issues_datatable_records_filtered_index` **retired** — it
  directly exercised the now-removed `_populate_issues_datatable`. **Extra (shared-helper
  collateral):** `TestCrossFileCompatibilityPanelRender._drive_panel` now seeds one representative
  real issue per distinct code so every emitted code renders under the grouped panel's
  `_GROUP_DISPLAY_MAX=40` cap (the error group otherwise floods with `MAC_PARSE_ERROR`).
- `test_tui_issues_view.py`: census #1 — the unused `DataTable` import / stray `query_one` were
  already gone (Inc2); corrected three stale docstrings that said the DataTable is `display:none`.

**Trailing-reference doc fix (6th file, see Deviation):** `s19_app/tui/issues_view.py:7` docstring
said the DataTable is "retained beside them" — corrected to "fully retired … sole Issues surface"
so the grep-clean gate passes and the docstring is not false.

## 2. Files modified
1. `s19_app/tui/app.py` — LLR-043.R1/R3/R4/R5 + trailing-reference scrub.
2. `s19_app/tui/styles.tcss` — LLR-043.R2.
3. `tests/test_tui_directionb.py` — invert census #10; add AT-043a/b/c.
4. `tests/test_tui_app.py` — census #4/#5/#6/#8 re-point, #7 + orphan retire, #9 re-point,
   `_drive_panel` dedup-by-code.
5. `tests/test_tui_issues_view.py` — census #1 doc corrections.
6. `s19_app/tui/issues_view.py` — 1-line docstring correction (trailing reference; **deviation**).

## Census-row → disposition map
| # | File · test | Disposition (Inc4) |
|---|---|---|
| 1 | issues_view · `_select_issue_row` / AT-020a | import/stray already gone (Inc2); 3 stale docstrings corrected |
| 4 | app · empty-issues | dropped `#validation_issues_list` fake-`query_one` branch; summary assertion kept |
| 5 | app · pages-large | mounted-row/`issue:`-key assertion retired → summary line + `_get_window_bounds` |
| 6 | app · paging-actions | dropped fake table branch; `window_start` assertion kept |
| 7 | app · worker-precomputed-cells | **retired** (reuse path gone) |
| 8 | app · dispatches-by-id | dropped `"issue":2` + `_issue_row_key_to_index` seed; mac+a2l kept |
| 9 | app · `_query_issues_panel_codes` + snapshot-harness | re-pointed to `.issue-code-chip` render |
| 10 | directionb · tc023 primary-content | **inverted** (AT-043a home) |
| 11 | directionb · tc023 not-nested-in-workspace | holds trivially (table gone); unchanged |
| — | app · `test_populate_issues_datatable_records_filtered_index` | **retired** (census gap — tests removed helper) |
| — | app · `TestCrossFileCompatibilityPanelRender._drive_panel` | dedup-by-code (shared-helper collateral of #9) |

Census rows #12–#18 were already migrated in Inc3 (they read the grouped panel / `#a2l_tags_list`
and stay green post-removal — verified below).

## LLR → change map
| LLR | Change |
|---|---|
| R1 | `_compose_screen_issues`: DataTable + comment removed; docstring updated |
| R2 | `styles.tcss`: both rules + comment removed |
| R3 | column-init try/except removed |
| R4 | `update_validation_issues_view` DataTable path + `_populate_issues_datatable` removed; grouped calls kept |
| R5 | `on_data_table_row_selected` issues branch + `_issue_row_key_to_index` + `_jump_to_validation_issue_by_index` removed; docstrings updated |
| R6 | (by-retention) `IssueRow` code-chip + `.issue-detail` markup-safety, hex pane, paging, summary, `_GROUP_DISPLAY_MAX` unchanged — recolor/AT-039 suites green |
| R7 | engine-frozen diff 0 (below) |
| R8 | (Inc2) `.issue-related` node — untouched here |

## 3. How to test
```
python -m pytest tests/test_tui_directionb.py tests/test_tui_app.py tests/test_tui_issues_view.py \
    tests/test_tui_a2l_issue_recolor.py tests/test_validation_service_supplemental.py -q
python -m ruff check s19_app/tui/app.py s19_app/tui/issues_view.py \
    tests/test_tui_directionb.py tests/test_tui_app.py tests/test_tui_issues_view.py
python -m pytest tests/test_engine_unchanged.py -q
git diff --stat main -- s19_app/core.py s19_app/hexfile.py s19_app/range_index.py \
    s19_app/validation s19_app/tui/a2l.py s19_app/tui/mac.py s19_app/tui/color_policy.py
```

## 4. Test results
- `test_tui_app.py` + `test_tui_issues_view.py`: **66 passed, 1 xfailed** (18.2 s).
- `test_tui_directionb.py` + `test_tui_a2l_issue_recolor.py` + `test_validation_service_supplemental.py`:
  **174 passed** (116 s).
- Combined verify set: **240 passed, 1 xfailed, 0 failed**.
- `test_engine_unchanged.py`: **1 passed** (0 frozen diffs).
- Ruff: **All checks passed!** (5 python files).
- Snapshot suite (`test_tui_snapshot.py`): **14 passed, 20 xfailed, 0 errors** — the 20 xfailed are
  the pre-existing batch-28 `xfail(strict=False)` cells absorbing the drift; no ERROR, no unexpected
  fail. Local textual is unpinned (≠ 8.2.8) so **no regen** (FORBIDDEN locally). See snapshot
  disposition.
- First TC-065.b–f run failed (grouped panel's 40-cap dropped the sparse cross-codes behind a flood
  of `MAC_PARSE_ERROR`); fixed by the `_drive_panel` dedup-by-code re-seed; re-run green.

## Frozen-diff confirmation
`git diff --stat main -- <frozen set>` → **EMPTY** (0 lines). Grep of `s19_app/` for
`validation_issues_list` → **no source hits** (only a gitignored `__pycache__/*.pyc` from a prior
compile). Engine-frozen guard `test_engine_unchanged.py` passes.

## Ledger delta
Baseline (Inc3 tip) **1181**. Per-file test-count delta vs the pre-Inc4 tree:
- `test_tui_directionb.py`: 155 → 158 = **+3** (AT-043a/b/c)
- `test_tui_app.py`: 65 → 63 = **−2** (retired worker-precomputed-cells + orphan `_populate_issues_datatable` test)
- `test_tui_issues_view.py`: 4 → 4 = **0** (docstring-only)

**Signed math:** +3 (AT-043a/b/c) −1 (worker-precomputed-cells) −1 (`_populate_issues_datatable`
orphan) = **+1** → **1181 → 1182**.

*Deviation from task's stated expectation (+2 = −worker-precomputed +AT-043a/b/c):* the additional
−1 is `test_populate_issues_datatable_records_filtered_index`, a census-missed white-box test that
directly called the removed `_populate_issues_datatable` and would otherwise AttributeError. Its
removal is mandatory, not discretionary.

## Snapshot disposition
DataTable was `display:none` (zero layout) → removal is SVG-neutral within the existing batch-28
xfail envelope. Snapshot run showed **0 ERROR** (no collection/compose-subtree crash) and the 20
mismatches are all already-`xfail(strict=False)` Issues cells. Per the "if a cell ERRORS mark
xfail, else touch nothing" rule: **touched nothing** in `test_tui_snapshot.py`. Canonical-CI regen
(pinned `textual==8.2.8`) remains the operator's follow-up; local regen FORBIDDEN.

## 5. Risks
- **R-043-3 (as designed):** `precompute_issue_datatable_payload` (app.py:752) is still invoked by
  the load worker (app.py:6525 / :7037) and its caches (`_validation_issue_cell_rows` /
  `_validation_issue_cell_styles`, written at :6219/:6314/:6526/:6831) are now **dead-written every
  load, never read**. Left in place deliberately (surgical); retiring them is the named follow-up
  batch scope.
- **`_drive_panel` dedup-by-code (new):** the TC-065.b–h panel-render tests now observe one
  representative real issue per code (not the full report) because the grouped panel caps at 40
  rows. Faithful — each assertion still checks that the engine-emitted code co-renders as a real
  `IssueRow` through the shipped surface — but it no longer proves "all N instances render" (which
  the 40-cap makes impossible and which was a DataTable-era property). If distinct-code count ever
  exceeds 40 the test fails loudly, not vacuously.
- **Async-removal double-count trap (Inc3 carry):** every new `query(IssueRow)`/chip count in
  AT-043a/b awaits `pilot.pause()` after the triggering render.

## 6. Pending items
- Follow-up batch: retire the worker `precompute_issue_datatable_payload` calls + the dead-written
  caches (R-043-3), and the `test_tc021_precompute_payload_emits_related_cell` /
  `test_precompute_issue_datatable_payload_emits_eight_columns_and_styles` formatter TCs that pin
  them.
- Canonical-CI snapshot regen (pinned textual 8.2.8) to clear the 20 batch-28 xfail Issues cells.

## 7. Suggested next task
Phase 4 (validation) — run the full suite headless for the batch ledger, confirm dual traceability
(AT-043a/b/c + AT-021 + AT-043-c17 all green through the shipped grouped surface), then Phase 5/6
(post-mortem + docs) and the PR.

## Evidence checklist
- [✓] Tests/type checks/lint pass — 240 passed / 1 xfailed (verify set); ruff clean; engine-unchanged 1 passed. Evidence: §4.
- [✓] No secrets in code or output — synthetic fixtures + public `case_04`/`large_project` only.
- [✓] No destructive commands run — read/pytest/ruff/git-diff/grep only.
- [✓] File count — 5 named files + 1 trailing-reference doc-only fix in `issues_view.py` (already
  in the modified set); disclosed as a deviation, required for the grep-clean gate.
- [✓] Review packet attached — this file.
- [✓] Frozen diff 0 — `git diff --stat main -- <frozen set>` empty; grep `s19_app/` clean.
- [✓] Worker precompute + caches LEFT in place (R-043-3) — verified at app.py:752/6525/7037 + cache writes.
