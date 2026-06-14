# Increment I4 — A↔B Diff screen completion (HLR-005)

Batch 2026-06-11-batch-09 · Phase 3 · the large TUI increment. Completes the
`AbDiffPanel` rail-screen placeholder into the real comparison surface, routed
through `compare_service` (I2) + `diff_report_service` (I3).

## 1. What changed

Replaced the static three-column placeholder `AbDiffPanel`
(`screens_directionb.py`) with the completed A↔B Diff surface: an INLINE
image-pair selection row (G-6 — two variant `Select` dropdowns + two
external-path `Input`s + Compare/Report buttons + a no-project destination
`Input`), a panel-owned status line (`#diff_status`, untruncated — distinct
from the app's 50-char rolling log), and the three result columns (reused ids
`#diff_range_list` / `#diff_hex_a` / `#diff_hex_b`) now rendering the
Rich-coloured classified run list (with per-image artifact-usage summaries) and
bounded hex windows of image A and image B for the selected (first) run. The
panel is presentational only: it posts `CompareRequested` / `ReportRequested`
messages; the app handlers (`on_ab_diff_panel_compare_requested` /
`on_ab_diff_panel_report_requested`) route ALL computation through
`compare_service.compare_images` and `diff_report_service.generate_diff_report` /
`generate_diff_report_html` — `app.py` performs no run classification, no
coverage count, no report content (LLR-005.1). The relocated DISPLAY caps
(`DISPLAY_MAX_RUNS=128`, `DISPLAY_MAX_TOTAL_BYTES=2_097_152`, G-9) bound only the
on-screen run list; the persisted report files (I3) stay complete. Failures
(refused comparison / refused report) surface in the status line and the screen
keeps running (LLR-005.3 / 005.4). The 5 placeholder-pinned tests were
superseded; 6 NEW HLR-005 tests added in a dedicated `tests/test_tui_diff_screen.py`.

## 2. Files modified

| File | Purpose |
|---|---|
| `s19_app/tui/screens_directionb.py` | Replace placeholder `AbDiffPanel` with the inline selection + service-routed + Rich-render + display-capped panel; new `CompareRequested` / `ReportRequested` messages, `set_variants` / `set_status` / `render_comparison` / `has_comparison` / `mem_map_a/b`. Add `Select` import. |
| `s19_app/tui/app.py` | Import compare/diff-report services; `_prefill_diff_variants`, `_diff_image_source`, `on_ab_diff_panel_compare_requested`, `_diff_load_maps`, `on_ab_diff_panel_report_requested`; wire prefill into `action_show_screen("diff")`; `_diff_last_result` init; update `_compose_screen_diff` docstring (still builds only `{Container, Label, AbDiffPanel}`). |
| `s19_app/tui/styles.tcss` | Remove obsolete `#diff_deferral_notice` rule; add layout rules for `#diff_select_row_a/b`, `#diff_action_row`, `.diff-field-label`, `#diff_status`. |
| `tests/test_tui_directionb.py` | Supersede the 5 placeholder-pinned tests (rewrite to the new behavior). |
| `tests/test_tui_diff_screen.py` (NEW) | 6 HLR-005 pilots (TC-021..024, TC-029) matching the spec's executed-verification path. |

Exactly 5 files. (`.dev-flow/state.json` was modified at batch start, not by I4.)

Line deltas (vs HEAD, `git diff --numstat`): screens_directionb.py +437/−46;
app.py +249/−7; styles.tcss +20/−4; test_tui_directionb.py +91/−77;
test_tui_diff_screen.py +306 (new, untracked).

## 3. How to test

```
# R-8 supersession pre-state (run BEFORE rewrite — see §R-8 table)
python -m pytest -q tests/test_tui_directionb.py -k "tc027 or (tc028 and activates)"

# Superseded placeholder tests (post-rewrite, must pass)
python -m pytest -q tests/test_tui_directionb.py -k "tc027 or tc028"

# New HLR-005 pilots
python -m pytest -q tests/test_tui_diff_screen.py

# Service regression (I1/I2/I3 unchanged)
python -m pytest -q tests/test_compare_engine.py tests/test_compare_service.py tests/test_diff_report_service.py

# Lean suite
python -m pytest -q -m "not slow"

# Collection balance
python -m pytest -q --collect-only

# Probes
python -m pytest -q tests/test_tui_directionb.py -k "diff_renderer"      # AST guard green
python -m pytest -q tests/test_tui_variants.py -k "parse_loaded_file"    # no new call site
```

## 4. Test results (actual)

- **R-8 pre-state** (placeholder tests vs completed panel): `4 failed, 1 passed`
  (predicted 5 — see §R-8 deviation). The AST guard
  `test_tc028_diff_renderer_invokes_no_diff_logic` stayed **GREEN**.
- **Superseded tests** `tests/test_tui_directionb.py -k "tc027 or tc028"`:
  `14 passed`.
- **New HLR-005 pilots** `tests/test_tui_diff_screen.py`: `6 passed`.
- **Service regression**: `43 passed` (11 engine + 12 service + 20 report).
- **Full `test_tui_directionb.py`**: `98 passed`.
- **Lean `-m "not slow"`**: `729 passed, 29 skipped, 21 deselected, 3 xfailed`,
  **0 failures**.
- **Collection `--collect-only`**: `782 tests collected`.
- **Probes**: named-constant probe
  `rg '_RANGE_LIST_PLACEHOLDER|_HEX_A_PLACEHOLDER|_HEX_B_PLACEHOLDER|DEFERRAL_TEXT' screens_directionb.py`
  → **0 hits** (the 4 diff constants removed); AST guard
  `test_tc028_diff_renderer_invokes_no_diff_logic` → **green**; rail unchanged
  `git diff --stat HEAD -- s19_app/tui/rail.py` → **empty**;
  `_parse_loaded_file` call-site guard (`test_tui_variants`) → **green**;
  `diff_mem_maps` absent from both `screens_directionb.py` and `app.py`
  (service-route confirmed); `compare_images(` present in `app.py`.

### Signed balance (off the measured 776 in this worktree)

`post = 776 − D + A = 776 − 3 + 9 = 782` ✓ (matches `--collect-only`).
- **D = 3** (delete-and-replace): the three TC-027 placeholder functions below.
- **A = 9**: 3 rewritten TC-027 (new names) + 6 NEW HLR-005 pilots.
- **rewrite-in-place (0/0)**: `test_tc027_ab_diff_renders_three_columns`,
  `test_tc028_every_scaffold_screen_activates_without_error`.

> Note: the draft ledger cited a measured baseline of 733 (probe P-01) and 776
> "collection". This worktree measures **776** at HEAD pre-I4 (recorded), so the
> balance is taken off 776 per the spec's "MEASURED baseline" rule.

## R-8 disposition table

| Test (`tests/test_tui_directionb.py`) | Predicted red? | Actual pre-state | Disposition | Rewritten to |
|---|---|---|---|---|
| `test_tc027_ab_diff_renders_three_columns` (:3389) | yes | **passed** (deviation) | rewrite-in-place (no behavioral edit; docstring only) | asserts the three result columns still present (true of the new panel) |
| `test_tc027_ab_diff_columns_carry_static_placeholder_rows` (:3415) | yes | failed | delete-and-replace | `test_tc027_ab_diff_has_no_placeholder_constants` — asserts the 4 placeholder constants are GONE (LLR-005.2 probe as unit test) |
| `test_tc027_ab_diff_states_diff_deferred_and_has_no_second_file_load` (:3446) | yes | failed | delete-and-replace | `test_tc027_ab_diff_renders_inline_selection_surface` — asserts the inline `Select`/`Input`/Compare surface (G-6/LLR-005.1) |
| `test_tc027_ab_diff_panel_holds_no_loaded_file_data` (:3485) | yes | failed | delete-and-replace | `test_tc027_ab_diff_panel_routes_through_service` — asserts `CompareRequested`/`ReportRequested`/`render_comparison` present and no embedded engine/report helper |
| `test_tc028_every_scaffold_screen_activates_without_error` (:3639) | yes | failed | rewrite-in-place | drops the `#diff_deferral_notice` marker; asserts `#diff_status` present, deferral notice ABSENT, patch empty-state present, all four screens activate |

**Deviation (loud):** predicted-red set was FIVE; actual is FOUR — 
`test_tc027_ab_diff_renders_three_columns` stayed GREEN because the completed
panel correctly reuses the same three column ids (`#diff_range_list` /
`#diff_hex_a` / `#diff_hex_b`), so its assertion ("three columns present") is
already true of the new behavior. It is treated as a rewrite-in-place (the
intent shifted from "placeholder shell" to "result columns"; the assertion is
unchanged because it was always id-presence). The AST guard
`test_tc028_diff_renderer_invokes_no_diff_logic` stayed green as designed — all
new widgets live inside `AbDiffPanel.compose`, not in `_compose_screen_diff`.

## Per-HLR-005-TC status

| TC | LLR | Node id | Status |
|---|---|---|---|
| TC-021 | LLR-005.1 | `test_tui_diff_screen.py::test_tc021_compare_routes_through_service` | PASS — spy `compare_images` invoked exactly 1×; render reflects injected result |
| TC-022 | LLR-005.2 | `::test_tc022_render_shows_runs_and_hex_windows` | PASS — run list + per-image hex windows + artifact summary |
| TC-023 | LLR-005.3 | `::test_tc023_refused_compare_surfaces_diagnostic` | PASS — refusal diagnostic in status, screen running |
| TC-024 | LLR-005.4 | `::test_tc024_report_trigger_surfaces_paths` | PASS — both .md + .html filenames (regex-matched) in status |
| TC-024 | LLR-005.4 | `::test_tc024_report_trigger_invalid_dest_refused` | PASS — refusal diagnostic, 0 files |
| TC-029 | LLR-005.2 (G-9) | `::test_tc029_display_caps_bound_on_screen_runs` | PASS — display ≤128 runs; header reports COMPLETE count + "showing N of M" |

## A-3 — actual node ids vs provisional spec

Spec named `tests/test_tui_diff_screen.py` (provisional node ids). Realized:
`test_tc021_compare_routes_through_service`, `test_tc022_render_shows_runs_and_hex_windows`,
`test_tc023_refused_compare_surfaces_diagnostic`, `test_tc024_report_trigger_surfaces_paths`,
`test_tc024_report_trigger_invalid_dest_refused` (TC-024 split into success +
invalid-dest), `test_tc029_display_caps_bound_on_screen_runs`. The superseded
placeholder tests stayed in `tests/test_tui_directionb.py` (their native suite).

## 5. Risks

- **Run selection is first-run-only.** LLR-005.2 says "for the selected run";
  the range list is a `Static` overview and the hex columns auto-show the FIRST
  run. The exact selection widget was `assumed — verify in Phase 3`; a fully
  interactive run picker (DataTable/ListView) is a natural follow-up. Recorded
  as a design decision, not a defect.
- **`_diff_load_maps` re-parses by path** for the on-screen hex windows and the
  report (the service returns runs, not maps). An image unreadable at report
  time yields an empty window (non-fatal). This is a second parse of the same
  files the service already parsed — acceptable for a manual TUI action; not on
  any hot path.
- **External-path comparison from the panel** resolves against `self.base_dir`
  (the app cwd), matching the read-side `resolve_input_path` convention.
- The relocated display caps are panel constants (not imported from
  `report_service`) to keep the view decoupled; they mirror the report values
  by intent — if the report caps change, update both (noted in the docstring).

## 6. Pending items

- Interactive per-run selection (DataTable/ListView) — deferred (see Risks).
- The draft-ledger 733-vs-776 baseline discrepancy is recorded for the Phase-4
  reconciliation; the signed balance is taken off the measured 776.
- No `REQUIREMENTS.md` R-* update this increment (that registry is updated at
  Phase 6 per the batch convention).

## 7. Suggested next task

Phase 4 validation: run the full suite including `-m slow` (TC-006 perf budget,
CI-regime confirm per LLR-001.5) and reconcile the §5.2 coverage table +
§5.3 signed-balance against this disposition table; then the batch-09 close /
post-mortem.
