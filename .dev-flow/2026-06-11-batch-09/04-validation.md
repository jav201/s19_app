# Phase 4 — Validation Report — s19_app — Batch 2026-06-11-batch-09 (US-006 hex compare)

> **Agent:** qa-reviewer. **Date:** 2026-06-13. **Worktree:** `claude/competent-clarke-1e8940`, branch `claude/batch-09`.
> **Run ownership (A-6):** qa-reviewer owns the per-TC targeted matrix + all inspections. The FULL suite (incl. `slow`) and the lean suite are ORCHESTRATOR-OWNED — those §5.3 rows are left as `ORCHESTRATOR-OWNED` placeholders below.
> **Environment:** Windows 11 Pro 10.0.26200, Python 3.14.4 (local repo venv), OneDrive-synced worktree, `pytest` with `-p no:randomly`. (CI regime = ubuntu / Python 3.11; the slow-suite CI confirmation is an orchestrator row.)
> **Discipline:** every result below was EXECUTED; commands + outputs recorded. No code/tests/requirements modified. The HTML probe scratch was deleted after use.

---

## 0. Executive verdict

**PASS-WITH-NOTES** (excluding orchestrator-owned rows).

- 29/29 TCs PASS (49 collected items across the 4 new test files + the directionb supersession/guard set; all green).
- All 26 LLRs covered and their numeric thresholds verified MET by source inspection.
- All inspections PASS (purity, no-logging, HTML-safety, G-4/rail non-edit, G-8/M-4 resolver, M-5 collision, R-8 supersession, service-route, package-root guards, parse-loaded-file guard).
- Signed-balance reconciled exactly: `782 = 733 − D(3) + A(52)`.
- The NOTES are doc-reconciliation items (DEV-1 node-id drift: HLR/LLR Executed-verification lines cite a `test_diff_report.py` file that was implemented as `test_diff_report_service.py`, and the per-LLR `-k` keyword selectors are provisional and do not all match implemented `-k` filters) and the I4 predicted-red reconciliation (predicted 5, actual disposition = 3 delete-and-replace + 2 rewrite-in-place). None is a code/behavior defect; all routed to Phase 6 as DEV-N.

---

## 1. Per-requirement pass/fail matrix (HLR → LLR → TC → node id → result → evidence)

Provisional node ids from §4/§5 were placeholders (batch-08 A-3). The implemented node ids below were collected from the real tree; the test→TC→LLR map is taken from each test file's module docstring. Provisional→implemented drift is recorded as DEV-1/DEV-2 (Phase-6 doc reconciliation), NOT a failure.

### HLR-001 — Byte-run comparison engine — file `tests/test_compare_engine.py` — **PASS** (11 passed in 1.44s)

| LLR | TC | Implemented node id | Result | Runtime | Threshold met (evidence) |
|---|---|---|---|---|---|
| LLR-001.2 | TC-001 | `test_classification_set_equality` | PASS | <5ms | per-address reconstruction == brute force, set equality 0 mismatches |
| LLR-001.2 | TC-001 | `test_classification_set_equality_random` | PASS | <5ms | randomized set-equality (extra hardening) |
| LLR-001.2 | TC-002 | `test_adjacency_merge_same_kind_merges` | PASS | <5ms | same-kind adjacency merges into one run |
| LLR-001.2 | TC-002 | `test_adjacency_change_forces_boundary` | PASS | <5ms | classification change forces run boundary |
| LLR-001.2 | TC-003 | `test_boundary_cases` | PASS | <5ms | run at addr 0, touching runs of different kinds, single-byte runs, interleaved gaps |
| LLR-001.3 | TC-004 | `test_identity_empty_and_equal` | PASS | <5ms | identical/empty maps ⇒ exactly 0 runs |
| LLR-001.3 | TC-004 | `test_determinism_repeated_calls` | PASS | <5ms | double-call outputs compare `==` |
| LLR-001.4 | TC-005 | `test_stats_byte_count_equals_run_lengths` | PASS | <5ms | `byte_count[kind] == sum(end-start)` 0 mismatches |
| LLR-001.4 | TC-005 | `test_stats_run_counts_match` | PASS | <5ms | per-kind run count matches |
| LLR-001.3/.4 | TC-005 | `test_symmetry_swap_only_a_only_b` | PASS | <5ms | swap A/B ⇒ only_a↔only_b symmetry |
| LLR-001.5 | TC-006 | `test_large_image_perf` (`@pytest.mark.slow`) | PASS | **1.39s** | `assert elapsed <= 2.0` (test:279); MEASURED 1.39s < 2.0s budget. CI-regime confirmation = ORCHESTRATOR-OWNED (slow-suite timing). |
| LLR-001.1 | — (inspection) | rg purity probe | PASS | — | see §2.1 |

### HLR-002 — Comparison sources + service seam — file `tests/test_compare_service.py` — **PASS** (12 passed in 0.54s)

| LLR | TC | Implemented node id | Result | Threshold met (evidence) |
|---|---|---|---|---|
| LLR-002.1 | TC-007 | `test_module_imports_no_textual` | PASS | in-process mirror of the rg purity probe; 0 Textual symbols |
| LLR-002.2 | TC-007 | `test_variant_pair_matches_engine` | PASS | variant-pair run output == engine over independently-parsed maps, 0 mismatches |
| LLR-002.2 | TC-007 | `test_variant_pair_reports_real_diff` | PASS | real difference surfaced (extra coverage of LLR-002.2) |
| LLR-002.3 | TC-008 | `test_external_unresolvable_returns_refused` | PASS | refused result, ≥1 diagnostic carrying the input string, no exception |
| LLR-002.3 | TC-008 | `test_external_resolved_pair` | PASS | resolved external pair compares (positive control for 002.3) |
| LLR-002.4 | TC-009 | `test_mixed_source_pairings_record_identity` | PASS | all three pairings; image metadata matches requested sources, 0 mismatches |
| LLR-002.5 | TC-010 | `test_parse_failure_isolated_to_refused` | PASS | parse exception captured as diagnostic on refused result; no raised exception |
| LLR-002.6 | TC-011 | `test_result_field_set_matches_c9_contract` | PASS | `dataclasses.fields == {image_a,image_b,runs,stats,notes,diagnostics,refused}` (test:283-293) — 0 missing, 0 extra; matches §6.2 C-9 |
| LLR-003.1 | TC-012 | `test_artifact_context_applies_to_external` | PASS | external image inside 1-A2L+1-MAC project receives 2 of 2 notes |
| LLR-003.2 | TC-013 | `test_coverage_counts_match_hand_computed` | PASS | `usage.mac.covered == 3` hand-computed (test:358), 0 mismatches |
| LLR-003.3 | TC-014 | `test_usage_summary_all_four_outcomes` | PASS | BOTH / ONE_A2L / ONE_MAC / NONE all exercised (test:412-426), 4 of 4 |
| LLR-003.4 | TC-015 | `test_absent_artifacts_summary_none` | PASS | no-artifact comparison ⇒ summary NONE, statuses UNUSED, 0 exceptions |

### HLR-003 — Artifact-usage notes — TC-012..TC-015 (co-located in `tests/test_compare_service.py`) — **PASS** (covered above)

### HLR-004 — Diff report (Markdown + HTML) — file `tests/test_diff_report_service.py` — **PASS** (20 passed in 0.56s)

| LLR | TC | Implemented node id | Result | Threshold met (evidence) |
|---|---|---|---|---|
| LLR-004.1 | TC-016 | `test_filename_scheme_and_same_second_collision` | PASS | base + `-01` distinct, both match `DIFF_REPORT_FILENAME_REGEX` (test:168-171) |
| LLR-004.1 (M-5) | TC-016 | `test_collision_never_overwrites_existing_file` | PASS | pre-existing file byte-unchanged `== "PLANTED CONTENT"` (test:193), 0 overwrites |
| LLR-004.2 (G-4) | TC-017 | `test_self_contained_listing_newest_first` | PASS | `list_diff_reports` newest-first; `-01` newer of same-second group (test:218) |
| LLR-004.2 (G-4 NON-edit) | TC-017 | `test_report_service_regex_unedited` | PASS | shared `REPORT_FILENAME_REGEX` does NOT match diff names (test:234-235); separate scheme |
| LLR-004.3 | TC-018 | `test_report_sections_present_in_order` | PASS | header→stats→run-table→hex-windows in order; `"TRUNCATED" not in text` (test:284) |
| LLR-004.3 | TC-018 | `test_generation_is_deterministic_fixed_clock` | PASS | fixed-clock determinism |
| LLR-004.3 (G-9) | TC-026 | `test_markdown_file_is_complete_no_truncation` | PASS | large planted diff ⇒ `text.count("TRUNCATED") == 0` (test:331), all runs present |
| LLR-004.3 (cue) | TC-027 | `test_changed_run_emits_diff_fenced_block` | PASS | `"```diff" in text` (test:364); `-` lines carry `AA`, `+` lines carry `BB` (test:373-374) |
| LLR-004.4 (G-2) | TC-019 | `test_symbol_annotation_only_intersecting_run` | PASS | exactly the inside symbol annotated, 0 false positives |
| LLR-004.4 | TC-019 | `test_annotation_absent_without_context` | PASS | non-gating: raw binary run still reported with no context |
| LLR-004.5 (F-S-07) | TC-020 | `test_module_performs_no_logging` | PASS | mirrors the `getLogger\|import logging` rg probe (§2.2) |
| LLR-004.6 (G-8 valid) | TC-025 | `test_no_project_valid_directory_writes_one_file` | PASS | operator dir + existing ⇒ exactly 1 file with tool-generated name |
| LLR-004.6 (G-8 refuse) | TC-025 | `test_no_project_empty_path_refused[]` | PASS | empty path ⇒ 0 files, diagnostic, no exception |
| LLR-004.6 (G-8 refuse) | TC-025 | `test_no_project_empty_path_refused[   ]` | PASS | whitespace path ⇒ refused (parametrized 2nd id) |
| LLR-004.6 (G-8 refuse) | TC-025 | `test_no_project_nonexistent_dir_refused` | PASS | non-existent dir ⇒ refused, diagnostic names input |
| LLR-004.6 (M-5) | TC-025 | `test_no_project_collision_no_overwrite` | PASS | no-project branch ⇒ `-01` sibling, original `== "PLANTED"` (test:537), 0 overwrites |
| LLR-004.6 (M-4) | TC-025 | `test_no_sanitize_project_name_in_validator` | PASS | source probe confirms `sanitize_project_name` not used in the validator |
| LLR-004.7 (G-9 HTML) | TC-028 | `test_html_export_complete_and_safe` | PASS | 0 `<script>`, 0 external-resource matches, inline `style=`, `count("TRUNCATED")==0` (test:581) |
| LLR-004.7 (html.escape) | TC-028 | `test_html_escapes_embedded_payload` | PASS | escapable payload round-trips as `&lt;script&gt;` (test:618) |
| LLR-004.7 (regex/M-5) | TC-028 | `test_html_filename_scheme_and_collision` | PASS | `.html` base + `-01`, match `DIFF_REPORT_HTML_FILENAME_REGEX`, NOT shared regex (test:643-647) |

### HLR-005 — A↔B Diff screen completion — file `tests/test_tui_diff_screen.py` — **PASS** (6 passed in 4.04s)

| LLR | TC | Implemented node id | Result | Runtime | Threshold met (evidence) |
|---|---|---|---|---|---|
| LLR-005.1 | TC-021 | `test_tc021_compare_routes_through_service` | PASS | 0.55s | monkeypatched service entry invoked exactly once; rendered output reflects injected result |
| LLR-005.2 | TC-022 | `test_tc022_render_shows_runs_and_hex_windows` | PASS | 0.51s | run list + bounded A/B hex windows rendered |
| LLR-005.3 | TC-023 | `test_tc023_refused_compare_surfaces_diagnostic` | PASS | 0.54s | pilot observes status diagnostic; 0 unhandled exceptions |
| LLR-005.4 | TC-024 | `test_tc024_report_trigger_surfaces_paths` | PASS | 0.65s | success status carries `.md` + `.html` destination paths |
| LLR-005.4 | TC-024 | `test_tc024_report_trigger_invalid_dest_refused` | PASS | 0.69s | invalid-destination ⇒ 0 files written, diagnostic in status |
| LLR-005.2 (G-9) | TC-029 | `test_tc029_display_caps_bound_on_screen_runs` | PASS | 0.67s | over-cap comparison ⇒ bounded on-screen display while persisted file stays complete |

**TC count check:** 29 named TCs (TC-001..TC-029) — all covered and PASS. (TC-001..006 engine, 007..011 service, 012..015 artifact, 016..020 + 025 + 026..028 report, 021..024 + 029 screen.)

---

## 2. Inspections (command + output + regime)

### 2.1 Purity (LLR-001.1, LLR-002.1) — PASS
- `rg -c "textual|S19File|IntelHexFile" s19_app/compare.py` → **no match (exit 1) = 0 hits**. Regime: package-root headless module (P-10 regime). PASS (threshold 0).
- `rg -c "textual" s19_app/tui/services/compare_service.py` → **no match (exit 1) = 0 hits**. Regime: `tui/services/` module (P-11 regime). PASS.
- `rg -c "textual" s19_app/tui/services/diff_report_service.py` → **1 hit**, BUT `rg -n` shows it is line 52 prose `"not a textual scan"` (a comment). Confirmed no actual import: `rg -n "import textual|from textual"` → 0; `rg -n "Textual"` → 0. PASS (no Textual import; the lexical hit is documentation prose, recorded as DEV-5 benign false-positive of the substring probe).

### 2.2 No-logging (LLR-004.5, F-S-07) — PASS
- `rg -c "getLogger|import logging" s19_app/tui/services/diff_report_service.py` → **no match (exit 1) = 0 hits**. Regime: `tui/services/` module. PASS (threshold 0).

### 2.3 HTML-safety (R-10, LLR-004.7) — PASS
Generated a real `.html` diff report to a tmp dir via `generate_diff_report_html(...)` with a planted injection payload `<script>alert("x")&p=1</script>` placed in the image-A source `path`/`label` and in `diagnostics`. Scratch dir created under `%TEMP%/_qa_p19_*`, file `20260614T044242Z-diff-report.html` (len 2448), then `shutil.rmtree` (scratch removed = True). Recorded outputs:
- `count "<script"` = **0** ✓
- external-resource hits `re.findall(r"<script|https?://|@import|src=|url\(")` = **0** (empty list) ✓
- `&lt;` present = **True**, `&amp;` present = **True**, `&quot;` present = **True** ✓
- raw `<script>alert` (the unescaped payload) absent = **True** ✓
- `TRUNCATED` present = **False** ✓ (completeness)
- inline `style=` present = **True** ✓ (the three run kinds distinguished by inline CSS)

All P-19 / R-10 pass conditions met. Regime: `tui/services/` service-layer `.html` output (P-19 target regime).

### 2.4 G-4 non-edit (report_service.py) — PASS
- `git diff --stat ec453a2..HEAD -- s19_app/tui/services/report_service.py` → **empty** (no edit). The shared `REPORT_FILENAME_REGEX` and `list_project_reports` are byte-for-byte unchanged.
- Regression guard: `pytest tests/test_report_service.py -q` → **14 passed** (P-09's 3 `REPORT_FILENAME_REGEX` assertions intact, unchanged-semantics confirmed).

### 2.5 Rail integrity — PASS
- `git diff --stat ec453a2..HEAD -- s19_app/tui/rail.py` → **empty** (no edit). No new rail entry; the 8-entry rail (`rail.py:78`, diff entry `:85`) is untouched.

### 2.6 G-8 / M-4 resolver (diff_report_service.py) — PASS
- `rg -n "Path\.home|Downloads"` → 1 hit at line 49, which is docstring prose ("there is **no** implicit ``Downloads`` (or other) default"). No code reference. PASS — no implicit default.
- `rg -n "sanitize_project_name"` → 1 hit at line 57, docstring prose ("``sanitize_project_name`` is deliberately NOT used"). No code reference. PASS — M-4 satisfied.
- Resolver body (`_resolve_destination`, lines 325-342) verified: project-active ⇒ `<project>/reports/`; no-project ⇒ `(dest_input or "").strip()` empty ⇒ refuse "no implicit default"; else `Path(raw).expanduser().resolve()` → `if not resolved.is_dir(): refuse`. Matches LLR-004.6 exactly.

### 2.7 M-5 collision counter on the no-project branch — PASS
- `test_no_project_collision_no_overwrite` (TC-025) exists and PASSES; asserts a `-01` sibling and the pre-existing file `== "PLANTED"` (0 overwrites) in the resolved no-project directory. The collision discipline is applied to the no-project write.

### 2.8 R-8 supersession — PASS
- The 5 placeholder-pinned tests are superseded. Disposition (verified by name-set diff `ec453a2` vs HEAD on `tests/test_tui_directionb.py`):
  - **Delete-and-replace (3):** `test_tc027_ab_diff_columns_carry_static_placeholder_rows`, `test_tc027_ab_diff_panel_holds_no_loaded_file_data`, `test_tc027_ab_diff_states_diff_deferred_and_has_no_second_file_load` — REMOVED; replaced by `test_tc027_ab_diff_has_no_placeholder_constants`, `test_tc027_ab_diff_panel_routes_through_service`, `test_tc027_ab_diff_renders_inline_selection_surface`.
  - **Rewrite-in-place (2):** `test_tc027_ab_diff_renders_three_columns` (body inverted: now asserts real columns, no placeholder) and `test_tc028_every_scaffold_screen_activates_without_error` (deferral clause inverted: `:3679` now `not bool(app.query("#diff_deferral_notice"))`).
- No test still asserts `#diff_deferral_notice` PRESENT (the only surviving reference asserts it ABSENT). The named placeholder constants (`_RANGE_LIST_PLACEHOLDER` / `_HEX_A_PLACEHOLDER` / `_HEX_B_PLACEHOLDER` / `DEFERRAL_TEXT`) are gone from `AbDiffPanel` (asserted by `test_tc027_ab_diff_has_no_placeholder_constants`).
- AST guard `test_tc028_diff_renderer_invokes_no_diff_logic` → **GREEN** (compose still constructs only `AbDiffPanel`; panel gains content internally).
- Service-route: `rg -n "diff_mem_maps" s19_app/tui/app.py s19_app/tui/screens_directionb.py` → **0 hits**. `app.py` imports + calls `compare_images` (`app.py:72,2009`), `generate_diff_report`, `generate_diff_report_html` (`:75,76`). The view never calls the engine directly. PASS.

### 2.9 Package-root module-placement guards (I1 finding) — PASS
- `test_tc028_no_new_processing_module_added_outside_view_layer` → GREEN.
- `test_tc028_no_new_processing_module_added_outside_view_layer_inc10` → GREEN.
- Both pass with `compare.py` added to the allowlist (HLR-001/D-7 supersedes the batch-04 7-module invariant per the conflict rule; supersession comment recorded at I1).

### 2.10 `_parse_loaded_file` no-new-call-sites AST guard — PASS
- `tests/test_tui_variants.py::test_no_new_parse_loaded_file_call_sites` → **1 passed**. GREEN.

**Aggregate targeted run** (all batch-09 nodes + guards): `72 passed in 9.42s`.

---

## 3. Signed-balance reconciliation (§5.3)

- Baseline (P-01, recorded at draft): **733 tests collected**.
- Post-batch: `python -m pytest -q --collect-only` last line → **`782 tests collected in 0.68s`**.
- Balance: `post = 733 − D + A` ⇒ `782 = 733 − 3 + 52`. **CONFIRMED.**

**D set (3 — placeholder-pinned tests DELETED, drawn from the corrected R-8 census; delete-and-replace contributes 1 to D):**
1. `test_tc027_ab_diff_columns_carry_static_placeholder_rows`
2. `test_tc027_ab_diff_panel_holds_no_loaded_file_data`
3. `test_tc027_ab_diff_states_diff_deferred_and_has_no_second_file_load`

**A set (52 — net-new collected items):**
- 49 from the 4 new test files (`test_compare_engine.py` 11 + `test_compare_service.py` 12 + `test_diff_report_service.py` 20 + `test_tui_diff_screen.py` 6 = 49, verified by `--collect-only`).
- 3 directionb replacement TC-027 functions (delete-and-replace, new names): `test_tc027_ab_diff_has_no_placeholder_constants`, `test_tc027_ab_diff_panel_routes_through_service`, `test_tc027_ab_diff_renders_inline_selection_surface`.

**Rewrite-in-place (0/0, no contribution to D or A):** `test_tc027_ab_diff_renders_three_columns`, `test_tc028_every_scaffold_screen_activates_without_error`, plus the two package-root guards updated in place. The directionb file `def test_` count is identical (98 → 98) between base and HEAD, consistent with +3 D / +3 A there netting to 0.

**Reconciliation against the R-8 predicted-red set (5):** predicted 5 = 3 delete-and-replace + 2 rewrite-in-place. Actual matches exactly (recorded as DEV-3 — prediction count correct; disposition split recorded for Phase 6).

---

## 4. §5.3 batch acceptance criteria — verdicts

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| 1 | 100 % of LLRs covered by ≥1 TC or an executed inspection probe (26 of 26) | **PASS** | 26/26 — §1 matrix (24 test-covered LLRs + LLR-001.1/LLR-002.1 inspection probes §2.1) |
| 2a | 0 blocker fails in Phase-4 validation | **PASS** (qa scope) | 72/72 targeted nodes pass; 0 inspection failures |
| 2b | `pytest -q` exit code 0 (FULL suite) | **PASS** (orchestrator) | Full suite `pytest -q` exit code 0, 2026-06-13 — **750 passed, 29 skipped, 3 xfailed, 0 failed** in 782.09s |
| 3 | Suite-count reconciliation `782 = 733 − D + A` | **PASS** | §3 — D=3, A=52, confirmed; full-run cross-check 750+29+3 = 782 collected (exact) |
| 4 | 0 occurrences of `should` inside any §3/§4 Statement | **PASS** (re-affirmed) | P-13 recorded 0 at draft; no §3/§4 Statement edited in Phase 3 (requirements doc unchanged) |
| 5 | No requirement without an assigned validation method | **PASS** | every HLR/LLR carries a method (test/inspection); §5.2 coverage table complete |
| 6 | `pytest tests/test_report_service.py -q` passes with `REPORT_FILENAME_REGEX` assertions UNCHANGED (G-4 NON-edit guard) | **PASS** | 14 passed; `git diff --stat report_service.py` empty (§2.4) |
| — | LLR-001.5 CI-regime perf confirmation (ubuntu / Python 3.11) | **PASS** (orchestrator, local-regime) | local slow run 1.39s < 2.0s budget within the full-suite run; the `@slow` test passed in the full 750-passed run. CI (ubuntu/3.11) confirmation rides the batch-PR push-job full run — flagged for the PR CI gate. |
| — | Lean-suite passed/skipped split | **PASS** (orchestrator) | `pytest -q -m "not slow"` (I4 close) = **729 passed, 29 skipped, 21 deselected, 3 xfailed, 0 failed** |
| — | Full-suite passed/skipped split | **PASS** (orchestrator) | `pytest -q` = **750 passed, 29 skipped, 3 xfailed, 0 failed** (782.09s, 2026-06-13). Reconciliation: 729 lean + 21 slow = 750; 750+29+3 = 782 collected. |

---

## 5. Deviations / gaps register (DEV-N — routed to Phase 6 doc reconciliation)

These are documentation-reconciliation items, NOT code or behavior defects. They mirror the batch-08 DEV-1 pattern (provisional node-id rename). No action on code/tests is implied.

| ID | Class | What | Spec said | Implemented as | Disposition (Phase 6) |
|---|---|---|---|---|---|
| **DEV-1** | doc-reconciliation (node-id / filename drift) | HLR-004 / LLR-004.x Executed-verification lines name a test FILE `tests/test_diff_report.py`. | `pytest tests/test_diff_report.py -q` | File is `tests/test_diff_report_service.py` (the `_service` suffix matches the module-under-test naming convention of the other new files). | Update the §3/§4 Executed-verification file paths `test_diff_report.py` → `test_diff_report_service.py`. Pure rename; 0 behavior impact. |
| **DEV-2** | doc-reconciliation (provisional `-k` selectors) | Per-LLR Executed-verification lines use provisional `-k` keyword selectors (e.g. `-k "classification or merge"`, `-k variant`, `-k filename`, `-k html`). | The provisional `-k` strings. | Implemented test function names do not all contain the provisional `-k` tokens (e.g. TC-021..024 are named `test_tc0NN_*`; the diff-report tests use descriptive names like `test_filename_scheme_and_same_second_collision`). The §4 lines themselves flag "provisional until Phase 3" (A-3). | Replace the provisional `-k` selectors with the real node ids (this report's §1 matrix is the authoritative map). 0 behavior impact. |
| **DEV-3** | reconciliation note (predicted-red split, informational) | R-8 corrected predicted-red set = 5 placeholder-pinned tests; suite-count reconciles rewrite-in-place vs delete-and-replace at Phase 4. | predicted-red = 5. | Disposition resolved at Phase 4: **3 delete-and-replace** (contribute to D/A) + **2 rewrite-in-place** (0/0). Prediction count was correct. | Record the disposition split in §6.4/§6.6 closeout. No discrepancy — confirmatory. |
| **DEV-4** | resolution note (run-selection flag) | Task framing referenced running TC-006 via `pytest ... -m slow -k large`. | `-m slow` filter for the perf TC. | `test_large_image_perf` is collected and runs without a marker filter (it carries `@pytest.mark.slow` but is not deselected in the file-scoped run); it executed and passed at 1.39s in the targeted file run. The marker is honored only when an `-m` filter is applied at suite level. | No action; recorded so Phase 5/6 know TC-006 was validated in-file (not via the `-m slow` selection). The CI slow-suite timing remains the orchestrator's confirmation. |
| **DEV-5** | benign probe note | LLR-001.1/002.1/004.5 purity/no-logging probes are substring greps. | `rg -c "textual"` → 0. | `diff_report_service.py` returns 1 lexical hit for the word "textual" in a prose comment (line 52). The actual `import textual`/`from textual`/`Textual` check is 0. | None required (the requirement is satisfied); optionally tighten the probe wording to `import textual\|from textual` in Phase 6 to avoid the prose false-positive. |

**No gaps in coverage, no failed TCs, no inspection failures, no unmet numeric thresholds.**

---

## 6. Final verdict

**PASS-WITH-NOTES** — now INCLUDING the four orchestrator-owned rows (full suite 750 passed/0 failed, lean 729 passed/0 failed, slow perf 1.39s<2.0s, reconciliation 782 exact). All §5.3 criteria PASS.

**Orchestrator gate disposition (2026-06-13, under the operator standing directive):** Phase 4 APPROVED — PASS-WITH-NOTES, 0 code/behavior defects; all notes (DEV-1..5) are doc-reconciliation deferred to Phase 6 (provisional→implemented node-id renames, the `test_diff_report_service.py` filename, the I4 predicted-red 5→4 confirmatory split, the run-selection assumed-flag resolution, the benign "textual" prose grep). LLR-001.5 CI-regime perf flagged for the PR push-job (full suite runs on push to main per CI-1). Advancing to Phase 5.

- 29/29 TCs PASS; 26/26 LLRs covered with thresholds met; 5/5 HLRs PASS.
- All 10 inspection classes PASS (purity ×3, no-logging, HTML-safety, G-4 non-edit, rail integrity, G-8/M-4 resolver, M-5 collision, R-8 supersession + service-route, package-root guards ×2, parse-loaded-file guard).
- Signed balance reconciled exactly (782 = 733 − 3 + 52).
- The only open items are DEV-1..DEV-5 doc-reconciliation notes for Phase 6 (node-id/filename drift, provisional `-k` selectors, predicted-red disposition split, run-selection note, benign probe false-positive) — none touches code or behavior.

The orchestrator appends the full/lean suite results to the four ORCHESTRATOR-OWNED rows before final batch closeout.
