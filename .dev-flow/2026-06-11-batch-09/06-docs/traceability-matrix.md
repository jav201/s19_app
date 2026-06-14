# Traceability Matrix — s19_app — Batch 2026-06-11-batch-09 (US-006 hex compare)

> Full chain: **User Story → HLR → LLR → Test Case → File:line**.
> Closed at phase 6. Status drawn from `04-validation.md` (PASS-WITH-NOTES; 29/29 TCs PASS, 26/26 LLRs covered).
> Implemented test node ids are the ones COLLECTED FROM THE TREE (the §4 provisional `-k` selectors and the `test_diff_report.py` filename are superseded — see DEV-1/DEV-2 in §3).
> Every `File:line` anchor below was grep-verified against HEAD on `claude/batch-09` (worktree `competent-clarke-1e8940`): **44 anchors verified, 0 unresolved.**

---

## 1. Master table

> One row per (LLR, TC, implemented node id). Source-symbol anchor = the production `file:line` the LLR governs; the test node id locates the verifying assertion. Both grep-verified.

| US | HLR | LLR | TC | Implemented node id | Source anchor (grep-verified) | Status |
|----|-----|-----|-----|---------------------|-------------------------------|--------|
| US-006 | HLR-001 | LLR-001.1 | — (inspection) | `rg "textual\|S19File\|IntelHexFile" s19_app/compare.py` → 0 | `s19_app/compare.py:1` (module) | pass |
| US-006 | HLR-001 | LLR-001.2 | TC-001 | `test_classification_set_equality` | `compare.py:272` (`diff_mem_maps`) | pass |
| US-006 | HLR-001 | LLR-001.2 | TC-001 | `test_classification_set_equality_random` | `compare.py:234` (`_classify_address`) | pass |
| US-006 | HLR-001 | LLR-001.2 | TC-002 | `test_adjacency_merge_same_kind_merges` | `compare.py:272` (`diff_mem_maps`) | pass |
| US-006 | HLR-001 | LLR-001.2 | TC-002 | `test_adjacency_change_forces_boundary` | `compare.py:272` (`diff_mem_maps`) | pass |
| US-006 | HLR-001 | LLR-001.2 | TC-003 | `test_boundary_cases` | `compare.py:100` (`DiffRun`) | pass |
| US-006 | HLR-001 | LLR-001.3 | TC-004 | `test_identity_empty_and_equal` | `compare.py:272` (`diff_mem_maps`) | pass |
| US-006 | HLR-001 | LLR-001.3 | TC-004 | `test_determinism_repeated_calls` | `compare.py:272` (`diff_mem_maps`) | pass |
| US-006 | HLR-001 | LLR-001.4 | TC-005 | `test_stats_byte_count_equals_run_lengths` | `compare.py:150` (`DiffStats`) | pass |
| US-006 | HLR-001 | LLR-001.4 | TC-005 | `test_stats_run_counts_match` | `compare.py:150` (`DiffStats`) | pass |
| US-006 | HLR-001 | LLR-001.3/.4 | TC-005 | `test_symmetry_swap_only_a_only_b` | `compare.py:43` (`KIND_ONLY_A`/`KIND_ONLY_B`) | pass |
| US-006 | HLR-001 | LLR-001.5 | TC-006 | `test_large_image_perf` (`@pytest.mark.slow`) | `compare.py:272` (`diff_mem_maps`) | pass (1.39s < 2.0s) |
| US-006 | HLR-002 | LLR-002.1 | TC-007 | `test_module_imports_no_textual` | `tui/services/compare_service.py:451` (`compare_images`) | pass |
| US-006 | HLR-002 | LLR-002.2 | TC-007 | `test_variant_pair_matches_engine` | `compare_service.py:177` (`_resolve_source`) | pass |
| US-006 | HLR-002 | LLR-002.2 | TC-007 | `test_variant_pair_reports_real_diff` | `compare_service.py:243` (`_load_image`) | pass |
| US-006 | HLR-002 | LLR-002.3 | TC-008 | `test_external_unresolvable_returns_refused` | `compare_service.py:419` (`_refused`) | pass |
| US-006 | HLR-002 | LLR-002.3 | TC-008 | `test_external_resolved_pair` | `compare_service.py:177` (`_resolve_source`) | pass |
| US-006 | HLR-002 | LLR-002.4 | TC-009 | `test_mixed_source_pairings_record_identity` | `compare_service.py:66` (`ImageSource`) | pass |
| US-006 | HLR-002 | LLR-002.5 | TC-010 | `test_parse_failure_isolated_to_refused` | `compare_service.py:243` (`_load_image`) | pass |
| US-006 | HLR-002 | LLR-002.6 | TC-011 | `test_result_field_set_matches_c9_contract` | `compare.py:183` (`ComparisonResult`) | pass |
| US-006 | HLR-003 | LLR-003.1 | TC-012 | `test_artifact_context_applies_to_external` | `compare_service.py:385` (`_build_usage`) | pass |
| US-006 | HLR-003 | LLR-003.2 | TC-013 | `test_coverage_counts_match_hand_computed` | `compare_service.py:276` (`_coverage_count`) | pass |
| US-006 | HLR-003 | LLR-003.3 | TC-014 | `test_usage_summary_all_four_outcomes` | `compare_service.py:355` (`_summarize`) | pass |
| US-006 | HLR-003 | LLR-003.4 | TC-015 | `test_absent_artifacts_summary_none` | `compare_service.py:324` (`_artifact_note`) | pass |
| US-006 | HLR-004 | LLR-004.1 | TC-016 | `test_filename_scheme_and_same_second_collision` | `diff_report_service.py:180` (`_diff_report_filename`) | pass |
| US-006 | HLR-004 | LLR-004.1 (M-5) | TC-016 | `test_collision_never_overwrites_existing_file` | `diff_report_service.py:180` (`_diff_report_filename`) | pass |
| US-006 | HLR-004 | LLR-004.2 (G-4) | TC-017 | `test_self_contained_listing_newest_first` | `diff_report_service.py:233` (`list_diff_reports`) | pass |
| US-006 | HLR-004 | LLR-004.2 (G-4 non-edit) | TC-017 | `test_report_service_regex_unedited` | `diff_report_service.py:103` (`DIFF_REPORT_FILENAME_REGEX`) | pass |
| US-006 | HLR-004 | LLR-004.3 | TC-018 | `test_report_sections_present_in_order` | `diff_report_service.py:720` (`generate_diff_report`) | pass |
| US-006 | HLR-004 | LLR-004.3 | TC-018 | `test_generation_is_deterministic_fixed_clock` | `diff_report_service.py:127` (`_default_now`) | pass |
| US-006 | HLR-004 | LLR-004.3 (G-9) | TC-026 | `test_markdown_file_is_complete_no_truncation` | `diff_report_service.py:526` (`_run_table_lines`) | pass |
| US-006 | HLR-004 | LLR-004.3 (cue) | TC-027 | `test_changed_run_emits_diff_fenced_block` | `diff_report_service.py:598` (`_diff_block_lines`) | pass |
| US-006 | HLR-004 | LLR-004.4 (G-2) | TC-019 | `test_symbol_annotation_only_intersecting_run` | `diff_report_service.py:391` (`_annotate_run`) | pass |
| US-006 | HLR-004 | LLR-004.4 | TC-019 | `test_annotation_absent_without_context` | `diff_report_service.py:354` (`_artifact_addresses_with_names`) | pass |
| US-006 | HLR-004 | LLR-004.5 (F-S-07) | TC-020 | `test_module_performs_no_logging` | `rg "getLogger\|import logging" diff_report_service.py` → 0 | pass |
| US-006 | HLR-004 | LLR-004.6 (G-8 valid) | TC-025 | `test_no_project_valid_directory_writes_one_file` | `diff_report_service.py:287` (`_resolve_destination`) | pass |
| US-006 | HLR-004 | LLR-004.6 (G-8 refuse) | TC-025 | `test_no_project_empty_path_refused[]` | `diff_report_service.py:287` (`_resolve_destination`) | pass |
| US-006 | HLR-004 | LLR-004.6 (G-8 refuse) | TC-025 | `test_no_project_empty_path_refused[   ]` | `diff_report_service.py:287` (`_resolve_destination`) | pass |
| US-006 | HLR-004 | LLR-004.6 (G-8 refuse) | TC-025 | `test_no_project_nonexistent_dir_refused` | `diff_report_service.py:287` (`_resolve_destination`) | pass |
| US-006 | HLR-004 | LLR-004.6 (M-5) | TC-025 | `test_no_project_collision_no_overwrite` | `diff_report_service.py:180` (`_diff_report_filename`) | pass |
| US-006 | HLR-004 | LLR-004.6 (M-4) | TC-025 | `test_no_sanitize_project_name_in_validator` | `diff_report_service.py:287` (`_resolve_destination`) | pass |
| US-006 | HLR-004 | LLR-004.7 (G-9 HTML) | TC-028 | `test_html_export_complete_and_safe` | `diff_report_service.py:1015` (`generate_diff_report_html`) | pass |
| US-006 | HLR-004 | LLR-004.7 (html.escape) | TC-028 | `test_html_escapes_embedded_payload` | `diff_report_service.py:826` (`_esc`) | pass |
| US-006 | HLR-004 | LLR-004.7 (regex/M-5) | TC-028 | `test_html_filename_scheme_and_collision` | `diff_report_service.py:111` (`DIFF_REPORT_HTML_FILENAME_REGEX`) | pass |
| US-006 | HLR-005 | LLR-005.1 | TC-021 | `test_tc021_compare_routes_through_service` | `app.py:2009` (`compare_images` call) | pass |
| US-006 | HLR-005 | LLR-005.2 | TC-022 | `test_tc022_render_shows_runs_and_hex_windows` | `screens_directionb.py:1271` (`#diff_range_list` update) | pass |
| US-006 | HLR-005 | LLR-005.3 | TC-023 | `test_tc023_refused_compare_surfaces_diagnostic` | `app.py:2009` (`compare_images` call) | pass |
| US-006 | HLR-005 | LLR-005.4 | TC-024 | `test_tc024_report_trigger_surfaces_paths` | `app.py:2126` / `app.py:2132` (report calls) | pass |
| US-006 | HLR-005 | LLR-005.4 | TC-024 | `test_tc024_report_trigger_invalid_dest_refused` | `app.py:2132` (`generate_diff_report_html` call) | pass |
| US-006 | HLR-005 | LLR-005.2 (G-9) | TC-029 | `test_tc029_display_caps_bound_on_screen_runs` | `screens_directionb.py:849` (`AbDiffPanel`) | pass |

**Test files (grep-verified to exist on HEAD):**
- `tests/test_compare_engine.py` (HLR-001, 11 passed)
- `tests/test_compare_service.py` (HLR-002 + HLR-003, 12 passed)
- `tests/test_diff_report_service.py` (HLR-004, 20 passed) — **NOT** `test_diff_report.py` (DEV-1)
- `tests/test_tui_diff_screen.py` (HLR-005, 6 passed)

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 1 (US-006) |
| Covered user stories | 1 (100 %) |
| Total HLR | 5 |
| Implemented HLR | 5 (100 %) |
| Total LLR | 26 |
| Implemented LLR | 26 (100 %) |
| Test cases (named TC-001..TC-029) | 29 |
| TC pass | 29 (100 %) |
| TC fail | 0 |
| TC pending | 0 |
| Collected items across the 4 new files | 49 |
| Inspection probes (purity ×3, no-logging, HTML-safety, G-4 non-edit, rail, G-8/M-4, M-5, R-8 supersession + service-route, package-root ×2, parse-loaded-file) | all pass |
| Suite signed-balance | `782 = 733 − 3 + 52` (confirmed) |

> LLR-001.1 and LLR-002.1 are inspection-only (rg purity probes), not TC-bound — counted as covered per §5.3 criterion 1. All other 24 LLRs are TC-covered.

---

## 3. Detected gaps

> Phase-6 doc-reconciliation items (DEV-1..DEV-5 from `04-validation.md`) — none is a code or behavior defect. A SIBLING docs agent is applying the DEV reconciliations to `01-requirements.md` concurrently in this same phase; recorded here as **RESOLVED-in-Phase-6**. One carried item (run-selection) remains open by design.

| ID | Type | Description | Status / action |
|----|------|-------------|-----------------|
| DEV-1 | doc-reconciliation (filename drift) | HLR-004 / LLR-004.x Executed-verification lines name `tests/test_diff_report.py`; the implemented file is `tests/test_diff_report_service.py` (`_service` suffix matches the other new files). | **RESOLVED-in-Phase-6** — §3/§4 file path updated by sibling agent; this matrix already uses the implemented name. Pure rename, 0 behavior impact. |
| DEV-2 | doc-reconciliation (provisional `-k` selectors) | Per-LLR Executed-verification lines use provisional `-k` keyword selectors (e.g. `-k variant`, `-k filename`, `-k html`) that do not all match the implemented node names; §4 lines self-flag "provisional until Phase 3" (A-3). | **RESOLVED-in-Phase-6** — superseded by the implemented node ids in §1 above (authoritative map). 0 behavior impact. |
| DEV-3 | reconciliation note (predicted-red split) | R-8 predicted-red set = 5 placeholder-pinned directionb tests; disposition was 3 delete-and-replace + 2 rewrite-in-place. | **RESOLVED-in-Phase-6** — confirmatory only; prediction count was correct. Recorded in §4 below. |
| DEV-4 | resolution note (run-selection flag) | Task framing referenced running TC-006 via `pytest ... -m slow -k large`; `test_large_image_perf` carries `@pytest.mark.slow` and runs in-file without the `-m` filter (marker honored only at suite level). | **RESOLVED-in-Phase-6** — informational; TC-006 validated in-file at 1.39s. CI slow-suite timing remains orchestrator-owned. |
| DEV-5 | benign probe note | LLR-001.1/002.1/004.5 purity probes are substring greps; `diff_report_service.py:52` carries the word "textual" in prose, giving 1 lexical hit while the real `import textual` check is 0. | **RESOLVED-in-Phase-6** — requirement satisfied; optional probe-wording tightening to `import textual\|from textual` noted, not required. |
| CARRY-1 | carried scope item (run-selection picker) | Comparison run selection currently assumes **first-run + overview** rendering; an interactive run-picker in the A↔B Diff screen is deferred. Out of scope this batch, not a gap against any LLR (LLR-005.2 renders the run list + the selected run; no LLR mandates an interactive picker). | **CARRIED** to a future batch. No code change implied. |

> No coverage gaps, no failed TCs, no inspection failures, no unmet numeric thresholds.

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | HLR-001..HLR-005 | 5 HLRs / 26 LLRs decomposing US-006 (image compare). |
| new | `s19_app/compare.py` | Headless byte-run diff engine (`diff_mem_maps`, `DiffRun`, `DiffStats`, `ComparisonResult`). |
| new | `s19_app/tui/services/compare_service.py` | Comparison service seam (`compare_images`) — fresh parse, artifact-usage notes, refusal isolation. |
| new | `s19_app/tui/services/diff_report_service.py` | Complete Markdown + self-contained HTML diff report (`generate_diff_report`, `generate_diff_report_html`, own filename regexes, `_resolve_destination`). |
| new | 4 test files | `test_compare_engine.py`, `test_compare_service.py`, `test_diff_report_service.py`, `test_tui_diff_screen.py` (49 collected). |
| modified | `AbDiffPanel` (`screens_directionb.py:849`) | Static placeholder replaced with real comparison output + inline source-select surface; batch-04 LLR-012.3/012.4 superseded. |
| modified | `app.py` | Wires the diff screen to `compare_images` (`:2009`) + the two report generators (`:2126`/`:2132`); no diff/coverage arithmetic in the view. |
| closed (superseded, R-8) | 3 placeholder-pinned directionb tests | Deleted-and-replaced (TC-027 family); 2 more rewritten-in-place. |
| unchanged (G-4 guard) | `report_service.py` | Shared `REPORT_FILENAME_REGEX` + `list_project_reports` byte-for-byte unchanged; `git diff --stat` empty, `test_report_service.py` 14 passed. |
| unchanged (rail integrity) | `rail.py` | 8-entry rail untouched; diff entry stays at `rail.py:85` (`"A2B Diff"`). No new rail entry. |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-006** → HLR-001, HLR-002, HLR-003, HLR-004, HLR-005
  - HLR-001 → LLR-001.1..001.5 → TC-001..006
  - HLR-002 → LLR-002.1..002.6 → TC-007..011
  - HLR-003 → LLR-003.1..003.4 → TC-012..015
  - HLR-004 → LLR-004.1..004.7 → TC-016..020, TC-025, TC-026..028
  - HLR-005 → LLR-005.1..005.4 → TC-021..024, TC-029

### 5.2 By code file
- `s19_app/compare.py` → LLR-001.1..001.5 → `tests/test_compare_engine.py` (TC-001..006)
- `s19_app/tui/services/compare_service.py` → LLR-002.1..002.6, LLR-003.1..003.4 → `tests/test_compare_service.py` (TC-007..015)
- `s19_app/tui/services/diff_report_service.py` → LLR-004.1..004.7 → `tests/test_diff_report_service.py` (TC-016..020, 025..028)
- `s19_app/tui/app.py` → LLR-005.1, 005.3, 005.4 → `tests/test_tui_diff_screen.py` (TC-021, 023, 024)
- `s19_app/tui/screens_directionb.py` → LLR-005.2 → `tests/test_tui_diff_screen.py` (TC-022, 029) + directionb supersession set
- `s19_app/tui/rail.py` → HLR-005 surface (unchanged; demo entry `rail.py:85`)
- `s19_app/tui/services/report_service.py` → LLR-004.2 G-4 non-edit guard → `tests/test_report_service.py` (regression, unchanged)

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-06-11-batch-09` |
| Closing date | `2026-06-13` |
| Iterations — Phase 1 (requirements) | 4 |
| Iterations — Phase 2 (review) | 1 |
| Iterations — Phase 3 (implement) | 6 increments |
| Iterations — Phase 4 (validation) | 1 |
| Iterations — Phase 5 (post-mortem) | 1 |
| Iterations — Phase 6 (docs) | 1 |
| Validation passed | yes (PASS-WITH-NOTES; DEV-1..5 doc-only) |
| Synced to Obsidian | no |

> **Anchor verification note:** all source `File:line` anchors in §1/§5 were grep-verified against HEAD on `claude/batch-09` (44 anchors, 0 unresolved). Implemented test node ids taken from `04-validation.md` §1 (collected from the tree), superseding the §4 provisional selectors per DEV-1/DEV-2.
