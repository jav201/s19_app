# Traceability Matrix — s19_app — Batch 2026-11-01-batch-101

> **Artifact language:** canonical English scaffold. This document mints no field a rule keys on — its ids (`US-` / `R-` / `AT-` / `TC-`) are read by the Atlas id-scanner and are not words in any language — so it carries no reserved-field block.

> **Roles:** `docs-writer`. Phase 6 artifact. Audience: technical stakeholder. The requirement topology differs from batch-100's: batch-101's requirement rows are **canon-hosted** — every increment writes its rows into the strict-EARS canon `REQUIREMENTS.md` (id form `R-…`) and keeps its increment-level record in `inc-<n>/01-requirements.md`. The batch-level `01-requirements.md` is the **template** plus a user-story index; its only contract ids are `HLR-001` / `LLR-001.1`. The authoritative per-row hand-over is `close/FORWARD-requirements-session.md` (273 rows: 234 new, 29 changed, 8 withdrawn, 2 brought in). Increment attribution comes from each increment's `01-requirements.md` (user stories `### US-…`, the `Rows:` / `Counts:` summary, and the `Coverage of the stories` table where present) and the `03-increments/increment-0NN*.md` packet headers. `Test (file::function)` is read from each increment's `02-test-cases.md` and the `04-validation.md` Layer 0 table; nothing here was re-run.

> **Owed in.** `full` — one row per user story, with the requirement rows each story names.

> Two chains (per the Two-layer validation rule): a story is complete only when BOTH exist — the functional (white-box) chain US → `R-…` row → test case (`R-…/n`) → test node, and the behavioral (black-box) chain US → `AT-…` → observed outcome through the shipped surface. Every story below has both; there is no coverage gap.

## 1. Master table — functional chain (white-box)

> One row per user story (55), grouped by increment. `Requirement rows` are the canon ids the story names (read from each increment's `Coverage of the stories` / section headers / `Rows:` summary, and the `close/FORWARD-requirements-session.md` table). `Test cases` is the increment's `02-test-cases.md` count (each case id is `<R-id>/<n>`). `Test nodes` are the implementing test files named in the increment's `04-validation.md` / `02-test-cases.md`. `Inc` is the increment packet; the merge evidence is `evidence/merge/lan-merge-*.txt`.

| US | Requirement rows (R-…) | Test cases | Test nodes (file) | Inc |
|----|------------------------|-----------|-------------------|-----|
| **Inc 1 — strict-EARS canon swap** | | | | |
| US-101.1 | R-DOC-CANON.1 … R-DOC-CANON.11 | 11 (RED 11/11 on `e273181`, GREEN 11/11) | `tests/test_requirements_canon.py` (canon guards) | Inc 1 |
| **Inc 2 — test hygiene, timing arms, CI** | | | | |
| US-TST-1 | R-TST-001 … R-TST-009 (the `serial_timing` marker, its guard, the two lanes) | 82 cases over 49 rows | `tests/support/timing.py`, `tests/support/suite_census.py`, `tests/b97_probes.py`, `tests/test_r_tst_*.py`, `.github/workflows/tui-ci.yml` | Inc 2 |
| US-TST-2 | R-TST-010 … R-TST-018, R-TST-090, R-TST-091 (CI lanes, history arms, time limits) | as above | as above | Inc 2 |
| US-TST-3 | R-TST-020 … R-TST-025, R-TST-030 … R-TST-032, R-TST-040 … R-TST-049, R-TST-050 … R-TST-052, R-TST-060 (waits, post-press, QC-TM margins, QC-OR oracles, QC-BC census) | as above | as above | Inc 2 |
| US-TST-4 | R-TST-070 … R-TST-072 (the batch-100 CI deferral read) | as above | as above | Inc 2 |
| US-TST-5 | R-TST-080 … R-TST-082 (version-agnostic report goldens) | as above | as above | Inc 2 |
| **Inc 3 — Save project margin, vanished folder, paint timing** | | | | |
| US-PROJ-SAVE-1 | R-PROJ-001.13, R-PROJ-GATHER.12, R-PROJ-GATHER.13, R-PROJ-ROLLBACK.9, R-PROJ-ROLLBACK.2 | 30 cases (27 full, 3 partial) | `tests/test_project_gather.py`, `tests/test_b100_project_check.py` | Inc 3 |
| US-PROJ-SYNC-1 | R-PROJ-002.12, R-PROJ-002.13, R-PROJ-002.14 | as above | as above | Inc 3 |
| US-TST-PAINT-1 | R-TST-110, R-TST-111, R-TST-112, R-TST-113 | as above | as above | Inc 3 |
| **Inc 4 — documents resolve symbols through the loaded A2L** | | | | |
| US-SYM-1 | R-CHG-SYM.9, R-CHG-SYM.10, R-CHG-SYM.13 | 23 cases (23 covered) | `tests/test_b101_symbol_reads.py` | Inc 4 |
| US-SYM-2 | R-CHG-SYM.11, R-CHG-SYM.12 | as above | as above | Inc 4 |
| US-SYM-3 | R-CHG-SYM.9 (alternative 4), R-TUI-058.9 | as above | as above | Inc 4 |
| **Inc 5 — CRC Designer refresh, Check Editor picks and spec bytes** | | | | |
| US-CRC-FRESH-2 | R-CRC-PREVIEW-002.1, R-CRC-PREVIEW-002.5 | 40 cases (36 covered, 4 partial) | `tests/test_b101_designer_writes.py`, `tests/test_b101_check_spec_keep.py` | Inc 5 |
| US-CHK-KEEP-1 | R-CHKED-010, R-CHKED-054, R-CHKED-055 | as above | as above | Inc 5 |
| US-CHK-SPEC-1 | R-CHKED-041.1, R-CHKED-041.2, R-CHKED-041.3, R-CHKED-025, R-CHKED-026, R-CHKED-027, R-CHKED-056, R-CHKED-057 | as above | as above | Inc 5 |
| **Inc 6 — Patch Editor document lifecycle** | | | | |
| US-PE-LIFE-1 | R-BEFORE-AFTER-REPORT-001.36 (the before/after offer) | 81 cases | `tests/test_b101_patch_lifecycle.py` (82 Windows nodes), `tests/test_b101_document_homes.py` | Inc 6 |
| US-PE-LIFE-2 | R-PATCH-DOC-DROPDOWN-001.1 … .5, R-CHKED-040, R-DIFF-CHK.1/.3/.5 | as above | as above | Inc 6 |
| US-PE-LIFE-3 | R-CHKED-031, R-CHKED-034, R-CHKED-044 | as above | as above | Inc 6 |
| US-PE-LIFE-4 | R-TUI-049.3 (split into .3.1 / .3.2), R-CHKS-009 | as above | as above | Inc 6 |
| **Inc 7 — before/after and diff reports** | | | | |
| US-BAR-1 | R-BEFORE-AFTER-REPORT-001.11, .24, .32 … .35 | 61 cases | `tests/test_diff_report_service.py`, `tests/test_tui_diff_screen.py` | Inc 7 |
| US-HEXWIN-1 | R-CMP-004.14 (F6-1: whole hex windows) | as above | as above | Inc 7 |
| US-MDESC-1 | R-CMP-004.9 (split into .9.1 / .9.2), R-CMP-004.15 | as above | as above | Inc 7 |
| **Inc 8 — Flow CRC block, external-step outputs, CRC model** | | | | |
| US-I8-1 | R-FLOW-CRC.1, R-FLOW-CRC.3, R-FLOW-CRC.4, R-CRC-CONFIG-001.16, R-CRC-CONFIG-001.17 | 99 cases (96 covered, 3 partial) | `tests/test_b101_flow_ext_copy.py`, `tests/test_b101_crc_model_and_reasons.py` | Inc 8 |
| US-I8-2 | R-CRC-CONFIG-001.10 … .12, R-CRC-CONFIG-001.11 | as above | as above | Inc 8 |
| US-I8-3 | R-CRC-ENGINE-002.2 (the CRC model with reverse; release note R-DOC-RELNOTE.1/.2) | as above | as above | Inc 8 |
| US-I8-4 | R-FLOW-EXT.9 … R-FLOW-EXT.14 | as above | as above | Inc 8 |
| **Inc 9 — confirm re-run, saved flow names, guarded saves** | | | | |
| US-I9-1 | R-FLOW-CHAIN.19, R-FLOW-CHAIN.20 | 34 cases | `tests/test_b101_flow_saves.py`, `tests/test_b101_flow_names_ui.py` | Inc 9 |
| US-I9-2 | R-FLOW-FILE.12 … R-FLOW-FILE.14, R-FLOW-SET.9, R-FLOW-SET.10 | as above | as above | Inc 9 |
| US-I9-3 | R-FLOW-FILE.11, R-FLOW-SET.7, R-FLOW-SET.8, R-FB-SAVE.8, R-FX-SET.15 | as above | as above | Inc 9 |
| **Inc 10a — hex navigation, unload state, focus landing** | | | | |
| US-HEXNAV-1 | R-TUI-018.1 … .4, R-TUI-040.4/.8/.11/.12, R-SEG-OPEN.6/.7 | 91 cases (89 full, 2 partial) | `tests/test_tui_goto_marker.py`, `tests/test_tui_app.py` focus arms | Inc 10a |
| US-UNLOAD-1 | R-WS-LOADED.13/.14/.16/.18 … .20 | as above | as above | Inc 10a |
| US-FOCUS-2 | R-SHELL-FOCUS.2 … .5, R-TUI-007.9 | as above | as above | Inc 10a |
| **Inc 10b — views after an in-place write** | | | | |
| US-FRESH-3 | R-A2L-048, R-A2L-049, R-A2L-105, R-A2L-106, R-TUI-004.7 … .9, R-SEG-PREV.21, R-SEG-PREV.22, R-SEG-EXP.15 | 21 cases | `tests/test_b101_inplace_views.py` (21 nodes) | Inc 10b |
| **Inc 11 — A2L validation and parsing** | | | | |
| US-I11-1 | R-VAL-032.1 … .3 (62 ASAM block names, IF_DATA skip) | 78 cases (76 covered, 2 partial) | `tests/test_b101_a2l_blocks.py`, `tests/test_tui_issues_triage_b94.py` | Inc 11 |
| US-I11-2 | R-TUI-025.2/.6, R-TUI-042b.1/.5, R-A2L-034, R-A2L-121 (severity order) | as above | as above | Inc 11 |
| US-I11-3 | R-VAL-032.4 (CURVE without axis points) | as above | as above | Inc 11 |
| US-I11-4 | R-SEG-SRC.6, R-A2L-036 (MEMORY_SEGMENT reader) | as above | as above | Inc 11 |
| **Inc 12 — unreachable code, reach/opener censuses, Reports Escape** | | | | |
| US-I12-1 | R-DLG.14, R-SHELL-KEYS.3, R-CHKED-058 | 22 cases | `tests/test_b101_reach_and_reports_escape.py`, `tests/test_b101_shown_widgets.py` | Inc 12 |
| US-I12-2 | R-CHKED-058 (the Check Editor half; cited R-CHKED-021) | as above | as above | Inc 12 |
| US-I12-3 | R-DLG.2, R-DLG.15 (Escape closes Reports) | as above | as above | Inc 12 |
| **Inc 12b — Flow Builder/Execution hidden widgets removed** | | | | |
| US-I12b-1 | R-TUI-059.25, R-FX-SCR.4, R-FB-ADD.1 | 4 cases | `tests/test_b101_shown_widgets.py` | Inc 12b |
| **Inc 13 — CRC Designer / Split/Join responsive at 10 MB** | | | | |
| US-CRC-RESP-1 | R-CRC-PREVIEW-001, R-CRC-DESIGNER-001.1/.2.1/.2.2/.007 | 52 cases (49 covered, 3 partial) | `tests/test_b101_designer_recompute.py`, timing arms | Inc 13 |
| US-CRC-FRESH-1 | R-CRC-PREVIEW-002.1 … .5 | as above | as above | Inc 13 |
| US-SEG-RESP-1 | R-SEG-PREV.2/.7/.20 | as above | as above | Inc 13 |
| **Inc 14 — help, legend, README, security, release notes, user guide** | | | | |
| US-HELP-1 | R-WHELP.7 … .26 | 74 cases (69 covered, 2 partial, 3 not-testable) | `tests/test_b101_help_legend_docs.py`, `tests/test_docs_canon.py` | Inc 14 |
| US-LEGEND-1 | R-TUI-062.10.1, R-LEGEND-011 | as above | as above | Inc 14 |
| US-README-1 | R-DOC-README.2 … .4 | as above | as above | Inc 14 |
| US-SEC-1 | R-DOC-SECURITY.1, R-DOC-SECURITY.2 | as above | as above | Inc 14 |
| US-REL-1 | R-DOC-RELNOTE.1 … R-DOC-RELNOTE.14 | as above | as above | Inc 14 |
| US-GUIDE-1 | R-DOC-GUIDE.1, R-DOC-GUIDE.2 | as above | as above | Inc 14 |
| **Inc 15 — Windows-only test failures (tests only)** | | | | |
| US-TST-15 | R-TST-150 … R-TST-157, R-TST-159 … R-TST-164 | 28 cases (28 covered) | `tests/test_tui_patch_editor_v2.py`, `tests/test_tui_flow_execution_b94.py`, `tests/support/timing.py` | Inc 15 |
| US-TST-16 | R-TST-154, R-TST-155, R-TST-158 | as above | as above | Inc 15 |
| **Inc 16 — documentation hygiene** | | | | |
| US-DOC-HYG-1 | R-DOC-REF.1 … R-DOC-REF.6 | 53 cases | `tests/test_b101_doc_hygiene.py` (44 doc-hygiene guards) | Inc 16 |
| US-DOC-HYG-2 | R-DOC-DEV.1 … R-DOC-DEV.11 | as above | as above | Inc 16 |
| US-DOC-HYG-3 | R-DOC-ARCH.1 … R-DOC-ARCH.4, R-DOC-ARCHIVE.1 … .4 | as above | as above | Inc 16 |

## 1b. Behavioral chain (black-box)

> One row per acceptance test the batch's increments declare. `Test (file::function)` is the implementing node read from the increment's `02-test-cases.md`. `Inc` is the increment that wrote it.

| US | AT | Test (file::function) | Inc |
|----|-----|----------------------|-----|
| US-101.1 (batch) | AT-101 | the batch-end battery + the doc-pass guards (`evidence/close/full-suite-final.txt`, `evidence/close/docpass-guards.txt`) | batch end |
| US-CHK-KEEP-1 | AT-I5-1 | `tests/test_b101_check_spec_keep.py::test_at_i5_1_picks_survive_write_and_return_by_keys` | Inc 5 |
| US-CHK-SPEC-1 | AT-I5-2 | `tests/test_b101_check_spec_keep.py::test_at_i5_2_spec_comes_back_and_validate_reports_the_drift` | Inc 5 |
| US-CHK-SPEC-1 | AT-I5-3 | `tests/test_b101_check_spec_keep.py::test_at_i5_3_moved_parameter_keeps_the_declared_entry_by_keys` | Inc 5 |
| US-CRC-FRESH-2 | AT-I5-4 | `tests/test_b101_designer_writes.py::test_at_i5_4_save_back_by_keys_then_display` | Inc 5 |
| US-I9-1 | AT-I9-1 | `tests/test_b101_flow_names_ui.py::test_at_i9_1_confirm_report_says_confirm_rerun` | Inc 9 |
| US-I9-2 | AT-I9-2 | `tests/test_b101_flow_names_ui.py::test_at_i9_2_resaved_flow_and_long_set_keep_own_names` | Inc 9 |
| US-I9-3 | AT-I9-3 | `tests/test_b101_flow_names_ui.py::test_at_i9_3_linked_homes_refuse_saves` | Inc 9 |
| US-I11-1 | AT-I11-1 | `tests/test_b101_inc11_acceptance.py::test_at_i11_1_clean_demo_issues_without_standard_blocks` | Inc 11 |
| US-I11-2 | AT-I11-2 | `tests/test_b101_inc11_acceptance.py::test_at_i11_2_faulty_demo_errors_first` | Inc 11 |
| US-I11-2 | AT-I11-3 | `tests/test_b101_inc11_acceptance.py::test_at_i11_3_warnings_filter_lists_warnings_only` | Inc 11 |
| US-I11-4 | AT-I11-4 | `tests/test_b101_inc11_acceptance.py::test_at_i11_4_split_join_lists_four_demo_segments` | Inc 11 |
| US-I11-3 | AT-I11-5 | `tests/test_b101_inc11_acceptance.py::test_at_i11_5_curve_description_index_note_once` | Inc 11 |
| US-I11-1 | AT-I11-6 | `tests/test_b101_inc11_acceptance.py::test_at_i11_6_a2l_explorer_region_flash` | Inc 11 |
| US-I11-4 | AT-I11-7 | `tests/test_b101_inc11_acceptance.py::test_at_i11_7_split_join_lists_software_a_segments` | Inc 11 |
| US-I12-3 | AT-I12-1 | `tests/test_b101_reach_and_reports_escape.py::test_at_i12_1_escape_closes_reports_from_list_box_and_dropdown` | Inc 12 |
| US-I12-1 | AT-I12-2 | `tests/test_b101_reach_and_reports_escape.py::test_at_i12_2_rail_keys_and_issue_peek_after_the_aliases_go` | Inc 12 |
| US-I12-2 | AT-I12-3 | `tests/test_b101_shown_widgets.py::test_at_i12_3_addendum_tab_by_keys` | Inc 12 |
| US-I12b-1 | AT-I12b-1 | `tests/test_b101_flow_shown_widgets.py::test_at_i12b_1_kind_chip_add_and_ribbon_by_keys` | Inc 12b |

## 1c. Withdrawn rows (listed once, not live)

> Eight canon rows leave the canon in batch-101. They are carried in `close/FORWARD-requirements-session.md` (kind `withdrawn`) and are not counted in the live total below. Each is withdrawn by a split that keeps the same behaviour under finer ids.

| Id | What happened |
|----|---------------|
| R-A2L-036.5 | Withdrawn — absorbed by R-A2L-036.2 / .4 (Inc 11) |
| R-VAL-032 | Withdrawn — split into R-VAL-032.1 / .2 / .3 (Inc 11) |
| R-TUI-062.10 | Withdrawn — split into R-TUI-062.10.1 / .2 / .3 (Inc 14) |
| R-CHKED-041 | Withdrawn — split into R-CHKED-041.1 / .2 / .3 (Inc 5, F-27) |
| R-TUI-049.3 | Withdrawn — split into R-TUI-049.3.1 / .3.2 (Inc 6) |
| R-CRC-DESIGNER-001.2 | Withdrawn — split into R-CRC-DESIGNER-001.2.1 / .2.2 (Inc 13) |
| R-CMP-004.9 | Withdrawn — split into R-CMP-004.9.1 / .9.2 (Inc 7) |
| R-FB-RUN.8 | Withdrawn — proposed row, withdrawn by ruling D-2, kept by id (Inc 9) |

> The two rows `brought in` unchanged are `R-TUI-007.9` (Inc 10a) and `R-BEFORE-AFTER-REPORT-001.11` (Inc 7).

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | `55` (`US-101.1` + the 54 increment `### US-…` stories; every one resolves to a `### US-…` heading in an increment's `01-requirements.md`) |
| Ready user stories | `55` (`100%`) — every story shipped in an increment that merged |
| Covered user stories | `55` (`100%`) — every story has at least one passing `AT` and a complete functional chain (§1 / §1b) |
| Total requirement rows | `273` canon rows the batch touched: `234` new + `29` changed + `8` withdrawn + `2` brought in (`close/FORWARD-requirements-session.md` Totals) |
| Live requirement rows | `265` (new + changed + brought in = 234 + 29 + 2) |
| Covered requirement rows | `265` (`100%` of live) — every increment closed with 0 BLOCKER / 0 HIGH open; per-row `Result: pass` in each `inc-*/04-validation.md` |
| Test cases | `≈ 884` (the sum of each increment's `02-test-cases.md` `Count` line) |
| Acceptance tests | the batch's own `AT-101`, `AT-I5-1 … I5-4`, `AT-I9-1 … I9-3`, `AT-I11-1 … I11-7`, `AT-I12-1 … I12-3`, `AT-I12b-1` (§1b); every one resolves to a node on the current tree |

> The pass/pending figures rest on the increment packets' executed transcripts and the batch-end battery (`04-validation.md`). The gate is the orchestrator's full Linux run on the final tree `b982846`: lane 1 `6 failed / 6113 passed / 182 skipped / 4 xfailed`, lane 2 `69 passed / 2 skipped` with `QC-TM 95 bounds, 0 under 20 % margin`; the 6 split as 4 known failures + 2 `test_tc_b100_53` load flakes that pass alone 2/2 (see `executive-summary.md`). GitHub CI on the final tree `42391147566` = the 4 known failures.

## 3. Detected gaps

> **The requirement chain has no gap.** Every live user story resolves to an increment, every increment's requirement rows resolve to the canon (`REQUIREMENTS.md` via `close/FORWARD-requirements-session.md`), and every row's test case resolves to a node in `tests/`. The rows below are record notes, not coverage gaps.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| R-1 | record note | The batch-level `01-requirements.md` is the template (not folded); its only contract ids are `HLR-001` / `LLR-001.1`. The canon fold is a hand-over to the requirements session (`close/FORWARD-requirements-session.md`, 273 rows), not this batch's act. | `04-validation.md` "Requirements". |
| R-2 | record note | Eight rows are `withdrawn` (they leave the canon); they are listed in §1c, not in the live total. | — |
| R-3 | record note | Inc 8's and Inc 14's counts read `99 cases (96 covered, 3 partial)` and `74 cases (69 covered, 2 partial, 3 not-testable)` respectively after their E5 re-audits; the earlier figures differ and are named in each `02-test-cases.md`. | — |
| R-4 | record note | The three residual visible gaps are carried as backlog rows flagged for the batch-end review page: BL-I10b-1 (Hex Peek panes keep pre-write bytes), BL-I12-5 (seven dialogs ignore Escape, R-DLG.2 `Partly`), BL-I12-6 (a Generate in flight under Escape / a double click raises `ScreenStackError`). | `04-validation.md` Gaps; accepted for 1.0.0 by the operator. |

**A worked example — text to read, never rows of your record:**

```text
| *(example)* G-001 | TC fail | TC-004 fails on condition X | See post-mortem phase 5 |
```

## 4. Changes from previous batch

*(Added, modified or closed since batch `2026-10-26-batch-100`, close commit `570b4b5`; batch base `7717394`.)*

| Type | Item | Detail |
|------|------|--------|
| new | strict-EARS canon (Inc 1) | `REQUIREMENTS.md` replaces the old canon (2623 rows, modules S0 … S17); the old canon is kept in `docs/requirements/history/`; R-DOC-CANON.1 … .11 + the TC-record generator |
| new | test infrastructure (Inc 2) | `serial_timing` marker + guard, QC-TM margin reporter, QC-OR status oracle, QC-BC census, shared `settled` waits, CI xdist lanes, version-agnostic report goldens, the redaction gate |
| new | symbol resolution (Inc 4) | change/check documents resolve `symbol` entries through the loaded/project A2L; the headless `run_checks_for_project` entry point deleted |
| new | CRC Designer + Check Editor (Inc 5, Inc 13) | coverage refreshes after every in-place write; Check Editor keeps picks and spec bytes; both stay responsive on the 10 MB demo image |
| new | Patch Editor lifecycle (Inc 6) | patches/checks/library list order, project-home writes, before/after offer only with a project, Checks tab resets |
| new | reports (Inc 7) | before/after and diff reports write full hex windows, escape hostile names, write atomically with a random staging name |
| new | Flow CRC block + external steps (Inc 8) | designer templates, external-step copies, the CRC model with reverse, config refusal reasons |
| new | flow saves (Inc 9) | confirm re-run report, saved flow/chain-set names, work-area-contained saves with a post-claim check |
| new | hex navigation / unload / focus / in-place views (Inc 10a/10b) | jump target as second row, unload clears stale state, focus never lands in a hidden window, views follow in-place writes |
| new | A2L parsing (Inc 11) | 62 ASAM block names, IF_DATA skip, MEMORY_SEGMENT reader, severity order, CURVE note |
| new | dead-surface removal (Inc 12/12b) | `VariantHelpScreen`, the view aliases, the issue-jump trio and the hidden Flow widgets removed; reach/opener censuses; Escape closes Reports |
| new | help/legend/README/security/release/user guide (Inc 14) | the in-app help, legend, README, SECURITY.md, 1.0.0 release notes and user guide describe the shipped app |
| new | Windows-only test fixes (Inc 15) | single pauses → shared `settled` waits (tests only, 0 product files) |
| new | documentation hygiene (Inc 16) | stale/dead/duplicate docs corrected or archived; 44 doc-hygiene guards |
| closed | G-005 / G-015 | G-015 (`serial_timing` runs apart) landed as test infrastructure in Inc 2; the batch-100 post-close CI `41372953464` was read in Inc 2/Inc 14 |

## 5. Quick bidirectional mapping

### 5.1 By increment (requirement homes)

- **Inc 1** → US-101.1 → R-DOC-CANON.1 … .11 → `tests/test_requirements_canon.py`
- **Inc 2** → US-TST-1 … US-TST-5 → R-TST-001 … .091 → `tests/support/timing.py`, `tests/b97_probes.py`, `.github/workflows/tui-ci.yml`
- **Inc 3** → US-PROJ-SAVE-1, US-PROJ-SYNC-1, US-TST-PAINT-1 → R-PROJ-*, R-TST-110 … .113 → `tests/test_project_gather.py`
- **Inc 4** → US-SYM-1 … US-SYM-3 → R-CHG-SYM.9 … .13, R-TUI-058.9 → `tests/test_b101_symbol_reads.py`
- **Inc 5** → US-CRC-FRESH-2, US-CHK-KEEP-1, US-CHK-SPEC-1 → R-CRC-PREVIEW-002.1/.5, R-CHKED-* → `tests/test_b101_designer_writes.py`, `tests/test_b101_check_spec_keep.py`
- **Inc 6** → US-PE-LIFE-1 … US-PE-LIFE-4 → R-PATCH-DOC-*, R-TUI-049.3, R-CHKED-*, R-DIFF-CHK.* → `tests/test_b101_patch_lifecycle.py`
- **Inc 7** → US-BAR-1, US-HEXWIN-1, US-MDESC-1 → R-BEFORE-AFTER-REPORT-001.*, R-CMP-004.* → `tests/test_diff_report_service.py`
- **Inc 8** → US-I8-1 … US-I8-4 → R-FLOW-CRC.*, R-FLOW-EXT.9 … .14, R-CRC-CONFIG-001.* → `tests/test_b101_flow_ext_copy.py`, `tests/test_b101_crc_model_and_reasons.py`
- **Inc 9** → US-I9-1 … US-I9-3 → R-FLOW-CHAIN.19/.20, R-FLOW-FILE.11 … .14, R-FLOW-SET.7 … .10 → `tests/test_b101_flow_saves.py`, `tests/test_b101_flow_names_ui.py`
- **Inc 10a** → US-HEXNAV-1, US-UNLOAD-1, US-FOCUS-2 → R-TUI-018, R-WS-LOADED.*, R-SHELL-FOCUS.* → `tests/test_tui_goto_marker.py`
- **Inc 10b** → US-FRESH-3 → R-A2L-048/049/105/106, R-TUI-004.7 … .9, R-SEG-PREV.21/.22 → `tests/test_b101_inplace_views.py`
- **Inc 11** → US-I11-1 … US-I11-4 → R-VAL-032, R-TUI-025/042b, R-SEG-SRC.6, R-A2L-034/036/121 → `tests/test_b101_a2l_blocks.py`
- **Inc 12** → US-I12-1 … US-I12-3 → R-DLG.2/.14/.15, R-SHELL-KEYS.3, R-CHKED-058 → `tests/test_b101_reach_and_reports_escape.py`
- **Inc 12b** → US-I12b-1 → R-TUI-059.25, R-FX-SCR.4, R-FB-ADD.1 → `tests/test_b101_shown_widgets.py`
- **Inc 13** → US-CRC-RESP-1, US-CRC-FRESH-1, US-SEG-RESP-1 → R-CRC-PREVIEW-001, R-CRC-DESIGNER-001, R-SEG-PREV.* → `tests/test_b101_designer_recompute.py`
- **Inc 14** → US-HELP-1, US-LEGEND-1, US-README-1, US-SEC-1, US-REL-1, US-GUIDE-1 → R-WHELP.*, R-DOC-* → `tests/test_b101_help_legend_docs.py`
- **Inc 15** → US-TST-15, US-TST-16 → R-TST-150 … .164 → `tests/test_tui_patch_editor_v2.py`, `tests/test_tui_flow_execution_b94.py`
- **Inc 16** → US-DOC-HYG-1 … US-DOC-HYG-3 → R-DOC-REF.*, R-DOC-DEV.*, R-DOC-ARCH.* → `tests/test_b101_doc_hygiene.py`

### 5.2 By module of the canon

`close/FORWARD-requirements-session.md` groups the 273 rows by module; the per-module totals are: S0 128 · S2 21 · S3 6 · S4 10 · S5 3 · S6 4 · S7 12 · S8 5 · S9 10 · S10 7 · S11 4 · S13 16 · S14 17 · S15 21 · S16 4 · S17 5 (S1 and S12 hold 0). See that document for the per-row table.

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-11-01-batch-101` |
| Closing date | written 2026-11-07 (P5 close; the `v1.0.0` tag is the operator's act on the review page's OK) |
| Total increments | `16` planned increments; the 10 and 12 split into a/b, so `18` packets (1 … 16 with 10a/10b and 12/12b) |
| Validation passed | `PASS-WITH-NOTES` on the batch-end battery (`04-validation.md`); final CI `42391147566` = the 4 known failures |
| Synced to Obsidian | no — the operator commits, pushes and runs `/dev-flow-sync` |
