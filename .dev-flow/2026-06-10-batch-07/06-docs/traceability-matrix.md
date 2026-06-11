# Traceability Matrix — s19_app — Batch 2026-06-10-batch-07

> Full chain: **User Story → HLR → LLR → Test Case → File:line**.
> Completed at batch close (phase 6). Every row is complete; there are **0 coverage gaps** (all 51 LLRs map to ≥1 passing TC).
> Validation status is taken verbatim from `04-validation.md` (Phase 4, run-ownership per A-6: qa-reviewer ran all 9 targeted clusters + inspections — **196 passed / 0 failed**; orchestrator owns the lean pass **670 passed / 0 failed** (E8 gate, `670 passed, 29 skipped, 20 deselected, 3 xfailed`) and the slow pass **20 passed / 0 failed**).
> At 51 LLRs the master table is one row **per LLR cluster** following the `01-requirements.md` §5.2 TC index (the per-LLR exhaustive form would be 51 rows restating §4 — the per-LLR executed verifications + thresholds live embedded in each LLR there). `File:line` references are grep-verified against the worktree at batch close (HEAD b1cde0c + Phase-6 docs).

---

## 1. Master table

| US | HLR | LLR cluster | TC | Implementing files (file:line) | Test files | Status | Evidence (04-validation.md §2) |
|----|-----|-------------|-----|-------------------------------|-----------|--------|--------------------------------|
| US-002 | HLR-001 | LLR-001.1–001.8 (v2 format, reader/validator, collision, ceilings, v1 hard break) | TC-001..TC-008 | `s19_app/tui/changes/model.py` (`ChangeEntry`/`ChangeDocument`), `changes/io.py` (`read_change_document`/`write_change_document`; `CHG-*` codes, v1-precedence, text-codec allowlist, pre-encode guard), `changes/validate.py` (`CHG-COLLISION`), `changes/apply.py:106` (`classify_containment`, LLR-001.6) | `tests/test_changes_schema.py`, `tests/test_changes_collision.py`, `tests/test_changes_containment.py` | pass | Cluster 1: `42 passed in 0.68s`; containment rides cluster 2: `23 passed in 0.43s` |
| US-002 | HLR-002 | LLR-002.1–002.6 (apply gate, dispositions, before-capture, summary, linkage) | TC-009..TC-014 | `changes/apply.py:210` (`apply_change_document`), `changes/model.py:373` (`ChangeSummary`, injectable `now_fn`) | `tests/test_changes_apply.py`, `tests/test_changes_linkage.py` | pass | Cluster 2: `23 passed in 0.43s` (all 5 dispositions, all 4 linkage classes, fixed-clock determinism) |
| US-002 | HLR-002 | LLR-002.7 / LLR-002.8 (S19 save-back + declaration-fault visibility — late-assigned ids) | TC-051, TC-052 | `changes/apply.py:558` (`save_patched_image`, F-S-01 sanitizer), `changes/io.py:1298` (`emit_s19_from_mem_map`), `services/change_service.py` (stamps `saved_path`), `screens_directionb.py:325` (`PatchEditorPanel` prompt + persistent fault area) | `tests/test_changes_apply.py:321-390` (`test_save_back_*` family: reparse-equal, declined→`None`, adversarial filenames, HEX refused), `tests/test_tui_patch_editor_v2.py:390` (`test_save_back_prompt`), `:515` (`test_declaration_faults_visible`) | pass | Clusters 2+3; adversarial filenames pinned (`test_changes_apply.py:363-366`: `..\escape.s19`, absolute path, `CON.s19`, trailing dot) |
| US-002 | HLR-003 | LLR-003.1–003.5 (single-section panel, 8→9 action routing, cfdx retirement, service consolidation, legacy-load UX) | TC-015..TC-019 | `screens_directionb.py:325` (`PatchEditorPanel`, 6 `patch_doc_*` ids), `app.py:106` (`PATCH_ACTIONS_V2`) + router `:1277`, `services/change_service.py` (NEW), `changes/display.py` (migrated `memory_display`); deletions: `cdfx/` package (11 modules) + `services/cdfx_service.py` | `tests/test_tui_patch_editor_v2.py`, `tests/test_change_service.py` + inspections | pass | Cluster 3: `24 passed in 6.09s`; retirement probe `grep -rE` → **0 hits** (self-tested: 164 pre-delete); `git ls-files s19_app/tui/cdfx/` → empty; cluster 9b (migrated/surviving stack) `87 passed in 0.67s` |
| US-003 | HLR-004 | LLR-004.1–004.5 (check discriminator, pass/fail/uncheckable, results object, headless entry, TUI display) | TC-020..TC-024 | `changes/check.py:68` (`run_check_document`, shared linkage classifier), `changes/model.py:608` (`CheckRunResult` incl. `issues` — B-2 carrier), `services/change_service.py:1084` (`run_checks_for_project`) | `tests/test_checks_engine.py`, `tests/test_tui_patch_editor_v2.py:610` (`test_check_run_display`) | pass | Cluster 4: `7 passed in 0.59s`; TC-024 inside cluster 3 |
| US-005 | HLR-005 | LLR-005.1–005.6 (N-S19 workspace, variant types, back-compat, thread contract, selector, first-variant default) | TC-025..TC-030 | `workspace.py:376` (`build_variant_set`; 1-S19 limit removed, single-MAC/A2L kept), `models.py:56`/`:81` (`VariantDescriptor`/`ProjectVariantSet`; `LoadedFile.variant_id` additive), `screens.py:208` (`SelectVariantScreen`), `app.py:497` (binding `v`) + `:2207` (`action_select_variant`) | `tests/test_workspace_variants.py:71` (`test_single_s19_project_loads_equivalently`), `tests/test_tui_variants.py:86,:123` (first-variant pilot, `(i/N)` label) | pass | Cluster 5: `20 passed in 9.65s` (incl. LLR-005.4 zero-new-parse-call-sites inspection) |
| US-005 | HLR-006 | LLR-006.1–006.6 (project.json manifest + containment, deterministic order, headless per-variant parse, isolation, C-6 consumption, scope UI) | TC-031..TC-036 | `services/variant_execution_service.py:473` (`VariantExecutionResult`; manifest read project-dir-only per F-S-03), `app.py` (`execute_scope` = 9th routed action; `active_variant` override), `screens_directionb.py` (scope cycler) | `tests/test_variant_execution.py` (+ TC-036 demo at the E6 gate, F-Q-18 observable no-freeze) | pass | Cluster 6: `11 passed in 2.58s` (incl. injected-failure: `len(results) == N`, ≥3 adversarial manifest paths) |
| US-004 | HLR-007 | LLR-007.1–007.8 + 007.x (headless generator, context knob 0..4096, window math + merge, `render_hex_view` reuse, content (a)–(f), filename scheme, caps, confidentiality) | TC-037..TC-044 | `services/report_service.py:913` (`generate_project_report`), `:115` (`EXECUTION_SCOPE_TO_REPORT_MODE`), `ReportOptions` (F-S-05 domain-validated), `variant_execution_service.py` (opt-in `capture_mem_maps`) | `tests/test_report_service.py` (13 lean + 1 slow `REPORT_MAX_*` measurement) | pass | Cluster 7: `13 passed, 1 deselected in 0.43s`; slow measurement passed at E7 gate (106,848 B / 0.011 s — constants HOLD) |
| US-004 | HLR-008 | LLR-008.1–008.5 (viewer screen hardened, no 9th rail item, newest-first listing, headless guarantee, generation trigger) | TC-045..TC-049 | `screens.py:282` (`ReportViewerScreen`), `:375` (`Markdown("", open_links=False, …)` — F-S-06), `app.py:499` (binding `t`) + `:1628` (`action_view_reports`), `app.py:1821` (scope→mode wiring, no assembly logic) | `tests/test_tui_report_view.py` (`open_links` pin at the `:179` block), `tests/test_report_service.py:535` (`test_generation_is_headless_no_app` — DEV-8 node-id drift vs spec, intent identical) | pass | Cluster 8: `9 passed in 9.92s`; rail diff empty (stays 8 items); + viewer-scroll demo at the E8 gate |
| US-002..005 | HLR-001..008 | §5.3 guards (engine read-only; migrated/surviving stack) | TC-027-guard, §6.6 enactment | `tests/test_engine_unchanged.py:135` (`test_tc027_engine_modules_unchanged_vs_main` — relocated from deleted `test_cdfx_unchanged.py`) | `test_memory_*`, `test_unified_*` survivors/rewrites | pass | Clusters 9a/9b: `1 passed in 0.04s` + `87 passed in 0.67s` |
| US-002..005 | HLR-001..008 | (roll-up) | TC-053 | full lean suite at every increment gate | `pytest -q -m "not slow"` | pass | Cluster 10 (orchestrator, E8 gate): `670 passed, 29 skipped, 20 deselected, 3 xfailed` — 0 failures; slow (cluster 11): `20 passed, 702 deselected in 460.57s` |

> TC-050 is **retired-unassigned** (the roll-up moved to TC-053 so late-assigned TC-051/052 never renumbered anything — F-A-10/F-Q-13). It is not a gap.

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories (active) | 4 (US-002..US-005; US-001 closed in batch-06) |
| Covered user stories | 4 (100%) |
| Total HLR | 8 |
| Implemented HLR | 8 (100%) |
| Total LLR | 51 |
| Implemented LLR | 51 (100%) |
| Test cases | TC-001..TC-049 + TC-051..TC-053 (TC-050 retired-unassigned) |
| TC pass | all (targeted **196/196**; lean **670 passed / 0 failed**; slow **20/20**) |
| TC fail | 0 |
| TC pending | 0 blocking (snapshot cell `xfail(strict=False)` pending CI-env regen — §3.1) |

> **N_i ledger (suite-count reconciliation, F-Q-14 exact form — `04-validation.md` §4):** new tests per increment E1..E8 = 42/23/24/7/12/8/11/14/8 → **ΣN_i = 149** (13 new test files); equation `826 (true pre-batch collection) + 149 − 229 RETIRE − 1 D3-resolved − 23 folds − 1 TC-027 out + 1 TC-027 relocated = 722` = measured `pytest --collect-only -q` ✓ **exact**, balanced at all 3 collection checkpoints (915 / 662 / 722) and 11 lean checkpoints. The circulated "794" pre-batch basis was a units error (passed-counts vs collected-counts, off by exactly 32 = 29 skipped + 3 xfailed) — corrected in Phase 4.

---

## 3. Detected gaps

> No incomplete rows, no LLR without a passing TC, no TC without a code/test mapping. **0 blocking gaps.**

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | **None blocking.** All 51 LLRs map to ≥1 passing TC; all 8 HLRs covered; roll-up TC-053 green. | — |

### 3.1 Non-gap items (accepted, informational)

| Item | Status | Disposition |
|------|--------|-------------|
| **CI-1 two-tier gate not in tree at HEAD b1cde0c** (the one OPEN §5.3 criterion; Phase-4 verdict is PASS-WITH-NOTES because of it) | open process item | The ~3-line `tui-ci.yml` edit (PR gate `-m "not slow"`, full suite on `main` push) **rides the batch PR** (post-mortem A-1, High). Both jobs green on the PR also closes the Python 3.11 confirmation (local evidence is 3.14.4). |
| Snapshot cell `patch-comfortable-120x30` pinned `xfail(strict=False)` (`tests/test_tui_snapshot.py:386`) | pending by design | Project memory forbids local regen; regenerate in the canonical CI env post-merge, then drop the xfail (A-5/V-6). Counted inside the 3 xfailed of every lean line. |
| No single E2E pilot (load → execute → generate → view) | accepted, recommendation | Each seam is covered pairwise; the only uncovered defect class is seam state (e.g. the `_last_execution` handoff — pinned by a results-dropped assertion in `test_tui_report_view.py`). Post-mortem V-4: add ONE E2E pilot in batch-08, amortized with US-006. |
| Batch-06 A-9 knee test (~216-col MAC layout) NOT added | carried 2 batches | Its conditional MUST never triggered (no MAC selectors touched — verified live). Post-mortem V-5: convert to a **fixed** batch-08 task. |
| Demo criteria (LLR-006.6 no-freeze, HLR-008 viewer scroll) | met at gates | Operator-observed at the E6/E8 gates; Phase 4 verified the pilot-test proxies. Gate observation = evidence of record. |

---

## 4. Changes from previous batch (batch-06 → batch-07)

| Type | Item | Detail |
|------|------|--------|
| **retired (feature)** | Entire cfdx/.cdfx parameter flow | The §6.6 measured disposition table (355 rows, 98.3% first-pass accuracy) enacted at E3b: **229 RETIRE / 50 REWRITE (28 in place + 22 folds to named targets) / 69 SURVIVES (63 unchanged + 6 gate-ratified re-dispositions, DEV-2) / 7 DEPENDS-ON-DESIGN all resolved**. **12 production modules deleted** (11 `cdfx/` modules + `services/cdfx_service.py`) + 15 whole test files; E3b totals 45 files, `+1,518 / −16,212`. Retirement probe self-tested 164 → 0 hits (B-3 rule). |
| supersede | REQUIREMENTS.md §8–9 (R-CDFX-*, batch-04 memory-editing R-IDs) | Superseded by the single v2 JSON system (US-002 locked decision). **Supersession notes go into the living REQUIREMENTS.md §8–9 rows — IDs preserved, never renumbered** (post-mortem A-4; includes the DEV-5 notes on rows that cited the 3 flipped cardinality-lock tests). |
| relocated (test) | TC-027 engine-unchanged guard | `test_cdfx_unchanged.py` (deleted) → `tests/test_engine_unchanged.py:135`; count-neutral (−1/+1 in the ledger). |
| flipped (tests, ratified DEV-5) | 3 legacy cardinality locks | `test_tui_helpers.py` rejects-multiple-data → accepts; `test_tui_directionb.py::tc034` two-S19 block; `test_tui_workspace.py::tc048` case-collision — newer requirement (LLR-005.1) supersedes the batch-06-era locks. |
| deviations (8, all gate-ratified, 0 silent) | DEV-1..DEV-8 | DEV-1 HEX save-back message = status line, not dead prompt (amend LLR-002.7 wording) · DEV-2 6 SURVIVES→REWRITE re-dispositions (`MEMV-*` WARNINGs became apply dispositions) · DEV-3 one `changes/io.py` message edit beyond the E3b deletion budget (surviving S57-02 assertion; loosening forbidden by rule 9) · DEV-4 6 REWRITE rows enacted as whole-file deletes with named-target folds · DEV-5 above · DEV-6 E6 file-cap 7 vs ≤6 (contract-mandated pins) · DEV-7 window upper clamp implemented (align LLR-007.2 wording) · DEV-8 headless-test node id drift (`test_generation_is_headless_no_app`; fix HLR-008's verification line). Doc-reconciliation actions per `04-validation.md` §5. |
| process | Two new template controls (post-mortem §5, A-2) | **Probe self-test rule** (B-3/B-4: every executable verification runs at draft time with recorded pre-state) + **contract-touch rule** (B-1/B-2: any edit to a producer/consumer LLR re-opens the C-6 identity check). |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-002** → HLR-001/002/003 → LLR-001.1–.8, 002.1–.8, 003.1–.5 → TC-001..019, TC-051, TC-052
- **US-003** → HLR-004 → LLR-004.1–.5 → TC-020..024
- **US-004** → HLR-007/008 → LLR-007.1–.8+.x, 008.1–.5 → TC-037..049
- **US-005** → HLR-005/006 → LLR-005.1–.6, 006.1–.6 → TC-025..036
- All → TC-053 (lean roll-up)

### 5.2 By code file
- `s19_app/tui/changes/model.py` → LLR-001.1/.2, 002.5 (`ChangeSummary` @373), 004.3 (`CheckRunResult` @608)
- `s19_app/tui/changes/io.py` → LLR-001.1/.3/.4/.7/.8, 002.7 (`emit_s19_from_mem_map` @1298)
- `s19_app/tui/changes/validate.py` → LLR-001.5 (`CHG-COLLISION`)
- `s19_app/tui/changes/apply.py` → LLR-001.6 (`classify_containment` @106), 002.1–.6 (`apply_change_document` @210), 002.7 (`save_patched_image` @558)
- `s19_app/tui/changes/check.py` → LLR-004.1/.2 (`run_check_document` @68)
- `s19_app/tui/changes/display.py` → LLR-003.3 (migration target of `cdfx/memory_display.py`; destination of its 12 SURVIVES tests)
- `s19_app/tui/services/change_service.py` → LLR-003.4, 004.4 (`run_checks_for_project` @1084)
- `s19_app/tui/services/variant_execution_service.py` → LLR-006.1–.5 (`VariantExecutionResult` @473)
- `s19_app/tui/services/report_service.py` → LLR-007.1–.8 (`generate_project_report` @913; `EXECUTION_SCOPE_TO_REPORT_MODE` @115)
- `s19_app/tui/workspace.py` → LLR-005.1 (`build_variant_set` @376)
- `s19_app/tui/models.py` → LLR-005.2 (`VariantDescriptor` @56, `ProjectVariantSet` @81)
- `s19_app/tui/screens.py` → LLR-005.5 (`SelectVariantScreen` @208), 008.1 (`ReportViewerScreen` @282, `open_links=False` @375)
- `s19_app/tui/screens_directionb.py` → LLR-003.1 (`PatchEditorPanel` @325), 002.8-UI, 006.6 (scope cycler)
- `s19_app/tui/app.py` → LLR-003.2 (`PATCH_ACTIONS_V2` @106, router @1277), 005.5/.6 (`v` @497, `action_select_variant` @2207), 008.5 (`t` @499, `action_view_reports` @1628, scope wiring @1821)

### 5.3 By test file (all NEW this batch; N_i in parentheses)
- `tests/test_changes_schema.py` (33) + `test_changes_collision.py` (9) → TC-001..005, 007, 008
- `tests/test_changes_apply.py` (16) + `test_changes_linkage.py` (2) + `test_changes_containment.py` (5) → TC-006, TC-009..014, TC-051-engine
- `tests/test_tui_patch_editor_v2.py` (8) + `test_change_service.py` (16) → TC-015/016/019/024, TC-051-UI, TC-052
- `tests/test_checks_engine.py` (7) → TC-020..023
- `tests/test_workspace_variants.py` (12) + `test_tui_variants.py` (8) → TC-025..030
- `tests/test_variant_execution.py` (11) → TC-031..035 (+TC-036 demo)
- `tests/test_report_service.py` (14) → TC-037..044 + LLR-008.4 (`test_generation_is_headless_no_app` @535)
- `tests/test_tui_report_view.py` (8) → TC-045..049
- `tests/test_engine_unchanged.py` (1, relocated) → §5.3 engine read-only guard (`test_tc027_engine_modules_unchanged_vs_main` @135)

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-06-10-batch-07 |
| Closing date | 2026-06-11 |
| Total iterations (sum of phases) | 7 (P1=2 forced, P2=1, P3=1, P4=1, P5=1, P6=1) |
| Total LLRs / covered | 51 / 51 (100%) |
| TCs | TC-001..049 + TC-051..053 — all pass, 0 fail, 0 blocking pending |
| Validation passed | yes (Phase-4 verdict **PASS-WITH-NOTES**; targeted 196/196, lean 670/0, slow 20/20; the one OPEN note = CI-1 rides the batch PR) |
| Synced to Obsidian | no (pending dev-flow-sync after PR merge — post-mortem A-10; use the canonical G: vault path) |
