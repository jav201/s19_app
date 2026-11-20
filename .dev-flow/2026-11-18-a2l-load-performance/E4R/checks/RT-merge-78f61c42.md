# FA-RT on the merge tree (`merge-78f61c42`)

Case 3 of `frontA/units/FA-RT.md`: the merge tree before FA-PRIV. Commit `78f61c42` (branch `alp-e4r-mB`) is alp-e4r `0a0c5e7c` merged with Front B `6eccf0cb`, plus FA-D11c. Front A's own contribution is `6eccf0cb..78f61c42`.

**Bottom line**
- **Reverse trace.** The scope holds 169 tests in 11 files. None is class X or U.
- **O candidates.** There are 7, all pre-existing AT/TC id-registry guards in `tests/test_id_registry.py`. Ruling: keep them, but each needs a canon row (operator); none is retired.
- **Front A's own lines miss step 4 ("all K") in 5 nodes.** One new test cites the absorbed id `LLR-154.1` (class S, re-cite). Four `test_alp_inc2` nodes are K?: two cite only AT ids that link to stories not in the canon, and two carry an absorbed `HLR-176` comment beside an active row. These get advisory re-cites.
- **trace_check is not 0 gaps.** It gives 26 gaps with base `f44e8bc4` and 17 with base `6eccf0cb`. `shared.py` is in the slice and named, so it is not a gap.
- **What the 17 gaps are.** 12 CASE gaps come from the case-id format in `E4R/02-test-cases.md`. 4 SLICE gaps are files that only `E4R/RECORD.md` names. 1 EVID gap: `E4R/04-validation.md` is missing.
- **Negative controls.** Both PASS.

## 1. How it was run (read-only)

- **Clean copy.** `git -C <worktree> archive 78f61c42 | tar -x -C <scratch>/rt-merge`. The archive has 13655 files, the same count as `git ls-tree -r` of 78f61c42; `.gitattributes` has no `export-ignore`. The worktree stayed on `alp-e4r-mB` with a clean status before and after.
- **TA1 run.** `python -I -B ~/clde/s19-review-2026-11-19/TA/reverse_trace.py --repo <scratch>/rt-merge --out ~/clde/s19-review-2026-11-19/frontA/RT/merge-78f61c42 --tmp <scratch>/rt-tmp`
- **TA2 run.** The same command with `--ta2`.
- **trace_check setup.** The copy of `trace_check.py` sat in `<scratch>/tc` (the skill folder was not touched). It ran with cwd `<scratch>/rt-merge`, using a temporary git index:
  - `GIT_DIR=<repo>/.git`, `GIT_WORK_TREE=<scratch>/rt-merge`, `GIT_INDEX_FILE=<scratch>/tc/index.78f61c42`, `GIT_OPTIONAL_LOCKS=0`;
  - `git read-tree 78f61c42` wrote only the temporary index, and nothing was checked out.
- **Check of that setup.** `git diff --name-only <base>` from the clean copy is byte-identical to the commit-to-commit `git diff --name-only <base> 78f61c42`. Both bases agree: 538 paths for f44e8bc4 and 297 for 6eccf0cb. The clean copy has 0 untracked files.
- **No pytest, no import, no py_compile.** Everything was read with AST or text.

## 2. Negative controls (a missing control voids the run: both present, both PASS)

TA1 (`TA-negative-control.txt`). The temp-repo path is replaced by `<scratch>/rt-tmp/control_repo`; every other line is verbatim:

```
- `test_planted_cites_only_retired_id` -> class **X** (expected X) PASS; ids: LLR-9990.1[retired]
- `test_llr_9990_1_planted_by_name_only` -> class **X** (expected X) PASS; ids: LLR-9990.1[retired]
- `test_planted_cites_absorbed_id` -> class **S** (expected S) PASS; ids: LLR-9991.1[absorbed]
- `test_planted_cites_active_id` -> class **K** (expected K) PASS; ids: R-DOC-CANON.1[active]

Control result: PASS - the retired-only tests classify X
```

TA2 (in `TA2-summary.md`; the temp path is replaced the same way):

```
- `test_planted_cites_only_tc_99999` -> TA1 class U; tc_links: HLR-9990[retired]; class2 = **X** (expected X)

Control result: PASS - class2 = X
```

Printed by the script. TA1: `Control result: PASS - the retired-only tests classify X`. TA2: `Control result: PASS - class2 = X`.

## 3. Whole tree (context only)

| | tests | K | K? | S | X | O | U |
|---|---|---|---|---|---|---|---|
| merge-78f61c42 | 7045 | 3411 | 644 | 1215 | 214 | 1561 | 0 |

- **TA2 rerouting.** AT/TC ledger links moved 1231 O tests: K? 1101, K 96, S 11, X 23.
- **TA2 candidates.** There are 123, and none of them is in Front A's scope.
- **Against Front B's end state.** The X 214 / U 0 figures match the end state that `TA/exec/TA-REMAINING-DESIGN.md` gave for Front B.

## 4. Scope and counts per class

**How the scope was built:**
- **Files.** Every test file in `git diff --name-only 6eccf0cb..78f61c42 -- tests` (12 files; `conftest.py` has no test functions), plus the `tests/test_alp_*.py` files.
- **Range citations.** Every test citing R-A2L-REFRESH.029–.053 or R-A2L-DEF.156–.168. A text grep of `tests/` finds these ids only in files already in scope.
- **FA-D11c.** `test_suite_hygiene.py::test_r_tst_011_push_runs_two_lanes` cites R-TST-011 and .019. `::test_r_tst_015_016_017_ci_time_limits` cites R-TST-015, .016, .017 and .026. Both are **K**, and all three FA-D11c rows are in the canon (S0.11).
- **Seven alp files.** The tree holds seven `test_alp_*.py` files, not six: `test_alp_s19_read_once.py` (FA-TICK2u) is the seventh.

Result: **169 tests in 11 files**. Of these, 72 cite an id in the ranges and 97 are in scope by file only.

| class | TA1 class | after AT/TC ledger link (TA2 class2 for O rows) |
|---|---|---|
| K | 131 | 133 |
| K? | 4 | 20 |
| S | 9 | 9 |
| X | 0 | 0 |
| O | 25 | 7 |
| U | 0 | 0 |

Per file, after the ledger link:

| file | tests | K | K? | S | O | whose lines |
|---|---|---|---|---|---|---|
| tests/test_alp_a2l_occupancy.py | 26 | 26 | | | | alp |
| tests/test_alp_a2l_occupancy_at.py | 3 | 3 | | | | alp (2 of them K through a ledger link) |
| tests/test_alp_a2l_occupancy_perf.py | 6 | 6 | | | | alp |
| tests/test_alp_inc2_a2l_attach.py | 20 | 16 | 4 | | | alp / Front A |
| tests/test_alp_inc3_load_responsiveness.py | 6 | 6 | | | | alp |
| tests/test_alp_inc3_snapshot_parity.py | 13 | 13 | | | | alp |
| tests/test_alp_s19_read_once.py | 2 | 1 | | 1 | | Front A (FA-TICK2u) |
| tests/test_b103_picker_model.py | 14 | 14 | | | | pre-existing; FA-C7b re-pins |
| tests/test_suite_hygiene.py | 48 | 48 | | | | pre-existing; FA-D11c |
| tests/test_b100_session_reset.py | 19 | 0 | 11 | 8 | | pre-existing; Front A edited two data constants only |
| tests/test_id_registry.py | 12 | 0 | 5 | | 7 | pre-existing; Front A edited one constant only |

**Known re-cites (step 4): all present.**

| target row | nodes citing it |
|---|---|
| `.049` (capture arm) | 2 |
| `.050` (tick asserts) | 13 |
| `.051` (GC arms) | 5 |
| `.052` (GC arms) | 2 |
| `.053` (GC arms) | 2 |
| R-A2L-DEF.166 (the `.140/11` arm) | 3 |
| R-A2L-DEF.167 / .168 (scale cases) | 1 each |

No scoped node still cites `R-A2L-DEF.140`. One docstring names `.140/11` as the graph example of `.166/1` (`test_alp_a2l_occupancy.py:1074`), and that is correct.

## 5. Candidates and rulings (TR-01 / TR-02) — `rulings.tsv`

### 5.1 X / U / O in scope: 7, all O

Ruling for all seven: **needs a canon row (operator)**. Retire: 0. Re-cite: 0.

| node (`tests/test_id_registry.py::`) | id | ruling |
|---|---|---|
| test_tc600_g1_every_named_node_id_is_registered | TC-600 (G1) | needs a canon row |
| test_tc601_g2_live_entries_name_existing_nodes | TC-601 (G2) | needs a canon row |
| test_tc602_g3_every_citation_is_registered | TC-602 (G3) | needs a canon row |
| test_tc604_g5_grammar_holds_or_is_registered_legacy | TC-604 (G5) | needs a canon row |
| test_tc606_g7_no_stem_exceeds_the_high_water_mark | TC-606 (G7) | needs a canon row |
| test_tc610_reservations_are_recorded_and_respected | TC-610 | needs a canon row |
| test_at280_registry_and_repository_agree_in_both_directions | AT-280 | needs a canon row |

**Why they are not retired:**
- Every one of these ids is LIVE in `AT-TC-REGISTRY.jsonl`, and the guarded registry and `tools/id_registry.py` are live.
- The only nearby canon pointer is `HLR-124` ("Process: id-registry hygiene", `REQUIREMENTS.md:292`). It is S0.2 **retired** in the "process … tool" class of CTX-RETIRED, which is not "superseded or withdrawn", so TR-01 forbids retiring the tests.

**Why they are not re-cited:**
- `R-DOC-CANON.10` covers only test names in review files, which is the G4 replacement.
- S0.14 `R-TST-200..203` cover other tools.

**Suggested home.** One S0.14 row for the registry guard rules G1–G3 and G5–G7, plus the reservation block. TA exec T4c is the precedent: it added S0.14 rows for 33 guard tests.

**Where these came from.** They are part of the "O/O" pool that `TA/exec/TA-REMAINING-DESIGN.md:49` left outside TA's X/U scope. They are in scope here only because Front A bumped `EXPECTED_SCANNED_TEST_FILES` (366 → 373) in the same file.

### 5.2 Front A's own nodes that are not K (outside X/U/O; listed because step 4 expects K)

| node | class | ruling | target |
|---|---|---|---|
| `tests/test_alp_s19_read_once.py::test_llr_154_1_s19_reader_line_semantics_unchanged` | S | re-cite | R-READ-002, R-READ-007.1, R-READ-007.3, R-PARSE-002, R-READ-006.1, R-READ-001.1 |
| `tests/test_alp_inc2_a2l_attach.py::test_at_alp_i2_1_direct_attach_routes_publish_snapshots` | K? (O + link) | re-cite, advisory | R-A2L-REFRESH.031, .035 |
| `tests/test_alp_inc2_a2l_attach.py::test_at_alp_i2_3_same_path_picker_generations` | K? (O + link) | re-cite, advisory | R-A2L-REFRESH.037 |
| `tests/test_alp_inc2_a2l_attach.py::test_r034_progress_throughout` | K? | re-cite, advisory | HLR-176 comment → successor (probably R-PROGRESS-LINE.3) or drop |
| `tests/test_alp_inc2_a2l_attach.py::test_at_alp_i2_2_case06_keys_and_progress` | K? | re-cite, advisory | same as above |

**`test_llr_154_1_…` (FA-TICK2u, e53631df).** This is a new node, written to the FA-TICK2u brief, and it cites `LLR-154.1`.
- **The id is absorbed.** `LLR-154.1` is absorbed in S0.2 (`REQUIREMENTS.md:322`).
- **What the node checks, row by row:**
  - CR / lone-CR / CR LF line ends → R-READ-002. The check's c2 control (`newline=''`) turns this node RED.
  - The record after S9 makes no record and gives S19-AFTER-TERMINATOR → R-READ-007.1 and .3.
  - The damaged S1 gives `Invalid byte count hex` → R-PARSE-002.
  - S5 equals the tally, because the tally counts rejected lines (`REQUIREMENTS.md:680`), so there is no S19-COUNT-MISMATCH → R-READ-006.1.
  - The blank line makes no record → R-READ-001.1.
- **The stale id is in three places:** the node name, its docstring and the module docstring.
- **A docstring-only re-cite stops at K? (mixed).** Reaching K needs a rename; the E4R records cite the current node name.

**The two AT-only nodes** link through `inc-2/02-test-cases.md:66/68` only to US-103-02, US-103-04 and US-ALP-01. None of these is in the canon's story table (55 rows), so they are `df`. As an alternative to the re-cites, the operator can fold those stories into the canon at batch close.

### 5.3 Pre-existing non-K nodes in scope: no ruling (not X/U/O; S is traceable through S0.2 by design, TA2b)

**`tests/test_b100_session_reset.py`**
- **S (8).** The ids are absorbed, with active successors through S0.2:
  - test_tc_b100_08_reset_runs_once_before_the_first_install
  - test_tc_b100_08_the_one_reset_call_sits_in_the_install_handler
  - test_tc_b100_09_twelve_b_adds_exactly_the_quit_flag
  - test_tc_b100_10_outgoing_service_finishes_after_rebind
  - test_tc_b100_10_interim_discard_notice
  - test_tc_b100_10_no_discard_notice_when_nothing_unsaved
  - test_tc_b100_10_notice_names_every_discarded_entry
  - test_tc_b100_11_unload_a2l_alone_clears_the_parsed_a2l
- **K? (11).** These are TC-B100 ids whose ledger links reach absorbed ids and df stories:
  - test_tc_b100_08_loose_file_load_performs_no_reset
  - test_tc_b100_08_call_site_census
  - test_tc_b100_09_domain_matches_the_live_source_census
  - test_tc_b100_09_two_cold_loads_have_equal_snapshots
  - test_tc_b100_09_load_over_matches_cold_outside_the_allow_list
  - test_tc_b100_09_load_over_leaves_no_p1_state
  - test_tc_b100_10_change_service_is_rebound
  - test_tc_b100_11_unload_all_clears_the_parsed_a2l
  - test_tc_b100_11_bare_s19_reload_after_unload_shows_no_a2l_tags
  - test_at_b100_03_project_load_over_unsaved_work_saves_only_p2
  - test_tc_b100_10_reset_leaves_the_patch_editor_clean_for_the_next_load
- **Front A's edit.** Front A added `_accepted_a2l_picker_snapshots` to `SNAPSHOT_EXCLUSIONS` and to `_CENSUS_AT_12B_BASE`. Two nodes read that data: `…_09_domain_matches_the_live_source_census` (K?) and `…_09_twelve_b_adds_exactly_the_quit_flag` (S).

**`tests/test_id_registry.py`, K? (5).** test_tc605_g6_normalized_keys_are_unique, test_tc607_scanned_corpus_matches_the_declared_bound, test_tc608_tokenizer_and_normalizer_edge_cases, test_tc609_registry_file_is_well_formed and test_at281_every_guard_rule_can_fail.
- **tc607 changed class.** It reads the constant Front A bumped. It was K on main and is K? here, because an alp ledger row now also links it to the absorbed `LLR-154.1`, the same stale id as in §5.2.

## 6. trace_check (copied from the dev-flow skill; output verbatim)

### (a) Brief command, `--base f44e8bc4`

`python -I -B <scratch>/tc/trace_check.py --req ".dev-flow/2026-11-18-a2l-load-performance/*/01-requirements.md" --base f44e8bc4 --src s19_app --canon REQUIREMENTS.md`

```
CASE   R-A2L-DEF.166 has no test case R-A2L-DEF.166/<n>
CASE   R-A2L-DEF.167 has no test case R-A2L-DEF.167/<n>
CASE   R-A2L-DEF.168 has no test case R-A2L-DEF.168/<n>
CASE   R-A2L-REFRESH.049 has no test case R-A2L-REFRESH.049/<n>
CASE   R-A2L-REFRESH.050 has no test case R-A2L-REFRESH.050/<n>
CASE   R-A2L-REFRESH.051 has no test case R-A2L-REFRESH.051/<n>
CASE   R-A2L-REFRESH.052 has no test case R-A2L-REFRESH.052/<n>
CASE   R-A2L-REFRESH.053 has no test case R-A2L-REFRESH.053/<n>
CASE   R-A2L-REFRESH.054 has no test case R-A2L-REFRESH.054/<n>
CASE   R-TST-011 has no test case R-TST-011/<n>
CASE   R-TST-019 has no test case R-TST-019/<n>
CASE   R-TST-026 has no test case R-TST-026/<n>
SLICE  s19_app/core.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/a2l_label_list.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/app/core.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/app/issues_checks.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/definition_sheet.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/screens.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/screens_directionb/memory_map.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/screens_directionb/patch_editor/actions.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/screens_directionb/patch_editor/panel.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/services/a2l_service.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/styles.tcss changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/tui/window_help.py changed since f44e8bc4 and no requirement file names it
SLICE  s19_app/validation/engine.py changed since f44e8bc4 and no requirement file names it
EVID   no 04-validation.md beside .dev-flow/2026-11-18-a2l-load-performance/E4R/01-requirements.md
trace_check: 4 US, 52 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, CANON, 26 gap(s)
```
Exit 1. **26 gaps.**

### (b) Same command, `--base 6eccf0cb`

```
CASE   R-A2L-DEF.166 has no test case R-A2L-DEF.166/<n>
CASE   R-A2L-DEF.167 has no test case R-A2L-DEF.167/<n>
CASE   R-A2L-DEF.168 has no test case R-A2L-DEF.168/<n>
CASE   R-A2L-REFRESH.049 has no test case R-A2L-REFRESH.049/<n>
CASE   R-A2L-REFRESH.050 has no test case R-A2L-REFRESH.050/<n>
CASE   R-A2L-REFRESH.051 has no test case R-A2L-REFRESH.051/<n>
CASE   R-A2L-REFRESH.052 has no test case R-A2L-REFRESH.052/<n>
CASE   R-A2L-REFRESH.053 has no test case R-A2L-REFRESH.053/<n>
CASE   R-A2L-REFRESH.054 has no test case R-A2L-REFRESH.054/<n>
CASE   R-TST-011 has no test case R-TST-011/<n>
CASE   R-TST-019 has no test case R-TST-019/<n>
CASE   R-TST-026 has no test case R-TST-026/<n>
SLICE  s19_app/core.py changed since 6eccf0cb and no requirement file names it
SLICE  s19_app/tui/app/issues_checks.py changed since 6eccf0cb and no requirement file names it
SLICE  s19_app/tui/services/a2l_service.py changed since 6eccf0cb and no requirement file names it
SLICE  s19_app/validation/engine.py changed since 6eccf0cb and no requirement file names it
EVID   no 04-validation.md beside .dev-flow/2026-11-18-a2l-load-performance/E4R/01-requirements.md
trace_check: 4 US, 52 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, CANON, 17 gap(s)
```
Exit 1. **17 gaps.**

### Reading the gaps

**`shared.py` is included in both runs.** `s19_app/tui/app/shared.py` is in both diffs (f44e8bc4 and 6eccf0cb) and is named at `E4R/01-requirements.md:47`, so SLICE counts it and reports no gap.

**US, TEST and CANON: 0 gaps in both runs.** Every active ledger row is in the canon and is named under `tests/`.

**CASE ×12 (both runs).** These come from the batch's case records, not from the tests.
- `E4R/02-test-cases.md` (16 lines, "State: planned") writes its cases as `.049` and `.167/.168`, not as `<id>/<n>`.
- R-TST-011, R-TST-019 and R-TST-026 have no case line at all.
- R-A2L-REFRESH.054 (log the install GC's duration) is an E4R row outside the brief's .029–.053 range. It is cited only as `.052/.054` in docstrings and in assertion strings of the two `test_r_a2l_refresh_052_install_runs_no_full_collection` nodes (inc2 and parity, both K). reverse_trace does not expand `/.054`, so it does not see .054; trace_check's TEST check does.

**SLICE (b) ×4: Front A's E4R units, named only in `E4R/RECORD.md`, its briefs and its checks, in no `01-requirements.md`.**

| file | commit | unit |
|---|---|---|
| `s19_app/core.py` | e53631df | FA-TICK2u |
| `s19_app/validation/engine.py` | 788ecbd1 | FA-TICK3u |
| `s19_app/tui/app/issues_checks.py` | 788ecbd1 | FA-TICK3u |
| `s19_app/tui/services/a2l_service.py` | 7f2286db | FA-TICKb |

**SLICE in (a) only, 9 files.** These are Front B's files. Each one is in `diff f44e8bc4..6eccf0cb` and not in `diff 6eccf0cb..78f61c42`, and f44e8bc4 is an ancestor of 6eccf0cb.

**EVID ×1 (both runs).** `E4R/` has no `04-validation.md`.

### Diagnostic run (c), not part of the brief: (b) plus `--fixes .dev-flow/2026-11-18-a2l-load-performance/E4R/RECORD.md`

This shows whether the SLICE gaps are only a records gap. The 12 CASE lines were identical to (b); the rest of the output is verbatim:

```
EVID   no 04-validation.md beside .dev-flow/2026-11-18-a2l-load-performance/E4R/01-requirements.md
trace_check: 4 US, 52 active requirements (0 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, CANON, 13 gap(s)
```

**What it shows:**
- **SLICE.** With RECORD.md accepted as a correction record, SLICE gives 0 gaps.
- **What still blocks 0 gaps.** The E4R case lines (`<id>/<n>` form, plus the three R-TST rows) and `E4R/04-validation.md`. Whether RECORD.md counts as a `--fixes` record is the orchestrator's call.

## 7. Caveats

- **Stale text in the generated summaries.** `TA-summary.md` and `TA2-summary.md` in this folder have a header that names "3afebf90". That text is hardcoded in `reverse_trace.py`. The tree analysed is 78f61c42 (an archive copy, so it has no `.git/HEAD`).
- **Stale `ci_failing` column.** The `ci_failing` column of `TA2-*.tsv` comes from the hand-curated 3afebf90 failure list, so it means nothing for this tree.
- **Host paths in the generated files.** The script-generated files (`TA-summary.md`, `TA2-summary.md`, `TA-negative-control.txt`) carry the scratch path as the script writes it; this summary does not.
- **Blind spots.** These are the same as in TA1:
  - existence is checked, not meaning;
  - ids in assertion strings and parametrize data are not read;
  - parametrised arms count once.
- **Meaning observation (no ruling).** The name of the two `test_r_a2l_refresh_052_install_runs_no_full_collection` nodes predates the amended `.052` ("at most one" full collection, D-GC = A), but their docstrings state the amended text.

## 8. Files in this folder

- `RT-summary.md`: this file.
- `rulings.tsv`: 7 O rows plus 5 advisory rows from §5.2.
- reverse_trace outputs: `TA-matrix.tsv`, `TA-inventory.tsv`, `TA-summary.md`, `TA-negative-control.txt`, `TA2-matrix.tsv`, `TA2-candidates.tsv`, `TA2-U-families.tsv` (empty: U = 0) and `TA2-summary.md`.
