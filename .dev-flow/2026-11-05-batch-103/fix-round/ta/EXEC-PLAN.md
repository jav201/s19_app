# TA exec — re-cite and retire step (s19_app batch-103 fix round)

Base: worktree `s19_app-b103-fixround`, branch `b103-fix-round` at **b5ca5b72** (folded canon). Every map line number refers to b5ca5b72.
Inputs built here (read-only, AST/text, `python -I -B`): `build_exec.py` -> `recite-map.tsv`; `retire_facts.py` -> `retire-facts.txt`; `retire-list.tsv` (TR-01 re-check by hand); `baseline-rt/` = `reverse_trace.py --ta2` on b5ca5b72 (tests 6966: K 3062, K? 602, S 1215, O 1563, **X 484, U 40**) and `baseline-rt/scope-before.tsv` (class before, per in-scope test).

## Decisions taken here (with the reason)
- **One script applies the whole map (U1), not 22 three-file units.** 386 applied rows over 65 files are pure docstring/comment edits. A script is deterministic, re-runnable and checkable by one AST rule: the module AST with docstrings stripped must be identical before and after (code cannot change). Hand units would put prose surgery in 22 model sessions.
- **Two edit forms only.** `REPLACE`: the test's own docstring/comment holds exactly one dead id -> swap the token for the new id(s). `ADD`: everything else (module/class-docstring citations shared by many tests, ids derived from a node name, `R-<n>` risk labels, AT/AC/TC labels and `<row>/<n>` case ids that key the ledgers, or 2+ dead ids in one prose span) -> append one `Traces: <ids>.` line to the test's own docstring and leave the old text as history. Never a rename.
- **Retirement by name, after the re-cite (U2 on top of U1).** The retire script finds functions by AST name, so map line numbers stay valid for U1 at b5ca5b72.
- **No DeepSeek flash unit.** Every fixed text (registry reason, statements, the S10 cell) is written verbatim in `units/U2-retire.md`.
- **Law gap, stated.** No law file checks that an `R-`/`US-` id cited in `tests/` is a canon row (G3 covers AT/TC only; R-DOC-CANON.8 covers S0.2 only). The re-cite oracle is therefore the apply script's preflight plus `reverse_trace.py`, not a law.

## Units, in order
| # | Unit | Model | Inputs | Files touched | Oracle that proves it worked |
|---|---|---|---|---|---|
| U0 | Host prep (orchestrator) | none | clone at b5ca5b72; `recite-map.tsv`, `retire-list.tsv`, `baseline-rt/scope-before.tsv`, `reverse_trace.py` | none | base laws transcript (six law files, `-n 0`), base `--collect-only -q tests` node count N0, reverse_trace baseline re-run on the host = 6966 / X 484 / U 40 |
| U1 | `units/U1-recite.md` | v4-pro | `recite-map.tsv` | worker writes 2 files (`apply_recite.py`, `test_apply_recite.py`); the script edits 65 test files (docstrings/comments only) | 386 rows applied, 4 NEEDS-RULING skipped; docstring-stripped AST identical per file; reverse_trace: every in-scope test without a NEEDS-RULING row leaves X/U; whole tree **X 484 -> 278, U 40 -> 7** (retirees still present); `--collect-only` delta **0**; laws: no new RED vs U0 |
| C1 | `units/C-check.md` + `frontB/CHK-ds.md` | DeepSeek, other session | U1 tree, base clone | none | MECH-GO |
| U2 | `units/U2-retire.md` | v4-pro | `retire-list.tsv` rows 1-14 | worker writes 1 file (`retire_apply.py`); the script edits 8 test files, `AT-TC-REGISTRY.jsonl`, `docs/requirements/review/S10-ears-strict.md` | exactly 13 `def test_` removed, nothing else; `--collect-only` delta **exactly -13** vs U1 (-14 only if the operator overrides the FLAG row); TC-678 RETIRED; TC-638/628/011/017 lose only the retired nodes; reverse_trace whole tree **X 269, U 3, tests 6953**; laws: no new RED vs U0 |
| C2 | `units/C-check.md` | DeepSeek, other session | U2 tree, U1 tree | none | MECH-GO |
| IR | Intent review (orchestrator) | Opus | C1/C2 CHECK.md, diffs | none | read every SUPERSEDED/SPLIT/U-STALE row, 20 sampled REPLACE lines, the whole U2 diff |

Six law files (checker only, serial): `tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`. "No new RED" is against U0's transcript at b5ca5b72, not the 3afebf90 list in CHK-ds.

## Counts (what the map holds)
- Re-cite, 261 tests / 390 rows: X KEEP-RETRACE 203, X DELETE-DUP 5 (kept; target = the twin's row), U RENUMBERED 31, U STALE 4, T5 1, split parents 9 (F2a/F2a-2), batch-102 rows superseded by batch-103 7, TR-01 flag 1.
- Applied: 257 tests, 386 rows (144 REPLACE, 242 ADD rows = 122 tests get a `Traces:` line).
- NEEDS-RULING, 4 tests (skipped by U1): `test_examples_pilot_gifs::test_case_pilot_capture_and_gif` (R-7, no active row: its LLR-122.5 is retired); `test_b101_designer_recompute::test_r_crc_preview_coverage_crc_error_after_a_clean_evaluation_is_named` (no coverage row; candidate R-CRC-DESIGNER-002.5 or orphan); `test_b102_patch_picker::test_tc_b102_pe_06_empty_states_mirror_check` (live lines, but only Check Editor rows R-CHKED-002/.004 name them); `test_validation_mac::test_validate_mac_records_reports_parse_and_empty_fields` (TR-01 fails for its retirement: R-VAL-020 arm is live).
- Retire: 13 tests + TC-678 (retire-list rows 1-14), all TR-01 PASS with the deciding row re-read in b5ca5b72. One proposed retirement fails TR-01 (row FLAG).

## Deliberately left for later
- (d) T3 8 GAP rows, T4 class rows, F2b test cases, UNIMPLEMENTED code units.
- The 4 NEEDS-RULING tests above; the 54 X KEEP-NEWREQ tests (operator policy question in `TA2b-X-summary.md`).
- Tests citing rows moved to S0.2 history by F2a-2 (`CONGRUENT -> HISTORY`, e.g. R-TST-008, R-TST-070): the fold note says they re-trace "to the history line"; not in the approved set, and a history line is not an active row (TR-02).
- Side findings, no action here: TC-679 and AT-295 verify the same retired HLR-133 as TC-678 and stay LIVE (US-125 is not in the canon); `tests/test_tui_workspace.py::test_tc_041_find_repo_root_recognises_project_toml_marker` verifies the D5-8 fallback too; D4-11 `context preserved` asserts in `tests/test_tui_hexview.py:311`, `tests/test_b101_hex_jump.py:1169`; the product helper `list_diff_reports` (D14-8 code change).
- Product code: none in this step.
