# Increment 003 — Inc 3 · R-PROJ-GATHER.12/.13, R-PROJ-002.12…14, R-PROJ-001.13, R-PROJ-ROLLBACK, R-TST-110…113 · gather once per name without resolve, no folder re-creation on sync, panel-paint timing verifiers

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-3/`: `01-requirements.md` (US-PROJ-SAVE-1, US-PROJ-SYNC-1, US-TST-PAINT-1; 12 active requirements), `02-test-cases.md` (30 cases), `E1-rulings.md`, `E1-slice.md`, `E1-profile.md`, `E3-rulings.md`, `E3-architect.md` + `E3-r2.md`, `E3-security.md`, `E4-impl-notes.md`, `E4-tester-notes.md`, `E4-integration-notes.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-rulings.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc3.md`, `evidence/`. Branch `b101-inc3` from `main` (`9f9f6af`), head `77a0ac4` plus the uncommitted E5 records and the corrective-pass test edits.

Models per stage (from `steps.log` and the orchestrator's assignment): Opus — E1–E3 (requirements, rulings, both design reviews, the E3 corrective), the E4 integration step, the E5 code and security reviews, the coverage audit and the E5 corrective pass; Sonnet — the E4 implementer and the independent tester (the Kimi weekly quota was exhausted), the E5 mutant battery and LAN runs, and this record.

| Field | Value |
|---|---|
| Batch | `2026-11-01-batch-101` |
| Increment | `003` |
| Lane (if the batch forked) | none |
| Requirement(s) | R-PROJ-GATHER.12 · R-PROJ-GATHER.13 · R-PROJ-002.12 · R-PROJ-002.13 · R-PROJ-002.14 · R-PROJ-001.13 · R-PROJ-ROLLBACK.2 · R-PROJ-ROLLBACK.9 · R-TST-110 · R-TST-111 · R-TST-112 · R-TST-113 (stories US-PROJ-SAVE-1, US-PROJ-SYNC-1, US-TST-PAINT-1) |
| Acceptance | the 30 cases of `02-test-cases.md`; black-box by keys: Save project (`ctrl+s`), Load (`ctrl+l` + replace question), A2L typed into the Load dialog · white-box: the gather, the two syncs and the verifier nodes · unit: the clock rule node |
| Agent | `software-dev` |
| Date | 2026-11-05 |

---

## 1 · What changed

A Save project over a large composition no longer pays one filesystem check per repeated document name, and a load into a project whose folder was deleted outside the app is refused instead of bringing the folder back. In `gather_project_artifacts` a name whose exact text was already checked is skipped, and the check is a lexical join (`os.path.normpath`) with `is_file()` instead of `resolve()`, so a link loop at a composition name no longer raises and the name falls to the common patches library (R-PROJ-GATHER.12/.13). The two sync functions in `app.py` lose their `mkdir`, so a deleted folder reaches `validate_project_files`, which refuses with the existing `… sync NOT done …` lines, and nothing is re-created (R-PROJ-002.12 … .14). In the test suite the Load-result panel and variant-append timing arms now start their clock at the install stamp and stop it at the product's own paint and outcome-line stamps, with a verifier that compares the arms' values to a class-level observer (R-TST-110 … 113); the 1 s bounds are not raised. Shipped surface: Save project, Load and A2L attach in the TUI. No painted text is new; one painted line changes in one scene (a Save whose composition names a link loop ends with R-PROJ-ROLLBACK.9's refusal instead of the unexpected-error line).

---

## 2 · Files modified

**The budget counts SOURCE files only. Tests are not capped. Product docs and `.dev-flow/**` are outside the count.**

Committed: `git diff --stat main...HEAD` (96 files, +14 904 / −42). Uncommitted: the corrective-pass test edit, the E5 records and the transcripts marked below. SOURCE files: **2 / 4**.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/services/project_gather_service.py` | source | US-PROJ-SAVE-1 | `gather_project_artifacts`, composition limb: a `checked_names` set skips a name whose exact text was already checked; the check is `Path(os.path.normpath(resolved_project / name)).is_file()` with no `resolve()`, so a link loop at a name falls to the library; the Data Flow docstring states why |
| `s19_app/tui/app.py` | source | US-PROJ-SYNC-1 | `_sync_loaded_file_to_project` and `_sync_loaded_a2l_to_project` lose their `project_dir.mkdir(parents=True, exist_ok=True)` (2 lines): a deleted project folder is refused at `validate_project_files` and not re-created |
| `tests/test_project_gather.py` | test | US-PROJ-SAVE-1 | 3 new nodes: GATHER.12 (1 000 checks not 2 000; a missing name twice = 1 check; `missing/../x.json` folded, the spy also records the raw text), GATHER.13/1 (Windows junction loop), GATHER.13/2 (POSIX self-symlink) |
| `tests/test_b100_active_variant.py` | test | US-PROJ-SAVE-1 | Save project by keys (`ctrl+s`, dialog) node; the ROLLBACK.9 and ROLLBACK.2 link-loop nodes; the exact `Project saved + manifest verified` line pinned for `save-project` |
| `tests/test_b100_workers.py` | test | US-PROJ-SYNC-1 | R-PROJ-002.12 (deleted and file-in-place arms), 002.13 (A2L mid-attach), 002.14 (s19/hex/mac/a2l, each asserting its sync refusal) and the by-keys Load and A2L-typed nodes; `TC-B100-54` docstring |
| `tests/test_b100_project_check.py` | test | US-TST-PAINT-1 | `_paint_clock_start` re-pinned to the install stamp; `_StampObserver` with its own layout reading and `_watch_panel_paint`; the R-TST-110 rule node, the R-TST-111/112 verifier (`all-bad`/`cap`/`scene`), the R-TST-113 source check; the 6 arms moved to the product's stamps and `wait_until` |
| `tests/test_b97_flow_execution.py` | test | US-TST-PAINT-1 | `@pytest.mark.serial_timing` on `test_tc_b97_64_burst_on_two_waiting_lanes_confirms_one` (ruling OR-5), nothing else in the node |
| `tests/support/suite_census.py` | test | US-TST-PAINT-1 | the burst arm listed by hand in `SAMPLED_TIMING_ARMS` (seam ruling S-2) so the marker guard accepts the mark |
| `tests/test_suite_hygiene.py` | test | US-TST-PAINT-1 | `_SAMPLED_PIN` names the same hand entry (S-2) |
| `.dev-flow/BACKLOG-CODE.md` | doc |  | batch-101 Inc 3 rows: S-3 + E5S-1, S-4, S-5, E5S-2, CR-8, OR-4 / D-4, and the CR-2 extension of the `TC-B97-64` burst row |
| `.dev-flow/2026-11-01-batch-101/inc-3/01-requirements.md` | doc |  | EARS requirements: US-PROJ-SAVE-1, US-PROJ-SYNC-1, US-TST-PAINT-1; R-PROJ-001.13, GATHER.12/.13, ROLLBACK.2/.9, 002.12 to .14, R-TST-110 to 113 |
| `.dev-flow/2026-11-01-batch-101/inc-3/02-test-cases.md` | doc |  | 30 ISO 29119-3 cases (26 + 4 added at E5), Result per platform, the mutant table with M-12, M-C1, M-C3; audited at E5 (uncommitted: Result cells of 002.14/4 and R-TST-111/1-3, 112/1) |
| `.dev-flow/2026-11-01-batch-101/inc-3/E1-profile.md` | doc |  | E1 profile of the Save project margin (R1-P1) and the painted ~1 s step |
| `.dev-flow/2026-11-01-batch-101/inc-3/E1-rulings.md` | doc |  | E1 decisions D-1 to D-4, observations O-1 to O-3 and the backlog rows S-3, S-4, S-5, D-4 |
| `.dev-flow/2026-11-01-batch-101/inc-3/E1-slice.md` | doc |  | E1 slice: the functions to change mapped to rows, drift check against origin/main |
| `.dev-flow/2026-11-01-batch-101/inc-3/E3-architect.md` | doc |  | E3 design review round 1 (architect): FAIL, F1 HIGH, F2 MAJOR, F3 to F11 MINOR |
| `.dev-flow/2026-11-01-batch-101/inc-3/E3-r2.md` | doc |  | E3 round 2 (architect): PASS-WITH-NOTES, F1 and F2 closed, notes N-1 to N-3 |
| `.dev-flow/2026-11-01-batch-101/inc-3/E3-rulings.md` | doc |  | E3 round 1 rulings and the E4 addenda A-1 to A-4 |
| `.dev-flow/2026-11-01-batch-101/inc-3/E3-security.md` | doc |  | E3 design security review: FAIL (BLOCK-UNTIL S-1), closed with F1 |
| `.dev-flow/2026-11-01-batch-101/inc-3/E4-impl-notes.md` | doc |  | E4 implementer notes (Sonnet): the 3 functions changed, no deviation |
| `.dev-flow/2026-11-01-batch-101/inc-3/E4-integration-notes.md` | doc |  | E4 integration (Opus): GREEN on Windows, OR-1 to OR-5, S-1 to S-4 |
| `.dev-flow/2026-11-01-batch-101/inc-3/E4-tester-notes.md` | doc |  | E4 independent tester notes (Sonnet): case-to-test mapping, RED on base, mutant plan |
| `.dev-flow/2026-11-01-batch-101/inc-3/E5-code-review.md` | doc |  | E5 code review: PASS-WITH-NOTES, CR-1 to CR-8 |
| `.dev-flow/2026-11-01-batch-101/inc-3/E5-corrective-notes.md` | doc |  | E5 corrective pass C-1 to C-11 (Opus), backlog rows, final runs |
| `.dev-flow/2026-11-01-batch-101/inc-3/E5-coverage-audit.md` | doc |  | Independent coverage audit and its re-audit: 30/30 covered, 27 full, 3 partial (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-3/E5-mutants.md` | doc |  | E5 mutant table M-1 to M-11 and the owed Linux runs (Sonnet) |
| `.dev-flow/2026-11-01-batch-101/inc-3/E5-rulings.md` | doc |  | E5 rulings C-1 to C-11 and the backlog routing |
| `.dev-flow/2026-11-01-batch-101/inc-3/E5-security.md` | doc |  | E5 security review: PASS-WITH-NOTES, E5S-1 to E5S-5 |
| `.dev-flow/2026-11-01-batch-101/inc-3/codewire/graph-inc3.md` | doc |  | Code-Wire graph: 15 nodes, contracts and examples |
| `.dev-flow/2026-11-01-batch-101/inc-3/steps.log` | doc |  | Stage log: models and UTC stamps (uncommitted: the E5 records line) |
| `.dev-flow/2026-11-01-batch-101/inc-3/04-validation.md` | doc |  | This increment's validation record (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-003.md` | doc |  | This packet (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-base-4dfb5a1-vs-head.txt` | generated | US-PROJ-SAVE-1 | E1 profile transcript or script for the Save project step (R1-P1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-busy-vs-quiet-waiter.txt` | generated | US-PROJ-SAVE-1 | E1 profile transcript or script for the Save project step (R1-P1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-cprofile-callers-e266395.txt` | generated | US-PROJ-SAVE-1 | E1 profile transcript or script for the Save project step (R1-P1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-cprofile-e266395.txt` | generated | US-PROJ-SAVE-1 | E1 profile transcript or script for the Save project step (R1-P1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-cprofile-gather-memo.txt` | generated | US-PROJ-SAVE-1 | E1 profile transcript or script for the Save project step (R1-P1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-experiments-script-runs.txt` | generated | US-PROJ-SAVE-1 | E1 profile transcript or script for the Save project step (R1-P1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-marks-e266395.txt` | generated | US-PROJ-SAVE-1 | E1 profile transcript or script for the Save project step (R1-P1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-node-experiments.txt` | generated | US-PROJ-SAVE-1 | E1 profile transcript or script for the Save project step (R1-P1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/appended-poll-vs-stamp.txt` | generated | US-TST-PAINT-1 | E1 measurement of the `sec6_5 appended` interval (poll clock vs product stamp, split) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/appended-split.txt` | generated | US-TST-PAINT-1 | E1 measurement of the `sec6_5 appended` interval (poll clock vs product stamp, split) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c1-observer-own-reading.txt` | generated | US-TST-PAINT-1 | C-1: the observer's own reading; M-C1 and the predicate mutants |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c10-save-project-windows.txt` | generated | US-TST-PAINT-1 | C-10: 3 more `save-project` runs on Windows, 0.515 to 0.582 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c2-m9-lan-and-windows.txt` | generated | US-PROJ-SAVE-1 | C-2: M-9 killed on LAN Linux and on Windows (raw-text spy) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c3-c8-sync-mutants-lan.txt` | generated | US-PROJ-SYNC-1 | C-3/C-8: M-3, M-4, M-C3 against the 002.14 arms and the by-keys nodes (LAN Linux) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c6-m6-m7ci-final-file-lan.txt` | generated | US-TST-PAINT-1 | C-6: M-6 and M-7 (`CI=1`) RED by the equality, head file without the C-9 print lines |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c7-c8-rollback-mutants.txt` | generated | US-PROJ-SAVE-1 | C-7/C-8 and C-10 mutants M-10, M-11, M-12 on Windows, junction arms 6 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c9-stamp-gaps-lan.txt` | generated | US-TST-PAINT-1 | C-9: stamp-pair gaps of the verifier, 3 serial runs, all under 0.5 ms |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-final-lane1-lan.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 final lane 1: 318 passed, 10 skipped, 1 xfailed (LAN Linux, idle) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-final-serial-lan.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 final serial lane: 23 passed, 1 skipped, 0 bounds under 20 % (LAN Linux) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-law-guards-lan.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 law guards: 196 passed (LAN Linux) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5d-a2l-sync-assert-lan.txt` | generated | US-PROJ-SYNC-1 | Re-audit item (a): the `[a2l]` arm asserts the A2L sync; GREEN on the tree, RED under the never-reaches-the-sync mutant (LAN Linux) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5d-final-lan.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | Final run: workers + hygiene + registry, `-n 8 -m "not serial_timing"` (LAN Linux) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/impl-smoke.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E4 implementer smoke run (155 passed, 1 xfailed) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-00-first-attempts.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E4 integration run (see E4-integration-notes.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-01-verifier-diag.txt` | generated | US-TST-PAINT-1 | E4 integration run (see E4-integration-notes.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-02-touched-lane1.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E4 touched files, parallel selection (Windows): 248 passed, 1 xfailed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-03-serial-lane.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E4 serial lane (Windows): 52 passed, 1 failed (`sec6_5 load` 1.001 s) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-04a-guards.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E4 integration run (see E4-integration-notes.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-04b-importers.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E4 integration run (see E4-integration-notes.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-04c-importers.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E4 integration run (see E4-integration-notes.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-04d-importers.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E4 integration run (see E4-integration-notes.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-05-verifier-3of3.txt` | generated | US-TST-PAINT-1 | E4 integration run (see E4-integration-notes.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-06-serial-lane-rerun.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E4 serial lane rerun (Windows): 53 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-01-lane1.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 lane 1: 1 failed (stale `main` ref), 301 passed (LAN Linux) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-01b-hygiene-049-diag.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | Diagnosis of the `test_r_tst_049` failure: a stale clone ref; passes against `9f9f6af` |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-02-serial-run1.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-02-serial-run2.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-02-serial-run3.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-02-serial-run4-loadnote.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-02-serial-run4.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-loadnote.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-run1.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-run2.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-run3.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-run4.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-run5.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-04-posix-arms.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 LAN Linux owed run (see E5-mutants.md) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M1.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant transcript, applied and restored byte-exact |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M10.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant transcript, applied and restored byte-exact |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M11.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant transcript, applied and restored byte-exact |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M2.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant M-2 transcript, applied and restored byte-exact; one pytest-truncated temp-folder prefix redacted at E5 (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M3.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant transcript, applied and restored byte-exact |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M4.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant transcript, applied and restored byte-exact |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M5.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant transcript, applied and restored byte-exact |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M6.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant transcript, applied and restored byte-exact |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M7.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant transcript, applied and restored byte-exact |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M8.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant transcript, applied and restored byte-exact |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M9.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | E5 mutant transcript, applied and restored byte-exact |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/painted-step-main-profile.txt` | generated | US-TST-PAINT-1 | E1 diagnosis of the bimodal `painted` interval |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/painted-step-marks.txt` | generated | US-TST-PAINT-1 | E1 diagnosis of the bimodal `painted` interval |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/red-01-tester-base.txt` | generated | US-PROJ-SAVE-1 · US-PROJ-SYNC-1 · US-TST-PAINT-1 | Tester RED on base `9f9f6af`: gather 3 failed, workers + variant 9 failed, mutants M5 to M8 (Windows) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/sync-end-lines-base.txt` | generated | US-PROJ-SYNC-1 | E3 corrective F8: the end lines of a load with the project folder gone, on base |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-profile-script.py` | generated | US-PROJ-SAVE-1 | E1 profile transcript or script for the Save project step (R1-P1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/appended-split-script.py` | generated | US-TST-PAINT-1 | E1 measurement of the `sec6_5 appended` interval (poll clock vs product stamp, split) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/appended-stamp-script.py` | generated | US-TST-PAINT-1 | E1 measurement of the `sec6_5 appended` interval (poll clock vs product stamp, split) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/painted-step-script.py` | generated | US-TST-PAINT-1 | E1 diagnosis of the bimodal `painted` interval |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/r1p1_exp.py` | generated | US-PROJ-SAVE-1 | E1 R1-P1 experiments as a pytest plugin |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-3/sync-end-lines-script.py` | generated | US-PROJ-SYNC-1 | E3 corrective F8: the end lines of a load with the project folder gone, on base |

| Count | Value |
|---|---|
| **SOURCE files** | **2 / 4** |
| Test files | 7 (uncapped) |
| Doc files | 23 (outside the count), plus 68 evidence files |

- ⚠ **Below the cap:** 2 source files (`project_gather_service.py`, `app.py`). `project_gather_service.py` joined the slice by ruling D-1 (2026-11-02): the composition check lives there and not in `app.py`.
- The test-file edit made at this record's close: `tests/test_b100_workers.py`, 3 lines (the `[a2l]` arm of R-PROJ-002.14/4 asserts `A2L_SYNC_REFUSAL` once).

---

## 3 · How to test

```bash
# LAN Linux host (fish login shell: wrap in bash -lc), interpreter of the s19ci env
env -u NO_COLOR PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m pytest -q -p no:cacheprovider \
  tests/test_project_gather.py tests/test_b100_workers.py tests/test_b100_active_variant.py \
  tests/test_b100_project_check.py tests/test_b97_flow_execution.py \
  tests/test_suite_hygiene.py tests/test_id_registry.py -n 8 -m "not serial_timing"
# the serial lane (timing arms, the verifier, save-project)
env -u NO_COLOR PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m pytest -q -p no:cacheprovider -m serial_timing \
  tests/test_b100_project_check.py tests/test_b100_active_variant.py tests/test_b97_flow_execution.py
# law guards
env -u NO_COLOR PYTHONPATH=. python -m pytest -q tests/test_engine_unchanged.py tests/test_tui_directionb.py tests/test_requirements_canon.py
# Windows-only arms (junction loops): a Windows host with an isolated LOCALAPPDATA
python -m pytest -q tests/test_project_gather.py -k r_proj_gather_13
python -m pytest -q tests/test_b100_active_variant.py -k "r_proj_rollback_9_2 or (tc_b100_20 and save-project)"
```

---

## 4 · Test results

Windows (E4 integration): touched files 248 passed, 1 xfailed; serial lane 52 passed + 1 failed (the `sec6_5 load` bound, 1.001 s, not an Inc 3 row) then 53 passed; verifier 3/3. LAN Linux (E5 corrective, idle host): lane 1 **318 passed, 10 skipped, 1 xfailed**; serial lane **23 passed, 1 skipped**, QC-TM 43 bounds, 0 under 20 %; law guards **196 passed**; final run with the re-audit edits: **158 passed, 1 xfailed** in 448.19 s on LAN Linux (`e5d-final-lan.txt`). Black-box by keys: Save project, Load over unsaved work and an A2L typed into the Load dialog each assert the painted lines (Linux; no Windows run). Mutants **14 / 14 killed**; after the coverage re-audit: **30 cases, 30 covered, 0 `gap`, 27 full, 3 partial**. Details: `04-validation.md`.

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **0 · unit** | `core` · `full` | `test_r_tst_110_panel_clock_starts_at_the_install_stamp`, `test_r_tst_113_panel_and_append_bounds_stay_at_one_second` | passed (Windows `int-02-touched-lane1.txt`; LAN `e5c-final-lane1-lan.txt`) |
| **A · white-box** `TC` ↔ LLR | `core` · `full` | `test_r_proj_gather_12_*`, `test_r_proj_gather_13_*`, `test_r_proj_002_12_*`, `test_r_proj_002_13_*`, `test_r_proj_002_14_*`, `test_r_proj_rollback_9_2_*`, `test_r_tst_111_112_arm_values_equal_the_product_stamps[all-bad/cap/scene]` | lane 1 318 passed, serial 23 passed (LAN); junction arms 6 passed (Windows) |
| **B · black-box** `AT` ↔ story, through the shipped surface | `core` · `full` | the by-keys nodes: Save project (`ctrl+s`), Load (`ctrl+l`, replace question), A2L typed (`ctrl+l`) | passed on LAN Linux (`e5c-final-lane1-lan.txt`); not run on Windows (operator run rule) |

### RED counterfactual

| Field | Value |
|---|---|
| **RED counterfactual** | The tester's RED on base `9f9f6af`: gather 3 failed, workers + active-variant 9 failed (5 passed), and mutants M5 to M8 on the test file each RED — `evidence/inc-3/red-01-tester-base.txt`. The re-audit's own new assertion (`lines.count(A2L_SYNC_REFUSAL) == 1` in the `[a2l]` arm of R-PROJ-002.14/4) fails under the mutant "the A2L attach never calls `_sync_loaded_a2l_to_project`" (the call replaced by `pass`, `app.py` in a private LAN worktree): `assert 0 == 1`, 1 failed; GREEN unmutated, 1 passed; `app.py` digest prefix `ec7839290cb95543` before and after — `evidence/inc-3/e5d-a2l-sync-assert-lan.txt` |

| Field | Value |
|---|---|
| **Mutation verdicts** | 14 mutants, all KILLED, per node in `E5-mutants.md` and `E5-corrective-notes.md`: M-1 (`resolve()` restored; killed by the POSIX self-symlink node), M-2 (once-per-name skip removed), M-3 / M-4 (sync `mkdir` restored; 002.12/.14 arms and the by-keys nodes), M-5 (clock rule `max`), M-6 / M-7 (clocks stopped at the wait; M-7 with `CI=1` killed by the equality), M-8 (bound raised), M-9 (fold dropped; killed on both platforms), M-10 / M-11 / M-12 (link refusal, `written` not handed to the rollback, `home_preexisted`), M-C1 (arm's reading one pass late), M-C3 (the load never posts the sync). Arms that stayed GREEN: M-7 `[all-bad]` and `[cap]` (they do not measure the append). 3 equivalent predicate mutants recorded and not counted. Each restored byte-exact (digest). Transcripts `evidence/inc-3/mut-M1.txt` … `mut-M11.txt`, `e5c-*` |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 3 instruments shown RED before their PASS was believed: the verifier (RED under M-6 and M-7, `red-01-tester-base.txt`, `e5c-c6-m6-m7ci-final-file-lan.txt`); the GATHER.12 arm-3 spy (RED under M-9 on both platforms once it records the raw text, `e5c-c2-m9-lan-and-windows.txt`); the observer's own reading (RED under M-C1, `e5c-c1-observer-own-reading.txt`) |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | The by-keys nodes assert the painted status lines the product emits (exact last line, refusal counted once, forbidden lines absent, no folder at the project path, no run left): `Project saved + manifest verified`, `Loaded other.s19`, `A2L loaded: firmware.a2l` and the two `… sync NOT done: project 'P2' could not be read — …` lines — `e5c-final-lane1-lan.txt`, `e5c-c3-c8-sync-mutants-lan.txt` |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

| Evidence artifact | Path — under `artifact_homes.evidence` | SHA-256 |
|---|---|---|
| `R1-P1-base-4dfb5a1-vs-head.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-base-4dfb5a1-vs-head.txt` | `bb55230b8a2ff69a58b8e4df6bd47ef45c8f004c8b81bc3fdd6150d50be74e30` |
| `R1-P1-busy-vs-quiet-waiter.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-busy-vs-quiet-waiter.txt` | `ff519d8a7ce7999b9946f94872356a7bf40c263651a0ad8e3f81c674a3f65476` |
| `R1-P1-cprofile-callers-e266395.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-cprofile-callers-e266395.txt` | `139a3fbe17d60884acd1f85f1cc40f3a41693f36017b6dc3c74549aadecc6ff2` |
| `R1-P1-cprofile-e266395.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-cprofile-e266395.txt` | `b3372ef851c583b5d233a4aba58704df9c349de285cd1369e4b0318978bc0b54` |
| `R1-P1-cprofile-gather-memo.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-cprofile-gather-memo.txt` | `59bf319e51599555a32d1afec40583808a17b43e9ade25879b13c4b2cbf03c42` |
| `R1-P1-experiments-script-runs.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-experiments-script-runs.txt` | `f4b2596e31c1e6f806944402adcbf1312f0b050908bfd030f64f70629dec8a0f` |
| `R1-P1-marks-e266395.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-marks-e266395.txt` | `714e5df1efd5b36f40db05ba5b199e47eb94dc964038930f4262cc294b6b31dc` |
| `R1-P1-node-experiments.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/R1-P1-node-experiments.txt` | `2c6a83bd7c00de6f6ee0f17e57e7f9d4aac8f3bef0150c460b7e7f8f50a31889` |
| `appended-poll-vs-stamp.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/appended-poll-vs-stamp.txt` | `0e9f5975d1a52fcbf4f743e2c67c8c947224c552c55ca168f4f0074a139f68c9` |
| `appended-split.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/appended-split.txt` | `98909148904bd462546b0a248e144cf7be42cd12124b47d9ccb7eea3054f12df` |
| `e5c-c1-observer-own-reading.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c1-observer-own-reading.txt` | `6086150d8b18e8e7cfeb2b717df06e3522d58481888416de11d94639b1ece4b3` |
| `e5c-c10-save-project-windows.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c10-save-project-windows.txt` | `c6f714c9de88a683c0f80ff407a46b19bdc0c90e4d10a39ff868a221af287357` |
| `e5c-c2-m9-lan-and-windows.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c2-m9-lan-and-windows.txt` | `cd8e9be4b5ead4f57584c3d3ec4524950797a1b9600535137bd69244a534e9d2` |
| `e5c-c3-c8-sync-mutants-lan.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c3-c8-sync-mutants-lan.txt` | `442535a3752912cccd06746022c74a005d715541f4761e63b01bd355f776a373` |
| `e5c-c6-m6-m7ci-final-file-lan.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c6-m6-m7ci-final-file-lan.txt` | `eaa56a98e7d1b8b13a2f77fa43b1f3ab8e619c7c112545caf8982baa5c61725b` |
| `e5c-c7-c8-rollback-mutants.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c7-c8-rollback-mutants.txt` | `1cac83f6be1bbdcc48d0aad91dcdacbdafc9fc80cde0be0acf3c35f972845c78` |
| `e5c-c9-stamp-gaps-lan.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-c9-stamp-gaps-lan.txt` | `f5897d65ebdfd1b28c5e14555d15ca8650fbc4b76c9092fec77fef1808f23088` |
| `e5c-final-lane1-lan.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-final-lane1-lan.txt` | `a642f38c05f2eae07b33b90dba480667a689ce2a6949529f15fd8a17c413c5d6` |
| `e5c-final-serial-lan.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-final-serial-lan.txt` | `bfb383e138804cc161c27975c0fa5aeb5118854eed9db174bc07cc42d3f44a2e` |
| `e5c-law-guards-lan.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5c-law-guards-lan.txt` | `ae943f336e3a677cfb0e68f645836742d0744d8a4ee62102f0d45f7116cfc8d1` |
| `e5d-a2l-sync-assert-lan.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5d-a2l-sync-assert-lan.txt` | `e4f8a7baf728c2a8f75c38efbbad510d1952ad04b91bde6fdc2c5e93910be8e3` |
| `e5d-final-lan.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/e5d-final-lan.txt` | `2f6757c5df4e5de1dee6068f7cf5333c017f8979b7a1b10dde9795f3739c6fec` |
| `impl-smoke.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/impl-smoke.txt` | `c94f70be3d6ea864f23922adeeaaabf486b55b20fbb0b47d30899c261a71eb60` |
| `int-00-first-attempts.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-00-first-attempts.txt` | `3b15a65f1763deeefb23ce9fb03f0da2e646a8ca9fdfacd7f01d4a803833491b` |
| `int-01-verifier-diag.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-01-verifier-diag.txt` | `c913f650c32ac7b6b00080f5df76246b4aadddd816b056c9b8a23f2e19139df6` |
| `int-02-touched-lane1.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-02-touched-lane1.txt` | `10716cd0bd46e9dfbfe1c06ce1f6308fcc8702862a1a9d93960b29a723413057` |
| `int-03-serial-lane.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-03-serial-lane.txt` | `49eb322283bed74c059e994e2154c116c030c0724e30745a9d8f30a0e8050a07` |
| `int-04a-guards.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-04a-guards.txt` | `7cf0bde0d0ed700f79f881deda77e2b62db88e73c7c99670481998fa2f1fec04` |
| `int-04b-importers.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-04b-importers.txt` | `ee5173b6bb1e987446ef6ad42e561d16083ca711c1f49fbb0d71347b51d288cb` |
| `int-04c-importers.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-04c-importers.txt` | `413b21069e26632c61426b21867f84e012b4d617ee53b2652c5dcd801a5fcd1a` |
| `int-04d-importers.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-04d-importers.txt` | `ce2589658392b2f31ebb819777f8df86c5c76bcc0ce57592cfc8e06f78bceb96` |
| `int-05-verifier-3of3.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-05-verifier-3of3.txt` | `073566a926b6fb35c3cf39e9a1ca0c4865548a862ed1be59783cdd0ef4860d3f` |
| `int-06-serial-lane-rerun.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/int-06-serial-lane-rerun.txt` | `0076bf6e32e155283676be8a84430eb42e49d9ff2b5e82d283dfbc19cc899a8d` |
| `lan-01-lane1.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-01-lane1.txt` | `6134d04d832293262d54661ebe119aed2a5edbaaa7ab7a925174c4abfee1738d` |
| `lan-01b-hygiene-049-diag.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-01b-hygiene-049-diag.txt` | `906c25e756c5dae8f77e22289fd744698d3dc7078a7c46caac6c6712d8e0f10b` |
| `lan-02-serial-run1.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-02-serial-run1.txt` | `1bf33dd2142449c78086120213ced8a59eeec261a977b795fd518234bb3e6868` |
| `lan-02-serial-run2.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-02-serial-run2.txt` | `af1c16e75794faffed0f2b2c9472701954d6a47bcd399323850a9c7c3a96dde1` |
| `lan-02-serial-run3.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-02-serial-run3.txt` | `ef5901af8b11b1d0a429d41bfe2de213b44de78b3de6ac1e0b93976f553c9522` |
| `lan-02-serial-run4-loadnote.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-02-serial-run4-loadnote.txt` | `827d5520deb322cf910151403250b09b36268a04ef7617f7743a1ae9dc68108d` |
| `lan-02-serial-run4.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-02-serial-run4.txt` | `18075f04504d7ed723fc9dd04c7434749f87b6b1590d155250cf881bc79f37f1` |
| `lan-03-saveproject-loadnote.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-loadnote.txt` | `8328d91255fb23046ecfec9ab8dee8f10c93c803ff771a6a60bb080eef26c476` |
| `lan-03-saveproject-run1.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-run1.txt` | `1222c0170d11cf654b64f22d8ceda3800681fed637f54f2a16c10855a7d08f45` |
| `lan-03-saveproject-run2.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-run2.txt` | `0e008f5f1d3eb1c9ac51a75b0a6d2cd19d112ea7267e6965732e62f5e5b32dab` |
| `lan-03-saveproject-run3.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-run3.txt` | `8a8f3cd834c1c4c7fb515782728b25278b947d22ee9f84f9b9a5cfbaeee7b046` |
| `lan-03-saveproject-run4.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-run4.txt` | `70ec8a6e044dd09a3552fedcfd64717cf93d7a31aaf38cbc3179ab03b6af92fe` |
| `lan-03-saveproject-run5.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-03-saveproject-run5.txt` | `d3919ad20178ffbb397270b8936a493a247fdbfcaeb0de4e03b2a1ac173eb053` |
| `lan-04-posix-arms.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/lan-04-posix-arms.txt` | `bb15bc86be46b06c54c0557dbf8057f59c4f69137cc6b29f3306bae4edac7ec5` |
| `mut-M1.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M1.txt` | `12e3b91fec7fc4908613400fafcd5b277485314903c3fcbb66a032c004e05783` |
| `mut-M10.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M10.txt` | `9e1174cab48e20b59aba30c70ac45be0d112ee5cffe3b2e25716cc5b1a987d20` |
| `mut-M11.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M11.txt` | `5294a6d629afee8956bc5e1bd877d5e8a3f33be258e244f3076aa512c4d958a9` |
| `mut-M2.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M2.txt` | `a41107ddc87382e2ddb05ea0b4d398958aaeddf441f0a067d13b912447d3e759` |
| `mut-M3.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M3.txt` | `95122790850392454b41da20a0887e4af32c37673a8b59eebeca3800b4cfc8fd` |
| `mut-M4.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M4.txt` | `89eee57fcd02d5465e879d432e9c774188cb46d259f63b2219c46eef1c0ecce8` |
| `mut-M5.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M5.txt` | `b81b02bcf14ab0684bbef5cfc48a4d2062cc14316de126785552938677e91a1f` |
| `mut-M6.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M6.txt` | `bdeaa83cbe74097982fc7edb0b20a826acddac5f863ead5dfb830484992f9ac4` |
| `mut-M7.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M7.txt` | `45f576fad15e12e1c50c261843faf0a7d1ec576169262d0e950689e50dd67669` |
| `mut-M8.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M8.txt` | `f364ef4ffdebdf29c8e5f0044f4b82d7b1f3e55e66c3ea9d306afe21b132ddaa` |
| `mut-M9.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/mut-M9.txt` | `e7ca9cd07b71b449583c3606d3cd504710f93af735798aa6a0e51f0794e43b17` |
| `painted-step-main-profile.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/painted-step-main-profile.txt` | `020ccea236338ba3c16c81040b22fda182aca8d4094cf365e3aa7c2b05b0fdde` |
| `painted-step-marks.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/painted-step-marks.txt` | `702d52a63de56140437e046cf45ad6261756f1fdc0e714945924073ea96a160d` |
| `red-01-tester-base.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/red-01-tester-base.txt` | `4e89d56670a910f13d3810836786df21768c8068745324db3a9712024ab75534` |
| `sync-end-lines-base.txt` | `.dev-flow/2026-11-01-batch-101/evidence/inc-3/sync-end-lines-base.txt` | `15edd98c5f050588c138b66bf123773e5f5df784e9a87a476dd9771fdefe5413` |

| Field | Value |
|---|---|
| **Evidence files** | 62 transcripts, each at `evidence/inc-3/` and cited with the digest of its stored bytes (the 6 scripts are listed in §2 only). `mut-M2.txt` carries its post-redaction digest. |

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim here rest on the tree holding NO instance of some case? | yes: the sync tests assert that no folder exists at the project path (`os.path.lexists` False) and that no `Added variant` or `now opens` line is painted |
| If the result is an ABSENCE, what made the search wide enough | each by-keys node first proves the sync was reached (the refusal line counted exactly once) and that the app is alive with no run left, so an attach stopped earlier cannot pass; the `[a2l]` arm asserts the same since the re-audit |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_r_proj_002_14_sync_into_a_deleted_project_folder_creates_no_folder` |
| Conjunctive criteria: one mutation per conjunct | M-3 (s19/hex/mac sync `mkdir`), M-4 (A2L sync `mkdir`), M-C3 (the load never posts the sync) |
| Synthetic instance of the absent case | the deleted-folder scenes themselves; the injected mid-attach delete (a wrapper on the worker thread) |
| **Positive control for every probe that returned an ABSENCE** | the `file-in-place` arms (folder present: the refusal line is painted and the file is placed) and the base run, where the folder is re-created (`red-01-tester-base.txt`: `True is False`) |

### Reverse census

| Field | Value |
|---|---|
| **Reverse census** | B1: `gather_project_artifacts` is imported by other test files (importers run: `int-04b` … `int-04d`, 328 + 315 + 125 passed); `_paint_clock_start` / `_summary_laid_out` are asserted only in `test_b100_project_check.py` · B2: no file moved · B3: no golden captures the changed sources (engine-frozen guards pass: `int-04a-guards.txt`, `e5c-law-guards-lan.txt`) · B4: the two sync functions are called only by the file-load worker (`call_from_thread`) and the A2L install; neither reads a return value (`E5-code-review.md`, check 2) · A3: no signature or text changed in `gather_project_artifacts`; the test census of `current_project = ` / `current_project_dir = ` found every data-file-loading site creating its folder first (F10) |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | 3 corrections enumerated before their first site was edited: the 6 arms moved to the product's stamps (`E1-slice.md` §3) · the 4 Result-cell rows of R-TST-111/1-3 and 112/1 reworded for the head-form runs (`grep "^| R-TST-11[12]/"` in `02-test-cases.md`) · the 30 case rows re-stated per platform at C-11 |

### Signed-balance test ledger

Not recomputed for this increment: no test was deleted; the case count went 26 → 30 and the tests only grew.

---

## 4b · Independent review — the lens the author cannot be

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES**, 0 BLOCKER / 0 MAJOR / 7 MINOR / 1 NIT — CR-1, CR-3, CR-4, CR-5, CR-6, CR-7 closed by the corrective pass, CR-2 and CR-8 to the backlog — `E5-code-review.md`. `security-reviewer` · **PASS-WITH-NOTES**, no HIGH or MEDIUM — E5S-1 … E5S-5 routed (S-3, S-5, E5S-2) or accepted (O-3) — `E5-security.md`; at E3 round 1 **FAIL** (`BLOCK-UNTIL: S-1`, the same defect as F1), closed in round 2 — `E3-security.md`, `E3-r2.md`. `qa-reviewer` · coverage audit re-audit 30/30 covered, 0 `gap`, 27 full, 3 partial; its five remaining rows applied at this close — `E5-coverage-audit.md`. E3 design review by the `architect` lens: round 1 FAIL (F1 HIGH, F2 MAJOR), round 2 **PASS-WITH-NOTES** — `E3-architect.md`, `E3-rulings.md`, `E3-r2.md` |

---

## 5 · Risks

- The Windows results of R-TST-111/112 and R-PROJ-002.14 come from head-form runs (before C-1 and C-3); the new by-keys nodes, the C-1 observer form and the A2L-sync assert have no Windows run (operator run rule). The Linux runs cover them.
- The `sec6_5 load`, `painted` and `appended` arms still sit near their 1 s bounds (1.001 s Windows, 1.0017 s on a loaded LAN host); the verifier's `[scene]` parameter inherits the `sec6_5 load` flake, so a red `[scene]` must be read for which assert stopped it. No bound was raised.
- The 1 ms stamp tolerance rests on 3 LAN runs and 6 Windows runs (gaps 3 to 52 microseconds); a GC pause or a GIL hand-off between a paired stamp could still exceed it.
- About 9 dwell-then-press arms of the `TC-B97-64` form stay in the parallel lane (CR-2); only the burst arm is hand-listed in `SAMPLED_TIMING_ARMS`.
- A folder deleted between `validate_project_files` and the write is still re-created by the placement (accepted residual O-3, inside the work area).
- `gather_project_artifacts` can still raise `OSError` on an over-long name component (S-3 / E5S-1, same on base) and `_schedule` does not catch `RuntimeError` (E5S-2).

---

## 6 · Pending items / spec deviations

- **R-TST-008 / 009** — Inc 2's two LAN gate runs; the painted-interval prerequisite is addressed here, the full-gate runs are not made.
- **Windows runs** of the by-keys nodes 002.12/7 and 002.13/3, the C-1 observer form, the C-3 asserts and the A2L-sync assert: not run by the operator's run rule.
- **The full suite** at the batch end, and the CI serial-lane confirmation of the verifier and of the `TC-B97-64` burst arm.
- Backlog rows in `.dev-flow/BACKLOG-CODE.md`: S-3 + E5S-1 (OS error at a composition name), S-4 (Save reads through a library link), S-5 (names reach the filesystem before a text check), E5S-2 (`_schedule` and `RuntimeError`), CR-8 (duplicated helper), OR-4 / D-4 (the `sec6_5` margins), and the CR-2 extension of the `TC-B97-64` burst row.
- The uncommitted records (this packet, `04-validation.md`, the E5 records, `02-test-cases.md`, `tests/test_b100_workers.py`, `BACKLOG-CODE.md`, `steps.log`, the `e5d-*` transcripts and the redacted `mut-M2.txt`) are to be committed by the orchestrator; nothing here is committed by this record.

---

## 7 · Suggested next task

Merge this branch after Inc 2; take Inc 4 (it edits `variant_execution_service.py`, whose writer link refusal R-PROJ-ROLLBACK.9/1 depends on, ruling A-4), and read the CI serial lane for the verifier and the `TC-B97-64` burst arm.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence (node id · command output · file:line) |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 2 / 4: `project_gather_service.py`, `app.py` (§2) |
| 2 | Tests written in this same increment | all | ✓ | 9 test files touched; the E4 nodes plus 4 cases added at E5 (`E4-tester-notes.md`, `E5-corrective-notes.md`) |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | `test_r_tst_110_…`, `test_r_tst_113_…` passed (§4) |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | §4: `red-01-tester-base.txt`, `e5d-a2l-sync-assert-lan.txt` |
| 5 | Reverse census declared | `core` · `full` | ✓ | §4 Reverse census |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | PASS-WITH-NOTES, 0 HIGH (§4b, `E5-code-review.md`) |
| 7 | No file from another lane touched | all | ✓ | no lane fork in this batch; the file set is §2 |
| 8 | Frozen interfaces untouched | all | ✓ | engine-frozen guards 196 passed (`e5c-law-guards-lan.txt`) |
| 9 | Coverage claims verified on disk | all | ✓ | 27 / 27 cited node ids collected (`E5-coverage-audit.md`, Node ids) |
| 10 | Load-bearing emptiness declared | all | ✓ | §4 Load-bearing emptiness |
| 11 | Mutation verdicts declared | all | ✓ | 14 / 14 killed (§4) |
| 12 | Instrument RED-proof declared | all | ✓ | 3 instruments (§4) |
| 13 | Correction population declared | all | ✓ | 3 corrections (§4) |
| 14 | Emitted-form assertion declared | all | ✓ | by-keys nodes assert painted lines (§4) |
| 15 | Independent review names somebody | all | ✓ | §4b leads with `code-reviewer`, `security-reviewer`, `qa-reviewer` |
| 16 | Evidence files declared | all | ✓ | 62 transcripts with SHA-256 (§4) |

## Close-out checks

- `trace_check.py --req inc-3/01-requirements.md --tests tests --base 9f9f6af --src s19_app` (the branch base): `trace_check: 3 US, 12 active requirements (0 withdrawn), 0 gap(s)`. A first run with `--base main` and `E1-slice.md` as a requirement file reported 7 gaps that are not this increment's: 6 SLICE for files Inc 7/8 brought to `main` after this branch's base, and 1 CASE for `R-TST-008`, which `E1-slice.md` only mentions as Inc 2's owed gate evidence.
- Flow validator: `devflow-validate.py --brief`: 4 BLOCK, all V20 (the derived atlas files, the orchestrator's); no BLOCK names an Inc 3 file; notices only for this packet (V9 wording, V56 failure-count note for the RED transcripts)
