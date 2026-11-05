# Increment 002 — Inc 2 · R-TST-001 … R-TST-091 · test hygiene: serial timing lane, margins, shared waits, CI xdist lanes, version-agnostic goldens, redaction gate

Flow: dev-flow-v3-beta (operator ruling 2026-11-01). Records live in `.dev-flow/2026-11-01-batch-101/inc-2/`: `01-requirements.md` (US-TST-1 … 5, R-TST-001 … 091), `02-test-cases.md` (82 cases), `E1-rulings.md`, `E1-slice.md`, `E3-rulings.md`, `E3-architect.md` + `E3-architect-r2.md`, `E3-security.md`, `E4-impl-notes.md`, `E4-tester-notes.md`, `E4-integration-notes.md`, `E5-mutants.md`, `E5-code-review.md`, `E5-security.md`, `E5-coverage-audit.md`, `E5-corrective-notes.md`, `04-validation.md`, `steps.log`, `codewire/graph-inc2.md`, `evidence/`. Branch `b101-inc2` from `main` (`e266395`), head `57d19f4` plus the uncommitted E5 records.

Models per stage (from `steps.log` and the orchestrator's assignment): Opus — E1–E3 (requirements, rulings, both design reviews, the E3 corrective), the E4 integration step, the E5 code and security reviews, the coverage audit and the E5 corrective pass; Kimi K2.8 — the E4 implementers (swarm A/B) and the independent tester, the E5 mutant battery, and this record.

## 1. What changed

The test suite gains a timing-arm discipline. A new `serial_timing` marker (`pyproject.toml`) marks every wall-clock arm; CI and the release gate run the suite in two lanes — `pytest -n auto -m "not serial_timing"` (parallel) then `pytest -m serial_timing` (serial) — with `pytest-xdist==3.8.0` pinned, per-step and job `timeout-minutes`, `fetch-depth: 0` on the `tui-ci` checkout and `persist-credentials: false` on both. The seven shared wait helpers are re-pinned to one wall-clock-bounded, yielding `wait_until` (W1–W9 texts unchanged), and `load_project` stops its clock at the install callback. Every raw upper timing bound is wrapped in `report_margin`, which reports each bound's margin to a QC-TM terminal section (ascending rows, `LOW` prefix under 20 %, a gate finding in the serial lane). A pure-AST census (`tests/support/suite_census.py`) detects timing arms, unreported bounds and newest-line waits, and `tests/test_suite_hygiene.py` (65 nodes) guards every rule. The 7 report goldens become version-agnostic through a `<TOOL-VERSION>` token canonicalized to the package's version at comparison time. A redaction gate scans every text file under the batch folder for home paths, account names, host names and LAN addresses. No product file under `s19_app/` is touched.

## 2. Files modified

Committed: `git diff --stat main...HEAD` (88 files, +18 466 / −127). Uncommitted: the E5 records listed at the end. SOURCE files: **0 / 4**.

| File | Kind | Traces to | Change |
|---|---|---|---|
| `.dev-flow/2026-11-01-batch-101/inc-2/01-requirements.md` | doc |  | EARS requirements: 49 R-TST rows + Definitions (timing arm, upper bound, newest-line wait, clock set) |
| `.dev-flow/2026-11-01-batch-101/inc-2/02-test-cases.md` | doc |  | 82 ISO 29119-3 cases over 49 requirements; audited at E5 (marks, coverage, results) |
| `.dev-flow/2026-11-01-batch-101/inc-2/E1-rulings.md` | doc |  | E1 rulings O-1 … O-3, F-1, F-2; orchestrator rulings |
| `.dev-flow/2026-11-01-batch-101/inc-2/E1-slice.md` | doc |  | E1 implementation slice: 31 static arms, 37 upper bounds, the census contract |
| `.dev-flow/2026-11-01-batch-101/inc-2/E3-rulings.md` | doc |  | E3 round-1/2 rulings + E4 addenda + seam rulings (S-1, G-1) |
| `.dev-flow/2026-11-01-batch-101/inc-2/E3-architect.md` | doc |  | E3 design review round 1: FAIL, 3 HIGH + 4 MAJOR |
| `.dev-flow/2026-11-01-batch-101/inc-2/E3-architect-r2.md` | doc |  | E3 round 2: PASS-WITH-NOTES, 7/7 closed, notes N-1 … N-4 |
| `.dev-flow/2026-11-01-batch-101/inc-2/E3-security.md` | doc |  | E3 design security review: PASS-WITH-NOTES, 2 MEDIUM + 5 LOW for E4/E5 |
| `.dev-flow/2026-11-01-batch-101/inc-2/E4-impl-notes.md` | doc |  | E4 implementer swarm notes (swarm cap cut their own verification runs) |
| `.dev-flow/2026-11-01-batch-101/inc-2/E4-tester-notes.md` | doc |  | Independent tester notes: 54 nodes over the 81 cases, full/partial rule |
| `.dev-flow/2026-11-01-batch-101/inc-2/E4-integration-notes.md` | doc |  | E4 integration: the runs, the timing distribution, the owed list |
| `.dev-flow/2026-11-01-batch-101/inc-2/E5-mutants.md` | doc |  | E5 mutant table: 53 mutants, score 45/46, survivor analysis (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-2/E5-code-review.md` | doc |  | E5 independent code review: FAIL (BLOCK-UNTIL F1) → re-review PASS-WITH-NOTES at 57d19f4 (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-2/E5-security.md` | doc |  | E5 security review: PASS-WITH-NOTES, E5S-1 … E5S-7 (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-2/E5-coverage-audit.md` | doc |  | Independent coverage audit of the case records + re-audit at 57d19f4 (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-2/E5-corrective-notes.md` | doc |  | E5 corrective pass: F1–F11, E5S-1/2/3, F-1 … F-5, M-040/4 and M-017 closed |
| `.dev-flow/2026-11-01-batch-101/inc-2/04-validation.md` | doc |  | This increment's validation record (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/inc-2/steps.log` | doc |  | Stage log, models and UTC stamps (appended at close) |
| `.dev-flow/2026-11-01-batch-101/inc-2/codewire/graph-inc2.md` | doc |  | Code-wire graph I-1 … I-9, G1, per-node contracts |
| `.dev-flow/2026-11-01-batch-101/evidence/ci/41372953464.txt` | generated | US-TST-4 | Batch CI record: 5 FAILED lines = the 5 known failures, 0 new; snapshot success, 29/29 cells |
| `.dev-flow/2026-11-01-batch-101/evidence/ci/42037470050.txt` | generated | US-TST-2 | Inc 2's own PR CI run (head 379cd20): 6/6 history arms PASSED, 4/4 xdist workers, lane 1 116 min 29 s, lane 2 5 min 48 s; 7 FAILED = 5 known + 1 known-on-main + 1 load flake (tc_b97_64 burst, backlog) |
| `.dev-flow/2026-11-01-batch-101/evidence/ci/42059144223.txt` | generated | US-TST-2 | First push CI run after the merge (main 9f9f6af): lanes 114 min 31 s + 5 min 20 s = 119 min 51 s ≤ 150 (R-TST-091); 5 FAILED = the 5 known |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/impl-1-full.txt` | generated | US-TST-1 | E4 implementer run: full suite slice (cut by the swarm cap; superseded by integration) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/impl-2-serial-timing.txt` | generated | US-TST-1 | E4 implementer run: serial-timing slice, 6 failed, 53 passed, 995 deselected |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/impl-3-not-serial-collect.txt` | generated | US-TST-1 | E4 implementer collection check: arms not in the parallel lane |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-lane1.txt` | generated | US-TST-1 | E4 LAN lane-1 run on the branch working tree (EXIT=1, the 5 known + context) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-lane2.txt` | generated | US-TST-1 | E4 LAN lane-2 serial run on the working tree (EXIT=0) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-plain-lane1.txt` | generated | US-TST-1 | E4 LAN lane-1 at 86c8aa6: 6 failed, 5055 passed, 205 skipped, 4 xfailed in 4014.94 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-plain-lane2.txt` | generated | US-TST-1 | E4 LAN lane-2 at 86c8aa6: 1 failed, 57 passed, 2 skipped (the R-3 arm) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-plain-recheck.txt` | generated | US-TST-1 | Recheck of the lane-1 flakes: file alone passes, 3/3 serial |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-confirm.txt` | generated | US-TST-2 | Speed confirmation: loadfile 8:51 vs plain -n 8 2:02 on one module |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-timing-base1.txt` | generated | US-TST-1 | E4 serial-timing distribution study, base tree, round 1 (EXIT=1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-timing-base2.txt` | generated | US-TST-1 | E4 serial-timing distribution study, base tree, round 2 (EXIT=0) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-timing-basewaits1.txt` | generated | US-TST-1 | E4 basewaits study round 1 (EXIT=1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-timing-basewaits2.txt` | generated | US-TST-1 | E4 basewaits study round 2 (EXIT=1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-timing-head1.txt` | generated | US-TST-1 | E4 serial-timing distribution study, head tree, round 1 (EXIT=0) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-linux-timing-head2.txt` | generated | US-TST-1 | E4 serial-timing distribution study, head tree, round 2 (EXIT=1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-arms-a.txt` | generated | US-TST-1 | E4 Windows arm-wrap verification, round A (EXIT=1 pre-fix) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-arms-b.txt` | generated | US-TST-1 | E4 Windows arm-wrap verification, round B (EXIT=0) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-arms-timeout.txt` | generated | US-TST-1 | E4 arms run cut at the 900 s budget (EXIT=124) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-collect-split.txt` | generated | US-TST-1 | Windows collection check of the lane split |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-e5c.txt` | generated | US-TST-1 | E5 final Windows run: 3 failed, 183 passed in 365.23 s (the 3 = the R-3 step) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-final.txt` | generated | US-TST-1 | E4 final Windows integration run (EXIT=0) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-final2.txt` | generated | US-TST-1 | E4 final Windows run at ab879c8: 54/54 hygiene nodes (79 with Inc 1 guards) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-goldens.txt` | generated | US-TST-5 | E4 golden run: 204 passed, 1 failed (the known at056e_a2b) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-hygiene-pre-fix-1.txt` | generated | US-TST-1 | Hygiene suite run before the E4 fix, round 1 (EXIT=1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-hygiene-pre-fix-2.txt` | generated | US-TST-1 | Hygiene suite run before the E4 fix, round 2 (EXIT=1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-hygiene.txt` | generated | US-TST-1 | Hygiene suite run after the E4 fix (EXIT=0) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-registry.txt` | generated | US-TST-1 | Inc 1 registry guards on top of Inc 2 (EXIT=0) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-serial-timing-base.txt` | generated | US-TST-1 | E4 Windows serial-timing study, base (EXIT=1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-serial-timing.txt` | generated | US-TST-1 | E4 Windows serial-timing study, head (EXIT=1) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-tc607-measure.txt` | generated | US-TST-1 | TC-607 measured count at the Inc 2 tree (241) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-waitcallers.txt` | generated | US-TST-3 | Shared-wait callers census run (EXIT=0) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-waitcallers-timeout.txt` | generated | US-TST-3 | Wait-callers run cut at the budget (EXIT=124) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/int-win-workers.txt` | generated | US-TST-2 | Windows xdist worker-header check (EXIT=0) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/red-01-tester-base.txt` | generated | US-TST-1 | Tester RED-proof: the hygiene suite on base 84d4507, 48 failed + 6 errors (54/54 RED) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5c-red-before.txt` | generated | US-TST-3 | E5 RED-before on ab879c8: 3 failed, 12 passed, 50 deselected |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5c-arm-file-check.txt` | generated | US-TST-3 | F1 whole-file AST check: 12 arm files equal main after normalisation; ab879c8 is not |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5c-mutation-checks.txt` | generated | US-TST-1 | 032/1 and E5S-3 mutants; the old gates on the planted inputs |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5c-f11-capture.txt` | generated | US-TST-5 | F11 capture harness: 1 passed in 101.35 s |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5c-painted-base-vs-head.txt` | generated | US-TST-1 | The R-3 timing note's base-vs-head runs: same distribution on both trees |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5c-redaction-final.txt` | generated | US-TST-4 | The widened redaction gate over the final batch folder: 2 passed |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5-golden-rerun.txt` | generated | US-TST-5 | E5 golden re-run at 57d19f4: 1 failed, 133 passed (the known at056e_a2b) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5-linux-57d19f4.txt` | generated | US-TST-1 | E5 Linux hygiene+guards at 57d19f4: 90 passed; the earlier run 3 failed, 55 passed, 2 skipped (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/e5-linux-timing-57d19f4.txt` | generated | US-TST-1 | E5 Linux timing lane at 57d19f4: 58 passed, 2 skipped (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-001.txt` | generated | US-TST-1 | M-001 transcript: marker entry removed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-S1.txt` | generated | US-TST-1 | M-S1 transcript: doubled marker description — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-002.txt` | generated | US-TST-1 | M-002 transcript: arm mark removed — KILLED, the guard names it (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-003.txt` | generated | US-TST-1 | M-003 transcript: unmarked-arm check removed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-004.txt` | generated | US-TST-1 | M-004 transcript: reverse check deleted — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-005.txt` | generated | US-TST-3 | M-005 transcript: stamp/form-(d) census removed — KILLED ("census lost base timing arms") (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-005-6.txt` | generated | US-TST-3 | M-005/6 transcript: stamp form removed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-005-7.txt` | generated | US-TST-3 | M-005/7 transcript: form (d) dropped — KILLED by 040_041 (the named [form6] passes; analysis) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-006.txt` | generated | US-TST-3 | M-006 transcript: any-clock detector — KILLED (≥18 false arms) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-007.txt` | generated | US-TST-1 | M-007 transcript: release-gate sentence deleted — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-010.txt` | generated | US-TST-2 | M-010 transcript: PR lanes collapsed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-011.txt` | generated | US-TST-2 | M-011 transcript: push lanes collapsed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-012.txt` | generated | US-TST-2 | M-012 transcript: `!cancelled()` removed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-013-014.txt` | generated | US-TST-2 | M-013 + M-014 transcripts: `fetch-depth: 0` removed — KILLED (014's dynamic half CI-owed) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-015.txt` | generated | US-TST-2 | M-015 transcript: lane-1 timeout removed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-016.txt` | generated | US-TST-2 | M-016 transcript: job timeout removed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-017.txt` | generated | US-TST-2 | M-017 transcript: `success()` lane-2 conditions — KILLED by 012, not the row's own node (closed at E5, mut-r2-017) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-018.txt` | generated | US-TST-2 | M-018 transcript: xdist pin removed — KILLED statically (018/2 owed to the PR run) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-G1.txt` | generated | US-TST-2 | M-G1 transcript: `--dist loadfile` restored — KILLED by both lane guards (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-020.txt` | generated | US-TST-3 | M-020 transcript: count-bounded loop restored — KILLED by 020_021 (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-021.txt` | generated | US-TST-3 | M-021 transcript: the 0.05 s yield removed — KILLED (>21 checks) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-022.txt` | generated | US-TST-3 | M-022 transcript: pause-first removed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-023.txt` | generated | US-TST-3 | M-023 transcript: `attempts` removed from the signature — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-024.txt` | generated | US-TST-3 | M-024 transcript: W1 text changed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-025.txt` | generated | US-TST-3 | M-025 transcript: install-return stamp moved — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-030.txt` | generated | US-TST-3 | M-030 transcript: post-press sentence deleted — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-031.txt` | generated | US-TST-3 | M-031 transcript: the Hold install removed — KILLED statically (3-of-3 owed to the gate) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-032.txt` | generated | US-TST-1 | M-032 transcript: dwell restart removed — KILLED by the runtime arm (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-040.txt` | generated | US-TST-3 | M-040 transcript: one real bound reverted to its literal — KILLED (site reported raw) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-040-4.txt` | generated | US-TST-3 | M-040/4 transcript: the IfExp taint removed — SURVIVED (real gap; closed at E5, mut-r2-040_4) (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-041.txt` | generated | US-TST-3 | M-041 transcript: margin guard skipped — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-042.txt` | generated | US-TST-3 | M-042 transcript: hook drain removed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-043.txt` | generated | US-TST-3 | M-043 transcript: sort removed — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-044.txt` | generated | US-TST-3 | M-044 transcript: threshold set to 10.0 — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-045.txt` | generated | US-TST-3 | M-045 transcript: count line wrong — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-046.txt` | generated | US-TST-3 | M-046 transcript: drain only on pass — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-047.txt` | generated | US-TST-3 | M-047 transcript: clock-rule sentence deleted — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-048.txt` | generated | US-TST-3 | M-048 transcript: margin-rule sentence deleted — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-050.txt` | generated | US-TST-3 | M-050 transcript: `since` capped to 4 lines — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-051.txt` | generated | US-TST-3 | M-051 transcript: ratchet `>=` — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-052.txt` | generated | US-TST-3 | M-052 transcript: oracle-rule sentence deleted — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-060.txt` | generated | US-TST-3 | M-060 transcript: census-rule sentence deleted — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-080.txt` | generated | US-TST-5 | M-080 transcript: a golden re-pinned to a literal version — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-081.txt` | generated | US-TST-5 | M-081 transcript: version substitution removed — KILLED 7/7 (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-082.txt` | generated | US-TST-5 | M-082 transcript: canonicalizer masks any value — KILLED (uncommitted) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-r2-017.txt` | generated | US-TST-2 | E5 re-run: M-017 killed by the row's own node (1 failed, 64 deselected) |
| `.dev-flow/2026-11-01-batch-101/evidence/inc-2/mut-r2-040_4.txt` | generated | US-TST-3 | E5 re-run: M-040/4 killed by 040_4 and 040_1 (2 failed, 2 passed, 61 deselected) |
| `.dev-flow/BACKLOG-CODE.md` | doc |  | Eight batch-101 Inc 2 rows appended at the KF-101 block (E5S-4, E5S-7, tc016b/tc016s, pause-count waits, census N-1, R-1, R-2, the painted-interval step) |
| `.dev-flow/2026-11-01-batch-101/03-increments/increment-002.md` | doc |  | This packet (uncommitted) |
| `.github/workflows/tui-ci.yml` | config | US-TST-2 | Two-lane split (PR and push), xdist 3.8.0 pinned, `fetch-depth: 0` on `tui-ci`, `persist-credentials: false` on both checkouts, step/job `timeout-minutes`, two-lane header |
| `docs/engineering-rules.md` | doc |  | New "Test timing, waits and oracles" section: the six batch-101 Inc 2 rules (R-TST-007, 030, 047, 048, 052, 060) |
| `pyproject.toml` | config | US-TST-1 | The `serial_timing` marker registered |
| `tests/b97_probes.py` | test | US-TST-3 | `settled` delegates to `wait_until` (wall-clock bound, pause-first); `last_status` pinned as a newest-line reader |
| `tests/conftest.py` | test | US-TST-5 | QC-TM hooks imported; `pytester` enabled; `TOOL_VERSION_TOKEN` and the version-token canonicalization, docstring corrected (F8) |
| `tests/goldens/batch35/at054b-before-after-report.html` | fixture | US-TST-5 | Golden version line becomes `<TOOL-VERSION>` |
| `tests/goldens/batch35/at054b-before-after-report.md` | fixture | US-TST-5 | Golden version line becomes `<TOOL-VERSION>` |
| `tests/goldens/batch35/at055b-project-report.md` | fixture | US-TST-5 | Golden version line becomes `<TOOL-VERSION>` |
| `tests/goldens/batch64/addendum-below-bound.md` | fixture | US-TST-5 | Golden version line becomes `<TOOL-VERSION>` (12 lines) |
| `tests/goldens/batch74/producer-bound-positive-control.md` | fixture | US-TST-5 | Golden version line becomes `<TOOL-VERSION>` |
| `tests/goldens/batch76/document-bound-preflight.md` | fixture | US-TST-5 | Golden version line becomes `<TOOL-VERSION>` |
| `tests/goldens/batch99/at288-pre-move-report.bin` | fixture | US-TST-5 | Golden version line becomes `<TOOL-VERSION>` |
| `tests/support/b100_load_dialog.py` | test | US-TST-3 | The dialog `wait_for` delegates to `wait_until`; failure texts as callables; `attempts` accepted and ignored |
| `tests/support/b100_projects.py` | test | US-TST-3 | `wait_for` delegates to `wait_until`; W1/W9 texts kept; `load_project` stamps the clock at the install callback and restores the attribute in `finally` |
| `tests/support/suite_census.py` | test | US-TST-1 | New pure-AST census: timing arms, unreported upper bounds, newest-line waits, shared-wait bodies; F2's spec-exact all-line rule |
| `tests/support/timing.py` | test | US-TST-3 | New: `wait_until`, `report_margin` (label validation, E3S-7), QC-TM pending/drain/summary machinery |
| `tests/test_a2l_alignment_sizing.py` | test | US-TST-1 | Timing arms marked `serial_timing`, bounds wrapped in `report_margin` |
| `tests/test_a2l_inline_axis_length.py` | test | US-TST-1 | Timing arms marked `serial_timing`, bounds wrapped in `report_margin` |
| `tests/test_a2l_multiline_headers.py` | test | US-TST-1 | Timing arms marked `serial_timing`, bounds wrapped in `report_margin` |
| `tests/test_b100_active_variant.py` | test | US-TST-1 | TC-B100-20 arm wrapped (`report_margin`); operator/CI scaling unchanged |
| `tests/test_b100_busy.py` | test | US-TST-1 | One timing arm marked `serial_timing` |
| `tests/test_b100_document.py` | test | US-TST-1 | TC-B100-30 hostile arms wrapped (`report_margin`) |
| `tests/test_b100_project_check.py` | test | US-TST-1 | The 37 wraps; F1's two oracle assertions restored at 1211-1212 |
| `tests/test_b100_project_homes.py` | test | US-TST-1 | Ceiling arms marked `serial_timing`, bounds wrapped |
| `tests/test_b100_save_dialog.py` | test | US-TST-1 | Save arms wrapped; bounds through `report_margin` |
| `tests/test_b100_save_guards.py` | test | US-TST-1 | The merge arm wrapped (`report_margin`) |
| `tests/test_compare_engine.py` | test | US-TST-1 | Large-image arm marked and wrapped |
| `tests/test_id_registry.py` | test | US-TST-1 | `EXPECTED_SCANNED_TEST_FILES` 239 → 241 (measured) |
| `tests/test_report_addendum_bound.py` | test | US-TST-5 | Golden read through `canonical_report_bytes` |
| `tests/test_report_service.py` | test | US-TST-5 | Golden comparisons canonicalized; the at288 capture tokenizes only `Tool version: ` + version (F11) |
| `tests/test_suite_hygiene.py` | test | US-TST-1 | New guard host: 65 nodes over R-TST-001 … 082 + E5 additions (049 guard, widened redaction gate, injection ratchet) |
| `tests/test_tui_app.py` | test | US-TST-1 | Timing arms marked `serial_timing`, bounds wrapped |

| Count | Value |
|---|---|
| **SOURCE files** | **0 / 4** |
| Test files | 30 committed (2 support modules new, 16 test files changed, 7 goldens, conftest, b97_probes) |
| Doc files | 2 (`docs/engineering-rules.md`, `.dev-flow` records) |
| Config files | 2 (`pyproject.toml`, `.github/workflows/tui-ci.yml`) |

No product file under `s19_app/` — the increment is suite machinery, workflow and records only.

## 3. How to test

```bash
# the hygiene suite + Inc 1 guards (Windows or Linux)
env PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=. \
  python -m pytest -q tests/test_suite_hygiene.py tests/test_id_registry.py \
  tests/test_batch91_registry_hygiene.py tests/test_report_addendum_bound.py \
  tests/test_tui_patch_json.py tests/test_engine_unchanged.py
# the serial lane
python -m pytest -q -m serial_timing
# the full gate (LAN Linux host): lane 1 then lane 2, twice
python -m pytest -v -rs -n 8 -m "not serial_timing"
python -m pytest -q -rs -m serial_timing
```

## 4. Test results

Layer 0 / white-box: hygiene suite 65/65 (`int-win-e5c.txt`); Linux 90 passed (`e5-linux-57d19f4.txt`); RED 54/54 on base (`red-01-tester-base.txt`); RED-before 3 failed on `ab879c8` (`e5c-red-before.txt`). Black-box: the two CI lanes' static guards pass; the gate lanes ran at `86c8aa6` (`int-linux-plain-lane1/2.txt`) with the R-3 step the only timing failure. Goldens 133 passed, 1 known failure (`e5-golden-rerun.txt`). Mutants 45/46, survivor closed at E5 (`mut-r2-040_4.txt`, `mut-r2-017.txt`). Case totals after the coverage re-audit: 82 cases, 62 verified / 20 not_run / 0 failed. Details: `inc-2/04-validation.md`.

### RED counterfactual

| Field | Value |
|---|---|
| **RED counterfactual** | The guard host's own RED run on base `84d4507`: 54/54 nodes RED (48 failed + 6 errors in 24.40 s) — `evidence/inc-2/red-01-tester-base.txt`; plus the E5 RED-before on `ab879c8` (3 failed, each for the defect its fix targets) — `evidence/inc-2/e5c-red-before.txt`; the F10 guard names the dropped-oracle wrap on `ab879c8` and nothing on `57d19f4` — `evidence/inc-2/e5c-arm-file-check.txt` |

| Field | Value |
|---|---|
| **Mutation verdicts** | 53 mutants, per-node verdicts in `E5-mutants.md` and `evidence/inc-2/mut-*.txt`: 45 KILLED, 1 SURVIVED (M-040/4, a real gap), 7 N/A owed to the gate/CI; each applied to a detached copy of `ab879c8` and restored byte-exact (`git diff --quiet` clean after every mutant); the survivor re-run: KILLED by `040_4` and `040_1` (`mut-r2-040_4.txt`); M-017 re-run: KILLED by the row's own node (`mut-r2-017.txt`) |

### Instrument RED-proof

| Field | Value |
|---|---|
| **Instrument RED-proof** | 4 instruments shown RED before their PASS was believed: the hygiene suite on base (`red-01-tester-base.txt`); the E5 guard file on `ab879c8` (`e5c-red-before.txt`); the pre-E5 redaction gate on the planted lines (3 of 9 caught, `.xml` unscanned — `e5c-mutation-checks.txt`); the pre-E5 injection check (misses the unspaced form, one job only — `e5c-mutation-checks.txt`) |

### Emitted-form assertion

| Field | Value |
|---|---|
| **Emitted-form assertion** | The F11 capture harness runs the at288 capture branch against a temp path and asserts the emitted bytes: exactly one `<TOOL-VERSION>` on the `Tool version:` line, canonically equal to the committed golden, nothing written under `tests/goldens` — `evidence/inc-2/e5c-f11-capture.txt` (1 passed in 101.35 s) |

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59)

Digests: SHA-256 of the bytes at the cited path, taken 2026-11-02. The transcripts live in `.dev-flow/2026-11-01-batch-101/evidence/` — the home `artifact_homes.evidence` declares.

| Evidence artifact | Path — under `.dev-flow/2026-11-01-batch-101/` | SHA-256 |
|---|---|---|
| int-win-e5c.txt | evidence/inc-2/int-win-e5c.txt | 07d3f6bababc9b2f4140500c40f6916db49be4b77518705031f0050d65812ae3 |
| e5c-red-before.txt | evidence/inc-2/e5c-red-before.txt | c7245bc708ce11a05b942b90d79f2d8a26251c39e887c60542cb8a9afa0e74eb |
| e5-golden-rerun.txt | evidence/inc-2/e5-golden-rerun.txt | d425c38192e081db0aeed1decf38a5609ad69d0ab820c66151312ce8a2a23687 |
| e5-linux-57d19f4.txt | evidence/inc-2/e5-linux-57d19f4.txt | 324b579a34c7c38950fe7e6def2e34a375683d749b246db924c3631dc1e97d16 |
| e5-linux-timing-57d19f4.txt | evidence/inc-2/e5-linux-timing-57d19f4.txt | 9d63045e9b1176e9f3866ac19fb3bcb34de1a256fc72e8daef97afa08d4c4408 |
| int-linux-plain-lane1.txt | evidence/inc-2/int-linux-plain-lane1.txt | 95279bb0cb7f1a9f9a2baf623eb823e61679751ac50bfdc455e5f65379a71b9b |
| int-linux-plain-lane2.txt | evidence/inc-2/int-linux-plain-lane2.txt | 30428ba07d68d3154350a07558a044541c9d0e522d26a1133ade92d267a24a79 |
| red-01-tester-base.txt | evidence/inc-2/red-01-tester-base.txt | ec5839ed362d975cb6dc54061dfa2928af47bec225f413455f87acc75a8f0284 |
| mut-040-4.txt | evidence/inc-2/mut-040-4.txt | aba16f92e7c5d56db2bbb3e214f8a26b2fe922917df21bf4946a5cbbb8e39b68 |
| mut-r2-040_4.txt | evidence/inc-2/mut-r2-040_4.txt | 3afd1dc01389e4364c69cda971dddd2ea3c3e36862a6dba541ab331c7d980377 |
| mut-r2-017.txt | evidence/inc-2/mut-r2-017.txt | 728adfbb64a34fd6a06bebc7f978ca0fcdf5851eb879fc977099885ca486e51f |
| e5c-arm-file-check.txt | evidence/inc-2/e5c-arm-file-check.txt | b1d31860f0c3f3afdcfa9c505d6b7f024669bde35145f8e52349831d4815c57f |
| e5c-mutation-checks.txt | evidence/inc-2/e5c-mutation-checks.txt | 6222c2850eac1da2396211faf29bf829cfde28c5724f02c1e69d0a7cf5ac22a0 |
| e5c-f11-capture.txt | evidence/inc-2/e5c-f11-capture.txt | f7dc572f3f85f0fca22ad8be5b8c21e36dc8de454311561c4b6a8ef51306cee1 |
| e5c-painted-base-vs-head.txt | evidence/inc-2/e5c-painted-base-vs-head.txt | a649a13f369dffd458765fb12613f24ef9bec45ed24eef4e326ae1d3fa429b35 |
| e5c-redaction-final.txt | evidence/inc-2/e5c-redaction-final.txt | 2ad94aa89344ed18f600c1803e74f273a888afc2ae48ae86ebe0c70603ce9488 |
| 41372953464.txt | evidence/ci/41372953464.txt | 3a5e1382094c1171ef2d05f72978b019177326579bb256bab9e53b2570a280cb |
| 42037470050.txt | evidence/ci/42037470050.txt | e656090512599e98def1f8313ed4cdf83043fe9dbc0169fbd96c4395c6db7697 |
| 42059144223.txt | evidence/ci/42059144223.txt | ab7b40b51c1d2db3d3f55bda91e37588a9afe2d4339c4d0778b6d33daeee836e |

| Field | Value |
|---|---|
| **Evidence files** | 19 transcripts, each cited with the digest of its stored bytes, all under the home `artifact_homes.evidence` names (`repo:.dev-flow/2026-11-01-batch-101/evidence/`) |

### Load-bearing emptiness (C-55)

| Field | Value |
|---|---|
| Does any claim rest on the tree holding NO instance of some case? | yes: the real-tree guards assert 0 unreported bounds, 0 unmarked arms, 0 newest-line-wait growth on the head tree |
| If the result is an ABSENCE, what made the search wide enough | the census parses every `tests/**/*.py` module (AST only, nothing imported); the guards re-run over the whole tree on every suite run |
| Guard labelled as protecting a CONCLUSION, not a behaviour | `test_r_tst_040_041_every_upper_timing_bound_is_reported` (0 lines on head); `test_r_tst_002_every_timing_arm_carries_serial_timing`; `test_r_tst_051_newest_line_waits_do_not_grow` |
| Conjunctive criteria: one mutation per conjunct | M-040/4 (the lost-taint conjunct) survived the head-tree half and was caught by the planted + base-tree halves — one mutation per conjunct, closed at E5 |
| Synthetic instance of the absent case | the planted modules under `tmp_path`: raw bounds (041), a dropped oracle (049), all-line and `[-1]` waits (051), the N-1 appended/conditional arm (040/4) |
| **Positive control for every probe that returned an ABSENCE** | each guard's planted twin returns the named finding (transcripts `mut-*.txt`, `e5c-red-before.txt`); the base tree reports its 37 bounds (`test_r_tst_040_1_base_tree_reports_its_37_bounds`) |

### Reverse census

| Field | Value |
|---|---|
| **Reverse census** | B1: `report_margin` / `wait_until` / `suite_census` symbols are asserted only by `tests/test_suite_hygiene.py` and read by the wrapped arm files (grep `tests/`) · B2: no file moved; both new modules are new paths · B3: `canonical_report_bytes` sources the 7 goldens, each now carrying `<TOOL-VERSION>`; its consumers are the 7 golden tests + `test_report_addendum_bound` (grep `tests/goldens/**`) · B4: the QC-TM section is consumed by the gate reader (lane-2 transcripts hold the section; lane 1 holds none — E5S-6) · A3: no `s19_app/` interface changed (0 source files) |

### Correction population

| Field | Value |
|---|---|
| **Correction population** | 3 corrections, each enumerated before its first site was edited: the 37 raw upper bounds (`E1-slice.md` §3 census, 5+1+3+16+2+5+1+1+3) · the 12 wrapped arm files ("marker plus `report_margin` wrap, nothing else", the F1 census over the whole diff) · the 86 newest-line waits in the F2 baseline (regenerated on the base tree: 80 waits in 14 files by the spec-exact rule) |

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` · **PASS-WITH-NOTES** (after re-review at `57d19f4`) — round 1 FAIL, BLOCK-UNTIL F1 (HIGH: the wrap deleted two oracle assertions); re-review: F1 closed on the diff (2 asserts restored, the whole-file AST check and the R-TST-049 guard re-run by the reviewer, RED on `ab879c8`, GREEN on `57d19f4`), F2 closed (spec-exact all-line rule; baseline 80/14 regenerated on `e266395` and matching), F10 closed; F3–F9, F11 MINOR recorded as closed by the corrective pass, not re-read — `inc-2/E5-code-review.md` §Re-review. `security-reviewer` · **PASS-WITH-NOTES** — 0 HIGH; E5S-1 MEDIUM (redaction gate widened, now scans the whole batch folder), E5S-2/3 LOW fixed; E5S-4, E5S-7 routed to the backlog; the whole diff holds no personal name, account name, host name or LAN address — `inc-2/E5-security.md`. **Design reviews (E3, code-free):** `architect` round 1 **FAIL** (3 HIGH + 4 MAJOR) → round 2 **PASS-WITH-NOTES** (7/7 closed; N-1 … N-4) · `security-reviewer` **PASS-WITH-NOTES** — `E3-architect.md`, `E3-architect-r2.md`, `E3-security.md`. **Independent tester (E4):** the 54-node guard host written from the design records only; its RED run on base is `red-01-tester-base.txt` — `E4-tester-notes.md`. **Coverage audit by `qa-reviewer` (E5):** first audit 17.3 % of 81 cases changed by judgment; re-audit at `57d19f4` 13.6 % (10 resolved, 005/7 newly lost → R-1) + the new case 049/1; final totals 62 verified / 20 not_run / 0 failed over 82 cases — `E5-coverage-audit.md`. **There WAS a re-review (E3 round 2 and the E5 code re-review), because each round 1 blocked.** |

## 5. Risks

- The pre-existing `painted`/`appended` ~1 s step (two `sec6_5 painted` arms at 2.49 s, one `appended` at 1.017 s in the final run) sits at its 1.0 s bound on both trees; it is ruled to Inc 3 (R-3, profile first) and can fail any serial-lane run until then.
- The gate distribution does not yet guarantee 0 failed timing arms in two consecutive runs (2 of 4 E4 Linux serial runs had one arm over bound); R-TST-008/009 stay not_run until Inc 3.
- CI rows (R-TST-012, 014, 017, 018/2, 090, 091) rest on Inc 2's own PR/push runs; the job limit (240 min) vs the measured 4 h 53 min push run leaves the N-3 budget arithmetic tight.
- The 7 N/A mutants are owed to evidence no local run can produce (the LAN gate, CI, a condition that never occurred).
- Windows-only coverage for the E5-changed nodes (the 86c8aa6 Linux runs no longer count for them, per the re-audit); the Linux runs at `57d19f4` re-cover the suite.

## 6. Pending

- **R-TST-008/009** — the two LAN gate runs; owed until Inc 3 settles the painted-interval step (ruling R-3). Backlog: the painted-interval ~1 s step (R1-P1, profile first).
- **R-TST-031/032** — 1 of 3 parallel-lane runs on record; 3/3 owed to the gate.
- **R-TST-014/018-2/090** — verified on PR run 42037470050 (`evidence/ci/42037470050.txt`); **R-TST-012/017** owe a real red/stop CI run; **R-TST-091** verified on push run 42059144223 (119 min 51 s ≤ 150).
- **R-TST-005/7** (ruling R-1: the case input no longer matches the F7 form 6) and **R-TST-049/1** (ruling R-2: the planted test compares function names, not the guard text) — backlog rows.
- Backlog rows appended to `.dev-flow/BACKLOG-CODE.md`: E5S-4 (CI supply-chain hashing), E5S-7 (at288 self-capture), the tc016b/tc016s environment fragility, the file-local pause-count waits (`tc_b97_23`, `tc_b100_65`), the census N-1 operator rule, and (2026-11-05) the `tc_b97_64` burst arm that fails under xdist load (routed to Inc 3).
- The uncommitted E5 records (this packet, `04-validation.md`, the four E5 records, the mutant transcripts, the three E5 transcripts, the `02-test-cases.md` re-audit edit) are to be committed by the orchestrator — nothing here is committed by this record.

## 7. Suggested next task

Merge Inc 1 (canon) then this branch; open Inc 3 to profile the painted-interval ~1 s step (R1-P1) so the two gate runs (R-TST-008/009) and the 3/3 parallel-lane runs can close; read Inc 2's PR CI run for R-TST-014/018-2/090.
