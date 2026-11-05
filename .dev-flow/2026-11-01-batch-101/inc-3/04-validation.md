# Inc 3 — validation (E5)

**Verdict: PASS-WITH-NOTES.** The product change (two source files: the once-per-name composition check in `project_gather_service.py`, and the two `mkdir` removals in `app.py`) and the four timing verifiers (R-TST-110 … 113) are verified, and no HIGH or MAJOR is open. The notes are the Windows runs the operator's run rule did not allow, the `sec6_5` margins and the two LAN gate runs, all listed under "Not run / owed". Branch `b101-inc3` at `77a0ac4` plus the uncommitted E5 records and the corrective-pass test edits. Windows host and LAN Linux host. Source files: 2 / 4.

## Runs

| Run | Platform | Result | Evidence (`.dev-flow/2026-11-01-batch-101/evidence/inc-3/`) |
|---|---|---|---|
| RED on base `9f9f6af` (tester: the 4 test files copied into a base worktree) | Windows | gather `-k r_proj_gather_1` **3 failed**; workers + active-variant (14 nodes) **9 failed, 5 passed**; project-check R-TST rows **11 passed** (test-only rows, product identical to base) | `red-01-tester-base.txt` |
| E4 integration, touched files, parallel selection | Windows | **248 passed, 1 xfailed** (pre-existing), 23 deselected | `int-02-touched-lane1.txt` |
| E4 integration, serial lane | Windows | run 1: **52 passed, 1 failed** (the verifier's `[scene]` stopped at the scene's own `sec6_5 load` bound, 1.001 s; not an Inc 3 row); run 2: **53 passed** | `int-03-serial-lane.txt`, `int-06-serial-lane-rerun.txt` |
| E4 integration, verifier alone | Windows | **3 passed** in each of 3 runs; stamp gaps 29.8-52.4 us (panel), 2.7-5.3 us (append) | `int-01-verifier-diag.txt`, `int-05-verifier-3of3.txt` |
| E4 integration, guards and importers | Windows | guards **261 passed**; importers **328 + 315 + 125 passed** | `int-04a-guards.txt` … `int-04d-importers.txt` |
| E5 mutants and owed runs at `6355565` (private remote worktree of `9f9f6af` + the Inc 3 diff) | LAN Linux | lane 1 **1 failed, 301 passed, 10 skipped, 1 xfailed** (the failure is `test_r_tst_049`, a stale `main` ref in the clone, since fixed: the clone's `main` follows `origin/main`; the node passes against the true base); serial runs 1-4: 4 failed under a shared host, then **23 passed, 1 skipped** three times; `save-project` 5/5 at 0.543-0.587 s; POSIX arms **2 passed, 1 skipped** | `lan-01-lane1.txt`, `lan-01b-hygiene-049-diag.txt`, `lan-02-serial-run1.txt` … `run4.txt`, `lan-03-saveproject-run1.txt` … `run5.txt`, `lan-04-posix-arms.txt` |
| E5 corrective pass: final lane 1 (`-n 8 -m "not serial_timing"`, 4 touched files + hygiene + registry) | LAN Linux | idle host: **318 passed, 10 skipped, 1 xfailed, 0 failed** (the counted run); the earlier run at host load 16 had 2 failures, both pre-existing count-bounded waits in untouched nodes, and both pass alone | `e5c-final-lane1-lan.txt` |
| E5 corrective pass: final serial lane (`-m serial_timing`) | LAN Linux | **23 passed, 1 skipped**; QC-TM **43 bounds, 0 under 20 % margin** | `e5c-final-serial-lan.txt` |
| E5 corrective pass: law guards (engine-frozen, directionb incl. `tc031`, requirements canon) | LAN Linux | **196 passed** | `e5c-law-guards-lan.txt` |
| E5 corrective pass: junction arms, GATHER.12/13 and rollback nodes; M-10/M-11/M-12 | Windows | **6 passed** unmutated; each mutant RED | `e5c-c7-c8-rollback-mutants.txt` |
| E5 corrective pass: `save-project` (R-PROJ-001.13/1), 3 more runs | Windows | **3 passed**: 0.525, 0.582, 0.515 s; with the 2 on record (0.694, 0.561) that is 5/5, margins 30.6-48.5 % | `e5c-c10-save-project-windows.txt` |
| Stamp-pair gap of the verifier (C-9), 3 serial runs | LAN Linux | **3 passed** each; panel gaps +30.9 to +52.4 us, append gaps -2.8 to -3.9 us; all under 0.5 ms, so the 1 ms tolerance stands | `e5c-c9-stamp-gaps-lan.txt` |
| Re-audit item (a): the `[a2l]` arm of R-PROJ-002.14/4 now asserts the A2L sync refusal | LAN Linux | GREEN on the tree (**1 passed**); RED under the mutant "the A2L attach never calls the A2L sync" (**1 failed**, `assert 0 == 1` on the refusal count); `app.py` digest identical before and after | `e5d-a2l-sync-assert-lan.txt` |
| Final run on the tree with the re-audit edits: `tests/test_b100_workers.py` + `tests/test_suite_hygiene.py` + `tests/test_id_registry.py` (`-n 8 -m "not serial_timing"`) | LAN Linux | **158 passed, 1 xfailed** in 448.19 s (0 failed; the xfail is pre-existing) | `e5d-final-lan.txt` |

The first final run (`-n 8`, the same three files) ended **1 failed, 157 passed, 1 xfailed**: `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` found one unredacted fragment (a pytest-truncated temp-folder prefix) in `mut-M2.txt`. The transcript was redacted and the gate re-run; the result above is the re-run.

## Mutant score

**14 / 14 KILLED, 0 SURVIVED.** The E5 table had 11 mutants (9 killed on Linux, M-10 and M-11 not runnable there); the corrective pass killed M-10 and M-11 on Windows (the junction node) and added M-12 (`home_preexisted` forced False), M-C1 (the arm's layout reading one pass late) and M-C3 (the file load never posts the sync). M-9 (the `normpath` fold dropped) is killed on both platforms since the C-2 raw-text spy. Three predicate mutants of `_summary_laid_out` are **equivalent** (the first layout publish already carries a laid-out summary) and are recorded, not counted. Each mutant was applied to a copy or a private worktree and restored byte-exact (digest checked). Detail: `E5-mutants.md`, `E5-corrective-notes.md`, `mut-M1.txt` … `mut-M11.txt`, `e5c-*` transcripts.

## Reviews

- **E3 design:** `architect` round 1 **FAIL** (F1 HIGH: R-PROJ-GATHER.13 stated at the wrong level; F2 MAJOR: R-TST-111/112 had no verifier; F3-F11 MINOR) and `security-reviewer` round 1 **FAIL** (`BLOCK-UNTIL: S-1`, the same defect as F1) → corrective pass → round 2 **PASS-WITH-NOTES**: F1 = S-1 and F2 closed, the F5 fold lets no name reach outside the project, notes N-1 … N-3 applied at E4. S-3 and S-5 (LOW) and S-4 (MAJOR, pre-existing) are backlog rows. `E3-architect.md`, `E3-security.md`, `E3-rulings.md`, `E3-r2.md`.
- **E5 code review:** `code-reviewer` **PASS-WITH-NOTES**, 0 BLOCKER / 0 MAJOR / 7 MINOR / 1 NIT (CR-1 … CR-8). CR-1, CR-3 (measured, tolerance kept), CR-4, CR-5, CR-6, CR-7 closed by the corrective pass; CR-2 and CR-8 are backlog rows. `E5-code-review.md`.
- **E5 security review:** `security-reviewer` **PASS-WITH-NOTES**, no HIGH or MEDIUM: E5S-1 (LOW, ENAMETOOLONG, same on base, folded into backlog S-3), E5S-2 (INFO, `_schedule` and `RuntimeError`, backlog), E5S-3 (LOW, existence oracle, same on base, backlog S-5), E5S-4 (INFO, the accepted mid-sync residual O-3), E5S-5 (INFO, a link before `..`, confirms the design). 17 hostile names, 0 outside bytes, head and base. `E5-security.md`.
- **Coverage audit** (independent `qa-reviewer`, which ran nothing and read the transcripts): first audit, 4 of 26 case rows changed; re-audit of the corrective pass, 30 cases: **30 / 30 covered, 0 `gap`, 27 full, 3 partial** (R-PROJ-001.13/1, R-PROJ-GATHER.12/1 and the call-site half of R-TST-110/1), 5 rows still to change (4 wording, 1 assert). Those five are applied by this unit: the R-TST-111/1-3 and 112/1 Results now say the Windows results come from the head-form runs before C-1 and that the C-1 and C-6 runs used the head file minus the C-9 `GAP` print lines (print-only, sha `79a6d8e4…`, checked by the auditor); the `[a2l]` arm asserts the A2L sync refusal (item above). Final totals unchanged: 30 covered, 0 `gap`, 27 full, 3 partial. 27 / 27 cited node ids collected. `E5-coverage-audit.md`.

## Not run / owed

- **002.12/7 and 002.13/3** (the by-keys Load and A2L-typed nodes): not run on Windows by the operator's run rule; Linux only. The new key-driven Save, Load and A2L tests have no Windows run.
- **The C-1 observer form, the C-3 line asserts and the A2L-sync assert** of R-PROJ-002.14/4 have no Windows run either; the Windows Results of R-TST-111/112 and R-PROJ-002.14 name the head-form runs.
- **`sec6_5` margins (OR-4 / D-4):** `sec6_5 load` measured 1.001 s on Windows (int-03) and `sec6_5 painted` 1.0017 s on the loaded LAN host (run 1); `sec6_5 appended` ran 0.59-0.96 s on the E1 Windows host. Idle LAN serial runs show 0 bounds under 20 % margin. Backlog row; no bound raised.
- **R-TST-008 / 009** (Inc 2's two LAN gate runs): owed. This increment addressed their prerequisite (the painted-interval step: clocks stop at the product's own stamps), but the two full-gate runs are not made here.
- **Full suite:** not run here; owed at the batch end. The CI serial-lane confirmation of the verifier and of the `TC-B97-64` burst arm (now `serial_timing`) is also owed.
- **Windows probes** for E5S-1, E5S-2 and the 8.3-name and device-name cases: not run (code reading and E3 runs only).
- **Stale-`main` artifact:** `test_r_tst_049` failed in the first LAN lane-1 run only because the clone's local `main` ref was older than the batch base. The clone's `main` now follows `origin/main`; the node passed in both final lane-1 runs.
- `trace_check.py` and the flow validator were run on this record at close; their summary lines are in the increment packet.
