# Inc 3 -- E5 mutant table and owed Linux runs

Batch 2026-11-01-batch-101, increment 3. Author: tester. Evidence state: `executed` for every row; nothing here is `approved`. Host: LAN Linux host, Python 3.11.18, branch base `9f9f6af` plus the Inc 3 diff (`git diff 9f9f6af HEAD`) applied in a private remote worktree; `s19_app.__file__` is printed in every transcript and points at that worktree. The patched state was staged in that worktree, so each mutant was reverted with `git checkout -- s19_app tests` back to the Inc 3 head state and verified with `git diff --quiet` (every mutant transcript ends `REVERTED`). The remote worktree is removed and no remote pytest is left. Transcripts: `evidence/inc-3/mut-*.txt` and `lan-*.txt` (redacted: `<HOME>`, `<USER>`, "LAN Linux host").

## Mutant table

| Id | Requirement | Mutation | Tests run | Result | Transcript |
|---|---|---|---|---|---|
| M-1 | R-PROJ-GATHER.13/2 (also .13/1, ROLLBACK.9/1, 001.13/1) | composition check back to `(resolved_project / name).resolve()` in `gather_project_artifacts` | `test_project_gather.py` -k gather_12/13; `test_b100_active_variant.py` -k rollback_9_2 or save-project | **KILLED** by `test_r_proj_gather_13_a_posix_self_symlink_at_a_composition_name_is_not_raised` (the deterministic POSIX catch). Not caught by time: `save-project` still passed at 0.643 s (35.7 % margin). Junction and rollback arms N/A (skipped, Windows only) | `mut-M1.txt` |
| M-2 | R-PROJ-GATHER.12/1, /2 | once-per-name skip removed | `test_project_gather.py` -k gather_12 | **KILLED** by `test_r_proj_gather_12_each_distinct_composition_name_is_checked_once` | `mut-M2.txt` |
| M-9 | R-PROJ-GATHER.12/3 | `os.path.normpath` fold dropped (`resolved_project / name`) | same | **KILLED** on POSIX by the same node (the case predicted a kill on POSIX only) | `mut-M9.txt` |
| M-10 | R-PROJ-ROLLBACK.9/1 | `manifest_writer._reject_unsafe_entry` returns `None` (accepts link entries); remote E5 copy, reverted | `test_b100_active_variant.py` -k r_proj_rollback_9_2 | **N/A here**: the node is Windows-junction only and skips on Linux (`b100_links.py:30`). State `not-run` until a Windows run | `mut-M10.txt` |
| M-11 | R-PROJ-ROLLBACK.2/1 | `placed_files.extend(gather_outcome.written)` removed in `app.py` | same | **N/A here**: same skipped node. `not-run` | `mut-M11.txt` |
| M-3 | R-PROJ-002.12/2-/4, 002.14/1-/3 | `project_dir.mkdir(parents=True, exist_ok=True)` restored at the start of the S19/HEX/MAC sync's try body | `test_b100_workers.py` -k r_proj_002_12 or r_proj_002_14 or tc_b100_54 | **KILLED**: 6 failed = `..002_12..[deleted-s19/hex/mac]` and `..002_14..[s19/hex/mac]`; the 3 `file-in-place` arms and the existing `tc_b100_54` nodes passed, as designed | `mut-M3.txt` |
| M-4 | R-PROJ-002.13/2, 002.14/4 | mkdir restored in the A2L sync | same file, -k r_proj_002_13 or r_proj_002_14 or tc_b100_54 | **KILLED**: `test_r_proj_002_13_a2l_sync_...mid_attach` and `..002_14..[a2l]` failed | `mut-M4.txt` |
| M-5 | R-TST-110/1 | `_paint_clock_start` returns `max(pressed, stamp)` | `test_b100_project_check.py` -k r_tst_110 | **KILLED** | `mut-M5.txt` |
| M-6 | R-TST-111/1-/3 | panel clock stopped when the wait notices (`time.perf_counter()`), all 3 sites | -k r_tst_111_112 | **KILLED**: `[all-bad]`, `[cap]`, `[scene]` all failed | `mut-M6.txt` |
| M-7 | R-TST-112/1 | append clock stopped when the wait notices | -k r_tst_111_112 | **KILLED** by `[scene]`; `[all-bad]` and `[cap]` passed (they do not measure the append) | `mut-M7.txt` |
| M-8 | R-TST-113/1 | `sec6_5 appended` bound raised to `timing_bound(1.5)` | -k r_tst_113 | **KILLED** | `mut-M8.txt` (the first attempt did not apply: my mutation pattern also matched the node's own planted copy and asserted; the transcript is the re-run that applied) |

M-5 to M-8 were mutated in `tests/test_b100_project_check.py`, because their controls name test-file functions. Source mutants touched only `project_gather_service.py`, `app.py` and (M-10) `manifest_writer.py`.

## Score

11 mutants: **9 KILLED** (M-1, M-2, M-3, M-4, M-5, M-6, M-7, M-8, M-9), **0 SURVIVED**, **2 N/A** (M-10, M-11). Score on the runnable mutants: 9/9.

## Survivor and gap analysis

- No survivor. Two controls were not exercised on this host: M-10 and M-11 need the Windows junction node (`test_r_proj_rollback_9_2_...`), which skips on Linux. They stay `not-run` until a Windows run; R-PROJ-ROLLBACK.9/1 and R-PROJ-ROLLBACK.2/1 have no Linux coverage.
- M-1 is killed on Linux only through the POSIX self-symlink arm. The by-time control (R-PROJ-001.13/1 with `resolve()` restored) did not turn red here: 0.643 s. The timing arm cannot discriminate on this host; no base-revision timing run was made in this unit.
- M-9 is killed on POSIX, as predicted; it survives on Windows by construction (recorded in `02-test-cases.md`).

## Owed Linux runs

| Run | Selection | Result line | Transcript |
|---|---|---|---|
| (a) lane 1 | `-n 8 -m "not serial_timing"`, the 4 touched files + `tests/test_suite_hygiene.py` | `1 failed, 301 passed, 10 skipped, 1 xfailed in 721.68s`; the failure is `test_suite_hygiene.py::test_r_tst_049_wrapped_arms_change_nothing_else` (finding 1) | `lan-01-lane1.txt` |
| (a) diagnosis | the same node with `_merge_base_with_main` pointed at the `origin/main` merge-base | passes against base `9f9f6af` | `lan-01b-hygiene-049-diag.txt` |
| (b) serial x3 (+1) | `-m serial_timing`, same 5 files | run 1: `4 failed, 19 passed, 1 skipped` (another agent's pytest shared the host; failures are bounds: `TC-B100-20` variant-append 1.238 s, mac-sync 1.119 s, a2l-sync 1.042 s, `sec6_5 painted` 1.0017 s in the folder-ceiling arm). Runs 2 and 3: `23 passed, 1 skipped`. Re-run 4 on an idle host: `23 passed, 1 skipped in 66.25s`, QC-TM `43 bounds, 0 under 20 % margin` | `lan-02-serial-run1.txt` to `run4.txt`, `run4-loadnote.txt` |
| (b) verifier | `test_r_tst_111_112_arm_values_equal_the_product_stamps[all-bad/cap/scene]` | passed in all 4 serial runs; none of the 4 run-1 failures is the verifier, so no red `[scene]` needed reading | same |
| (c) save-project x5 | `tests/test_b100_active_variant.py -k "tc_b100_20 and save-project"`, serial | 5/5 passed: 0.560, 0.587, 0.572, 0.543, 0.573 s; margins 44.0, 41.3, 42.8, 45.7, 42.7 % (all >= 20 %, all <= 0.8 s) | `lan-03-saveproject-run1.txt` to `run5.txt`, `lan-03-saveproject-loadnote.txt` |
| (d) POSIX arms | `-k "r_proj_gather_12 or r_proj_gather_13"` | GATHER.12 node (including arm /3) passed; GATHER.13/2 symlink node passed; GATHER.13/1 skipped (junctions Windows-only): `2 passed, 1 skipped` | `lan-04-posix-arms.txt` |

### Findings to route

1. `test_r_tst_049` fails on this host only because the clone's local `main` ref is older than the batch base, so `_merge_base_with_main` picks a different base and sees Inc 2's wrapped arms as drift. It passes against `9f9f6af`. A host/ref artifact, not a product or test defect. For the orchestrator: CI's `main` decides.
2. In serial run 1 the bounds above went over 1 s while another pytest ran on the host; they passed when it was idle (runs 2 to 4). The `sec6_5` margin items (OR-4, D-4) stay open for the orchestrator.
3. The (c) load notes show another agent's pytest was running during those runs, so the times are, if anything, pessimistic.

## Limits

Windows-only cases (GATHER.13/1, ROLLBACK.9/1, ROLLBACK.2/1) and M-10/M-11 are not run here. No base-revision `save-project` timing run was made on the LAN host in this unit.
