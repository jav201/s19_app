# Inc 3 — E5 rulings (orchestrator, 2026-11-05)

Inputs: E5-code-review.md (PASS-WITH-NOTES, CR-1…CR-8), E5-security.md (PASS-WITH-NOTES, E5S-1…5), E5-coverage-audit.md (4/26 rows changed), E5-mutants.md (9 killed, 0 survived, 2 N/A on Linux), the LAN transcripts `lan-*.txt`.

Run rule: test runs go to the LAN Linux host. Only Windows-only arms (junctions) and Windows timing thresholds run on the Windows PC, with LOCALAPPDATA isolated and no clipboard.

## Corrective pass (binding)

| Id | Source | Ruling |
|---|---|---|
| C-1 | CR-1 | The R-TST-111/112 stamp observer takes its own "laid out" reading instead of sharing `_summary_laid_out` with the arm (graph: written separately). Prove with a mutant of the shared helper that the verifier now goes red. |
| C-2 | CR-4 + audit GATHER.12/3 | The GATHER.12 arm-3 spy records the raw path text the product passes, so folding is observable on both platforms; M-9 must be killed on Windows too. GATHER.12/3 Result follows the new run. |
| C-3 | CR-5 | The R-PROJ-002.14 s19/hex/mac arms assert the status lines the requirement fixes, so a load stopped before the sync cannot pass. |
| C-4 | CR-6, CR-7 | `gather_project_artifacts` docstring states why repeats are skipped and why `resolve()` is not used (cite R-PROJ-GATHER.12/.13); the R-TST-110 docstring drops the retired `max` rule. |
| C-5 | audit 001.13/1 | The test pins the exact line `Project saved + manifest verified`. Case GATHER.12/1 stays `partial` with the audit's reason (1 000 flat names, not the T2 31-folder chain). |
| C-6 | audit R-TST-111/112 | Re-run M-7 with `CI=1` on the final test file so the equality assert, not the 1 s bound, decides; save the transcript; save a RED transcript for R-TST-111 on the final file. On the LAN host. |
| C-7 | audit ROLLBACK.2 | Add case ROLLBACK.2/2 ("unless `patches/` existed before the save") and its test. |
| C-8 | audit owed ATs | Black-box through keys with the pilot: Save project via ctrl+s and the Save dialog; Load via ctrl+l with the replace question; an A2L typed into the Load dialog. Each asserts the painted outcome exactly; where no key route exists, `partial` with the reason. |
| C-9 | CR-3 | Record the stamp-pair gap of the 1 ms equality on the LAN host (3 serial runs; print the gaps). If any gap exceeds 0.5 ms, raise the tolerance to 5 ms and record it as an E3 amendment; otherwise keep 1 ms. |
| C-10 | Windows-only owed | On Windows (exception): 3 more `tc_b100_20[save-project]` runs for R-PROJ-001.13/1 (5/5 with the 2 on record), and M-10/M-11 with the ROLLBACK.9/1 junction node, mutating a detached copy outside the repo. |
| C-11 | records | Repair 02-test-cases.md per the audit's change table and the rows above (platform evidence per case: Windows / LAN Linux); E1-slice §4; Count note. Note in 04-validation (later) that `test_r_tst_049` failed on the LAN clone only because its local `main` ref was stale (fixed by the orchestrator: the clone's `main` now follows `origin/main`). |

## Routed to BACKLOG-CODE (append, batch-101 style)

| Id | Item |
|---|---|
| CR-2 | About 10 dwell-then-press arms stay in the parallel lane (e.g. `test_tc_b97_64_two_external_steps_end_ok`, the same `press("c","c")`); extend the existing tc_b97_64 burst row to name them. |
| E5S-1 | A too-long composition name raises `OSError` (ENAMETOOLONG) in the gather on head and base — fold into the existing S-3 row. |
| E5S-2 | `_schedule` (`project_gather_service.py:643-646`) does not catch `RuntimeError` (library file swapped for a loop mid-gather). |
| CR-8 | duplicated `_folders` helper, stacked spies, import order (NIT). |
| OR-4 / D-4 | `sec6_5 load` / `painted` margins: 1.001 s (Windows int-03) and 1.0017 s (LAN run 1 under load) against 1.0 s. |
