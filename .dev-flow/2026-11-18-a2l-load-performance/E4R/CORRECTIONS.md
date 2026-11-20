# Corrections to inherited claims (E4R, fixed forward)

Each row quotes a claim from the batch's own records, gives the evidence and the corrected statement. Inherited files are unchanged (PP-06). Sources of the findings: reviews R3–R6 and DX of 2026-11-19.

## Table A — the conductor's status note (uncommitted, 2026-11-19 09:35)

| # | Claim (translated) | Verdict | Evidence | Corrected statement |
|---|---|---|---|---|
| A1 | "Conductor: Hermes (DeepSeek v4 Pro)" | UNVERIFIED | `steps.log` E0–E3 name a "Kimi orchestrator"; the D-rulings name only "the conductor" | The conductor's model is not recorded consistently. |
| A2 | "RED on base: 26/26, 37/37, 39/39" | MISLEADING | 77–78 of 102 nodes were RED only through seam guards (`inc-*/evidence-e4/red-*.txt`); re-measured at this HEAD: 83 of 102 carry a missing-seam assertion (see REPORT row A2) | RED counts are real, but most are seam guards; base responsiveness and load time were never measured. |
| A3 | "Inc 2 37/37 (sequential chunks, 0 failures)" | FALSE | each of the three complete runs failed one node: `inc-2/evidence-e4/green-inc2-attach-final*.txt` | 37/37 was assembled from two partial chunks; three full runs each had one failure. |
| A4 | "Inc 3 perf 4/4 (12 case_06 runs, median ≤ 80 s D-14)" | FALSE | `inc-3/evidence-e4/green-inc3-perf-fixed.txt` ends `4 failed in 836.00s`; `tick_failures` 75–99 | All four Inc 3 performance nodes failed their tick assertion. |
| A5 | "Mutants 14/14, 13/13, 13/13 KILLED; 0 survivors unruled" | FALSE (Inc 3) | the `.040`/`.041` targets fail unmutated (A4), so their kills are vacuous; no `.042` mutant; "13/13" counts the 039 re-run twice | Inc 3 mutant evidence is incomplete; re-run after the nodes pass (FA-D11b). |
| A6 | "Inc 1 thresholds executed … 0 oracle differences" | TRUE ON WINDOWS ONLY | the case_06 pins were the CRLF working copy; on LF checkouts the digest guard fails (R6-F1); re-pinned at `25161a00`, verified by FA-0 | Valid on the Windows working copy; Linux verification by FA-0. |
| A7 | "Law guards 57/57 green … 1 pre-existing failure" | CONTRADICTED | `evidence/e5-law-guards.txt`: `1 failed, 57 passed`; on Linux the branch adds two law failures (`test_r_tst_002`, `test_r_tst_040_041`) and C-7 2 → 4 sites (R6-F3); `test_no_private_tokens` fails (R3-F7) | Laws were not green; fixed by FA-2, FA-C7, FA-PRIV. |
| A8 | "Independent E5 review … 2 MAJOR ruled COVERED with executed evidence … 2 permanent arms (green)" | FALSE | reviewer and author were the same model (R4-F7); `file_load.py` attach install `except` never re-enabled GC (R5-F3); the two arms cannot fail (Textual re-raises over the AssertionError); no transcript of them (R4-F4) | The MAJORs were not covered; fixed by FA-GC2T/FA-GC2 (R-A2L-REFRESH.051). |
| A9 | "Canon: form guard passes for all new rows" | MISLEADING | true only because the canon was folded from the uncommitted `.033` edit; the committed `inc-2` row has three `shall` (R4-F3) | Superseded by E4R `.033` + `.049` + `.034`. |
| A10 | "Form fix of .033 … only needs committing" | FALSE | the edit restores the 1.0 s capture bound that D-11 removed and keeps three responses (R4-F3) | Not adopted; E4R splits the row per operator D-11. |
| A11 | "Reference runs green: b103+b100+b102 …, Inc 2/Inc 3 regressions" | CONTRADICTED | `inc-3/evidence-e4/b103-regression.txt`: 10 preserved-family failures; `run2`: 1; called flakes without N ≥ 10 (R4-F8) | Re-measured by FA-0 block 8 (×10 per failing node). |
| A12 | "trace_check … cross-increment SLICE gaps expected" | FALSE IN PART | `shared.py` is Inc 3's own file and no row named it; `trace_check --canon` exits 1 (R4-F9) | E4R slice section names `shared.py`. |
| A13 | "First attempt (4 chunks) died at ~4.7 h by session cleanup" | CONTRADICTED | P-167(a): the orchestrator stopped the batch-end suite by PID on the operator's choice. That decision record lives outside the repository (it names hosts); the orchestrator verified the row against it. Not reproducible from this tree alone: the tree holds only P-167b/P-167c (`E4R/E4R-rulings.md`) | Stopped on the operator's choice; no result. |
| A14 | "3–5 F observed in the first files of chunk 1" | INCOMPLETE | the stopped 4-chunk transcript reached 61 % with 21 `F` (archived outside the repository; the orchestrator counted it). The committed `evidence/full-suite-chunk1.txt` is the conductor's copy that stops at 5 % with 3 `F` | 21 failures by 61 % of chunk 1, untriaged. |
| A15 | "Whole-batch E2 extraction 0 drift" | TRUE BUT BLIND | the extraction compares signatures and call edges only; it cannot see R5-F1's behavioural deviation | Index behaviour is checked by R-A2L-DEF.166 tests. |
| A16 | "Executed verification (machine, no smoke)" | MISLEADING | see A3–A8 | — |

## Table B — committed records

| # | Record | Claim | Verdict | Evidence | Corrected statement |
|---|---|---|---|---|---|
| B1 | `inc-3/E4-report.md:12`, `inc-3/04-validation.md:8`, `steps.log` E4 Inc3 | performance 4/4, responsiveness intact | FALSE | as A4 | as A4 |
| B2 | `steps.log` E4 Inc2 | 37/37 GREEN in two sequential chunks | MISLEADING | as A3 | as A3 |
| B3 | `inc-1/04-validation.md:8` | 459 regression nodes | FALSE | `inc-1/evidence-e4/regression-inc1.txt`: `25 passed, 285 deselected` and `64 passed` | 89 regression nodes ran. |
| B4 | `inc-3/E4-report.md:7`, `inc-3/04-validation.md:7` | behavioural smoke confirmed route-level RED | UNSUPPORTED | no transcript exists | No evidence on disk. |
| B5 | `evidence/e5-review.txt`, `steps.log` E5 | MAJORs covered; law guards 57/57 | FALSE | as A7, A8 | as A7, A8 |
| B6 | `conflicts.md` (grep `probe-producer-cost`) | producer-cost probe "describes ~180 s each" | UNSUPPORTED | only the `.py` is committed, no `.txt` | No transcript on disk. |
| B7 | `inc-3/04-validation.md:29` | SLICE clean | FALSE | as A12 | as A12 |
| B8 | `inc-2/codewire/graph-inc2.md:47,48,59,60`; `inc-2/02-test-cases.md` rules | the pre-D-11/D-12 obligations; 50 typed `not_run` | STALE | R4-F10 | Superseded by E4R rows and `E4R/02-test-cases.md`. |
| B9 | `inc-3/01-requirements.md` `.040`–`.042` status `new`; notes inside canon sentences; `steps.log` lines without time; `evidence/deepseek-e1-audit.txt` 0 bytes | record hygiene | STALE | R4-F10 | E4R rows carry status and clean sentences; E4R `steps.log` lines carry times. |

Status note: the conductor's uncommitted status file of 2026-11-19 09:35 is not committed to the branch; its claims are listed in table A (translated from Spanish). The interrupted batch-end suite transcripts are not committed; they are archived outside the repository (stopped on the operator's choice, P-167a).
