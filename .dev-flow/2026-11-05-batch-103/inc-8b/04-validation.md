# Inc 8b — validation (E5)

**Verdict: PASS-WITH-NOTES.** No MAJOR or worse open. Four MAJOR found and fixed in the increment, test first;
MINOR items go to PENDING; the capture verdicts (incl. E5-8b-12) wait for the operator (DF-09).

Reviewer X8b (claude-opus-5-5), orchestrator relevo-16. Base `48af05ff`; reviewed tip `7c4e377c`; validated tip
`ab0aa3d0` (tests `a63f1841`, RED evidence `13ac75d6`, fix `ab0aa3d0`). Runner rtx, HT-02 env (`<runner-home>`),
`s19_app.__file__` and `uptime` head every transcript; `timeout 300` per file; driver `evidence/e5/runs/x8b-run.sh`.

## Runs

| run | tree | result | evidence |
|---|---|---|---|
| New E5 nodes, before the fix | `a63f1841` | s1 96 passed, **2 failed** (R-PE-DEF.117/4, `ZeroDivisionError`); s2 38; at `94_6` 1; bw `81_6`/`91_1` 3 | `evidence/e5/runs/out-red/tip-*.txt` |
| Survivor mutants (HT-09 hard-link copies) | `a63f1841` | 9 / 9 killed on their own rows: N-91, N-101, N-103, N-94c, N-115b, P-B5_5, P-81_6, C-103a, C-103b | `out-red/mut/*.txt`, driver `x8b-mut-driver.py` |
| Inc 8b files (4) | `ab0aa3d0` fresh clone | s1 98 · s2 38 · bw 32 · at 13 — all passed | `out-green/g-b103_inc8b_*.txt` |
| Inc 8 files (14) | same | all passed (a1 23, a2 23, a3 9, at_help 2, at 11, p_layout 31, p_ledger 10, p_wiring 12, s1_detail 43, s1 122, s2_picker 6, s2_formula 27, s2_keys 22, s2_rows 35) | `out-green/g-b103_inc8_*.txt` |
| Inc 9 files (13) | same | all passed (a9 29, b_canvas 42, b_cells 40, b_detail 54, b_model 20, b_tools 59, i 3, ob_json_view 2, w_keys 19, w_mutants 29, w_select 14, w_stage 11, w_jobs 4 without the timing arm and 26_2) | `out-green/g-b103_inc9_*.txt` |
| Hue census `test_tui_patch_json` | same | 14 passed, 3 failed ac1/ac3/ac5 — base-identical (I8b `b3-tui_patch_json`) | `out-green/g-tui_patch_json.txt` |
| Laws (13, HT-03 exact clone + `main` ref) | same | passed: engine_unchanged 1, deps_seam 6, docs_canon 2, no_private_tokens 2, filename_markup 2, b101_doc_hygiene 45, b101_help_legend 71, report_markup 166, b97_key_bar 38, id_registry 12. Base-identical failures only: requirements_canon (same 3 rows), address_census `at_b83_08`, suite_hygiene `r_tst_070_2` (only the base offender `inc-8b/steps.log` "/home/end") | `out-green/law-*.txt`, base `evidence-e4/i8b/b3-*` |
| Timing, serial `-n 0`, 1-min load < 2 | `7c4e377c` | 29_1 **0.224 s** / 0.5 (load 0.15) · 29_2 **0.531 s** / 1.0 (0.67) · 82_1 **0.891 s** / 1.0 (0.91, margin 10.9 %, E5-8b-8) · 20_1 **0.142 s** / 0.5 (1.06) — all passed | `out-timing/t-*.txt` |
| w_jobs 28_2 (memory, 20 LARGE rows) | `7c4e377c` | 1 passed (79.8 s, load 1.05) | `out-timing/t-28_2.txt` |
| Hostile-text probe (scratch, not in `tests/`) | `ab0aa3d0` copy | 84 passed | `evidence/e5/runs/probe/probe.txt`, `probe/test_x8b_probe.py` |

**Mutant score:** E4 61/68 on the row's tests (64/68 wide); after E5 **70/70** on the row's own tests (61 from M8b's run on `35e98ac1`, the 7 survivors re-run here, 2 new card controls).
**Review:** `E5-review.md` — 4 MAJOR fixed (E5-8b-1 subnormal span crash; -2 vacuous 81/6; -3 animation not
observable through Pilot; -4 card half of R-PE-DEF.103), 3 test gaps fixed (-5…-7), MINOR -8…-11 to PENDING.
**Captures:** `E5-captures.md` — 22 real Windows Terminal PNG + sidecars (10 scenes at 118×54 and 220×60, grid and
End at 80×24) on `7c4e377c`, all in colour; the Limits column starts at the same cell on every row kind
(number, enum, bit mask, text, array, NaN): **aligned**; V = 110 / 70 / 194 at 118 / 80 / 220 in WT (equal to
headless; the earlier 111 is not reproduced); 220 seam equal to `D.off` except the expanded ground (E5-8b-12).
Verdicts provisional until the operator's page (DF-09).

## Not run

`w_jobs::26_2` (300 s timeout on tip and base, I8b); `test_b97_width`, `test_tui_snapshot`, `test_b97_chips_help`,
`test_tui_directionb` (unchanged since I8b's GREEN; snapshots only in CI, HT-09). Timing not re-run after
`ab0aa3d0` (touches only `_position`). Captures were taken on `7c4e377c` (the fix changes no painted cell outside a
subnormal-limit row).

## trace_check

```
$ python -I -B <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-8b/01-requirements.md --base 48af05ff --src s19_app
trace_check: 1 US, 43 active requirements (2 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 0 gap(s)
```
