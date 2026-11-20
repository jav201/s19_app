# Unit FA-REQ2 — final load bounds for R-A2L-REFRESH.040–.042 (operator D1 verdict) [deepseek-v4-pro · medium]

Tree: `alp-e4r` at **`92fac5fe`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-rtx.md` (this unit runs on rtx). No agent edits `~/.claude/skills`. **Append to `../REPORT.md` after EACH row (a row not in REPORT.md does not exist). Edit at most the 3 files listed below.**

Brief updated 2026-11-20 by relevo-28 with the M2c numbers; facts re-grepped at 92fac5fe (HT-13).

## Fixed values (operator D1 verdict on page r4, 2026-11-20 = M040/M041_1/M041_2/M042 option A; never compute them yourself)
| row | M2c median (reference host) | median bound (s) | run bound (s) | negative-control hold (s) = run bound + 5 |
|---|---|---|---|---|
| R-A2L-REFRESH.040 | 42.5 s | 54 | 68 | 73 |
| R-A2L-REFRESH.041 (both shapes, /1 pair 47.8 s, /2 nomac 47.3 s) | — | 60 | 75 | 80 |
| R-A2L-REFRESH.042 | 41.5 s | 52 | 65 | 70 |

## Facts at 92fac5fe (re-grepped; do not re-derive)
- `.dev-flow/2026-11-18-a2l-load-performance/E4R/01-requirements.md` lines 26–28 hold the `.040`/`.041`/`.042` rows (`| Id | Form | Requirement | Fit criterion | Negative control | Story | Change |`). Each sentence says "at most 80 s over 3 runs and no individual run of 100 s or more". `.040`'s fit criterion says "median ≤ 80 s, every run < 100 s" and ends "80/100 s is a regression guard until the final bound (measured median × 1.25, operator D1) is approved."; its negative control says "Hold the producer 105 s → RED.". `.041` and `.042` say "As .040." / "As .040, per project shape.".
- There is **no** `## Held for Q1` section, and `R-A2L-REFRESH.050` is **already** in the canon (`REQUIREMENTS.md` :1492) and in E4R: nothing to move or add.
- `REQUIREMENTS.md` :1482–1484 hold the same three sentences in the 3-column canon format `| Id | Form | Requirement |`.
- `tests/test_alp_inc3_load_responsiveness.py`: `BUDGET_MEDIAN_S = 80.0`, `BUDGET_RUN_S = 100.0` (:73–74) under the D-14 comment (:67–72); used only in `_assert_budget` (:520, asserts :524–525 and the print :553). No other file uses these names. The 105 s hold is in the comment only (no code constant). Docstrings citing "median <= 80 s, every run < 100 s (D-14)": module docstring :12–13, `test_r040_…` :563, `test_r041_…` :585, `test_r042_…` :602. `_assert_budget` labels start with the row id: `"R-A2L-REFRESH.040 image+A2L case_06"`, `f"R-A2L-REFRESH.041 project-pair {shape} case_06"`, `"R-A2L-REFRESH.042 A2L-only case_06"`.
- `.dev-flow/.../inc-3/01-requirements.md` also says "80 s": it is an inherited record — **never edit it** (PP-06).
- This unit adds no test module: TC-607 `EXPECTED_SCANNED_TEST_FILES` stays as is (HT-15).

## Files you may edit (3)
`.dev-flow/2026-11-18-a2l-load-performance/E4R/01-requirements.md`, `REQUIREMENTS.md`, `tests/test_alp_inc3_load_responsiveness.py`. (`E4R-rulings.md` is written by the orchestrator at integration.)

## Rows
| row | change | proof / negative control |
|---|---|---|
| 1 | E4R `01-requirements.md`: in each of the three sentences replace `80 s` / `100 s` with the row's median / run bound from the table. `.040` fit criterion: "median ≤ 54 s, every run < 68 s", and replace the sentence "80/100 s is a regression guard until … is approved." with "54/68 s is the final bound (operator D1 verdict, 2026-11-20: M2c median × 1.25, run bound = median bound × 1.25)." `.040` negative control: "Hold the producer 73 s → RED.". `.041` fit: "As .040, per project shape, with median ≤ 60 s and every run < 75 s."; negative control "Hold the producer 80 s → RED.". `.042` fit: "As .040, with median ≤ 52 s and every run < 65 s."; negative control "Hold the producer 70 s → RED.". Leave the Story and Change columns as they are. | every sentence still holds exactly one `shall`; `grep -c "80 s\|100 s"` on the three rows = 0 |
| 2 | `REQUIREMENTS.md`: replace the three canon sentences with the new E4R sentences, byte for byte. | write `../scratch/canon_eq.py` (reads both files, compares the Requirement cell of `.040`–`.042`) → prints `diffs=0` |
| 3 | `tests/test_alp_inc3_load_responsiveness.py`: replace `BUDGET_MEDIAN_S` / `BUDGET_RUN_S` with one dict `BUDGET_S = {"R-A2L-REFRESH.040": (54.0, 68.0), "R-A2L-REFRESH.041": (60.0, 75.0), "R-A2L-REFRESH.042": (52.0, 65.0)}` (row id → (median bound, run bound)). In `_assert_budget`, look the pair up with `BUDGET_S[label.split()[0]]` (a missing key must raise, never default) and use it in the two asserts and the print. Replace the D-14 comment with the D1 verdict text: per-route final bounds (operator D1, 2026-11-20, M2c on the reference host), median bound = ⌈median × 1.25⌉ s, run bound = ⌈median bound × 1.25⌉ s, negative-control hold = run bound + 5 s (73/80/70 s). Update the four docstrings to the route's numbers and "(D1)" instead of "(D-14)". | `--collect-only -q` node ids identical before/after (paste both counts); `python -c` import of the module + assert `BUDGET_S` keys. Negative control without case_06: `../scratch/budget_nc.py` imports the module (same env as pytest) and calls `_assert_budget` with 3 synthetic runs (every field `_assert_budget` reads, valid; `phases` = `PHASES_IMAGE` with 0.0 values): label `"R-A2L-REFRESH.040 x"` totals 50/50/60 s → passes; totals 50/50/69 s → AssertionError (run bound 68); totals 55/55/60 s → AssertionError (median bound 54); label `"R-A2L-REFRESH.099 x"` → KeyError. Paste the four outcomes. (`env -i` leaves `CI` unset, so `timing_bound` returns the bound itself.) |
| 4 | Laws: `tests/test_requirements_canon.py tests/test_id_registry.py tests/test_suite_hygiene.py` (`-n 0`, `timeout 300` each). | no new failure against the base set (inherited: `test_r_tst_070_2`, canon obligation word R-A2L-DEF.153 / R-PICKER-CORRECT.004/.008, `at_b83_08`) |

Never run the case_06 nodes (`test_r040_…`, `test_r041_…`, `test_r042_…`): the orchestrator decides whether they run after integration.
