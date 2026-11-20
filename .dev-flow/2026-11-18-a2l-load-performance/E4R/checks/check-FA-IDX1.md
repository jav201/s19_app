# CHECK FA-IDX1 (mechanical)

- Unit: FA-IDX1
- Tree path: ~/work/zq-fa/FA-IDX1/repo
- HEAD sha: ec8e7bd419208a5c891d35a965d5d091b561c52c
- Start time: 2026-11-19 16:40:39 CST

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fa/FA-IDX1/repo ~/work/zq-fa/chk-FA-IDX1` ; in the copy `git diff > ../chk-FA-IDX1.diff`.

Files changed (from `grep '^diff --git'`):
- s19_app/tui/a2l_definition.py
- tests/test_alp_a2l_occupancy.py

Both are within the brief's "Files you may edit" (s19_app/tui/a2l_definition.py, tests/test_alp_a2l_occupancy.py). PASS.

CR count (`tr -cd '\r' < ~/work/zq-fa/chk-FA-IDX1.diff | wc -c`): 0. PASS.

Added `skip`/`skipif`/`xfail`/`sleep(` lines (`grep -E '^\+' diff | grep -nE 'skip|skipif|xfail|sleep\('`): none. PASS.

Removed `def test_` names not re-added: none removed; three added (`test_r_a2l_def_166_1_unresolved_array_is_open_ended`, `test_r_a2l_def_166_2_equivalence_with_global_scan`, `test_r_a2l_def_166_3_write_safety_curve_com_axis`). No retirements ordered by the brief beyond adding these. PASS.

## Step 2 — GREEN vs base

Ran the brief's node set on the copy (same `-n` as brief), and the same nodes on the base clone (~/work/zq-fa/base-alp, 25161a00) as the baseline. Base-RED nodes for the unit node set: none (all passed at base). No node that passed at base fails now.

Copy results (exact commands + summary):
- `timeout 1200 env -i … /data/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q tests/test_alp_a2l_occupancy.py -n 4` → `19 passed in 2.61s`
- `… -q tests/test_alp_a2l_occupancy_at.py -n 4 -m "not slow and not serial_timing"` → `2 passed in 26.60s`
- `… -q tests/test_b103_a2l_definition_arrays_write.py -k "138 or 139 or 140" -n 4` → `11 passed in 2.45s`
- `… -q tests/test_b103_a2l_definition.py -n 4 -m "not serial_timing"` → `310 passed in 13.91s`

Base (25161a00) results:
- `tests/test_alp_a2l_occupancy.py -n 4` → `15 passed in 2.68s`
- `tests/test_alp_a2l_occupancy_at.py -n 4 -m "not slow and not serial_timing"` → `2 passed in 25.21s`
- `tests/test_b103_a2l_definition_arrays_write.py -k "138 or 139 or 140" -n 4` → `11 passed in 3.99s`
- `tests/test_b103_a2l_definition.py -n 4 -m "not serial_timing"` → `310 passed in 10.90s`

The provided base transcript ~/work/zq-fa/briefs/laws-base-alp.txt covers only the six law files (not the unit node set). Its 6 base-RED nodes are re-checked in Step 4.

## Step 3 — Negative controls are real

Re-applied the worker's single negative-control mutation (REPORT.md row 1; shared for rows 1–4) in a second copy ~/work/zq-fa/chk-FA-IDX1-nc: restore old order = delete the new `elif entry[2] == "AXIS_PTS" or is_array_entry(entry):` branch at s19_app/tui/a2l_definition.py:3934 (so unresolved entries fall through to provisional `entry[4]`). Ran only the affected node for each new test.

- Node `tests/test_alp_a2l_occupancy.py::test_r_a2l_def_166_1_unresolved_array_is_open_ended` → RED: `E assert (16, 19) == (16, None)` (At index 1 diff: 19 != None)
- Node `tests/test_alp_a2l_occupancy.py::test_r_a2l_def_166_2_equivalence_with_global_scan` → RED: `E AssertionError: (13, 1, 'N13_8', 'N13_0')` / `assert 'N13_8' == 'N13_0'`
- Node `tests/test_alp_a2l_occupancy.py::test_r_a2l_def_166_3_write_safety_curve_com_axis` → RED: `E AssertionError: assert None == 'CR'`

All three controls go RED (none stays GREEN). PASS.

## Step 4 — Laws

Command (serial, from copy root):
`timeout 1200 env -i … /data/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`

Summary: `6 failed, 109 passed, 2 skipped in 469.20s (0:07:49)`.

The 6 RED nodes are exactly the allowed base-RED set, with the same offender lists as base:
- test_r_tst_002_every_timing_arm_carries_serial_timing (same 5 offenders)
- test_r_tst_040_041_every_upper_timing_bound_is_reported (same 1 offender: tests/test_alp_inc2_a2l_attach.py:609)
- test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses (same evidence offenders)
- test_canon_rows_hold_the_obligation_word_once (offenders: R-A2L-DEF.153, R-PICKER-CORRECT.004, R-PICKER-CORRECT.008 — the base offenders only; no new offender)
- test_at_b83_08_tree_holds_no_assembled_selectors (same 9 inherited test-file sites)
- test_no_tracked_file_holds_a_private_token (hits all under inherited .dev-flow/ evidence; none in s19_app/tui/a2l_definition.py or tests/test_alp_a2l_occupancy.py)

Known hole note: at HEAD ec8e7bd4 the blank lines after R-A2L-REFRESH.028 and R-A2L-DEF.155 are already removed (fixed by FA-REQb before this unit), so the canon law now sees the rows below them (checked 3355 rows vs 3317 at base) and still reports only the 3 base offenders. Direct proof for this front's 18 E4R rows (R-A2L-DEF.162–168, R-A2L-REFRESH.033/.034/.037/.040–.042/.049–.053): each holds `shall` exactly once (grep count = 1 for every row). PASS.

## Step 5 — Worker claims

1. REPORT.md header "HEAD: ec8e7bd419208a5c891d35a965d5d091b561c52c" → TRUE. `git rev-parse HEAD` in the unit tree prints ec8e7bd419208a5c891d35a965d5d091b561c52c.
2. REPORT.md final run "tests/test_alp_a2l_occupancy.py -n 4 → 19 passed" → TRUE. Re-ran on the copy: `19 passed in 2.61s`.
3. REPORT.md final run "tests/test_b103_a2l_definition.py -n 4 -m 'not serial_timing' → 310 passed" → TRUE. Re-ran on the copy: `310 passed in 13.91s`.
4. REPORT.md row 2 negative-control RED line `E assert (16, 19) == (16, None)` → TRUE. Re-applied the "restore old order" mutation in ~/work/zq-fa/chk-FA-IDX1-nc and ran only that node: RED with `E assert (16, 19) == (16, None)` (At index 1 diff: 19 != None).
5. REPORT.md Deviations row-4 reachability (parse errors == [], CR tag length 4, CR byte_length 10, V.shared_with == "CR") → TRUE. Ran ../FA-IDX1/scratch/reach166.py from the copy root: `parse errors: []`, `tag CR … length= 4`, `CR definition: byte_length= 10`, `V definition: shared_with= CR`. (The encode refusal A2L-DEF-OVERLAP is asserted by the GREEN test test_r_a2l_def_166_3_write_safety_curve_com_axis, which passed in Step 2.)

## Step 6 — Diff saved

Saved the step-1 diff as ~/work/zq-fa/FA-IDX1/CHECK.diff (10018 bytes; CR count 0).

## Verdict

Steps 1–5 all pass.

CHECK_DONE FA-IDX1 MECH-GO

## Orchestrator intent review (Opus, relevo-21)
GO. The product change is the designed reorder only (operator D2, ruling D-4): a cached or requested final length still wins; an entry with neither that is AXIS_PTS or array-like is now open-ended instead of being bounded by the parser's provisional length; the rest keep `first + len - 1`. Row 4 proved R5's case REACHABLE (CURVE `CR` with `COM_AXIS` to an AXIS_PTS, standing `DATA_SIZE 4`, final span 10; VALUE `V` at 0x105 was pruned before): `test_r_a2l_def_166_3` now asserts `shared_with == "CR"` and the `A2L-DEF-OVERLAP` encode refusal, so this is a real write-safety fix, not only a ruling alignment. Rows 2/3: the direct-index test and the 4,000-trial equivalence with a global-scan reference (final lengths, walk order, self-exclusion, mask exemption). Cost (worker's open question, accepted for now): a narrow describe of case_06's last name builds the index in 3.63 s warm vs 1.82 s (same materializations/builds), because `is_array_entry` now runs for every entry without a final length — and twice for the open-ended ones (the new branch, then the existing `last = None` branch). Measured with a law run on the same host; FA-DESIGN §5/§6 already route this to FA-IDX2 (traversal) and M1 (quiet-host decision on the .163/.165 margins). BLOB/INSTANCE also become open-ended: conservative and result-neutral (`_entry_overlaps` still checks exact spans), as the ruling allows false positives but no missed overlap.
