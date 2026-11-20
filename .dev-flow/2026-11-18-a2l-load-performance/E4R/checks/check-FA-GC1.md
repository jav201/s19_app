# CHECK — FA-GC1 (mechanical check, CHK-ds)

- Unit: FA-GC1
- Tree path: ~/work/zq-fa/FA-GC1/repo
- HEAD sha: 35d69a03f4f07c704857c2915b373b536a0bd17f
- Start time: Thu Nov 19 16:10:18 CST 2026

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fa/FA-GC1/repo ~/work/zq-fa/chk-FA-GC1`; in the copy `git diff > ../chk-FA-GC1.diff`.

- Files changed (from `git diff --stat`):
  - s19_app/tui/a2l_definition.py   | 1 +
  - tests/test_alp_a2l_occupancy.py | 32 ++++++++++++++++++++++++++++++++
  - 2 files changed, 33 insertions(+)
- Both files are within the brief's "Files you may edit" (`s19_app/tui/a2l_definition.py`, `tests/test_alp_a2l_occupancy.py`): OK.
- CR count (`tr -cd '\r' < diff | wc -c`): 0 — OK.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines (grep `^+` on diff): NONE — OK.
- Removed `def test_` names (grep `^-` on diff): NONE — OK. (One `def test_` added: `test_r_a2l_refresh_053_describe_leaves_no_cyclic_garbage`, ordered by the brief row 2.)


## Step 2 — GREEN vs base

Node set run on the copy `~/work/zq-fa/chk-FA-GC1` with the mandated env (timeout 1200), same `-n` as the brief.

1. `tests/test_alp_a2l_occupancy.py -n 4` → `16 passed in 2.59s`
2. `tests/test_alp_a2l_occupancy_at.py -n 4 -m "not slow and not serial_timing"` → `2 passed in 23.04s`
3. `tests/test_b103_a2l_definition.py -n 4 -m "not serial_timing"` → `310 passed in 8.30s`

Base transcript (`~/work/zq-fa/briefs/laws-base-alp.txt`) covers only the six law files, not the brief's node set. There are therefore no base-RED nodes within the brief's node set, and no node in the brief's node set fails now (all 328 collected tests pass). OK.

## Step 3 — Negative controls are real

Second copy `~/work/zq-fa/chk-FA-GC1-nc`; re-applied the worker's product mutation (delete the `walk = None` line, i.e. reverse the row-1 fix — the only product mutation; REPORT rows 1 and 2 share this one control).

Command: `cd ~/work/zq-fa/chk-FA-GC1-nc; sed -i '/    walk = None  # break the closure self-cycle/d' s19_app/tui/a2l_definition.py` then run only the affected node `tests/test_alp_a2l_occupancy.py::test_r_a2l_refresh_053_describe_leaves_no_cyclic_garbage`.

RED assertion line:
`E   AssertionError: describe_definitions left 24023 cyclic objects behind (the walk closure self-cycle keeps every per-name list and walk entry alive)`
`E   assert 24023 < 1000`

Result: `1 failed in 1.02s`. Control went RED (n = 24023 ≈ 3 × 8000, matching REPORT) → the test is a real negative control. OK.

## Step 4 — Laws (serial, -n 0)

Command: `tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py` with `-n 0` (full env line, timeout 1200).

Summary line: `6 failed, 109 passed, 2 skipped in 448.15s (0:07:28)` — identical counts to base (25161a00): `6 failed, 109 passed, 2 skipped`.

Failed nodes (all six are the allowed base-RED set; no new RED, no new offenders inside an allowed RED):
- test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing (allowed; same timing-arm offenders as base)
- test_suite_hygiene.py::test_r_tst_040_041_every_upper_timing_bound_is_reported (allowed; same `tests/test_alp_inc2_a2l_attach.py:609` offender)
- test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses (allowed; same `.dev-flow` evidence offenders)
- test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once (allowed; offenders exactly R-A2L-DEF.153, R-PICKER-CORRECT.004, R-PICKER-CORRECT.008 — same 3 as base, line numbers shifted by the E4R rows added upstream)
- test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors (allowed; same 9 offenders in test_alp_inc2_a2l_attach.py / test_b103_a2l_refresh.py / test_b103_picker_model.py)
- test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token (allowed; same `.dev-flow/2026-11-18-a2l-load-performance/inc-1/evidence-e4/*` offenders; none in the unit's edited files)

Known hole (blank lines after R-A2L-REFRESH.028 / R-A2L-DEF.155) does not apply here: this unit edited no REQUIREMENTS.md rows; its row R-A2L-REFRESH.053 lives in E4R/01-requirements.md and is verified by the unit's new test (Step 2/3). OK.

## Step 5 — Worker claims (re-verified)

1. "HEAD check: 35d69a03 ✓ matches brief" → TRUE. `git rev-parse HEAD` in the copy = 35d69a03f4f07c704857c2915b373b536a0bd17f.
2. "Grep-first: walk calls only at 658/730 (recursion) and 732 (initial call); no later code in describe_definitions calls walk" → TRUE. `grep -n walk s19_app/tui/a2l_definition.py`: closure `def walk` at 644, recursive calls at 658 and 730, initial call at 732, then `walk = None` at 733; all other matches are unrelated identifiers (`_walk_record_layout_components`, docstrings, `walked`, etc.).
3. "New test test_r_a2l_refresh_053_describe_leaves_no_cyclic_garbage passes (1 passed)" → TRUE. Individual run: `1 passed in 0.99s`.
4. "Negative control RED: n = 24023 (≈ 3 × 8000)" → TRUE. Step 3 produced `E   assert 24023 < 1000`.
5. "Final runs 16 / 2 / 310 passed; git diff --stat 2 files +33; CR count 0" → TRUE. Step 2: 16 passed / 2 passed / 310 passed. Step 1: 2 files changed, 33 insertions(+); `tr -cd '\r' < diff | wc -c` = 0.

All 5 claims TRUE.

## Step 6 — Save the diff

Saved step 1's diff to `~/work/zq-fa/FA-GC1/CHECK.diff` (62 lines; identical to the copy's `git diff`).

## Verdict

Steps 1–5 all pass → MECH-GO.

CHECK_DONE FA-GC1 MECH-GO

## Orchestrator intent review (Opus, relevo-21)
GO. Row 1 is the fixed diagnosis DX-F3: `walk` is a recursive closure whose cell refers to itself, so every per-name list and walk entry it captures waited for a cyclic collection; `walk = None` right after the last call (no later code calls it, worker grep) breaks the cycle. Row 2 measures the property the row states (R-A2L-REFRESH.053: no cyclic garbage after a describe) with `gc` disabled around the call and no wall-clock bound; control RED at n = 24023 (about 3 per object). Integration note: the orchestrator added the row id to the one-line comment (`(R-A2L-REFRESH.053, DX-F3)`, as the brief asked; comment-only change after the check). Worker deviation recorded in PENDING P-198: the worker uninstalled and reinstalled the shared editable install to run its control; a probe showed pytest imports the cwd tree, so its results and this check stand.
