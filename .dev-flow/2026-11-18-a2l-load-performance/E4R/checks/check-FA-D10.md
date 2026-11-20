# CHECK — FA-D10 (mechanical check)

- unit: FA-D10
- tree: ~/work/zq-fa/FA-D10/repo
- HEAD sha: 8fd1b9588b63ba9ae06203194259c3e75d912b62
- start time: Thu Nov 19 05:33:20 PM CST 2026

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fa/FA-D10/repo ~/work/zq-fa/chk-FA-D10`; in the copy `git diff > ../chk-FA-D10.diff`.

- Files changed (must be within the brief's "Files you may edit" = `s19_app/tui/app/file_load.py`, `tests/test_alp_inc2_a2l_attach.py`, `tests/test_alp_inc3_snapshot_parity.py`):
  - `s19_app/tui/app/file_load.py` (24 lines touched)
  - `tests/test_alp_inc2_a2l_attach.py` (45 lines touched)
  - `tests/test_alp_inc3_snapshot_parity.py` (8 lines touched)
  - `git diff --stat`: 3 files changed, 49 insertions(+), 28 deletions(-). All within the allowed list. OK.
- CR count: `tr -cd '\r' < ../chk-FA-D10.diff | wc -c` → `0`. OK.
- Added `skip` / `skipif` / `xfail` / `sleep(` lines: none. OK.
- `def test_` names removed / re-added: none in the worker's diff (grep `^[+-].*def test_` → no matches). The unit tree shows `test_r033_key_ack_instrument_controls` relative to base-alp 25161a00, but that was added by FA-KEY (parent commit e8dc86a1), not by this worker — the worker's own diff touches no `def test_` line. OK.

Step 1 result: **PASS**.

## Step 2 — GREEN vs base

Environment/HT-03 note: `pyproject.toml` sets `pythonpath = ["."]`. A bare `-c "import s19_app"` under `-I` resolves to the shared editable install, but under `python -I -m pytest` the tree root is inserted first and `s19_app.__file__` resolves inside `./s19_app` (verified: inserting `'.'` into `sys.path` first yields `.../chk-FA-D10/s19_app/__init__.py`, and the D10 `== 1` assertions actually execute against the local tree). OK.

Runs (exact env from the CHK brief, `timeout 1200`, from the copy root):

1. `pytest -q -n 4 -m "not serial_timing and not slow" tests/test_alp_inc2_a2l_attach.py tests/test_alp_inc3_snapshot_parity.py` → `63 passed in 402.37s`.
2. `pytest -q -n 0 tests/test_alp_inc2_a2l_attach.py -k "r029 or r037 or at_alp_i2_3"` → `9 passed, 31 deselected in 148.40s`.
3. `pytest -q -n 0 tests/test_alp_inc3_snapshot_parity.py -k "describe"` → `36 deselected` (0 nodes; brief says then name the changed nodes) → `pytest -q -n 0 tests/test_alp_inc3_snapshot_parity.py -k "r039"` → `5 passed, 31 deselected in 92.82s`.
4. `pytest -q -n 4 tests/test_b103_picker_model.py tests/test_b103_picker_editor.py` → **2 failed, 75 passed in 114.63s**.

Base-RED nodes (from ~/work/zq-fa/briefs/laws-base-alp.txt, six laws at 25161a00) and their result now:
- `test_r_tst_002_every_timing_arm_carries_serial_timing` → now **PASS** (was RED at base).
- `test_r_tst_040_041_every_upper_timing_bound_is_reported` → now **PASS** (was RED at base).
- `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` → still RED (allowed).
- `test_canon_rows_hold_the_obligation_word_once` → still RED (allowed).
- `test_at_b83_08_tree_holds_no_assembled_selectors` → still RED (allowed).
- `test_no_tracked_file_holds_a_private_token` → still RED (allowed).

Nodes that passed at base and fail now (must be none):
- `tests/test_b103_picker_model.py::test_r018_2_changed_generation_batches_once_per_picker` — now FAILS: `assert len(describes) == 2` → `AssertionError: assert 1 == 2` (line 683).
- `tests/test_b103_picker_model.py::test_r018_4_live_reload_refreshes_both_without_reentry` — now FAILS: `assert len(describes) == 2` → `AssertionError: assert 1 == 2` (line 759).

Base verification: ran both at base-alp (25161a00): `pytest -q -n 0 tests/test_b103_picker_model.py -k "test_r018_2 or test_r018_4"` → `2 passed`. So these two nodes passed at base and fail now.

Step 2 result: **FAIL** — 2 nodes pass at base (25161a00) and fail now. Cause: operator D10 (one shared bulk describe) is applied in `file_load.py`, but `test_b103_picker_model.py` still asserts the pre-D10 "one describe per picker" contract (`== 2`). That file was out of FA-D10's edit list ("picker regression, no edits"); its re-pin belongs to the R-PICKER-CORRECT.018 unit.

## Step 3 — Negative controls (re-applied in ~/work/zq-fa/chk-FA-D10-nc)

1. Mutation A (row 1): restore two `describe_definitions` calls + two `MappingProxyType(...)` in `file_load.py`.
   - Run: `pytest -q -n 0 tests/test_alp_inc2_a2l_attach.py -k "r037 and initial"` → RED:
     `assert len(worker_describes) == 1` → `AssertionError ... assert 2 == 1`.
2. Mutation B (row 4): build two separate `MappingProxyType(dict(definitions))`.
   - Run: same node → RED:
     `assert snapshot_map["check"].definitions is snapshot_map["patch"].definitions` → `AssertionError: assert mappingproxy({...}) is mappingproxy({...})`.
3. Mutation C (row 5): duplicate the `_describe_one` call inside `describe_name` in `s19_app/tui/a2l_definition.py` (one bulk describe, two builds per name).
   - Run: same node → RED:
     `assert all(count == 1 for count in describe_one_builds.values())` → `AssertionError: Counter({'OLD_SCALAR': 2, 'ARR12': 2, 'AUX2': 2})`.

All three controls go RED. Step 3 result: **PASS**.

## Step 4 — Laws

Command: `pytest -q -n 0 -rfE --tb=line tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py` → **4 failed, 111 passed, 2 skipped in 422.15s**.

Failing nodes (all within the allowed base-RED set; no new RED node):
- `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` — allowed; offender paths are a strict subset of base (42 vs 43 unique paths; 0 new paths).
- `test_canon_rows_hold_the_obligation_word_once` — allowed; 3 offending (3355 checked): `R-A2L-DEF.153`, `R-PICKER-CORRECT.004`, `R-PICKER-CORRECT.008` — the exact 3 base offenders (line numbers shifted). No new offender.
- `test_at_b83_08_tree_holds_no_assembled_selectors` — allowed; 8 address sites, all present in base's 9 (base's `test_alp_inc2_a2l_attach.py:408` is no longer an offender). No new offender.
- `test_no_tracked_file_holds_a_private_token` — allowed; identical 20-file offender list to base. No new offender.

Known hole check (blank lines in REQUIREMENTS.md after R-A2L-REFRESH.028 / R-A2L-DEF.155): not present in this tree — the rows below both are contiguous (R-A2L-REFRESH.028→.029→.030→.031… and R-A2L-DEF.155→.156→.157→.158… with no blank lines). Direct proof on the unit's rows in REQUIREMENTS.md: each of R-A2L-REFRESH.033/.034/.037/.040/.041/.042/.049/.050/.051/.052/.053 and R-A2L-DEF.162/.163/.164/.165/.166/.167/.168 holds exactly 1 `shall`. The canon law already sees them (3355 checked vs 3317 at base) and reports no new offender.

Step 4 result: **PASS**.

## Step 5 — Worker claims (re-verified)

1. HEAD sha = `8fd1b9588b63ba9ae06203194259c3e75d912b62` → **TRUE** (`git rev-parse HEAD`).
2. `test_alp_inc2_a2l_attach.py` full file = 27 passed → **TRUE** (collect-only: 27/40 collected; combined run 63 passed = 27 + 36).
3. `test_alp_inc3_snapshot_parity.py` full file = 36 passed → **TRUE** (collect-only: 36 collected).
4. Targeted `-k "r029 or r037 or at_alp_i2_3"` = 9 passed → **TRUE** (9 passed, 31 deselected).
5. Deviation 1: picker regression `test_b103_picker_model.py` = 2 failed / 75 passed, both `assert len(describes) == 2` → `1 == 2` → **TRUE** (reproduced: 2 failed, 75 passed; lines 683 and 759).
6. CR check = 0 → **TRUE** (`tr -cd '\r' < diff | wc -c` → 0).

All sampled claims TRUE. Step 5 result: **PASS**.

## Step 6 — Save diff

`~/work/zq-fa/FA-D10/CHECK.diff` written (copy of step 1's diff; 252 lines). DONE.

## Verdict

Step 2 fails (2 nodes pass at base and fail now: `tests/test_b103_picker_model.py::test_r018_2` and `::test_r018_4`), so steps 1–5 do not all pass.

These two failures are a direct, operator-ordered consequence of D10 ("one shared bulk describe"; R-PICKER-CORRECT.018 read as "at most one bulk describe per picker per changed generation"). FA-D10's brief marked `tests/test_b103_picker_model.py` "picker regression, no edits", so the worker correctly left it untouched and reported it as a deviation + open question; the `== 2` → `== 1` re-pin of those two assertions belongs to the R-PICKER-CORRECT.018 unit.

CHECK_DONE FA-D10 MECH-NO-GO

## Orchestrator intent review (Opus, relevo-22)
GO. Operator D10 as designed (DX-F4, R5-F6): `_prepare_a2l_attach_snapshot_inner` describes once and wraps the result in one `MappingProxyType` that both `A2LPickerSnapshot` entries hold, so the 16–19 s second describe of the case_06 attach is gone on all three routes (they share this producer); the mapping is read-only and its dict is not exposed elsewhere. Rows 2–3: every count that measured the producer's bulk describes goes 2 → 1 (attach: r029, r037 ×5, AT-ALP-I2-3 ×2; parity ×4), with the docstrings. Row 4 pins the shared identity; row 5 pins one `_describe_one` build per requested name. Controls: second describe restored → counts RED; two mappings → identity RED; double build → row 5 RED. Worker finding accepted: `test_b103_picker_model.py::test_r018_2` and `::test_r018_4` assert the pre-D10 "one describe per picker" count (`== 2`) and are RED after this unit; that file belongs to FA-C7b (one writer per file), so their re-pin to `== 1` is FA-C7b row 4 (requirement reading changed by operator ruling D10, so TR-01 allows the re-pin). Expected RED until FA-C7b: those two nodes.

## Orchestrator ruling on the MECH-NO-GO (Opus, relevo-22)
Override to GO (DF-02). The only failing step is the pair the worker itself reported: `test_b103_picker_model.py::test_r018_2` and `::test_r018_4` assert the pre-D10 count (`== 2`, one describe per picker) and fail with `1 == 2` because the operator-ordered change (D10, one shared bulk describe) is in place. Their re-pin is FA-C7b row 4 (that file's one writer). Expected RED until FA-C7b: those two nodes. Laws: no new offender (the census offender at the old `:408` is gone).
