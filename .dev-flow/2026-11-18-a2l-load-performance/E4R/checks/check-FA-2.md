# CHECK FA-2 — mechanical check

- unit: FA-2
- tree: ~/work/zq-fa/FA-2/repo
- HEAD sha: bac9f386048d3be12289c118118afc8c2990c0d4
- start time: Thu Nov 19 05:05:57 PM CST 2026


## Step 1 — Diff hygiene
Command: `cp -a ~/work/zq-fa/FA-2/repo ~/work/zq-fa/chk-FA-2`; `cd chk-FA-2 && git diff > ../chk-FA-2.diff`

- files changed: `tests/test_alp_a2l_occupancy_perf.py`, `tests/test_alp_inc2_a2l_attach.py` — both within the brief's "Files you may edit" ✓
- diff stat: `2 files changed, 24 insertions(+), 9 deletions(-)`
- CR count: `tr -cd '\r' < chk-FA-2.diff | wc -c` = `0` ✓
- added `skip`/`skipif`/`xfail`/`sleep(` lines: none ✓
- removed `def test_` names: none ✓

## Step 2 — GREEN vs base
Base transcript: `~/work/zq-fa/briefs/laws-base-alp.txt` (at 25161a00). Base-RED nodes relevant to this unit and their result now (run on the copy, `-n 0`):

| base-RED node | base result | now |
|---|---|---|
| tests/test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing | FAILED | PASS |
| tests/test_suite_hygiene.py::test_r_tst_040_041_every_upper_timing_bound_is_reported | FAILED | PASS |
| tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors | FAILED | FAILED (no longer names this unit's file; only pre-existing `test_b103_*` main hits) |

Command (law nodes): `S=$HOME/work/zq-fa/chk-FA-2-state; ... pytest -q -n 0 tests/test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing tests/test_suite_hygiene.py::test_r_tst_040_041_every_upper_timing_bound_is_reported`
→ `2 passed in 107.22s`

Command (census): `pytest -q -n 0 tests/test_address_census.py`
→ `1 failed, 22 passed in 46.62s` — the single failure names only `tests/test_b103_a2l_refresh.py` and `tests/test_b103_picker_model.py` (pre-existing `main` hits), NOT `test_alp_inc2_a2l_attach.py`.

Collect-only proofs:
- `--collect-only -q -m "not serial_timing" tests/test_alp_inc2_a2l_attach.py` → `27/40 tests collected (13 deselected)`; none of `test_r033_key_latency`, `test_r034_progress_throughout`, `test_at_alp_i2_2_case06_keys_and_progress` listed ✓
- `--collect-only -q -m "serial_timing and not slow" tests/test_alp_inc2_a2l_attach.py tests/test_alp_a2l_occupancy_perf.py` → 10 collected: held-phase Inc 2 arms only; no case_06 nodes; 158_* counters absent (row 2 removed their serial_timing) ✓
- `--collect-only -q -m "slow" tests/test_alp_inc2_a2l_attach.py tests/test_alp_a2l_occupancy_perf.py` → 7 collected: exactly the 7 heavy case_06 nodes ✓

Nodes that passed at base and fail now: none.

## Step 3 — Negative controls (scratch copy ~/work/zq-fa/chk-FA-2-nc)
Re-applied 3 of the worker's mutations (revert each file to HEAD), ran only the affected node; each went RED as expected:

- NC-1 (row 1): `git show HEAD:tests/test_alp_inc2_a2l_attach.py > tests/test_alp_inc2_a2l_attach.py`; run `test_r_tst_002` →
  `E   AssertionError: timing arm without serial_timing: tests/test_alp_inc2_a2l_attach.py::test_at_alp_i2_2_case06_keys_and_progress`
  `E     timing arm without serial_timing: tests/test_alp_inc2_a2l_attach.py::test_r033_key_latency`
  `E     timing arm without serial_timing: tests/test_alp_inc2_a2l_attach.py::test_r034_progress_throughout`
  → `1 failed` ✓ RED

- NC-2 (row 2): `git show HEAD:tests/test_alp_a2l_occupancy_perf.py > tests/test_alp_a2l_occupancy_perf.py`; run `test_r_tst_002` →
  `E   AssertionError: serial_timing on a test that is not a timing arm: tests/test_alp_a2l_occupancy_perf.py::test_r_a2l_def_158_1_disjoint_1000_checks_bounded`
  `E     serial_timing on a test that is not a timing arm: tests/test_alp_a2l_occupancy_perf.py::test_r_a2l_def_158_2_disjoint_4000_checks_bounded`
  `E     serial_timing on a test that is not a timing arm: tests/test_alp_a2l_occupancy_perf.py::test_r_a2l_def_164_1_case06_index_memory_bound`
  → `1 failed` ✓ RED

- NC-3 (row 4): `git show HEAD:tests/test_alp_inc2_a2l_attach.py > tests/test_alp_inc2_a2l_attach.py`; run `test_address_census.py` →
  `E   AssertionError: address arguments outside {literal, name, fstring} appeared: tests/test_alp_inc2_a2l_attach.py:408 other:IfExp, tests/test_b103_a2l_refresh.py:218 other:IfExp, ...`
  → `1 failed` ✓ RED (the `:408` IfExp is back)

No control stayed GREEN.

## Step 4 — Laws (serial, `-n 0`, six files, on the edited copy)
Command: `pytest -q -n 0 -rfE --tb=line tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`
→ `4 failed, 111 passed, 2 skipped in 420.30s`

RED now vs allowed-RED-at-base (25161a00):

| node | now | allowed at base? |
|---|---|---|
| test_r_tst_002_every_timing_arm_carries_serial_timing | PASS | was RED at base (now fixed) ✓ |
| test_r_tst_040_041_every_upper_timing_bound_is_reported | PASS | was RED at base (now fixed) ✓ |
| test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses | FAILED | allowed RED (pre-existing .dev-flow evidence, not this unit) ✓ |
| test_canon_rows_hold_the_obligation_word_once | FAILED (3 offenders: R-A2L-DEF.153, R-PICKER-CORRECT.004, R-PICKER-CORRECT.008 — exactly the base offenders) | allowed RED ✓ |
| test_at_b83_08_tree_holds_no_assembled_selectors | FAILED (names only tests/test_b103_a2l_refresh.py and tests/test_b103_picker_model.py) | allowed RED ✓ |
| test_no_tracked_file_holds_a_private_token | FAILED (`.dev-flow/.../inc-1/evidence-e4/...` pre-existing files) | allowed RED ✓ |

No new offender inside any allowed RED; no other RED.

Known hole check (blank lines after R-A2L-REFRESH.028 / R-A2L-DEF.155): the parser sees all 3355 rows; the line after each anchor is the next row (`.029` / `.156`), not a blank line, so no rows are hidden. Direct parse + `shall` count of every unit-front row (R-A2L-REFRESH.033/.034/.037/.040–.042/.049–.053, R-A2L-DEF.162–.168) → each `shall_count=1 OK`.

## Step 5 — Worker claims (re-verified)
1. HEAD sha `bac9f386048d3be12289c118118afc8c2990c0d4` (REPORT header / pi.log) → TRUE (`git rev-parse HEAD`).
2. `git diff --stat` = `2 files changed, 24 insertions(+), 9 deletions(-)` (REPORT) → TRUE (same output).
3. CR count = 0 (`git diff | grep -c $'\r'`) (REPORT) → TRUE (`tr -cd '\r' < chk-FA-2.diff | wc -c` = 0).
4. Final law run "2 passed" for 002 + 040_041 (REPORT) → TRUE (I measured `2 passed in 107.22s`; REPORT's `104.56s` is host-load-dependent, the count claim holds).
5. `-m "slow"` lists exactly the 7 heavy nodes (REPORT row 5) → TRUE (7 collected, exact list matches).
6. `test_address_census.py` failure no longer names `test_alp_inc2_a2l_attach.py` (REPORT deviation) → TRUE (remaining names are only `test_b103_a2l_refresh.py` / `test_b103_picker_model.py`).


## Verdict
Steps 1–5 all pass. Verdict: MECH-GO.

CHECK_DONE FA-2 MECH-GO

## Orchestrator intent review (Opus, relevo-22)
GO. Markers only, as designed (R5-F4, R6-F3, operator D11). Row 1: `serial_timing` on the three Inc 2 timing arms, including `test_r034_progress_throughout`, which FA-KEY's capture bound turned into a timing arm (the NO-GO FA-KEY's check raised; resolved here). Row 2: `158_1`/`158_2` (overlap-check counters) and `164_1` (memory bound) are not wall-clock arms by the law's own rule, so `serial_timing` is removed rather than the law changed; they now run in the parallel lane, which is correct for deterministic counts. Row 3: verify only, `test_r_tst_040_041` already GREEN after FA-KEY. Row 4: the census line becomes a named `table_id` variable (no assembled selector). Row 5: `slow` on the seven case_06 nodes, through `pytest.param(..., marks=...)` for the parametrized arms so the ids stay; CI's PR lanes (`serial_timing and not slow`, `not slow and not serial_timing`) now exclude them (operator D11). Controls: each file restored to HEAD turns its law RED again. Laws `test_r_tst_002` and `test_r_tst_040_041`: 2 passed.
Condition of the FA-KEY override met: law `test_r_tst_002` PASSES on this unit's tree and its RED-before control names `test_r034_progress_throughout`; six laws 4 failed (base-alp set minus `test_r_tst_002` and `test_r_tst_040_041`).
