# CHECK FA-IDX2 — mechanical check (DeepSeek v4-pro)

- unit: FA-IDX2
- tree: ~/work/zq-fa/FA-IDX2/repo
- HEAD sha: f8b7dcf49f5e2364740f474b86d15d3e898d5dc4
- start time: Thu Nov 19 05:19:37 PM CST 2026


## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fa/FA-IDX2/repo ~/work/zq-fa/chk-FA-IDX2`; `cd ~/work/zq-fa/chk-FA-IDX2 && git diff > ../chk-FA-IDX2.diff`

- HEAD sha in copy: `f8b7dcf49f5e2364740f474b86d15d3e898d5dc4` (matches brief `f8b7dcf4` ✓)
- files changed: `s19_app/tui/a2l_definition.py` — within the brief's "Files you may edit" ✓
- diff stat: `1 file changed, 189 insertions(+), 52 deletions(-)`
- CR count: `tr -cd '\r' < ../chk-FA-IDX2.diff | wc -c` = `0` ✓
- added `skip`/`skipif`/`xfail`/`sleep(` lines: none (the only grep hit was the docstring word "is skipped", not a marker) ✓
- removed `def test_` names: none ✓

STEP1_OK

## Step 2 — GREEN vs base (unit node set, same -n as brief)

Env (one line, from the copy root): `S=$HOME/work/zq-fa/chk-FA-IDX2-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q <nodes> < /dev/null`

1. `pytest -q -n 4 tests/test_alp_a2l_occupancy.py` → `23 passed in 3.45s` ✓
2. `.158` counters (explicit node id — see deviation below): `pytest -q -n 0 tests/test_alp_a2l_occupancy_perf.py::test_r_a2l_def_158_1_disjoint_1000_checks_bounded tests/test_alp_a2l_occupancy_perf.py::test_r_a2l_def_158_2_disjoint_4000_checks_bounded` → `4 passed in 1.53s` ✓
3. `pytest -q -n 4 -m "not slow and not serial_timing" tests/test_alp_a2l_occupancy_at.py` → `2 passed in 27.66s` ✓
4. `pytest -q -n 4 -m "not serial_timing" tests/test_b103_a2l_definition.py tests/test_b103_a2l_definition_perf.py tests/test_b103_a2l_definition_arrays.py tests/test_b103_a2l_definition_arrays_coverage.py` → `504 passed in 13.68s` ✓
5. `pytest -q -n 4 -m "not serial_timing" tests/test_b103_a2l_definition_arrays_decode.py tests/test_b103_a2l_definition_arrays_fix_cap.py tests/test_b103_a2l_definition_arrays_scale.py tests/test_b103_a2l_definition_arrays_write.py` → `144 passed in 8.24s` ✓

Unit node set: 23 + 4 + 2 + 648 = 677 passed, 0 failed. Matches REPORT's 673 (occupancy+at+b103) + 4 (`.158`).

Worker deviation #2 re-verified: `pytest --collect-only -q -m "not slow" tests/test_alp_a2l_occupancy_perf.py` collects 8 nodes — the 4 `.158` counters PLUS the 4 forbidden case_06 nodes `.162/.163/.164/.165` (all `serial_timing`, none `slow`). Running `.158` by explicit node id is correct; `-m "not slow"` would have selected the forbidden case_06 nodes. ✓

Base transcript (`~/work/zq-fa/briefs/laws-base-alp.txt`, six laws at 25161a00): its base-RED nodes and their result now are reported in Step 4 (full law run). Base-RED nodes: `test_r_tst_002_every_timing_arm_carries_serial_timing`, `test_r_tst_040_041_every_upper_timing_bound_is_reported`, `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses`, `test_canon_rows_hold_the_obligation_word_once`, `test_at_b83_08_tree_holds_no_assembled_selectors`, `test_no_tracked_file_holds_a_private_token`.

Nodes that passed at base and fail now: none (verified in Step 4 — no base-GREEN law node fails).

## Step 3 — Negative controls are real

Copy: `cp -a ~/work/zq-fa/FA-IDX2/repo ~/work/zq-fa/chk-FA-IDX2-nc` (re-created fresh before each mutation). Same env as Step 2.

1. Row 1 mutation — walk-order leaves (`order = tuple(range(count))` at a2l_definition.py:3981). Node `test_r_a2l_def_167_visits_per_definition[shuffled]`:
   `E   AssertionError: shuffled: mean 5799.0 index-node visits per definition exceeds the bound 67.9`
   → `1 failed in 27.71s` ✓ RED
2. Row 2 mutation — DFS stack in address order (heap → `stack`, push right then left). Nodes `test_r_a2l_def_159_1_position_not_address_selects_next` + `test_r_a2l_def_166_2_equivalence_with_global_scan`:
   `E   AssertionError: assert 'EARLY' == 'LATE'`
   `E   AssertionError: (3, 1, 'N3_28', 'N3_1')`
   → `2 failed in 0.19s` ✓ RED
3. Row 3 mutation — remove the `_tighten_occupancy(index, entry[0], entry)` call in `_shared_with` (a2l_definition.py:4260). Node `test_r_a2l_def_168_dense_overlap_checks`:
   `E   AssertionError: dense: 7000000 candidate-overlap checks exceed the bound 200000`
   → `1 failed in 11.52s` ✓ RED

All three negative controls RED. No control stayed GREEN.

STEP3_OK

## Step 4 — Laws

Command (serially, `-n 0`, env as Step 2): `pytest -q -n 0 -rfE --tb=line tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`

→ `5 failed, 110 passed, 2 skipped in 424.49s`

Failed (all in the allowed-RED-at-base list):
1. `test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing` — offenders: `test_alp_inc2_a2l_attach.py::test_at_alp_i2_2_case06_keys_and_progress`, `::test_r033_key_latency`, `::test_r034_progress_throughout`, `test_alp_a2l_occupancy_perf.py::test_r_a2l_def_158_1_disjoint_1000_checks_bounded`, `::test_r_a2l_def_158_2_disjoint_4000_checks_bounded`, `::test_r_a2l_def_164_1_case06_index_memory_bound`
2. `test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` — offenders all in inherited `evidence/` + `local-runs/` files (redaction gate)
3. `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` — `R-DOC-CANON.4 … 3 offending (3355 checked)`: `R-A2L-DEF.153`, `R-PICKER-CORRECT.004`, `R-PICKER-CORRECT.008` (exactly the base offenders) ✓
4. `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` — offenders: `test_alp_inc2_a2l_attach.py:408`, `test_b103_a2l_refresh.py:218/.282`, `test_b103_picker_model.py:94/.186/.197/.191/.680/.747` (identical to base list) ✓
5. `test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token` — offenders all in `.dev-flow/2026-11-18-a2l-load-performance/` (E3-integration.md, canon_fold.py, inc-1/evidence-e4/*) — identical to base list ✓

No other RED. No base-GREEN node fails now. `test_r_tst_040_041_every_upper_timing_bound_is_reported` (RED at base) now PASSES (fixed by the FA-KEY commit e8dc86a1, "the bound through report_margin (law r_tst_040_041 now passes)").

Offender attribution vs FA-IDX2's diff (only `s19_app/tui/a2l_definition.py`):
- `test_r_tst_002` gained one offender vs base 25161a00: `test_r034_progress_throughout`. This is NOT from FA-IDX2. Proof: at committed HEAD `f8b7dcf4` with `s19_app/tui/a2l_definition.py` reset to HEAD (no FA-IDX2 diff), `test_r_tst_002` fails with the IDENTICAL 6-offender list (incl. `test_r034_progress_throughout`). The offender is in `tests/test_alp_inc2_a2l_attach.py`, introduced by commit `e8dc86a1` (FA-KEY), whose message records it: "The check's NO-GO (r034 becomes a timing arm without serial_timing inside the already-RED law r_tst_002) is resolved by FA-2 row 1." — a cross-unit dependency, not FA-IDX2.
- `test_r_tst_070_2` RESULT file content drifted (`~` → `/home/<name>` inside the same inherited `b103-g3-recents/RESULT`), also pre-existing inherited evidence; FA-IDX2's diff touches no `.dev-flow`/evidence file and contains no home path/user/host/IP token (grep = 0 hits).

Known hole check: current `REQUIREMENTS.md` has 0 blank lines hiding canon rows (0 empty lines followed by `| R-`). Rows after `R-A2L-DEF.155` (R-A2L-DEF.156–.168) and after `R-A2L-REFRESH.028` (R-A2L-REFRESH.029+), incl. the E4R rows `.166/.167/.168` this unit's tests cite, each hold exactly one `shall` — verified by direct parse. No hidden offender.

STEP4_OK

## Step 5 — Worker claims (5 re-verified)

1. **Report extras: mean visits per addressed definition** — "monotone 25.0 / shuffled 25.0 / dense 25.1". Ran `pytest -q -n 0 -s tests/test_alp_a2l_occupancy.py::test_r_a2l_def_167_visits_per_definition[monotone] [shuffled] [dense]` →
   `monotone: 199872 visits / 8000 = 25.0`, `shuffled: 199872 visits / 8000 = 25.0`, `dense: 175860 visits / 7000 = 25.1`. **TRUE** ✓
2. **Report extras: dense `_entry_overlaps` after = 1000**. Ran the unit's `scratch/dense_after.py` (from copy root, PYTHONPATH=.):
   `DENSE overlap_checks: 1000` (visits 175860, materializations 1000). **TRUE** ✓
3. **Report extras: equivalence query count = 4000**. Ran `pytest -q -n 0 -s ...::test_r_a2l_def_166_2_equivalence_with_global_scan` → `R-A2L-DEF.166/2 query count: 4000`. **TRUE** ✓
4. **Row 3b: is_array_entry calls per build, monotone/shuffled/dense = 0**. Ran the unit's `scratch/count_isa.py` →
   `monotone/shuffled/dense: build-loop is_array_entry calls = 0`. **TRUE** ✓
5. **Row 3b: synthetic open-ended fixture 2500 → 1500**. Ran the unit's `scratch/count_isa_synthetic.py` →
   `before(old double-eval) = 2500`, `after(once per entry) = 1500` (records 2000, open-ended 1500). **TRUE** ✓

All 5 claims TRUE.

STEP5_OK

## Step 6 — Diff saved

`cp ~/work/zq-fa/chk-FA-IDX2.diff ~/work/zq-fa/FA-IDX2/CHECK.diff` → 387 lines, `diff --git a/s19_app/tui/a2l_definition.py`.

## Verdict

- Step 1 diff hygiene: PASS (single file `s19_app/tui/a2l_definition.py` within allowed files; CR=0; no added skip/xfail/sleep; no removed tests).
- Step 2 GREEN vs base: PASS (unit node set 677 passed / 0 failed; no base-GREEN node fails now).
- Step 3 negative controls: PASS (all 3 mutations RED with the exact RED lines the worker reported).
- Step 4 laws: PASS (5 RED, all allowed-at-base; FA-IDX2's diff introduces no new offender — the one offender delta vs 25161a00, `test_r034_progress_throughout` in `test_r_tst_002`, is proven pre-existing at HEAD f8b7dcf4 and attributed to FA-KEY e8dc86a1 "resolved by FA-2 row 1", outside FA-IDX2's file scope).
- Step 5 worker claims: PASS (5/5 TRUE).

CHECK_DONE FA-IDX2 MECH-GO

## Orchestrator intent review and Opus diff review (relevo-22)
GO on the diff (design FA-DESIGN §3.5 met). Build: records keep walk order and the FA-IDX1 bounds (each branch rewritten to set `last` directly, so the open-ended predicate runs at most once per entry, design 3b); leaves are a stable sort of record indices by first address (ties keep walk order), with `min_pos`, `order`, `leaf_of_record` and `positions` added and `max_last` kept as a mutable list. Candidates: a min-heap on `(min_pos, node)`; each popped internal node reads `min_first` once (the counted visit) and is pruned on fresh summaries, leaves are checked against their current `max_last`; since a node's `min_pos` bounds every walk position below it, leaves come out in exact walk order, so `shared_with` (first non-exempt overlap in walk order) is unchanged. Tighten: bisect on `positions`, write the leaf's final end, recompute ancestors and stop at the first unchanged node; called in `_shared_with` right after `materialize`. Empty index returns early. Tighten during a lazy walk is safe: nodes already queued are re-checked when popped.
Risk checked: the D2 guard raises `AssertionError` in product code if a non-AXIS, non-array entry materializes longer than its provisional length. Real-data oracle (rtx, not a timing run): `describe_definitions` over all 220,040 case_06 names on ca5ed3bc and on the FA-IDX2 tree — 0 differences in `(shared_with, address, byte_length)`, no exception; each run imported its own tree. Measured by the worker: mean visits 25.0/25.0/25.1 (before 25.0/5,800.8/1,029.8), dense checks 1,000 (before 7,000,000). Re-pins: none. Timing gate `.162`–`.165` on the quiet laptop: see the orchestrator gate note below.

## Orchestrator gate note (relevo-22): `.162`–`.165` on the quiet host
Quiet laptop (load ≤ 1.5), case_06, serial; before = 52d43ae5, after = 52d43ae5 + FA-IDX2T + FA-IDX2. Timing (QC-TM, all ≥ 20 % margin): `.162` index build 0.21 → 0.30 s / 2.5 s; `.163` all 220,040 resolutions 1.08 → 2.98 s / 18 s; `.165` integrated describe 17.4 → 20.4 s / 30 s. **Memory `.164` RED:** retained 76,744,324 B > 67,108,864 B (before: 51.6 MiB retained, 61.3 MiB peak). tracemalloc: the new ints of `order` (8.4 MiB) and `leaf_of_record` (5.9 MiB), `min_pos` (4.0 MiB) and three 1.7 MiB tuples. This unit is integrated with `.164` RED; the design correction is FA-IDX2b (leaf records instead of `order`, keyed-bisect leaf lookup, no return-time copies), integrated next, and the gate is re-run on the combined tree.
