# CHECK FA-IDX2b — mechanical check

- Unit: FA-IDX2b
- Tree path: ~/work/zq-fa/FA-IDX2b/repo
- HEAD sha: 0c14129fa3f38808cda7bfaf9d623d7a6ac19676
- Start time: Thu Nov 19 05:44:58 PM CST 2026


## Step 1 — Diff hygiene
- `cp -a ~/work/zq-fa/FA-IDX2b/repo ~/work/zq-fa/chk-FA-IDX2b`
- `cd ~/work/zq-fa/chk-FA-IDX2b && git diff > ../chk-FA-IDX2b.diff`
- Files changed (`git diff --name-only`): `s19_app/tui/a2l_definition.py` (the only file the brief allows). PASS.
- CR count (`tr -cd '\r' < chk-FA-IDX2b.diff | wc -c`): 0. PASS.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: none. PASS.
- `def test_` removed / re-added: none. PASS.

## Step 2 — GREEN vs base
Ran the brief's node set on the copy (`~/work/zq-fa/chk-FA-IDX2b`, HEAD 0c14129f + worker's uncommitted diff):

- `tests/test_alp_a2l_occupancy.py -n 4` → `23 passed in 3.66s`
- `tests/test_alp_a2l_occupancy_perf.py -n 0 -k "158"` → `4 passed, 4 deselected in 1.54s`
- `tests/test_b103_a2l_definition_arrays.py tests/test_b103_a2l_definition_arrays_coverage.py tests/test_b103_a2l_definition_arrays_decode.py tests/test_b103_a2l_definition_arrays_fix_cap.py -n 4 -m "not serial_timing"` → `274 passed in 11.61s`
- `tests/test_b103_a2l_definition_arrays_scale.py tests/test_b103_a2l_definition_arrays_write.py tests/test_b103_a2l_definition_perf.py tests/test_b103_a2l_definition.py -n 4 -m "not serial_timing"` → `374 passed in 16.34s`
- `tests/test_alp_a2l_occupancy_perf.py::test_r_a2l_def_164_1_case06_index_memory_bound -n 0` → `1 passed in 23.69s`

Base-RED node (reproduced by reversing the worker's diff in `~/work/zq-fa/chk-FA-IDX2b-base` = clean HEAD):
- `test_r_a2l_def_164_1_case06_index_memory_bound` → RED at base: `AssertionError: (1, 'retained', 76744324)` / `assert 76744324 <= 67108864`. NOW GREEN (1 passed).

No node that passed at base fails now: every node in the brief's node set is GREEN above. PASS.

## Step 3 — Negative controls are real
Second copy `~/work/zq-fa/chk-FA-IDX2b-nc` (fresh from worker's tree each time).

NC-1 (row 1, per REPORT): reintroduced `order = tuple(sorted(range(count), key=lambda i: first_of(records[i])))`, kept it as an `_OccupancyIndex` field, and built `leaf_records = [records[i] for i in order]`. Run only `.164`:
`tests/test_alp_a2l_occupancy_perf.py::test_r_a2l_def_164_1_case06_index_memory_bound -n 0`
→ RED: `E AssertionError: (1, 'retained', 68896616)` / `assert 68896616 <= 67108864`. PASS (control is real).

NC-2 (row 2, per REPORT): replaced the two-bisect run search with `leaf = bisect_left(leaf_records, entry[3], key=first_of)` only. Run only `.166/2`:
`tests/test_alp_a2l_occupancy.py::test_r_a2l_def_166_2_equivalence_with_global_scan -n 0`
→ RED: `E AssertionError: occupancy bound grew on materialization (D2 broken)` at `s19_app/tui/a2l_definition.py:4177`. PASS (control is real).

## Step 4 — Laws
Ran serially on the copy: `tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py -n 0`
→ `4 failed, 111 passed, 2 skipped in 412.40s`.

The 4 RED are all in the allowed-at-base list, no new offender:
- `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` — allowed. Offender files (42 distinct) are all pre-existing committed evidence (`evidence/full-suite/...`, `inc-*/...`), subset of base's 43; none is the worker's file.
- `test_canon_rows_hold_the_obligation_word_once` — allowed. Offenders exactly `R-A2L-DEF.153`, `R-PICKER-CORRECT.004`, `R-PICKER-CORRECT.008` (3 offending / 3355 checked; line numbers shifted +6 vs base 4241/4245 → 4247/4251, same rows). No new offender.
- `test_at_b83_08_tree_holds_no_assembled_selectors` — allowed. Offenders are a subset of base (base also had `tests/test_alp_inc2_a2l_attach.py:408`, now fixed/absent); remaining 8 lines identical to base.
- `test_no_tracked_file_holds_a_private_token` — allowed. Offender list (20 `.dev-flow/.../inc-1/evidence-e4/...` paths) byte-identical to base.

Known hole (blank lines after R-A2L-REFRESH.028 / R-A2L-DEF.155): not present in this tree — the rows after `.155` are contiguous. Verified directly that R-A2L-DEF.156–.168 each hold the obligation word exactly once (`shall` x1). The two timing-hygiene laws (`test_r_tst_002`, `test_r_tst_040_041`) now PASS (they were RED at base; passing is fine). PASS.

## Step 5 — Worker claims (5 re-verified)
1. Claim: `git diff --stat` = 1 file, 54 insertions(+), 49 deletions(-), only `s19_app/tui/a2l_definition.py`. → **TRUE** (reproduced: `1 file changed, 54 insertions(+), 49 deletions(-)`).
2. Claim: `git diff | grep -c $'\r'` = 0. → **TRUE** (output `0`, grep exit 1 = no CR lines).
3. Claim (row 4): tree retained 57.26 MiB / peak 59.00 MiB, both ≤ 64 MiB (HEAD was 73.19 / 84.61). → **TRUE** (ran `scratch/mem164.py` on the copy: run 1 & 2 both `retained=60036456 (57.26 MiB) peak=61863864 (59.00 MiB)`, both `<=64MiB=True`; also prints `s19_app: .../chk-FA-IDX2b/s19_app/tui/a2l_definition.py`, confirming HT-03).
4. Claim: `.167` visit means monotone 25.0 / shuffled 25.0 / dense 25.1. → **TRUE** (`R-A2L-DEF.167 monotone: ... = 25.0`, `shuffled: ... = 25.0`, `dense: ... = 25.1`).
5. Claim: final run node set all GREEN (occupancy 23, perf-158 4, b103 584+64, `.164` 1). → **TRUE** (I re-ran: occupancy `23 passed`; perf-158 `4 passed, 4 deselected`; b103 split `274 passed` + `374 passed` = 648 total (worker's 584+64 = same 648, different file split); `.164` `1 passed`).

## Verdict
Steps 1–5 all pass. Verdict: MECH-GO.

CHECK_DONE FA-IDX2b MECH-GO

## Orchestrator intent review and Opus diff review (relevo-22)
GO. Design correction of FA-IDX2's memory defect, implemented as designed: `leaf_records = sorted(records, key=itemgetter(0))` replaces `order` (no new ints; stable, so ties keep walk order); `positions` and `leaf_of_record` are gone and `_tighten_occupancy(index, entry, final_entry)` finds the leaf with two keyed bisects (the run of leaves at `entry[3]`, then `entry[0]` inside it; positions increase inside a run because the sort is stable), raising `AssertionError("occupancy leaf not found")` on a miss; `_shared_with` passes the unmaterialized entry; `min_first`/`max_last`/`min_pos` are returned as built lists (no 4 MiB copies at return). Walk, counted visit and tighten rule unchanged.
Evidence: memory on case_06 (worker, tracemalloc) retained 73.19 → 57.26 MiB, peak 84.61 → 59.00 MiB; `.167` 25.0/25.0/25.1 and `.168` 1,000 unchanged; controls RED (retained `order` → `.164` 68,896,616 B; position-blind run search → the D2 guard fires on `.166/2`). Orchestrator, combined tree (53d61d4b + this diff): case_06 oracle vs 9c464b6a (pre-FA-IDX2 index) 0 differences over 220,040 names; quiet-laptop gate (load ≤ 1.3) 4 passed: `.162` 0.249 s / 2.5 s, `.163` 3.556 s / 18 s, `.164` GREEN, `.165` 20.889 s / 30 s (30.4 % margin, was 42.1 % before FA-IDX2: the per-materialization keyed bisects and the heap cost about 3.5 s on the integrated describe; reported to M2).
