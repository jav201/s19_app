# CHECK — FA-IDX2T (mechanical)

- Unit: FA-IDX2T
- Tree path: ~/work/zq-fa/FA-IDX2T/repo
- HEAD sha: bac9f386048d3be12289c118118afc8c2990c0d4
- Start time: Thu Nov 19 05:05:31 PM CST 2026


## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fa/FA-IDX2T/repo ~/work/zq-fa/chk-FA-IDX2T`; in the copy `git diff > ../chk-FA-IDX2T.diff`.

- Files changed: `tests/test_alp_a2l_occupancy.py` only (1 file, 195 insertions, 15 deletions). This is the single file in the brief's "Files you may edit". ✅
- CR count: `tr -cd '\r' < diff | wc -c` → `0`. ✅
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: none (grep of `+` lines returned nothing). ✅
- `def test_` names removed and not re-added: none. Added: `test_r_a2l_def_167_visits_per_definition`, `test_r_a2l_def_168_dense_overlap_checks` (both ordered by the brief); `test_r_a2l_def_159_2_aliases_are_not_gathered_or_sorted` kept the same name (re-pin, not a retirement). ✅

Step 1 PASS.

## Step 2 — GREEN vs base

Command (copy root, full node set with `-n 4` as the brief allows):
`S=$HOME/work/zq-fa/chk-FA-IDX2T-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 4 tests/test_alp_a2l_occupancy.py < /dev/null`

Summary: `3 failed, 20 passed in 20.88s` (re-run: same).

The three failures are exactly the brief's RED-before arms (counts, not import/seam errors):
- `test_r_a2l_def_167_visits_per_definition[shuffled]` → RED: `mean 5800.8` (`46406794 visits / 8000`), `assert 5800.84925 <= 67.86313713864834`.
- `test_r_a2l_def_167_visits_per_definition[dense]` → RED: `mean 1029.8` (`7208408 visits / 7000`), `assert 1029.7725714285714 <= 67.86313713864834`.
- `test_r_a2l_def_168_dense_overlap_checks` → RED: `dense: 7000000 candidate-overlap checks exceed the bound 200000` (`assert 7000000 <= (25 * 8000)`).
- `test_r_a2l_def_167_visits_per_definition[monotone]` → GREEN: `200000 visits / 8000 = 25.0 mean` (verified `-s -n 0`).

Base node set (base clone 25161a00, `tests/test_alp_a2l_occupancy.py` has 15 nodes): `15 passed`. None of the 15 base-passing nodes fails now (all are among the 20 passing). Base-RED nodes: none existed at base for this file; the three RED arms are new nodes that are RED-now by design (the brief's "RED now" arms). No node that passed at base fails now. ✅

Step 2 PASS.

## Step 3 — Negative controls are real

Second copy `~/work/zq-fa/chk-FA-IDX2T-nc` (fresh `cp -a` each time), run the affected node only.

Row 3 mutation (per REPORT.md): removed address pruning in `_occupancy_candidates` (kept the `min_first[node]` read so the visit counter still counts):
```python
        subtree_min = min_first[node]
        if subtree_min is None:
            continue
        stack.append(2 * node + 1)
        stack.append(2 * node)
```
Command: `… python -I -B -m pytest -p no:cacheprovider -q -s -n 0 "tests/test_alp_a2l_occupancy.py::test_r_a2l_def_167_visits_per_definition[monotone]" < /dev/null`
Result RED: `AssertionError: monotone: mean 8003.0 index-node visits per definition exceeds the bound 67.9` / `assert 8003.0 <= 67.86313713864834`. ✅ (matches worker's RED line)

Row 4: brief states "AXIS_PTS already behave as the mutation would, so RED now is the evidence" — no mutation applied; the RED-now evidence is the 7,000,000-check RED in step 2. ✅

Row 5 mutation (per REPORT.md): full gather before the first yield (`results=[]`, `results.append(record[2])` in the leaf branch, `yield from results` after the walk):
Command: `… python -I -B -m pytest -p no:cacheprovider -q -s -n 0 "tests/test_alp_a2l_occupancy.py::test_r_a2l_def_159_2_aliases_are_not_gathered_or_sorted" < /dev/null`
Result RED: `AssertionError: 4003` / `assert 4003 <= ((2 * 11.965784284662087) + 4)`. ✅ (matches worker's RED line)

All applied controls go RED. No control stayed GREEN.

Step 3 PASS.

## Step 4 — Laws

Command: `… python -I -B -m pytest -p no:cacheprovider -q -n 0 -rfE tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null`

Summary: `5 failed, 110 passed, 2 skipped in 439.33s`.

Failed now (all within the allowed-RED list):
- `test_r_tst_002_every_timing_arm_carries_serial_timing` — allowed RED, but see NEW offender note below.
- `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` — allowed RED; offender files identical to base (all under `evidence/full-suite/…`, inherited). No new offender.
- `test_canon_rows_hold_the_obligation_word_once` — allowed RED; offenders are exactly the base three (`R-A2L-DEF.153`, `R-PICKER-CORRECT.004`, `R-PICKER-CORRECT.008`). No new offender.
- `test_at_b83_08_tree_holds_no_assembled_selectors` — allowed RED; 9 offenders identical to base (attach.py:408, b103_refresh:218/282, picker:94/186/197/191/680/747). No new offender.
- `test_no_tracked_file_holds_a_private_token` — allowed RED; offender file set identical to base (`.dev-flow/2026-11-18-a2l-load-performance/…` inc-1 evidence). No new offender.

`test_r_tst_040_041_every_upper_timing_bound_is_reported` was RED at base and now PASSES (improvement, not a new offender).

NEW offender inside an allowed RED (reported for the orchestrator's intent review):
- `test_r_tst_002` now additionally flags `timing arm without serial_timing: tests/test_alp_inc2_a2l_attach.py::test_r034_progress_throughout`. This line did NOT exist at base 25161a00.
- Attribution: NOT introduced by this unit. FA-IDX2T's diff touches only `tests/test_alp_a2l_occupancy.py`; this offender is in `tests/test_alp_inc2_a2l_attach.py`. `git blame` shows the `gap <= timing_bound(1.0)` line (which makes r034 a timing arm) was added by commit `cedb7374 SPEC (unchecked): FA-KEY`, a different unit whose check runs in parallel. FA-IDX2T's own diff adds no timing/skip/sleep lines and introduces zero law offenders.
- Per the strict rule "a new offender inside an allowed RED = MECH-NO-GO", this triggers NO-GO mechanically, but it is attributable to FA-KEY, not FA-IDX2T.

Known hole check: no blank lines remain after `R-A2L-REFRESH.028` / `R-A2L-DEF.155` in this tree (rows flow continuously; FA-REQb fixed the canon visibility). The unit's rows R-A2L-DEF.159/.167/.168 are present and visible in `REQUIREMENTS.md` (lines 1379/1387/1388) and each uses the obligation word once, so they add no canon offender.

Step 4: MECH-NO-GO (sole cause: new offender inside allowed RED, attributable to FA-KEY commit cedb7374, not to this unit).

## Step 5 — Worker claims (5 re-verified)

1. Claim "HEAD bac9f386 verified" — TRUE. `git rev-parse HEAD` → `bac9f386048d3be12289c118118afc8c2990c0d4`.
2. Claim "only tests/test_alp_a2l_occupancy.py edited, 195 insertions, 15 deletions" — TRUE. `git diff --stat` → `1 file changed, 195 insertions(+), 15 deletions(-)`.
3. Claim "monotone mean 25.0" — TRUE. Run: `R-A2L-DEF.167 monotone: 200000 visits / 8000 addressed definitions = 25.0 mean visits`, passed.
4. Claim "shuffled RED mean 5800.8" — TRUE. Run: `R-A2L-DEF.167 shuffled: 46406794 visits / 8000 = 5800.8 mean visits`, `assert 5800.84925 <= 67.863…` failed.
5. Claim "168 dense RED 7,000,000 checks" — TRUE. Run: `E AssertionError: dense: 7000000 candidate-overlap checks exceed the bound 200000` / `assert 7000000 <= (25 * 8000)`.
6. (bonus) Claim "159_2 re-pin GREEN now" — TRUE. `pytest …::test_r_a2l_def_159_2_aliases_are_not_gathered_or_sorted` → `1 passed`.

All checked claims TRUE.

## Step 6 — Save the diff

`cp ~/work/zq-fa/chk-FA-IDX2T.diff ~/work/zq-fa/FA-IDX2T/CHECK.diff` (268 lines, same as step 1's diff). ✅

## Verdict

Steps 1, 2, 3, 5, 6 pass. Step 4 trips the strict rule (a new offender inside an allowed RED) — but that offender (`test_r_tst_002` → `test_r034_progress_throughout`) is introduced by FA-KEY (commit cedb7374), not by this unit's diff, and this unit's own diff introduces zero law offenders. Mechanical verdict per the brief's rule:

CHECK_DONE FA-IDX2T MECH-NO-GO

## Orchestrator intent review (Opus, relevo-22)
GO. Tests only, as designed (R5-F2, R5-F8, operator D3). Row 1: `_CountingSeq` counts reads of `min_first` (one internal-node read = one visit, E4R definition) and delegates the rest; `counting_build` wraps the index the product builds, so the counter sees the product's real traversal. Row 2: one builder, three layouts, 8,000 disjoint objects, census asserted. Rows 3–4 are RED for the stated reason (counts, not import errors): shuffled 5,800.8 and dense 1,029.8 mean visits against 67.9; dense 7,000,000 overlap checks against 200,000; monotone 25.0 GREEN. Convention pinned by the orchestrator: the mean divides by the **addressed** definitions (the ones that run an occupancy query); AXIS_PTS names resolve to `A2L-DEF-NAME` refusals and run no query, which also explains 7.0 M vs the diagnosis's 7.5 M (the diagnosis counted AXIS_PTS-vs-AXIS_PTS queries) — conclusion unchanged. Row 5: the token blacklist is replaced, for `.159_2`, by a behavioural probe (one `next()` over a directly built index: ≤ 2·log2(4000)+4 visits and the minimum-position alias first); `_assert_no_gather_sort` stays because `.159_1`/`.159_3` still use it. Controls: pruning removed → monotone RED (8,003.0); a full gather before the first yield → 4,003 visits RED.

## Orchestrator ruling on the MECH-NO-GO (Opus, relevo-22)
Override to GO (DF-02). The unit ran on the speculative tree bac9f386 (ca5ed3bc + FA-KEY + FA-IDX1, before FA-2), so the six laws still showed FA-KEY's `test_r034_progress_throughout` offender inside `test_r_tst_002`; the checker attributes it to FA-KEY and finds zero offenders from this unit's diff. FA-2 (43c5a857) removed that offender before this integration.
