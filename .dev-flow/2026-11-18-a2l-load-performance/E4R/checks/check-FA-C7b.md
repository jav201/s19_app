# CHECK — FA-C7b (mechanical)

- Unit: FA-C7b
- Tree: ~/work/zq-fa/FA-C7b/repo
- HEAD sha: fd8e744c0ca689eb8d676b78030fb44a11e55e41
- Start time: 2026-11-19 20:12:31 CST
- Base clone: ~/work/zq-fa/base-alp (= 25161a00)
- Base transcript: ~/work/zq-fa/briefs/laws-base-alp.txt

## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fa/FA-C7b/repo ~/work/zq-fa/chk-FA-C7b`; in the copy `git diff > ../chk-FA-C7b.diff`.

- Files changed (`git diff --name-only`):
  - `tests/test_alp_inc2_a2l_attach.py`
  - `tests/test_b103_picker_model.py`
  - `tests/test_tui_patch_history_strip.py`
  → all 3 within the brief's "Files you may edit". OK.
- CR count (`tr -cd '\r' < ../chk-FA-C7b.diff | wc -c`): **0**. OK.
- Added `skip`/`skipif`/`xfail`/`sleep(`/`flaky`/`rerun` lines (added lines only): **0** (grep, case-insensitive). OK.
- `def test_` names removed and not re-added: **none** (no `^-def test_` lines). OK.
- `git diff --stat`: 3 files changed, 95 insertions(+), 46 deletions(-).

## Step 2 — GREEN vs base (run the brief's node set on the copy)

Env: the CHK one-liner (timeout 1200), from the copy root `~/work/zq-fa/chk-FA-C7b`.

### `-n 0` set (3 changed files' nodes + 2 probes)
Command: `... pytest -q -n 0 tests/test_tui_patch_history_strip.py::test_tc081_2_strip tests/test_b103_picker_model.py::test_r017_2_hostile_unit_is_replaced_literally tests/test_alp_inc2_a2l_attach.py::test_r037_picker_snapshot_reuse tests/test_b103_picker_model.py::test_r018_2_changed_generation_batches_once_per_picker tests/test_b103_picker_model.py::test_r018_4_live_reload_refreshes_both_without_reentry tests/test_tui_patch_card.py::test_tc080_2_c7_purity_probe tests/test_tui_patch_checks_strip.py::test_tc078_2_aggregates_param`

Summary: **`11 passed in 122.48s`** (exit 0). All changed nodes + the two probes GREEN.

### `-n 4 -m "not serial_timing and not slow"` set (3 files + bulk-add + picker-editor)
Command: `... pytest -q -n 4 -m "not serial_timing and not slow" tests/test_tui_patch_history_strip.py tests/test_b103_picker_model.py tests/test_alp_inc2_a2l_attach.py tests/test_b102_bulk_add.py tests/test_b103_picker_editor.py`

Summary: **`2 failed, 125 passed, 1 skipped in 363.01s`** (exit 1).

The 2 failures:
- `tests/test_alp_inc2_a2l_attach.py::test_r_a2l_refresh_052_install_runs_no_full_collection`
- `tests/test_alp_inc2_a2l_attach.py::test_r038_install_exception_reenables_gc`

### Comparison with the base transcript
The base transcript `~/work/zq-fa/briefs/laws-base-alp.txt` covers only the 6 law files (step 4 scope). The brief's node set (3 changed files + `test_b102_bulk_add.py` + `test_b103_picker_editor.py` + 2 probes) has **no overlap** with those 6 law files. Therefore:
- base-RED nodes in the brief's node set: **none** (the 6 base-RED law nodes are handled in step 4).
- nodes that passed at base and are in the brief's node set: **none** (no overlap).

### The 2 GC failures are not caused by FA-C7b
- The unit's diff is test-only (3 files) and does not mention either GC test (`git diff | grep` returns nothing).
- Re-running both GC nodes in a copy with the diff reverted to clean HEAD (3 test files restored via `git show HEAD:`) gives the same result: **`2 failed in 51.85s`** — i.e. they fail at HEAD `fd8e744c` independently of the FA-C7b diff.
- `git log 25161a00..HEAD -- s19_app/tui/app/file_load.py` shows the GC-relevant product change came from commit `1dd52089` (FA-D10, "one shared bulk describe for both pickers"); `test_r038_install_exception_reenables_gc` PASSES at base `25161a00` (`1 passed in 39.20s`) and `test_r_a2l_refresh_052_install_runs_no_full_collection` did not exist at base. Both are pre-existing at HEAD, out of FA-C7b's scope (its brief lists rows 1–4 only).

## Step 3 — Negative controls are real (re-applied in `~/work/zq-fa/chk-FA-C7b-nc`)

Copy = `cp -a ~/work/zq-fa/chk-FA-C7b ~/work/zq-fa/chk-FA-C7b-nc` (keeps the unit's test diff; product files restored to HEAD via `git show HEAD:` between controls). Re-applied 3 of the 4 controls (cap = 3).

### Row 1 — rename `_history_strip_text` (REPORT's isolated form: def + call site renamed)
Mutation: `sed -i 's/_history_strip_text/_history_strip_text_RENAMED/g' s19_app/tui/screens_directionb/patch_editor/actions.py`
Node: `tests/test_tui_patch_history_strip.py::test_tc081_2_strip`
RED line: `AssertionError: the strip's members must be provided by a class inside the patch_editor package (found through the MRO); missing {'_history_strip_text'}` (tests/test_tui_patch_history_strip.py:575)
Summary: `1 failed in 2.51s` — **RED**. ✓

### Row 2 — panel ignores `a2l_data` (else branch)
Mutation: `a2l_picker.py:62` else branch `a2l_data=a2l_data` → `a2l_data=None`
Node: `tests/test_b103_picker_model.py::test_r017_2_hostile_unit_is_replaced_literally`
RED line: `AssertionError: assert '' == 'HOSTILE_UNIT'` (tests/test_b103_picker_model.py:564)
Summary: `1 failed in 5.02s` — **RED**. ✓

### Row 4 — restore the second `describe_definitions` call
Mutation: `file_load.py` after line 1102 add `describe_definitions(names, a2l_data)` (second call)
Nodes: `test_r018_2_changed_generation_batches_once_per_picker`, `test_r018_4_live_reload_refreshes_both_without_reentry`
RED line (both): `AssertionError: assert 2 == 1`
Summary: `2 failed in 10.32s` — **RED** for both. ✓

Row 3 control not re-run (CHK cap of 3); REPORT.md documents its two RED lines (mismatch arm `2 == 0` at :2187, unmounted arm at :2281). No control stayed GREEN.

## Step 4 — Laws (serial `-n 0`, 6 files, on the copy)

Command: `... pytest -q -n 0 -rfE --tb=line tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py`

Summary: **`5 failed, 110 passed, 2 skipped in 410.61s`** (exit 1).

Failing (all in the allowed-RED list at base 25161a00):
1. `test_suite_hygiene.py::test_r_tst_002_every_timing_arm_carries_serial_timing` — allowed
2. `test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` — allowed
3. `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` — allowed; offenders = `R-A2L-DEF.153`, `R-PICKER-CORRECT.004`, `R-PICKER-CORRECT.008` (identical to base offenders)
4. `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` — allowed; 8 offenders, same code as base (the two `test_b103_picker_model.py` offenders are the same IfExp expressions, renumbered :680→:692 and :747→:759 by the unit's docstring additions)
5. `test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token` — allowed; same `.dev-flow/...` offender list as base

`test_r_tst_040_041_every_upper_timing_bound_is_reported` (base-RED) is now **GREEN** — an allowed-RED fixed upstream (FA-2, commit `43c5a857`).

### No new offender introduced by FA-C7b
To isolate FA-C7b's contribution, I ran the same 6 law files on a copy with the FA-C7b diff reverted to clean HEAD (`~/work/zq-fa/chk-FA-C7b-reverted`, 3 test files restored via `git show HEAD:`): result **`5 failed, 110 passed, 2 skipped in 425.15s`** — the exact same 5 failures with the same offender sets. The only offender that differs from base is `test_r_tst_002`'s `test_alp_inc2_a2l_attach.py::test_r_a2l_refresh_052_case06_no_mainthread_gc_pause`, added by commit `fd8e744c` (FA-GC2T, "SPEC (unchecked)"), not by FA-C7b's diff. FA-C7b's diff introduces **zero** new law offenders.

### Known hole check
The CHK-BRIEF notes blank lines after R-A2L-REFRESH.028 / R-A2L-DEF.155 can hide rows from the canon laws. At this tree that hole is absent: `parse_canon` sees all **3355** rows (0 hidden), and the two rows FA-C7b's docstrings cite are both visible with exactly one `shall`:
- `R-A2L-REFRESH.037` → seen_by_parser=True, shall_count=1
- `R-PICKER-CORRECT.018` → seen_by_parser=True, shall_count=1

No other RED, no new offender inside an allowed RED. **Step 4 PASS.**

## Step 5 — Worker claims (5 picked from REPORT.md, re-verified)

1. **Claim: HEAD sha `fd8e744c0ca689eb8d676b78030fb44a11e55e41`, diff stat "3 files changed, 95 insertions(+), 46 deletions(-)".** → **TRUE.** `git rev-parse HEAD` = `fd8e744c0ca689eb8d676b78030fb44a11e55e41`; `git diff --stat` = 3 files, 95 insertions(+), 46 deletions(-) (all 3 files in the brief's allowed list).

2. **Claim: final `-n 0` run of all changed nodes + 2 probes = `11 passed`** (11 = r037×5 + tc081_2 + r017_2 + r018_2 + r018_4 + tc080_2 + tc078_2). → **TRUE.** My `-n 0` run printed `11 passed in 122.48s`; r037 carries 5 parametrize arms (`initial`, `changed-generation`, `filter-page-noop`, `adapter-mismatch`, `headless-unmounted`), so 5+1+1+1+1+1+1 = 11. (Wall time differs 122 vs 120 s — shared host, indicative only.)

3. **Claim: `-n 4 -m "not serial_timing and not slow"` set = `2 failed, 125 passed, 1 skipped`.** → **TRUE.** My run printed exactly `2 failed, 125 passed, 1 skipped in 363.01s` (the 2 failures = the GC tests `test_r_a2l_refresh_052_install_runs_no_full_collection`, `test_r038_install_exception_reenables_gc`).

4. **Claim (row 2 negative control RED line): `assert name.plain == "HOSTILE_UNIT"` → `AssertionError: assert '' == 'HOSTILE_UNIT'` (tests/test_b103_picker_model.py:564).** → **TRUE.** Re-applying the mutation (`a2l_picker.py` else branch `a2l_data=a2l_data` → `a2l_data=None`) gave exactly `E   AssertionError: assert '' == 'HOSTILE_UNIT'` at `tests/test_b103_picker_model.py:564`.

5. **Claim (deviation 2): the 2 GC failures "reproduce identically with the FA-C7b diff reverted (clean HEAD working tree in a scratch copy)".** → **TRUE.** In `~/work/zq-fa/chk-FA-C7b-reverted` (3 test files restored to HEAD) both GC nodes give `2 failed in 51.85s`; the unit's diff never touches those tests (`git diff | grep` = 0 hits) nor `s19_app/tui/app/file_load.py`.

(Also consistent: REPORT's `git diff | grep -c $'\r'` = 0 — my CR count was 0, and row 1 / row 4 RED lines matched exactly — see Step 3.)

## Verdict

Steps 1–5 all pass for FA-C7b's own diff:
1. Diff hygiene: 3 allowed files, 0 CR, 0 skip/xfail/sleep, no removed test names. PASS.
2. Node set: `-n 0` = 11 passed (all changed nodes + 2 probes GREEN). `-n 4` = 2 failed / 125 passed / 1 skipped; the 2 failures are GC tests that fail identically at clean HEAD and are not in the base transcript (no overlap). PASS for FA-C7b.
3. Negative controls (3 of 4 re-applied): all RED, exact match to REPORT. PASS.
4. Laws: 5 failures, all in the allowed-RED list; clean-HEAD run shows identical failures → FA-C7b adds zero new offenders; no other RED. PASS.
5. Worker claims: all 5 re-verified TRUE. PASS.

Note for the orchestrator (not a FA-C7b defect): `test_r038_install_exception_reenables_gc` PASSES at base `25161a00` and FAILS at `fd8e744c`; both GC failures trace to commit `1dd52089` (FA-D10, the shared bulk describe) in `s19_app/tui/app/file_load.py`, and `test_r_a2l_refresh_052_case06_no_mainthread_gc_pause` (an FA-GC2T addition, commit `fd8e744c`) carries a `serial_timing` marker that the hygiene law flags. These are batch-level product/spec issues, untouched by FA-C7b's test-only diff.

CHECK_DONE FA-C7b MECH-GO

## Orchestrator intent review (Opus, relevo-23)
GO. The worker timed out (2700 s) with a complete 3-file test-only diff and no report; the diff was frozen and a report-only session (MD-06) wrote the evidence without editing the tree (diff md5 unchanged). Every row re-pins a test to a design already ruled, and each keeps its intent (FB-common rule 5; TR-01 allows the count change because operator D10 changed the requirement reading).
- Row 1: `test_tc081_2` §2.4-10 counts a strip member only when a class inside the `patch_editor` package defines it (MRO walk), so the batch-modular mixin split no longer fails it while a Textual-inherited name still cannot satisfy it; the `dir(Widget)` collision check stays. Control: definition renamed (call site kept) → RED on the missing member.
- Row 2: the Patch arm of `test_r017_2` threads `a2l_data=app.current_a2l_data` as `app/patch.py` does since C-7; the Check arm stays on its own seam. Control: panel ignores `a2l_data` → RED (`'' == 'HOSTILE_UNIT'`).
- Row 3 (ruling R3): the Patch half of the `.037` adapter arms drives the app caller `_prefill_patch_editor` against the same constructed mismatch maps (stale source, stale signature), re-seeding the map for each half so the two halves are checked independently; the no-op arm and the unmounted arm also go through the caller. Mapping identity, invalidate-before-fallback, describe counts and unmounted survival are still asserted. Controls: skip the invalidation in `patch.py` → mismatch arm RED (`2 == 0`); invalidate on the unmounted branch → survival arm RED.
- Row 4: `test_r018_2`/`test_r018_4` count one shared describe (`== 1`, operator D10); `test_r018_3` untouched. Control: second describe restored → `2 == 1` RED on both.
- Risk (minor, recorded): the unmounted arm forces Textual's private `_is_mounted` to False on the app's real panel (restored in `finally`), because the caller branches on `panel.is_mounted`. A Textual upgrade that renames the attribute turns that arm RED loudly, not silently GREEN.
- Not this unit's: the two GC REDs in the report's `-n 4` run (`test_r038…`, `.052` spy) are the base fd8e744c state; r038 is GREEN since FA-GC2 row 4 (74f23842) and `.052` is FA-GC2R's.
- Orchestrator note on the checker's attribution: `test_r038_install_exception_reenables_gc` passed at 25161a00 because it could not fail then (Textual re-raised over its AssertionError); FA-GC2T (in fd8e744c) made it falsifiable and RED by design, and FA-GC2 row 4 (74f23842) turned it GREEN. FA-D10 is not the cause. The `.052` spy RED is FA-GC2R's (operator D-GC = A).
