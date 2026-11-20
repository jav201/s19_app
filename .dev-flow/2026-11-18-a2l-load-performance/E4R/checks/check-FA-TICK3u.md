# CHECK — FA-TICK3u (orchestrator-scripted mechanical check; the orchestrator did not write this unit)

- unit: FA-TICK3u; worker DeepSeek v4-pro (medium), PI_EXIT=0 in ~20 min, per-row REPORT (`FA-TICK3u` REPORT copy in the orchestrator's review folder)
- tree: fresh clone of `alp-e4r` e53631df + the integration diff (= the worker diff, md5 b924dc5f), host `<host>` (rtx), HT-02 environment
- script: `tools26/chk_tick3u.sh` + `chk_tick3u_mut.py` (orchestrator tools, outside the repo), the CHK-ds-fa-rtx steps; no model judgement in the run
- the product hunks are compared line by line with the FA-TICK3 scratch fix that was measured (`product-hunks-equal-scratch=yes`)

## Transcript
```
start 04:54:27 load 0.84 1.38 1.28
HEAD e53631df diff-md5 b924dc5f file ~/work/zq-fa/chk3u/s19_app/__init__.py
## step1
s19_app/tui/app/issues_checks.py
s19_app/validation/engine.py
tests/test_alp_a2l_occupancy.py
 3 files changed, 200 insertions(+), 2 deletions(-)
CR=0 added-skip/xfail/sleep=0
removed-tests=0
product-hunks-equal-scratch=yes
## step2 green
unit 3 passed, 25 deselected in 0.40s
reg rc=1 4 failed, 350 passed, 1 skipped, 2 xfailed in 108.40s (0:01:48)
FAILED tests/test_synth_release_case.py::test_a2l_issues_reported
FAILED tests/test_synth_release_case.py::test_a2l_zero_issues
FAILED tests/test_synth_release_case.py::test_addresses_inside_image
FAILED tests/test_tui_app.py::test_load_selected_file_attaches_mac_to_loaded_binary
9 passed, 58 deselected in 152.31s (0:02:32)
## base re-run of the failing nodes (e53631df)
FAILED tests/test_tui_app.py::test_load_selected_file_attaches_mac_to_loaded_binary
FAILED tests/test_synth_release_case.py::test_a2l_zero_issues
FAILED tests/test_synth_release_case.py::test_a2l_issues_reported
FAILED tests/test_synth_release_case.py::test_addresses_inside_image
4 failed in 2.66s
## step3 controls
control c1 applied
~/work/zq-fa/chk3u-nc/tests/test_alp_a2l_occupancy.py:798: AssertionError: a slice passed to sorted() held 8292 names, above the bound 4096
1 failed, 27 deselected in 0.23s
control c2 applied
~/work/zq-fa/chk3u-nc/tests/test_alp_a2l_occupancy.py:843: AssertionError: assert ['a2l_only_10...ly_1008', ...] == ['a2l_only_0'...ly_1001', ...]
1 failed, 27 deselected in 0.22s
control c3 applied
~/work/zq-fa/chk3u-nc/tests/test_alp_a2l_occupancy.py:897: AssertionError: _deduplicate_issues returned with its seen set holding 5000 entries
1 failed, 27 deselected in 0.18s
## step4 laws
laws rc=1 4 failed, 113 passed in 410.56s (0:06:50)
FAILED tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
FAILED tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once
FAILED tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
FAILED tests/test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token
E     line 1373 R-A2L-DEF.153: 'shall' appears 2 times
E     line 4248 R-PICKER-CORRECT.004: 'shall' appears 2 times
E     line 4252 R-PICKER-CORRECT.008: 'shall' appears 2 times
end 05:06:36
CHK3U_DONE
```

## Verdict
**MECH-GO.** Step 1 clean (3 files, CR 0, no skip/xfail/sleep, no test removed, product hunks equal to the measured scratch fix). Unit nodes 3 passed. Regression over the nine files that reach `validate_artifact_consistency`, `build_validation_report` or `_deduplicate_issues` (`-m "not serial_timing and not slow"`): 350 passed, 4 failed — the same 4 fail on base e53631df (inherited: synth ×3, `test_load_selected_file_attaches_mac_to_loaded_binary`). Controls c1 (one long sort), c2 (runs chained, not merged), c3 (no key-set release) each RED at the expected assertion. Laws: 4 failed = the inherited base-alp set (070_2, canon obligation word R-A2L-DEF.153 / R-PICKER-CORRECT.004/.008, at_b83_08, no_private_tokens). Timing is decided on the quiet laptop (M2b), not here.

# FA-TICK3u — intent review (orchestrator, Opus 5.5, relevo-26)

Verdict: **GO**.

- Product hunks: exactly `diffs/FA-TICK3-scratch.diff` (the measured FA-TICK3 fix; the scripted check compares the +/- lines).
- Row 1 (`test_r_a2l_refresh_050_validation_sorts_names_in_slices`): a module-global spy on `engine.sorted` records every input length over > 2 × `SORT_SLICE` distinct names in four populations (A2L-only, MAC-only, both equal, both different); fails if any single sort sees more than `SORT_SLICE`. It encodes why: one long C-level sort starved the UI tick. RED under the revert (worker: "a slice passed to sorted() held …").
- Row 2 (`…_validation_issue_order_unchanged`): the expected symbol order is computed in the test from the inputs with one plain `sorted()`, independent of the product helper; coverage equals a plain-iterator run. It is a pin (GREEN on both trees by design); its power is shown by the `chain` mutant (RED).
- Row 3 (`…_dedupe_frees_its_key_set_before_return`): `sys.setprofile` return event on the target code object; `seen` empty; same objects and order as a no-op release run; profiler restored in `finally`. RED under the removal (5000 entries).
- Worker deviation (an `import itertools` for its own row-2 mutant) is scratch-only; the orchestrator's control uses `__import__('itertools')`.
- No new module (TC-607 unchanged); no skip/xfail/sleep; nothing removed.
