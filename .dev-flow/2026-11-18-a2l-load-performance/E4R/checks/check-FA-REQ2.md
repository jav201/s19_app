# check-FA-REQ2 — orchestrator-scripted mechanical check (MD-11) + Opus intent review

Unit FA-REQ2 [deepseek-v4-pro · medium], worker tree = `alp-e4r` 92fac5fe + the unit diff (3 files +25/−23). Host `<host>` (rtx), HT-02 env (`HOME=<runner-home>`), `-n 0`. Script: `chk_req2.sh` (orchestrator). Not a timing decision (HT-08): the case_06 nodes were not run.

## Mechanical result: MECH-GO
```
== head 92fac5fe; diff files: .dev-flow/2026-11-18-a2l-load-performance/E4R/01-requirements.md REQUIREMENTS.md tests/test_alp_inc3_load_responsiveness.py 
== step1 hygiene: CR=0 skips_added=0 files=3
== s19_app.__file__: ~/work/zq-fa/FA-REQ2/repo/s19_app/__init__.py
== canon_eq
diffs=0
== unit file (not slow)
4 passed, 6 deselected in 40.13s
== collect-only all nodes
10 tests collected in 0.29s
== budget_nc (GREEN tree)
[R-A2L-REFRESH.040 x] totals=['50.000', '50.000', '60.000'] median=50.000s bound_median=54.0s bound_run=68.0s
case1_pass_50_50_60: PASS
case2_runbound_50_50_69: AssertionError
case3_medianbound_55_55_60: AssertionError
case4_missingkey_099: KeyError(R-A2L-REFRESH.099)
== power control: copy with .040 back to (80,100) -> case2/case3 must PASS (check would be blind)
1
1
[R-A2L-REFRESH.040 x] totals=['55.000', '55.000', '60.000'] median=55.000s bound_median=80.0s bound_run=100.0s
case3_medianbound_55_55_60: PASS
case4_missingkey_099: KeyError(R-A2L-REFRESH.099)
== six laws
FAILED tests/test_suite_hygiene.py::test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses
FAILED tests/test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once
FAILED tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors
FAILED tests/test_no_private_tokens.py::test_no_tracked_file_holds_a_private_token
4 failed, 113 passed in 418.74s (0:06:58)
CHK_REQ2_DONE

```

- Step 1: 0 CR, 0 skip/xfail added, 3 files (MD-10).
- `canon_eq.py` (worker scratch): the `.040`–`.042` canon sentences equal the E4R sentences, `diffs=0`.
- Unit file `-m "not slow"`: 4 passed; `--collect-only`: 10 node ids, identical before/after (worker `collect_before/after`).
- Negative controls without case_06 (`budget_nc.py`, synthetic runs into `_assert_budget`): 50/50/60 s PASS; 50/50/69 s AssertionError (run bound 68); 55/55/60 s AssertionError (median bound 54); unknown row id KeyError.
- Power control: a copy with `.040` set back to (80, 100) makes the median-bound case PASS, so the controls see the bound change.
- Six laws: 113 passed, 4 failed = the inherited base-alp four (070_2 on inherited evidence, canon obligation word R-A2L-DEF.153 / R-PICKER-CORRECT.004/.008, at_b83_08, no_private_tokens on inherited files). No new failure.

## Worker deviations (ruled)
- Row 1's proof `grep -c "80 s\|100 s"` over the whole rows cannot be 0: the brief itself sets `.041`'s negative control to "Hold the producer 80 s". The worker scoped the grep to the Requirement cells (0) and checked one `shall` per sentence (3). Brief defect; accepted.
- Row 4: `test_suite_hygiene.py` exceeded the worker's `timeout 300` on the shared host; the orchestrator's six-law run above covers it.

## Intent review (Opus, orchestrator): GO
- The three sentences, fit criteria and negative controls carry exactly the D1 verdict values (`.040` 54/68 s hold 73, `.041` 60/75 s hold 80, `.042` 52/65 s hold 70); Story and Change columns untouched; one `shall` each.
- `BUDGET_S` keyed by row id; `_assert_budget` raises on an unknown id (fail loud, no default); both shapes of `.041` share its bound, as the verdict says.
- The D-14 comment and four docstrings now cite D1; the inherited `inc-3/01-requirements.md` is untouched (PP-06).
