# CHECK G9b

Unit: G9b
Tree path: ~/work/zq-fb/G9b/repo
HEAD sha: 2a8ab75f2fcff5d939eba00372ecf11ea4dda886
Start time: Thu Nov 19 03:35:08 PM CST 2026


## Step 1 — Diff hygiene

Command: `cp -a ~/work/zq-fb/G9b/repo ~/work/zq-fb/chk-G9b`; in the copy `git diff > ../chk-G9b.diff`.

- Files changed: `tests/test_b100_project_check.py`, `tests/test_tui_report_filter_surface.py`.
  - `tests/test_tui_report_filter_surface.py` = the only file G9b was allowed to edit (brief). OK.
  - `tests/test_b100_project_check.py` = G9's pre-existing row-2 edit, kept untouched per the brief ("Keep that edit; do not touch that file"). OK (inherited, not authored by G9b).
- CR count (`tr -cd '\r' < chk-G9b.diff | wc -c`): **0**.
- Added `skip`/`skipif`/`xfail`/`sleep(` lines: **NONE**.
- `def test_` names removed and not re-added: **NONE**.

Step 1 verdict: PASS.

## Step 2 — GREEN vs base

Base transcript: `~/work/zq-fb/baseline/G9.txt` (base 3afebf90).

Node set run on the copy (`-n 0`):

```
=== node run 1 ===  test_at_056e_a2b_diff_report_byte_identical_despite_selection  1 passed in 17.11s
=== node run 2 ===  test_at_056e_a2b_diff_report_byte_identical_despite_selection  1 passed in 17.00s
=== node run 3 ===  test_at_056e_a2b_diff_report_byte_identical_despite_selection  1 passed in 17.12s
=== whole file ===  tests/test_tui_report_filter_surface.py                        14 passed in 147.36s
=== b100 node ===   tests/test_b100_project_check.py::test_tc_b100_61_files_at_the_cap_all_missing_are_bounded  1 passed in 4.81s
```

- Base-RED nodes and their result now:
  - `test_at_056e_a2b_diff_report_byte_identical_despite_selection` → **GREEN** (3/3, and in whole-file 14 passed).
- Nodes that passed at base and fail now: **NONE** (`test_tc_b100_61_files_at_the_cap_all_missing_are_bounded` still GREEN).

Step 2 verdict: PASS.

## Step 3 — Negative controls are real

Re-applied the worker's two REPORT.md mutations in copy `~/work/zq-fb/chk-G9b-nc`.

NC1 (`s19_app/tui/services/diff_report_service.py`, append `lines.append("Report filter applied")` before the markdown write):
```
$ <node> < /dev/null
>           assert "Report filter applied" not in selected[name].decode("utf-8")
E           AssertionError: assert 'Report filter applied' not in '# Diff repo...lter applied'
tests/test_tui_report_filter_surface.py:807: AssertionError
1 failed in 17.09s
```
RED — matches the worker's reported RED line.

NC2 (delete the two variant-select-driving lines from the test):
```
>           assert not status.startswith("Compare refused"), (
                "AT-056e: the compare must not be refused — "
                f"#diff_status read {status!r}"
            )
E           AssertionError: AT-056e: the compare must not be refused — #diff_status read 'Compare refused: both sides are the same file — the B path was not updated (clipboard paste failed?)'
tests/test_tui_report_filter_surface.py:771: AssertionError
1 failed in 5.59s
```
RED — matches the worker's reported RED message (line number shifted because the control deletes lines).

Step 3 verdict: PASS.

## Step 4 — Laws (serial, -n 0)

Command (6 law files, one line, from the copy root):
```
S=$HOME/work/zq-fb/chk-G9b-state; mkdir -p $S/home/<runner-home> $S/tmp $S/x; timeout 1200 env -i PATH=/usr/bin:/bin HOME=$S/home/<runner-home> XDG_CONFIG_HOME=$S/x/config XDG_CACHE_HOME=$S/x/cache XDG_DATA_HOME=$S/x/data TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 LANG=C.UTF-8 ~/miniconda3/envs/s19ci/bin/python -I -B -m pytest -p no:cacheprovider -q -n 0 tests/test_suite_hygiene.py tests/test_requirements_canon.py tests/test_id_registry.py tests/test_address_census.py tests/test_import_census.py tests/test_no_private_tokens.py < /dev/null
```

Result summary: `116 passed, 2 skipped in 405.03s` (exit 0).

Base RED (from `~/work/zq-fb/baseline/laws.txt`) and their result now:
- `test_r_tst_070_2_committed_evidence_has_no_home_paths_or_lan_addresses` → GREEN (0 failures now).
- `test_canon_rows_hold_the_obligation_word_once` (canon two-shall row test) → GREEN.
- `test_at_b83_08_tree_holds_no_assembled_selectors` → GREEN.

Any other RED: **NONE**.

Step 4 verdict: PASS.

## Step 5 — Worker claims (5 picked)

1. pi.log: "Node ran 3/3 GREEN (15.90s / 16.23s / 16.05s, -n 0)". → **TRUE**. Re-ran 3x, 3/3 GREEN (17.11s / 17.00s / 17.12s; wall-clock differs slightly with load, GREEN result confirmed).
2. pi.log: "Whole `tests/test_tui_report_filter_surface.py`: 14 passed". → **TRUE**. Re-ran: `14 passed in 147.36s`.
3. pi.log: "`test_b100_project_check.py::test_tc_b100_61_files_at_the_cap_all_missing_are_bounded`: 1 passed". → **TRUE**. Re-ran: `1 passed in 4.81s`.
4. REPORT.md NC1: append `Report filter applied` in `diff_report_service.py` → RED on `assert "Report filter applied" not in selected[name].decode("utf-8")`. → **TRUE**. Reproduced exactly (`AssertionError: assert 'Report filter applied' not in '# Diff repo...lter applied'`, line 807).
5. REPORT.md NC2: delete the two select-driving lines → RED on `assert not status.startswith("Compare refused")`. → **TRUE**. Reproduced exactly (`AssertionError: AT-056e: the compare must not be refused — #diff_status read 'Compare refused: both sides are the same file — the B path was not updated (clipboard paste failed?)'`, line 771).

Supporting (already verified in steps 1–3): diff = 2 files only, CR count 0, no added skip/skipif/xfail/sleep, no removed `def test_`; HEAD still `2a8ab75f2fcff5d939eba00372ecf11ea4dda886`, `git stash list` empty, import `AbDiffPanel` present (line 74), required docstring line present (line 737).

Step 5 verdict: PASS (5/5 TRUE).

## Step 6 — Save the diff

`CHECK.diff` saved as a copy of step 1's diff (`~/work/zq-fb/G9b/CHECK.diff`).

CHECK_DONE G9b MECH-GO

## Orchestrator intent review (relevo-20)
GO. Row 2 (TC-B100-61): the race reproduced only under load (4/10 PASS before, 10/10 after the bounded wait on the deferred `end_busy` line; serial 10/10 both ways); the 60 s bound is stated in the test. Row 1 (AT-056e): the test, not the product, was wrong — R-CMP-006.2 starts both variant selects on the first variant and the BUG B7 same-file refusal is approved, so the typed paths never reached the compare (vacuous PASS before B7). The test now drives both selects to the external-path entry, asserts the compare is not refused, and waits for the report worker (unbounded `wait_for_complete`, bounded by the node timeout: MINOR). Worker note: G9 undid one test edit with `git checkout --` (rule break; net tree correct).
