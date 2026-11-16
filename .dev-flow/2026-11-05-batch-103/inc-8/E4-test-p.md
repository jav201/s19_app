# Inc 8 E4 — tester `test-p` (group P, panel wiring)

Cases: `02-test-cases-P.md` (48 rows, 10 partial; open gaps below). Tests: `tests/test_b103_inc8_p_layout.py` (25 nodes), `tests/test_b103_inc8_p_ledger.py` (10), `tests/test_b103_inc8_p_wiring.py` (12), drivers `tests/support/b103_inc8_p.py`. No existing test file and no source file edited.

## RED on base `d5d48685` (tests tree, cwd = the base tree)
One run of the three files, `<runner>` load 5.1 at start (`uptime`; not a timing run):

```
/…/zq-e4-8-test-p/tree/s19_app/__init__.py          <- s19_app.__file__ (the base tree, not an editable install)
PASSED tests/test_b103_inc8_p_layout.py::test_r_picker_correct_011_every_picker_id_is_unique_with_both_editors_mounted
PASSED tests/test_b103_inc8_p_ledger.py::test_r_pe_041_the_json_tab_shows_the_schema_token_and_checks_its_run_state
45 failed, 2 passed in 122.52s (0:02:02)
```
- The 2 passes are behaviour that already holds on base and stays (R-PICKER-CORRECT.011/3, R-PE-041/5): regression guards, GREEN on base by design, each with a non-vacuous control (both `patch_param_*` and `check_param_*` families must be non-empty; the Checks subtitle must equal a non-empty run state).
- Behaviour that exists on base and the assertion that fails there: R-PE-041/1–4 `assert '' == '0 entries'` / `'1 entry'` / `'3 entries'` / `'3 entries ●'` (the Inspector tab shows no ledger subtitle); R-TUI-063.3 `['Inspector', …, 'A2L'] == ['Patch script', …]`; R-TUI-063.4 `'patch_pane_inspector' == 'patch_win_script'`; R-TUI-063.6 `'INSPECTOR'/'JSON'/'CHECKS' == 'LANDS IN'`; R-TUI-063.1/4 `#patch_main must leave`; R-PE-DEF.3 `#patch_param_use_row is not inside #patch_pane_inspector`. The other 33 fail on an absent new id (`#patch_sheet_win`, `#patch_filter_row`, `#patch_sheet`, `#patch_sheet_body`, `#patch_tab_script`, `note_staged`) with a named assertion (`need()`), never a bare `NoMatches` except the `#patch_tab_script` chip lookup.
- Mechanics sanity on base (not a RED claim): the drivers, DEFC fixture, `visible_params` (8 names), filter `MASK` (2 names), the 201-name A2L (page 1 = 200, page 2 = `PNAME_0200`), Add/undo + `_refresh_patch_history_view`, and the Parse pasted button all work on base, so the wiring tests fail only for the missing sheet.

## GREEN: `not-run`
The implementers' tree is closed to testers; no GREEN transcript exists. Every test was written against the graph (`graph-inc8.md`), the requirements and `E1-slice.md`, and has never touched Inc 8 code. **Expect to repair tests, not code, first** if GREEN shows a mismatch in: the row-height equation (`panel.content_region.height − Σ other regions`), `StagingSheet.selected_name` (method or property, both handled), the body text in `#patch_sheet_body` (read from the compositor), and the `PNAME` page-2 click on `#patch_param_page_next_button` on the filter row.

## trace_check (repo root, group P ids)
```
trace_check: 20 active requirements match --ids, checks run: CASE, TEST, 0 gap(s)
```
Command: `python -I -B <skill>/trace_check.py --req .dev-flow/2026-11-05-batch-103/inc-8/01-requirements.md --tests tests --ids "R-TUI-063.1" "R-TUI-063.3" "R-TUI-063.4" "R-TUI-063.6" "R-PE-041" "R-PE-DEF.1.1" "R-PE-DEF.1.2" "R-PE-DEF.2" "R-PE-DEF.3" "R-PE-DEF.4" "R-PE-DEF.49" "R-PE-DEF.74" "R-PICKER-CORRECT.011" "R-PICKER-CORRECT.020" "R-PE-034" "R-PE-DEF.10" "R-PE-DEF.11" "R-PE-DEF.18" "R-PE-DEF.60" "R-PE-DEF.62"`. Note: it checks that the ids appear in file and test names, not that a test asserts them.

## Open gaps (one line each)
- R-PE-DEF.62/2 (Remove of a masked pair) and .62/4 (new image, EX-M1): sheet-model and stage semantics, groups S/A.
- R-TUI-064.1 … .3: no Inc 8 requirement row or case; only 80×24 height (R-PE-DEF.74/1) and containment (R-PICKER-CORRECT.020) are asserted, no scroll-reach.
- R-PICKER-CORRECT.020/1 (80×24): vertical reach under panel scroll is not asserted (horizontal containment and non-zero regions only).
- Partials by stand-in: R-PE-DEF.1.1/3, .74/2 (stand-in dock), .1.2/1 (`-bench` set by the test), .60/1–4 and R-PE-034/1 (`note_staged` called directly), .11/3 (payload swapped by assignment) — to be re-run when Inc 9 / Inc 10 / group A land.
- The Enter-to-stage route (A3 → `note_staged`) and the status line belong to group A and the AT; no P test drives it.
- Timing (R-PE-DEF.12) and real Windows Terminal captures (V-1, V-2, V-13) not in scope.

## Findings and proposed interface changes
- No requirement/code disagreement observed (no implementation read). **Proposed (no interface change):** pin `StagingSheet.selected_name` as a method (I-8.4 lists it in S17 but never states property vs method); the tests accept both.
- E1's R-PE-DEF.4 expects `border #91abec` and "rule colour": read from `$accent-calm` and `$rule` in `styles.tcss`, so a retheme moves the oracle with the product.

Scratch on `<runner>` (`~/work/zq-e4-8-test-p/`) is deleted at hand-back.
