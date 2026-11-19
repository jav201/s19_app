# Check G2 (unit G2b tree = G2 product change + G2b re-pins) — verdict: GO

Base = `~/work/zq-fb/base` (3afebf90). Copies deleted after the run. Diff: `frontB\diffs\G2.diff` (LF, 4 files). Host load during runs: 5-12 (never below 4; see (a)).

| # | Check | Evidence |
|---|---|---|
| 1 | Diff hygiene | chkdiff: files=4 (`s19_app/tui/app/patch.py`, `.../patch_editor/a2l_picker.py`, `tests/test_b103_picker_model.py`, `tests/test_tui_patch_history_strip.py`) = union of G2+G2b allowed sets; `checks_diff.py` untouched (correctly: its `panel` is the Check editor); CR=0; skipadd=0; no test def removed; no sleep/skip/xfail added. |
| 2 | Intent | Product: `a2l_data` keyword param replaces the `self.app` read; the app caller threads `a2l_data=self.current_a2l_data`; bulk-add: picker's own `BulkAddRequested` bubbles to a new app handler (`on_a2l_parameter_picker_bulk_add_requested`, `event.stop()`, pushes `BulkParameterAddScreen(panel._a2l_picker)` with `panel._on_bulk_add_closed`); smaller than a new message, Check editor stops its own copy at its panel. Tests: strip arm re-pinned vault-neutrally to MRO members restricted to `s19_app.tui.screens_directionb.patch_editor` classes (Textual-inherited members still excluded; the `dir(Widget)` collision assertion kept) = same meaning, not loosened; r017_2 patch arm passes `a2l_data=app.current_a2l_data`, check arm unchanged, all assertions kept. |
| 3 | GREEN vs base | Base (`chk-G2b-base`): `test_tc080_2_c7_purity_probe` RED ("found 2 access(es)"), `test_tc081_2_strip` RED (544, C-7), `test_tc078_2_aggregates_param` RED (582, "2 access(es) at lines [24, 102]"), `test_r017_2` GREEN. Copy: all 4 GREEN (`4 passed`). Both whole files `-n 4 -m "not serial_timing"`: copy `50 passed, 1 skipped`; base `1 failed, 49 passed, 1 skipped` (only test_tc081_2_strip). The skip is the same pre-existing git/main arm on both. Bulk set `test_b102_bulk_add.py test_b103_picker_editor.py test_import_census.py` `-n 4`: `47 passed`. |
| 4 | Negative controls (scratch copy) | (1) rename `_history_strip_text` in actions.py: `test_tc081_2_strip` RED at :575 "missing {'_history_strip_text'}". (2) `set_parameters(..., a2l_data=None)` ignoring the arg: `test_r017_2` RED at :548. (3) G2: re-add `getattr(self.app, "current_a2l_data", None)` in `set_a2l_parameters`: probe RED "reaches self.app at 1 site(s)". |
| 5 | Laws | Six law files `-n 0` on copy: `3 failed, 112 passed, 2 skipped` = exactly the base set (`test_r_tst_070_2`, canon two-shall, address census); census offending sites are the same 8 as base (picker_model lines shifted +7 by the re-pin; no new site). No other law RED. |
| 6 | Worker claims (5) | G2: probe RED at HEAD with 2 accesses - TRUE; probe GREEN after - TRUE; `test_r017_2` passes at base, fails only after the change - TRUE (base 49 passed; NC2 shows the `'' == 'HOSTILE_UNIT'` mode); bulk+editor `45 passed` + census `2 passed` = my 47 - TRUE. G2b: `50 passed, 1 skipped` - TRUE; row-1 mutation by rename and the reason for it (deleting crashes `on_mount`) - plausible, my rename control reproduced RED. No false claim. Not verified: the "-k selects 0 tests" note. |

## Extra (a): test_r019_1 "flaky" label — not accepted
Serial `-n 0`, alternating, on the copy vs base, load 5.2-5.5 (host never fell below 4 in a 20 min wait; other agents running):
- copy: 1.215, 1.241, 1.231 s, median **1.231 s**, 3/3 PASS.
- base: 1.249, 1.223, 1.233 s, median **1.233 s**, 3/3 PASS.
Spread < 3%, bound 2.0 s. G2's 1.98/2.58/2.14 s values were taken under `-n 4` / loads above 10: the test is load-sensitive (timing bound), not flaky. G2 does not affect it: it drives the Check editor and `A2LParameterPicker.set_parameters` directly with `a2l_data=`, and no touched file is on that path (copy median = base median). Recommendation: it stays a `serial_timing` node measured at low load by the orchestrator.

## Extra (b): bulk-add flow
`tests/test_b103_picker_editor.py` presses `#patch_param_bulk_button` on the Patch picker (line 335) and runs the patch bulk counts/summaries/close tests (`test_r013_r014_patch_bulk_counts_and_exact_summaries`, `test_r015_patch_bulk_close_preserves_ledger_and_document`): all pass on the copy (47 passed set). The user-visible flow works through the new app handler.

## Limits
Load stayed above 4; timing medians were taken at ~5.3. Full suite not run (not asked). Notes: the G2 REPORT's `-k "c7 or purity"` selects 0 tests; the C-7 arms live in `test_tc078_2_aggregates_param` / `test_tc081_2_strip` (run explicitly here).
