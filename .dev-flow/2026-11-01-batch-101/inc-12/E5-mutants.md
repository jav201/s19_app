# Inc 12 — E5 mutant table (Escape closes Reports; dead dialog/action censuses; Check Editor walk)

Batch 2026-11-01-batch-101, increment 12. Executor: E5 unit (single-unit mutant run, DeepSeek).
Base commit: `6f1743c1ad54ff7db89e8fcd4e96266414950f42` (branch `b101-inc12`, head `c6ad230`,
the Inc 12 integrated tree applied onto `origin/main`).

Method: every row's nodes were confirmed GREEN on the unmutated copy first (30 passed over the
28 distinct node ids, `evidence/inc-12/mut-00-green` not kept — see the per-row transcripts). Each
mutant was applied **one at a time** in a fresh copy of the base worktree (`<HOME>/work/s19_i12mut_m<N>`,
`cp -a` of `<HOME>/work/s19_i12mut`), the mutation was verified to have landed (a grep of the row's
marker, plus the `diff -u` of the changed file recorded in the transcript) and `s19_app.__file__`
printed from inside the copy (= the copy), only the row's nodes were run from the copy (cwd = the
copy, `python -m pytest -p no:cacheprovider -q -rf`, single process), and the copy was then deleted.
The green run and all mutants ran on LAN Linux host 2 only (Python 3.11.18); nothing importing
`s19_app` ran on the Windows PC. Transcripts `evidence/inc-12/mut-01.txt` … `mut-17.txt`, redacted
(home → `<HOME>`, account → `<USER>`, host → "LAN Linux host 2", `pytest-of-<name>` →
`pytest-of-<user>`).

Sources: the M1–M17 table in `E4-integration-notes.md`. Files: **R**
`tests/test_b101_reach_and_reports_escape.py`, **W** `tests/test_b101_shown_widgets.py`, **D**
`tests/test_b101_help_legend_docs.py`, **U** `tests/test_window_usage_help.py`; node names drop the
`test_r_` prefix. A mutant that stays GREEN is a finding unless the row says it may survive.

| M | Row | Mutation | Nodes | Result (killed / survived) | Killing node(s) / failure line | Transcript |
|---|---|---|---|---|---|---|
| M1 | R-DLG.14 | `screens.py`: `VariantHelpScreen` + `VARIANT_HELP_TEXT` restored (the base) | R `dlg_14_1` | KILLED | `dlg_14_1` — `dialogs_without_opener == ['VariantHelpScreen']` | `mut-01.txt` |
| M2 | R-SHELL-KEYS.3 neg 1 | `app.py`: `action_view_alt` + `_jump_to_validation_issue` + `_jump_to_validation_issue_object` restored | R `shell_keys_3_1` | KILLED | `shell_keys_3_1` — `actions_without_reach == ['S19TuiApp.action_view_alt']` | `mut-02.txt` |
| M3 | R-SHELL-KEYS.3 neg 2 | `app.py`: `action_view_mac` restored | R `shell_keys_3_1` | KILLED | `shell_keys_3_1` — `actions_without_reach == ['S19TuiApp.action_view_mac']` | `mut-03.txt` |
| M4 | R-SHELL-KEYS.3 neg 3 | new `s19_app/_e5_m4_mutant.py`: unbound `def action_copy(self)` on a plain class `_E5PlainCard` | R `shell_keys_3_1` | KILLED | `shell_keys_3_1` — `actions_without_reach == ['_E5PlainCard.action_copy']` | `mut-04.txt` |
| M5 | R-SHELL-KEYS.3 neg 4 (E3A-R2-1) | `app.py`: `action_a2l_tag_find_next` restored (the base) | R `shell_keys_3_1` | KILLED | `shell_keys_3_1` — `actions_without_reach == ['S19TuiApp.action_a2l_tag_find_next']` | `mut-05.txt` |
| M6 | R-CHKED-058 | `screens_directionb.py` `CheckEditorPanel.compose`: the hidden `Addendum preview` button restored | W `chked_058_1`; TC-B97-08 (census, tab) + TC-B97-61 stay GREEN | KILLED | `chked_058_1` — `never == ['check_preview_toggle_button']`; the 5 B97 nodes stay GREEN (they no longer pin the toggle, I-3) | `mut-06.txt` |
| M7 | R-DLG.2 neg 1 | `screens.py`: the Escape binding removed (the base) | R `dlg_2_1..11`, `dlg_15_1`, `at_i12_1`; U `tc706_seat_census` | KILLED | `dlg_2_1..11` — "did not settle: the Reports dialog closed"; `dlg_15_1`/`at_i12_1` (the second Escape); `tc706_seat_census` — bindings census | `mut-07.txt` |
| M8 | R-DLG.2 neg 2 | `action_close_reports` runs Generate's path (posts `GenerateRequested`, then dismisses) | R `dlg_2_1..10`, `at_i12_1` | KILLED | `dlg_2_1..10` — `app.log_lines` gains `'Report: no manifest … nothing to report.'`; `at_i12_1` stays GREEN (no third file: generation fails gracefully with no manifest/change/check loaded) | `mut-08.txt` |
| M9 | R-DLG.15 neg 1 | the Escape binding made `priority=True` | R `dlg_15_1`, `at_i12_1` | KILLED | `dlg_15_1` — the dialog closes with the list open (`app.screen is screen` fails, stack `['Screen']`) | `mut-09.txt` |
| M10 | R-DLG.15 neg 2 | copy-root `conftest.py`: `SelectOverlay.action_dismiss` applies the highlighted option before dismissing (session-level; the installed toolkit is not edited) | R `dlg_15_1`, `dlg_15_2`, `at_i12_1` | KILLED | `dlg_15_1` — `select.value == 'f1.json'` (Escape applied the highlight) | `mut-10.txt` |
| M11 | R-DOC-GUIDE.1/13 | `ch16-reports.md`: the base row `Open reports/, `?`, Close` · `chips, button` restored | D `doc_guide_1[passage-12]` | KILLED | `doc_guide_1[passage-12]` — stale `'Open reports/, `?`, Close'` | `mut-11.txt` |
| M12 | R-DOC-GUIDE.1/14 | `ch18-flow-execution.md`: the base sentence restored | D `doc_guide_1[passage-13]` | KILLED | `doc_guide_1[passage-13]` — stale ``'`esc` does not close this viewer'`` | `mut-12.txt` |
| M13 | R-DOC-GUIDE.2 (`_FIXED` 13 → 17) | `DOSSIER.md` F-51: the ` · fixed in 1.0.0` mark removed | D `doc_guide_2_1`, `doc_guide_2_2` | KILLED | `doc_guide_2_1` — `unmarked == ['F-51']`; `doc_guide_2_2` — the marked set loses F-51 | `mut-13.txt` |
| M14 | R-DLG.2 (U-2, focus back) | `action_close_reports`: `self.app.screen_stack[0].set_focus(None)` before the dismiss | R `dlg_2_1..11`, `at_i12_1` | KILLED | `dlg_2_1..11`, `at_i12_1` — `(app.focused, app._active_screen_key) == known` fails (the focus is not given back) | `mut-14.txt` |
| M15 | AT-I12-2 | `app.py` `on_issue_row_selected`: no `_update_issues_hex_pane` call | R `at_i12_2` | KILLED | `at_i12_2` — "did not settle: the peek paints the row 00C00FF0; it shows ''" | `mut-15.txt` |
| M16 | AT-I12-3 | `CheckEditorPanel.on_button_pressed`: the tab-chip branch removed | W `at_i12_3`, `chked_058_1` | KILLED | `at_i12_3` — "did not settle: enter on the Addendum chip shows the Addendum pane alone"; `chked_058_1` — its states never settle | `mut-16.txt` |
| M17 | R-DLG.2/12 | `window_help.py` `action_close_window_help` also pops the screen beneath (copy only; outside the slice) | R `dlg_2_12` | KILLED | `dlg_2_12` — `isinstance(app.screen, ReportViewerScreen)` → stack `['Screen']` | `mut-17.txt` |

## Score

- Total mutants run: **17** (no row skipped).
- Killed: **17**.
- Survived: **0**.

Mutation score (killed / total): **17 / 17 = 100%**.

One sub-observation (not a survivor): on **M8** the `at_i12_1` node — which the row's "every
node that counts 2 files" arm predicted would turn RED on a third report file — stayed GREEN,
because the Generate path fails gracefully in these fixtures (no manifest/change/check file is
loaded, so no third file is written). The mutant is still killed, by the 10 `dlg_2_*` nodes whose
`app.log_lines` check catches the posted `Report: no manifest …` status line; the prediction about
which observable turns RED differs from the row, not the verdict.
