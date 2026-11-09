# Inc 12 — E5 coverage audit

Batch 2026-11-01-batch-101, increment 12, design-first flow (`dev-flow-v3-beta`, E5: "someone who did not write the test cases re-checks their `full`/`partial` marks and coverage"). Mode: **validation** (an audit of marks, oracles and results; no test was run). Auditor: the QA reviewer agent, which wrote no case, no node and no run. Worktree `<HOME>/Github/s19_app-b101-inc12`, branch `b101-inc12`, head `c6ad230`. Inputs: `01-requirements.md` (5 active rows), `02-test-cases.md` (22 cases), `E1-slice.md` §5 (existing nodes touched), `E4-integration-notes.md` (int-00 … int-08, I-D1 … I-D10, the mutant table M1 … M17), `E4-tester-g-t1-notes.md`, `E4-tester-g-t2-notes.md`, the transcripts in `../evidence/inc-12/`, `tests/test_b101_reach_and_reports_escape.py` (**R**, G-T1), `tests/test_b101_shown_widgets.py` (**W**, G-T2), the passages and `_FIXED` of `tests/test_b101_help_legend_docs.py` (**D**), every edited existing test (`git diff 6f1743c -- tests`), the fixtures and probes the nodes call (`tests/b97_fixtures.py`, `tests/b97_probes.py`), and the product code they enter (`ReportViewerScreen`, `CheckEditorPanel`, `S19TuiApp.action_show_screen`). `02-test-cases.md` is not edited; the marks below are this audit's proposal for it. Result words here are the flow's evidence states: the record's `verified (linux, int-01)` reads as `executed` by the E4 integrator, passed.

## 1. Verdict

**PASS-WITH-NOTES.** No HIGH or MAJOR finding. Two MINOR findings and six NITs (§7). One MINOR (QA-1) is conditional: if mutant M14 survives the E5 mutant run, it becomes MAJOR and two marks drop to `partial`.

- **Coverage: 22 `full`, 0 `partial`, 0 `gap`.** All 22 nodes the cases name exist (35 node ids collected in int-01's appendix: the 20 new nodes, the 13 passage ids and the two `_FIXED` nodes; none missing, none extra for this increment). Marks changed: 0 of 22.
- **Row thresholds: 5 of 5 met on Linux**, plus the two cited passages of R-DOC-GUIDE.1 and the `_FIXED` extension of R-DOC-GUIDE.2. No row of Inc 12 has an "N/N runs" repeat threshold. Its counts (12/12, 2/2, 1/1) are case counts, and each was met in the single run int-01.
- **Results: every node was executed and passed on the commit's own tree.** I recomputed the tree with git plumbing (§2): it equals int-01 … int-06's staged tree `d1713533…` byte for byte. Executor: the E4 integrator (Opus) on LAN Linux host 2. The base runs (red-01) were made by the testers G-T1 and G-T2 (Sonnet). This audit executed none of them.
- **Negative controls.** The base runs already show 10 of the 17 mutants RED: M1, M2, M3, M5, M6, M7, M11, M12, M13, and M4 through its in-node synthetic mutant (§6). The other seven have no run yet: M8, M9, M10, M14, M15, M16, M17. They are the only failure evidence of the four declared standing guards and of R-DLG.15's own clauses (QA-2). The E5 mutant run is in flight (`steps.log`, E5 start).
- **Windows: `not-run` on every driven case.** This audit cannot discharge it: nothing that imports `s19_app` runs on the Windows PC. The record's "windows: not_run (E5)" needs the orchestrator's ruled state and its reason (QA-8).

## 2. Evidence checks made by this audit

- **The tree is the commit's.** I recomputed it with git plumbing only: a scratch index and a scratch object directory, the repository's objects as alternates, nothing written to the worktree or the repository, and no `s19_app` import. `6f1743c` + `git diff --binary 6f1743c c6ad230 -- s19_app tests docs README.md AT-TC-REGISTRY.jsonl` = **`d171353393e0d3a7…`** (18 files), the tree printed by int-00-grep, int-01, int-02 and int-06. So int-01 … int-06 ran this commit's product, tests, docs and registry. Between the testers' commit `d76c278` and `c6ad230` only `app.py`, `screens.py` (the two I-D1 comments) and `tests/test_id_registry.py` (I-D3) changed. The two new test files are the ones the testers ran on base. The line numbers in red-01's tracebacks (`R:537`, `R:554`, `W:129`, `D:1853`) match the committed files.
- **What ran on the commit's tree.**
  - int-01: the 2 new files and the 7 edited modules. `432 passed, 1 xfailed`: the xfail is TC-065.a in `tests/test_tui_app.py`, a documented carry-over and not a case of Inc 12. No failure, no skip, no deselection.
  - int-02: the QC-BC set (43 files, with `test_b100_focus.py` and `test_b99_export.py`, which E1-slice §5 lists).
  - int-03: the importers.
  - int-04: the law guards.
  - int-05: the serial-timing nodes.

  The 4 failures of int-02 and int-03 are the batch's known ones. They fail with the same text on base (int-07-base) and lie in no file of int-01 or int-04.
- **Per-node results come from whole-file totals.** int-01 is `-q`, with no per-node line. With 0 failed and 0 skipped, every collected node of those 9 files passed, and the appendix collects the 35 node ids on the same tree.
- **Base RED (red-01).**
  - G-T1 reads `20 failed, 194 passed, 1 xfailed`.
    - The two censuses fail on the base's own dead entries: `['VariantHelpScreen']` and the 4 of 83 (`action_a2l_tag_find_next`, `action_view_alt`, `action_view_mac`, `action_view_main`).
    - R-DLG.2/1 … /11 each fail with `did not settle: the Reports dialog closed (…); stack ['Screen', 'ReportViewerScreen']`. R-DLG.15/1 fails at its second Escape and AT-I12-1 at its first.
    - Passages 12 and 13 fail on the stale text, the two `_FIXED` nodes on F-33/34/35/51, and TC-706 on its binding census.
  - G-T2 reads `1 failed, 1 passed`: the walk names `check_preview_toggle_button`.
  - Both transcripts print base `6f1743c1` and an `s19_app.__file__` in the tester's clone.
- **Pinned I-3 grep (S-3), re-run on the commit with `git grep` (text only).** It gives exactly the three BL-I12-1 lines of `s19_app/tui/window_help.py` (`:12`, `:627`, `:661`), as int-00-grep does.
- **trace_check** (`python -I …/dev-flow-v3-beta/trace_check.py --req …/inc-12/01-requirements.md --base 6f1743c --src s19_app`; it reads text and git only): `3 US, 5 active requirements (0 withdrawn), 1 gap`. The gap is `EVID` (no `04-validation.md`), which is expected before the validation record.
- **Toolkit behaviour read, not run.** In a local textual 8.2.8 install (the version of every run), `Screen._on_screen_resume` calls `_update_auto_focus`. When the resumed screen's `focused` is `None`, that function focuses the first focusable widget of `query(AUTO_FOCUS)` (`textual/screen.py:1465-1500`). This bears on QA-1.
- **Product routes read, not run.**
  - `ReportViewerScreen.BINDINGS` holds `Binding("escape", "close_reports", "Close", show=False)` with no `priority`.
  - `action_close_reports` logs and calls `dismiss(None)`. It posts no message.
  - The Check Editor toggle was hidden by `display = False`, which `is_displayed` reads, so the walk's "shown" sees it.
  - Key `5` is `show_screen('issues')` (`app.py:2736`), the Issues rail key AT-I12-2 presses.
  - The three removed aliases called `action_show_screen("workspace" / "a2l" / "mac")` and nothing else.

## 3. Per case

Node names drop the `test_r_` prefix. "(+)" means the node also asserts the shared `_escape_closes` clauses: 2 files in `reports/`, `app.log_lines` equal to before the key, and `(app.focused, app._active_screen_key)` equal to the pair recorded before `t`. "Std guard" means the node passes on base.

| # | Case | Node | Stimulus route ok | Oracle exact | Evidence | Verdict |
|---|---|---|---|---|---|---|
| 1 | R-DLG.14/1 | R `dlg_14_1_every_dialog_has_an_opener` | n/a: an `ast` census of the tree's own `s19_app/**/*.py`, read by path | yes: ≥ 21 (21), `[]`. Synthetic mutants: orphan and dead-only dialogs flagged, live dialog and base-via-child passed. Spells no removed name | int-01; base RED `['VariantHelpScreen']`; int-06 21 / 0 (base 22 / 1) | full · executed (linux, int-01) |
| 2 | R-SHELL-KEYS.3/1 | R `shell_keys_3_1_every_action_has_a_reach` | n/a: census | yes: ≥ 80 (80), `[]`, the six clipboard overrides reached by `toolkit`. Synthetic mutants flag exactly the four dead shapes: chain alias, lone alias, unbound `action_copy`, id-and-comparison only. One positive control per reach arm. Seed list wider than the case's (QA-7) | int-01; base RED the 4 of 83; int-06 80 / 0 (base 83 / 4) | full · int-01 |
| 3 | R-CHKED-058/1 | W `chked_058_1_every_check_editor_widget_is_shown_in_a_state` | yes. The app's A2L loader, then `action_show_screen`. The three tab chips are pressed with `Button.press()`, and each state waits for its pane to be shown alone and its chip marked | yes: the four states, ≥ 45 (51), `#check_addendum_preview` displayed in the Addendum state, never shown `[]`. "Shown" is `display` up to the screen (`visibility` not read, as the fixture states) | int-01; base RED names the toggle; int-06 51 / 0 (base 52 / 1) | full · int-01 |
| 4 | R-DLG.2/1 | R `dlg_2_1_escape_on_the_report_list_closes_reports` | yes. `t` and `escape` through the pilot; the focus on `#report_list` asserted; the reference is Close by `.press()`. Waits on `_closed` | yes, as the case (+), and the same pair after Close. That the focus clause can fail is not shown (QA-1) | int-01; base RED (dialog stays) | full · int-01 (QA-1) |
| 5 | R-DLG.2/2 | R `dlg_2_2_…` | yes. `enter` on the list (waits for `selected_path`); the focus placed by `.focus()` is a precondition | yes: closed, 2 files (+) | int-01; base RED | full · int-01 |
| 6 | R-DLG.2/3 | R `dlg_2_3_…` | yes. `x` typed and asserted, `escape`, `t` | yes: closed; reopened box `""` (+) | int-01; base RED | full · int-01 |
| 7 | R-DLG.2/4 | R `dlg_2_4_…` | yes. `expanded is False` asserted before the key | yes: closed (+) | int-01; base RED | full · int-01 |
| 8 | R-DLG.2/5 | R `dlg_2_5_…` | yes. `a`, `b`, `c` typed and asserted, `escape`, `t` | yes: closed; path `""`, dropdown `Select.NULL` (+) | int-01; base RED | full · int-01 |
| 9 | R-DLG.2/6 | R `dlg_2_6_…` | yes. `9` typed, the value asserted changed | yes: closed, 2 files (+) | int-01; base RED | full · int-01 |
| 10 | R-DLG.2/7 | R `dlg_2_7_escape_on_generate_writes_no_report` | yes. Generate focused | yes: closed, 2 files right after the close and again after `settle_workers` + 12 pumps, status unchanged (+) | int-01; base RED; M8 pending | full · int-01 |
| 11 | R-DLG.2/8 | R `dlg_2_8_…` | yes | yes: closed (+) | int-01; base RED | full · int-01 |
| 12 | R-DLG.2/9 | R `dlg_2_9_…` | yes. The folder spy is installed as in `test_open_folder_chips.py`, and shown live by a later chip press that counts 1 | yes: closed, 0 calls after 8 pumps (+) | int-01; base RED | full · int-01 |
| 13 | R-DLG.2/10 | R `dlg_2_10_…` | yes | yes: closed, no `WindowHelpScreen` (+) | int-01; base RED | full · int-01 |
| 14 | R-DLG.2/11 | R `dlg_2_11_…` | yes. The empty text mounted and the focus on `#window_help_reports`, both asserted | yes for the case ("closed"), plus the focus pair. Neither 0 files nor the status line (QA-4) | int-01; base RED | full · int-01 |
| 15 | R-DLG.2/12 | R `dlg_2_12_…` | yes. `question_mark` on the list, a wait for the help window on top, `escape`, a wait for it to go | yes: the top screen is `ReportViewerScreen`, asserted with no pump after the wait (QA-5) | int-01; std guard (declared); M17 pending | full · int-01 |
| 16 | R-DLG.15/1 | R `dlg_15_1_…` | yes. `enter` (waits for `expanded`), `down` (highlight on `f1.json` asserted, U-3), `escape` (waits for not `expanded`), `escape`, `t` | yes: list closed, the same screen on top, `Select.NULL`, no `Report filter:` among the recorded statuses (lossless) nor in `log_lines`; closed; reopened `Select.NULL` | int-01; base RED at the second Escape; first half std guard; M9, M10 pending | full · int-01 |
| 17 | R-DLG.15/2 | R `dlg_15_2_…` | yes (U-4). The FX project and the Flow Builder; the CHECK chip, `#flow_ref` by value, Add (waits for 1 block, `advisory`); `#flow_pick` = `1`; Edit (waits for `FlowBlockEditScreen`). Then `enter`, `down` (`block-own-op` asserted), `escape`, `escape` | yes: list closed, `FlowBlockEditScreen` on top, `advisory`; then closed and block 1 keeps `advisory` | int-01; std guard (declared); M10 pending | full · int-01 |
| 18 | R-DOC-GUIDE.1/13 | D `doc_guide_1_passages_describe_1_0_0[passage-12]` | n/a: reads `ch16-reports.md` | yes: the old row absent; both new rows present (whitespace-flattened) | int-01; base RED (stale row) | full · int-01 |
| 19 | R-DOC-GUIDE.1/14 | D `…[passage-13]` | n/a: reads `ch18-flow-execution.md` | yes: the old sentence absent, `**Close** or `esc`.` present | int-01; base RED | full · int-01 |
| 20 | AT-I12-1 | R `at_i12_1_escape_closes_reports_from_list_box_and_dropdown` | yes, keys throughout: `t`, `enter`, `escape`, `tab` (bounded, 30), `a b c`, `enter`, `down`, `escape`, `escape` | yes on every clause. The highlight after `down` is not asserted (QA-3), and the 2 files are checked once, at the end | int-01; base RED at the first Escape | full · int-01 (QA-1, QA-3) |
| 21 | AT-I12-2 | R `at_i12_2_rail_keys_and_issue_peek_after_the_aliases_go` | yes. Case 08 (seed 20260001, 1 MB) through the app's two loaders; keys `2`, `3`, `1`, `5`; the first `IssueRow` in `mem_map` focused, then `enter` | yes for the routing. The window is read from `_active_screen_key` and the peek from `pane.render()`. The aligned 8-hex row is absent before and present after; Issues is kept (QA-6) | int-01; std guard (declared); M15 pending | full · int-01 |
| 22 | AT-I12-3 | W `at_i12_3_addendum_tab_by_keys` | yes. `1` (left asserted), `=`, `tab` ≤ 150 (named failure), `enter` | yes: Fields shown before; Addendum pane alone, chip marked; the composited rows (`painted_rows`) start `## Checks` | int-01; std guard (declared); M16 pending | full · int-01 |

## 4. Per row: thresholds (Linux)

| Row | Threshold | Cases | Met | Note |
|---|---|---|---|---|
| R-DLG.14 | 1/1 census, ≥ 21 (21), 0 without | 14/1 | yes | Negative control: the base restore names `VariantHelpScreen` (red-01) |
| R-SHELL-KEYS.3 | 1/1 census, ≥ 80 (80), 0 without, 6 overrides via the toolkit | 3/1 | yes | Negative controls 1, 2 and 4 are the base restores (named, red-01), shown together, not one by one (QA-2). Negative control 3 is the in-node `PlainCard.action_copy` |
| R-CHKED-058 | 1/1 walk, ≥ 45 (51), 0 never shown, the Addendum state shows the preview | 058/1, AT-I12-3 | yes | Negative control: the base restore names the toggle (red-01-g-t2) |
| R-DLG.2 | 12/12 | /1 … /12, AT-I12-1 | yes | Negative control 1 (no binding = base): /1 … /11 RED (red-01). Negative control 2 (Generate path, M8) pending. The focus clause's discrimination is unshown (QA-1). The "nothing more changes" clauses are uneven (QA-4) |
| R-DLG.15 | 2/2 | /1, /2, AT-I12-1 | yes | Both negative controls (M9 priority, M10 list applies) pending. Both cases hold on base for these clauses, so no failing evidence yet (QA-2) |
| R-DOC-GUIDE.1 (cited) | /13, /14 | passage-12, -13 | yes | base RED |
| R-DOC-GUIDE.2 (cited, `_FIXED` 13 → 17) | marked set = pinned set | `doc_guide_2_1`, `2_2` | yes | base RED. F-35 is marked because Inc 12b is on main (`#flow_kind` occurs nowhere in `s19_app/`, checked) |

## 5. Removed and re-pointed existing nodes

| Node or assertion | Change | What it covered | Still owed by | Ruling |
|---|---|---|---|---|
| `test_tui_variants.py::test_variant_help_modal_fits_at_both_sizes`, its inner `_measure`, `_VARIANT_HELP_TOKENS` | removed | It pushed the orphan `VariantHelpScreen` directly, then measured its fit at 80×24 and 120×30 and its text tokens | Nothing. The class is gone. A restored orphan is R-DLG.14/1's failure (base RED). The retirement surface stays guarded by `test_at067a_…` and `test_tc336_tc337_…` (unchanged, no removed name). No other node reads the tokens. Its only live citation, `AT-067a`'s `nodes`, is cleaned (I-D2). A legacy history file names it; that file is not canon | ok |
| `test_tui_app.py::test_jump_to_validation_issue_prefers_address` | removed | `_jump_to_validation_issue` → the three hex views and a status, on a dead path (no route since batch-29) | Nothing shipped: no canon row names the jump or its status text (grep of `REQUIREMENTS.md`, `docs/requirements/review`). The shipped selection, R-ISSUES-HEXPANE-001.1 / .2, keeps its nodes through `on_issue_row_selected` (`test_tui_directionb.py:2114`, `:2418`, `:7861`, `:8104`), plus AT-I12-2 | ok |
| `test_tui_app.py::test_validation_issue_filtering_and_format`, its 3 formatter lines | assertions removed | `_format_validation_issue_line`, which no product code calls | Nothing: no row pins that format; the filter assertions stay | ok |
| `test_b97_check_editor.py::test_tc_b97_61_…` toggle lines | assertions removed | "the toggle is mounted, not displayed" (the base defect pinned) | R-CHKED-058/1's walk: any widget mounted and never shown, the toggle included (base RED). `len(typed) == 16 and typed <= column` keeps the old `shipped` set exactly | ok, strength kept |
| `test_tc_b97_08_…`, `b97_fixtures.CE_IDS_9C7BEAF` | 36 → 35 | The shipped ids stay mounted (a subset test) | Unchanged for the 35. A restored toggle stays GREEN here by design (M6 note) | ok |
| `test_tui_goto_marker.py::test_goto_focus_not_cleared_on_tab_switch` | aliases → `action_show_screen("a2l" / "mac" / "workspace")` | The focus address survives tab switches | The same calls the aliases made (`app.py` diff), so the node is identical in effect | ok, strength kept |
| `test_tui_directionb.py` TC-011 | docstring and comment only | Every pre-batch action keeps a keyboard path | The `hasattr` arm is now false, so the node passes only through the `show_screen` bindings: stricter | ok |
| `test_window_usage_help.py::test_tc706_seat_census_…` | the pinned list gains `("escape", "close_reports", False)` | The exact Reports bindings | Stricter. The `priority` flag is not in the tuple, so M9 relies on R-DLG.15/1 and AT-I12-1 | ok |
| `test_id_registry.py` (272 → 274), `AT-TC-REGISTRY.jsonl` `AT-067a` | count and node list | — | int-04 passes. The merge with Inc 10b resolves to 275 (I-D3) | ok |

## 6. Negative controls (the E4 mutant table)

| Mutant | Shown RED by | State |
|---|---|---|
| M1 `VariantHelpScreen` restored | red-01: the base names it | executed (base tree as a whole) |
| M2 `action_view_alt` + its two callers, M3 `action_view_mac`, M5 `action_a2l_tag_find_next` | red-01: the base names all three, with `action_view_main` | executed together, not one at a time |
| M4 unbound `action_copy` on a plain class | the in-node synthetic `PlainCard.action_copy`, flagged on the commit tree (int-01) | executed |
| M6 hidden toggle restored | red-01-g-t2: named | executed (base) |
| M7 Escape binding removed | red-01: /1 … /11, /15/1 (second Escape), AT-I12-1, TC-706 | executed (base) |
| M11, M12 doc rows restored | red-01: passage-12, passage-13 | executed (base) |
| M13 the F-51 mark removed | red-01: `2_1`, `2_2` (the base lacks all four marks) | executed (base; F-51 alone pending) |
| M8 Escape runs Generate's path | — | not-run (E5 mutant run) |
| M9 `priority=True` | — | not-run |
| M10 the open list's Escape applies the highlight | — | not-run |
| M14 focus cleared before the dismiss | — | not-run (QA-1) |
| M15 no hex-pane call on an issue selection | — | not-run |
| M16 the tab-chip branch removed | — | not-run |
| M17 the help window's close also pops the dialog | — | not-run |

The censuses carry their synthetic mutants inside the nodes. On base they failed at their first assertion, before the synthetic part, so those mutants ran only on the commit tree (int-01), where they hold.

## 7. Findings

| Id | Severity | Finding | Fix |
|---|---|---|---|
| QA-1 | MINOR (conditional; MAJOR if M14 survives) | **The focus-return oracle (U-2) may not tell "focus restored" from "focus re-landed".** <ul><li>In textual 8.2.8 a screen that resumes with no focus gives it to the first focusable widget of `query("*")` (`textual/screen.py:1465-1500`, §2).</li><li>The Known focus is whatever startup and the project load leave focused. No case or node shows that it differs from that auto-focus candidate.</li><li>If it does not differ, M14 (`screen_stack[0].set_focus(None)` before the dismiss) passes every focus clause: /1 … /11 and AT-I12-1.</li><li>R-DLG.2/1 and AT-I12-1 would then go to `partial`.</li></ul> | <ul><li>In the shared precondition, before `t`, move the focus to a non-input control of the shown window that is not `next(w for w in app.screen.query("*") if w.focusable)`, and assert the difference. Add it to the case's Known-focus fixture (U-2).</li><li>The E5 mutant run decides. If M14 is RED, downgrade this finding to NIT, and record which widget the fixture leaves focused and why it differs.</li></ul> |
| QA-2 | MINOR | **Seven mutants have no run, and they are the only failure evidence for five clauses** (§6): <ul><li>R-DLG.2/12 (M17);</li><li>R-DLG.15/2 (M10);</li><li>AT-I12-2 (M15);</li><li>AT-I12-3 (M16);</li><li>the first half of R-DLG.15/1 (M9, M10).</li></ul> All of these hold on base. M8 (R-DLG.2's second negative control) and M14 (QA-1) are pending too. M2, M3 and M5 were shown only together. | E5 mutant run (in flight): one mutant at a time in a copy, printing `s19_app.__file__` and the command. Cite each mutant's RED nodes per case in `02-test-cases.md`. Run M2, M3, M5 and M13 alone, as the table states. A survivor is a finding unless the table says it may survive |
| QA-3 | NIT | **AT-I12-1 does not assert the highlight after `down`.** M10's RED expectation for it depends on the highlight being on `f1.json`: with the highlight left on the blank option, an Escape that applies the highlight leaves the dropdown blank and the node GREEN. R-DLG.15/1 asserts the same step, so the gap is in the AT only | After the `down`, add `assert "f1.json" in _highlighted_prompt(select)`, as /15/1 does |
| QA-4 | NIT | **R-DLG.2's "nothing more changes" clauses are uneven.** /11 (the empty dialog) asserts neither 0 new files nor the status line. The filter-selection clause is asserted only at /5 (and /15/1, AT-I12-1). One binding serves every place, and /7 plus the 2-file count of /1 … /10 carry the Generate-path class, so no plausible defect passes; marks kept. Also, `_escape_closes` compares `app.log_lines`, a `deque(maxlen=4)`. `record_statuses` (used by /15/1) is the lossless form | When the file is next touched: in /11, assert that `reports/` is still absent and that the statuses recorded after the key are empty. In `_escape_closes`, compare `record_statuses` from the key on |
| QA-5 | NIT | **R-DLG.2/12 asserts the top screen with no pump after its wait.** A pop of the dialog scheduled one tick later (the shape of a `call_later`) could pass | `await settle(pilot)` before `assert isinstance(app.screen, ReportViewerScreen)` |
| QA-6 | NIT | **AT-I12-2 reads the window from bookkeeping and the peek from `render()`.** `_active_screen_key` is set first thing in `action_show_screen`. `pane.render()` is the widget's content, not the composited rows. The routing defects are caught: a rail key that no longer reaches `show_screen`, or a selection that jumps to the A2L window. A `show_screen` that sets the key but leaves the container hidden is not caught; other suites own that | Optional: assert `is_displayed` on the shown container after each key, and read the pane through `painted_rows` |
| QA-7 | NIT | **The census's spec and node differ on the reached-function seeds.** The node also seeds `compute_*`, `key_*`, `render`, `render_line`, `check_action` and `@on` handlers (`R:82-83`, `:287-292`). The case fixture and I-5 list only `on_*`, `_on_*`, `compose`, `watch_*`, `validate_*` and dunders. All of these names are ones textual dispatches, inside the row's "a handler the toolkit runs by its name". Separately, `App.bind(…)` is not read as a binding position: a live action bound only that way would be a false RED, never a false GREEN. No such action is on the tree | List the seed set in the Census fixture of `02-test-cases.md` and in I-5. Optionally, read `bind`'s second argument as a binding position |
| QA-8 | NIT | **Record hygiene in `02-test-cases.md`:** <ul><li>The Result cells cite int-01 and red-01 but name no executor.</li><li>`verified` is not one of the flow's evidence states.</li><li>The Windows column reads `not_run (E5)`, but E5 cannot run it: no `s19_app` import on the Windows PC. `steps.log`'s E5 start records that the increment has no Windows-only arm.</li></ul> | <ul><li>Name the executors: int-01 by the E4 integrator (Opus, LAN Linux host 2); red-01 by testers G-T1 and G-T2 (Sonnet).</li><li>Write `executed`.</li><li>The orchestrator rules the Windows state: `not-run — no s19_app import on the Windows PC; no Windows-only arm`, or `n/a — <ruling>`. Then re-cite the column.</li></ul> |

## 8. Not run by this audit

No test was run, and nothing that imports `s19_app` ran on the Windows PC. The only commands were:

- file reads and greps;
- git plumbing in a scratch index and a scratch object directory (the tree recomputation, §2);
- `git grep` of the I-3 names on `c6ad230`;
- `trace_check.py` under `python -I`, which reads text and git only;
- a read of the source text of textual 8.2.8's `screen.py` in a local install (no import).

The results above are:

- the E4 runs on LAN Linux host 2 (int-00 … int-08), executed by the E4 integrator;
- the testers' base runs (red-01).

During the audit, two untracked helper files of another E5 agent (`_e5_gen.py`, `_e5_runner.py`) appeared at the worktree root and were gone moments later. This audit did not read or run them. The scratch folder of the tree recomputation (`…/scratchpad/i12e5`) holds only this audit's scratch index and the tree objects it wrote. A safety check refused its removal, so it is left in the session scratch. It touches nothing in the worktree or the repository.

## 9. Totals

| | Before | After |
|---|---|---|
| Active cases | 22 | 22 |
| Coverage `full` / `partial` / `gap` | 22 / 0 / 0 | 22 / 0 / 0 (2 at risk: QA-1) |
| Marks changed | — | 0 |
| Row thresholds met (Linux) | 5 claimed | 5 of 5, plus the cited R-DOC-GUIDE.1 passages and R-DOC-GUIDE.2 |
| Results | 22 `verified (linux, int-01)`, no executor named | 22 executed (linux, int-01, on the commit's tree `d1713533…`, recomputed) by the E4 integrator |
| Windows | `not_run (E5)` on the driven cases | not-run, pending the orchestrator's ruled state (QA-8) |
| Negative controls | M1 … M17 "at E5" | 10 shown RED by the base runs or in-node mutants; 7 not-run (QA-2) |
| Cases or nodes to add | — | none. One precondition to strengthen (QA-1), one assertion to add (QA-3), optional tightening (QA-4 … QA-7) |
