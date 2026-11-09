# Inc 12 E4 tester (G-T1) - notes

Node file: `tests/test_b101_reach_and_reports_escape.py`, 18 nodes (2 censuses, 12 Reports Escape, 2 dropdown, 2 acceptance), plus 2 passage entries (`passage-12`, `passage-13`) in `tests/test_b101_help_legend_docs.py`. Names are the E1 proposals, unchanged.
RED run: base `6f1743c1` (origin/main; product tree equals the branch base `3c196d1`), LAN Linux host 2, python 3.11 `s19ci`, textual 8.2.8, `s19_app` resolved inside the work folder. Transcript: `.dev-flow/2026-11-01-batch-101/evidence/inc-12/red-01-g-t1-base.txt` (redacted; grep for home, account, host: 0 hits). Command: `env -u NO_COLOR python -m pytest -q -p no:cacheprovider -rfs <new file> tests/test_b101_help_legend_docs.py tests/test_tui_variants.py tests/test_tui_app.py tests/test_tui_goto_marker.py tests/test_window_usage_help.py -n 6 --dist loadfile`.
Summary line: `20 failed, 194 passed, 1 xfailed in 250.20s`. State: `executed` (RED on base; the 20 failures are the 15 new red nodes, passages 12/13, the two `_FIXED` nodes, and TC-706's binding census).
Also executed (not in the transcript, same host): a throwaway local fix on the remote clone (Escape binding + `action_close_reports`, the 4 dead actions and their callers and `VariantHelpScreen` removed, product code only, never saved here) took all 18 new nodes to `18 passed in 28.13s`. That fix was discarded; it only shows the nodes can go green. The real GREEN run is the integrator's.

## How the nodes read and drive
- Censuses read `s19_app/**/*.py` with `ast` (the toolkit is imported only for `BINDINGS`). The census is a function over a `{path: source}` dict, so each negative control appends one synthetic module to the real tree; no removed name is spelled (I-3 grep over `tests/`: 0 lines, new file included).
- Reach arms: the four positions (Binding/PaletteEntry call or tuple in `BINDINGS`/`*PALETTE_ENTRIES`, literal `run_action`, `@click=` in non-docstring strings), the toolkit arm (class-scoped, from the installed `textual` MRO `BINDINGS`), and the reached-function fixpoint by name (calls and references; seeds: module/class scope, `on_*`, `_on_*`, `watch_*`, `validate_*`, `compute_*`, `key_*`, dunders, `compose`, `render`, `@on`).
- Reports nodes: Reports project from `make_project`/`load_project`, dialog opened with `t`, Escape pressed through the pilot, waits through `settled` (10 s bound, so a missing behaviour fails with the stack in the message). Each precondition is asserted (focus on the named widget, typed text present, list expanded, highlight on `f1.json` / `block-own-op`, folder spy live by a later chip press). Closed = no `ReportViewerScreen` on the stack and the main screen on top; also files in `reports/`, `app.log_lines` unchanged, `(app.focused, app._active_screen_key)` equal to the pair recorded before `t`.
- AT-I12-2: case 08 (seed 20260001, 1 MB) with `firmware_issues.a2l`, loaded through the app's loaders; keys `2`, `3`, `1`, `5`; Enter on the first listed `IssueRow` whose address is in `mem_map`; reads `#issues_hex_pane`.

## Cases -> nodes, RED on base
| Case | Node | Base result and the reason |
|---|---|---|
| R-DLG.14/1 | `test_r_dlg_14_1_every_dialog_has_an_opener` | RED: `['VariantHelpScreen']` (22 dialogs, 1 without opener, as measured at E3) |
| R-SHELL-KEYS.3/1 | `test_r_shell_keys_3_1_every_action_has_a_reach` | RED: the 4 of 83 (`action_a2l_tag_find_next`, `action_view_alt`, `_mac`, `_main`), as E3A-R2-1 |
| R-DLG.2/1 .. /11 | `test_r_dlg_2_1_` .. `test_r_dlg_2_11_*` | RED each: "did not settle: the Reports dialog closed (...)" with the stack still `[Screen, ReportViewerScreen]`; all preconditions held before the Escape |
| R-DLG.2/12 | `test_r_dlg_2_12_escape_in_its_help_window_keeps_reports_open` | passes on base (standing guard, declared) |
| R-DLG.15/1 | `test_r_dlg_15_1_escape_with_the_dropdown_open_closes_only_the_list` | RED at the second Escape (dialog stays open); the first Escape (list closes, blank, no status) holds on base |
| R-DLG.15/2 | `test_r_dlg_15_2_escape_with_the_gating_dropdown_open_closes_only_the_list` | passes on base (standing guard, declared) |
| R-DOC-GUIDE.1/13, /14 | `test_r_doc_guide_1_passages_describe_1_0_0[passage-12]`, `[passage-13]` | RED (docs on the base keep the old row and sentence) |
| AT-I12-1 | `test_at_i12_1_escape_closes_reports_from_list_box_and_dropdown` | RED at the first Escape |
| AT-I12-2 | `test_at_i12_2_rail_keys_and_issue_peek_after_the_aliases_go` | passes on base (declared: holds on base) |
| `_FIXED` 13 -> 17 | `test_r_doc_guide_2_1_fixed_rows_marked`, `_2_2_no_other_row_marked` | RED on base (DOSSIER rows F-33/34/35/51 unmarked) |
| Existing edits | `test_window_usage_help.py::test_tc706_seat_census_header_row_and_window_section` | RED on base (pins the new `escape` binding); `test_tui_variants.py` (node and `_VARIANT_HELP_TOKENS` removed), `test_tui_app.py` (jump node removed, 3 formatter lines removed), `test_tui_goto_marker.py` (aliases -> `action_show_screen`) all pass on base |

Census negative controls (inside the two census nodes, synthetic mutants of the same shapes, cited by case id): an orphan dialog and a dialog built only in a function no reached function calls (R-DLG.14/1, expected `['DeadOnlyDialog', 'OrphanDialog']`); a dead chain alias, a lone dead alias, an unbound `action_copy` on a non-toolkit class, an action whose name is only a widget id plus a comparison literal (R-SHELL-KEYS.3/1; expected exactly those four). Positive controls: each reach arm (binding, palette, `run_action`, `@click=`, call from a reached function, toolkit) reaches its action, so the census cannot pass by flagging nothing or everything. The mutants were not run as RED on the base tree as such: they are asserted inside the nodes (they pass on the fixed tree and on base for those clauses; the base failure comes from the real tree's dead entries earlier in each node).

## Standing guards (pass on base) and why each still has a failure mode
- R-DLG.2/12: fails if Escape in the help window also closed the dialog (or the help window ignored Escape).
- R-DLG.15/2: fails if the open list's Escape applied `block-own-op`, closed Edit block with the list open, or the second Escape did not close it or changed the block.
- AT-I12-2: fails if a rail key stops showing its window, or an Issues row selection stops painting the address row (the peek) or leaves the Issues window.
- The first half of R-DLG.15/1 (list closes alone, blank, no `Report filter:` status).

## Findings for the integrator
1. `AT-TC-REGISTRY.jsonl` entry `AT-067a` names the removed node `tests/test_tui_variants.py::test_variant_help_modal_fits_at_both_sizes` and its inner `_measure`; `tests/test_id_registry.py` (G2, at280, at281) fail until the entry drops them. Not a test file; not edited here.
2. `EXPECTED_SCANNED_TEST_FILES` in `tests/test_id_registry.py` needs +1 for my file (and +1 for G-T2's); re-measure at integration (measured 273 vs 272 on base with my file only).
3. `test_tui_directionb.py`, `b97_fixtures.py`, `test_b97_check_editor.py` left to G-T2 per the orchestrator's note.
4. Whole-file wall time: Reports nodes wait up to 10 s each when Escape does nothing (base); on a fixed tree the file runs in about 28 s with `-n 6 --dist load`.
5. DOSSIER rows for F-33/34/35/51 and the ch16/ch18 edits were already in the working tree from the docs implementer; the `_FIXED` and passage nodes read them (not run against it here: the RED run is on pristine base).
