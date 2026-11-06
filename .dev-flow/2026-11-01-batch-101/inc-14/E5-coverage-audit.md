# Inc 14 — E5 coverage audit

Batch 2026-11-01-batch-101, increment 14, stage E5. Worktree head `7d37efa`. Role: coverage auditor. I did not write the cases or the tests. Mode: **validation** of the coverage records. This file is the only file I wrote.

Inputs read: `02-test-cases.md` (69 cases), `01-requirements.md`, `E4-tester-notes.md`, `E4-integration-notes.md` (SR-1, OR-1 … OR-6, §6), `evidence/inc-14/int-01 … int-06`, `git diff main...HEAD -- tests` (G = `tests/test_b101_help_legend_docs.py`, `tests/support/help_copy_i14.py`, and the re-bodied `test_window_usage_help.py`, `test_changes_file_notation_help.py`, `test_docs_canon.py` and `test_id_registry.py`), and the product call sites named below. Rules: TCP-MAP-1, -3, -5, -6, -7 from `s19w/test-cases/TC-PROFILE.md`. `PLAN.md` does not name TCP-MAP; the profile does.

Evidence:
- **Inspection** of the tests and the product code.
- One **executed** collection, run by me: `pytest --collect-only` over every cited file and node, 180 ids, 0 errors.
- One data read: the key tokens of `WINDOW_HELP_SECTIONS`.
- I ran no test. Every pass or fail cited here comes from the orchestrator's runs on the LAN Linux host (`int-02`, `int-03`, `int-05`), read from their transcripts.

Rule applied: a test verifies a case only if it asserts the case's expected result. It is `full` only when the product itself produces what it asserts:
- For a document case, that means the shipped file's text.
- For a help-copy case, the asserted value is the product constant `WINDOW_HELP_SECTIONS`, and the pinned copy in `tests/support` is only the oracle. The tie to the screen is `test_tc706_affordance_opens_window_section_modal`, which asserts that the modal body equals `section_body_text(key)` on 9 seats, and `test_tc707_numbering_generated_sequential`, which asserts that the body is the numbered steps. So these cases are `full`, provided the tie node is cited (§2).

## 1. Summary

| Count | Value |
|---|---|
| Cases audited | 69 |
| Coverage column wrong as it stands | **67 of 69**: 66 say `gap` although a test is listed and passed, and R-WHELP.23/2 says `partial` although a `full` G test exists |
| Coverage after this audit | covered **59** · partial **5** · conflict **4** (SR-1; they become covered once the case text is corrected) · not-testable **1** |
| Marks changed `full` → `partial` | **5** (7.2%): R-WHELP.12/2, R-WHELP.13/2, R-DOC-README.4/3, R-DOC-RELNOTE.1/1, R-DOC-GUIDE.1/9 |
| Expected result no longer matches the pinned text | **4** (SR-1): R-DOC-GUIDE.1/1, /4, /7, /8. Plus 1 count slip in an Expected cell (R-WHELP.12/1, "11 sections") |
| Cited ids that are not collectable nodes (TCP-MAP-3) | **2**: `tests/test_segment_split_window.py` (R-WHELP.21/2) and `tests/test_legend_map_sheet.py` (R-LEGEND-011/2), each cited as a whole module |
| Cited nodes that collect | every node id cited (180 collected, 0 errors) |
| Supporting (partial) nodes run in no Inc 14 run | 4: `test_tc084_1_*` (23/2), `test_ac3_*` and `test_ac4_*` (062.10.1/2), `test_tc_b100_46_*` (19/2) |
| Result cells with a word that is not an evidence state | **68**: `verified (linux, int-02)` → `executed (orchestrator, LAN Linux host, int-02)` |
| **Cases changed, any column except Result** | **67 of 69 = 97.1%** (unchanged: R-WHELP.26/2, R-DOC-SECURITY.1/2) |
| **Cases changed, leaving out the mechanical Coverage column** | **23 of 69 = 33.3%** |
| Requirement clauses with no case | 9 (§4) |
| Black-box checks owed | 5 (§5) |
| Hold-out group (cases that depend on `SECURITY.md`) | 4 cases, 4 tests (§6) |

Top issues:
1. **R-WHELP.12/2 does not show that a control is in its window.** Every rail window is a container on one screen (`SCREEN_CONTAINER_IDS`, `app.py:9309`). `_painted_strings(app.screen)` therefore reads all rail windows at once, so a control painted by any window satisfies every window. On top of that, `_control_found` accepts a prefix: `t.startswith(control + " ")`. So `Goto 0xADDR` stands in for the `Goto` button, `Load path` for `Load`, and any `Save …` for `Save`. Both are TCP-MAP-6 failures, and the test can pass with a named control missing.
2. **No case opens a help window through `?`.** Every help-copy case asserts the data constant. The rendered tie runs through the chip (`Button.press`), and that tie covers 9 seats. For `split_join_export`, no test compares the painted modal body with the copy.
3. **SR-1 is still open in the records.** Cases /1, /4, /7 and /8 still expect `(capture taken before 1.0.0)`, but the test and the shipped guide use `(capture taken before 1.0.0` followed by `: <what the capture shows>`.
4. **The Result column overstates its provenance.** It reads "every case's named tests passed in int-02". In fact `test_tui_checks_view.py`, `test_map_click_chain.py` and `test_b100_load_question.py` ran in no Inc 14 run, and TC-B97-32 (int-03), `test_report_service` and `test_segment_split_window` (int-05) ran outside int-02. The cases' `full` G nodes are all in int-02, so no case result changes. Only the provenance does.
5. **Image loads use `load_selected_file`, which has no product caller** (no call in `s19_app`). This affects 12/2, 20/2, 21/2, 22/2, 011/1 and 011/2. It reaches the same `_parse_loaded_file` / `_apply_loaded_file` as the load worker (`app.py:18430`, `:14054`), and the load is a precondition here, not the behaviour under test, so the marks stay. TCP-MAP-7 still requires the Tests column to say so.

## 2. Change table

"Who" names the artifact that changes: **case** (`02-test-cases.md`), **test** (G or a re-bodied file), **row** (`01-requirements.md`).

| Case | Column | Old → new | Reason | Who |
|---|---|---|---|---|
| (66 rows) | Coverage | `gap` → `covered` / `partial` / `conflict` as in §3 | tests are listed and passed (int-02); `gap` requires that no test exists | case |
| (68 rows) | Result | `verified (linux, int-02)` → `executed (orchestrator, LAN Linux host, int-02)` | `verified` is not one of the seven evidence states; the executor is named | case |
| R-WHELP.12/1 | Expected; Inputs | "the 11 sections with tokens" → "the 8 sections with tokens" (the list itself names 8; a data read confirms 8); add N-1 to K(w): `/` and `g` act only on Workspace, A2L and MAC, `pgdn` and `pgup` only on A2L, MAC and Issues | the test applies N-1 and the case does not; mark stays full. Note: the test's K(w) and `_SECTION_WINDOW` are hand copies of `check_action` and `HELP_KEY_WINDOW` (`window_help.py:910`), so they can drift from the product | case; test (optional: read `HELP_KEY_WINDOW`) |
| R-WHELP.12/2 | Mark; Coverage; Preconditions | full → **partial**; `gap` → `partial`; "Project P open" → the synthetic `_make_report_project`, image loaded by `load_selected_file` | all rail windows are searched as one set, and prefix matching lets a longer label stand in for a control (TCP-MAP-6); the coverage column matches only a pattern (OR-2) | case; test: query each window's own container (`#screen_<key>`) and match labels exactly |
| R-WHELP.12/4 | Tests | add the tie node `test_window_usage_help.py::test_tc706_affordance_opens_window_section_modal` (rendered body = `section_body_text`, chip route, 9 seats) | the copy pinned in `tests/support` is tied to the screen only through this node | case |
| R-WHELP.13/2 | Mark; Coverage | full → **partial**; `gap` → `partial` | the case expects each folder mapped to its own constant (8/8). The test checks only that each folder is in the union of the constant values, so `splits\` written where `patches\` belongs would pass (TCP-MAP-1) | test: map each token to its named constant |
| R-WHELP.18/2 | Preconditions | "Project P0 open with Image F" → the synthetic reportable project (`_make_report_project`); Reports opened with `t`; Generate by `Button.press()` | fixture deviation (tester note); mark stays full | case |
| R-WHELP.19/2 | Preconditions; Tests | Project P → the synthetic project with `declared_regions` written into its manifest; P0 loads A2L F after the project. Tests: `test_tc_b100_46_*` "(partial; run in no Inc 14 run)" | fixture deviation; mark stays full | case |
| R-WHELP.19/3 | Inputs | "type … in the box; … close the dialog" → "`TextArea.text` set; Generate by `Button.press()`, which closes the dialog itself (`screens.py:3506`); `t` reopens it" | the step is widget-driven; the reopened screen is a new instance, so the mark stays full | case |
| R-WHELP.20/2, 22/2 | Tests (what) | add "image loaded by `load_selected_file` (no product caller; same parse and apply as the load worker)" | TCP-MAP-7 | case |
| R-WHELP.21/2 | Tests | `tests/test_segment_split_window.py` (module) → name a node (e.g. `::test_default_tab_is_ranges_with_and_without_an_a2l`) or drop it; add "reads `window._rows()`, not the painted table; window opened by `action_open_split_join_export`; image loaded by `load_selected_file`" | TCP-MAP-3, TCP-MAP-7 | case |
| R-WHELP.23/2 | Coverage; Tests | `partial` → `covered`; `test_tc084_1_*` "(partial; run in no Inc 14 run)" | the G test asserts the literal headers in order | case |
| R-TUI-062.10.1/1 | Inputs | "the sheet opened by `k`" → "opened by `action_show_screen('map')` + `action_show_legend()`, no image loaded" | `k` is not pressed here. `k` → `show_legend` (`app.py:2699`) and 011/1 shows `k` opening the same `LegendScreen`, so the mark stays full; black-box check owed (§5 B-3) | case |
| R-TUI-062.10.1/2 | Preconditions; Tests | add "`current_file` installed by `_map_ready`"; `test_ac3_*`, `test_ac4_*` "(partial; run in no Inc 14 run)" | the `post_message` spy passes the product's own messages through and echoes no text, so TCP-MAP-5(a) does not apply | case |
| R-LEGEND-011/1 | Tests (what) | add the `load_selected_file` note | TCP-MAP-7 | case |
| R-LEGEND-011/2 | Tests | `tests/test_legend_map_sheet.py` (module) → `::test_tc680_sheet_no_wrapped_lines[80x24]`; add the `load_selected_file` note | TCP-MAP-3, TCP-MAP-7 | case |
| R-DOC-README.4/3 | Mark; Coverage | full → **partial**; `gap` → `partial` | the test finds `not implemented` anywhere in the section and does not tie it to `extract` and `split_by_segment`, nor say that `crc` is the operation that runs (TCP-MAP-1) | test |
| R-DOC-SECURITY.1/1 | Tests | `test_r_doc_security_1_3_readme_links_the_policy` → "supporting (README link, hold-out group), verifies no clause of 1/1" | the case's Expected has no README clause | case |
| R-DOC-RELNOTE.1/1 | Mark; Coverage | full → **partial**; `gap` → `partial` | the case and the row ask for the "What changed" and "Am I affected?" paragraphs of `release-note-crc.md`. The test pins 6 fragments, so a paraphrase that keeps them passes | test: compare the two paragraphs, whitespace-normalised |
| R-DOC-GUIDE.1/1, /4, /7, /8 | Expected; Coverage | `(capture taken before 1.0.0)` → `(capture taken before 1.0.0` followed by `: <what the capture shows>` (graph I-5); `gap` → `conflict` until corrected, then `covered` | SR-1 | case; row (R-DOC-GUIDE.1 threshold); E1 ruling D-5 |
| R-DOC-GUIDE.1/9 | Mark; Coverage | full → **partial**; `gap` → `partial` | the case places `a2l=used` "in the 21.1 header bullet" and `from the loaded A2L and MAC` "in the Runs bullet". The test checks both anywhere in the file (TCP-MAP-1) | test |

## 3. Per-case result (all 69)

The mark is the strongest node's. Coverage is the new value; the old value was `gap` unless stated.

| Case(s) | Mark | Coverage | Note |
|---|---|---|---|
| R-WHELP.12/1 | full | covered | case text fix (§2) |
| R-WHELP.12/2 | **partial** | partial | §1 issue 1 |
| R-WHELP.12/3, 13/1, 14/1 | full | covered | product constant scanned; negative controls present |
| R-WHELP.12/4 | full | covered | tie node to cite |
| R-WHELP.13/2 | **partial** | partial | union, not mapping |
| R-WHELP.7/1 | full | covered | (a) body from `section_body_text`, (b) and (c) pinned, census of 12 with controls. `boundary` is partial, as the case says |
| R-WHELP.18/1, 19/1, 20/1, 21/1, 22/1, 23/1, 24/1, 25/1, 26/1 | full | covered | step equals copy, plus the rendered tie. For 21/1 and 22/1 (`split_join_export`) the tie holds by class only (§5 B-1). For 25/1, TC-B97-32 ran in int-03 |
| R-WHELP.18/2, 19/2, 19/3 | full | covered | `t` key; fixtures corrected (§2) |
| R-WHELP.20/2, 22/2 | full | covered | keys `2` `/`, `space` `m` |
| R-WHELP.21/2 | full | covered | product rows model against product ranges; module cite to fix |
| R-WHELP.23/2 | full | **partial → covered** | |
| R-WHELP.24/2 | full | covered | `0` key; typed Ranges through the widget; 8-byte CRC present, 16-byte CRC absent |
| R-WHELP.26/2 | full | covered (unchanged) | Inc 8 node, in int-02, not one of the 3 skips (those are the Windows-only arms at `test_b101_flow_ext_copy.py:563`, `:796`, `:1268`) |
| R-TUI-062.10.1/1, /2; R-LEGEND-011/1, /2 | full | covered | 011/1 and 011/2 press `4` then `k` |
| R-DOC-README.2/1, 2/2, 3/1, 4/1 | full | covered | shipped file |
| R-DOC-README.3/2 | full | covered | AT-285 re-bodied with the A-5 negative control; single-key cells only (OR-4) |
| R-DOC-README.4/2 | full | covered | **hold-out** (§6) |
| R-DOC-README.4/3 | **partial** | partial | |
| R-DOC-SECURITY.1/1, 2/1 | full | covered | **hold-out** |
| R-DOC-SECURITY.1/2 | none | not-testable (unchanged) | Result stays `not-run`: the `gh api` transcript is the orchestrator's merge precondition and is not yet in `evidence/`. **hold-out** |
| R-DOC-RELNOTE.1/1 | **partial** | partial | |
| R-DOC-RELNOTE.1/2, 2/2 | full | covered | the product engine `crc32_stream` |
| R-DOC-RELNOTE.2/1, 3/1 … 14/1 | full | covered | shipped `CHANGELOG.md` text. 7/1, 11/1 and 13/1 also pin the product token or behaviour |
| R-DOC-GUIDE.1/1, /4, /7, /8 | full | **conflict** | SR-1; covered once the case is corrected |
| R-DOC-GUIDE.1/2, /3, /5, /6, /10, /11 | full | covered | |
| R-DOC-GUIDE.1/9 | **partial** | partial | |
| R-DOC-GUIDE.2/1, 2/2 | full | covered | |

## 4. Requirement clauses with no case

| # | Row | Clause not covered |
|---|---|---|
| C-1 | R-WHELP.7 (event row) | "When the system opens a help window … the section title … and the key lines". 7/1 checks `section_body_text` only. No case observes the opened window, and none observes its key lines. |
| C-2 | R-DOC-SECURITY.1 | "no public-issue fallback text": no absence check. |
| C-3 | R-DOC-SECURITY.2 | "`SECURITY.md` ships with the 1.0.0 release [S-6]": no case. `pyproject.toml` includes only `s19_app*`, and nothing shows whether `SECURITY.md` is in the sdist. |
| C-4 | R-DOC-RELNOTE.6 | the earlier 512-row cut "of the HTML window of a run present in one image only"; "0 claims that the earlier HTML changed pane was cut" is checked for one phrase only (tester: partial). |
| C-5 | R-DOC-RELNOTE.7 | the full status line `Project sync NOT done: project '<name>' could not be read — check that the folder can be opened, then load again.` The case pins the prefix; the test checks the code tokens, not that the CHANGELOG quotes them. |
| C-6 | R-DOC-RELNOTE.8 | "no text says how the climb could be used (0)": no case (tester: not expressible as a scan). |
| C-7 | R-DOC-RELNOTE.1 | the two paragraphs, verbatim (case 1/1 is partial). |
| C-8 | R-DOC-GUIDE.1 | the note is "beside" each named capture (ch06-05, ch17-05, ch19-01, ch21-02), but only presence anywhere in the file is checked; the I-5 continuation `: <what the capture shows>` is not asserted. |
| C-9 | R-WHELP.12 (b) | "exists in its mounted window": nominally a case (12/2), in practice the window scope is not asserted (§1 issue 1). |

## 5. Black-box checks owed

| # | Check | Status today |
|---|---|---|
| B-1 | Help modal through `?` on each window whose section changed (A2L Explorer, Workspace, Checks, CRC Designer, Reports, Split / Join / Export, Flow Builder): focus a widget of the window (not the chip), press `?`, and assert that the painted `#window_help_body` equals the numbered approved copy and the title equals the copy's title | `not-run`. tc706 asserts the body when the chip is pressed (9 seats, Split / Join / Export not among them). With `?` it asserts only `section_key`, and only with the chip focused. No G test opens a help window. |
| B-1b | `F1` on each window | `n/a — no F1 binding exists in s19_app (grep), and no requirement names F1` |
| B-2 | The key lines of each opened help window (R-WHELP.7, C-1) | `not-run`; no case |
| B-3 | Legend through `k`: read the `Map keys` box after `4` then `k` (062.10.1/1 opens the legend by action) | `Region row` box under `k`: observed (011/1, 011/2). `Map keys` box under `k`: `not-run`. The cheapest fix is to read both boxes in 011/1. |
| B-4 | Each named control in its own window's container, matched exactly (12/2) | `not-run` (§1 issue 1) |
| B-5 | Split / Join / Export opened from the palette (`^K`), the claim of help step 1 | not cited by a case. `test_segment_split_window.py::test_tc710_palette_entry_no_rail_key_esc_close` exists (int-05) and could be cited as supporting |

## 6. Hold-out group (`SECURITY.md`, ruling N-2)

If `SECURITY.md` is held out at merge, the following move with it:

| Case | Test | Why |
|---|---|---|
| R-DOC-SECURITY.1/1 | `test_r_doc_security_1_1_policy_names_private_path` | reads the file |
| R-DOC-SECURITY.1/2 | none (the `gh api` transcript) | the merge precondition itself |
| R-DOC-SECURITY.2/1 | `test_r_doc_security_2_1_supported_versions` | reads the file |
| (supporting) | `test_r_doc_security_1_3_readme_links_the_policy` | README link |
| R-DOC-README.4/2 | `test_r_doc_readme_4_2_linked_documents_exist` | asserts that every README link target exists (`test_b101_help_legend_docs.py:1198`), and `README.md:429` links `SECURITY.md`. Its Expected also lists `SECURITY.md`. It stays GREEN only if the README row is held out with the file and the case's link list is edited. |

No other case depends on `SECURITY.md`: `CHANGELOG.md` does not link it, and the TC-607 bound counts only `tests/**/*.py`.
