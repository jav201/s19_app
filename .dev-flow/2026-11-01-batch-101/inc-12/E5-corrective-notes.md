# Inc 12 — E5 corrective notes

Batch 2026-11-01-batch-101, increment 12, stage E5 corrective pass (Sonnet). Branch `b101-inc12`, start head `99b136c`, base `6f1743c` (origin/main). Rulings: `E5-rulings.md`. Inputs: `E5-review.md` (R-1 … R-7), `E5-coverage-audit.md` (QA-1 … QA-8), `E5-mutants.md` (17 / 17 killed, not touched). Scope kept: records, docstrings and comments (no code change; the one source file touched is `s19_app/tui/screens_directionb.py`, a docstring), and tests. No product behaviour changed. Transcripts: `../evidence/inc-12/e5c-02.txt` … `e5c-15.txt` (names below), redacted (`<HOME>`, `<USER>`, "LAN Linux host 2").

R = `tests/test_b101_reach_and_reports_escape.py`, CC = `docs/requirements/review/CODE-CHANGES.md`.

## 1. Per ruling

| Ruling | What changed (file:line) | RED / GREEN |
|---|---|---|
| R-1 | CC:76 D3-7 `done (batch-101 Inc 12)`; CC:160 D6-12 `partly done (batch-101 Inc 12): action_view_main, action_view_mac (and action_view_alt) removed; _toggle_settings_menu still open`; CC:181 D7-10 `done`; CC:223 D9-8 `done`; CC:183 D7-20 adds "Reports (Inc 12)" to the done list and drops it from the missing list ("7 of 18 dialogs"). Totals line untouched. | records; the doc guards stay GREEN (e5c-13) |
| R-2 | `s19_app/tui/screens_directionb.py` `CheckEditorPanel.compose` docstring: "The shipped ids are kept (LLR-145.1), except the hidden addendum toggle, which batch-101 Inc 12 removed (R-CHKED-058)." No code change. | `git diff` shows docstring lines only; GREEN e5c-12 |
| R-3 | `tests/test_tui_directionb.py` TC-011: the `hasattr(S19TuiApp, f"action_{action}")` arm and the bare `view_*` candidates dropped; the comment no longer says "Either path". | GREEN e5c-12. The arm was already false on this tree, so the edit cannot turn the node RED today; the stricter reading is by construction |
| R-4, R-5, QA-7 | `codewire/graph-inc12.md` I-5: the reached-function seeds now list `compute_*`, `key_*`, `render`, `render_line`, `check_action` and `@on(...)` handlers, and a second stated limit (a toolkit-named handler counts as reached on any class, mounted or not; no instance at Inc 12). `02-test-cases.md` Census fixture states the same seeds and limit. | records |
| R-6 | `tests/test_tui_app.py:635` `test_validation_issue_filtering_and_format` renamed `test_validation_issue_filtering` (no registry entry names it: grep of `AT-TC-REGISTRY.jsonl`, 0); `tests/test_tui_variants.py:463` comment now "The tests below (three until batch-101 Inc 12 removed the orphan-modal geometry node)". | GREEN e5c-12 |
| R-7 | `E1-rulings.md` §6: backlog **BL-I12-6** (a dismissing handler returns early when its screen is no longer active; Generate in flight when Escape lands, or a double click; `screens.py:3404-3427`). | backlog, no code |
| QA-1 | R: new `_known_off_default` (before `_report_files`): focuses `#sections_list`, asserts the focus holds, that it is not `next(w for w in app.screen.query("*") if w.focusable)` and not an `Input` / `TextArea`; then returns `_known`. Used by R-DLG.2/1 and AT-I12-1 in place of `_known`. | **RED**: M14b (the focus put back on `#files_list` one tick after the dismiss, i.e. the startup focus) on the new nodes, `At index 0 diff: ListView(id='files_list') != ListView(id='sections_list')`, 2 failed (e5c-09); the earlier nodes under the same M14b: 2 passed (e5c-10), the gap QA-1 named. M14 (focus cleared, Textual's fallback `palette_input`): 2 failed on the new nodes (e5c-02), 2 failed on the earlier ones too (e5c-03). **GREEN** e5c-12 |
| QA-2 | Done by the mutant table (17 / 17). Nothing to change. | — |
| QA-3 | R AT-I12-1: after `down`, `assert "f1.json" in _highlighted_prompt(select)`. | **RED**: the `down` press removed in the remote copy → `assert 'f1.json' in 'Select'` (e5c-04). **GREEN** e5c-12 |
| QA-4 | R R-DLG.2/11: takes `monkeypatch`, `record_statuses`; asserts `_report_files(project) == []` and `statuses[mark:] == []` after the key. | **RED** one mutant per clause: a status written on Escape → `['closed'] == []` (e5c-05); Escape running Generate → the "nothing to report" status (e5c-06); a stray `reports/stray.md` written → `['stray.md'] == []` (e5c-11). **GREEN** e5c-12 |
| QA-5 | R R-DLG.2/12: `await settle(pilot)` before the top-screen assertion. | **RED**: the help window's close also schedules a pop of the dialog with `call_later` → top screen is the main `Screen` (e5c-07). The earlier node fails under the same mutant too (e5c-08): it did not need the pump for this shape; the pump closes the later-tick shapes. **GREEN** e5c-12 |
| QA-6 | Record only: the active window key and `pane.render()` are the product's own state; acceptable. | — |
| QA-8 | `02-test-cases.md`: every Result cell reads `executed (linux, int-01, E4 integrator Opus, LAN Linux host 2; re-run on the corrected tree e5c-12 .. e5c-14, E5 corrective, LAN Linux host 2)`; the Windows column reads `n/a (no Windows-only arm in this increment)` on all 20 rows. | records |

## 2. Decisions taken in this pass

- **E-1 (the Known focus widget).** `#sections_list` of the Workspace window: a `ListView`, shown and focusable on the tree (probe: the focus after a project load is `#files_list`; the first focusable widget is `#palette_input`). It differs from the startup focus and from Textual's fallback, so neither a fallback nor a re-focus of the startup widget can pass.
- **E-2 (M14b).** The audit's M14 proved to be killed by the earlier nodes as well (the fallback lands on `#palette_input`, which differs from the startup `#files_list`). QA-1's gap shows only for a dismiss that returns the focus to the startup widget, so M14b is that mutant. The earlier nodes pass it (e5c-10); the new ones fail (e5c-09).
- **E-3 (registry path).** The AT-TC registry is `AT-TC-REGISTRY.jsonl` at the repo root (`.dev-flow/` holds only its SPEC); the staged diff names that path. The renamed node is not listed in it.

## 3. Runs

LAN Linux host 2 (16 cores, `-n 8`), Python 3.11.18 (`s19ci`), `env -u NO_COLOR`. A `git clone --shared` of the host's repo whose own `main` is `6f1743c` (= origin/main), prefix `s19_i12c`, with `git diff --binary 6f1743c -- s19_app tests docs README.md AT-TC-REGISTRY.jsonl` of the local tree applied: staged tree **`de2521d3…`** (final; the test files did not change after the mutant runs). Every transcript prints the base commit, the staged tree, `s19_app.__file__` (the clone, or the `cp -a` mutant copy `s19_i12c_mut`) and the command line. Mutants and bad inputs ran in the copy, one at a time.

| Transcript | What |
|---|---|
| e5c-02 / e5c-03 | M14 on the new / the earlier nodes (R-DLG.2/1, AT-I12-1) |
| e5c-04 | QA-3: `down` removed |
| e5c-05 / e5c-06 / e5c-11 | QA-4: status written / Escape runs Generate / stray file |
| e5c-07 / e5c-08 | QA-5 late pop, new / earlier node |
| e5c-09 / e5c-10 | M14b, new / earlier nodes |
| e5c-12 | final: the two new Inc 12 files and the edited test files, `-n 8`, `-m "not serial_timing"` |
| e5c-13 | final: the 7 law guards |
| e5c-14 | final: `-m serial_timing -p no:xdist` over the files of e5c-12 |
| e5c-15 | the pinned I-3 grep |

Results are in the section "Final results" below.

## Final results

| Transcript | Result |
|---|---|
| e5c-12 | `444 passed, 1 xfailed` (the xfail is TC-065.a of `tests/test_tui_app.py`, the documented carry-over); 0 failed, 0 skipped. Files: `test_b101_reach_and_reports_escape`, `test_b101_shown_widgets`, `test_b101_help_legend_docs`, `test_b97_check_editor`, `test_id_registry`, `test_tui_app`, `test_tui_directionb`, `test_tui_goto_marker`, `test_tui_variants`, `test_window_usage_help` |
| e5c-13 | the 7 law guards: `221 passed` (`test_at_b78_03` is not in these files) |
| e5c-14 | `-m serial_timing -p no:xdist` over the e5c-12 files: `4 passed, 445 deselected`; `QC-TM: 4 bounds, 0 under 20 % margin` |
| e5c-15 | the pinned I-3 grep: exactly the 3 `window_help.py` lines (`:12`, `:627`, `:661`) |

`trace_check.py --req …/inc-12/01-requirements.md --base 6f1743c --src s19_app`: see `steps.log`. Windows: not run (nothing here imports `s19_app` on the Windows PC; no Windows-only arm in this increment). The remote clone `s19_i12c` and its mutant copy were removed at the end.
