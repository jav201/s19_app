# Inc 4 — E5 mutation testing (documents resolve symbols through the loaded A2L)

Batch 2026-11-01-batch-101, increment 4, branch `b101-inc4` (head `149e3bf`,
base `b7b77c4`). Stage E5 of the design-first flow. Mutants M-1 … M-15 are the
"Negative control" seeds of `02-test-cases.md` — one per requirement row of
`01-requirements.md` (R-CHG-SYM.9 … .13, R-TUI-058.9) — plus the controls named
in `E1-rulings.md`, `E3-rulings.md` and `E4-integration-notes.md`.

## Method

- Platform: the LAN Linux host only (operator rule; no run on the Windows PC).
  Interpreter: the `s19ci` Python 3.11 environment.
- Remote worktree: a detached worktree of `origin/main` with the branch diff
  `git diff b7b77c4 149e3bf` applied and committed (so `git checkout -- .`
  restores the exact pre-mutant bytes). Removed at the end of the run.
- One mutant at a time, in the four slice files only (`s19_app/tui/changes/io.py`,
  `s19_app/tui/services/change_service.py`,
  `s19_app/tui/services/variant_execution_service.py`, `s19_app/tui/app.py`):
  apply it, print `s19_app.__file__` (every transcript shows
  `<HOME>/work/s19_m4/s19_app/__init__.py`), run the cited test nodes, then
  `git checkout -- .` and compare the sha256 of the four slice files to the
  pre-mutant values (every run reports `RESTORE_OK`).
- Baseline (`mut-00-base.txt`): the full new test file ran once on the
  unmutated copy — 22 passed (`-n 2 -m "not serial_timing"`) and 2 passed
  (`-m serial_timing`, serial). All green.
- Timing controls (R-CHG-SYM.13): M-10 runs `-m serial_timing` without `-n`;
  M-15 runs its call-counter node without `-n`. Every other mutant runs its
  cited nodes with `-n 2`.
- Transcripts are redacted to `<HOME>` / `<USER>`; the host is named
  "LAN Linux host". Transcript path column is relative to
  `.dev-flow/2026-11-01-batch-101/evidence/inc-4/`.

## Mutant table

| id | requirement | mutation | tests (in `tests/test_b101_symbol_reads.py`) | result | transcript |
|---|---|---|---|---|---|
| M-1 | R-CHG-SYM.9 alt. 1 | Patch Editor file load passes no A2L (`_patch_editor_load` drops `a2l_context=self.current_a2l_data`) | `test_r_chg_sym_9_patch_editor_file_load_resolves_symbols_through_the_loaded_a2l` | KILLED | mut-01.txt |
| M-2 | R-CHG-SYM.9 alt. 2 | Paste arm passes no A2L (`parse_paste` drops `a2l_context=…`) | `test_r_chg_sym_9_paste_resolves_symbols_through_the_loaded_a2l` | KILLED | mut-02.txt |
| M-3 | R-CHG-SYM.9 alt. 3 | Whole-document Edit JSON pre-check passes no A2L (`_apply_changeset_json_edit` drops `a2l_context=…`) | `test_r_chg_sym_9_whole_document_edit_json_confirm_resolves_symbols` | KILLED | mut-03.txt |
| M-4 | R-CHG-SYM.9 alt. 4 | Per-entry Edit JSON confirm passes no A2L (`_apply_entry_json_edit` drops `a2l_context=…`) | `test_r_chg_sym_9_per_entry_edit_json_confirm_of_a_symbol_entry_succeeds` | KILLED | mut-04.txt |
| M-5 | R-CHG-SYM.9 alt. 5 | Check Editor Spec pick passes no A2L (`on_check_editor_panel_spec_file_selected` drops `a2l_context=…`) | `test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols` | KILLED | mut-05.txt |
| M-6 | R-CHG-SYM.9 alt. 6 | A2B Diff check-spec pick passes no A2L (`on_ab_diff_panel_check_file_selected` drops `a2l_context=…`) | `test_r_chg_sym_9_ab_diff_check_spec_pick_resolves_symbols` | KILLED | mut-06.txt |
| M-7 | R-CHG-SYM.10 | A read declares the project's A2L file when no A2L is loaded (site 6 parses `validate_project_files`' A2L instead of `current_a2l_data`) | `test_r_chg_sym_10_reads_with_no_a2l_loaded_declare_none[ab-diff-project-a2l-not-implicit]` | KILLED | mut-07.txt |
| M-8 | R-CHG-SYM.11 | `_execute_one_variant` passes no A2L (drops `a2l_context=a2l_data`) | `test_r_chg_sym_11_variant_run_declares_the_project_a2l_file`; `test_r_chg_sym_11_execute_scope_applies_symbol_entries_by_keys` (2 arms); `test_r_chg_sym_11_report_run_declares_the_project_a2l_file` | KILLED (4 failed) | mut-08.txt |
| M-9 | R-CHG-SYM.12 | A fallback context in the variant read (`a2l_context=a2l_data or {}`) | `test_r_chg_sym_12_variant_run_without_a_project_a2l_declares_none` | KILLED | mut-09.txt |
| M-10 | R-CHG-SYM.13 | The tag-name index rebuilt for each symbol entry (lazy `index_built` gate removed) | `test_r_chg_sym_13_symbol_read_of_1000_entries_by_220040_tags_builds_the_index_once` (`serial_timing`) | KILLED (index built 1 000×) | mut-10.txt |
| M-11 | R-TUI-058.9 | The plain-language line keyed on the finding code alone (drops the `SYMBOL_NO_A2L_CONTEXT_TEXT in message` check) | `test_r_tui_058_9_entry_edit_with_a_non_string_symbol_paints_no_plain_line` | KILLED | mut-11.txt |
| M-12 | R-TUI-058.9 | The plain-language line removed | `test_r_tui_058_9_entry_edit_without_a2l_ends_on_the_plain_line` | KILLED | mut-12.txt |
| M-13 | R-TUI-058.9 | The "no A2L is loaded" guard dropped from the line's condition | `test_r_tui_058_9_entry_edit_with_an_unknown_symbol_paints_no_plain_line` (arm b) | KILLED | mut-13.txt |
| M-14 | R-CHG-SYM.11 / .12 | The variant run fed the session A2L instead of the project's A2L file (module `SESSION_A2L_DATA` set from `current_a2l_data`, used by `_execute_one_variant`) | `test_r_chg_sym_11_execute_scope_applies_symbol_entries_by_keys[session-a2l-unloaded]`; `test_r_chg_sym_12_session_a2l_does_not_reach_a_project_without_a2l` | KILLED (2 failed; the loaded-session arm still passes) | mut-14.txt |
| M-15 | R-CHG-SYM.13 | The tag-name index built eagerly before the loop | `test_r_chg_sym_13_read_without_symbol_entries_builds_no_index` | KILLED (address-only read builds 1) | mut-15.txt |

## Score

**15 / 15 killed, 0 survived, 0 N/A.**

Every negative control turns its cited case RED exactly as the design predicted:

- M-1 … M-6 → each session-read alternative paints the `CHG-SYMBOL-UNRESOLVED`
  no-context finding (or the base refusal) instead of the resolved load.
- M-7 → the A2B Diff pick inside an open project loads `demo_check.chk.json`
  (the project's A2L is used implicitly) instead of refusing.
- M-8 → all three variant-run surfaces block the change document / report no
  patched file.
- M-9 → the fallback `{}` context turns the no-context findings into
  "resolves to no tag" findings, so the `no A2L context` assertion fails.
- M-10 → `_symbol_name_index` is called 1 000 times for a 1 000-entry read
  (the counter oracle fires; 64 s wall clock).
- M-11 / M-13 → the plain-language line is painted where it must not be.
- M-12 → the plain-language line is gone.
- M-14 → with the session A2L unloaded the run is blocked (arm b), and with it
  loaded it reaches a project that has no A2L file and writes a patched file.
- M-15 → an address-only read builds the index once (eager) instead of none.

No survivors, so there are no equivalent mutants and no missing-assertion gaps
to report. The M-10 timing control was run serial (`-m serial_timing`, no `-n`)
as required, and its wall clock (64 s for the per-entry rebuild) is consistent
with the E1 projection, far above the 1.0 s bound the test enforces.
