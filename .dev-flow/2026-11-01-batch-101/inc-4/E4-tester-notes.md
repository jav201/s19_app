# Inc 4 — E4 tester notes

Batch 2026-11-01-batch-101, increment 4. Independent tester (E4). Written from the approved design only (`01-requirements.md`, `02-test-cases.md`, `codewire/graph-inc4.md`, `E1-slice.md`, `E1-rulings.md`, `E3-rulings.md`). Evidence state of everything below: **executed on the base revision** (RED/holds-on-base); **not-run against the implementation** (the implementer's tree was not used; GREEN is the integration run).

## 1. Files

- New: `tests/test_b101_symbol_reads.py` (24 collected cases = 18 test functions; parametrized: R-CHG-SYM.10 ×6, R-CHG-SYM.11/2 ×2 arms).
- Re-pinned (names unchanged): `tests/test_tui_patch_editor_v2.py::test_repopulate_blank_reset_posts_no_spurious_load` and `::test_tc329_popup_seed_and_load_text_apply_seam` (spies accept and forward `**kwargs`); `tests/test_checks_engine.py::test_no_textual_in_static_import_graph` (docstring text only).
- Not touched: `tests/test_checks_engine.py::test_headless_project_run` (the integrator removes it with its registry row); source files (0 edited).
- `02-test-cases.md`: tests column only (R-CHG-SYM.11/2 arms named; R-CHG-SYM.13/1 row also names the A-7 measurement test).

## 2. Test → case mapping

Full = the product itself produces what the test asserts. All cases run on the LAN Linux host.

| Case | Test (in `tests/test_b101_symbol_reads.py`) | Fidelity | On base |
|---|---|---|---|
| R-CHG-SYM.9/1 | `test_r_chg_sym_9_patch_editor_file_load_resolves_symbols_through_the_loaded_a2l` | full (image and A2L through the Load dialog; pick by `Select.value`) | RED: `Loaded change: 5 entries, 2 error(s)` + 2 findings |
| .9/2 | `test_r_chg_sym_9_paste_resolves_symbols_through_the_loaded_a2l` | full (Parse paste button) | RED: same lines |
| .9/3 | `test_r_chg_sym_9_whole_document_edit_json_confirm_resolves_symbols` | full; draft installed through the service with an explicit context so it does not depend on the paste read | RED: `Edit JSON refused: …` |
| .9/4 | `test_r_chg_sym_9_per_entry_edit_json_confirm_of_a_symbol_entry_succeeds` | full (same draft setup) | RED: rejection line + no-context finding |
| .9/5 | `test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols` | full | RED: `Check Editor: spec NOT loaded.` |
| .9/6 | `test_r_chg_sym_9_ab_diff_check_spec_pick_resolves_symbols` | full | RED: `Check spec not loaded — [CHG-SYMBOL-UNRESOLVED] …` |
| .10/1 … /6 | `test_r_chg_sym_10_reads_with_no_a2l_loaded_declare_none[file-load\|paste\|edit-json\|entry-json\|check-editor\|ab-diff-project-a2l-not-implicit]` | full | holds on base (negative controls): 6 pass |
| .11/1 | `test_r_chg_sym_11_variant_run_declares_the_project_a2l_file` | full (service level, one project per run) | RED: 2 unresolved findings in run 1 |
| .11/2 | `test_r_chg_sym_11_execute_scope_applies_symbol_entries_by_keys[session-a2l-loaded\|session-a2l-unloaded]` | full for the product output (patched bytes read with the independent S19 reader); drive fidelity partial (below) | RED: no `firmware-patched.s19` (run itself ends `Execute: scope 'all' finished - 1 variant(s), 0 error(s)`) |
| .11/3 | `test_r_chg_sym_11_report_run_declares_the_project_a2l_file` | full (Reports screen, Generate) | RED: no patched file |
| .12/1 | `test_r_chg_sym_12_variant_run_without_a_project_a2l_declares_none` | full | holds on base |
| .12/2 | `test_r_chg_sym_12_session_a2l_does_not_reach_a_project_without_a2l` | full for the output; premise adjusted (ambiguity 1) | holds on base |
| .13/1 | `test_r_chg_sym_13_symbol_read_of_1000_entries_by_220040_tags_builds_the_index_once` (`serial_timing`) | full | RED: index built 0 times (no builder); the read took 81.54 s |
| .13/2 | `test_r_chg_sym_13_read_without_symbol_entries_builds_no_index` | full | arm 1 (address-only, counter 0) holds on base; arm 2 (`demo_patch`, counter 1) RED |
| .13/3 (A-7) | `test_r_chg_sym_13_whole_document_edit_json_confirm_of_1000_entries_by_220040_tags` (`serial_timing`) | measurement | RED: `Edit JSON refused: change text carries 1000 error(s)` |
| R-TUI-058.9/1 | `test_r_tui_058_9_entry_edit_without_a2l_ends_on_the_plain_line` | full | RED: 2 lines, no plain line |
| .9/2 | `test_r_tui_058_9_entry_edit_with_a_non_string_symbol_paints_no_plain_line` | full | holds on base (guards mutant M-11) |
| .9/3 (arms a, b) | `test_r_tui_058_9_entry_edit_with_an_unknown_symbol_paints_no_plain_line` | full | RED: base paints the no-context finding, not the "resolves to no tag" one |

Names: the two R-CHG-SYM.13 timing tests carry the `…_of_1000_entries…` names given at E4 integration (F-1; the registry reads `_at_<digits>` as an AT id). This table was updated at the E5 corrective pass (ruling C-5); the base RED results are the tester's, taken under the old names.

Uncovered: none of the 22 cases is uncovered. E5 mutants M-1 … M-15 are E5's to run; the table above names which test each one should turn RED.

## 3. RED summary (base = origin/main `4648972c`, a descendant of the branch base `b7b77c4`; Inc 4 changes nothing there)

Command and transcript: `.dev-flow/2026-11-01-batch-101/evidence/inc-4/red-01-tester-base.txt` (`s19_app.__file__` printed first: the temporary base worktree). Result: **15 failed, 12 passed** in 412 s. The 15 fail for behavioural reasons (the table). The 12 passes are: the 6 R-CHG-SYM.10 negative controls, R-CHG-SYM.12/1 and /2, R-TUI-058.9/2, and the 3 re-pinned existing nodes — they hold on base by design (negative controls, and the spies forward `**kwargs`). They are not RED claims.

Oracle controls run on the LAN host, outside the repo:
- **GREEN rehearsal.** A throwaway copy of origin/main carrying a minimal tester-written reading of the *design* (the six `a2l_context=` pass-throughs, the `edit_entry_json` parameter, the lazy `_symbol_name_index`, the plain line) was used to see every test go green: **22 passed** non-timing, **both timing tests pass**. This is a control of the tests, not evidence of the implementation. The implementer's in-progress tree was not run.
- **Re-pin necessity.** The original spies fail against that rehearsal tree with `TypeError … unexpected keyword argument 'a2l_context'`; the re-pinned ones pass.
- Rehearsal measurements (LAN Linux host, reference only, **not the product**): one read of 1 000 symbol entries × 220 040 tags 0.18 s (5 runs, 0.182–0.188 s); whole-document confirm 1.037 s without symbols, 1.484 s with symbols, so the resolution adds 0.447 s for its two reads. The integration run re-measures on the implementer's code; the row's stop rule (E4 measures more than 0.5 s) is judged on that run.

## 4. Cases not expressible as written, and how they were realized

- **R-CHG-SYM.12/2 premise.** On origin/main, attaching an A2L while a project is open **copies it into the project folder**. The literal steps (open a project with no A2L file, attach `firmware.a2l`, Execute) therefore give a project that now has an A2L file, and a patched file is legitimate (seen in the rehearsal). The test removes the copied file after the attach (and asserts the session A2L is still loaded), so the run reads a project folder with none. Needs a ruling if the row means something else (ambiguity 1).
- **"Black-box … keys, clicks"**: the Load dialog (path typed, Load clicked), the `p` project row, the screen keys `6`, `7`, `=` are real keys. Three gestures are not: dropdown picks assign `Select.value` (the repo's idiom), Execute scope / Generate / Parse paste / popup Confirm use `Button.press()`, and the A2L unload posts `LoadedArtifactsPanel.UnloadRequested("a2l")` to the app handler. Product output is still what is asserted.

## 5. Ambiguities (not resolved by reading the implementation)

1. **A2L attach syncs into an open project** (above). Is "a project with no A2L file" for R-CHG-SYM.12 the folder state at run time (as tested)? Answer owed by `qa-reviewer`/architect.
2. **R-CHG-SYM.13/3 threshold.** A-7 says "no design change unless it exceeds the bound". The whole confirm renders 1 000 rows (about 1 s on the host, with or without symbols), so the clock of the whole confirm is not R-CHG-SYM.13's. The test bounds the **added** cost (with-symbols minus the same document without symbols) at 2 × 1.0 s and prints it. The orchestrator should confirm that reading.
3. **R-CHG-SYM.13/1 bound** stays 1.0 s (the row); the E4 stop rule (> 0.5 s) cannot be judged until the implementer's tree is run; the rehearsal reference gives 0.19 s.
4. **Collector rows (R-CHG-SYM.9/5)** are counted as `#check_mem_table` rows (3 today, unlabelled). Inc 5 changes how the rows are built and must re-pin this count.
5. **Report format (R-CHG-SYM.11/3)**: the assertion reads the Markdown `Modifications` rows (`| 0x… | n | before | after | linkage | Symbol |`, symbol Markdown-escaped, `VALUE\_0185`) and the overview applied count (>= 2, 7 expected). A change of report layout re-pins it.
6. **`tests/test_id_registry.py`** was not run: the new file raises `EXPECTED_SCANNED_TEST_FILES` (250 → 251, to be re-measured at integration) and TC-023's `nodes` still lists the headless node until the registry row is edited. Both are the integrator's.
7. **Disclosure.** Early on I read the working-tree `app.py` / `change_service.py` around the call sites and saw the implementer's in-progress `a2l_context=` edits. Nothing in the tests was derived from them; the design records and base sources (`git show HEAD:`) were the only inputs after that.

## 6. Environment limits

No pytest on the Windows PC (operator rule); everything ran on the LAN Linux host (Python 3.11, `s19ci`). Textual pilot timing on a shared host: the Execute and report cases poll with `wait_until` (60 s ceiling). The Windows-only behaviours of the repo are untouched by this file. The temporary worktrees on the host were removed at the end.
