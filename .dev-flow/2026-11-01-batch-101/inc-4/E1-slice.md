# Inc 4 — E1 slice: functions to change, mapped to rows

Base `b7b77c4`. Line numbers are `b7b77c4`'s. Decisions D-1 … D-4: `E1-rulings.md` §3. The slice below assumes D-1 "delete" and D-2 "add `io.py`" (both recommended); §3 gives the slice under the fallbacks.

## 1. Source files (4 of the cap of 4)

| # | File | Function | Change | Rows |
|---:|---|---|---|---|
| 1 | `s19_app/tui/app.py` | `S19TuiApp._patch_editor_load` (`:7091`; call `:7106`) | `service.load(path_text, self.base_dir, a2l_context=self.current_a2l_data)` | R-CHG-SYM.9, .10 (alt. 1) |
| 2 | `s19_app/tui/app.py` | `S19TuiApp.on_patch_editor_panel_action_requested` (`:4719`), `parse_paste` arm only (`:4808-4810`) | `service.load_text(event.paste_text, a2l_context=self.current_a2l_data)` | R-CHG-SYM.9, .10 (alt. 2, and the second half of alt. 3) |
| 3 | `s19_app/tui/app.py` | `S19TuiApp._apply_changeset_json_edit` (`:5357`; pre-check `:5404`) | `parse_change_document(edited, a2l_context=self.current_a2l_data)` | R-CHG-SYM.9, .10 (alt. 3) |
| 4 | `s19_app/tui/app.py` | `S19TuiApp._apply_entry_json_edit` (`:5485`; call `:5523`) | passes `a2l_context=self.current_a2l_data` to `edit_entry_json`; after `_report_change_result(result)`, when `result.ok` is False, no A2L is loaded and a result issue has code `CHG-SYMBOL-UNRESOLVED` and holds the R-CHG-SYM.2 reason text (the `io.py` constant of D-2), one more `set_status` with the R-TUI-058.9 text | R-CHG-SYM.9, .10 (alt. 4), R-TUI-058.9 |
| 5 | `s19_app/tui/app.py` | `S19TuiApp.on_check_editor_panel_spec_file_selected` (`:7413`; read `:7437`) | `read_change_document(str(candidate), self.base_dir, a2l_context=self.current_a2l_data)` | R-CHG-SYM.9, .10 (alt. 5) |
| 6 | `s19_app/tui/app.py` | `S19TuiApp.on_ab_diff_panel_check_file_selected` (`:7727`; read `:7763`) | as 5 | R-CHG-SYM.9, .10 (alt. 6) |
| 7 | `s19_app/tui/services/change_service.py` | `ChangeService.edit_entry_json` (`:1452`; probe `:1516`) | new keyword parameter `a2l_context: Optional[dict] = None`, forwarded to `parse_change_document(envelope_text, a2l_context=a2l_context)`; docstring Args | R-CHG-SYM.9, .10 (alt. 4) |
| 8 | `s19_app/tui/services/change_service.py` | `run_checks_for_project` (`:3163-3260`) and the module docstring's paragraph on it (`:16-20`) | **deleted** (D-1, CODE-CHANGES D9-7); imports used only by it are removed after a grep of each | none (canon S9 review: "Removed (D9-7)") |
| 9 | `s19_app/tui/services/variant_execution_service.py` | `_execute_one_variant` (`:2478`; read `:2557`) | `read_change_document(str(file_path), project_dir, a2l_context=a2l_data)` (the `a2l_data` parameter it already receives from `execute_variant_plan`, parsed from the project's A2L file) | R-CHG-SYM.11, .12 |
| 10 | `s19_app/tui/changes/io.py` | `_parse_entries` (`:833`) | builds the tag-name index lazily (new `_symbol_name_index(a2l_context)`): on the first raw entry whose `symbol` is a string, at most once per read, then passes it to that and every later `_parse_entry`; a document with no such entry builds none (E3 A-2) | R-CHG-SYM.13, R-CHG-SYM.7 (kept) |
| 11 | `s19_app/tui/changes/io.py` | `_parse_entry` (`:898`) | takes the index (keyword `symbol_index`) instead of `a2l_context`; passes it to `_resolve_symbol_tag` | R-CHG-SYM.13 |
| 12 | `s19_app/tui/changes/io.py` | `_resolve_symbol_tag` (`:1062`) | looks the symbol up in the given index (`None` = no declared A2L); the three refusal texts unchanged, the no-context one read from the new constant | R-CHG-SYM.2 … .4 (kept), .7, .8 (kept), .13, R-TUI-058.9 (shared text) |
| 13 | `s19_app/tui/changes/io.py` | new `_symbol_name_index(a2l_context) -> Optional[dict[str, dict]]` and new constant `SYMBOL_NO_A2L_CONTEXT_TEXT = "no A2L context is declared for this change-set"` | the loop of `_resolve_symbol_tag` `:1102-1108` moved here unchanged (dict tags only, stripped non-empty names, lowercase key, first match wins); `None` for a context that is not a dict | R-CHG-SYM.13, .7 |

**Count: 13 changed functions or units in 4 source files** (6 in `app.py`, 2 in `change_service.py` of which 1 deleted, 1 in `variant_execution_service.py`, 4 in `io.py` with 1 new function and 1 new constant). No public signature changes except the added keyword `edit_entry_json(…, a2l_context=None)` and the removed `run_checks_for_project`. `read_change_document`, `parse_change_document`, `ChangeService.load`, `ChangeService.load_text`, `execute_variant_plan`, `execute_project_variants` are unchanged (context nodes in the graph).

**Under the fallbacks:** D-1 "keep" → row 8 becomes "parse `a2l_path` before the read and pass `a2l_context=a2l_data`" under `R-CHK-HEADLESS.1`, and the D-1 test-node removal is dropped. D-2 "no" → rows 10–13 drop, R-CHG-SYM.13 is withdrawn, row 4's condition uses the literal R-CHG-SYM.2 fragment `no A2L context is declared` in `app.py` with a comment naming R-CHG-SYM.2, and the file count is 3.

**Must not change:** `variant_execution_service._resolve_manifest_entry` (`:823`) and the plan side (`plan_variant_executions`, `:2396`) — Inc 9's (D15-18, S8-1, S8-2); `app.py:2520` `recorded_document_state` and the reopen (`:13893-13941`); the flow reads in `flow_execution_service.py`; the R-CHG-SYM.1 … .6 message texts.

## 2. Callers checked (rule 8)

- `ChangeService.load` — one product caller, `_patch_editor_load`, itself called from the typed Load arm (`:4807`), the dropdown pick (`:7085`, `:7089`) and the dirty-guard accept (`:7194`). It already accepts `a2l_context` (`change_service.py:1542`).
- `ChangeService.load_text` — one product caller, the `parse_paste` arm (`:4810`); `_apply_changeset_json_edit` reaches it by posting `parse_paste`. Already accepts `a2l_context` (`:1609`).
- `ChangeService.edit_entry_json` — one product caller, `_apply_entry_json_edit` (`:5523`), itself the callback of the per-entry popup pushed by `on_patch_editor_panel_entry_edit_json_requested` (draft-only guard `:5469-5474`).
- `read_change_document` in the two pick handlers — the result is used only in the handler (Check Editor: `load_spec(items)`; A2B Diff: `self._diff_check_spec`, read by the report request).
- `_execute_one_variant` — one caller, `execute_variant_plan` (`:2606`), which parses `a2l_path` once (`:2662`) and passes `a2l_data`; `execute_variant_plan` is called by `execute_project_variants` (`:2688`), which takes the A2L from `validate_project_files` (`:2743-2755`); its product callers are `app.py:6036` (Execute scope worker) and `app.py:6566` (report run).
- `run_checks_for_project` — no product caller (`grep -rn "run_checks_for_project(" s19_app`: only its definition and docstrings). Test caller: `tests/test_checks_engine.py:348` (and the import `:46`).
- `_resolve_symbol_tag`, `_parse_entry`, `_parse_entries` — private to `io.py`; no test calls them (`grep` in `tests/`: one docstring mention, `tests/test_changes_symbol_entries.py:40`).
- `S19TuiApp.current_a2l_data` — written only by `_replace_current_a2l` (`app.py:19542`), read on the screen thread.

## 3. Tests: nodes touched (keep every other node name stable)

| Node | Why | Change |
|---|---|---|
| `tests/test_checks_engine.py::test_headless_project_run` | D-1 deletes the function it calls | **removed** (only if D-1 is ruled "delete"); the import at `:46` goes with it; the module docstring's TC-023 bullet (`:18-20`) updated |
| `tests/test_tui_patch_editor_v2.py::test_repopulate_blank_reset_posts_no_spurious_load` | its spy `_spy_load(path, base_dir)` (`:1634`) replaces `ChangeService.load` and would raise `TypeError` on the new `a2l_context=` keyword | the spy accepts and forwards `**kwargs`; assertions unchanged |
| `tests/test_tui_patch_editor_v2.py::test_tc329_popup_seed_and_load_text_apply_seam` | its spy `_spy(text)` (`:3443`) replaces `ChangeService.load_text`, same reason | the spy accepts and forwards `**kwargs`; assertions unchanged |
| `tests/test_checks_engine.py::test_no_textual_in_static_import_graph` | its docstring (`:411`) names the deleted headless entry point (E3 A-8) | docstring text only; the test body and its assertion unchanged |
| `AT-TC-REGISTRY.jsonl` TC-023 (`:610`, `LIVE`) — data file, not a test | its `nodes` list `tests/test_checks_engine.py::test_headless_project_run`; `tests/test_id_registry.py::test_tc601_g2_live_entries_name_existing_nodes` goes RED once the node is deleted (E3 A-1) | drop that one node; TC-023 stays `LIVE` with its other 10 nodes. Edited at integration by the requirements/test-case session, not by Inc 4's records. E4's targeted run adds `tests/test_id_registry.py` |

Census behind the list: `grep -rn "\.load = \|\.load_text = \|\.edit_entry_json = \|setattr(.*\(load\|load_text\|edit_entry_json\|read_change_document\|parse_change_document\))" tests` → the two spies above only. Tests that parse with an explicit `a2l_context` (`tests/test_changes_symbol_entries.py`, `tests/test_synth_release_case.py`, `tests/test_b100_document.py`) call the reader directly and keep their expectations; `test_tc712_no_context_refuses_symbol_entry_no_implicit_a2l` still holds (the reader is unchanged for `None`). No existing test drives an editor surface with a symbol document and the A2L loaded (census: files holding `"symbol"` and an editor or execution entry point → `tests/test_b97_patch_editor.py` only, where `"symbol"` is an arm label, not a document field).

New tests (E4, proposed homes; tests are not capped): `tests/test_b101_symbol_reads.py` (new file, R-CHG-SYM.9 … .13, R-TUI-058.9). A new file means `tests/test_id_registry.py`'s `EXPECTED_SCANNED_TEST_FILES` is re-measured at integration (brief rule). Proposed node names carry the `test_r_<id>` prefix (`02-test-cases.md`).

## 4. Interfaces with other increments

- **Inc 5** (F-26, F-27; `app.py`, `screens_directionb.py`): edits `on_check_editor_panel_spec_file_selected` too. This increment changes only the read call (`:7437`); Inc 5 re-resolves names from the loaded A2L by address in the items it builds after the read. Merge: same function, different lines; whoever merges second rebases. A resolved symbol entry now carries `ChangeEntry.symbol` = the tag's spelling (R-CHG-SYM.8), which Inc 5 may use as the name.
- **Inc 6** (F-40, F-06; `app.py`, `change_service.py`): edits `_patch_editor_load_tail` and the load arms' neighbourhood; this increment changes the line before the tail (`:7106`) and the `parse_paste` call (`:4810`). Disjoint lines; both touch `change_service.py` (Inc 6: `last_check_result`; here: `edit_entry_json`, `run_checks_for_project`).
- **Inc 9** (D15-18, S8-1/S8-2 on `variant_execution_service._resolve_manifest_entry`): this increment does not touch `_resolve_manifest_entry` or the plan. The interface is the `files` sequence `_execute_one_variant` receives: already resolved, in plan order; Inc 9 may refuse more entries before they reach it, and this increment's read does not re-resolve them.
- **Inc 14** (help and docs): the user-guide sentences listed in `E1-rulings.md` §4.
