# Inc 5 — E1 slice: functions to change

Base `c2cba35`. Rows: `01-requirements.md`. Design of each function: `codewire/graph-inc5.md`. Line numbers are the base's.

## 1. Source files (3 of the cap of 4)

`s19_app/tui/app.py`, `s19_app/tui/screens_directionb.py`, `s19_app/tui/crc_designer_view.py`. Not touched: `a2l_parameter_picker.py` (its `set_parameters`, `clear_picks` and `include_names` are used as they are), `services/change_service.py`, `changes/io.py`, `changes/apply.py`.

Docs, text only, not a source file (E4; E3 ruling SEC5-3 / A-3): `docs/user-guide/ch10-check-editor.md` §10.6 *Validate*, §10.7 *Write the spec*, §10.8 *Load a spec back* — state what `E1-rulings.md` §1 (5)–(7) admits: Validate compares a field loaded from a spec with the spec's bytes; Write keeps them (to re-baseline, exclude and include the parameter, or remove and add the memory row); a rewritten spec lists its parameters first; a parameter a new A2L moves, resizes or no longer lists comes back as an unlabelled memory row.

## 2. Functions (18: 13 changed, 5 new; #17 added at E3, #18 at E5)

| # | File | Function | Change | Rows |
|---|---|---|---|---|
| 1 | `app.py` | `S19TuiApp._note_image_bytes_written` | **new**: tell the CRC Designer that the loaded image's bytes were written in place; no-op when the panel is not mounted. E5 C-10: also clears the Check Editor's validation results (#18), queried separately | R-CRC-PREVIEW-002.1, -002.5, R-CHKED-057 |
| 2 | `app.py` | `S19TuiApp.on_patch_editor_panel_action_requested` (`:4733`) | changed: after the `try`/`except`, when the action is `apply_doc`, call #1 (both outcomes; never inside `if counts["applied"] > 0`, E3 A-2) | R-CRC-PREVIEW-002.5 (/3, /6, /8) |
| 3 | `app.py` | `S19TuiApp.on_patch_editor_panel_save_back_decision` (`:4943`) | changed: call #1 after `save_patched` returns, whatever `result.ok` (a save-back refused as blocked has reverted the image, E3 SEC5-2) | R-CRC-PREVIEW-002.5 (/4, /7) |
| 4 | `app.py` | `S19TuiApp._on_project_saved` (`:12560`) | changed: call #1 after `adopt_rederived` (only when the commit wrote the image) | R-CRC-PREVIEW-002.1 (/6), -002.5 (/5) |
| 5 | `app.py` | `S19TuiApp.on_check_editor_panel_spec_file_selected` (`:7449`) | changed: each item also carries `expected` (the entry's encoded bytes) and `symbol` (the resolved tag spelling or `None`) | R-CHKED-041.2, -026 |
| 6 | `app.py` | `S19TuiApp._check_items_to_document` (`:7283`) | changed: an item whose `expected` holds `size` bytes declares them without reading the image; other items read the image as on base | R-CHKED-025, -026, -027 |
| 7 | `crc_designer_view.py` | `CrcDesignerPanel.note_image_bytes_written` | **new**, public: delegates to `_on_image_changed` (`:679`, Inc 13) | R-CRC-PREVIEW-002.1, -002.5 |
| 8 | `screens_directionb.py` | `CheckEditorPanel.__init__` (`:7221`) | changed: adds `_spec_bytes: dict` (parameter name → `(address, size, bytes)` of its spec entry, E3 SEC5-1); memory rows become `(address, label, size, expected)` | R-CHKED-026, -056 |
| 9 | `screens_directionb.py` | `CheckEditorPanel.set_a2l_parameters` (`:7274`) | changed: on a real repopulation, turn each earlier pick loaded from a spec that the new ledger no longer lists at its spec entry's range into a memory row (#17, then the memory table rebuilt), re-include the other earlier picks the new ledger lists (earlier order), then prune `_spec_bytes` | R-CHKED-010, -055, -054, -056, -026 (/4) |
| 10 | `screens_directionb.py` | `CheckEditorPanel.load_spec` (`:7294`) | changed: include each entry's named parameter (entry order) with its spec entry `(address, size, bytes)`; other entries become unlabelled memory rows carrying their spec bytes | R-CHKED-041.1, -041.2, -041.3, -026 |
| 11 | `screens_directionb.py` | `CheckEditorPanel._named_parameter` | **new**: the named-parameter rule (symbol first, then the one parameter with the entry's address and byte count; `None` when none, ambiguous or already taken, or when the symbol names a listed parameter at another range — no address fallback, E3 A-6) | R-CHKED-041.2, -041.3 |
| 12 | `screens_directionb.py` | `CheckEditorPanel._collected_items` (`:7363`) | changed: each item gains `expected` (the spec's bytes when the field's current range is its spec entry's, else `None`); the four existing keys unchanged | R-CHKED-025, -026, -056 |
| 13 | `screens_directionb.py` | `CheckEditorPanel._rebuild_memory_table` (`:7345`) | changed: reads the 4-tuple rows (cells unchanged) | R-CHKED-041.3, -056 |
| 14 | `screens_directionb.py` | `CheckEditorPanel._add_memory_row` (`:7814`) | changed: appends `(address, label, size, None)` | R-CHKED-025 |
| 15 | `screens_directionb.py` | `CheckEditorPanel._on_a2l_parameter_picker_selection_changed` (`:7725`) | changed: prune `_spec_bytes` to the current picks before the preview refresh | R-CHKED-025 (/2), -026 |
| 16 | `screens_directionb.py` | `CheckEditorPanel._prune_spec_bytes` | **new**: keep only the `_spec_bytes` entries of currently included names whose ledger range is still their spec entry's | R-CHKED-025, -026, -055 |
| 17 | `screens_directionb.py` | `CheckEditorPanel._demote_moved_spec_params` | **new** (E3, SEC5-1 = A-1): for each earlier pick with a spec entry that the new ledger does not list at that entry's address and byte count (moved, resized or not listed), append the memory row `(address, default label, size, bytes)` and drop the name from `_spec_bytes`; return the earlier picks to re-include | R-CHKED-056, -010 |
| 18 | `screens_directionb.py` | `CheckEditorPanel.clear_check_results` | **new** (E5 C-10, SEC E5-S1): public; the Validate status line back to its mount text and the verdict rows removed; no tab switch, no focus move. #1 also calls it (changed at E5) | R-CHKED-057 |

Context (unchanged, read by the changed nodes): `CrcDesignerPanel._on_image_changed`, `on_show`, `_recompute` (Inc 13); `ChangeService.apply`, `save_patched`, `adopt_rederived`; `A2LParameterPicker.set_parameters`, `clear_picks`, `include_names`, `picked_params`, `param_rows`; `CheckEditorPanel.on_button_pressed` (Remove row pops by index, which keeps working with 4-tuples); `S19TuiApp._prefill_check_editor`; `read_change_document` (Inc 4: `entry.symbol`).

Every row maps to at least one function: R-CRC-PREVIEW-002.1 (#1, #4, #7), -002.5 (#1–#4, #7), R-CHKED-010 (#9, #17), -054 (#9), -055 (#9, #16, #17), -041.1 (#10), -041.2 (#5, #10, #11), -041.3 (#10, #11, #13), -025 (#6, #12, #14, #15, #16), -026 (#5, #6, #8, #9, #10, #12, #15, #16), -027 (#6), -056 (#8, #9, #12, #13, #17), -057 (#1, #18).

## 3. Nodes touched (existing tests)

| Node | What changes | Why |
|---|---|---|
| `tests/test_b101_symbol_reads.py::test_r_chg_sym_9_check_editor_spec_pick_resolves_symbols` | body only, name unchanged: `rows == 3` (memory rows) and the memory-table read of the symbol row become the field set: the symbol entry's tag is included, memory rows = 3 − the entries with a named parameter (counted from the generated A2L) | F-27 includes named parameters; the node's docstring says Inc 5 re-pins this count. The tag spelling becomes observable here (its E5 C-6 note "not-testable here" is lifted) |

No other existing node is expected to change: no test reads `_memory_rows` or the item dicts (grep, `c2cba35`); the picker tests that repopulate twice call `A2LParameterPicker.set_parameters` directly (`tests/test_b102_patch_picker.py`), which is unchanged; no test asserts that a repopulation clears the picks; the CRC Designer recompute counter is installed only in Inc 13's designer tests, which apply nothing. E4 confirms by running the Check Editor, picker, patch-editor and designer modules on the change and editing only nodes that turn RED for this reason.

New test file proposed: `tests/test_b101_check_spec_and_designer_writes.py` (E1-D8).
