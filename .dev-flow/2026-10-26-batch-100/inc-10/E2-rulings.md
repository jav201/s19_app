# Inc 10 — E2 orchestrator rulings (after the baseline)

| Id | Ruling | Design effect |
|---|---|---|
| Q-1 … Q-7 | As in `codewire/interfaces-10.md` §Orchestrator rulings. | interfaces fixed |
| Undo boundary | Restate LLR-174.1 and HLR-174a: a patch counts as unsaved while the image differs from the last loaded or saved image. `undo()` alone (ctrl+z) leaves the patched byte, so the question asks. The design follows the probe (`p10b-undo`). The requirement text is corrected in the draft. | draft text, G-B examples |
| `_pending_variant_id` | `_handle_select_variant` sets `_pending_variant_id` only inside `go`. A cancelled question leaves it unchanged. Add an example. | G-B node + example; draft gets one unwanted-form LLR (LLR-174.3d) |
| Census | The breaking set is: `test_at_b100_03…[size0/1]`; TC-B100-10 (`test_b100_session_reset.py:587`, `:629`); and `test_tc_b99_40_strip_shows_new_file_source_byte` (`test_b99_editor_image.py:468`), which is new; the tester re-pins it to answer `y`. Strike `test_tui_patch_variant.py`, `test_b100_active_variant.py` and `test_loadfilescreen_input.py` from E1's first-cut list. Reset stubs: 4 sites, all passing. | scope test notes |
| `ConfirmDiscardScreen` | Not reused; the new modal stands (E1 decision confirmed by probe U12). | — |
| G-B P-1 | **Accept.** The MAC test and the target name use `Path(str(path).strip().strip('"'))`, the same strip as the classifier (C35). | G-B |
| G-B P-2 | **Accept.** The LLR-174.4 AST census rule: the three loaders and `_handle_load_project` may be called only inside a `go` passed to the seam, inside `_handle_load_project`, or as `load_from_path`'s worker start. Callers of `_route_load_project` are exempt, and the `on_mount` exemption is dropped. | draft LLR-174.4 text (design-fix at E3) |
| G-B P-3 | **Accept.** Owed in the draft: replace "applied then undone → 0 questions" with "undo alone asks (C13); undo then Apply does not (C12)". Add LLR-174.3d: "If the engineer cancels the question of a variant switch, then the system shall leave the pending variant selection unchanged." (C42). Applied by the E3 design-fix pass. | draft |
| G-A P-GA10-1 | **Option A.** Labels are `rich.text.Text(label)`, which is already imported, paints literally and adds no new module, so TC-B100-64 stays green. Interface S-a now reads "labels as `rich.text.Text`". This supersedes the Q-1 wording. | interfaces S-a; G-A nodes |
| G-A P-GA10-2 | **Accept.** LLR-174.2r's negative controls become `min-width: 120` on `#confirm_box`, plus undocked buttons with a 7-row height. Both are executed and both go RED. The statement says "fully visible": the button's region equals its clipped region. The body must also be fully visible. | draft LLR-174.2r (design-fix at E3) |
| Q-6 (probe) | **Settled.** `styles.tcss` is unchanged, and the slice is 3 source files: `screens.py`, `screens_directionb.py`, `app.py`. | scope |
