# Unit FA-C7b — re-pin the tests to the C-7 design on alp [deepseek-v4-pro · medium]

Tree: `alp-e4r` at **`<sha after FA-C7 and FA-GC2T are both integrated>`** (one writer per file: FA-GC2T is the last chain-A writer of the Inc 2 file). HEAD check mandatory. Rules: `FB-common.md` + `FA-common-laptop.md`. No agent edits `~/.claude/skills`.

## Context
Run `git log -3 --oneline` and `git show --stat HEAD~…` to see FA-C7's product change in your tree.
- **What FA-C7 changed:**
  - `PatchEditorPanel.set_a2l_parameters(rows, signature=None, *, a2l_data=None, prepared_definitions=None)` takes everything from its caller.
  - The I-ALP-2.3 snapshot adapter (match / consume / invalidate the whole mapping before the fallback; unmounted → legacy) now lives in the app caller in `s19_app/tui/app/patch.py` (see the method around `:1860`; find its name).
  - Bulk-add is pushed by the app.
- **What FA-C7 reported RED:** these tests still drive the old seam. Their intent stays; only the seam moves (FB-common rule 5).

## Files you may edit
`tests/test_tui_patch_history_strip.py`, `tests/test_b103_picker_model.py`, `tests/test_alp_inc2_a2l_attach.py`.

## Rows (the first two are the G2b re-pins of `frontB\units\G2b.md`, applied to alp)
| row | change | negative control (scratch) → RED |
|---|---|---|
| 1 | `test_tui_patch_history_strip.py::test_tc081_2_strip`, §2.4-10 arm: look the strip members up through the class MRO, restricted to classes inside the `s19_app.tui.screens_directionb.patch_editor` package (Textual-inherited members do not count; keep the `dir(Widget)` collision assertion). | rename `_history_strip_text` in `patch_editor/actions.py` → RED |
| 2 | `test_b103_picker_model.py::test_r017_2_hostile_unit_is_replaced_literally`, patch arm: pass `a2l_data=app.current_a2l_data`. Leave the check arm alone. | make the panel ignore `a2l_data` → RED |
| 3 | `test_alp_inc2_a2l_attach.py`: the patch half of the `.037` adapter arms (~2172-2263 at fd8e744c: the stale-signature/source mismatch, the matching consumption and the unmounted `bare_patch` legacy call) drives the app caller found above instead of `patch.set_a2l_parameters(rows, key)`. Keep every assertion on mapping identity, invalidation order (invalidate before fallback), the describe counts and the unmounted survival. The check half is unchanged. Docstrings cite R-A2L-REFRESH.037 (E4R) and ruling R3. | in `patch.py`, skip the invalidation → the mismatch arm RED; read the mapping when unmounted → the unmounted arm RED |
| 4 | (added by the orchestrator, relevo-22, from FA-D10's report) `test_b103_picker_model.py::test_r018_2_changed_generation_batches_once_per_picker` and `::test_r018_4_live_reload_refreshes_both_without_reentry`: `assert len(describes) == 2` becomes `== 1`. Since FA-D10 the attach producer runs one shared bulk describe per generation for both pickers (operator D10; R-A2L-REFRESH.037 amended in E4R; R-PICKER-CORRECT.018 read as "at most one per picker"). Update r018_2's docstring ("one all-names call each" → one shared all-names call for both pickers, citing D10). Leave `test_r018_3` (its `== 2` still passes: it does not go through the producer). | in `file_load.py`, restore the second `describe_definitions` call → both RED (`2 == 1`) |

## Nodes you may run (`timeout 300`)
- `-n 0`: the three changed tests, `tests/test_tui_patch_card.py::test_tc080_2_c7_purity_probe`, `tests/test_tui_patch_checks_strip.py::test_tc078_2_aggregates_param`;
- `-n 4 -m "not serial_timing and not slow"`: the three files and `tests/test_b102_bulk_add.py tests/test_b103_picker_editor.py`.
