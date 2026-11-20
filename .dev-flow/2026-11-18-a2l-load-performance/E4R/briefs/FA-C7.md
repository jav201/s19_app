# Unit FA-C7 — C-7 on alp: the Patch panel stops reaching the app (4 → 0 sites) [deepseek-v4-pro · high]

Tree: `alp-e4r` at **`ec8e7bd4`** (HEAD check mandatory). Rules: `FB-common.md` + `FA-common-rtx.md` (this unit runs on rtx, P-202). No agent edits `~/.claude/skills`.

## Fixed diagnosis (R2-F7, R6-F3, operator D4; re-checked by the architect)
C-7 (LLR-078.2) requires `PatchEditorPanel` to be presentational, with 0 `self.app` reaches in its class tree. On alp, `s19_app/tui/screens_directionb/patch_editor/a2l_picker.py` reaches the app at 4 sites:
- `:43` `getattr(self.app, "current_a2l_data", None)` (from main, Inc 6);
- `:45` reads `self.app._accepted_a2l_picker_snapshots` (alp Inc 2);
- `:52` writes `self.app._accepted_a2l_picker_snapshots = MappingProxyType({})` on a mismatch (alp Inc 2);
- `:140` `self.app.push_screen(BulkParameterAddScreen(...), self._on_bulk_add_closed)` (from main).

`main`'s two sites are already fixed on `b103-fix-round` by unit G2 (`6480aab6`). The orchestrator copies its diff (`frontB\diffs\G2.diff` in the review folder) to `../G2.diff` before launch.

## Fixed design
1. **Port G2's product hunks verbatim** (only `s19_app/tui/app/patch.py` and `.../patch_editor/a2l_picker.py`; not its test hunks). Adjust context only.
   - `set_a2l_parameters(self, rows, signature=None, *, a2l_data=None)`.
   - The app caller (`patch.py:1860` on alp) passes `a2l_data=self.current_a2l_data`.
   - The panel's bulk-add handler and `_open_parameter_bulk_add` are removed. The picker's `BulkAddRequested` bubbles to a new app handler `on_a2l_parameter_picker_bulk_add_requested`, which pushes `BulkParameterAddScreen(panel._a2l_picker)` with `panel._on_bulk_add_closed`.
   - Using identical text keeps the later merge with `main` mechanical.
2. **The snapshot adapter of interfaces I-ALP-2.3 moves to the app caller** in `patch.py` (ruling R3 in `E4R/E4R-rulings.md`). Next to the G2 change, the caller:
   - reads `entry = getattr(self, "_accepted_a2l_picker_snapshots", MappingProxyType({})).get("patch")`;
   - **if `panel.is_mounted` is False:** calls `panel.set_a2l_parameters(measurable, key)` (legacy: no data, no mapping read, no invalidation; the snapshot survives for a later mount);
   - **elif `entry` is present and `entry.signature == key and entry.a2l_source is self.current_a2l_data`:** calls `panel.set_a2l_parameters(measurable, key, a2l_data=self.current_a2l_data, prepared_definitions=entry.definitions)`;
   - **elif `entry` is present (mismatch):** first `self._accepted_a2l_picker_snapshots = MappingProxyType({})`, then the call with `a2l_data` only (invalidate before the fallback runs);
   - **else:** the call with `a2l_data` only.
3. **The panel's `set_a2l_parameters` gains `prepared_definitions=None`.**
   - Not mounted → `self._a2l_picker.set_parameters(rows, signature, a2l_data=None)` (legacy).
   - Mounted → forwards `a2l_data` and, when given, `prepared_definitions` to `set_parameters` exactly as today's two branches do.
   - No `self.app` anywhere in the class tree. Docstrings name C-7 and I-ALP-2.3.

## Files you may edit
`s19_app/tui/screens_directionb/patch_editor/a2l_picker.py`, `s19_app/tui/app/patch.py`. No test file: FA-C7b re-pins the tests after you.

## Rows
| row | change | negative control (scratch) → RED |
|---|---|---|
| 1 | design 1 (G2 port) | re-add `getattr(self.app, "current_a2l_data", None)` in the panel → `tests/test_tui_patch_card.py::test_tc080_2_c7_purity_probe` |
| 2 | design 2 (adapter in the caller) | Deferred to FA-C7b row 3: today's `.037` arms call the panel directly, so they cannot see the caller. Here, paste the `-k r037` result and name every arm that changes outcome. |
| 3 | design 3 (panel forwards only) | re-add the `:45` read → probe RED |

## Expected RED until FA-C7b (do not fix tests; list them)
- `test_tui_patch_history_strip.py::test_tc081_2_strip` (MRO arm; on main it was masked behind C-7);
- `test_b103_picker_model.py::test_r017_2_hostile_unit_is_replaced_literally` (patch arm calls without `a2l_data`);
- the patch half of the `.037` arms in `test_alp_inc2_a2l_attach.py` (~1900-2020) that call `patch.set_a2l_parameters(rows, key)` directly and expect the panel to consume or invalidate.

## Nodes you may run (`timeout 300`)
- `-n 0`: `tests/test_tui_patch_card.py::test_tc080_2_c7_purity_probe`, `tests/test_tui_patch_checks_strip.py::test_tc078_2_aggregates_param`, `tests/test_tui_patch_history_strip.py::test_tc081_2_strip`;
- `-n 4` (at most 4 files per run): every file from `git grep -l BulkParameterAddScreen -- tests`, `tests/test_b103_picker_*.py`, `tests/test_import_census.py`;
- `tests/test_alp_inc2_a2l_attach.py -k r037 -n 0`.
