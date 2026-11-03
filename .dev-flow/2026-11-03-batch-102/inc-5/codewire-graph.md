# Code-Wire — Inc 5 — Patch Editor picker parity

Graph of the Patch parity slice. Requirements: `01-requirements.md`. Tests: `02-test-cases.md`.

## Nodes

A2LParameterPicker.__init__
req: R-B102-PE-002, R-B102-PE-006
in: A2LParameterPicker self; str id_prefix = "check_param"; str mode = "pick"; bool show_include_button = True; bool show_bulk_button = True; Callable layout_provider
out: None
func: changed constructor/config. Builds every child id and internal event route from `id_prefix`; accepts a proportional `layout_provider`; in `highlight` mode omits include/bulk controls, disables table include bindings/messages and exposes the highlighted row rather than a picked set. Check Editor keeps the default public ids and pick mode.
module: s19_app/tui/a2l_parameter_picker.py
examples: (TC-B102-PE-02) id_prefix `patch_param`, mode `highlight` → child ids include `#patch_param_filter`, `#patch_param_table`, `#patch_param_status`; zero ids start with `check_param`
examples: (TC-B102-PE-06) hostile name rendered by either mode → Parameter cell keeps sentinel with zero markup spans

PatchEditorPanel.compose
req: R-B102-PE-001, R-B102-PE-006
in: PatchEditorPanel self
out: ComposeResult
func: changed. Adds the `A2L` tab chip and pane to the inspector `ContentSwitcher`; the pane hosts one `A2LParameterPicker` in highlight mode with patch-prefixed ids and a patch-width `layout_provider` derived from the measured inspector.
module: s19_app/tui/screens_directionb.py
examples: (TC-B102-PE-01) panel composed → tabs are `Inspector`, `JSON`, `Checks`, `A2L`; selecting A2L shows the picker

S19TuiApp._prefill_patch_editor
req: R-B102-PE-001, R-B102-PE-005
in: S19TuiApp self
out: None
func: new/changed prefill on Patch screen activation. Computes measurable parameters and passes them to the Patch picker with `self._a2l_enriched_key`; same signature is a no-op, preserving filter/page/highlight.
module: s19_app/tui/app.py
examples: (TC-B102-PE-01) 10000 measurable rows, signature `("sig", 1)` → None; picker row count is `200`
examples: (TC-B102-PE-05) same signature after filter/page/highlight set → None; picker state is unchanged

A2LParameterPicker.highlighted_parameter
req: R-B102-PE-003
in: A2LParameterPicker self
out: dict? parameter
func: new read model for highlight mode. Returns the current visible row's source record (`name`, `address`, `size`, `fmt_unit`) or `None` when the cursor is out of range.
module: s19_app/tui/a2l_parameter_picker.py
examples: (TC-B102-PE-03) cursor on `TorqueMax` → parameter address `0x1000`, size `4`

PatchEditorPanel._use_highlighted_parameter
req: R-B102-PE-003, R-B102-PE-004
in: PatchEditorPanel self
out: None
func: new host action. Reads `highlighted_parameter`; with no row it paints `No parameter highlighted.`; otherwise writes Address as `0x%08X`, writes Bytes from the panel-retained current image map for `size` bytes, or clears Bytes and paints `Parameter address loaded; image bytes unavailable.` when no map/bytes exist. It posts no document action and leaves dirty state unchanged.
module: s19_app/tui/screens_directionb.py
modify: [UI: #patch_entry_address_input.value] (replace); [UI: #patch_entry_bytes_input.value] (replace)
examples: (TC-B102-PE-03) map `{0x1000:0xDE,0x1001:0xAD,0x1002:0xBE,0x1003:0xEF}` → Address `0x00001000`; Bytes `DE AD BE EF`; document entry count unchanged
examples: (TC-B102-PE-04) map `None` → Address populated; Bytes empty; status is `Parameter address loaded; image bytes unavailable.`

PatchEditorPanel._on_a2l_parameter_picker_view_changed
req: R-B102-PE-005, R-B102-PE-006
in: PatchEditorPanel self; A2LParameterPicker.ViewChanged event
out: None
func: new host listener for patch picker. Refreshes the A2L tab status/full-name surfaces after filter/page changes; does not touch document rows or entry inputs.
module: s19_app/tui/screens_directionb.py
examples: (TC-B102-PE-05) filter typed and page changed → None; picker state remains when screen is re-entered with same signature

## Entities

[Data: PatchEditorPanel._mem_map]
in: Mapping[int, int]
desc: image map retained by the panel for before/after rendering; read by `_use_highlighted_parameter` to seed Bytes.

[Data: A2LParameterPicker._signature]
in: object
desc: same safe A2L/image signature used by Check; prevents reset on screen activation.

[UI: Patch inspector ContentSwitcher]
in: tab id
desc: host of Inspector / JSON / Checks / A2L panes.

## Edges

S19TuiApp._prefill_patch_editor ──▶ A2LParameterPicker.set_parameters
PatchEditorPanel._use_highlighted_parameter ──▶ A2LParameterPicker.highlighted_parameter
[Data: PatchEditorPanel._mem_map] ──▶ PatchEditorPanel._use_highlighted_parameter
A2LParameterPicker.ViewChanged ──▶ PatchEditorPanel._on_a2l_parameter_picker_view_changed

## Findings

finding F-B102-PE-1 Patch lacks an A2L parameter selector
anchor: PatchEditorPanel.compose
seen: operator asks for the same usable selector as Check Editor
cause: batch-97 removed the old parameter section; only manual address/bytes entry remains
decision: add an A2L inspector tab reusing the shared picker in highlight mode

finding F-B102-PE-2 both editors mount simultaneously, so picker ids must be namespaced
anchor: S19TuiApp.compose
seen: CheckEditorPanel and PatchEditorPanel are both composed in the rail workspace
cause: reusing `check_param_*` ids would create duplicate DOM ids and break query_one/help/tests
decision: parameterize the component by id_prefix and use `patch_param_*` in Patch
