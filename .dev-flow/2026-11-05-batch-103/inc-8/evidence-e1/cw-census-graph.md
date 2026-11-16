# Inc 8 E1 census graph (context only: the existing functions in scope; no prototype)

## Nodes

LayoutMixin.compose
req: R-TUI-063.1
in: 
out: ComposeResult tree
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/layout.py
examples: (baseline) census only

LayoutMixin._apply_layout
req: R-PE-DEF.6
in: 
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/layout.py
examples: (baseline) census only

PatchEditorPanel.__init__
req: R-TUI-063.3
in: 
out: PatchEditorPanel panel
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (baseline) census only

PatchEditorPanel._refresh_inspector_subtitle
req: R-PE-041
in: 
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (baseline) census only

PatchEditorPanel.set_image_mem_map
req: R-PE-DEF.18
in: Optional[Mapping[int, int]] mem_map
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (baseline) census only

PatchEditorPanel.on_mount
req: R-TUI-063.4
in: 
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (baseline) census only

PatchEditorPanel._show_tab
req: R-TUI-063.6
in: str chip_id
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (baseline) census only

EntriesMixin.refresh_entries
req: R-PE-DEF.62
in: Sequence[object] rows; object mem_map = _UNSET; object document = _UNSET
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/entries.py
examples: (baseline) census only

A2lPickerMixin.set_a2l_parameters
req: R-PE-DEF.11
in: Sequence[dict] rows; object signature = None
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
examples: (baseline) census only

A2lPickerMixin._apply_a2l_layout
req: R-PICKER-CORRECT.020
in: 
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
examples: (baseline) census only

A2lPickerMixin._use_highlighted_parameter
req: R-PE-DEF.3
in: 
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
examples: (baseline) census only

A2lPickerMixin._on_a2l_parameter_picker_view_changed
req: R-PE-DEF.10
in: object event
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
examples: (baseline) census only

A2lPickerMixin._compose_a2l_tab
req: R-PE-DEF.2
in: 
out: ComposeResult tree
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
examples: (baseline) census only

A2LParameterPicker.highlighted_parameter
req: R-PE-DEF.49
in: 
out: Optional[dict] parameter
func: baseline, read for its real callers
module: s19_app/tui/a2l_parameter_picker.py
examples: (baseline) census only

A2LParameterPicker.visible_params
req: R-PE-DEF.10
in: 
out: list names
func: baseline, read for its real callers
module: s19_app/tui/a2l_parameter_picker.py
examples: (baseline) census only

ChangeService.add_symbol_entry
req: R-PE-DEF.50
in: str symbol_text; str value_text; Optional[dict] a2l_data
out: ChangeActionResult result
func: baseline, read for its real callers
module: s19_app/tui/services/change_service.py
examples: (baseline) census only

ChangeService._entry_index
req: R-PE-DEF.52
in: int address
out: int index
func: baseline, read for its real callers
module: s19_app/tui/services/change_service.py
examples: (baseline) census only

ChangeService._push_history
req: R-PE-DEF.61
in: 
out: None
func: baseline, read for its real callers
module: s19_app/tui/services/change_service.py
examples: (baseline) census only

ChangeService.rows
req: R-PE-DEF.62
in: Optional[Sequence[Tuple[int, int]]] ranges
out: list rows
func: baseline, read for its real callers
module: s19_app/tui/services/change_service.py
examples: (baseline) census only

PatchMixin._refresh_patch_history_view
req: R-PE-DEF.62
in: 
out: None
func: baseline, read for its real callers
module: s19_app/tui/app/patch.py
examples: (baseline) census only

PatchMixin._report_change_result
req: R-PE-DEF.57
in: ChangeActionResult result
out: None
func: baseline, read for its real callers
module: s19_app/tui/app/patch.py
examples: (baseline) census only

PatchMixin._prefill_patch_editor
req: R-PE-DEF.11
in: 
out: None
func: baseline, read for its real callers
module: s19_app/tui/app/patch.py
examples: (baseline) census only

PatchMixin._strip_source_map
req: R-PE-DEF.62
in: object loaded
out: object source_map
func: baseline, read for its real callers
module: s19_app/tui/app/patch.py
examples: (baseline) census only

describe_definition
req: R-PE-DEF.64
in: str name; dict a2l_data
out: Definition definition
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only

describe_definitions
req: R-PE-DEF.11
in: Iterable[str] names; dict a2l_data
out: dict definitions
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only

decode_definition
req: R-PE-DEF.17
in: Definition definition; dict a2l_data; Mapping[int, int] image
out: object decoded
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only

encode_definition
req: R-PE-DEF.51
in: Definition definition; dict a2l_data; str text; Mapping[int, int] image
out: object encoded
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only

display_text
req: R-PE-DEF.26
in: Definition definition; float value
out: str text
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only
