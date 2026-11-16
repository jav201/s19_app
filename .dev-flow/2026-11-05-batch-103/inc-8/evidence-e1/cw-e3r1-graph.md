# Inc 8 E3R1 census graph (context only: the existing functions the E3R1 rulings change or newly call; no prototype)

## Nodes

A2LParameterPicker.set_parameters
req: R-PE-DEF.11
in: Sequence[dict] rows; object signature; Optional[dict] a2l_data
out: bool repopulated
func: baseline, read for its real callers (E3A-04: it keeps its describe as `definitions`)
module: s19_app/tui/a2l_parameter_picker.py
examples: (baseline) census only

A2lPickerMixin._on_a2l_parameter_picker_view_changed
req: R-PE-DEF.10
in: A2LParameterPicker.ViewChanged event
out: None
func: baseline, read for its real callers (E3A-04: passes the picker's definitions to show_page)
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
examples: (baseline) census only

section_body_text
req: R-PE-DEF.83
in: str window_key
out: str body
func: baseline, read for its real callers (E3A-06: the reader of WINDOW_HELP_SECTIONS["patch"])
module: s19_app/tui/window_help.py
examples: (baseline) census only

PatchMixin._strip_source_map
req: R-PE-DEF.51
in: Optional[LoadedFile] loaded
out: Optional[Mapping[int, int]] view
func: baseline, read for its real callers (E3S-01: A3 passes its view to stage_definition)
module: s19_app/tui/app/patch.py
examples: (baseline) census only

PatchMixin._report_change_result
req: R-PE-DEF.59
in: ChangeActionResult result
out: None
func: baseline, read for its real callers (E3A-10: the notice line is printed apart from issues)
module: s19_app/tui/app/patch.py
examples: (baseline) census only

ShellMixin._refuse_if_busy
req: R-PE-110
in: 
out: bool refused
func: baseline, read for its real callers (E3S-03: A3 calls it first)
module: s19_app/tui/app/shell.py
examples: (baseline) census only
