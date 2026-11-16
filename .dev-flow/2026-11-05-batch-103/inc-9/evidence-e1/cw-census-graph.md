# Inc 9 E1 census graph (context only: the existing functions in scope at 593d56a4; no prototype)

## Nodes

decode_values
req: R-PE-BENCH.20
in: Definition definition; dict a2l_data; Mapping[int, int] image
out: DecodedValues | Refusal result
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only

encode_values
req: R-PE-BENCH.60
in: Definition definition; dict a2l_data; Mapping edit; Mapping[int, int] image
out: Encoded | Refusal result
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only

element_name
req: R-PE-BENCH.40
in: Definition definition; tuple position
out: str name
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only

display_text
req: R-PE-BENCH.51
in: Definition definition; int | float value
out: str text
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only

describe_definition
req: R-PE-BENCH.64
in: str name; dict a2l_data
out: Definition definition
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only

describe_definitions
req: R-PE-BENCH.20
in: Iterable[str] names; dict a2l_data
out: dict[str, Definition] defs
func: baseline, read for its real callers
module: s19_app/tui/a2l_definition.py
examples: (baseline) census only

A2LParameterPicker.set_parameters
req: R-PE-BENCH.20
in: (none)
out: None
func: baseline, read for its real callers
module: s19_app/tui/a2l_parameter_picker.py
examples: (baseline) census only

PatchEditorPanel.__init__
req: R-PE-BENCH.1
in: (none)
out: None
func: baseline, read for its real callers
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (baseline) census only

ChangeService._push_history
req: R-PE-BENCH.60
in: (none)
out: None
func: baseline, read for its real callers
module: s19_app/tui/services/change_service.py
examples: (baseline) census only

PatchMixin._report_change_result
req: R-PE-BENCH.62
in: ChangeActionResult result
out: None
func: baseline, read for its real callers
module: s19_app/tui/app/patch.py
examples: (baseline) census only

PatchMixin._refresh_patch_history_view
req: R-PE-BENCH.60
in: (none)
out: None
func: baseline, read for its real callers
module: s19_app/tui/app/patch.py
examples: (baseline) census only

PatchMixin.on_patch_editor_panel_action_requested
req: R-PE-BENCH.60
in: object event
out: None
func: baseline, read for its real callers
module: s19_app/tui/app/patch.py
examples: (baseline) census only
