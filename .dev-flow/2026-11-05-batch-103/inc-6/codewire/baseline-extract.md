# Inc 6 baseline extractor graph

## Nodes

A2LParameterPicker.set_parameters
req: R-PICKER-CORRECT.001
in: Sequence[dict] rows; object signature = None
out: bool repopulated
func: baseline population contract before the delta
module: s19_app/tui/a2l_parameter_picker.py
examples: (baseline) rows and signature → repopulated

A2LParameterPicker._row_cells
req: R-PICKER-CORRECT.003
in: str name; PickerLayout layout
out: tuple cells
func: baseline four-cell renderer
module: s19_app/tui/a2l_parameter_picker.py
examples: (baseline) name and layout → cells

A2LParameterPicker._refresh_full_name
req: R-PICKER-CORRECT.003
in:
out: None
func: baseline full-name renderer
module: s19_app/tui/a2l_parameter_picker.py
examples: (baseline) highlighted row → None

A2LParameterPicker.highlighted_parameter
req: R-PICKER-CORRECT.005
in:
out: Optional[dict] parameter
module: s19_app/tui/a2l_parameter_picker.py
examples: (baseline) highlighted row → parameter

PatchEditorPanel.__init__
req: R-PICKER-CORRECT.011
in:
out: PatchEditorPanel panel
func: baseline Patch panel construction
module: s19_app/tui/screens_directionb.py
examples: (baseline) construct panel → panel

PatchEditorPanel.set_a2l_parameters
req: R-PICKER-CORRECT.018
in: Sequence[dict] rows; object signature = None
out: None
func: baseline Patch population shim
module: s19_app/tui/screens_directionb.py
examples: (baseline) rows and signature → None

CheckEditorPanel.set_a2l_parameters
req: R-PICKER-CORRECT.018
in: Sequence[dict] rows; object signature = None
out: None
func: baseline Check population shim
module: s19_app/tui/screens_directionb.py
examples: (baseline) rows and signature → None

PatchEditorPanel._use_highlighted_parameter
req: R-PICKER-CORRECT.005
in:
out: None
func: baseline Use parameter route
module: s19_app/tui/screens_directionb.py
examples: (baseline) highlighted parameter → None

parse_parameter_list
req: to trace
in: str text
out: list tokens
func: baseline bulk parser
module: s19_app/tui/a2l_parameter_picker.py
examples: (baseline) text → tokens

A2LParameterPicker.include_names
req: to trace
in: Sequence[str] names
out: dict summary
func: baseline exact-match bulk include
module: s19_app/tui/a2l_parameter_picker.py
examples: (baseline) names → summary

CheckEditorPanel._on_a2l_parameter_picker_bulk_add_requested
req: to trace
in: A2LParameterPicker.BulkAddRequested event
out: None
func: baseline Check bulk host
module: s19_app/tui/screens_directionb.py
examples: (baseline) event → None

CheckEditorPanel._open_parameter_bulk_add
req: to trace
in:
out: None
func: baseline Check modal opener
module: s19_app/tui/screens_directionb.py
examples: (baseline) request → None

describe_definitions
req: to trace
in: Iterable[str] names; dict a2l_data
out: dict[str, Definition] definitions
func: baseline one-walk definition producer
module: s19_app/tui/a2l_definition.py
examples: (baseline) names and data → definitions
