# Code-Wire baseline — Inc 2 responsive direct A2L attach

Stage E1 baseline at `f44e8bc4266b6dead6ff24adef71fdb0b7b0154c` (product-identical to E0 `d658dfeaa336dea54b99001b52df52fa1fd434d0`). Code-Wire home `<code-wire>`, commit `b6cd30d62bf46abbe2f9375e8c04b296f1eeaf05` (PLAN-pinned v3.2.0). This is the graph of the six existing methods in the counted slice; the new preparation function and new data classes are deliberately absent from the baseline.

The `func` fields describe current code. The examples are concrete E4 oracles derived from `../01-requirements.md`, including behavior that is absent on this baseline; none is a recording or an executed result. The future graph will supply deltas rather than editing source from this baseline. No source marks, stubs, declarations or extraction were made in this repository.

Dynamic hand-off missing from a call-only AST census: the worker passes `_on_a2l_attached` to `call_from_thread` at `app/file_load.py:838`; that callback passes `_install_attached_a2l` to `call_after_refresh` at `:846`. The current worker returns after copy/parse, and `_install_attached_a2l` performs installation and common refresh on the UI thread. The future accepted hand-off names `_accepted_a2l_picker_snapshots: Mapping[str, A2LPickerSnapshot]` as a read-only mapping invalidated on generation/signature or A2L-source mismatch.

## Nodes

FileLoadMixin._start_a2l_load
req: R-A2L-REFRESH.030, R-A2L-REFRESH.032, R-A2L-REFRESH.033, R-A2L-REFRESH.034
in: FileLoadMixin self; Path path; Path normalized; bool copy; bool sync_project = True
out: None
func: preserves admission and recent decisions, begins the busy run, creates the frozen request without generation/image snapshot fields and starts the attach worker
module: s19_app/tui/app/file_load.py
modify: [Data: A2L busy run] (append)
examples: (E4-030-2) image map with one source byte changed after request capture → request keeps independent read-only original bytes and expected pair
examples: (E4-033-6) image bytes `1000000`; two keys during request capture → each acknowledgement latency at most `1.0` s
examples: (E4-034-4) image bytes `1000000` during request capture → visible progress gaps at most `1.0` s

FileLoadMixin._a2l_attach_worker
req: R-A2L-REFRESH.029, R-A2L-REFRESH.030, R-A2L-REFRESH.033, R-A2L-REFRESH.034, R-A2L-REFRESH.037, R-A2L-REFRESH.038
in: FileLoadMixin self; A2LAttachRequest request
out: None
func: copies when requested, parses with byte progress, constructs the current parsed result and dispatches install or failure; current code performs no enrichment or definition preparation
module: s19_app/tui/app/file_load.py
modify: [I/O: workarea A2L copy] (replace)
examples: (E4-029-1) typed NEW attach → worker completes enriched tags, summary and two picker snapshots before install dispatch
examples: (E4-037-1) OLD measurable names → Check describe count `1` and Patch describe count `1`, both off UI
examples: (E4-033-3) held enrichment and two keys → each key acknowledged within `1.0` s before install
examples: (E4-034-1) enrichment held `1.5` s → every visible progress gap at most `1.0` s
examples: (E4-038-1) enrichment raises ValueError → exact File NOT loaded outcome and no install
examples: (E4-038-2) real enrichment completes then render_a2l_view raises ValueError → exact File NOT loaded outcome and no describe or install

FileLoadMixin._install_attached_a2l
req: R-A2L-REFRESH.031, R-A2L-REFRESH.032, R-A2L-REFRESH.035, R-A2L-REFRESH.036, R-A2L-REFRESH.037
in: FileLoadMixin self; A2LAttachResult result
out: None
func: currently records recents, refreshes files, stores cache and A2L, attaches to the current file, runs common refresh and schedules success without a direct-snapshot generation preflight
module: s19_app/tui/app/file_load.py
modify: [Data: Current A2L] (replace); [Data: A2L view caches] (replace); [Data: A2L busy run] (clear)
examples: (E4-031-1) matching OLD result without an image → enrichment key (new A2L, unchanged image, `-1`) before refresh
examples: (E4-031-2) matching NEW result over IMG1 → enrichment key (new A2L, unchanged image, independently measured image map size) before refresh
examples: (E4-032-1) stale A2L generation → Load superseded — current state kept. with zero install or refresh
examples: (E4-035-2) accepted replacement → install then one UI common refresh then A2L loaded outcome
examples: (E4-036-2) accepted image-bearing snapshot → worker enrichment count `1` and UI enrichment count `0`

A2LParameterPicker.set_parameters
req: R-A2L-REFRESH.037
in: A2LParameterPicker self; Sequence[dict] rows; object signature = None; dict? a2l_data = None
out: bool repopulated
func: currently no-ops on equal non-None signature and otherwise performs one direct bulk describe before normalizing rows and rebuilding one page
module: s19_app/tui/a2l_parameter_picker.py
modify: [Data: Picker population] (replace)
examples: (E4-037-2) same-path NEW generation with declared length `8` and format f32 → one supplied worker snapshot paints length `8` and f32 without a UI describe
examples: (E4-037-3) twenty filter/page rebuilds plus unchanged signature → additional describe count `0` and page rows at most `200`

CheckEditorPanel.set_a2l_parameters
req: R-A2L-REFRESH.037
in: CheckEditorPanel self; Sequence[dict] rows; object signature = None
out: None
func: currently forwards rows, signature and the app's current A2L payload to the Check picker, then preserves picks and refreshes layout/previews after real population
module: s19_app/tui/screens_directionb/check_editor.py
modify: [Data: Check picker population] (replace)
examples: (E4-037-1) accepted OLD direct generation → Check consumes its own matching worker definitions and paints exact declared lengths/formats
examples: (E4-037-4) wrong A2L source or full signature → accepted mapping invalidated before existing-route describe and no stale definitions painted
examples: (E4-037-3) unchanged Check signature → repopulated False with preserved filter/page/picks and zero describes

A2lPickerMixin.set_a2l_parameters
req: R-A2L-REFRESH.037
in: A2lPickerMixin self; Sequence[dict] rows; object signature = None
out: None
func: currently forwards rows, signature and the app's current A2L payload to the Patch picker, then invalidates and reapplies layout after real population
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
modify: [Data: Patch picker population] (replace)
examples: (E4-037-2) same-path NEW direct generation → Patch consumes a distinct matching worker snapshot and paints f32, never the OLD u16 definition
examples: (E4-037-4) wrong A2L source or full signature → accepted mapping invalidated before existing-route describe and no stale definitions painted
examples: (E4-037-3) Patch filter/page rebuilds → additional describe count `0` and current NEW definitions retained

## Entities

[Data: A2L busy run]
desc: existing main-thread progress state; copy/parse byte progress and spinner/elapsed remain visible throughout processing

[I/O: workarea A2L copy]
desc: existing worker copy; a stale install preflight does not turn an already copied file into installed session state

[Data: Current A2L]
desc: current path and parsed payload owned by the existing single-writer replacement seam

[Data: A2L view caches]
desc: enriched tags, summary lines and the existing A2L/image/mem-size key installed before common refresh

[Data: Picker population]
desc: shared picker's current rows, definitions, A2L source, filter, page and picks

[Data: Check picker population]
desc: Check adapter's embedded picker and its existing selection/layout side effects

[Data: Patch picker population]
desc: Patch adapter's embedded picker and its existing layout side effects

## Edges

[Data: Current A2L] ──▶ FileLoadMixin._install_attached_a2l
[Data: Picker population] ──▶ CheckEditorPanel.set_a2l_parameters
