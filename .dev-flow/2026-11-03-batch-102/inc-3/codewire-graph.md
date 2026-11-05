# Code-Wire — Inc 3 — shared A2L picker / Check Editor performance

Graph of the shared selector slice. Requirements: `01-requirements.md`. Tests: `02-test-cases.md`.

## Nodes

A2LParameterPicker.set_parameters
req: R-B102-SEL-001, R-B102-SEL-004, R-B102-SEL-006
in: A2LParameterPicker self; Sequence[dict] rows; object signature = None
out: None
func: new shared population entry. Normalizes integer-address rows into `{name: (address, size, fmt_unit)}`; when `signature` equals the stored signature it returns without touching filter, page, picks or table. Otherwise replaces the source rows, clears picks, resets filter/page state and rebuilds one page.
module: s19_app/tui/a2l_parameter_picker.py
modify: [Data: A2LParameterPicker._param_rows] (replace); [Data: A2LParameterPicker._signature] (replace); [Data: A2LParameterPicker._picked_params] (clear); [UI: #check_param_table] (replace)
examples: (TC-B102-SEL-01) rows `199` synthetic parameters, signature `("sig", 1)` → None; table row count is `199`
examples: (TC-B102-SEL-01) rows `10000` synthetic parameters, signature `("sig", 2)` → None; table row count is `200`
examples: (TC-B102-SEL-04) same rows and same signature after two picks and page `2` → None; picks and page are unchanged; table rows are unchanged

A2LParameterPicker._schedule_filter_rebuild
req: R-B102-SEL-002
in: A2LParameterPicker self
out: None
func: new debounce seam for `Input.Changed`. Cancels the previous pending timer and schedules `_rebuild_ledger` 150 ms later, so one typed burst causes one content-cold rebuild.
module: s19_app/tui/a2l_parameter_picker.py
examples: (TC-B102-SEL-02) operator types `P` then pauses → None; exactly one rebuild happens after the debounce
examples: (TC-B102-SEL-02, mutant) the base shape rebuilt synchronously per key → rebuild count equals keystroke count and the test RED

A2LParameterPicker._rebuild_ledger
req: R-B102-SEL-001, R-B102-SEL-002, R-B102-SEL-005, R-B102-SEL-006
in: A2LParameterPicker self
out: None
func: new one-page renderer. Filters source names case-insensitively, clamps the page to the result, clears the table and uses one `add_rows` call for at most 200 `Text` cell rows. Paints the full-name/status line; when the filter exceeds one page it appends ` — refine filter.` to the count and enables page controls.
module: s19_app/tui/a2l_parameter_picker.py
modify: [Data: A2LParameterPicker._visible_params] (replace); [Data: A2LParameterPicker._filtered_params] (replace); [UI: #check_param_table] (replace)
examples: (TC-B102-SEL-02) filter `P`, total `10000`, page size `200` → None; count line is `200 of 10000 shown — refine filter.`
examples: (TC-B102-SEL-05) 250 filtered rows on page `2` → None; table row count is `50`; next is disabled
examples: (TC-B102-SEL-06) no source rows → None; line is `No A2L parameters — load an A2L (^L) to list them.`
examples: (TC-B102-SEL-06) source rows exist, filter `missing` → None; line is `No parameter matches the filter.`

A2LParameterPicker._toggle_highlighted
req: R-B102-SEL-003
in: A2LParameterPicker self
out: None
func: new row-toggle handler. Uses the table cursor to resolve the visible parameter name, appends/removes one pick, updates only the row's mark cell, refreshes the picked count and posts `SelectionChanged`; it never rebuilds the ledger.
module: s19_app/tui/a2l_parameter_picker.py
modify: [Data: A2LParameterPicker._picked_params] (replace); [UI: #check_param_table.mark cell] (replace)
examples: (TC-B102-SEL-03) three consecutive toggles with one duplicate → None; picked count is `2`; ledger rebuild spy remains `0` after mount
examples: (TC-B102-SEL-03, mutant) `_toggle_highlighted` calls `_rebuild_ledger` → spy increments per toggle and the test RED

A2LParameterPicker._turn_page
req: R-B102-SEL-005
in: A2LParameterPicker self; int delta
out: None
func: new pagination handler. Moves the stored page by `delta`, clamps it to `[1, page_count]`, disables previous on the first page and next on the last page, then re-renders one page.
module: s19_app/tui/a2l_parameter_picker.py
examples: (TC-B102-SEL-05) page `1`, delta `1`, two pages → None; page `2` renders and previous is enabled
examples: (TC-B102-SEL-05) page `2`, delta `1`, two pages → None; page stays `2` and next is disabled

A2LParameterPicker._row_cells
req: R-B102-SEL-007
in: A2LParameterPicker self; str name; ParameterLayout layout
out: tuple[Text, Text, Text, Text]
func: new cell builder. Reads the stored `(address, size, fmt_unit)`, derives mark/check/address/fmt cells and wraps the file-derived name with `safe_text` before clipping; no markup path is used.
module: s19_app/tui/a2l_parameter_picker.py
examples: (TC-B102-SEL-07) name `b77hostile[red]` with control bytes → tuple whose Parameter cell `.plain` keeps the sentinel and has zero markup spans

CheckEditorPanel.set_a2l_parameters
req: R-B102-SEL-004
in: CheckEditorPanel self; Sequence[dict] rows; object signature = None
out: None
func: changed delegation shim. Delegates rows and the signature to the embedded `A2LParameterPicker`; compatibility properties `_param_rows`, `_visible_params` and `_picked_params` read picker state so existing callers/tests keep working.
module: s19_app/tui/screens_directionb.py
examples: (TC-B102-SEL-04) app passes the same `_a2l_enriched_key` on re-entry → None; no table mount occurs and picks survive

CheckEditorPanel._on_a2l_parameter_picker_selection_changed
req: R-B102-SEL-003
in: CheckEditorPanel self; A2LParameterPicker.SelectionChanged event
out: None
func: new parent listener. Stops the event and refreshes the Fields/JSON/Addendum previews plus the left-column count; the document controls continue to collect `items` from the picker at write/validate time.
module: s19_app/tui/screens_directionb.py
examples: (TC-B102-SEL-03) picker posts picked names `Alpha`,`Beta` → None; preview field count is `2 fields`

## Entities

[Data: A2LParameterPicker._param_rows]
in: dict[str, tuple]
desc: normalized parameter source keyed by name; all rendered rows derive from this map.

[Data: A2LParameterPicker._picked_params]
in: list[str]
desc: picked names in inclusion order, preserved while the signature is unchanged.

[UI: #check_param_table]
in: DataTable rows
desc: the visible ledger page; at most 200 rows are mounted per rebuild.

[Data: A2LParameterPicker._signature]
in: object
desc: caller-provided identity (the app A2L/image cache key) used to avoid redundant repopulation.

## Edges

[Data: A2LParameterPicker._param_rows] ──▶ A2LParameterPicker._rebuild_ledger
[Data: A2LParameterPicker._picked_params] ──▶ A2LParameterPicker._row_cells
A2LParameterPicker.set_parameters ──▶ A2LParameterPicker._rebuild_ledger
A2LParameterPicker._schedule_filter_rebuild ──▶ A2LParameterPicker._rebuild_ledger
A2LParameterPicker._turn_page ──▶ A2LParameterPicker._rebuild_ledger
A2LParameterPicker._toggle_highlighted ──▶ [Data: A2LParameterPicker._picked_params]
[Outside: key space] ──▶ A2LParameterPicker._toggle_highlighted
when: focus is inside #check_param_table

## Findings

finding F-B102-SEL-1 Check Editor mounts every A2L row on entry and filter
anchor: CheckEditorPanel._rebuild_ledger
seen: operator reports the Check Editor is too slow to use with real A2L files; code adds every filtered row to a non-virtualized DataTable on entry and on each keystroke
cause: derive-class DataTable cost scales with mounted rows, not visible rows
decision: mount one 200-row page in a shared picker, debounce filter input and preserve state across screen entries

finding F-B102-SEL-2 screen entry currently clears useful picker state
anchor: S19TuiApp._prefill_check_editor
seen: every re-entry calls `panel.set_a2l_parameters`, whose current implementation clears picks and rebuilds the ledger
cause: population is keyed by the screen transition rather than by the A2L/image signature
effect: the operator loses included parameters merely for changing rail screens
decision: pass the safe Inc-2 `_a2l_enriched_key` as the picker signature and no-op when unchanged
