# Code-Wire — Inc 4 — bulk add

Graph of the bulk-add slice. Requirements: `01-requirements.md`. Tests: `02-test-cases.md`.

## Nodes

parse_parameter_list
req: R-B102-BULK-002
in: str text
out: list[str] names
func: new pure parser. Replaces newlines, commas and semicolons with spaces, splits on whitespace, trims tokens and drops empties; preserves input order including repeated tokens.
module: s19_app/tui/a2l_parameter_picker.py
examples: (TC-B102-BULK-02) text "Alpha\nBeta, Gamma; Delta   Alpha" → names ["Alpha", "Beta", "Gamma", "Delta", "Alpha"]

A2LParameterPicker.include_names
req: R-B102-BULK-003, R-B102-BULK-005
in: A2LParameterPicker self; Sequence[str] names
out: dict summary
func: new bulk include entry. For each parsed name in order, includes exact source matches not already picked; never clears existing picks; returns counts `included`, `already_included`, `not_found` and `first_missing`.
module: s19_app/tui/a2l_parameter_picker.py
modify: [Data: A2LParameterPicker._picked_params] (append); [UI: affected mark cells] (replace)
examples: (TC-B102-BULK-03) existing `Alpha`, names ["Beta","Beta","Alpha","Gamma"] → summary included `1`, already_included `1`, not_found `1`; picks are ["Alpha","Beta"]
examples: (TC-B102-BULK-05) names ["Nope1","Nope2"] with no source matches → summary included `0`, already_included `0`, not_found `2`; picks unchanged

BulkParameterAddScreen.compose
req: R-B102-BULK-001, R-B102-BULK-006
in: BulkParameterAddScreen self
out: ComposeResult
func: new modal. Composes heading, multiline `CappedTextArea`, exact instruction `Separate names with new lines, commas, semicolons or spaces.`, summary line and Include/Close actions; every file-derived surface is literal text/markup-safe.
module: s19_app/tui/screens.py
examples: (TC-B102-BULK-01) modal mounted → widgets include `#bulk_param_text`, `#bulk_param_summary`, `#bulk_param_include_button`, `#bulk_param_close_button`; instruction is exactly the contract line

BulkParameterAddScreen._apply_list
req: R-B102-BULK-002, R-B102-BULK-004, R-B102-BULK-005, R-B102-BULK-006
in: BulkParameterAddScreen self
out: None
func: new modal action. Parses the buffer, calls `picker.include_names`, paints `Included <n> · already included <n> · not found <n>` plus ` — first missing: <name>` when relevant, or exactly `No listed parameters found.` when zero included and zero already included.
module: s19_app/tui/screens.py
modify: [UI: #bulk_param_summary] (replace)
examples: (TC-B102-BULK-04) buffer `Alpha\nMissingOne\nMissingTwo`, source contains `Alpha` → summary `Included 1 · already included 0 · not found 2 — first missing: MissingOne`
examples: (TC-B102-BULK-05) buffer `Nope1 Nope2` → summary `No listed parameters found.`
examples: (TC-B102-BULK-06) buffer contains `[red]` missing token → summary plain text includes `[red]` with zero markup spans

CheckEditorPanel._open_parameter_bulk_add
req: R-B102-BULK-001
in: CheckEditorPanel self
out: None
func: new host action. Activating `#check_param_bulk_button` pushes the bulk modal for this panel's picker.
module: s19_app/tui/screens_directionb.py
examples: (TC-B102-BULK-01) button press → None; modal is the top screen and its text area has focus

CheckEditorPanel._on_bulk_add_closed
req: R-B102-BULK-007
in: CheckEditorPanel self; Optional[dict] summary
out: None
func: new dismiss tail. After any modal close, refreshes preview/count if picks changed and avoids a ledger rebuild; a no-change close repaints nothing beyond dismissing.
module: s19_app/tui/screens_directionb.py
examples: (TC-B102-BULK-07) include valid list then close → None; preview count updates and `_rebuild_ledger` spy stays unchanged
examples: (TC-B102-BULK-07) reopen and close without changes → None; no rebuild and no preview refresh

## Entities

[Data: A2LParameterPicker._picked_params]
in: list[str]
desc: existing inclusion order consumed and extended by the bulk path.

[UI: #bulk_param_summary]
in: str
desc: the single modal feedback region for bulk-add results.

## Edges

parse_parameter_list ──▶ BulkParameterAddScreen._apply_list
BulkParameterAddScreen._apply_list ──▶ A2LParameterPicker.include_names
A2LParameterPicker.include_names ──▶ [Data: A2LParameterPicker._picked_params]
CheckEditorPanel._open_parameter_bulk_add ──▶ BulkParameterAddScreen.compose
[Outside: key escape] ──▶ BulkParameterAddScreen.action_cancel
when: bulk modal is top screen

## Findings

finding F-B102-BULK-1 one-by-one inclusion does not scale to real label lists
anchor: CheckEditorPanel._toggle_highlighted
seen: operator request to add a list of labels/parameters, not only one highlighted row at a time
cause: the only inclusion path is cursor-row toggle
decision: add a modal bulk path that reuses exact-name source matching and the pick-state contract

finding F-B102-BULK-2 bulk feedback needs a single owner
anchor: BulkParameterAddScreen._apply_list
seen: mixed lists will commonly contain valid, duplicate and missing names
cause: separate messages would make it hard to know whether the operation changed anything
decision: one summary line with fixed count order and first discriminating missing name
