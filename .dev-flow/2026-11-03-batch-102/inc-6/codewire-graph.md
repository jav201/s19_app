# Code-Wire — Inc 6 — Flow block edit/remove

Graph of the block editing slice. Requirements: `01-requirements.md`. Tests: `02-test-cases.md`.

## Nodes

FlowBuilderPanel._selected_block
req: R-B102-FB-001, R-B102-FB-005
in: FlowBuilderPanel self
out: tuple[int, FlowBlock]? selected
func: new shared resolver for the Copy/Paste row's block #. Empty input means the last block; a non-numeric or out-of-range value returns None and paints `Edit/Remove needs a block # between 1 and <N>.`
module: s19_app/tui/flow_screens.py
examples: (TC-B102-FB-05) blocks `2`, inputs `""`, `x`, `9` → None/selected arms: empty resolves block `2`; invalid arms return None and notice names `1 and 2`

FlowBlockEditScreen.compose
req: R-B102-FB-001, R-B102-FB-006
in: FlowBlockEditScreen self
out: ComposeResult
func: new modal composition. Fixes the title to the block kind, initializes kind-specific fields from the selected block and renders all file-derived values through safe literal text.
module: s19_app/tui/screens.py
examples: (TC-B102-FB-01) ExternalStepBlock(mode terminal, instruction `python flash.py`, log `run.log`, output `out.s19`) → fields carry those exact values
examples: (TC-B102-FB-06) hostile ref → field plain text keeps sentinel with zero markup spans

FlowBuilderPanel._edit_block
req: R-B102-FB-001
in: FlowBuilderPanel self
out: None
func: new edit action. Resolves `_selected_block`; on success pushes FlowBlockEditScreen with index/block and a save callback.
module: s19_app/tui/flow_screens.py
examples: (TC-B102-FB-01) pick `2`, kind patch → None; modal title contains block `2` and kind `patch`

FlowBlockEditScreen._save
req: R-B102-FB-002, R-B102-FB-003, R-B102-FB-006
in: FlowBlockEditScreen self
out: None
func: new modal save. Builds a candidate block from the modal fields, substitutes it at the selected index in the current wire envelope and runs the hardened loader/validators. On success dismisses with the replacement; on findings keeps the original and paints the refusal in the modal.
module: s19_app/tui/screens.py
examples: (TC-B102-FB-02) SOURCE block #2 ref changed to `new_image.s19` → dismiss candidate; only index `1` changes in caller
examples: (TC-B102-FB-03) A2B replacement binding downstream → no dismiss; refusal names the binding and caller list is unchanged

FlowBuilderPanel._replace_block
req: R-B102-FB-002
in: FlowBuilderPanel self; int index; FlowBlock replacement
out: None
func: new apply seam. Replaces exactly `self._blocks[index]`, refreshes pipeline/ribbon and marks dirty; variables and clipboard remain untouched.
module: s19_app/tui/flow_screens.py
modify: [Data: FlowBuilderPanel._blocks] (replace one item)
examples: (TC-B102-FB-02) replacement middle block → None; first and last block dicts equal their originals; dirty is True

FlowBuilderPanel._remove_block
req: R-B102-FB-004, R-B102-FB-005
in: FlowBuilderPanel self
out: None
func: new remove action. Resolves `_selected_block`, asks `Remove block #<n> (<kind>)? This cannot be undone.` with Remove/Cancel; on confirm deletes only that index, refreshes and marks dirty. Variables and clipboard survive.
module: s19_app/tui/flow_screens.py
modify: [Data: FlowBuilderPanel._blocks] (remove one item)
examples: (TC-B102-FB-04) remove first/middle/last of three → None; each removal removes exactly one item; `_funnel` and `_clipboard` are unchanged
examples: (TC-B102-FB-05) pick `9` with two blocks → None; exact invalid notice and no mutation

## Entities

[Data: FlowBuilderPanel._blocks]
in: list[FlowBlock]
desc: ordered chain; edit/remove mutate exactly one index.

[Data: FlowBuilderPanel._funnel]
in: list[tuple]
desc: flow variables that must survive block edit/remove.

[Data: FlowBuilderPanel._clipboard]
in: dict
desc: copied wire block that must survive block edit/remove.

[UI: Flow edit modal refusal]
in: str
desc: single in-modal validation feedback region.

## Edges

FlowBuilderPanel._edit_block ──▶ FlowBuilderPanel._selected_block
FlowBuilderPanel._edit_block ──▶ FlowBlockEditScreen.compose
FlowBlockEditScreen._save ──▶ FlowBuilderPanel._replace_block
FlowBuilderPanel._remove_block ──▶ FlowBuilderPanel._selected_block
FlowBuilderPanel._remove_block ──▶ [Data: FlowBuilderPanel._blocks]

## Findings

finding F-B102-FB-1 Flow Builder only supports append and clear-all
anchor: FlowBuilderPanel.on_button_pressed
seen: operator reports blocks are not editable one by one; only Clear removes content
cause: mutation paths exist for append/paste/clear but not index-scoped edit/remove
decision: add index-scoped Edit and Remove with modal validation and confirmation

finding F-B102-FB-2 failed edits must not corrupt the chain
anchor: FlowBlockEditScreen._save
seen: replacing a block can invalidate A2B downstream bindings or external-step requirements
cause: direct mutation would bypass the hardened loader used by paste/load
decision: validate the candidate through the same envelope loader before replacing the original
