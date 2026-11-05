# Code-Wire — Inc 7 — Flow file origins/chooser

Graph of the file-origin/chooser slice. Requirements: `01-requirements.md`. Tests: `02-test-cases.md`.

## Nodes

resolve_flow_ref_source
req: R-B102-FILE-001, R-B102-FILE-007
in: str ref; Path project_root; Sequence[str] temp_files; Sequence[str] loaded_names
out: str source
func: new pure classifier. Returns `project`, `temp`, `loaded`, `external` or `missing` for a ref using the supplied roots and candidate lists; no filesystem mutation.
module: s19_app/tui/flow_screens.py
examples: (TC-B102-FILE-01) ref `calib.json` in project list → source `project`; ref `trial.a2l` only in temp list → `temp`; ref `ghost.bin` absent everywhere → `missing`

FlowBuilderPanel._card_rows
req: R-B102-FILE-001, R-B102-FILE-007
in: FlowBuilderPanel self; FlowBlock block; int index
out: List[Tuple[str, str, str]]
func: changed. Adds the source annotation row to file-bearing cards using `resolve_flow_ref_source`; all names render as literal text.
module: s19_app/tui/flow_screens.py
examples: (TC-B102-FILE-01) missing external ref → card rows include `missing` annotation
examples: (TC-B102-FILE-07) hostile filename → annotation plain text keeps sentinel with zero markup spans

FileRefChooserScreen.compose
req: R-B102-FILE-002, R-B102-FILE-007
in: FileRefChooserScreen self; Sequence candidates; Path project_root
out: ComposeResult
func: new modal. Lists Project, Temp/workarea and Loaded sections from candidate objects, plus an external path input and Import/Cancel actions; file-derived labels are literal Text.
module: s19_app/tui/screens.py
examples: (TC-B102-FILE-02) candidates from all three sources → modal contains section headers `Project`, `Temp / workarea`, `Loaded artifacts` and `#flow_external_path_input`

FileRefChooserScreen._pick_candidate
req: R-B102-FILE-003
in: FileRefChooserScreen self; Candidate candidate
out: None
func: new selection handler. Dismisses the modal with the candidate's wire value and display origin; it does not mutate the host field until the host applies the result.
module: s19_app/tui/screens.py
examples: (TC-B102-FILE-03) candidate `trial.a2l` from temp → dismiss value `trial.a2l`; host Add block count remains unchanged until Add

import_external_ref
req: R-B102-FILE-004, R-B102-FILE-005, R-B102-FILE-006, R-B102-FILE-007
in: Path external_path; Path project_root
out: tuple[Path, str]? imported
func: new service-side helper. Requires a project root, verifies readability, copies into `project_root/external` with a numeric suffix on collision, returns the relative workarea ref; refuses missing project/unreadable file without mutation.
module: s19_app/tui/workspace.py
modify: [I/O: project external folder] (append)
examples: (TC-B102-FILE-04) `C:\tmp\calib.json` into project P → imported path `P/external/calib.json`, returned ref `external/calib.json`
examples: (TC-B102-FILE-04) same import repeated → second destination is `P/external/calib-1.json`
examples: (TC-B102-FILE-05) project_root None → refusal `Load or create a project before importing an external file.`
examples: (TC-B102-FILE-06) missing external file → refusal `External file not readable: <name>`

FlowBuilderPanel._browse_ref
req: R-B102-FILE-002, R-B102-FILE-003
in: FlowBuilderPanel self; str input_id
out: None
func: new host action for Browse buttons beside Add/Edit ref fields. Builds candidate lists from active project/temp/loaded artifacts, pushes FileRefChooserScreen and writes the chosen ref into `input_id` on dismiss; external imports call `import_external_ref` first.
module: s19_app/tui/flow_screens.py
modify: [UI: target Input.value] (replace)
examples: (TC-B102-FILE-03) Browse on `#flow_ref`, pick project candidate → `#flow_ref.value` is the candidate ref; `_blocks` length unchanged
examples: (TC-B102-FILE-04) Browse external path success → `#flow_ref.value` is `external/calib.json`

## Entities

[I/O: active project workarea]
in: files
desc: source root for project candidates and the only destination for imported external files.

[UI: Flow block cards]
in: rows
desc: visible pipeline annotations showing each ref's origin.

[UI: ref chooser modal]
in: candidate list + external path
desc: modal used by Add and Edit forms to choose a file reference.

## Edges

FlowBuilderPanel._card_rows ──▶ resolve_flow_ref_source
FlowBuilderPanel._browse_ref ──▶ FileRefChooserScreen.compose
FileRefChooserScreen._pick_candidate ──▶ FlowBuilderPanel._browse_ref
FlowBuilderPanel._browse_ref ──▶ import_external_ref
import_external_ref ──▶ [I/O: active project workarea]

## Findings

finding F-B102-FILE-1 block refs do not say where the file comes from
anchor: FlowBuilderPanel._card_rows
seen: operator cannot tell which project/temp/loaded/external file a block consumes
cause: cards render only the raw ref string
decision: annotate every file-bearing card with a resolved source label

finding F-B102-FILE-2 refs are manual-only and external files are unsupported
anchor: FlowBuilderPanel.compose
seen: no Browse affordance; external paths are not accepted clearly
cause: add/edit forms accept only typed refs and runtime resolution expects project-contained files
decision: add a chooser modal with project/temp/loaded candidates and safe external import into the workarea
