# Inc 8 E4 — impl-s2 hand-back (group S2: sheet.py, picker attribute)

Model claude-sonnet-5-5. Files: new `s19_app/tui/screens_directionb/patch_editor/sheet.py` (`StagingSheet`, I-8.4);
`s19_app/tui/a2l_parameter_picker.py` (S22: `definitions`, `definitions_source`, set in `set_parameters` right after its one describe;
an equal signature returns before it and keeps the old mapping).

## Examples
`definition_sheet.py` (group S1) was not committed or on disk while I worked (`git log` showed no S1 commit). Every EX-* example of my nodes
needs S1's real functions, so they are all **could not run**. What I ran instead is a wiring smoke test on `<runner>` (textual 8.2.8, isolated env,
`s19_app.__file__` under my scratch) against a throwaway ~40-line stand-in of S1's pinned names, placed only in the scratch tree and deleted. It is
not evidence for any EX-* id. Output (host load 1.56 at start; no timing asserted):

```text
selected A / down2 C / up B                      (R-PE-DEF.45 wiring: up/down on the focusable body)
focus input True                                  (enter -> #patch_sheet_input, R-PE-DEF.46)
down in input ignored B                           (up/down with the input focused do not move the row)
pending {'B': 'xy'} xy
esc: pending {} focus body True value ''          (R-PE-DEF.48 reaches the sheet via on_key)
submit [('stage', 'B', '5')]                      (Enter in the input posts the ops.submit message)
after B -> C pending {}                           (select_after by name)
enum right {'E': 'OFF'} / enum end {'E': 'RUN'}   (no wrap)
Z selected Z input disabled True ''               (row with no editor: input disabled and empty)
enter on no-editor row: focus True                (focus stays on the body)
paste65536 len 0 / paste200 on 4000 len 4000      (R-PE-DEF.42: oversized insert refused, text unchanged)
window sel 40 top 14 bodyh 29                     (row window keeps the selected row painted)
```

## Deviations and decisions
- Escape is handled by `StagingSheet.on_key` (only while the input has focus), not by a sixth `BINDINGS` entry; `BINDINGS` is the five pinned keys.
- up/down/left/right/enter actions return early while the formula input has the focus (the input's own keys win; up/down would otherwise bubble to the sheet).
- `states` is not pruned by `show_page`; `pending` is (names no longer shown). Inc 9 owns `states`.
- Programmatic input fills are tracked in a FIFO of expected values so their queued `Input.Changed` is not taken as a typed edit; a typed value equal to the head of that queue would be swallowed (practically impossible, noted).
- Fallback size 118x20 is used for painting before the body has a size; `_SheetBody.on_resize` repaints.
- DEFAULT_CSS in `sheet.py` (input `border: none; height: 1`, bar `height: 1`); group P's `styles.tcss` owns `#patch_sheet_win`.

## Findings / interface notes (for S1 and the integrator)
- F-1: `KindOps.submit(name, text)` must return `StagingSheet.StageRequested`, but `definition_sheet.py` is pure (no toolkit) and `sheet.py` imports it. S1's submit needs a lazy import inside the function (the stand-in did this), or I-8.5 should say the widget builds the message. `on_input_submitted` posts whatever `ops.submit` returns.
- F-2: I use these S1 names with these shapes: `SheetRow.name/.definition/.kind/.current` (`.current.value` for the enum's matched text, `Decoded.value`), `ops_for(kind).editable(definition)/.preview(definition, a2l, text, overlay)/.submit/.label/.bar`, `row_window(...) -> (top, painted)`, `detail_lines(row, preview, width, state, room)`, `formula_tail(row, preview, width)`, `sheet_widths(width)`, `name_echo`, `plain`. If S1 differs, `sheet.py` needs an edit.
- F-3: `action_choose` branches on `row.kind == "enum"` and reads `definition.enum_entries[*].text` (the pinned table has no per-kind hook for it; an Inc 9 override can replace it).

## Open gaps
All EX-* examples of S13..S19', S22 (could not run: S1 absent). S22 itself is a 4-line attribute change checked only by `ast.parse` and by the import in the smoke test.
