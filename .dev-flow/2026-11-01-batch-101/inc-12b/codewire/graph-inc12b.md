# Code-Wire graph — Inc 12b (every widget of the Flow Builder and Flow Execution shown in some state), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`), split from Inc 12 at E3 (`../../inc-12/E3-rulings.md`, D-5 B): group G4 of `../../inc-12/codewire/graph-inc12.md` as it stood at E2, with the E3 rulings E3A-03, E3A-05, S-1 and S-2 applied. Graph only: no stub, mark or declaration in any tree. Base `2d1e2b1` (product `e07fb00`); E4 writes after Inc 9's merge. Requirements `../01-requirements.md`, slice `../E1-slice.md`, rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1 (the Code-Wire repository's `docs/Notation-Grammar.md`).

How to read it:
- Every node's `func:` starts with **unchanged**, **changed** (then "was: … / now: …", the baseline first) or **removed** (then "was: … / now: absent"). Context nodes (unchanged) are here because a changed node calls them, a removed node's function now lives in them, or their examples are the oracle of a row.
- Example sources are the case ids of `../02-test-cases.md`; `B` = the Inc 12 E1 pilot (`../../inc-12/evidence-e1/i12e1-pilot-transcript.txt`), `C` = the Inc 12 E1 census (`../../inc-12/evidence-e1/i12e1-census-transcript.txt`). Every example states the Inc 12b target unless it says "holds on base" or "the base".
- The 14 module names of the painter family that only other family members read (`_Grid`, six helper functions and seven constants) are one entity, `[Code: canvas grid helpers]`: they go together, their only example is the census, and no test names them (C lines 177-186). The four `FlowBuilderPanel` methods and `_flow_block_label`, which tests or callers name, are nodes.

### Groups for E4 (file ownership) and interfaces — pinned here, changed only by an orchestrator ruling

| Group | Files | Owns nodes |
|---|---|---|
| G4 Flow | `s19_app/tui/flow_screens.py`; tests `tests/test_b101_flow_shown_widgets.py` (tester G-T4: the two walks, R-FB-ADD.1/2, AT-I12b-1) and the 39 re-pointed nodes in 13 files (tester G-T3, `../E1-slice.md` §5) | `FlowBuilderPanel.__init__`, `.set_session_dir`, `.compose`, `._refresh_blocks`, `.on_button_pressed`, `.on_mount`, `.on_select_changed`, `._canvas_text`, `._layout`, `._block_rows`, `._blocks_text`, `_flow_block_label`, `FlowExecutionPanel.compose`, `FlowExecutionPanel.on_mount`, `[Code: canvas grid helpers]`, `[Data: FlowBuilderPanel._kind]`, `[Doc: flow_screens docstrings]` |

| Interface | Pinned form | Producer → consumers |
|---|---|---|
| I-2 the Flow Builder kind | `FlowBuilderPanel._kind: str`, `BLOCK_SOURCE` at construction, written only by the kind chip branch of `on_button_pressed` and **only with a value of `_KIND_OPTIONS`** (a `flow_palette_<suffix>` press whose suffix is not one of them is ignored: `_kind`, the inputs, the tag and the chip marks unchanged; E3 S-1); read by `+ Add` and by `on_mount`'s first `_sync_kind_dependent_visibility`; no widget holds it. Tests choose a kind by pressing `#flow_palette_<kind>` and read its painted effect (`.flow-kind-tag`, the chip's `chip-selected`, the inputs shown), never `_kind` | G4 → G-T3, G-T4 |
| I-3 the removed names | after Inc 12b no source or test names the ids `flow_help`, `flow_canvas`, `flow_blocks`, `flow_kind`, `flow_ext_session`, `fx_help` (in any form: `id=`, a comparison, a `#…` selector, a set literal), or a member of the painter family (`_flow_block_label`, `_blocks_text`, `_canvas_text`, `_layout` of `FlowBuilderPanel`, `_block_rows`, and the 14 names of `[Code: canvas grid helpers]`). No re-pointed or new test line spells one: a node that asserted a removed widget hidden drops that assertion (the walks R-TUI-059.25/1 and R-FX-SCR.4/1 carry the guard), and a mutant is cited by its case id. **Checked at integration, before the GREEN run** (pinned at E3 round 2, E3A-R2-4, S2-1), on the merged tree after Inc 9, with two commands. (1) `git grep -n -w -e flow_help -e flow_canvas -e flow_blocks -e flow_kind -e flow_ext_session -e fx_help -e _flow_block_label -e _blocks_text -e _canvas_text -e _block_rows -e _Grid -e _plc_block -e _chip -e _wire_bend -e _wire_drop -e _block_width -e _short_ext -e _CANVAS_COLS -e _BLOCK_W -e _EXT_BLOCK_W -e _S_WIRE -e _S_LABEL -e _S_VALUE -e _S_HEAD -- s19_app tests`. (2) `_layout`, narrowed to the removed method: `git grep -n -e 'def _layout(' -e 'self\._layout(' -- s19_app/tui/flow_screens.py` and `git grep -n -e '\._layout(' -- tests`. **Expected output of each: empty.** Any line is RED; the outputs are recorded. On base: (1) gives 145 lines (88 in `flow_screens.py`, 57 in the 12 base files of G-T3's list; Inc 9's `_add_load_block` adds its `#flow_kind` line on the merged tree); (2) gives 2 lines (`flow_screens.py:1912`, `:1965`) and 0. `_layout` is narrowed because `git grep -w _layout` gives 38 lines on base, of which 36 stay: `A2lParameterPicker._layout` (`a2l_parameter_picker.py`, 6), the `_layout` attributes of `FlowExecutionPanel` (`flow_screens.py:3285`, `:3490`, `:3670`, `:3767`, `:4109`) and of two `screens_directionb.py` panels (10), the module helper of `tests/test_b101_issues_severity_view.py:107` with its calls (14), and a Check Editor `getattr(panel, "_layout", None)` (`tests/test_b97_width.py:379`) | G4 → G-T3, G-T4; the testers of Inc 9, 10a, 10b, 12 (`../../inc-12/E1-rulings.md` §5) |
| I-4 the visible oracles | the chain: `#flow_pipeline` (cards), its frame title `chain · <n> block(s)`; the session: `#flow_name_strip`; the kind: `.flow-kind-tag`, `KindChip` `chip-selected`; a hostile ref: the card's plain text holds the literal brackets and the input adds no style span (cards scrub with `safe_text` and clip to the card width; E3 S-2); a re-pointed input stays whole when it fits a card, otherwise it keeps one of each hostile kind it carries (E3 S2-2) | unchanged producers → G-T3, G-T4 |

Interfaces with other increments:

| With | What is shared | Rule |
|---|---|---|
| Inc 9 (merges first) | the module docstring of `flow_screens.py` (Inc 9 `:5-10`, `:32-33`; 12b `:12-20`); `tests/test_b101_flow_names_ui.py` (`_add_load_block` reads `#flow_kind`, E3A-05) | 12b's E4 writes after Inc 9's merge; the helper is on G-T3's list |
| Inc 12 (merges after 12b, last in the `app.py` chain) | no code edge (no node of either calls a node of the other; 12b removes no action and no dialog, so Inc 12's census counts do not move). DOSSIER F-35 and `_FIXED`: Inc 12's; CTX-SHELL terms: identical text in both records, the first to merge folds them; `tests/test_tui_directionb.py`: two flow nodes here, the TC-011 docstring there (disjoint hunks); `tests/test_id_registry.py`: +1 here, +2 there | 12b marks no DOSSIER row; if the merge order flips, the increment that merges second marks F-35 |
| Inc 10a, 10b | none (neither touches `flow_screens.py`) | — |

Order inside E4: G4, then G-T3 and G-T4 in parallel (disjoint files). Integration after Inc 9 merges: the census of `../E1-slice.md` §5 and the I-3 grep are re-run on the merged tree before the GREEN run.

## Nodes

FlowBuilderPanel.__init__
req: R-TUI-059.25
in:
out: None
func: changed (D-4 A; I-2). was: no kind attribute (the hidden select `#flow_kind` holds the kind, value `source` at compose). / now: `self._kind: str = BLOCK_SOURCE` beside `_blocks`, `_flow_name`, … , commented as the kind the chips chose, written only with a value of `_KIND_OPTIONS` (S-1).
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) the Flow Builder opened → the kind tag `◉ LOAD`, the LOAD chip marked `chip-selected`, `#flow_ref` shown with the label `image file`

FlowBuilderPanel.set_session_dir
req: R-TUI-059.25
in: str path
out: None
func: changed (D-5 A). was: stores `_session_dir`, then when mounted updates the hidden `#flow_ext_session` (`session: <path> — on confirm, the output file is copied here`, or `session: (no active project)`) and the ribbon (`:1587-1597`). / now: stores `_session_dir` and, when mounted, refreshes the ribbon only (R-FB-RIB.2).
module: s19_app/tui/flow_screens.py
examples: (AT-I12b-1, holds on base) a project open → `#flow_name_strip` shows `session` and the tail of the project folder
examples: (test edit TC-B100-31) the session folder after `q` is read from `#flow_name_strip`, not from `#flow_ext_session`

FlowBuilderPanel.compose
req: R-TUI-059.25
in:
out: ComposeResult widgets
func: changed (D-4 A, D-5 A). was: also yields the help label `#flow_help` (`:1607-1612`), `#flow_canvas` and `#flow_blocks` painted from `_canvas_text()` / `_blocks_text()` (`:1619-1620`), the select `#flow_kind` as the first child of `#flow_add_row` (`:1627`) and `#flow_ext_session` (`:1692-1693`). / now: none of the five; every other part in the order of CTX-BUILDER (R-TUI-059.21).
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) walk [opened; the 7 kind chips; Variables open; the Add notice; 3 LOAD blocks] → 0 ids never shown; `48` ids in the population (the union of the ids mounted over the walked states, E3A-03; E5 QA-1, QA-7: the walk counts the whole window by widget, `53` = these 48 + `screen_flow`, `window_help_flow`, `open_folder_flows` + Textual's internal `label` of the two Selects, `e5c-02`)
examples: (R-TUI-059.25/1 neg, the base) the same walk → never shown: `flow_blocks`, `flow_canvas`, `flow_ext_session`, `flow_help`, `flow_kind` (B line 25)

FlowBuilderPanel._refresh_blocks
req: R-TUI-059.25
in:
out: None
func: changed (D-5 A). was: repaints the hidden `#flow_blocks` and `#flow_canvas` (`:2109-2110`), then the pipeline, its frame title, the legend and the ribbon. / now: the pipeline (`pipeline_text`), its frame title, the legend and the ribbon only.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) 3 × (`prg.s19`, `+ Add`) → the pipeline paints `3` LOAD cards; the frame title `chain · 3 blocks`
examples: (the base) the same Adds → the hidden canvas painted `3` times and the hidden list `3` times (B line 23)

FlowBuilderPanel.on_button_pressed
req: R-TUI-059.25, R-FB-ADD.1
in: Button.Pressed event
out: None
func: changed (D-4 A; I-2; S-1). was: a kind chip sets the hidden select (`#flow_kind`, `:2506`), whose options refuse any value outside `_KIND_OPTIONS`, syncs the add form and clears the notice; `+ Add` reads the kind from the select (`:2515`). / now: a kind chip's kind, when it is a value of `_KIND_OPTIONS`, is stored in `self._kind`, then `_sync_kind_dependent_visibility(kind)` and the cleared notice as before; any other `flow_palette_<suffix>` press returns with nothing changed; `+ Add` reads `self._kind`; the other branches are unchanged.
module: s19_app/tui/flow_screens.py
modify: [Data: FlowBuilderPanel._kind] (replace)
examples: (R-TUI-059.25/1) `#flow_palette_check` pressed → the kind tag `✓ CHECK`; `#flow_gating` shown; the CHECK chip marked (R-FB-ADD.1)
examples: (AT-I12b-1) `space` on the `✓ CHECK` chip, `baseline.chk.json` typed, `enter` on `+ Add` → the pipeline paints `1` CHECK card (R-FB-ADD.3)
examples: (R-FB-ADD.1/2, S-1) the CHECK chip pressed, then a `Button.Pressed` from a stray `flow_palette_bogus` button → `_kind` unchanged; the kind tag `✓ CHECK`, `#flow_gating` shown; then `baseline.chk.json`, `+ Add` → `1` CHECK card
examples: (R-FB-ADD.1/2 neg) mutant: the suffix stored unchecked → after the stray press `+ Add` shows `Add needs …` and adds nothing → RED
examples: (R-FB-ADD.1/2, the base) the stray press → `InvalidSelectValueError` from the hidden select (R, textual 8.2.8 `widgets/_select.py:577-594`)
examples: (R-TUI-059.25/1) the LOAD chip, `#flow_ref` empty, `+ Add` → the notice `Add needs image file — nothing added` shown (R-FB-ADD.4, holds on base)
examples: (the base) each of the 7 chips pressed → the hidden select's value equals the chip's kind (B line 22)

FlowBuilderPanel.on_mount
req: R-TUI-059.25
in:
out: None
func: changed (D-4 A, D-5 A). was: hides `#flow_help`, `#flow_canvas`, `#flow_blocks`, `#flow_kind`, `#flow_ext_session` (`:2584-2589`), syncs the add form to the select's value, hides the funnel editor and list, and paints. / now: no hide loop; the first sync reads `self._kind`; the funnel editor and list still start hidden (Variables shows them); the rest unchanged.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) opened → `#flow_funnel_editor` hidden; after `#flow_funnel_toggle` → shown (B: the walk displays it)

FlowBuilderPanel.on_select_changed
req: R-TUI-059.25
in: Select.Changed event
out: None
func: changed (D-4 A). was: `flow_kind` → `_sync_kind_dependent_visibility(event.value)`; `flow_ext_mode` → relabel the command box (`:2606-2616`). / now: the `flow_ext_mode` branch only (R-FB-ADD.14, .15).
module: s19_app/tui/flow_screens.py
examples: (holds on base) the EXT-STEP chip, mode set to Manual → the label `instruction`, the placeholder `what the human does`

FlowBuilderPanel._sync_kind_dependent_visibility
req: R-TUI-059.25
in: str kind
out: None
func: unchanged. Shows the chosen kind's inputs only, tags the add row with the kind's glyph and name, and marks its chip (`:2618-2652`): every visible effect of the kind.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1, holds on base) `a2b` → `#flow_ref_a`, `#flow_ref_b` and their Browse chips shown, `#flow_ref` hidden; the tag `⏚ A2B-DIFF`

FlowBuilderPanel._name_strip_text
req: R-TUI-059.25
in:
out: Text ribbon
func: unchanged. `ribbon_text(_flow_name, _dirty, kinds, _session_dir, width)` (`:1708-1723`): the ribbon carries the session that `#flow_ext_session` mirrored.
module: s19_app/tui/flow_screens.py
examples: (AT-I12b-1, holds on base) a project open → the ribbon holds `session` and the project folder's tail

pipeline_text
req: R-TUI-059.25
in: Sequence[FlowBlock] blocks; int card_w; int spare = 0; Callable? resolver = None
out: Text pipeline
func: unchanged. The visible chain: one row of cards joined by cables (`:1083-1161`); the re-pointed tests read the chain here instead of `#flow_blocks` and `#flow_canvas` (I-4). Its cards scrub each ref with `safe_text` (`:933`) and clip it to the card width (`:1017-1022`, `:1065-1069`), so a re-pointed markup node keeps its hostile input whole when it fits a card, otherwise cuts only plain letters and keeps one of each hostile kind it carries (a markup tag, a C0 byte, a C1 byte, DEL, the sentinel), and never loosens its check (S-2, S2-2).
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1, holds on base) 3 LOAD blocks of `prg.s19` → 3 cards headed `◉ LOAD`, joined by cables
examples: (R-FB-RIB.3, holds on base) a hostile ref added → the pipeline paints it as text, no injected style (as `tests/test_b97_flow_builder.py::test_at_b97_08_hostile_and_nul_refs_never_crash_or_inject` reads it): the surface the re-pointed markup-safety nodes move to
examples: (S-2, E5 mutant) the ref painted through `Text.from_markup` in `_card_rows` → every re-pointed markup node → RED

FlowBuilderPanel._canvas_text
req: R-TUI-059.25
in:
out: Text canvas
func: removed (D-5 A). was: the batch-94 framed grid with file chips, box blocks and cables (`:1955-2094`), painted into the hidden `#flow_canvas` at compose and on every `_refresh_blocks`. / now: absent with `[Code: canvas grid helpers]`.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) census → no `_canvas_text` in `flow_screens.py`; no test names it (C line 178)
examples: (the base) one paint with 3 blocks: `0.33` ms on the LAN host (B line 24)

FlowBuilderPanel._layout
req: R-TUI-059.25
in:
out: tuple(list positions, dict chips, int height)
func: removed (D-5 A). was: the canvas layout (`:1912-1953`); its one caller is `_canvas_text`. / now: absent. (`FlowExecutionPanel._layout`, an attribute holding a `LaneLayout`, is another name and stays.)
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) census → the method is absent; `FlowExecutionPanel._layout` is untouched (C line 160, 176)

FlowBuilderPanel._block_rows
req: R-TUI-059.25
in: FlowBlock block; int index
out: list rows
func: removed (D-5 A). was: the IO rows of one canvas block (`:1857-1910`), read by `_layout` and `_canvas_text` only. / now: absent.
module: s19_app/tui/flow_screens.py
examples: (R-TUI-059.25/1) census → absent (C line 161)

FlowBuilderPanel._blocks_text
req: R-TUI-059.25
in:
out: Text listing
func: removed (D-5 A). was: the numbered list `<n>. <label>` (or `(no blocks yet)`) painted into the hidden `#flow_blocks` (`:2096-2104`). / now: absent; the test nodes that read `#flow_blocks` read the pipeline (I-4).
module: s19_app/tui/flow_screens.py
examples: (the base) no block → `(no blocks yet)`; one LOAD `prg.s19` (S19) → `1. LOAD  prg.s19  (s19)`
examples: (test edit) `tests/test_flow_crc_ui.py::test_at128_crc_node_renders_and_shows_status` reads the CRC card of `#flow_pipeline` in place of `_blocks_text()`

_flow_block_label
req: R-TUI-059.25
in: FlowBlock block
out: str label
func: removed (D-5 A). was: the one-line label of the hidden list (`:373-398`; it still reads `REPORT  (generation deferred - FB-P1b)`, false since batch 60, S16 D16-6); its one caller is `_blocks_text`. / now: absent; its two direct tests are rewritten against the card text or removed, the card test that takes over a hostile input named in the E4 record (`../E1-slice.md` §5, S-2).
module: s19_app/tui/flow_screens.py
examples: (the base) `CheckBlock("c.json")` → a label starting `CHECK`; `SourceBlock("img.s19")` → starting `LOAD`
examples: (R-TUI-059.25/1) census → absent; no source names it

FlowExecutionPanel.compose
req: R-FX-SCR.4
in:
out: ComposeResult widgets
func: changed (D-5 A). was: also yields the help label `#fx_help` (`:3320-3326`) between the run row and the set row. / now: without it; the parts in the order of CTX-FXSCREEN (R-FX-SCR.2).
module: s19_app/tui/flow_screens.py
examples: (R-FX-SCR.4/1) walk [no lane; `flash_chain` imported; its Run waiting; the set saved as `s`] → 0 ids never shown; `34` ids in the population (the union over the walked states; the lane widgets mount on the import, E3A-03; E5 QA-1, QA-7: the walk counts the whole window by widget, `38` = these 34 + `screen_flow_execution`, `window_help_flow_execution`, `open_folder_session` + Textual's internal `label` of the one Select, `e5c-02`)
examples: (R-FX-SCR.4/1 neg, the base) the same walk → never shown: `fx_help` (B line 27)

FlowExecutionPanel.on_mount
req: R-FX-SCR.4
in:
out: None
func: changed (D-5 A). was: fills the set name, hides `#fx_help` and `#fx_required`, clears the notice and lays out (`:3348-3354`). / now: the same without the `#fx_help` line; `#fx_required` still starts hidden and is shown while a lane waits (`:4190`).
module: s19_app/tui/flow_screens.py
examples: (R-FX-SCR.4/1) the Run of `flash_chain` waiting → `#fx_required` shown (`log + output file: REQUIRED for flash_chain · press c to confirm`)

## Entities

[Data: FlowBuilderPanel._kind]
in: str
desc: new (D-4 A; I-2): the block kind the chips chose, `BLOCK_SOURCE` at construction; replaces the hidden select `#flow_kind` as the holder, and takes over its check: written only with a value of `_KIND_OPTIONS` (E3 S-1). The NUL refusal (`nul_add_refusal`) and the A2B / EXT-STEP branches key on it through `_ADD_PATH_INPUTS.get(kind, ())`, so an unknown kind would skip them; the guard keeps the kind one of the seven.

[Code: canvas grid helpers]
desc: removed with `FlowBuilderPanel._canvas_text` (D-5 A): `_Grid` (`:585-634`), `_plc_block` (`:637-659`), `_chip` (`:662-668`), `_wire_bend` (`:671-684`), `_wire_drop` (`:687-713`), `_block_width` (`:559-563`), `_short_ext` (`:566-571`), `_CANVAS_COLS` (`:547`), `_BLOCK_W` (`:550`), `_EXT_BLOCK_W` (`:556`), `_S_WIRE` (`:576`), `_S_LABEL` (`:578`), `_S_VALUE` (`:579`), `_S_HEAD` (`:581`) and the comments that introduce them. Each is read only by members of the family (C lines 162-175); no other module and no test names one. Kept: `_S_RULE`, `_S_DIM`, `_S_OUT`, `_S_ERR`, `_join_lines`, `_binding_label` (read elsewhere).

[Doc: flow_screens docstrings]
desc: no behaviour. The module docstring's "fb_a doctrine" paragraph (`:12-20`: the framed canvas, its box blocks and cables, the ledger strip `#flow_blocks`) is rewritten to the shipped surface (the pipeline of cards and the kind chips with the add form); `KindChip` (`:1284-1286`) names the panel's kind, not `#flow_kind`; `FlowBuilderPanel` (`:1389-1390`) drops the sentence on the hidden canvas and list. Inc 9 rewrites the same module docstring's import sentences (`:5-10`, `:32-33`): adjacent hunks, and 12b writes after Inc 9's merge.

## Edges

FlowBuilderPanel.on_button_pressed ──▶ [Data: FlowBuilderPanel._kind]
when: a kind chip `#flow_palette_<kind>` whose kind is a value of `_KIND_OPTIONS` (S-1)
[Data: FlowBuilderPanel._kind] ──▶ FlowBuilderPanel.on_button_pressed
when: `+ Add` builds the block of that kind
[Data: FlowBuilderPanel._kind] ──▶ FlowBuilderPanel.on_mount
FlowBuilderPanel.on_button_pressed ──▶ FlowBuilderPanel._sync_kind_dependent_visibility
FlowBuilderPanel.on_mount ──▶ FlowBuilderPanel._sync_kind_dependent_visibility
FlowBuilderPanel._refresh_blocks ──▶ pipeline_text
FlowBuilderPanel.set_session_dir ──▶ FlowBuilderPanel._name_strip_text

## Findings

> E2-1 (split from Inc 12's E2-1 at E3). Size: 2 active rows and 17 nodes (9 changed, 5 removed, 3 context); 3 entities (the 14 grid helpers are the one entity `[Code: canvas grid helpers]`, removed together; no test names one); 7 edges; 1 source file. The test work is the 39 re-pointed nodes in 13 files (G-T3) and one new file of 4 cases (G-T4). It depends on no `app.py` change, so it runs off the serial `app.py` chain once Inc 9 has merged.
> E2-2 (E3 S-1). Removing `#flow_kind` removed the kind's only check (the select's options). The chip branch keeps it: a kind outside `_KIND_OPTIONS` is ignored, so Add, the NUL refusal and the A2B / EXT-STEP branches always see one of the seven kinds (R-FB-ADD.1/2). No save or run reads the kind (`current_flow` carries blocks, not a kind), so nothing stale can be saved; the guard replaces the loud failure the base gave.
> E2-3 (E3 S-2). The security nodes among the 39 keep their hostile inputs and their painted-text assertions when they move to the cards; the two E5 mutants (`nul_add_refusal` → `None`; the ref through `Text.from_markup` in `_card_rows`) must turn them RED. A re-pointed input stays whole when it fits a card; otherwise it keeps one of each hostile kind it carries (a markup tag, a C0 byte, a C1 byte, DEL, the sentinel), so its control-byte checks can still fail (E3 S2-2).
> E2-4. Coverage of the requirement → node map: R-TUI-059.25: the `FlowBuilderPanel` nodes, `pipeline_text`, `_flow_block_label`; R-FX-SCR.4: `FlowExecutionPanel.compose`, `.on_mount`; the cited R-FB-ADD.1: `FlowBuilderPanel.on_button_pressed`. Every active row and every case of `../02-test-cases.md` (R-TUI-059.25/1, R-FX-SCR.4/1, R-FB-ADD.1/2, AT-I12b-1) has at least one concrete example.
