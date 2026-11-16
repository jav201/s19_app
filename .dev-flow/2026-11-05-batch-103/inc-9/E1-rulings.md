# Inc 9 — E1 rulings: Inc 8 rows changed, open decisions, Inc 8 changes needed, capture verdicts

Base `593d56a4`. Rows: `01-requirements.md`; cases: `02-test-cases.md`; slice: `E1-slice.md`; evidence: `evidence-e1/`. Every decision in §3 and every Inc 8 change in §4 is **PROPOSED — awaiting orchestrator ruling**; the rows carry the recommended option.

## 1. Sources and what the approved design fixes

- **G2 q1 `q1_pe=approve`** (`../design/G2-verdict-2026-11-12.md`, round `b103_ux_r2`): for CURVE, MAP and VAL_BLK the detail under the selected sheet row is pe_C's bench — a one-hue heat grid (MAP, VAL_BLK) or an eighth-block column chart (CURVE) with the values on the cells, a rectangular selection, the tool row `s Set · d +Δ · p ×% · i Interpolate · m Smooth · u Undo · shift+arrows select`, the changed-bytes line; the formula bar becomes the op line `<name>[<where>] op = … <tool> on <k> cells ✓  enter apply  alt+s stage record`; the sheet subtitle `enter edit · ↑↓ row · arrays open the bench`; array rows show a summary strip and count (Current), `<k> cells` / `<k> pts` (New), `max |Δ| <n>` (Δ), `<lo> … <hi>` (Limits); LANDS IN shrinks.
- Scenes read (read only, cited by name, never copied): round 2 `variants/pe_mix.py`, `scn_pe.py`, captures `pe_mix.pe-curve.118.png`, `pe_mix.pe-map.118.png`, `pe_mix.pe-valblk.118.png`; round 1 (archive) `variants/pe_C.py`, `_pe_common.py`, `scn_pe.py`.
- **Findings on the evidence (what the capture does not fix, so a row had to):**
  - The prototype never wired the cell cursor or the selection: `scn_pe.py` sets the rectangle from the driver; no key moves it (`pe_mix.py` binds only up/down/enter and `alt+s`). The key model is D-2.
  - Interpolate and Smooth are "drawn, not wired" (`pe_mix.py` docstring). Their arithmetic is D-9 and CTX-PE-BENCH *result*.
  - The VAL_BLK decode is a prototype stand-in ("PROTOTYPE decode (no VAL_BLK model yet)" on the capture); Inc 3's I-2 now decodes it, so the definition line and cells are real.
  - The axis labels are indices (`x0 … x7`, `0 4 8 …`); I-2 now gives the axis point texts (D-6).
  - The bench decodes synchronously and paints every cell; Inc 3a E3S3-03 forbids that for large objects (M3).
- **Where the rows deviate from the capture, and why** (DF-04 (b): a proposal adjusts the requirement; each is a decision below): the key model (D-2), staying on the row after a stage (D-3), the summary strip bound (D-4), the axis labels (D-6), the window line for large objects (R-PE-BENCH.37, new: the capture has no large object), the `↑ <k> more rows above` line (taken from the prototype's render code).

## 2. Changes to Inc 8 rows (with reasons; each is also an Inc 8 change in §4)

| # | Row | Before (Inc 8) | After | Reason |
|---|---|---|---|---|
| R-1 | R-PE-DEF.1 | landing pane 9 rows, always | **Withdrawn**, split into R-PE-DEF.1.1 (no bench: 9 rows) and R-PE-DEF.1.2 (bench: 6 rows) | The capture shrinks LANDS IN while a bench is shown (Inc 8 `E1-slice.md` §4 already names the `-bench` class). |
| R-2 | R-PE-DEF.36 | threshold: a curve row of software_a; a refused row | threshold: a refused row; an object of kind `""` (CUBOID) | Curves now have the bench (R-PE-BENCH.3); the text and the rule are unchanged. |
| R-3 | R-PE-DEF.60 | When a stage writes the document → select the next row | When a stage **from the formula bar** writes the document → select the next row | A record stage keeps the row (R-PE-BENCH.6, D-3 A). |
| R-4 | CTX-PE-DEF staging sheet subtitle | `enter edit · ↑↓ row` | `enter edit · ↑↓ row · arrays open the bench` (R-PE-BENCH.1) | The approved capture's text; Inc 8 cut the tail because it had no bench. |
| R-5 | CTX-PE-DEF definition line | no record layout word | ` · <record layout>` after the byte order when the definition names one (R-PE-BENCH.4) | The capture shows `RL_U16`; I-2 fills `record_layout` for Inc 3's kinds only (pilot `DEFC.*.record_layout`), so Inc 8's scalar lines are unchanged (Inc 8 D-7 A stands). |

R-PE-DEF.32 does not change (a refused definition has row kind `none`). No canon row outside Inc 8's is changed.

## 3. Decisions — PROPOSED, awaiting orchestrator ruling

### D-1 — The seam between the bench and Inc 8's `StagingSheet` (revised for Inc 8 E3, **per Inc 8 E3R1**) *(the `KindOps` text and the entries are superseded at E3R1: §8 S-1)*

Inc 8's E3 (`../inc-8/E3-rulings.md` on `b103-inc8` `6f0724a1`, E3A-02) replaces the three I-8.5 tables with one pinned table `_KIND_OPS: dict[str, KindOps]`; `KindOps` = `label`, `editable`, `value_text(row) -> str`, `staged(row, image, overlay) -> bool`, `preview(definition, a2l_data, text, overlay) -> Preview`, `detail(row, preview, width, state) -> list[Text]`, `submit(name, text) -> Message`; `build_row`, the preview, submit and `set_document` dispatch through it; a kind with no entry gets the pinned fallback (Current `<n> values`, no editor, staged = a span byte differs). E3R1 has not landed; this decision is designed against that text. *(Superseded: Inc 8's E3R1 and E3R2 landed, §8 S-1.)*
- **A (recommended):** Inc 9 adds three `_KIND_OPS` entries (`curve`, `map`, `array`) and keeps a **thin** subclass `ArrayBenchSheet(StagingSheet)` for the three things no per-kind table can carry in Textual: class-level `BINDINGS` (shift+arrows, page keys, `s d p i m u`, Escape, `alt+s`); the bench-focus mode (overrides of `action_edit`, `action_move`, `action_choose`, `_on_formula_escape`, each calling `super()` off a bench row); the thread workers (overrides of `show_page` and `set_document` that call `super()` first, and a handler of the sheet's own `SelectionChanged`). The entries: `label` `op =`; `editable` True; `value_text` and `staged` = Inc 8's pinned fallbacks; `preview` → a `Preview` with no result (the bench previews off the thread after an apply, R-PE-BENCH.66); `detail` → the bench lines; `submit` → `ArrayBenchSheet.BenchApplyRequested(name, text)`, which the subclass handles (the tool apply, R-PE-BENCH.51), so `on_input_submitted` is not overridden. Needs from Inc 8 (K-1, K-2, K-3, C-1, C-2 in §4). Consequence: no `_paint` duplication; Inc 9's widget code is keys, focus and workers.
- **B:** a full `KindOps` with `bindings`, `on_select` and `jobs` fields, no subclass. Consequence: Inc 8 pins a key-routing and worker protocol it does not use; Textual bindings are class-level, so Inc 8 would route keys by hand in `on_key`.
- **C:** Inc 9's E4 starts after Inc 8 merges and edits Inc 8's nodes (E3A-02 option B). Consequence: no parallel build.

### D-2 — Keys for the cell cursor and the selection (visible)

The capture says only `shift+arrows select`; up/down are the sheet's row keys (Inc 8 R-PE-DEF.45); left/right choose an enum entry (R-PE-DEF.47).
- **A (recommended):** a bench focus. Enter on a bench row gives the bench the focus (the sheet body keeps the keyboard focus with the bench mode on, cursor `▸` shown); there arrows move the cursor and collapse the selection, shift+arrows extend it, page up/down page, `s d p i m` choose the tool, `u` undoes, Enter goes to the op input, Escape back to the rows; in the op input Enter applies, Escape returns to the bench; `alt+s` stages from either. Consequence: single-cell moves without selecting (the capture's two separate Set points need it); the app's non-priority `s`, `d`, `p` (save project, describe tag, projects) are shadowed while the bench has the focus (ctrl+s keeps working: priority).
- **B:** no bench focus: shift+arrows extend from the sheet body, ctrl+arrows move without selecting, tool keys on the body. Consequence: one Enter fewer; `s`, `d`, `p` are shadowed whenever an array row is selected; ctrl+arrows are not in the design.
- Both need the E4 pilot of every key (shift+arrows, alt+s, page keys, letters) under Windows Terminal (P rows).

### D-3 — The selection after a record stage (visible)

- **A (recommended):** stay on the row (R-PE-BENCH.6); Inc 8's R-PE-DEF.60 is narrowed to formula-bar stages and `note_staged` gains `advance=False` (C-8). Consequence: the staged record stays in view; a large object is not decoded again on the way back.
- **B:** select the next row, as Inc 8 does for scalars (`enter stage ↓`). Consequence: no Inc 8 change; the bench closes after every record stage, and going back to a large object re-decodes it (≈ 11 s per 1,048,576 elements).

### D-4 — The summary strip in the Current column

Every array row of the page needs its values for a strip. Measured: V171 33 arrays/curves/maps, the largest 64 elements; software_a 466, the largest 822, none above 4,096 (`KINDS.*`); a 1,048,576-element object costs ≈ 11 s and ≈ 200 MiB to decode ([B1]).
- **A (recommended):** decode, off the UI thread and in page order, every bench row of at most 4,096 elements (≈ 45 ms each at [B1]'s 11 µs); a larger row shows `<count> values` until it is selected and decoded. Consequence: every real file gets strips; a hostile page cannot stall or flood memory.
- **B:** no strip: Current is always `<count> values`. Consequence: no page decodes; departs from the capture.
- **C:** decode every row off the thread whatever its size. Consequence: a page of large hand objects holds gigabytes.

### D-5 — Axis points on the bench

- **A (recommended):** the bench edits element values only; axis points are labels. Consequence: COM_AXIS points are refused by I-2 anyway (`A2L-DEF-AXIS-SHARED`, pilot `AXIS.CURVE.X.COM`), FIX points too (`AXIS.MAP.Y.FIX`); only STD_AXIS points could be edited, with the monotony rule (R-A2L-DEF.129); the capture shows no axis editing.
- **B:** STD_AXIS points editable as an extra grid row/column. Consequence: about 8 more rows (cursor on axis cells, monotony refusal statuses), above the cap.

### D-6 — Axis labels (visible)

- **A (recommended):** label by the axis point texts (map columns `224 577 648 909`, rows `10 15 20`; curve ticks `242.500 …`), falling back to indices. Consequence: the operator sees the breakpoints; differs from the capture's `x0 …` (the prototype had no axis model).
- **B:** indices, as the capture. Consequence: the breakpoints are invisible on the bench.

### D-7 — What value a tool computes from (visible)

The shown text is rounded: VAL_BLK_DEF_0001's (1,0) shows `11.0` but holds 10.95 (stored 219 × 0.05).
- **A (recommended):** the decoded physical value (I-2 `Decoded.value`), then the result text rounds to the display precision. ×% 10 on (1,0) gives `12.0` (10.95 × 1.1 = 12.045; pilot `TOOL.VB.PCT10`). Consequence: repeated tools do not drift by the display rounding; the operator may expect `12.1`.
- **B:** the shown text as a number (11.0 × 1.1 = 12.1). Consequence: what-you-see arithmetic; each tool adds up to half a display step of error.
- With either: a result on the display grid can be off the stored grid (LINEAR factors that are not a power of ten), and I-2 refuses it (`A2L-DEF-ENCODE … is not integral`, pilot `TOOL.VB.SET.(0,0).'10.03'`); the bytes line and the op line show the refusal. Snapping to the stored grid needs an I-2 function that does not exist (backlog, §7).

### D-8 — What a record stage writes

- **A (recommended):** the whole record (`Encoded` from `encode_values` is the whole record, R-A2L-DEF.123) as one bytes entry, through I-8.2: equal span → replace, no intersection → append, partial → refuse. Consequence: one entry per object; a second stage replaces it over the overlay (R-PE-BENCH.71); a 1 MiB object makes a 1 MiB entry.
- **B:** only the changed runs. Consequence: smaller entries, but the next stage of the same object partly overlaps them (`CHG-COLLISION`, refused by R-PE-DEF.55) unless I-8.2 learns to merge runs.

### D-9 — Interpolate and Smooth (visible)

They are on the approved tool row but were never wired.
- **A (recommended):** in Inc 9, by the CTX-PE-BENCH *result* rule (per grid row, by column position; Smooth a 3-point mean of the values before the tool, ends kept). Consequence: 3 rows; the operator judges the arithmetic in V-8.
- **B:** defer them (backlog); the tool row shows four tools. Consequence: a visible removal from the approved row.

### D-10 — Size: 80 rows, 47 graph nodes (43 new, 4 Inc 8 changes)

- **A (recommended):** keep one increment. The rows are at the cap of about 80; Inc 9's own nodes are 43; the other 4 are the Inc 8 nodes of §4 (C-1, C-4, C-6, C-8), which land in Inc 8's graph if accepted. `codewire/graph-inc9.md` tags every node 9a or 9b, so a split stays mechanical.
- **B:** split along the visible boundary *see* vs *edit*: **9a** read-only benches (M1–M4, M8: rows, canvas, decoding, window; about 42 rows, about 20 nodes) and **9b** editing (M5–M7: keys, tools, op line, staging; about 37 rows, about 26 nodes). Consequence: two E3/E4/E5 cycles; 9a alone lets the operator see arrays and still patch them through the Inspector's `Use parameter`.

### D-11 — Files and groups (the cap: 4 source files per worker group)

- **A (recommended):** three groups (`E1-slice.md` §1): **B** the bench, 3 new modules (`s19_app/tui/definition_bench.py` pure model, `s19_app/tui/definition_bench_view.py` pure render, `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` widget); **A9** staging, 2 Inc 8 files with added functions only (`services/change_service.py`, `app/patch.py`); **I** integration lines in 4 Inc 8 files (`patch_editor/panel.py`, `definition_sheet.py` table keys, `styles.tcss`, `patch_editor/layout.py` only if C-4 is not taken by Inc 8). Order: B's two pure modules build in parallel with Inc 8's E4; the widget, A9 and I need Inc 8's code (a subclass of a class that does not exist yet cannot run), so they build on Inc 8's merged branch.
- **B:** one widget module holding model, render and widget. Consequence: one file instead of three; the cell rules are tested only through Textual.

## 4. Inc 8 changes needed — PROPOSED (Inc 9 may only add functions, modules and I-8.5 keys)

Status after Inc 8's E3 rulings: **taken** = Inc 8's E3R1 is to make it as ruled; **open** = still PROPOSED here. Every row is **per Inc 8 E3R1** and is re-checked when the correction lands. *(Re-checked at Inc 9 E3R1; final statuses and the named exceptions: §8 S-2, S-12.)*

| C | Inc 8 node or interface | Change | Needed by | Status | If refused |
|---|---|---|---|---|---|
| C-1 | `PatchEditorPanel.__init__` (Inc 8 P2) | `self._sheet = ArrayBenchSheet(id="patch_sheet")`; applied by Inc 9's integrator after Inc 8 merges | D-1 A | open | D-1 B or C |
| C-2 | I-8.4 extension (pin) | the overridable methods of D-1 A (`action_edit`, `action_move`, `action_choose`, `_on_formula_escape`, `show_page`, `set_document`); `SelectionChanged` also handled by the sheet itself; `selected_name`; `states` (K-1); child ids `#patch_sheet_body`, `#patch_sheet_input`; `_paint()` as the one repaint entry | D-1 A | open | D-1 B |
| C-3 | I-8.5 → `_KIND_OPS` (E3A-02) | was: pin `row_kind` for added `_EDITABLE_KINDS`. Now: Inc 9 adds `_KIND_OPS["curve"/"map"/"array"]`; `row_kind` names any kind with an entry | the seam | taken (E3A-02) | — |
| K-1 | `KindOps.detail(row, preview, width, state)` | `state` = the sheet's per-row editor state (`states.get(name)`, `None` for Inc 8's kinds), and the rows left for the detail (`room`) | R-PE-BENCH.3, .30, .31, .36 | open *(§8 S-3)* | the subclass puts `room` in its state object (couples the state to the sheet's height) |
| K-2 | `KindOps.cells` (new optional field) | `cells(row, state, widths) -> tuple[Text, Text, Text, Text, Text] or None` (Kind, Current, New, Limits, Δ); `None` → Inc 8's cell rules | R-PE-BENCH.10 … .17 | open | Current is Inc 8's fallback `<n> values` for every array row and New / Δ / Limits follow the scalar rules: D-4 becomes B, R-PE-BENCH.10 … .17 are withdrawn |
| K-3 | `KindOps.bar` (new optional field) | `bar(row, state, width) -> tuple[str, Text] or None` — the formula bar's name text (`<name><where>`) and tail; `None` → Inc 8's `formula_tail` | R-PE-BENCH.50, .66, .93 | open | the op line shows Inc 8's tail for a kind with an editor (no `<where>`, no tool, no verdict) |
| C-4 | `LayoutMixin.compose` / CTX-PE-DEF | subtitle `enter edit · ↑↓ row · arrays open the bench` (R-4) | R-PE-BENCH.1 | open | Inc 9's integrator edits one string in `layout.py` after merge |
| C-5 | R-PE-DEF.1 / `styles.tcss` | split (R-1); Inc 9 adds `PatchEditorPanel.-bench #patch_inspector { height: 6; }`; the subclass sets `-bench` on its panel ancestor; E3A-05 (b)'s `min-height: 12` on the sheet window still holds | R-PE-DEF.1.2 | open | LANDS IN keeps 9 rows; the bench loses 3 |
| C-6 | `_definition_line` / CTX-PE-DEF | ` · <record layout>` when the definition names one (R-5); scalars unchanged | R-PE-BENCH.4 | open | Inc 9 writes its own bench definition line (one more node) |
| C-7 | I-8.2 `_stage_encoded` | was: add `staged_message`. Now `_stage_encoded(name, encoded, shown)` (E3A-03); `stage_values` passes `shown`. **Open point:** Inc 8's template is `staged as <shown>`, R-PE-BENCH.72 wants `staged: <k> values`. Recommended: if Inc 8 keeps its template, reword R-PE-BENCH.72 to `Patch Editor: <name> staged as <k> <value word> (<n> B at 0x<X>).` with `shown` = `<k> <value word>` | R-PE-BENCH.72 | taken (signature); template open *(§8 S-4)* | reword R-PE-BENCH.72 |
| C-8 | `note_staged(name)` → `select_after(name)` (E3A-07), R-PE-DEF.60 | Inc 9 needs no move after a record stage: `note_staged(name, advance: bool = True)`; R-PE-DEF.60 narrowed (R-3). `select_after` clearing `pending[name]` is harmless for a bench row | D-3 A | open (the `name` argument: taken) | D-3 B |
| C-9 | R-PE-DEF.36 threshold | the curve case moves to R-PE-BENCH.3 (R-2) | — | open | Inc 8's curve no-editor case fails once Inc 9 lands |
| E-1 | E3S-01 one source image | the bench decodes, previews and stages over the source view (`ChangeService.source_image_view`) the sheet reads (R-PE-BENCH.70, .71) | — | taken | — |
| E-2 | E3S-03 busy gate | R-PE-BENCH.83: a record stage is refused while a session action runs; R-PE-110's list gains "a record stage (alt+s)" | — | taken for the scalar stage; open for the record stage | a record stage writes during a project load |
| E-3 | E3A-04 page definitions | the page summary job reads the definitions Inc 8's `show_page` receives from the picker; no describe added | R-PE-BENCH.23 | taken | — |
| E-4 | E3A-01 row window | R-PE-BENCH.2 is only the start row and the `↑` line while a bench is shown, over Inc 8's window | R-PE-BENCH.2 | taken *(§8 S-5)* | — |
| E-5 | E3S-05 equal limits | the bench's ramp and chart never divide by hi − lo (CTX-PE-BENCH cell look, chart look); the array Limits cell is the dots form | R-PE-BENCH.11, .30, .31 | taken | — |

The I-8.5 keys Inc 9 adds, **per Inc 8 E3R1**: the three `_KIND_OPS` entries of D-1 A; no edit of `_EDITABLE_KINDS`, `_FORMULA_LABELS` or `_DETAIL_BY_KIND`, which E3A-02 folds into `_KIND_OPS`.

## 5. Interfaces, risks and notes

Consumed, pinned elsewhere, unchanged: **I-2** (`../inc-3/codewire/graph-inc3.md` §Interfaces): `describe_definition`, `decode_values`, `encode_values`, `element_name`, `display_text`, `Definition` (`kind`, `shape`, `element_count`, `index_mode`, `record_layout`, `axes`, `decimals`, `datatype`, `conversion_type`, `limits`, `unit`, `address`, `byte_length`), `AxisDefinition`, `DecodedAxis`, `DecodedValues`, `Encoded`, `Refusal`, `Position`, and its consumer obligations E3S3-03 (large decodes) and E3S3-04 (markup). **I-8.1** `StagedOverlay`. **I-8.2** `_stage_encoded(name, encoded, shown)` (E3A-03). **I-8.4** `StagingSheet` with `select_after(name)` and the row window (E3A-07, E3A-01; C-2 proposes pins). **I-8.5** `_KIND_OPS` (E3A-02; keys only, K-1 … K-3 proposed). All **per Inc 8 E3R1** *(superseded by the final forms: §8 S-7)*. **I-1** `OsClipboardInput` (the op input is Inc 8's formula input). **I-4** the A2L signature (Inc 5) through Inc 8's `show_page`.

Produced (pinned in `codewire/graph-inc9.md` §Interfaces; no later increment consumes them): **I-9.1** `ArrayBenchSheet(StagingSheet)` and its messages `ArrayBenchSheet.BenchApplyRequested(name: str, text: str)` (the `KindOps.submit` result) and `ArrayBenchSheet.RecordStageRequested(name: str, edit: tuple[tuple[Position, str], ...])`; **I-9.2** `ChangeService.stage_values(definition, a2l_data, edit, image) -> ChangeActionResult`.

### 5.1 Risks and notes for E3 / E4

- **Inc 8 E3 (failed, E3R1 pending):** *(superseded: landed, §8 S-8)* every dependency on the corrected I-8.x is marked **per Inc 8 E3R1** in the rows, this file and the graph; re-check them when E3R1 lands. K-1 … K-3, C-1, C-2 and C-4 … C-9 are best ruled inside Inc 8's E3R1 so its re-review sees them.
- **E3:** Inc 9 pins no interface a later increment uses, but it proposes changes to Inc 8's pinned interfaces (K-1, K-2, K-3, C-1, C-2, C-8) and takes operator text (the operand, through Inc 8's formula input). Recommendation: fold C-1 … C-9 into Inc 8's due E3 pass (one review of the shared interfaces, DF-03).
- **Keys to pilot at E4 (P rows):** shift+arrows (also open for QuickMap), `alt+s` on a non-modal screen, page up/down on a focused widget over the app's non-priority bindings, `s d p i m u` over the app's `s`, `d`, `p`, Escape on a focused body.
- **Memory:** R-PE-BENCH.26 bounds what is kept (compact numbers, not `DecodedValues`); the peak during one I-2 decode of 1,048,576 elements is still ≈ 200 MiB ([B1]) — I-2 has no paged decode.
- **Stored grid:** tool results on a display grid that is not the stored grid are refused per cell (D-7 note). Backlog: an I-2 "nearest stored value" encode option (an I-2 change, Incs 2/3 closed).
- **Threads:** I-2 is pure and reads its inputs only; each job takes a snapshot of the overlay's entries and a load/document generation; a result is applied on the UI thread only if both generations still match (R-PE-BENCH.22, .24, .78). *(Superseded: §8 S-9.)*
- **Timing evidence:** the pilot ran on `<runner>` at load average 8.76 / 7.95 / 6.47 on 16 cores (`pilot_inc9-transcript.txt`); its only timing (a 64-element decode, 1.9 ms) is not used for a decision (HT-08). The large-object costs are Inc 3's [B1].
- **Tests:** Inc 9 changes no existing test. Inc 8's sheet tests run against the subclass once C-1 lands; Inc 8's curve no-editor case (R-PE-DEF.36) is retargeted (C-9).
- **Trace at batch end:** this file withdraws R-PE-DEF.1 and redefines R-PE-DEF.1.1, .36, .60; Inc 8's file still defines them. The canon fold takes Inc 9's text for these four ids. *(Superseded: Inc 9 changes no Inc 8 row; the fold takes Inc 8's text, §8 S-10.)*

## 6. Capture verdicts needed (real Windows Terminal captures, 118×54 and 220×60; 80×24 where named)

Each element is visible to the operator and needs a real-capture verdict, batched with Inc 7 and Inc 8 into one review page (DF-09).

| V | Element | Rows | What the operator judges |
|---|---|---|---|
| V-1 | The sheet with a bench open: subtitle, LANDS IN at 6 rows, `↑ <k> more rows above` | R-PE-BENCH.1 … .3, R-PE-DEF.1.2 | The row window and the shrunk landing pane. |
| V-2 | Array rows: `MAP 4x3`, the summary strips, `<n> values`, `… <n>`, `<k> cells` / `<k> pts`, `max |Δ| <n>`, `<lo> … <hi>`, `◆` / `●` | R-PE-BENCH.10 … .18 | D-4 A (strips up to 4,096 elements). |
| V-3 | The curve chart: bars, the edited points, the old level, the ticks | R-PE-BENCH.30, .32, .34 | Real I-2 values (DEFC) instead of the prototype's. |
| V-4 | The map grid: shaded cells, edited `*`, the axis labels as breakpoints | R-PE-BENCH.31, .32, .34 | D-6 A (axis texts, not `x0 …`). |
| V-5 | The VAL_BLK grid, 1-D (16 columns, row offsets) and 2-D (`MATRIX_DIM 3 2`) | R-PE-BENCH.31, .32 | The 2-D layout was never shown. |
| V-6 | A large object: `decoding <n> values …`, the window line, paging | R-PE-BENCH.21, .36, .37, .43 | New elements (no large object in the round). |
| V-7 | The cursor `▸`, the selection bar / underline, the bench focus, Escape back | R-PE-BENCH.40 … .47 | D-2 A (the key model). |
| V-8 | The tool row and the tools' results, Interpolate and Smooth included | R-PE-BENCH.35, .44, .52 … .58 | D-7 A (physical arithmetic), D-9 A. |
| V-9 | The op line: `<name>[<where>] op =`, `<tool> on <k> cells`, ` ✓` / ` ▲ <n> notices` / ` ✗ <message>`, the cut | R-PE-BENCH.50, .66, .93 | The verdict texts. |
| V-10 | The bytes line: `<k> of <n> B differ +0x…`, `encoding …`, `✗ refused: …`, the cut | R-PE-BENCH.38, .39 | Wording. |
| V-11 | The definition line with the layout word | R-PE-BENCH.4 | C-6. |
| V-12 | A record stage: the row stays selected; `staged: <k> values (…)`, the notice and refusal statuses | R-PE-BENCH.6, .72 … .78, .81 | D-3 A; wording. |
| V-13 | The tool statuses: still decoding, nothing to undo, not a number, needs numbers, no value, needs columns | R-PE-BENCH.27, .61 … .65 | Wording. |
| V-14 | The bench at 80×24 | R-PE-BENCH.5 | The narrow grid (the 5-cell columns of CTX-PE-BENCH grid geometry). |

## 7. Orchestrator rulings

Orchestrator claude-opus-5-5, 2026-11-13T13:16-0600 (from `date`). These rulings override the PROPOSED rows above.

**Not visible to the operator (decided and recorded, DF-02):**

| D | Ruling | Reason |
|---|---|---|
| D-1 | A | `_KIND_OPS` entries plus a thin `ArrayBenchSheet` subclass. Textual bindings are class-level, so B would push a key-routing protocol into Inc 8 that Inc 8 never uses. |
| D-4 | A | Strips only for arrays of at most 4,096 elements, decoded off the UI thread. Every measured real file fits, and a hostile page cannot stall the UI. |
| D-5 | A | Values only. I-2 refuses COM and FIX points anyway, and axis editing is not in the approved design (DF-04 c). |
| D-8 | A | The whole record as one entry through I-8.2. B collides with R-PE-DEF.55. |
| D-10 | A | One increment. Inc 9 has 43 nodes of its own, and the other 4 move into Inc 8's graph. The 9a/9b tags stay as the fallback. |
| D-11 | A | Three groups. The build order follows the file dependency: only group B's two pure modules build in parallel with Inc 8's E4. The widget, A9 and I build on Inc 8's merged branch. |

**Inc 8 changes (§4):** they are folded into Inc 8's E3R1 pass, which is running now.
- Accepted and pinned in Inc 8: C-2, K-1, K-2, K-3, C-6, C-8, C-9 and E-2.
- Accepted but visible, provisional in Inc 8: C-4 and C-5. *(Superseded for C-4: split by Inc 8 E3R2 (E3A-15), Inc 9 appends the clause, §8 S-11.)*
- Done on the Inc 9 side: C-1 (the integrator builds the subclass after the merge) and C-7 (Inc 8 keeps `staged as <shown>`, and **R-PE-BENCH.72 is reworded** as recommended).
- Re-check every "per Inc 8 E3R1" tag against Inc 8's E3R1 commit before Inc 9's E3.

**Visible to the operator (provisional on option A, DF-09):** D-2, D-3, D-6, D-7 and D-9. E3 and E4 proceed on these options. Each one is only final after the operator's capture verdicts V-1 … V-14. D-2 also needs the E4 key pilot on Windows Terminal.

**E3 is due:** Inc 9 changes Inc 8's interfaces. It runs once Inc 8's E3R1 and its re-review have landed, so that it reviews against the final I-8.x text.

## 8. E3R1 corrections

Worker claude-opus-5-5 (Inc 9 E3R1 corrector), 2026-11-13 15:47 -0600 (from `date`). Applies `E3-rulings.md` (binding). The old text above stays as written (PP-06); each item below supersedes the lines it names, and a marker *(§8 S-n)* sits at each stale site. Inc 8's final records: E3R1 `d9f93b47`, E3R2 `de4f462f`, E3 closed `d5d48685`.

- **S-1 (D-1; tag audit #1; E3A-01, E3A-05).** The `KindOps` text of D-1 is superseded by Inc 8's final I-8.5: `KindOps(label, editable: Callable[[Definition], bool], decode, value_text(row, decoded), staged, preview, detail(row, preview, width, state, room), submit, cells=None, bar=None)`, plus the additive field `mark=None` ruled at Inc 9 E3 (E3A-05; it enters Inc 8 at its E4 integration). D-1 A's entries are now: label `op =`; `editable` = `lambda definition: True`; `decode` = `_FALLBACK_OPS.decode` (no I-2 call: the bench decodes only in its job); `value_text`, `staged` = Inc 8's fallbacks; `preview` = `bench_preview`; `detail` = `bench_detail`; `submit` = `bench_submit`; `cells` = `bench_cells`; `bar` = `op_line`; `mark` = `bench_mark`. Inc 8's E3R1 and E3R2 have landed.
- **S-2 (§4 statuses; tag audit #2).** Final: C-2, K-1, K-2, K-3, C-6, C-8, C-9 and E-2 pinned in Inc 8; C-3 and C-7 taken; C-5 is Inc 8's (P12'); C-4 split by Inc 8 E3R2 (E3A-15); C-1 is Inc 9's (S-12).
- **S-3 (§4 K-1).** K-1 is pinned with five arguments, `detail(row, preview, width, state, room)`; `room` is not a `BenchState` field.
- **S-4 (§4 C-7).** The template point is closed: Inc 8 keeps `staged as <shown>`, and R-PE-BENCH.72 is reworded to `Patch Editor: <name> staged as <k> <value word> (<n> B at 0x<X>).` (applied at E3R1, E3A-06).
- **S-5 (§4 E-4).** R-PE-BENCH.2 is withdrawn (E3A-04), so E-4 has nothing left to take. Backlog **BL-I9-E3-1** (for PENDING P-026): the `↑ <k> more rows above` line and the start row while a bench is shown. It needs an additive Inc 8 hook ruled into Inc 8's E4 first, e.g. an optional `KindOps.lead(row, state) -> list[Text]` painted above the rows and counted in `need`; only if the operator's V-1 verdict asks for the line.
- **S-6 (§4, the I-8.5 keys line).** Valid; unchanged.
- **S-7 (§5 consumed and produced; tag audit #3).** Consumed: I-8.4 with `show_page(names, definitions, a2l_data, image)` (Inc 8 E3R2 E3A-13) and the page A2L stored by the sheet; K-1 … K-3 pinned. Produced: I-9.1 as re-pinned in `codewire/graph-inc9.md` (`RecordStageRequested(name, definition, count, outcome, generation)`, `record_staged(name)`, `generation`); I-9.2 re-pinned as `ChangeService.stage_record(name, encoded, count) -> ChangeActionResult` (E3A-03), replacing `stage_values`.
- **S-8 (§5.1, the Inc 8 E3 note; tag audit #16).** Inc 8's E3R1 landed; no dependency is left to re-check.
- **S-9 (§5.1 threads).** Superseded by E3A-03, E3S-03 and E3S-04. One bench job runs at a time (R-PE-BENCH.28). The sheet's `generation` is bumped by every `set_document` (document change or image push), and a view counter by every `show_page` and bench selection. A record job is stale when the generation changed, and any other job when either changed. The job snapshots the overlay's entries on the UI thread when it starts. The record-stage encode runs as a bench job, and the write happens on the UI thread in the app's handler, which checks the generation and `_refuse_if_busy()` first. **Conflict resolved (rule 7):** the reviewer's E3A-03 fix kept the record encode in an app-side worker, and its E3S-03 fix bounds the bench to one worker. Two worker owners cannot keep "at most one" (R-PE-BENCH.28), so the record encode joins the bench's one job slot. E1's `PatchMixin._record_stage_done` is folded into the record-stage handler, which now receives the encoded outcome.
- **S-10 (§5.1 fold rule; E3A-07).** Inc 9 changes no Inc 8 row, and the fold takes Inc 8's text. Inc 9's copies of R-PE-DEF.1, .1.1, .1.2, .36 and .60 are removed from `01-requirements.md` (M1 cites them as Inc 8's). Two regression cases stay, numbered after Inc 8's: R-PE-DEF.1.2/2 and R-PE-DEF.60/5.
- **S-11 (§7 C-4).** C-4 is split by Inc 8 E3R2 (E3A-15). Inc 8 paints `enter edit · ↑↓ row`, and Inc 9's integrator appends ` · arrays open the bench`. C-5 is Inc 8's.
- **S-12 (the seam rule of §4's heading; E3A-08).** Two named exceptions to "Inc 9 may only add functions, modules and I-8.5 keys": **C-1** (`PatchEditorPanel.__init__` builds `ArrayBenchSheet`) and **C-4** (`LayoutMixin.compose` appends the clause). Each is one line. Owner: Inc 9's integrator. Order: after Inc 8 merges, with Inc 9's B3, A9 and I. E3A-05's `mark` is not an exception, because it enters through Inc 8's E4. E1's group I nodes I4 (`_definition_line`, C-6) and I6 (`note_staged`, C-8) and its `styles.tcss` line are removed: Inc 8 made those changes.
- **S-13 (§6 capture verdicts).**
  - V-1 judges the subtitle, LANDS IN at 6 rows and Inc 8's row window with a bench; the `↑` line is withdrawn (S-5).
  - V-2 judges the marks through `mark` (R-PE-BENCH.18).
  - V-12 judges `staged as <k> values (…)`. A verdict that wants `staged:` needs an I-8.2 template parameter, which is an Inc 8 change.
  - V-13 adds the statuses of R-PE-BENCH.62 (not finite), .64 (not finite) and .67.
  - V-14 adds the narrow fallback of R-PE-BENCH.7.
- **S-14 (§3 D-10, size).** After E3R1: 82 active rows (7 added, R-PE-BENCH.2 withdrawn, 4 Inc 8 copies removed) and 47 graph nodes (45 new, 2 Inc 8 exceptions; E2 also had 47). That is over the cap of about 80 rows, by the E3 fixes. D-10 A stands, with the 9a / 9b tags as the fallback.
- **S-15 (E3R2, after the re-review `E3-rereview.md`).** The record encode stays in the bench's one worker, which the re-review confirmed sound. Changes:
  - The worker does the whole-object work, and `_job_done` only assigns its results (E3S-06).
  - The queue resumes only on `record_done(name)`, which the app handler calls after the write or a refusal (R2-01).
  - `record_staged(name, edit)` clears only the staged edit (R2-02).
  - Counts: 82 rows, 189 cases, 48 nodes. Details are in `E3-rulings.md` §E3R2 corrections; R2-03 and R2-04 are E4 addenda.
- **E4 addenda** (MINOR findings E3A-12, E3A-13, E3S-07, E3S-08; E3R2: R2-03, R2-04): `E1-slice.md` §5.
- **For the orchestrator** (not Inc 9 edits):
  - the `mark` field enters Inc 8's records and E4 (E3A-05);
  - Inc 8's E4 integrator confirms the data names Inc 9 reads (E3A-10, `codewire/graph-inc9.md` §Interfaces);
  - Inc 8's `staged` cost on a 1 MiB entry needs a check (E3S-06);
  - BL-I9-E3-1 goes to P-026.
