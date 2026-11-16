# Inc 9 — Code-Wire graph: Patch Editor CURVE / MAP / VAL_BLK benches (E2 prototype)

Batch `2026-11-05-batch-103`, increment 9, stage E2, 2026-11-13, model Opus (E1 + E2 by one agent, DF-03). Base `593d56a4`. Code-Wire `v3.1.0-8-gb6cd30d`, core only: one node per function the change adds or touches, examples taken from the requirements, real callers from `tools/codewire_extract.py` (E1 census, `../evidence-e1/cw-census-*`), every example writable as a test that fails before the change and passes after. No lint, coherence or STE gate (the lint output is kept as a record). **The prototype is this graph only**: no stub, mark or declaration in the source.

Inputs: `../01-requirements.md` (82 active rows after E3R1), `../02-test-cases.md` (189 cases after E3R2), `../E1-rulings.md` (D-1 … D-11 and the Inc 8 changes C-1 … C-9, K-1 … K-3, E-1 … E-5, all PROPOSED; this graph follows each recommended option and marks what another ruling would change with `[D-n]`), `../E1-slice.md`. Computed examples: `../evidence-e1/pilot_inc9-transcript.txt` (I-2 on `<runner>`) and `../evidence-e1/examples_inc9-transcript.txt` (the CTX-PE-BENCH arithmetic).

**Inc 8's final design is the seam** (`../../inc-8/E3-rulings.md` §E3R1 and §E3R2; records E3R1 `d9f93b47`, E3R2 `de4f462f`, E3 closed `d5d48685`): `_KIND_OPS` and `KindOps` with `decode`, `detail(…, state, room)`, `cells`, `bar` (I-8.5), `_stage_encoded(name, encoded, shown)` with the template `staged as <shown>` (I-8.2), `show_page(names, definitions, a2l_data, image)` with the stored page A2L, the row window that cuts a detail to room = visible − 1, `select_after(name)`, `note_staged(name, advance)` (I-8.4), one source image and the busy gate (the I-8.2 stage seam). **E3R1 (Inc 9, 2026-11-13, model Opus):** the E3 rulings (`../E3-rulings.md`) are applied here; every node or interface line changed says `E3R1 (<finding>)`, and the earlier re-check tags are replaced by the final forms. New examples: `../evidence-e2/examples_e3r1-transcript.txt` (`uptime` beside it).

### Groups for E4 (file ownership, D-11 A) and split side (D-10)

| Group | Files | Nodes | 9a / 9b |
|---|---|---|---|
| B1 — bench model | new `s19_app/tui/definition_bench.py` | 15 | 9a: `bench_grid`, `BenchValues.from_decoded`, `page_cursor`, `window_for`, `bench_cells`, `summary_strip`; 9b: the other 9 (`bench_mark` added at E3R1, E3A-05) |
| B2 — bench render | new `s19_app/tui/definition_bench_view.py` | 9 | 9a: `bench_detail`, `grid_canvas`, `chart_canvas`, `axis_labels`, `legend_line`, `window_line`; 9b: `tool_row`, `bytes_line`, `op_line` |
| B3 — bench widget | new `s19_app/tui/screens_directionb/patch_editor/bench_sheet.py` | 20 | 9a: `register_bench_kinds`, `on_staging_sheet_selection_changed`, `show_page`, `set_document`, `_run_job`, `_job_done`; 9b: the other 14 (`check_action`, E3A-09, and `record_staged`, E3A-03, added at E3R1; `record_done`, R2-01, at E3R2) |
| A9 — staging | `s19_app/tui/services/change_service.py`, `s19_app/tui/app/patch.py` (added functions) | 2 | 9b (E3R1, E3A-03: `stage_record` replaces `stage_values`; `_record_stage_done` folded into the record-stage handler) |
| I — the two named exceptions (Inc 8 files, after Inc 8 merges) | `patch_editor/panel.py`, `patch_editor/layout.py` | 2 | 9a: `PatchEditorPanel.__init__` (C-1), `LayoutMixin.compose` (C-4). E3R1 (E3A-08): E1's `_definition_line` (C-6) and `note_staged` (C-8) and the `styles.tcss` line left the group; Inc 8 made them |

E4 runs B1 ∥ B2 (pure; their tests import Inc 8's `definition_sheet.py`, so they run on Inc 8's E4 branch, once Inc 8's integrator has confirmed the names of "Inc 8 names Inc 9 reads" below, E3A-10), then B3, A9 and I on Inc 8's merged branch (`E1-rulings.md` D-11). Shared edits: `_KIND_OPS` keys (set at import by `register_bench_kinds`, group B3); the `-bench` CSS rule is Inc 8's (P12'), and Inc 9's sheet only sets the class.

### Interfaces

**Consumed, pinned elsewhere.**
- **I-2** (`../../inc-3/codewire/graph-inc3.md` §Interfaces), unchanged: `describe_definition(name, a2l_data) -> Definition`; `decode_values(definition, a2l_data, image) -> DecodedValues | Refusal`; `encode_values(definition, a2l_data, edit: Mapping[Position, str], image) -> Encoded | Refusal`; `element_name(definition, position) -> str`; `display_text(definition, value) -> str`; `Definition` fields read by name: `name, char_type, kind, address, byte_length, datatype, byte_order, conversion_type, method_name, decimals, unit, limits, shape, element_count, index_mode, record_layout, axes, refusal`; `DecodedValues(values, axes)`, `DecodedAxis(letter, points)`; `Position = tuple[int, ...] | tuple[str, int]`. Consumer obligations met here: E3S3-03 large decodes → `ArrayBenchSheet._run_job` (off the UI thread), `window_for` (page what is shown), `BenchValues.from_decoded` (keep compact); E3S3-04 markup → every B2 node builds `Text` with markup never parsed, file words through Inc 8's `plain`; Inc 2 E3A-07 / E3S-08 overlay → the preview and record jobs (`_run_job`) encode over `StagedOverlay` (E3R2, R2-05); E3S-11 long messages → `bytes_line`, `op_line` cut with `…`; Inc 9 reads axis points only through `DecodedValues.axes` (never `fixed_rule`).
- **I-8.1** `StagedOverlay(image, entries)` — over the source view (`ChangeService.source_image_view`, what `_strip_source_map` returns; Inc 8 E3R1 E3S-01).
- **I-8.2** `ChangeService._stage_encoded(name, encoded, shown) -> ChangeActionResult`, message `Patch Editor: <name echo> staged as <shown echo> (<n> B at 0x<X>).`; `ChangeActionResult.notices`; the stage seam: `_refuse_if_busy()` first, the source view as the image (Inc 8 E3R1 E3A-03, E3A-10, E3S-01, E3S-03). The template is Inc 8's; Inc 9 passes `shown` = `<k> <value word>` (C-7 closed, R-PE-BENCH.72 reworded at E3R1, E3A-06).
- **I-8.4** `StagingSheet` (patch_editor/sheet.py): `show_page(names, definitions, a2l_data: dict | None, image)` (Inc 8 E3R2 E3A-13: the sheet stores the page A2L as `a2l_data`, never reads `app.current_a2l_data`), `set_document(entries, image)`, `selected_name`, `select_after(name)`, `states: dict[str, object]`, `_paint()`, the overridable `action_edit`, `action_move`, `action_choose`, `_on_formula_escape`, `show_page`, `set_document`, the sheet's own `SelectionChanged`, child ids `#patch_sheet_body`, `#patch_sheet_input`, the row window (`KindOps.detail` receives room = visible − 1, a longer detail is cut, E3R2 E3A-14), messages `StageRequested`, `SelectionChanged`; `PatchEditorPanel.note_staged(name, advance=True)` (Inc 8 E3R1, C-2, C-8).
- **I-8.5** `_KIND_OPS: dict[str, KindOps]`, `ops_for(kind)`, `_FALLBACK_OPS` (label `""`, editable never, decode None with no I-2 call, value text `<n> values`, staged = one pass over the document entries' bytes inside the span, detail = the definition line), and `KindOps(label: str, editable: Callable[[Definition], bool], decode: Callable[[Definition, dict, Mapping[int, int] | None], Decoded | Refusal | None], value_text: Callable[[SheetRow, Decoded | Refusal | None], str], staged: Callable[[SheetRow, Mapping[int, int] | None, StagedOverlay], bool], preview: Callable[[Definition, dict, str, StagedOverlay], Preview], detail: Callable[[SheetRow, Preview | None, int, object | None, int], list[Text]], submit: Callable[[str, str], Message], cells: … | None = None, bar: … | None = None)` (Inc 8 E3R1 E3A-02, K-1 … K-3; E3R2 E3S-10). **Plus the additive field ruled at Inc 9 E3 (E3A-05):** `mark: Callable[[SheetRow, object | None], str | None] | None = None` (None keeps Inc 8's mark rule; called in `row_line`); it enters Inc 8 at its E4 integration, recorded in Inc 8's records by the orchestrator. Inc 9 consumes it as pinned here and sets it for its three kinds only.
- **Inc 8 names Inc 9 reads (E3R1, E3A-10; to be confirmed by Inc 8's E4 integrator, or pinned in I-8.5 as read-only data, before B1 / B2 start):** `SheetRow.name: str`, `.definition: Definition`, `.kind: str`, `.current: Decoded | Refusal | None`, `.staged: Decoded | Refusal | None`, `.is_staged: bool`; `SheetWidths.kind, .current, .new, .limits, .delta: int` (cells); `Preview(result: Encoded | Refusal | None, decoded: Decoded | None)`; `short_number(float) -> str`; `plain(str) -> str`; `name_echo(str) -> str`. The bench cuts its own lines (`bytes_line`, `op_line`) and reads no other Inc 8 helper. The bench's definition line is `_FALLBACK_OPS.detail(row, None, width, None, 1)[0]` (pinned: the definition line, with the layout word since Inc 8 E3R1 C-6), never the unpinned `_definition_line`.
- **I-1** `OsClipboardInput` (Inc 8's formula input, the op input). **I-4** through Inc 8's `show_page` (definitions and the page A2L from the picker's population describe, Inc 8 E3A-04, E3A-13).

**Produced — PROPOSED, pinned here, changed only by an orchestrator ruling.** No later increment consumes them.

```text
I-9.1  ArrayBenchSheet(StagingSheet)   patch_editor/bench_sheet.py; built by PatchEditorPanel.__init__ (C-1)
         messages: ArrayBenchSheet.BenchApplyRequested(name: str, text: str)        (KindOps.submit result)
                   ArrayBenchSheet.RecordStageRequested(name: str, definition: Definition, count: int,
                       outcome: Encoded | Refusal, generation: int,
                       edit: tuple[tuple[Position, str], ...])
                       # E3R1 (E3A-03): posted by _job_done on the UI thread after the record job's
                       # encode; count = the cells of the bench edit; definition = the bench's (page A2L);
                       # E3R2 (R2-02): edit = the edit the job encoded
         handler names: on_array_bench_sheet_bench_apply_requested (the sheet itself),
                        on_array_bench_sheet_record_stage_requested (the app, PatchMixin)
         generation -> int (read only): +1 at every set_document, i.e. every document change and image
           push (E3S-04); two private view keys (E4 C9b, P-061): a page key +1 at every show_page, a selection key +1
           at every show_page and bench selection. A record job is stale when `generation` changed; a page
           job (summary, staged) when the generation or the page key changed; a selected-row job (decode,
           preview) when the generation or the selection key changed
         record_staged(name: str, edit: tuple[tuple[Position, str], ...]) -> None: clears the row's bench
           edit and undo stack only while the row's edit still equals `edit`; a newer edit and its undo
           stay (E3R2, R2-02; R-PE-BENCH.79); a no-op for a name with no state (E4 addendum R2-03)
         record_done(name: str) -> None: the handler calls it on every branch, after the write or after
           any refusal; only then does the bench worker start its next waiting job (E3R2, R2-01); a
           no-op for a name with no state
         register_bench_kinds() at import, by assignment only (idempotent, E3A-14) (E3R1, E3A-01, E3A-05):
           _KIND_OPS["curve"] = _KIND_OPS["map"] = _KIND_OPS["array"] =
           KindOps(label="op =", editable=lambda definition: True, decode=_FALLBACK_OPS.decode,
                   value_text=_FALLBACK_OPS.value_text, staged=_FALLBACK_OPS.staged,
                   preview=bench_preview, detail=bench_detail, submit=bench_submit,
                   cells=bench_cells, bar=op_line, mark=bench_mark)
           # decode: no I-2 call at build_row; every bench decode runs only in _run_job (E3A-01)
         every bench decode and encode uses self.a2l_data (the page A2L), never app.current_a2l_data (E3A-02)
I-9.2  ChangeService.stage_record(name: str, encoded: Encoded, count: int) -> ChangeActionResult
         (E3R1, E3A-03: replaces stage_values; the UI thread only, no encode, no image)
         _stage_encoded(name, encoded, shown=f"{count} {'value' if count == 1 else 'values'}");
         ok → the result's notices = "Patch Editor: <first notice>" + " (+<m> more)" (R-PE-BENCH.73).
Bench job (E3R1, E3S-03; B3, the one worker):
  at most one runs. Waiting: record jobs in order, one per row (a newer one for the same row replaces it);
  then the selected row's slot: at most one decode and one preview (a newer request of the same
  kind replaces it; E4 C9b, P-061); then the page's
  summary and staged decodes (rows ≤ 4,096 elements) in page order (a new page or set_document replaces
  the list). A job starts on the UI thread with a snapshot of the overlay's entries and the generation.
  E3R2: the worker also does the whole-object work of its result (E3S-06: the diff runs, the finite lo/hi,
  the strip, the axis labels) and posts it with the result; _job_done on the UI thread only assigns. After
  a "record" job whose result is posted to the app, the worker stays idle until record_done(name), so the
  next job's snapshot and generation are taken after the write (R2-01).
Bench state (B1, frozen; held by the sheet in states[name], K-1):
  BenchState(cursor: tuple[int, int], anchor: tuple[int, int], tool: str, edit: Mapping[Position, str],
             undo: tuple[Mapping[Position, str], ...], origin: tuple[int, int], focus: bool,
             values: BenchValues | None, staged: BenchValues | None, axes: tuple[DecodedAxis, ...],
             preview: Encoded | Refusal | str | None, job: str | None,
             runs: tuple[tuple[int, bytes, bytes], ...], lo: float, hi: float, strip: Text | None,
             labels: tuple[tuple[str, ...], tuple[str, ...]] | None,
             status: str | None, refusal: Refusal | None)
             # E3R1: room dropped (KindOps.detail's 5th argument, E3A-01). E3R2 (E3S-06): runs / lo / hi /
             # strip / labels computed once in the worker and only assigned by _job_done
             # E4 (Inc 9-internal, not an Inc 8 interface): status = an apply / undo refusal's text (E3A-12);
             # refusal = the I-2 Refusal of the row's values decode, set by the bench worker with values None,
             # read by bench_cells (Current `--`, R-PE-BENCH.14; ruling P-056 T9 F-1, record E4-integration-b.md).
             # Inc 8's row.current cannot carry it: build_row makes no I-2 call for a bench row (E3A-01).
             # FX9c O-D (additive I-9.1 field, existing fields unchanged; ruling P-101, record E4-fixes-fx9c.md):
             # staged_delta: tuple[BenchValues, BenchValues, float | None] | None = (values, staged, max |Δ|),
             # compare=False, set by the bench worker with the "decode" / "staged" result (staged_delta()); the Δ
             # cell uses it while values and staged are those same objects, else computes as before; a deselected
             # large row drops it with its values.
             # Order pinned at E4 (ruling P-056 T9 F-4): cursor / anchor are (col, row); origin and
             # window_for's answer are (row, col).
  Grid(mode: "chart" | "grid", nx: int, ny: int, count: int, layout: "2d" | "flat")
  BenchValues(numbers: array('d'), texts: tuple[str, ...] | None, missing: frozenset[int])   index = element order
```

### Examples (data; `EX-*` ids are cited by the cases)

DEFC = `make_release_case.py --case definitions`, seed 20260001 (pilot `DEFC.*`).

| Id | Input | Output |
|---|---|---|
| EX-A1 | DEFC `VAL_BLK_DEF_0001`: VAL_BLK, SWORD big, LINEAR `CM_DEF_FINE` (0.05), `%.1` (decimals 1), unit `units`, limits −50..50, shape (3, 2), ROW_DIR, `RL_DEF_S16_ROW`, 0x800090, 12 B; image `02 e1 00 db 02 7c fe 63 fe 75 ff 2a` | texts `36.9 11.0 31.8 -20.7 -19.8 -10.7` (physical 36.85 10.95 31.8 −20.65 −19.75 −10.7); grid 3 × 2 ("2d"); definition line `└ LINEAR phys = 0.05*raw · SWORD s16 big-endian · RL_DEF_S16_ROW · 0x00800090 · 12 B` |
| EX-A2 | DEFC `MAP_DEF_0001`: MAP, SWORD big, IDENTICAL, `%.0`, limits −1000..1000, shape (4, 3), COLUMN_DIR, `RL_DEF_MAP`, 0x800070, 32 B; X STD 4 points STRICT_INCREASE, Y FIX 3 points | values (element order) `472 132 610 330 709 -890 -383 -636 843 -485 730 -556`; X `224 577 648 909`; Y `10 15 20`; Kind `MAP 4x3` |
| EX-A3 | DEFC `CURVE_DEF_0001`: CURVE, UWORD big, IDENTICAL, limits 0..65535, shape (5,), `RL_U16`, 0x800050, 10 B; X COM `AXIS_DEF_0001` | values `37818 52215 28375 58106 11719`; X `242.500 317.500 348.000 414.000 450.500`; Limits `0 … 65.5k` |
| EX-T1 | VB Set `10` on (0,0) | edit {(0,0): `10`}; `Encoded(0x800090, 00 c8 00 db 02 7c fe 63 fe 75 ff 2a, ())`; bytes line `2 of 12 B differ  +0x00 02 E1 → 00 C8`; status `Patch Editor: VAL_BLK_DEF_0001 staged as 1 value (12 B at 0x800090).` (E3R1, E3A-06) |
| EX-T2 | VB +Δ `5` on (0,0), (1,0) | edit {(0,0): `41.9`, (1,0): `16.0`}; `03 46 01 40 …`; `4 of 12 B differ  +0x00 02 E1 00 DB → 03 46 01 40`; New `2 cells`; Δ `max |Δ| 5` |
| EX-T3 | VB ×% `10` on (1,0), (2,0) | edit {(1,0): `12.0`, (2,0): `35.0`} (10.95 × 1.1 = 12.045); `2 of 12 B differ` at offsets 3, 5 |
| EX-T4 | VB Interpolate row 0, columns 0..2 | edit {(1,0): `34.3`} (34.325) |
| EX-T5 | VB Smooth row 0, columns 0..2 | edit {(1,0): `26.5`} (26.533…) |
| EX-T6 | VB Set `abc` on (1,1) | `Refusal('A2L-DEF-NUMBER', "VAL_BLK_DEF_0001[1,1]: 'abc' is not a number")` |
| EX-T7 | VB Set `60` on (0,0) | `Refusal('A2L-DEF-LIMITS', 'VAL_BLK_DEF_0001[0,0]: 60 is outside the limits -50..50')` |
| EX-T8 | VB Set `10.03` on (0,0) | `Refusal('A2L-DEF-ENCODE', 'VAL_BLK_DEF_0001[0,0]: the converted raw value 200.59999999999997 is not integral')` |
| EX-O1 | VB Set `10` (0,0), stage; Set `-5` (1,1), stage over the overlay | e2 `00 c8 00 db 02 7c fe 63 ff 9c ff 2a`; one entry; decoded `10.0 11.0 31.8 -20.7 -5.0 -10.7`. Negative control (e2 over the image): (0,0) reads `36.9` |
| EX-M1 | MAP Set `0` on (1,2) | 32 B record, `2 of 32 B differ` at offsets 18, 19 |
| EX-M2 | MAP +Δ `100` on x0..1, y0..1 | edit {(0,0): `572`, (1,0): `232`, (0,1): `809`, (1,1): `-790`}; `6 of 32 B differ` at 8, 9, 10, 11, 15, 17; where `[x0..1,y0..1]`; status `Patch Editor: MAP_DEF_0001 staged as 4 values (32 B at 0x800070).` (E3R1, E3A-06) |
| EX-M3 | MAP Set `2000` on (0,0) | `MAP_DEF_0001[0,0]: 2000 is outside the limits -1000..1000` |
| EX-C1 | CURVE bench edit `40000` on points 1, 3 (a state: one apply edits a rectangle and a second one replaces it, R-PE-BENCH.51) | `93 ba 9c 40 6e d7 9c 40 2d c7`; `4 of 10 B differ` at 2, 3, 6, 7; New `2 pts` |
| EX-C2 | CURVE ×% `50` on every point | `Refusal('A2L-DEF-LIMITS', 'CURVE_DEF_0001[1]: 78323 is outside the limits 0..65535')`; software_a first 200 names (Inc 8 EX-C1) for R-PE-BENCH.23 |
| EX-G1 | CURVE strip at W 118 (Current 18 → strip 15) | `▅▇▄█▁ 5` |
| EX-G2 | MAP / VB column means | MAP steps `10 3 8 4` (lo −890, hi 843); VB steps `6 3 6` (lo −20.65, hi 36.85) |
| EX-G3 | MAP cell steps | (1,1) `-890` step 0; (0,2) `843` step 11; the 12 in `examples_inc9-transcript.txt` |
| EX-G4 | MAP legend | `shade ████████████ -890 … 843   sel x0,y0   * / bold = edited` |
| EX-G5 | CURVE legend | `scale 7.08k … 58.1k   █ edited  ─ old level` (base 7080.3) |
| EX-G6 | grid geometry | W 96 nx 16 → 15 columns, cell 5; W 118 nx 16 → 16, cell 6; W 200 nx 16 → 16, cell 11; nx 3 or 4 → cell 20 |
| EX-G7 | chart geometry | W 118, 5 points → column 6; W 118, 64 points → column 1 |
| EX-G9 | result texts | 12.045 d1 → `12.0`; 34.325 → `34.3`; 26.533 → `26.5`; 572.5 d0 → `573`; −572.5 → `-573`; 0.30000000000000004 no d → `0.3` |
| EX-G10 | short numbers | 65535 → `65.5k`; 58106 → `58.1k`; −1000 → `-1.00k`; 1000 → `1.00k`; −890 → `-890` |
| EX-G11 | MAP Smooth row 0, columns 0..3 | (1,0) `405`, (2,0) `357` |
| EX-G13 | values all equal (lo = hi) | strip levels all 1, ramp step 0, chart bars at half height; no division |
| EX-G12 | LARGE | 1,048,576 elements, flat → 65,536 grid rows × 16 |
| EX-K1 | MAP selected, sheet focus | Enter → bench focus `▸` at (0,0); Enter → op input; Escape (op) → bench; Escape (bench) → rows |
| EX-K2 | MAP bench focus at (0,0) | right → (1,0); down → (1,1) (1 cell); shift+right, shift+down from (0,0) → 4 cells `[x0..1,y0..1]`; left at column 0 → stays |
| EX-K4 | tool keys | `s d p i m` → Set, +Δ, ×%, Interpolate, Smooth; the app's `save_project`, `a2l_describe_tag`, `load_project` not run |
| EX-K5 | undo | Set then +Δ, `u` → the Set edit; `u` → {}; `u` → `Patch Editor: nothing to undo on the bench.`; 33 applies → the 32nd `u` restores apply 1 |
| EX-H1 … H4 | hostile words | `A[/x]B`, `Map[b]x`, `[@click=app.quit]OFF[/]`; `A\x1b[2J` → `A�[2J`, U+0085; a 294-character verdict; a 300-character name → 256 + `…` |
| EX-H5 | LARGE (hand A2L: VAL_BLK UBYTE `MATRIX_DIM 1048576`, NO_COMPU_METHOD) | `1048576 values`; `decoding 1048576 values …`; window line `rows 0..<b> of 65536 · cols 0..15 of 16 · pgup/pgdn page`; ≈ 11 s / ≈ 156 MiB per I-2 decode ([B1]) |
| EX-H6 | a summary decode held by a test gate | `… 12` |
| EX-H7 | LARGE Set on 64 cells spaced 2 apart | the bytes line ends `…` at 80 and 118 |
| EX-H8 | operands | `abc`, ``, `1_0`, ESC + 300 × `9` → `Patch Editor: '<echo>' is not a number.` |
| EX-F1 | raw 2-byte entry at 0x800092, then a VB record stage | `Patch Editor: VAL_BLK_DEF_0001 overlaps the entry at 0x800092 — remove that entry first.` |
| EX-F2 … F6 | A2L unloaded; reload moving VB to 0x8000A0 or `MATRIX_DIM 2 3`; a raw entry at 0x800090; Undo during a held encode; a session action held running | the statuses of R-PE-BENCH.76, .77, .25, .78, .83 |
| EX-R6, R8 … R12 | no image / a missing last byte; no limits; an axis with no points; a COM axis object's bytes missing; a TAB_VERB VAL_BLK; a refused element; a VAL_BLK with extended limits and two cells inside them | `--`; `-`; `x0 …`; `x<c>`; the needs-numbers and no-value statuses; `… (+1 more)` |
| EX-L1, L2, W1 | subtitle; LANDS IN 6 / 9 rows at 118×54 and 220×60; every line ≤ the sheet at 80/118/220 (EX-L3, the `↑` line, withdrawn with R-PE-BENCH.2 at E3R1) | built by the tests |
| EX-W2 | content width 10 and 0, MAP_DEF_0001 and LARGE (E3R1, E3S-05) | below the bench minimum width 12: the definition line only, cut at W with one `…`; the clamped geometry at W 10 gives nc `1`, cw `5` (6 + 5 = 11 > 10, so no grid); W 12 → nc `1`, cw `5` (`examples_e3r1-transcript.txt` `GEOM.*`) |
| EX-W3 | room 1 and 0 (E3R1, E3S-05) | room 1 → the definition line only; room 0 → no bench line; chart h = max(1, min(16, room − 4)) → `1` at room 0 … 5 (`CHART.*`) |
| EX-N1 | `F32_BLK`: hand VAL_BLK FLOAT32_IEEE big, `MATRIX_DIM 3`, NO_COMPU_METHOD, image `3F800000 FFFFFFFF 40400000` (E3R1, E3S-01) | values `1`, `nan`, `3` (I-2 R-A2L-DEF.39, E3 probe `NAN.decode`); finite lo `1`, hi `3` whatever the order (`LOHI.*`); steps `0`, none, `11`; +Δ 1 over (1,) → `Patch Editor: F32_BLK[1] has no value to change.`; all three `FFFFFFFF` → lo = hi = `0`, every step 0 |
| EX-N2 | a FLOAT32 CURVE copy with values 1, inf, 3 | point 1: no bar, `?` on the chart's bottom row; lo `1`, hi `3` |
| EX-N3 | operands `1e999`, 400 × `9` (E3S-02) | each matches the number text, its double is `inf` → not finite → `Patch Editor: '<echo>' is not a number.` (`OPERAND.*`) |
| EX-N4 | `F64_BLK`: hand VAL_BLK FLOAT64_IEEE, `MATRIX_DIM 2`, NO_COMPU_METHOD, `1.7e308` at (0,); ×% `100` | `1.7e308 × 2` = `inf` → `Patch Editor: ×% gives a value that is not finite for F64_BLK[0].`; the result text rule is never called (`RESULT.*`) |
| EX-J1 | 20 LARGE rows on a page, 20 × `down` at key repeat (E3S-03) | at most `1` bench job running; peak RSS above the idle sheet ≤ `320` MiB (64 kept + 256 for one decode: 216 B × 1,048,576 = 216 MiB, rounded up; `MEM.*`) |
| EX-J2 | LARGE with a previewed Set on 4,096 cells, `right` (E3S-06) | handled within `0.5` s (quiet host): the paint formats the stored runs and the window only |
| EX-B1 | the bench state lifetime (E3A-11) | MAP_DEF_0001 +Δ 100 on (0,0), a filter keystroke → edit {(0,0): `572`} kept; DISPLAY_0001 then MAP_DEF_0001 → kept; a page without MAP_DEF_0001 then back → cursor (0,0), tool Set, edit {}; LARGE then MAP → LARGE's values dropped |
| EX-K7 | keys off the bench (E3A-09) | DISPLAY_0001, the body focused, `s` → `save_project` runs `1` time; Escape on a number row → Inc 8's R-PE-DEF.48 |
| EX-T9 | VB operand `5` typed in the op input, no Enter (E3A-05) | mark ` ` (no `◆`); after Enter `◆`; after the record stage `●` while the input still holds `5` |
| EX-F7 | Inc 8 EX-R12's pair on a VAL_BLK copy: page A2L factor 0.05, loaded A2L factor 0.025 (CM_DEF_FINE), same span (E3A-02) | the two definitions differ (`Definition ==` is False); +Δ 5, alt+s → `Patch Editor: <name> changed in the A2L — select it again to reload its values.`, entries unchanged |
| EX-F8, F9 | an Apply during a held record-stage encode; a session action started during it (E3S-04) | `Patch Editor: the change document or the image changed while VAL_BLK_DEF_0001 was encoding — stage it again.`; the busy line of R-PE-110; entries unchanged |
| EX-I1 | after `import bench_sheet` (E3A-01) | `ops_for("map")` is a KindOps; `.editable(MAP_DEF_0001)` `True`; `.decode(MAP_DEF_0001, a2l, image)` `None`; `build_row` over a page holding LARGE → `0` `decode_values` calls |

### Baseline (code in scope at `593d56a4`, real callers)

From the E1 census (`../evidence-e1/cw-census-extract.json`; C = extractor, R = read, G = Inc 8's graph, no code yet).

| Function | Callers | Inc 9 |
|---|---|---|
| I-2 `decode_values` | none in the product (C; `encode_values` → `decode_values` `a2l_definition.py:4291`) | called by `ArrayBenchSheet._run_job` |
| I-2 `encode_values` | none in the product (C) | called by `_run_job` (the preview and record jobs; E3R1, E3A-03) |
| I-2 `element_name`, `display_text` | I-2 internal only (C) | called by `apply_tool`, `bench_cells`, `grid_canvas` |
| I-2 `describe_definition` | Inc 8's `on_staging_sheet_stage_requested` (G) | called by `PatchMixin.on_array_bench_sheet_record_stage_requested` |
| `PatchEditorPanel.__init__` (`panel.py:468`) | `app/compose_screens.py:540` (C) | changed (C-1, a named exception) |
| `ChangeService._push_history` (`change_service.py:971`) | 7 sites (C) and Inc 8's `_stage_encoded` (G) | reached through `_stage_encoded` |
| `PatchMixin._report_change_result` (`app/patch.py:1155`) | 8 sites (C) | called by `PatchMixin.on_array_bench_sheet_record_stage_requested` |
| `PatchMixin._refresh_patch_history_view` (`app/patch.py:529`) | `:727`, `:762`, `:1001` (C) | called by `on_array_bench_sheet_record_stage_requested` |
| `ShellMixin._refuse_if_busy` (`app/shell.py:425`) | every Patch action (`app/patch.py:145`, R) | called by `on_array_bench_sheet_record_stage_requested` when the encode ends (the I-8.2 stage seam, Inc 8 E3R1 E3S-03; E3R1 E3S-04) |
| Inc 8 `StagingSheet.show_page(names, definitions, a2l_data, image)`, `.set_document`, `.action_edit`, `.action_move`, `.action_choose`, `._on_formula_escape` | picker `ViewChanged` (4 positional arguments, Inc 8 E3R2), `refresh_entries`, `set_image_mem_map`, textual bindings (G) | overridden in `ArrayBenchSheet`, `super()` first or off a bench row |
| Inc 8 `_KIND_OPS`, `_FALLBACK_OPS`, `_stage_encoded`, `note_staged(name, advance)`, `select_after` | Inc 8's nodes (G) | keys set; called (Inc 8's final I-8.2, I-8.4, I-8.5) |
| app bindings `s`, `d`, `p`, `pageup`, `pagedown` (`app/core.py:178-222`, non-priority) | textual | shadowed while the bench has the focus (R-PE-BENCH.43, .44); live off the bench through `ArrayBenchSheet.check_action` (E3R1, E3A-09, R-PE-BENCH.49) |

### Coverage — every requirement → nodes and examples (owner group)

| Requirement | Nodes | Examples | Group |
|---|---|---|---|
| R-PE-BENCH.1 | LayoutMixin.compose | EX-L1 | I |
| Inc 8 R-PE-DEF.1.2 (regression case /2) | ArrayBenchSheet.on_staging_sheet_selection_changed (sets `-bench`; the rule is Inc 8's) | EX-L2 | B3 |
| R-PE-BENCH.3 | bench_detail, register_bench_kinds | EX-A1, A2, A3, I1 | B2 (+B3) |
| R-PE-BENCH.4 | bench_detail (Inc 8's `_FALLBACK_OPS.detail` line) | EX-A1, A2, A3 | B2 |
| R-PE-BENCH.5 | bench_detail, grid_canvas, chart_canvas, op_line | EX-W1, W3, EX-G6, EX-H5 | B2 |
| R-PE-BENCH.6, Inc 8 R-PE-DEF.60 (regression case /5) | PatchMixin.on_array_bench_sheet_record_stage_requested (Inc 8's `note_staged(name, advance=False)`) | EX-T1 | A9 |
| R-PE-BENCH.7 | bench_detail, grid_canvas | EX-W2 | B2 |
| R-PE-BENCH.9 | ArrayBenchSheet.on_staging_sheet_selection_changed, ArrayBenchSheet.show_page | EX-B1 | B3 |
| R-PE-BENCH.10 … .17 | bench_cells, summary_strip | EX-A1 … A3, G1, G2, G10, H5, H6, R6, R8, T2, M2, C1 | B1 |
| R-PE-BENCH.18 | bench_mark (+ Inc 8's staged fallback) | EX-T1, T2, T9 | B1 |
| R-PE-BENCH.19 | grid_canvas, chart_canvas, legend_line, summary_strip, ArrayBenchSheet._job_done | EX-N1, N2 | B2 (+B1, B3) |
| R-PE-BENCH.20 … .22 | ArrayBenchSheet.on_staging_sheet_selection_changed, _run_job, _job_done, bench_detail, register_bench_kinds | EX-H5, I1 | B3 |
| R-PE-BENCH.23, .24 | ArrayBenchSheet.show_page, _run_job, _job_done | EX-A1, C2, H6 | B3 |
| R-PE-BENCH.25 | ArrayBenchSheet.set_document, _run_job | EX-T1, F4 | B3 |
| R-PE-BENCH.26 | BenchValues.from_decoded, ArrayBenchSheet.on_staging_sheet_selection_changed | EX-H5, B1 | B1 (+B3) |
| R-PE-BENCH.27 | ArrayBenchSheet.on_array_bench_sheet_bench_apply_requested, action_stage_record | EX-H5 | B3 |
| R-PE-BENCH.28 | ArrayBenchSheet._run_job, _job_done, record_done | EX-J1, Q1 | B3 |
| R-PE-BENCH.29 | ArrayBenchSheet._run_job (the derived work, E3R2), _job_done, bytes_line, legend_line | EX-J2 | B3 (+B2) |
| R-PE-BENCH.30 | chart_canvas | EX-A3, C1, G5, G7 | B2 |
| R-PE-BENCH.31 | grid_canvas, bench_grid | EX-A1, A2, G3, G6, T2 | B2 |
| R-PE-BENCH.32, .33 | axis_labels | EX-A1, A2, A3, R10 | B2 |
| R-PE-BENCH.34 | legend_line | EX-G4, G5 | B2 |
| R-PE-BENCH.35 | tool_row | EX-K4 | B2 |
| R-PE-BENCH.36 | window_for | EX-H5, A2 | B1 |
| R-PE-BENCH.37 | window_line | EX-H5, A2 | B2 |
| R-PE-BENCH.38, .39 | bytes_line | EX-A1, T1, T2, T7, H7 | B2 |
| R-PE-BENCH.40 | ArrayBenchSheet.action_edit | EX-K1 | B3 |
| R-PE-BENCH.41 | ArrayBenchSheet.action_move, .action_choose, move_cursor | EX-K2 | B3 (+B1) |
| R-PE-BENCH.42 | ArrayBenchSheet.action_cursor, move_cursor, where_text | EX-K2 | B3 (+B1) |
| R-PE-BENCH.43 | ArrayBenchSheet.action_page, page_cursor | EX-H5 | B3 (+B1) |
| R-PE-BENCH.44 | ArrayBenchSheet.action_tool | EX-K4 | B3 |
| R-PE-BENCH.45, .46 | ArrayBenchSheet.action_leave_bench, action_edit | EX-K1 | B3 |
| R-PE-BENCH.47 | ArrayBenchSheet._on_formula_escape | EX-K1 | B3 |
| R-PE-BENCH.48 | ArrayBenchSheet.action_stage_record | EX-T1 | B3 |
| R-PE-BENCH.49 | ArrayBenchSheet.check_action | EX-K7 | B3 |
| R-PE-BENCH.50 | op_line, where_text | EX-M2, C1, A1 | B2 |
| R-PE-BENCH.51 | bench_submit, ArrayBenchSheet.on_array_bench_sheet_bench_apply_requested, apply_tool | EX-T1 | B3 (+B1) |
| R-PE-BENCH.52 … .56 | apply_tool, selection_cells, parse_operand | EX-C1, M1, T2, M2, T3, T4, T5, G11 | B1 |
| R-PE-BENCH.57 | result_text | EX-G9 | B1 |
| R-PE-BENCH.58 | apply_tool | EX-M2, A1 | B1 |
| R-PE-BENCH.59, .61 | undo, ArrayBenchSheet.action_tool | EX-K5 | B1 (+B3) |
| R-PE-BENCH.62 | parse_operand, apply_tool | EX-H8, N3 | B1 |
| R-PE-BENCH.63 … .65 | apply_tool | EX-R11, T4, T5, N1 | B1 |
| R-PE-BENCH.66 | bench_preview, ArrayBenchSheet.on_array_bench_sheet_bench_apply_requested, _run_job, _job_done, op_line | EX-T2, T7, C2 | B3 (+B1, B2) |
| R-PE-BENCH.67 | apply_tool | EX-N4 | B1 |
| R-PE-BENCH.70, .72, .73, .80 | ChangeService.stage_record (+ Inc 8 `_stage_encoded`); for .70/4 ArrayBenchSheet.record_done | EX-T1, M1, C1, M2, R12, Q1 | A9 (+B3) |
| R-PE-BENCH.71 | ArrayBenchSheet._run_job (the record job over the overlay snapshot) | EX-O1 | B3 |
| R-PE-BENCH.74 | ArrayBenchSheet._run_job, PatchMixin.on_array_bench_sheet_record_stage_requested | EX-T6, T7, T8 | B3, A9 |
| R-PE-BENCH.75 | ArrayBenchSheet.action_stage_record | EX-A1 | B3 |
| R-PE-BENCH.76, .77, .83 | PatchMixin.on_array_bench_sheet_record_stage_requested | EX-F2, F3, F6, F7, F9 | A9 |
| R-PE-BENCH.78 | ArrayBenchSheet.set_document, ArrayBenchSheet._job_done, PatchMixin.on_array_bench_sheet_record_stage_requested | EX-F5, F8 | B3, A9 |
| R-PE-BENCH.79 | ArrayBenchSheet.record_staged, bench_mark | EX-T1, T9, Q2 | B3 (+B1) |
| R-PE-BENCH.81 | ChangeService.stage_record (Inc 8's `_stage_encoded` partial branch) | EX-F1 | A9 |
| R-PE-BENCH.82 | ArrayBenchSheet.action_stage_record, ArrayBenchSheet._run_job | EX-H5 | B3 |
| R-PE-BENCH.90, .91 | grid_canvas, chart_canvas, axis_labels, legend_line, op_line, bytes_line (Inc 8 `plain`) | EX-H1, H2 | B2 |
| R-PE-BENCH.92 | apply_tool, ArrayBenchSheet.action_stage_record, ChangeService.stage_record (Inc 8 `name_echo`) | EX-H4, H8 | B1, B3, A9 |
| R-PE-BENCH.93 | op_line | EX-H3 | B2 |

Every active requirement has a node and at least one concrete example; none is uncovered. Scenario examples (L, W, F, K) are built by the tests from DEFC or LARGE; they fix their expected text in the rows.

### Node count

**48 prototype nodes after E3R2** (47 after E3R1; E3R2 adds `ArrayBenchSheet.record_done`, R2-01) — one per function the change adds or touches:
- **46 new.** B1 (15): `bench_grid`, `BenchValues.from_decoded`, `move_cursor`, `page_cursor`, `window_for`, `selection_cells`, `where_text`, `parse_operand`, `apply_tool`, `result_text`, `undo`, `bench_cells`, `bench_mark`, `summary_strip`, `bench_preview`. B2 (9): `bench_detail`, `grid_canvas`, `chart_canvas`, `axis_labels`, `legend_line`, `tool_row`, `window_line`, `bytes_line`, `op_line`. B3 (20): `register_bench_kinds`, `bench_submit`, `ArrayBenchSheet.check_action`, `.action_edit`, `.action_move`, `.action_choose`, `.action_cursor`, `.action_page`, `.action_tool`, `.action_leave_bench`, `.action_stage_record`, `.on_array_bench_sheet_bench_apply_requested`, `.on_staging_sheet_selection_changed`, `._on_formula_escape`, `.show_page`, `.set_document`, `._run_job`, `._job_done`, `.record_staged`, `.record_done`. A9 (2): `ChangeService.stage_record`, `PatchMixin.on_array_bench_sheet_record_stage_requested`.
- **2 changed Inc 8 nodes (the named exceptions C-1, C-4):** `PatchEditorPanel.__init__`, `LayoutMixin.compose`.
- **E3R1 changes to the E2 count (47 → 47):** added `bench_mark` (E3A-05), `ArrayBenchSheet.check_action` (E3A-09), `ArrayBenchSheet.record_staged` (E3A-03); `ChangeService.stage_values` re-pinned as `stage_record` (E3A-03); removed `PatchMixin._record_stage_done` (folded into the record-stage handler, E3A-03 with E3S-03), `_definition_line` and `PatchEditorPanel.note_staged` (Inc 8's, E3A-08). The data types `Grid`, `BenchState`, `BenchValues`, the messages and `BINDINGS` are covered by the nodes that use them.

47 is over "about 40": `E1-rulings.md` D-10 (A keep, with the 9a/9b tags above; B split). B1 and B3 exceed about 8 nodes and cannot be split further by file ownership; B3 can run as two implementers by side (9a workers, 9b keys).

### What a different ruling changes here

- **D-1 B:** no `ArrayBenchSheet`; its 17 nodes become `KindOps` fields (`bindings`, `on_select`, `jobs`) and Inc 8 routes keys. **D-1 C:** the overrides become edits of Inc 8's nodes.
- **D-2 B:** `action_edit`, `action_move`, `action_choose`, `action_leave_bench` lose the focus mode; `action_cursor` gains ctrl+arrows.
- **D-3 B:** the record-stage handler calls `note_staged(name)` with the default `advance` (E3R1: `_record_stage_done` is folded into it).
- **D-4 B:** `show_page` starts no summary job; `bench_cells` shows `<count> values` always; `summary_strip` leaves.
- **D-5 B:** `bench_grid` gains axis rows/columns; `move_cursor` and `apply_tool` take axis positions; monotony refusal statuses.
- **D-6 B:** `axis_labels` returns indices only.
- **D-7 B:** `apply_tool` reads `Decoded.text` as v.
- **D-8 B:** `stage_record` writes the changed runs; I-8.2 needs a merge branch.
- **D-9 B:** `apply_tool` loses two tools; `tool_row` shows four.
- **K-2 refused:** `bench_cells` and `summary_strip` leave; Inc 8's fallback cells apply. **K-3 refused:** `op_line` leaves; the formula bar shows Inc 8's tail. (K-1 … K-3 are pinned in Inc 8's E3R1; these lines are history.)
- **`mark` refused at Inc 8's E4 (E3A-05):** `bench_mark` leaves; R-PE-BENCH.18 is reworded to Inc 8's pending rule and R-PE-BENCH.79 drops its mark clause.

## Nodes

bench_grid
req: R-PE-BENCH.30, R-PE-BENCH.31
in: Definition definition
out: Grid grid
func: curve → chart of shape[0] points; map and a 2-D array → grid nx × ny ("2d"); 1-D and ≥ 3-D arrays → 16 columns, ⌈count / 16⌉ rows ("flat")
module: s19_app/tui/definition_bench.py
examples: (EX-A3) CURVE_DEF_0001 → mode "chart", nx `5`, ny `1`
examples: (EX-A2) MAP_DEF_0001 → mode "grid", nx `4`, ny `3`, layout "2d"
examples: (EX-A1) VAL_BLK_DEF_0001 → nx `3`, ny `2`, layout "2d"; (EX-G12) LARGE → nx `16`, ny `65536`, layout "flat"

BenchValues.from_decoded
req: R-PE-BENCH.14, R-PE-BENCH.26
in: DecodedValues decoded
out: BenchValues values
func: element-order numbers in an array('d') (a refused element → missing; text elements kept as texts); I-2's DecodedValues is dropped after the copy
module: s19_app/tui/definition_bench.py
examples: (EX-A1) VAL_BLK_DEF_0001 → numbers `36.85`, `10.95`, `31.8`, `-20.65`, `-19.75`, `-10.7`; missing empty
examples: (EX-R11) a refused element at index 2 → missing {`2`}
examples: (EX-H5) LARGE → retained after gc ≤ `64` MiB (8 B per number)

move_cursor
req: R-PE-BENCH.41, R-PE-BENCH.42
in: BenchState state; Grid grid; int dx; int dy; bool extend
out: BenchState state
func: cursor ± one cell within the grid (no wrap); extend False → anchor = cursor; extend True → anchor kept; origin from window_for
module: s19_app/tui/definition_bench.py
examples: (EX-K2) MAP 4 × 3, cursor (0,0), dx `1`, extend False → cursor (1,0), anchor (1,0)
examples: (EX-K2) cursor (0,0), shift+right then shift+down → cursor (1,1), anchor (0,0)
examples: (EX-K2) cursor (0,0), dx `-1` → cursor (0,0)

page_cursor
req: R-PE-BENCH.43
in: BenchState state; Grid grid; int rows; int direction
out: BenchState state
func: cursor row ± rows (clamped), anchor = cursor
module: s19_app/tui/definition_bench.py
examples: (EX-H5) LARGE, cursor row 0, rows `20`, direction `1` → cursor row `20`; then direction `-1` → row `0`

window_for
req: R-PE-BENCH.36
in: BenchState state; Grid grid; int rows_shown; int cols_shown
out: tuple(int row, int col) origin
func: the least move of the origin that keeps the cursor inside the shown rows and columns; E3R1 (E3S-05): rows_shown or cols_shown below 1 count as 1, so the origin is the cursor's own row or column and the move always has an answer
module: s19_app/tui/definition_bench.py
examples: (EX-H5) origin (0,0), rows_shown `20`, cursor row `20` → origin row `1`
examples: (EX-W3) rows_shown `0`, cursor row `7` → origin row `7`
examples: (EX-H5) pagedown from row 0, rows_shown `20` → cursor row `20`, origin row `1` (window rows 1..20)
examples: (EX-A2) MAP 4 × 3, rows_shown `3`, cols_shown `4` → origin (0,0) unchanged

selection_cells
req: R-PE-BENCH.52, R-PE-BENCH.53, R-PE-BENCH.54, R-PE-BENCH.55, R-PE-BENCH.56
in: BenchState state; Grid grid
out: list[tuple] positions
func: the I-2 positions of the rectangle cursor..anchor in element order (flat: index 16·r + c, cells past count left out)
module: s19_app/tui/definition_bench.py
examples: (EX-M2) MAP anchor (0,0), cursor (1,1) → [(0,0), (1,0), (0,1), (1,1)]
examples: (EX-C1) CURVE cursor 3, anchor 3 → [(3,)]

where_text
req: R-PE-BENCH.42, R-PE-BENCH.50
in: BenchState state; Grid grid
out: str where
func: the where of CTX-PE-BENCH
module: s19_app/tui/definition_bench.py
examples: (EX-M2) MAP (0,0)..(1,1) → "[x0..1,y0..1]"; (EX-K2) (0,0) only → "[x0,y0]"
examples: (EX-C1) CURVE point 3 → "[3]"; points 1..3 → "[1..3]"; (EX-G8) flat 36..43 → "[36..43]"

parse_operand
req: R-PE-BENCH.62
in: str text
out: float? number
func: the operand number text of CTX-PE-BENCH (sign, digits, point, exponent, spaces around); None otherwise; E3R1 (E3S-02): None also when the text's double is not finite
module: s19_app/tui/definition_bench.py
examples: (EX-H8) " +1.5e2 " → `150.0`; "abc" → `None`; "" → `None`; "1_0" → `None`; ".5" → `0.5`
examples: (EX-N3) "1e999" → `None`; 400 × "9" → `None`

apply_tool
req: R-PE-BENCH.51, R-PE-BENCH.52, R-PE-BENCH.53, R-PE-BENCH.54, R-PE-BENCH.55, R-PE-BENCH.56, R-PE-BENCH.58, R-PE-BENCH.62, R-PE-BENCH.63, R-PE-BENCH.64, R-PE-BENCH.65, R-PE-BENCH.67, R-PE-BENCH.92
in: Definition definition; BenchState state; Grid grid; BenchValues values; str operand
out: BenchState state
func: the result of the current tool over selection_cells, each number through result_text; cells whose result equals the current value leave the edit; the old edit pushed on undo (≤ 32); a refusal returns the same state with its status text in BenchState.job (the sheet shows it; E4 addendum E3A-12 moves it to a `status` field). E3R1 (E3S-01, E3S-02): before any arithmetic, a selected cell whose value is missing or not finite refuses with R-PE-BENCH.64's status, and an operand that parse_operand rejects (not finite included) with R-PE-BENCH.62's; a result that is not finite refuses with R-PE-BENCH.67's status, and result_text is never called on it; no exception leaves the tool
module: s19_app/tui/definition_bench.py
examples: (EX-T1) VB Set "10" on (0,0) → edit {(0,0): "10"}
examples: (EX-T2) VB +Δ "5" on (0,0), (1,0) → edit {(0,0): "41.9", (1,0): "16.0"}
examples: (EX-T3) VB ×% "10" on (1,0), (2,0) → edit {(1,0): "12.0", (2,0): "35.0"}
examples: (EX-T4) VB Interpolate row 0, columns 0..2 → edit {(1,0): "34.3"}; (EX-T5) Smooth → {(1,0): "26.5"}
examples: (EX-G11) MAP Smooth row 0, columns 0..3 → {(1,0): "405", (2,0): "357"}
examples: (EX-M2) MAP +Δ "0" on x0..1 → edit {}; (EX-A1) VB +Δ "0" on (0,0) → edit {}
examples: (EX-H8) +Δ "abc" → status "Patch Editor: 'abc' is not a number."
examples: (EX-R11) +Δ "1" on a TAB_VERB VAL_BLK → status "Patch Editor: +Δ needs numbers — <name> holds texts."; on a refused element → "Patch Editor: <name>[2] has no value to change."
examples: (EX-T4) Interpolate on 1 column → "Patch Editor: Interpolate needs at least 2 columns in the selection."; (EX-T5) Smooth on 2 → "… needs at least 3 columns …"
examples: (EX-N1) F32_BLK +Δ "1" over (1,) (`nan`) → status "Patch Editor: F32_BLK[1] has no value to change.", edit unchanged
examples: (EX-N3) +Δ "1e999" → status "Patch Editor: '1e999' is not a number."
examples: (EX-N4) F64_BLK ×% "100" on (0,) (`1.7e308`) → status "Patch Editor: ×% gives a value that is not finite for F64_BLK[0].", edit unchanged

result_text
req: R-PE-BENCH.57
in: Definition definition; float value
out: str text
func: 15 significant digits, then half away from zero to d decimals (0 for an integer datatype with no conversion or IDENTICAL, else decimals; none → the 15-digit text). E3R1 (E3S-02): defined for a finite value only; apply_tool refuses a result that is not finite before calling it (the pilot's Decimal rule raises InvalidOperation on inf, E3 probe `RESULT_TEXT.inf`)
module: s19_app/tui/definition_bench.py
examples: (EX-G9) VB `12.045` → "12.0"; `34.325` → "34.3"; MAP `572.5` → "573"; `-572.5` → "-573"; no decimals `0.30000000000000004` → "0.3"

undo
req: R-PE-BENCH.59, R-PE-BENCH.61
in: BenchState state
out: BenchState state
func: restores the newest undo entry; an empty stack → the same state with the status "Patch Editor: nothing to undo on the bench."
module: s19_app/tui/definition_bench.py
examples: (EX-K5) undo [{}, {(0,0): "10"}], edit {(0,0): "41.9"} → edit {(0,0): "10"}; again → {}; again → status "Patch Editor: nothing to undo on the bench."

bench_cells
req: R-PE-BENCH.10, R-PE-BENCH.11, R-PE-BENCH.12, R-PE-BENCH.13, R-PE-BENCH.14, R-PE-BENCH.15, R-PE-BENCH.16, R-PE-BENCH.17, R-PE-BENCH.19
in: SheetRow row; BenchState? state; SheetWidths widths
out: tuple(Text kind, Text current, Text new, Text limits, Text delta) cells
func: KindOps.cells (K-2, pinned in Inc 8 I-8.5): the array row cells of CTX-PE-BENCH; no state or no values → Inc 8's fallback `<count> values`; a running summary → `… <count>`; the strip is the one stored in the state at _job_done (E3R1, E3S-06); max |Δ| over finite values only (E3S-01). E3R1 (E3A-05): the mark column is bench_mark's, not this entry's
module: s19_app/tui/definition_bench.py
examples: (EX-A2) MAP_DEF_0001 → kind "MAP 4x3", limits "-1.00k … 1.00k"; (EX-A3) CURVE → kind "CURVE", limits "0 … 65.5k"
examples: (EX-G1) CURVE at W 118 → current "▅▇▄█▁ 5"
examples: (EX-T2) VB edit (0,0), (1,0) → new "2 cells", delta "max |Δ| 5"; staged and no edit → "max |Δ| 5.1 staged"
examples: (EX-C1) CURVE edit on points 1, 3 → new "2 pts"; (EX-H5) LARGE not decoded → current "1048576 values"; (EX-H6) running → "… 12"; (EX-R6) decode refused (state.refusal set, E4) → "--"; (EX-R8) no limits → "-"

bench_mark
req: R-PE-BENCH.18, R-PE-BENCH.79
in: SheetRow row; BenchState? state
out: str mark
func: new at E3R1 (E3A-05): the KindOps.mark entry (the additive I-8.5 field, entering Inc 8 at its E4): "◆" while state.edit is not empty; "●" while row.is_staged; else " ". It never reads the formula text, so an operand typed but not applied paints no "◆"
module: s19_app/tui/definition_bench.py
examples: (EX-T2) VB edit {(0,0): "41.9", (1,0): "16.0"} → "◆"
examples: (EX-T1) edit {}, row.is_staged `True` → "●"; staged and a new edit → "◆"
examples: (EX-T9) VB operand "5" typed, no Enter (edit {}, not staged) → " "; after the record stage (edit {}, staged, input "5") → "●"

summary_strip
req: R-PE-BENCH.11, R-PE-BENCH.19
in: BenchValues values; Grid grid; int width
out: Text strip
func: chart: an eighth block per k-th point, level 1 + round(t × 7); grid: one `█` per k-th column in the ramp step of its mean; lo = hi → t 0 (no division). E3R1 (E3S-01): t, lo and hi over the finite values only; a point that is not finite, or a column with no finite value, is a space. E3R1 (E3S-06): computed once in _job_done and stored in the state
module: s19_app/tui/definition_bench.py
examples: (EX-G1) CURVE values, width `15` → "▅▇▄█▁"
examples: (EX-G2) MAP → 4 × "█" on steps `10`, `3`, `8`, `4`; VB → steps `6`, `3`, `6`
examples: (EX-G13) values all `7` → levels all 1, no ZeroDivisionError
examples: (EX-N1) F32_BLK `1`, `nan`, `3` → a space for the `nan` column, no ValueError

bench_preview
req: R-PE-BENCH.66
in: Definition definition; dict a2l_data; str text; StagedOverlay overlay
out: Preview preview
func: KindOps.preview (pinned in Inc 8 I-8.5): Preview(result None, decoded None) — the bench never previews on a keystroke; the preview job runs after an apply
module: s19_app/tui/definition_bench.py
examples: (EX-T2) VB, text "5" → result `None`

bench_detail
req: R-PE-BENCH.3, R-PE-BENCH.4, R-PE-BENCH.5, R-PE-BENCH.7, R-PE-BENCH.21
in: SheetRow row; Preview? preview; int width; BenchState? state; int room
out: list[Text] lines
func: KindOps.detail (K-1 as pinned in Inc 8 I-8.5; E3R1 E3A-01: `room` is the 5th argument, not a state field): the definition line `_FALLBACK_OPS.detail(row, None, width, None, 1)[0]` (E3A-10), then the canvas (or "decoding <count> values …" while state.job is "decode"), window_line, legend_line, tool_row, bytes_line; cut to `room` lines, nothing when room < 1; under the bench minimum width (12) the definition line only, cut at width with one `…` (E3R1, E3S-05)
module: s19_app/tui/definition_bench_view.py
examples: (EX-A1) VB, decoded → lines start "└ LINEAR phys = 0.05*raw · SWORD s16 big-endian · RL_DEF_S16_ROW · 0x00800090 · 12 B", then the grid rows, legend, tool row, "no edit yet · bytes appear here"
examples: (EX-H5) LARGE, job "decode" → line 2 "decoding 1048576 values …"
examples: (EX-W1) width `76` (80 columns) → every line's cell length ≤ `76`
examples: (EX-W2) MAP, width `10` → 1 line, cell length ≤ `10`, ends "…"; width `0` → 1 empty line, no exception
examples: (EX-W3) MAP, room `1` → 1 line (the definition line); room `0` → `0` lines

grid_canvas
req: R-PE-BENCH.5, R-PE-BENCH.7, R-PE-BENCH.19, R-PE-BENCH.31, R-PE-BENCH.90, R-PE-BENCH.91
in: Definition definition; Grid grid; BenchValues values; BenchValues? staged; BenchState state; int width; int room
out: list[Text] lines
func: the grid geometry and cell look of CTX-PE-BENCH over the window; value texts plain (markup never parsed, controls → U+FFFD). E3R1 (E3S-05): nc = max(1, min(nx, ⌊(W − 6)/6⌋)), rows shown ≥ 1, no line when room < 1 — no width-derived division by zero; E3R1 (E3S-01): the ramp over the stored finite lo/hi, a cell that is not finite unshaded with its value text; the window only (E3S-06)
module: s19_app/tui/definition_bench_view.py
examples: (EX-G3) MAP at width `114` → 4 × 3 cells, (1,1) "-890" on step `0`, (0,2) "843" on step `11`
examples: (EX-A1) VB → rows "36.9 11.0 31.8" and "-20.7 -19.8 -10.7"
examples: (EX-T2) edit (0,0), (1,0) → "41.9*", "16.0*" bold
examples: (EX-G6) width `96`, nx 16 → `15` columns of `5` cells
examples: (EX-H1) an element text "[@click=app.quit]OFF[/]" → shown literally, no link
examples: (EX-N1) F32_BLK → cells "1", "nan", "3"; "nan" unshaded; (0,) step `0`, (2,) step `11`
examples: (EX-W2) width `12`, nx 16 → `1` column of `5` cells; width `10` → nc `1` (no ZeroDivisionError; bench_detail shows the definition line only)

chart_canvas
req: R-PE-BENCH.5, R-PE-BENCH.19, R-PE-BENCH.30, R-PE-BENCH.90
in: Definition definition; Grid grid; BenchValues values; BenchValues? staged; BenchState state; int width; int room
out: list[Text] lines
func: the chart look of CTX-PE-BENCH over the window of points. E3R1 (E3S-05): h = max(1, min(16, room − 4)), no line when room < 1; E3R1 (E3S-01): bars over the stored finite lo/hi, a point that is not finite has no bar and a `?` on the chart's bottom row
module: s19_app/tui/definition_bench_view.py
examples: (EX-A3) CURVE at width `118` → 5 columns of width `6`; the fourth tallest; top label "58106", bottom "11719"
examples: (EX-C1) edit points 1, 3 "40000" → those columns in the edit colour, "40000" above, "─" at the old levels
examples: (EX-G7) 64 points at `118` → column width `1`
examples: (EX-N2) a FLOAT32 CURVE copy (1, inf, 3) → point 1 "?" on the chart's bottom row, top label "3", bottom "1"
examples: (EX-W3) room `3` → h `1` (was 4 > room)

axis_labels
req: R-PE-BENCH.32, R-PE-BENCH.33
in: Definition definition; tuple[DecodedAxis, ...] axes; Grid grid
out: tuple(list[str] columns, list[str] rows) labels
func: the axis labels of CTX-PE-BENCH (plain text); points None or a point refusal → the index form. E3R2 (E3S-06): called in the worker after a decode, once per decode; the labels are posted with the values and stored, and the canvases take only the window's slice at paint
module: s19_app/tui/definition_bench_view.py
examples: (EX-A2) MAP → columns ["224", "577", "648", "909"], rows ["10", "15", "20"]
examples: (EX-A3) CURVE → columns ["242.500", "317.500", "348.000", "414.000", "450.500"]
examples: (EX-A1) VB → columns ["0", "1", "2"], rows ["0", "1"]; (EX-G12) LARGE → columns "+0" … "+15", rows "0", "16", …
examples: (EX-R10) an axis with points None → ["x0", "x1", …]

legend_line
req: R-PE-BENCH.19, R-PE-BENCH.34
in: Definition definition; Grid grid; BenchValues values; BenchState state
out: Text line
func: the legend line of CTX-PE-BENCH; E3R1 (E3S-01, E3S-06): lo and hi are the finite ones stored in the state at _job_done (updated from the edit's cells on an apply), never a merge over every shown value at paint
module: s19_app/tui/definition_bench_view.py
examples: (EX-G4) MAP, selection (0,0) → "shade ████████████ -890 … 843   sel x0,y0   * / bold = edited"
examples: (EX-G5) CURVE → "scale 7.08k … 58.1k   █ edited  ─ old level"
examples: (EX-N1) F32_BLK, selection (0,) → "shade ████████████ 1 … 3   sel 0   * / bold = edited"

tool_row
req: R-PE-BENCH.35
in: str tool
out: Text line
func: the tool row of CTX-PE-BENCH, the current tool's key and label in the selected style
module: s19_app/tui/definition_bench_view.py
examples: (EX-K4) "s" → " s  Set" span in the selected style; "d" → " d  +Δ" span selected

window_line
req: R-PE-BENCH.37
in: Grid grid; tuple origin; int rows_shown; int cols_shown
out: Text? line
func: the window line of CTX-PE-BENCH, or None when every row and column is shown
module: s19_app/tui/definition_bench_view.py
examples: (EX-H5) LARGE, origin (0,0), rows_shown `20`, cols `16` → "rows 0..19 of 65536 · cols 0..15 of 16 · pgup/pgdn page"
examples: (EX-A2) MAP, rows 3, cols 4 → `None`

bytes_line
req: R-PE-BENCH.29, R-PE-BENCH.38, R-PE-BENCH.39
in: Definition definition; tuple runs; object preview; int width
out: Text line
func: the bytes line of CTX-PE-BENCH against the record over the staged overlay; cut at width with one `…`. E3R1 (E3S-06): formats the diff runs (offset, old, new) that _job_done stored in the state; it never reads or diffs the record at paint (was: `bytes image_record`, whose builder was unstated)
module: s19_app/tui/definition_bench_view.py
examples: (EX-A1) preview None → "no edit yet · bytes appear here"
examples: (EX-T1) Encoded(0x800090, 00 c8 …) → "2 of 12 B differ  +0x00 02 E1 → 00 C8"
examples: (EX-T2) → "4 of 12 B differ  +0x00 02 E1 00 DB → 03 46 01 40"
examples: (EX-T7) Refusal → "✗ refused: VAL_BLK_DEF_0001[0,0]: 60 is outside the limits -50..50"
examples: (EX-H7) LARGE, 64 runs, width `76` → ends "…", length ≤ `76`

op_line
req: R-PE-BENCH.50, R-PE-BENCH.66, R-PE-BENCH.90, R-PE-BENCH.93
in: SheetRow row; BenchState state; int width
out: tuple(str name, Text tail) bar
func: KindOps.bar (K-3, pinned in Inc 8 I-8.5): name `<name><where>`, tail `<unit>  <tool label> on <k> <pts|cells><verdict>   enter apply  alt+s stage record`, cut with `…`
module: s19_app/tui/definition_bench_view.py
examples: (EX-M2) MAP x0..1,y0..1, tool d → name "MAP_DEF_0001[x0..1,y0..1]", tail contains "+Δ on 4 cells"
examples: (EX-C1) CURVE point 3 → name "CURVE_DEF_0001[3]", tail contains "Set on 1 pts"
examples: (EX-T2) preview with no notice → tail contains " ✓"; (EX-C2) refusal → " ✗ CURVE_DEF_0001[1]: 78323 is outside the limits 0..65535"
examples: (EX-H3) a 294-character verdict, width `100` → length `100`, ends "…"

register_bench_kinds
req: R-PE-BENCH.3, R-PE-DEF.36
in: (none)
out: None
func: at import, by assignment only (idempotent, E3A-14): _KIND_OPS["curve"], ["map"], ["array"] = the KindOps literal of I-9.1. E3R1 (E3A-01): fits Inc 8's final I-8.5 — `decode` given (= _FALLBACK_OPS.decode, no I-2 call; every bench decode runs only in _run_job, never in build_row on the UI thread), `editable` a callable (`lambda definition: True`), `detail` the 5-argument bench_detail; plus `mark` = bench_mark (E3A-05)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: definition_sheet._KIND_OPS] (append)
examples: (EX-A3) after import → `_KIND_OPS["curve"].label` "op ="; row_kind(CURVE_DEF_0001) "curve"
examples: (EX-I1) `ops_for("map")` is a KindOps; `.editable(MAP_DEF_0001)` `True`; `.decode(MAP_DEF_0001, a2l, image)` `None`; build_row over a page holding LARGE → `0` decode_values calls
examples: (EX-I1) register_bench_kinds() called twice → the same three entries
examples: (EX-R9) a CUBOID (kind "") → no entry → Inc 8's no-editor tail

bench_submit
req: R-PE-BENCH.51
in: str name; str text
out: Message message
func: KindOps.submit (pinned in Inc 8 I-8.5): ArrayBenchSheet.BenchApplyRequested(name, text)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
examples: (EX-T1) "VAL_BLK_DEF_0001", "10" → BenchApplyRequested("VAL_BLK_DEF_0001", "10")

ArrayBenchSheet.check_action
req: R-PE-BENCH.44, R-PE-BENCH.48, R-PE-BENCH.49
in: str action; tuple parameters
out: bool? enabled
func: new at E3R1 (E3A-09), the Textual override that keeps the class-level BINDINGS off outside the bench: False for "cursor", "page", "tool" and "leave_bench" unless the selected row's state has focus True; False for "stage_record" unless the bench has the focus or the op input of a bench row has it; else True. A False makes Textual skip the binding, so the key reaches the app's non-priority binding (save_project, a2l_describe_tag, load_project, page_*_context) or Inc 8's own handler. The toolkit behaviour is shown by the E4 key pilot (P)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
examples: (EX-K7) DISPLAY_0001 selected, body focused, action "tool" → `False`; the app's save_project runs `1` time on `s`
examples: (EX-K7) a number row, action "leave_bench" → `False` (Escape keeps Inc 8's R-PE-DEF.48)
examples: (EX-K4) MAP in bench focus, action "tool" → `True`

ArrayBenchSheet.action_edit
req: R-PE-BENCH.40, R-PE-BENCH.45
in: (none)
out: None
func: Enter on the body: a bench row out of bench focus → bench focus on; in bench focus → focus to the op input; any other row → super()
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace); [Data: App.focused] (replace)
examples: (EX-K1) MAP selected, focus body → states["MAP_DEF_0001"].focus `True`, "▸" before (0,0)
examples: (EX-K1) in bench focus → focus "#patch_sheet_input"; a number row → super() (focus "#patch_sheet_input")

ArrayBenchSheet.action_move
req: R-PE-BENCH.41
in: int delta
out: None
func: in bench focus → move_cursor(0, delta); else super() (Inc 8's row move)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace)
examples: (EX-K2) bench focus at (1,0), delta `1` → cursor (1,1); out of bench focus → the next row selected

ArrayBenchSheet.action_choose
req: R-PE-BENCH.41
in: int delta
out: None
func: in bench focus → move_cursor(delta, 0); else super() (Inc 8's enum choose)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace)
examples: (EX-K2) bench focus at (0,0), delta `1` → cursor (1,0); delta `-1` at column 0 → (0,0)

ArrayBenchSheet.action_cursor
req: R-PE-BENCH.42
in: int dx; int dy
out: None
func: shift+arrows in bench focus: move_cursor(dx, dy, extend True); repaint
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace)
examples: (EX-K2) from (0,0): (1,0) then (0,1) → selection 4 cells, name "MAP_DEF_0001[x0..1,y0..1]"

ArrayBenchSheet.action_page
req: R-PE-BENCH.43
in: int direction
out: None
func: page up/down in bench focus: page_cursor by the window's rows
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace)
examples: (EX-H5) LARGE row 0, window `20` rows, direction `1` → cursor row `20`

ArrayBenchSheet.action_tool
req: R-PE-BENCH.44, R-PE-BENCH.59, R-PE-BENCH.61
in: str key
out: None
func: s/d/p/i/m → the current tool; u → undo; the status of a refusal through the app's status line
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace)
examples: (EX-K4) "d" → tool "d"; the app's a2l_describe_tag runs `0` times
examples: (EX-K5) "u" with an empty stack → status "Patch Editor: nothing to undo on the bench."

ArrayBenchSheet.action_leave_bench
req: R-PE-BENCH.46
in: (none)
out: None
func: Escape in bench focus → bench focus off, focus stays on the body (rows)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace)
examples: (EX-K1) bench focus → focus `False`; then up → the row above selected

ArrayBenchSheet.action_stage_record
req: R-PE-BENCH.27, R-PE-BENCH.48, R-PE-BENCH.75, R-PE-BENCH.82, R-PE-BENCH.92
in: (none)
out: None
func: alt+s: decoding → the still-decoding status; empty edit → "Patch Editor: <name echo> has no bench edit to stage."; else E3R1 (E3A-03, E3S-03): queues a "record" bench job for the row with its edit items (the record queue of I-9.1's bench job; a newer one for the same row replaces it); nothing is written here
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
examples: (EX-T1) VB edit {(0,0): "10"} → one "record" job queued for "VAL_BLK_DEF_0001" with edit (((0, 0), "10"),); entries unchanged until the handler writes
examples: (EX-A1) edit {} → status "Patch Editor: VAL_BLK_DEF_0001 has no bench edit to stage."
examples: (EX-H5) LARGE decoding → status "Patch Editor: <name> is still decoding — try again when its values show."

ArrayBenchSheet.on_array_bench_sheet_bench_apply_requested
req: R-PE-BENCH.27, R-PE-BENCH.51, R-PE-BENCH.66
in: ArrayBenchSheet.BenchApplyRequested event
out: None
func: decoding → the still-decoding status; else apply_tool over the row's values; a changed edit starts the preview job (_run_job "preview"); focus stays in the op input
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace)
examples: (EX-T1) BenchApplyRequested("VAL_BLK_DEF_0001", "10"), tool Set, cursor (0,0) → edit {(0,0): "10"}, job "preview"
examples: (EX-T7) "60" → after the job, op line verdict " ✗ VAL_BLK_DEF_0001[0,0]: 60 is outside the limits -50..50"

ArrayBenchSheet.on_staging_sheet_selection_changed
req: R-PE-BENCH.3, R-PE-BENCH.9, R-PE-BENCH.20, R-PE-BENCH.22, R-PE-BENCH.26
in: StagingSheet.SelectionChanged event
out: None
func: the sheet's own message (it still bubbles to the picker). E3R1 (E3A-11): the row already selected → nothing changes (Inc 8's show_page re-posts the message on every rebuild); a new bench row → the selection key +1 (I-9.1), its kept state or, at its first selection, a fresh one (cursor (0,0), tool Set), the "decode" request in the selected-row slot; a deselected row of more than 4,096 elements drops values, staged and axes from its state (its edit, undo, cursor and tool stay). `-bench` on the panel ancestor set while a bench row is selected, cleared otherwise (Inc 8 owns the CSS rule). E3R1 (E3A-04): no start row and no `↑` line (R-PE-BENCH.2 withdrawn)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace); [Data: ArrayBenchSheet.generation] (replace)
examples: (EX-L2) MAP selected at 118×54 → panel has class "-bench", LANDS IN height `6`; a number row → no class, height `9`
examples: (EX-B1) MAP edit {(0,0): "572"}, SelectionChanged("MAP_DEF_0001") again after a filter keystroke → states["MAP_DEF_0001"].edit unchanged, `0` new decodes
examples: (EX-B1) LARGE decoded, then MAP selected → states["LARGE"].values `None`, retained memory back to the level before LARGE
examples: (EX-H5) LARGE then MAP before the decode ends → selection key +2; LARGE's result discarded

ArrayBenchSheet._on_formula_escape
req: R-PE-BENCH.47
in: (none)
out: None
func: a bench row → focus to the body with bench focus on, the operand kept; else super() (Inc 8's clear and back)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: App.focused] (replace)
examples: (EX-K1) MAP, operand "100" → focus "#patch_sheet_body", bench focus `True`, input "100"

ArrayBenchSheet.show_page
req: R-PE-BENCH.9, R-PE-BENCH.12, R-PE-BENCH.13, R-PE-BENCH.23, R-PE-BENCH.24
in: Sequence[str] names; Mapping[str, Definition] definitions; dict? a2l_data; Mapping[int, int]? image
out: None
func: E3R1 (E3A-02): Inc 8's final signature (E3R2 E3A-13); super().show_page(names, definitions, a2l_data, image) with all four, so the sheet stores the page A2L in self.a2l_data, which every bench job then uses; then both view keys +1, the states of rows the new definitions no longer hold dropped (E3A-11), and the page list of "summary" requests for the bench rows of ≤ 4,096 elements in page order (replacing the waiting list)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.generation] (replace); [Data: ArrayBenchSheet.states] (replace)
examples: (EX-A1) the three DEFC bench rows → `3` summary decodes in page order
examples: (EX-H5) a page with LARGE → `0` decodes for it; Current "1048576 values"
examples: (EX-C2) software_a first 200 names → Inc 8's page paint ≤ `0.5` s still holds
examples: (EX-F7) the picker passes definitions with a2l_data of factor 0.05 while app.current_a2l_data has 0.025 → the bench decodes and encodes with factor 0.05 (self.a2l_data)

ArrayBenchSheet.set_document
req: R-PE-BENCH.25, R-PE-BENCH.78
in: Sequence[tuple[int, Sequence[int]]] entries; Mapping[int, int]? image
out: None
func: super().set_document; E3R1 (E3S-04): the generation +1 on every call (Inc 8 calls it for every document change and every image push: refresh_entries, set_image_mem_map; an Apply ends with that push), so every running job's result is stale; then the selected bench row's "decode" request (current and staged) and its "preview" when it holds an edit, and the page list of "staged" requests for the rows of ≤ 4,096 elements whose span holds an entry byte (others: staged = current, no decode)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.generation] (replace)
examples: (EX-F4) a raw entry at 0x800090 → `1` staged decode (VAL_BLK_DEF_0001); MAP_DEF_0001 `0`
examples: (EX-T1) Undo of the VB record → staged = current, mark "●" gone
examples: (EX-F8) an Apply while VB's record job runs → generation +1; that job's result is dropped with R-PE-BENCH.78's status

ArrayBenchSheet._run_job
req: R-PE-BENCH.20, R-PE-BENCH.23, R-PE-BENCH.25, R-PE-BENCH.28, R-PE-BENCH.66, R-PE-BENCH.71, R-PE-BENCH.74, R-PE-BENCH.82
in: str kind; str name; int generation; Definition definition
out: None
func: E3R1 (E3S-03): the one bench worker. A request goes into the waiting slots of I-9.1's bench job; when no job runs, the next one starts (record, then the selected row's, then the page list), on the UI thread with a snapshot of the overlay's entries `tuple((e.address, tuple(e.encoded_bytes)) for e in entries)`, the current generation and view keys (E3A-03); then one thread worker (textual, thread=True, one at a time): "decode" / "summary" / "staged" → decode_values over the source view or StagedOverlay(image, snapshot) → BenchValues.from_decoded; "preview" and "record" → encode_values(definition, self.a2l_data, edit, StagedOverlay(image, snapshot)) → Encoded or Refusal; every decode and encode with self.a2l_data, never app.current_a2l_data (E3A-02); E3R2 (E3S-06): the worker also computes, over its own result and the snapshot, the whole-object work: for a decode the finite lo/hi, the strip (summary_strip) and the axis labels (axis_labels); for a preview the diff runs (offset, old, new) against the record over the snapshot; the worker writes nothing and posts (kind, name, generation, result, derived) to _job_done through call_from_thread. E3R2 (R2-01): a "record" job's next job waits for record_done
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
examples: (EX-J2) "preview" of LARGE with a 4,096-cell Set → the 1,048,576-byte diff and lo/hi run in the worker; the UI thread does no O(element count) step for it
examples: (EX-H5) "decode" LARGE → the UI handles "down" within `0.5` s while it runs
examples: (EX-T2) "preview" VB edit → Encoded(0x800090, 03 46 01 40 …)
examples: (EX-O1) "record" VB {(1,1): "-5"} after a first stage → Encoded(0x800090, 00 c8 00 db 02 7c fe 63 ff 9c ff 2a) over the snapshot
examples: (EX-J1) 20 LARGE rows, 20 × "down" → `1` job running at most; the waiting "decode" slot holds only the newest row; peak RSS ≤ `320` MiB above idle

ArrayBenchSheet._job_done
req: R-PE-BENCH.19, R-PE-BENCH.21, R-PE-BENCH.22, R-PE-BENCH.24, R-PE-BENCH.29, R-PE-BENCH.66, R-PE-BENCH.78
in: str kind; str name; int generation; object result; object derived
out: None
func: on the UI thread, O(1) per job apart from the repaint of the window: a stale job (I-9.1: a record job when `generation` changed, a page job when the generation or the page key changed, a selected-row job when the generation or the selection key changed) → dropped (a "record" job: the status "Patch Editor: the change document or the image changed while <name echo> was encoding — stage it again.", document and edit unchanged, E3S-04), then the next waiting job starts; a fresh "record" result → posts RecordStageRequested(name, definition, count, outcome, generation, edit) to the app (E3A-03, E3R2 R2-02) and starts nothing: the worker stays idle until record_done (E3R2, R2-01); else E3R2 (E3S-06): only assigns the result and its derived work (runs, finite lo/hi, strip, labels), all computed in the worker, to the row's state; then repaints and starts the next waiting job (E3S-03)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace)
examples: (EX-H5) generation 1 result when the current is 2 → dropped, MAP's values kept
examples: (EX-H6) "summary" for the old page after a page turn → dropped
examples: (EX-F5) a "record" result whose generation is older than the sheet's (an Undo ran) → status "Patch Editor: the change document or the image changed while VAL_BLK_DEF_0001 was encoding — stage it again.", no message posted
examples: (EX-J2) "preview" of LARGE with a 4,096-cell Set → runs, lo, hi assigned as posted; a `right` pressed while that result arrives, and one after it, are each handled within `0.5` s
examples: (EX-Q1) a fresh "record" result for VB while a "record" job for MAP waits → RecordStageRequested posted; MAP's job does not start until record_done("VAL_BLK_DEF_0001")

ArrayBenchSheet.record_staged
req: R-PE-BENCH.79
in: str name; tuple edit
out: None
func: new at E3R1 (E3A-03): called by the app's record-stage handler after the write. E3R2 (R2-02): clears states[name].edit and .undo only while states[name].edit equals `edit` (the edit the record job encoded); a newer edit made while the job waited or ran stays, with its undo and its "◆"; the cursor, tool and values stay; a no-op for a name with no state (R2-03); repaints. The op input keeps its text (Inc 8's note_staged with advance False keeps the pending text), and bench_mark shows "●" from the staged row
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
modify: [Data: ArrayBenchSheet.states] (replace)
examples: (EX-T1) VB edit {(0,0): "10"}, undo [{}], edit (((0, 0), "10"),) → edit {}, undo (), New "1 cells", mark "●", the input still "10"
examples: (EX-Q2) staged edit E1 {(0,0): "10"}, the row's edit now E2 {(1,1): "-18.8"} (+Δ 1 on (1,1), physical −19.75 + 1 = −18.75, made while the job waited; the apply replaced E1, which went to the undo stack, R-PE-BENCH.51) → E2 and its undo kept, mark "◆"

ArrayBenchSheet.record_done
req: R-PE-BENCH.28, R-PE-BENCH.70
in: str name
out: None
func: new at E3R2 (R2-01): called by the app's record-stage handler on every branch (after the write and record_staged, or after any refusal); resumes the bench worker, which starts its next waiting job with a snapshot and generation taken after the write; a no-op beyond the resume for a name with no state (R2-03)
module: s19_app/tui/screens_directionb/patch_editor/bench_sheet.py
examples: (EX-Q1) alt+s on VB, then alt+s on MAP during VB's held encode → VB written, record_done("VAL_BLK_DEF_0001"), MAP's job starts with generation `g + 1` → both staged, `2` entries, no changed status
examples: (EX-F6) the busy refusal → record_done is still called; the next waiting job starts

ChangeService.stage_record
req: R-PE-BENCH.70, R-PE-BENCH.72, R-PE-BENCH.73, R-PE-BENCH.80, R-PE-BENCH.81, R-PE-BENCH.92
in: str name; Encoded encoded; int count
out: ChangeActionResult result
func: I-9.2, re-pinned at E3R1 (E3A-03; replaces stage_values): on the UI thread only, no encode and no image: _stage_encoded(name, encoded, shown "<count> <value word>") (Inc 8 I-8.2: equal span → replace, no intersection → append, partial → the overlap refusal; _push_history first); encoded.notices → the result's notices "Patch Editor: <first> (+<m> more)"
module: s19_app/tui/services/change_service.py
examples: (EX-T1) "VAL_BLK_DEF_0001", Encoded(0x800090, 00 c8 00 db 02 7c fe 63 fe 75 ff 2a), count `1` → ok `True`, one bytes entry 0x800090, message "Patch Editor: VAL_BLK_DEF_0001 staged as 1 value (12 B at 0x800090)."
examples: (EX-M2) "MAP_DEF_0001", the 32 B record, count `4` → "Patch Editor: MAP_DEF_0001 staged as 4 values (32 B at 0x800070)."
examples: (EX-O1) then Encoded(0x800090, 00 c8 00 db 02 7c fe 63 ff 9c ff 2a), count `1` → `1` entry, replaced
examples: (EX-F1) a raw 2-byte entry at 0x800092 → ok `False`, "Patch Editor: VAL_BLK_DEF_0001 overlaps the entry at 0x800092 — remove that entry first."
examples: (EX-R12) an Encoded with two notices → notices ["Patch Editor: <first notice> (+1 more)"]

PatchMixin.on_array_bench_sheet_record_stage_requested
req: R-PE-BENCH.6, R-PE-BENCH.74, R-PE-BENCH.76, R-PE-BENCH.77, R-PE-BENCH.78, R-PE-BENCH.79, R-PE-BENCH.80, R-PE-BENCH.83
in: ArrayBenchSheet.RecordStageRequested event
out: None
func: E3R1 (E3A-03, E3S-03, E3S-04): the UI thread, after the bench's record job, before any write: _refuse_if_busy() first (the I-8.2 stage seam), so a session action running when the encode ends refuses with the busy line; no A2L → "Patch Editor: no A2L is loaded — nothing staged."; event.generation ≠ sheet.generation → R-PE-BENCH.78's status; describe_definition(name, app.current_a2l_data) is not equal to event.definition (`Definition ==`, the conversion included, E3A-02) → the changed status; event.outcome a Refusal → "Patch Editor: <message>"; else ChangeService.stage_record(name, outcome, count), _report_change_result (notices as their own line); ok → note_staged(name, advance=False) (Inc 8 C-8), sheet.record_staged(name, event.edit) (E3R2, R2-02), _refresh_patch_history_view. Every refusal leaves the document and the bench edit unchanged. E3R2 (R2-01): every branch, the write and each refusal, ends with sheet.record_done(name), which resumes the bench worker. E1's _record_stage_done is folded into this handler
module: s19_app/tui/app/patch.py
examples: (EX-F6) a session action running when the record job ends → the busy line, entries unchanged
examples: (EX-F9) a session action started during a held encode, then released → the busy line, entries unchanged
examples: (EX-F2) no A2L → status "Patch Editor: no A2L is loaded — nothing staged."
examples: (EX-F3) VB moved to 0x8000A0 → "Patch Editor: VAL_BLK_DEF_0001 changed in the A2L — select it again to reload its values."
examples: (EX-F7) page A2L factor 0.05, loaded A2L factor 0.025 (CM_DEF_FINE), same span → the same changed status, entries unchanged
examples: (EX-T7) outcome Refusal → "Patch Editor: VAL_BLK_DEF_0001[0,0]: 60 is outside the limits -50..50", entries unchanged
examples: (EX-T1) ok → status "Patch Editor: VAL_BLK_DEF_0001 staged as 1 value (12 B at 0x800090).", VB still selected, undo depth +`1`, dirty `True`, the bench edit cleared

PatchEditorPanel.__init__
req: R-PE-BENCH.3
in: (none)
out: PatchEditorPanel panel
func: C-1, a named exception to the seam rule (E3R1, E3A-08): self._sheet = ArrayBenchSheet(id="patch_sheet") in place of Inc 8's StagingSheet line; applied by Inc 9's integrator after Inc 8 merges
module: s19_app/tui/screens_directionb/patch_editor/panel.py
modify: [Data: PatchEditorPanel._sheet] (replace)
examples: (EX-L1) a new panel → `_sheet` is an ArrayBenchSheet with id "patch_sheet"

LayoutMixin.compose
req: R-PE-BENCH.1
in: (none)
out: ComposeResult tree
func: C-4, a named exception to the seam rule (E3R1, E3A-08): Inc 8 paints the #patch_sheet_win border subtitle "enter edit · ↑↓ row" (Inc 8 E3R2 E3A-15); Inc 9's integrator appends " · arrays open the bench" after Inc 8 merges; nothing else of Inc 8's compose changes
module: s19_app/tui/screens_directionb/patch_editor/layout.py
examples: (EX-L1) → border_subtitle "enter edit · ↑↓ row · arrays open the bench"

## Entities

[Data: ArrayBenchSheet.states]
in: dict[str, BenchState]
desc: the per-row bench state (Inc 8 I-8.4 `states`, K-1): cursor, anchor, tool, edit, undo, origin, focus, values, staged, axes, preview, job, runs, lo, hi, strip (E3R1: room dropped, E3A-01; runs, lo, hi, strip stored at _job_done, E3S-06); preview `"encoding"` while the row's preview job runs (E4 C9b, P-061); kept for the bench state lifetime (E3A-11)
sequence:
  select: ArrayBenchSheet.on_staging_sheet_selection_changed → ArrayBenchSheet._run_job → ArrayBenchSheet._job_done wins
  apply: ArrayBenchSheet.on_array_bench_sheet_bench_apply_requested wins → ArrayBenchSheet._run_job → ArrayBenchSheet._job_done
  stage: ArrayBenchSheet.action_stage_record → ArrayBenchSheet._run_job → ArrayBenchSheet._job_done → PatchMixin.on_array_bench_sheet_record_stage_requested → ArrayBenchSheet.record_staged wins → ArrayBenchSheet.record_done

[Data: ArrayBenchSheet.generation]
in: int
desc: E3R1 (E3S-04): +1 at every set_document (each document change and image push); beside it two private view keys (page key: +1 at every show_page; selection key: +1 at every show_page and bench selection). A record job's result is dropped when the generation changed; a page job's when the generation or the page key changed; a selected-row job's when the generation or the selection key changed (I-9.1)

[Data: definition_sheet._KIND_OPS]
in: dict[str, KindOps]
desc: Inc 8's per-kind operations table (I-8.5, pinned at Inc 8 E3R1); Inc 9 sets three keys at import

[Data: ChangeService.document.entries]
in: list[ChangeEntry]
desc: the change document; a record stage writes one bytes entry for the whole record
sequence:
  recordStage: PatchMixin.on_array_bench_sheet_record_stage_requested → ChangeService.stage_record wins → ArrayBenchSheet.set_document

[Data: PatchEditorPanel._sheet]
in: ArrayBenchSheet
desc: the one sheet widget (C-1)

[Data: PatchEditorPanel._dirty]
in: bool
desc: the dirty flag; set by Inc 8's note_staged (w6), which the record-stage handler calls with advance False

[Data: App.focused]
in: Widget
desc: the sheet body (rows or bench focus) or the op input

## Edges

[Outside: key enter] ──▶ ArrayBenchSheet.action_edit
when: App.focused is the sheet body
[Outside: key shift+arrow] ──▶ ArrayBenchSheet.action_cursor
when: ArrayBenchSheet.check_action("cursor") is True (the bench has the focus)
[Outside: key pageup] ──▶ ArrayBenchSheet.action_page
when: ArrayBenchSheet.check_action("page") is True (the bench has the focus)
[Outside: key s d p i m u] ──▶ ArrayBenchSheet.action_tool
when: ArrayBenchSheet.check_action("tool") is True (the bench has the focus); else the key reaches the app
[Outside: key escape] ──▶ ArrayBenchSheet.action_leave_bench
when: ArrayBenchSheet.check_action("leave_bench") is True (the bench has the focus)
[Outside: key alt+s] ──▶ ArrayBenchSheet.action_stage_record
when: ArrayBenchSheet.check_action("stage_record") is True (the bench or a bench row's op input has the focus)
bench_submit ──▶ ArrayBenchSheet.on_array_bench_sheet_bench_apply_requested
ArrayBenchSheet.action_stage_record ──▶ ArrayBenchSheet._run_job
ArrayBenchSheet._run_job ──▶ ArrayBenchSheet._job_done
ArrayBenchSheet._job_done ──▶ PatchMixin.on_array_bench_sheet_record_stage_requested
PatchMixin.on_array_bench_sheet_record_stage_requested ──▶ ChangeService.stage_record
PatchMixin.on_array_bench_sheet_record_stage_requested ──▶ ArrayBenchSheet.record_staged
PatchMixin.on_array_bench_sheet_record_stage_requested ──▶ ArrayBenchSheet.record_done
ArrayBenchSheet.record_done ──▶ ArrayBenchSheet._run_job
PatchMixin.on_array_bench_sheet_record_stage_requested ──▶ [Data: PatchEditorPanel._dirty]
ChangeService.stage_record ──▶ [Data: ChangeService.document.entries]
register_bench_kinds ──▶ [Data: definition_sheet._KIND_OPS]

## Findings

finding F-1 The pinned tables cannot carry a bench
anchor: register_bench_kinds
seen: I-8.5's `_DETAIL_BY_KIND` callables take (SheetRow, Preview, int); Inc 8's submit, preview and row cells are scalar-only
cause: the seam was pinned before Inc 9's design (Inc 8 E3A-02 found the same)
effect: Inc 9 could not add its kinds by keys alone
decision: `_KIND_OPS` entries + a thin subclass for keys, focus and workers (D-1 A); K-1 … K-3 pinned in Inc 8's E3R1 I-8.5; the bench's entry re-pinned against the final KindOps at Inc 9 E3R1 (E3A-01), with the additive `mark` field (E3A-05)

finding F-2 `_stage_encoded` could not write its message
anchor: ChangeService.stage_record
seen: I-8.2 `(name, encoded)` gets no definition, so R-PE-DEF.58's `<text>` cannot be decoded inside it
cause: the message moved into the shared writer
effect: Inc 9's array stage (and Inc 8's own) had no way to say what was staged
decision: Inc 8's E3R1 (E3A-03, which ruled the same): `_stage_encoded(name, encoded, shown)` with the template `staged as <shown>`; the template point C-7 is closed: R-PE-BENCH.72 reworded at Inc 9 E3R1 (E3A-06)

finding F-5 Two fixes disagree on who owns the record-stage worker
anchor: ArrayBenchSheet._run_job
seen: E3A-03's fix keeps the record encode in an app-side worker of PatchMixin; E3S-03's fix bounds the bench to one worker with a single waiting slot
cause: two owners of encode threads cannot keep "at most one bench job at a time" (R-PE-BENCH.28)
effect: either a second concurrent ≈ 200 MiB encode, or a record stage replaced silently by a later selection decode
decision: E3R1: the record encode is a bench job of the sheet's one worker, in its own ordered queue (never replaced by a decode); the write stays on the UI thread in the app's handler, which checks busy, generation and the re-described definition first; E1's `_record_stage_done` folds into that handler (recorded in `../E3-rulings.md` §E3R1 and `../E1-rulings.md` §8 S-9)

finding F-3 Tools on the display grid can fall off the stored grid
anchor: result_text
seen: VB Set `10.03` → `A2L-DEF-ENCODE … 200.59999999999997 is not integral` (pilot); a LINEAR factor that is not a power of ten makes some display-grid values unstorable
cause: I-2 has no "nearest stored value" encode
effect: some tool results are refused per cell; the bytes line and the op line show it
decision: accepted for Inc 9 (D-7 note); backlog: an I-2 nearest-stored option

finding F-4 Rounded no-ops would change bytes
anchor: apply_tool
seen: VB (0,0) shows `36.9` but holds 36.85; +Δ 0 rounded to `36.9` encodes stored 738 ≠ 737
cause: the result text rounds to the display precision
effect: a tool that changes nothing would still write a byte
decision: a cell whose result equals its current value leaves the edit (R-PE-BENCH.58)
