# Inc 8 — Code-Wire graph: Patch Editor edit by definition (E2 prototype)

Batch `2026-11-05-batch-103`, increment 8, stage E2, 2026-11-13, model Opus (E1 + E2 by one agent, DF-03). Base `91d5ae56`. Code-Wire `v3.1.0-8-gb6cd30d` (`git -C C:\Users\<user>\Github\code-wire describe --tags`), core only: one node per function the change adds or touches, examples taken from the requirements, real callers from `tools/codewire_extract.py` (E1 census, `../evidence-e1/cw-census-*`), every example writable as a test that fails on base and passes after. No lint, coherence or STE gate. **The prototype is this graph only**: no stub, mark or declaration in the source.

**E3R1 (2026-11-13, model Opus):** the E3 rulings (`../E3-rulings.md`) and the Inc 9 items the orchestrator accepted (Inc 9 `E1-rulings.md` §4 at `cf755dcf`: C-2, K-1, K-2, K-3, C-4, C-5, C-6, C-8, C-9, E-2) are applied here. I-8.2, I-8.4 and I-8.5 are re-pinned; I-8.3 carries the E3A-05 ruling. A node changed by E3R1 says `E3R1 (<finding>)` in its `func`. E3R1 callers: `../evidence-e1/cw-e3r1-*` (Code-Wire extractor on the changed existing functions); E3R1 examples: `../evidence-e1/examples_e3r1-transcript.txt`.

**E3R2 (2026-11-13, model Opus):** the re-review rulings (`../E3-rulings.md` §E3R2 corrections): I-8.4 re-pinned as `show_page(names, definitions, a2l_data, image)` (E3A-13), the detail cut in the row window (E3A-14), Inc 8's subtitle without the bench clause (E3A-15), the per-row work bounded by the document (E3S-10). Examples: `../evidence-e1/examples_e3r2-transcript.txt`. Node count unchanged (46).

Inputs: `../01-requirements.md` (89 active rows after E3R2), `../02-test-cases.md` (210 cases after E3R2), `../E1-rulings.md` (D-1 … D-9 PROPOSED; this graph follows each recommended option and marks what another ruling would change with `[D-n]`), `../E1-slice.md`. Computed examples: `../evidence-e1/pilot_inc8-transcript.txt` (I-2 on `<runner>`) and `../evidence-e2/examples_inc8-transcript.txt` (widths, short numbers, Δ, ruler cells, mask words; pure arithmetic of CTX-PE-DEF).

### Groups for E4 (file ownership, D-5 A)

| Group | Files | Nodes |
|---|---|---|
| S1 — sheet model | new `s19_app/tui/definition_sheet.py` | 19 |
| S2 — sheet widget | new `s19_app/tui/screens_directionb/patch_editor/sheet.py`; `s19_app/tui/a2l_parameter_picker.py` (one attribute, E3A-04) | 11 |
| P — panel | `screens_directionb/patch_editor/layout.py`, `panel.py`, `a2l_picker.py`; `s19_app/tui/styles.tcss` | 12 |
| A — staging | `s19_app/tui/services/change_service.py`; `s19_app/tui/app/patch.py`; `s19_app/tui/window_help.py` (E3A-06) | 4 |

Each requirement has one owner group (coverage table). Shared edits: `styles.tcss` (group P only); `_KIND_OPS` (I-8.5, group S1; Inc 9 adds keys after Inc 8 merges). `a2l_parameter_picker.py` is Inc 7's file: group S2 adds one attribute in `set_parameters` and rebases on Inc 7 if Inc 7 merges first (DF-10, one writer per file at a time).

### Interfaces

**Consumed, pinned elsewhere, unchanged.**
- **I-2** (`../../inc-2/codewire/graph-inc2.md` §Interfaces): `describe_definition(name, a2l_data) -> Definition`, `describe_definitions(names, a2l_data) -> dict[str, Definition]`, `decode_definition(definition, a2l_data, image) -> Decoded | Refusal`, `encode_definition(definition, a2l_data, text, image) -> Encoded | Refusal`; `Definition` fields read by name: `name, section, char_type, kind, address, byte_length, datatype, byte_order, bit_mask, bit_mask_text, conversion_type, method_name, decimals, unit, limits, extended_limits, enum_table, enum_entries, default_text, coeffs_linear, refusal`. Consumer obligations met here: the staging overlay (E3A-07/E3S-08) → `StagedOverlay.__getitem__`, `preview`, `ChangeService.stage_definition`, `_stage_encoded`; markup off (E3S-04a) → `row_line`, `StagingSheet._paint`; control characters in raw file words (E3A-25/E3S-19) → `plain`; re-describe after an A2L change → `A2LParameterPicker.set_parameters` (one describe per population, kept as `definitions`, E3A-04) and `PatchMixin.on_staging_sheet_stage_requested`; never `a2l.encode_physical_to_raw_bytes` for a masked object → `stage_definition` calls only `encode_definition`.
- **I-1**: `OsClipboardInput` (`os_clipboard_input.py:849`) as the formula input, with `max_length=4096`.
- **I-4** (Inc 5): every A2L load or reload changes `_a2l_enriched_key`, so `A2LParameterPicker.set_parameters` repopulates and posts `ViewChanged` (`a2l_parameter_picker.py:568-642`) → N29.

**Produced — PROPOSED, pinned here, changed only by an orchestrator ruling.**

```text
I-8.1  definition_sheet.StagedOverlay(image: Mapping[int, int] | None,
                                      entries: Sequence[tuple[int, Sequence[int]]])   Mapping[int, int]
         __getitem__(address): the last entry byte written at address (document order), else image[address];
         KeyError when neither holds it. __iter__/__len__: the union of the image's and the entries' addresses.
         image None → only the entries' bytes. Read only; never copies the image (entries ≤ the document).
I-8.2  ChangeService._stage_encoded(name: str, encoded: Encoded, shown: str) -> ChangeActionResult
         (re-pinned at E3R1: E3A-03, E3S-02)
         shown = the caller's display text for the message: stage_definition passes the staged value's
         decoded text; Inc 9's stage_values passes its own summary (`<k> <value word>`, Inc 9 C-7).
         equal span → _push_history, then REPLACE the entry with
             ChangeEntry("bytes", encoded.address, tuple(encoded.data), symbol=<the old entry's symbol>)
             (entry_type "bytes", value None: a "string" entry's declaration never survives a stage);
         no intersection → _push_history, append ChangeEntry("bytes", encoded.address, tuple(encoded.data),
             symbol=name);
         partial → ok False, the overlap status, no history.
         message: "Patch Editor: <name echo> staged as <shown echo> (<n> B at 0x<X>)."
         It writes, refuses or reports only: no decode, no encode, no image.
       ChangeActionResult gains `notices: tuple[str, ...] = ()` (E3A-10; additive, every existing
         constructor unchanged): stage_definition puts each encode notice there as "Patch Editor: <notice>".
       Stage seam (Inc 9 E-2): every stage handler, A3 and Inc 9's record-stage handler, calls
         ShellMixin._refuse_if_busy() first (existing, unchanged; app/shell.py:425) and passes the source
         view PatchMixin._strip_source_map(loaded) as the image (E3S-01).
I-8.3  Inc 10 shared points (D-8 A; ruling E3A-05, recorded in both increments' records by the orchestrator):
         (a) LayoutMixin.compose calls self._compose_doc_controls() once, after the file row and before the
             legend; Inc 10 yields its dock inside ActionsMixin._compose_doc_controls, after
             #patch_doc_controls. Inc 10's re-map (PENDING P-020) consumes this point, not #patch_main.
         (b) the region that yields rows is #patch_main before Inc 8 and #patch_sheet_win after it, with
             `min-height: 12` on #patch_sheet_win (R-PE-DEF.74).
         (c) R-PE-DEF.1.1 counts "the other shown regions", the dock included.
         (d) Inc 10's tab list follows R-TUI-063.3 as merged (Patch script, Inspector, JSON, Checks).
         (e) Either merge order; whichever merges second rebases and owns the shared test files' retarget.
I-8.4  StagingSheet (patch_editor/sheet.py), a Vertical with id "patch_sheet" (re-pinned at E3R1: E3A-01,
         E3A-04, E3A-07, Inc 9 C-2; re-pinned at E3R2: E3A-13, E3A-14):
         show_page(names: Sequence[str], definitions: Mapping[str, Definition],
                   a2l_data: dict | None, image: Mapping[int, int] | None) -> None
                   # 0 describes (R-PE-DEF.11); a2l_data = the page A2L the definitions came from; the sheet
                   # stores it; None → the no-A2L line (R-PE-DEF.14)
         set_document(entries: Sequence[tuple[int, Sequence[int]]], image: Mapping[int, int] | None) -> None
                   # rebuilds with the stored a2l_data
         every build_row, KindOps.decode and KindOps.preview the sheet calls gets the stored a2l_data;
         the sheet never reads app.current_a2l_data
         selected_name -> str | None (property)
         select_after(name: str) -> None   # clears pending[name]; selects the row after `name`, or keeps
                                           # `name` on the last row; refills the input; focus unchanged
         states: dict[str, object]         # per-row editor state by name, owned by the sheet; Inc 8 kinds
                                           # store none; KindOps.detail/cells/bar read states.get(name)
         _paint() -> None                  # the one repaint entry: body (row window), formula bar
         overridable by a subclass, each calling super() off its own rows (Inc 9 D-1 A):
             action_edit, action_move, action_choose, _on_formula_escape, show_page, set_document;
             the sheet may also handle its own SelectionChanged.
         child ids: #patch_sheet_body (the focusable body), #patch_sheet_input (the formula input).
         row window: rows top … top + visible − need are painted (CTX-PE-DEF row window); a kind's detail
             lines count in `need`, KindOps.detail receives room = visible − 1, and a longer detail is cut
             to room lines, so the selected row is always painted (E3R2, E3A-14).
         messages (bubble to the app): StagingSheet.StageRequested(name: str, text: str)
                                       StagingSheet.SelectionChanged(name: str)
         handler names: on_staging_sheet_stage_requested, on_staging_sheet_selection_changed
       Source of `definitions`: A2LParameterPicker.definitions -> Mapping[str, Definition] (read only;
         replaced at each real population by set_parameters' own describe; {} without A2L data; unchanged on
         an equal signature). Added by Inc 8 (E3A-04) in Inc 7's file. Beside it (E3R2, E3A-13):
         A2LParameterPicker.definitions_source -> dict | None, the a2l_data that same describe used (read only,
         replaced with `definitions`, None without A2L data); the view-changed handler passes both.
       PatchEditorPanel.note_staged(name: str, advance: bool = True) -> None   # Inc 9 C-8: advance → the
         sheet's select_after(name); advance False → the selection and the pending text stay.
I-8.5  definition_sheet per-kind operations (re-pinned at E3R1: E3A-02, Inc 9 K-1, K-2, K-3; the only Inc 8
         symbol Inc 9 edits, by adding keys):
         class KindOps(NamedTuple):
             label: str                                                    # the formula label
             editable: Callable[[Definition], bool]                        # has an editor
             decode: Callable[[Definition, dict, Mapping[int, int] | None], Decoded | Refusal | None]
             value_text: Callable[[SheetRow, Decoded | Refusal | None], str]
             staged: Callable[[SheetRow, Mapping[int, int] | None, StagedOverlay], bool]
             preview: Callable[[Definition, dict, str, StagedOverlay], Preview]
             detail: Callable[[SheetRow, Preview | None, int, object | None, int], list[Text]]
                                                        # (row, preview, width, state, room)
             submit: Callable[[str, str], Message]                         # (name, formula text)
             cells: Callable[[SheetRow, object | None, SheetWidths], tuple[Text, Text, Text, Text, Text]]
                    | None = None    # (Kind, Current, New, Limits, Δ); None → Inc 8's cell rules
             bar: Callable[[SheetRow, object | None, int], tuple[str, Text]] | None = None
                    # (the bar's name text, its tail); None → Inc 8's name and formula_tail
             mark: Callable[[SheetRow, object | None], str | None] | None = None
                    # E4 amendment (Inc 9 E3A-05, orchestrator ruling, relevo-8): (row, state) → the
                    # mark column's second glyph; a None field or a None answer → Inc 8's rule
                    # (R-PE-DEF.23/.24); one call site, row_line. Inc 8's kinds and _FALLBACK_OPS set None.
         _KIND_OPS: dict[str, KindOps] = {"number": …, "bit mask": …, "enum": …, "text": …}
         ops_for(kind: str) -> KindOps = _KIND_OPS.get(kind, _FALLBACK_OPS)
         build_row, preview, submit and set_document dispatch through ops_for; none branches on the kind.
```

**I-8.5 per-kind operations table (pinned at E3R1).** Inc 9 adds the rows `array`, `curve` and `map` (its D-1 A); nothing else in this table changes. *E4 amendment (Inc 9 E3A-05):* the optional `mark` column is None for every Inc 8 row and the fallback; Inc 9 sets it for its three kinds (`bench_mark`). Test: `tests/test_b103_inc8_s1.py::test_r_pe_def_23_i85_mark_field_none_keeps_inc8_rule_and_a_kind_mark_overrides`.

| Kind | label | editable | decode | value_text | staged | preview | detail (row, preview, width, state, room) | submit | cells | bar |
|---|---|---|---|---|---|---|---|---|---|---|
| number | `new =` | always | I-2 `decode_definition` | `value_text` (`143.5`) | value texts differ | `preview` (I-2 encode + decode over the overlay) | definition line | `StageRequested(name, text)` | None | None |
| bit mask | `field =` | always | same | `174 (0xAE)` | value texts differ | same | definition line + bit strip (2 lines) | same | None | None |
| enum | `new =` | always | same | `1 IDLE` | value texts differ | same | definition line + enum options (2 lines) | same | None | None |
| text | `text =` | span ≤ 4,096 B | same while span ≤ 4,096 B; None over it (E3R2, E3S-10: no decode) | `"Hello ASAM"`; `<n> B` over 4,096 B | value texts differ; over 4,096 B the entry-byte rule of the fallback | same | definition line + ≤ 4 text rows (64 raw bytes read from the image) + `… <n> more B` | same | None | None |
| fallback (`_FALLBACK_OPS`, any other kind, `none`) | `""` | never | none (no I-2 call) | `<n> values` (element count), `refused`, or `--` | E3R2 (E3S-10): one pass over the bytes of the document's entries that fall inside the span, each against the image's byte; never a walk of the span, never twice | never called (no editor) | definition line (or `└ <refusal>`) | never called | None | None |
| array, curve, map (Inc 9 adds) | `op =` | Inc 9 | Inc 9 (off the UI thread) | Inc 8 fallback | Inc 8 fallback | Inc 9 | the bench lines | `BenchApplyRequested` | Inc 9 | Inc 9 |

### Examples (data; `EX-*` ids are cited by the cases)

Pilot facts (`pilot_inc8-transcript.txt`): DEFC = `make_release_case.py --case definitions`, seed 20260001.

| Id | Input | Output |
|---|---|---|
| EX-D1 | DEFC `ENUM_0001`: VALUE, UBYTE, big, 0x800000, 1 B, TAB_VERB `VT_DEF_STATE` OFF/IDLE/RUN/FAULT (0…3), default `UNKNOWN_STATE`; image `01` | `Decoded(1, 'IDLE', 'IDLE')`; value text `1 IDLE`; definition line `└ TAB_VERB 4 pairs · UBYTE u8 big-endian · 0x00800000 · 1 B` |
| EX-D2 | DEFC `DISPLAY_0001`: VALUE, SWORD, big, 0x800020, 2 B, LINEAR (0.5, 0.0), `%.1`, `deg C`, limits -40..150, extended -50..200; image `01 1F` | `Decoded(287, 143.5, '143.5')`; `└ LINEAR phys = 0.5*raw · SWORD s16 big-endian · 0x00800020 · 2 B`; limits cell at W = 118: track 22, `●` on cell 19 |
| EX-D3 | DEFC `MASK_FIELD_0001`: UWORD, big, 0x800010, mask 0x0FF0 (`bit_mask = 4080`), IDENTICAL, limits 0..255; image word `1A E7` | `Decoded(174, 174, '174')`; value text `174 (0xAE)`; `└ IDENTICAL phys = (word & 0x0FF0) >> 4 · UWORD u16 big-endian · 0x00800010 · 2 B`; bits high first `0001101011100111` |
| EX-D3b | DEFC `MASK_BIT_0001`: same word, mask 0x0001, limits 0..1 | `Decoded(1, 1, '1')`; value text `1 (0x01)` |
| EX-V1 | V171 `ASAM.C.ASCII.UBYTE.NUMBER_42`: ASCII, 42 B at 0x810200; image `Hello ASAM` + 32 × `00` | `Decoded(None, 'Hello ASAM', 'Hello ASAM')`; value text `"Hello ASAM"`; `└ text · 0x00810200 · 42 B`; text rows `+00`, `+10`, `+20` |
| EX-P1 | DISPLAY_0001 text `25.5` (also typed `25.50`) over the image | `Encoded(0x800020, 00 33, ())`; preview text `25.5`; Δ `-118.0 (-62.1%)`; ruler `◆` on cell 8; tail `deg C  (-40 … 150)  raw 287→51 · 01 1F → 00 33  ✓ in limits  enter stage ↓` |
| EX-P2 | ENUM_0001 text `RUN` (right key from IDLE) | `Encoded(0x800000, 02, ())`; value text `2 RUN`; Δ `1 → 2`; options `(●) 2 RUN` |
| EX-P3 | DISPLAY_0001 `abc` | `Refusal('A2L-DEF-NUMBER', "DISPLAY_0001: 'abc' is not a number")`; New `abc`; Δ `✗ refused`; status `Patch Editor: DISPLAY_0001: 'abc' is not a number` |
| EX-P4 | DISPLAY_0001 `x` × 300 | `A2L-DEF-NUMBER`, message 289 characters (`'` + 256 × `x` + `…'`, I-2's .151/7 cap); tail cut at the bar edge with `…` |
| EX-P5 | MASK_FIELD_0001 `255` | `Encoded(0x800010, 1F F7, ())`; Δ `+81`; strip `word 1A E7 → 1F F7` |
| EX-P6 | V171 ASCII `ABC` | `Encoded(0x810200, 41 42 43 + 39 × 00, ())`; Δ `10 chars`; tail `3/42 chars · NUL-padded  enter stage ↓` |
| EX-P7 | DISPLAY_0001 `250` | `Refusal('A2L-DEF-EXTENDED', 'DISPLAY_0001: 250 is outside the extended limits -50..200')` |
| EX-P8 | ENUM_0001 `WALK` (and `2`) | `Refusal('A2L-DEF-ENUM', "ENUM_0001: 'WALK' is not a text of VT_DEF_STATE")` (`'2'` likewise) |
| EX-D4 | DISPLAY_0001 `175` | `Encoded(0x800020, 01 5E, ('DISPLAY_0001: 175 is outside the limits -40..150 and inside the extended limits -50..200',))`; ruler `▶` on the right end |
| EX-O1 | stage MASK_FIELD_0001 `255`, then MASK_BIT_0001 `0` over the overlay | e1 `1F F7`, e2 `1F F6`; one entry at 0x800010, symbol `MASK_FIELD_0001`; decode over it: `255`, `0`. Negative control (e2 over the image, two entries): MASK_FIELD reads `174` |
| EX-O2 | the reverse order | e1 `1A E6`, e2 `1F F6`; decode `255`, `0`; negative control: MASK_BIT reads `1` |
| EX-W1 | W = 96 / 118 / 200 | `{2,16,0,14,12,0,limits 41,10}` / `{2,18,9,18,13,7,limits 34,16}` / `{2,24,10,44,20,8,limits 64,22}` |
| EX-C1 | software_a (13,990 tags), first 200 addressed names | `describe_definitions` median 0.1301 s, max 0.2086 s; kinds number 170, enum 17, curve 7, array 4, text 2. E3R1 (E3A-04): the "200 decodes 0.0002 s" figure decoded over an empty image (every decode a first-byte refusal) and is withdrawn; over a full image 0.0008 s, one `describe_definition` 0.1167 s (E3 probe `P1.*`, load 9.5: ratios only) |
| EX-F1 | software_a page of EX-C1, the non-scalar rows (E3R1) | `(array, VAL_BLK, element_count 4, 8 B) × 4`, `(curve, CURVE, 5, 20 B) × 1`, `(curve, CURVE, 8, 32 B) × 6` (`F.page200.*`): under Inc 8 alone they show `4 values`, `5 values`, `8 values` |
| EX-R9 | a DEFC DISPLAY_0001 definition copied with kind `cuboid` (no operations) and element count 24; the same with element count None; a raw entry `AA BB` over its span 0x800020 (E3R1) | Current `24 values`; `--`; with the entry: staged (span bytes `AA BB` ≠ `01 1F`) → `●`; formula tail `edit VALUE objects in the Inspector tab`, input disabled |
| EX-R10 | DISPLAY_0001 copies with limits `5 5` and `9 1`, pending `25.5` (E3R1) | limits cell `5 … 5`, `9 … 1`; Δ `-118.0` both; the plain division raises `ZeroDivisionError` (`L.*`) |
| EX-R11 | a DISPLAY_0001 copy with `record_layout = "RL_U16"` (E3R1, Inc 9 C-6) | `└ LINEAR phys = 0.5*raw · SWORD s16 big-endian · RL_U16 · 0x00800020 · 2 B` |
| EX-W3 | W = 118: name `温度`×6 (24 cells) in Parameter 18, unit `温度温度` (8 cells) in Unit 7 (E3R1) | `温度温度温度温度…` (17 cells), `温度温…` (7 cells); the `len()` clip leaves 24 and 8 cells (`C.*`) |
| EX-T1 | V171 ASCII copies widened to 65, 4,096, 4,097 and 1,048,576 bytes (E3R1) | text rows 4 each; cut `… 1 more B`, `… 4032 more B`, `… 4033 more B`, `… 1048512 more B`; detail lines 6; editor at ≤ 4,096 only; all rows of 1 MiB would be 65,536 (`T.*`) |
| EX-T2 | an enum entry text of 5,000 characters (E3R1) | the input holds its first 4,096 characters (`T.fill_cap.enum_text_5000`); a direct `value =` holds 5,000 (E3 probe `P4.programmatic_5000`) |
| EX-K4 | row window, visible 20 body lines (E3R1) | `row_window(40, 0, 20, 1) = 22`; `(39, 22, 20, 1) = 22`; `(21, 22, 20, 1) = 21`; `(5, 0, 20, 3) = 0`; `(18, 0, 20, 3) = 2`; `(3, 0, 3, 3) = 3`; 40 × down from row 0 → top 22, the selected row on body line 18, its detail on 19; negative control (top 0) → body line 40 (`W.*`) |
| EX-O3 | MASK_FIELD_0001 `255` staged, Apply, Remove, MASK_BIT_0001 `0` staged (E3R1, E3S-01) | over the source view: entry `1A E6`, MASK_FIELD `174`; over the live map: `1F F6` (E3 probe `P2.after_apply_and_remove.*`) |
| EX-S8 | a `string` entry of 42 × `Q` at 0x810200; V171 ASCII `XYZ` → `Encoded(0x810200, 58 59 5A 00 …, len=42)` (E3R1, E3S-02) | replaced by a bytes entry: wire `"type": "bytes"`, reload decodes `XYZ`; bytes kept inside the string entry: wire `"type": "string"`, reload decodes the 42 × `Q` (`X.*`) |
| EX-R12 | DISPLAY_0001 raw `287`: the picker's page A2L (LINEAR 0.5) and an app payload whose COMPU_METHOD gives factor 1.0 (E3R2, E3A-13) | `143.5` with the page A2L; `287.0` with the app payload (I-2's decoded text, decimals 1; E5, P-045) (`R12.*`): the sheet shows `143.5` until the picker repopulates |
| EX-T3 | a page of 200 copies of the V171 ASCII object widened to 1,048,576 B at one address, image `41` × 1 MiB, one 42-byte entry inside the span (E3R2, E3S-10) | per row: Current `1048576 B`, staged `True`, 42 image lookups; 200 rows median 0.00086 s; one full decode 0.156 s, so the negative control ≈ 62 s (`S.*`, load 7.7–8.0, indicative) |
| EX-K6 | row window with a detail taller than the window (E3R2, E3A-14) | `(3, 0, 3, 3)` → top 3, detail cut to 2; `(10, 0, 8, 10)` → top 10, detail cut to 7; the selected row on body line 0 (`W2.*`) |
| EX-M1 | MASK_FIELD_0001 `255` over word `1A E7` → entry `1F F7`; new image word `1A E6` (E3R1, E3S-08) | MASK_BIT current `0`, staged `1` → `●`, New `1 (0x01)`; MASK_FIELD staged `255` (`M.*`) |

Scenario examples (built by the tests; no computed value): **EX-L1** the regions at 118×54 and 220×60; **EX-L2** the chips and the title; **EX-L3** ledger subtitle with 0/1/3 entries and the dirty flag; **EX-L4** the filter row and the Use row; **EX-L5** containment at 80×24 / 118×54; **EX-L6** focus colours; **EX-W2** line widths at 80/118/220; **EX-R1** population, filter `MASK`, page turn of 201 names; **EX-R2** an A2L reload that changes ENUM_0001's texts, and an equal signature; **EX-R3** an empty page, no A2L; **EX-R4** clipping the V171 ASCII name; **EX-R5** a MEASUREMENT; **EX-R6** no image, a missing byte; **EX-R7** a name declared twice, a BIT_MASK keyword with no mask; **EX-R8** an object with no limits; **EX-K1** up/down/Enter and the picker cursor; **EX-K2** the detail moving; **EX-K3** pending text kept per row; **EX-S1** DISPLAY_0001 `25.5` staged (entry `00 33` at 0x800020, symbol `DISPLAY_0001`, status, next row, undo, dirty); **EX-S2** ENUM_0001 `RUN` staged; **EX-S3** MASK_FIELD_0001 `255` staged; **EX-S4** V171 ASCII `ABC` staged; **EX-S5** DISPLAY_0001 `25.5` then `30` (one entry `00 3C`); **EX-S6** staging the last row; **EX-S7** Parse pasted with a DISPLAY_0001 entry; **EX-F1** a raw entry at 0x800021 or 0x80001F…0x800020 then a DISPLAY_0001 stage; **EX-F2** A2L unloaded before Enter; **EX-F3** reload moving DISPLAY_0001 to 0x800030; **EX-H1** markup words `A[/x]B`, `[@click=app.quit]OFF[/]`, `Map[b]x`, `A[b]`; **EX-H2** ESC, NUL, U+0085 in a text, name, unit; **EX-H3** (E3R1, E3S-06) a 65,536-character paste into an empty input → empty; 200 pasted onto 4,000 → 4,000; 5,000 typed → 4,096 (E3 probe `P4.*`); **EX-H4** a 300-character name. E3R1 scenarios: **EX-L7** a 4-row stand-in for Inc 10's dock yielded inside `_compose_doc_controls` (118×54); **EX-L8** the panel with the `-bench` class (Inc 9's bench state); **EX-L9** the sheet window at 80×24 and with the stand-in dock; **EX-K5** V171 ASCII selected and left unchanged, then edited to `ABC`, left and re-selected; **EX-S9** a V171 ASCII copy widened to 4,000 bytes staged with 300 × `x`; **EX-S10** the selection moved down two rows between Enter and the stage's handling, and a `note_staged(name, advance=False)` call; **EX-S11** a stage then Undo, and a stage then re-selecting the row; **EX-B1** a session action held running (the busy fixture) during Enter; **EX-H6** a row named `A[/x]B` selected; **EX-HL1** the `patch` help body read through TC-B97-32's `label — effect` parser. **EX-C2** (a software_a curve row with no editor) leaves Inc 8's cases at E3R1 (Inc 9 C-9; R-PE-BENCH.3) and stays only as the `ops_for` example of Inc 8 alone.

### Baseline (code in scope at `91d5ae56`, real callers)

From the E1 census (`../evidence-e1/cw-census-extract.json`; C = extractor, R = read). Context nodes are in `../evidence-e1/cw-census-graph.md`; they are not repeated in `## Nodes`.

| Function | Callers | Inc 8 |
|---|---|---|
| `LayoutMixin.compose` (`layout.py:17`) | textual (R) | changed (N20) |
| `A2lPickerMixin._compose_a2l_tab` (`a2l_picker.py:221`) | `layout.py:75` (R) | renamed + split (N27, N28) |
| `A2lPickerMixin._on_a2l_parameter_picker_view_changed` (`a2l_picker.py:209`) | message dispatch (R); calls `_apply_a2l_layout` `:221` (C) | changed (N29) |
| `A2lPickerMixin._use_highlighted_parameter` (`a2l_picker.py:126`) | `actions.py:94` (R) | unchanged; reads the cursor N30 moves |
| `A2lPickerMixin.set_a2l_parameters` (`a2l_picker.py:23`) | `app/patch.py:1613` (C); `app/checks_diff.py:101` is the Check panel's homonym (R) | unchanged |
| `PatchEditorPanel.__init__` (`panel.py:468`) | `app/compose_screens.py:540` (C) | changed (N21) |
| `PatchEditorPanel._show_tab` (`panel.py:711`) | the chips' handler (R) | changed (N22) |
| `PatchEditorPanel._refresh_inspector_subtitle` (`panel.py:623`) | `_show_tab` `:728`, `_set_window_subtitle` `:622` (C/R) | changed (N23) |
| `PatchEditorPanel.set_image_mem_map` (`panel.py:673`) | `app/loaded_state.py:407` (C) | changed (N25) |
| `EntriesMixin.refresh_entries` (`entries.py:115`) | `app/loaded_state.py:675`, `app/patch.py:289`, `:568`, `:1534`, `app/project_load.py:1029`, `panel.py:698` (C/R) | overridden in `panel.py` (N24), not edited |
| `ChangeService.add_symbol_entry` (`change_service.py:1253`) | tests only (R) | unchanged, not called |
| `ChangeService._push_history` (`:971`) | 6 sites (C) | called by N33 |
| `PatchMixin._refresh_patch_history_view` (`app/patch.py:529`) | `:726`, `:761`, `:1000` (C) | called by N34 |
| `PatchMixin._report_change_result` (`app/patch.py:1155`) | 8 sites (C) | called by N34 |
| I-2 `describe_definitions` / `describe_definition` / `decode_definition` / `encode_definition` | `a2l_parameter_picker.py:609` only (C) | called by the per-kind `decode` and `preview`, `stage_definition`, A3; no longer by `show_page` (E3A-04) |
| `A2LParameterPicker.set_parameters` (`a2l_parameter_picker.py:568`) | `screens_directionb/check_editor.py:223`, `screens_directionb/patch_editor/a2l_picker.py:40` (C, E3R1 census) | changed at E3R1 (keeps `definitions`); the Check Editor's picker gains the same read-only attribute and does not read it |
| `section_body_text` (`window_help.py:622`), the reader of `WINDOW_HELP_SECTIONS` | `window_help.py:712` (C, E3R1 census); TC-B97-32's `_help_lines` (tests, R) | unchanged; the `patch` section changes (E3A-06) |
| `PatchMixin._strip_source_map` (`app/patch.py:1001`) | `app/patch.py:293`, `:571`, `:1537` (C, E3R1 census); `app/loaded_state.py:679` (R) | unchanged; A3 calls it (E3S-01) |
| `PatchMixin._report_change_result` (`app/patch.py:1156`) | 8 sites `app/patch.py:192`, `:213`, `:249`, `:261`, `:416`, `:860`, `:985`, `:1498` (C, E3R1 census) | unchanged; A3 prints `result.notices` after it (E3A-10) |
| `ShellMixin._refuse_if_busy` (`app/shell.py:425`) | C lists 2 sites (`app/file_load.py:675`, `app/patch.py:1586`; the extractor marks 9 name resolutions ambiguous); R (grep) 20 sites, among them `app/patch.py:145`, the Patch actions' gate | unchanged; A3 calls it first (E3S-03, Inc 9 E-2) |

### Coverage — every requirement → nodes and examples (owner group)

| Requirement | Nodes | Examples | Group |
|---|---|---|---|
| R-TUI-063.1 | LayoutMixin.compose, PatchEditorPanel.__init__ | EX-L1 | P |
| R-TUI-063.3 | PatchEditorPanel._TABS, LayoutMixin.compose | EX-L2 | P |
| R-TUI-063.4 | LayoutMixin.compose | EX-L2 | P |
| R-TUI-063.6 | PatchEditorPanel._TABS, _show_tab | EX-L2 | P |
| R-PE-041 | PatchEditorPanel._refresh_inspector_subtitle | EX-L3 | P |
| R-PE-DEF.1.1 | LayoutMixin.compose (+ styles.tcss) | EX-L1, EX-L7 | P |
| R-PE-DEF.1.2 | styles.tcss (`PatchEditorPanel.-bench #patch_inspector { height: 6; }`) | EX-L8 | P |
| R-PE-DEF.74 | styles.tcss (`#patch_sheet_win { min-height: 12; }`) | EX-L9 | P |
| R-PE-DEF.2 | LayoutMixin.compose, A2lPickerMixin._compose_filter_row (+ styles.tcss) | EX-L4 | P |
| R-PICKER-CORRECT.011 | A2lPickerMixin._compose_filter_row | EX-L4 | P |
| R-PICKER-CORRECT.020 | LayoutMixin.compose (+ styles.tcss) | EX-L5 | P |
| R-PE-DEF.3 | A2lPickerMixin._compose_use_row, LayoutMixin.compose | EX-L4 | P |
| R-PE-DEF.4 | styles.tcss (`#patch_sheet_win:focus-within`) | EX-L6 | P |
| R-PE-DEF.5 | header_line, StagingSheet._paint | EX-W1 | S |
| R-PE-DEF.6 | sheet_widths | EX-W1 | S |
| R-PE-DEF.7 | sheet_widths, row_line (clip in cells), StagingSheet._paint | EX-W1, EX-W2, EX-W3 | S |
| R-PE-DEF.10 | StagingSheet.show_page, A2lPickerMixin._on_a2l_parameter_picker_view_changed | EX-R1 | S (+P call) |
| R-PE-DEF.11 | A2LParameterPicker.set_parameters, StagingSheet.show_page, StagingSheet.set_document, build_row, _on_a2l_parameter_picker_view_changed | EX-R2, EX-R12 | S (+P call) |
| R-PE-DEF.12 | StagingSheet.show_page, build_row, ops_for | EX-C1, EX-T3 | S |
| R-PE-DEF.13, .14 | StagingSheet.show_page | EX-R3 | S |
| R-PE-DEF.15 | row_line, plain | EX-R4, EX-H1 | S |
| R-PE-DEF.16 | kind_word | EX-D1, EX-V1, EX-R5 | S |
| R-PE-DEF.17 | ops_for, build_row, value_text, row_line | EX-D1, D2, D3, V1 | S |
| R-PE-DEF.75 | ops_for (`_FALLBACK_OPS.value_text`), build_row | EX-R9, EX-F1 | S |
| R-PE-DEF.88 | ops_for (the text entry over 4,096 B), build_row | EX-T1, EX-T3 | S |
| R-PE-DEF.18 | StagedOverlay.__getitem__, build_row, value_text, set_document, set_image_mem_map | EX-R6 | S (+P) |
| R-PE-DEF.19 | build_row, value_text | EX-R7 | S |
| R-PE-DEF.20 | row_line, plain | EX-D2, EX-H2 | S |
| R-PE-DEF.21 | limits_cell, short_number | EX-D2, P1, D4, R8 | S |
| R-PE-DEF.76 | limits_cell | EX-R10 | S |
| R-PE-DEF.77 | delta_text | EX-R10 | S |
| R-PE-DEF.22 | row_line, StagingSheet.action_move | EX-K1 | S |
| R-PE-DEF.23 | ops_for (staged), build_row, value_text, row_line, set_document | EX-S1, S2, S3, R9 | S |
| R-PE-DEF.24 | preview, value_text, row_line, on_input_changed, formula_fill | EX-P1, P2, K5 | S |
| R-PE-DEF.25 | preview, row_line, on_input_changed | EX-P3, P4 | S |
| R-PE-DEF.26 | delta_text | EX-P1, S1, P2, P5, P6 | S |
| R-PE-DEF.81 | row_window, StagingSheet.action_move, StagingSheet._paint | EX-K4, EX-K6 | S |
| R-PE-DEF.27 | delta_text | EX-P7 | S |
| R-PE-DEF.28 | row_line | EX-D2 | S |
| R-PE-DEF.30 | detail_lines, action_move, _paint | EX-K2 | S |
| R-PE-DEF.31 | detail_lines | EX-D1, D2, D3, V1, R11 | S |
| R-PE-DEF.32 | detail_lines | EX-R7 | S |
| R-PE-DEF.33 | detail_lines | EX-D1, P2 | S |
| R-PE-DEF.34 | detail_lines | EX-D3, P5 | S |
| R-PE-DEF.35 | detail_lines | EX-V1, P6 | S |
| R-PE-DEF.79 | detail_lines | EX-T1 | S |
| R-PE-DEF.36 | row_kind, ops_for (editable), formula_tail, _paint | EX-R7, R9, T1 | S |
| R-PE-DEF.78 | formula_fill, _paint | EX-T1 | S |
| R-PE-DEF.37 | ops_for (label), _paint | EX-D1, D2, D3, V1 | S |
| R-PE-DEF.38 | formula_fill, _paint | EX-V1, K5 | S |
| R-PE-DEF.39 | formula_fill, on_input_changed, _paint | EX-K3 | S |
| R-PE-DEF.80 | formula_fill, StagingSheet.action_choose | EX-T2 | S |
| R-PE-DEF.40 | preview, formula_tail, on_input_changed | EX-P1, D4, P3, P6 | S |
| R-PE-DEF.41 | formula_tail | EX-P4 | S |
| R-PE-DEF.42 | StagingSheet.on_input_changed (the input is an `OsClipboardInput(max_length=4096)`, I-1) | EX-H3 | S |
| R-PE-DEF.45 | action_move | EX-K1 | S |
| R-PE-DEF.46 | StagingSheet.action_edit | EX-K1, EX-R9, EX-T1 | S |
| R-PE-DEF.47 | action_choose | EX-P2 | S |
| R-PE-DEF.48 | _on_formula_escape | EX-P1 | S |
| R-PE-DEF.49 | action_move, A2lPickerMixin._on_staging_sheet_selection_changed | EX-K1 | P |
| R-PE-DEF.50 | on_input_submitted (ops.submit), ChangeService.stage_definition | EX-S1 … S4 | A |
| R-PE-DEF.51 | StagedOverlay.__getitem__, preview, stage_definition, on_staging_sheet_stage_requested (the source view) | EX-O1, O2, O3 | A |
| R-PE-DEF.52 … .55 | ChangeService._stage_encoded | EX-S5, O1, S1, F1, S8 | A |
| R-PE-DEF.56, .57 | stage_definition, on_staging_sheet_stage_requested | EX-P3, P7, P8 | A |
| R-PE-DEF.58 | _stage_encoded, name_echo, on_staging_sheet_stage_requested | EX-S1, S2, S9 | A |
| R-PE-DEF.59 | stage_definition (`notices`), on_staging_sheet_stage_requested | EX-D4 | A |
| R-PE-DEF.60 | PatchEditorPanel.note_staged, StagingSheet.select_after | EX-S1, S6, S10 | P (+S) |
| R-PE-DEF.82 | StagingSheet.select_after | EX-S11 | S |
| R-PE-110 | on_staging_sheet_stage_requested (`_refuse_if_busy` first) | EX-B1 | A |
| R-PE-DEF.61 | _stage_encoded | EX-S1 | A |
| R-PE-034 | PatchEditorPanel.note_staged, on_staging_sheet_stage_requested | EX-S1 | P (writer), A (call) |
| R-PE-035 | on_staging_sheet_stage_requested | EX-P3 | A |
| R-PE-DEF.62 | PatchEditorPanel.refresh_entries, PatchEditorPanel.set_image_mem_map, StagingSheet.set_document, build_row | EX-S1, O1, S7, M1 | P (+S) |
| R-PE-DEF.63, .64 | on_staging_sheet_stage_requested | EX-F2, F3 | A |
| R-PE-DEF.70 | row_line, _paint (the bar's name, label and tail as `Text`), plain | EX-H1, H6 | S |
| R-PE-DEF.71 | plain | EX-H2 | S |
| R-PE-DEF.72 | name_echo, _stage_encoded | EX-H4 | S (+A call) |
| R-PE-DEF.73 | on_staging_sheet_stage_requested (`_report_change_result`, plain status) | EX-H1 | A |
| R-PE-DEF.83 … .87 | WINDOW_HELP_SECTIONS | EX-HL1 | A |

Every active requirement (89 after E3R2) has a node and at least one concrete example; none is left uncovered. The CSS-only rows (R-PE-DEF.1.1, .1.2, .2, .4, .74, R-PICKER-CORRECT.020) are owned by group P through `styles.tcss` and verified by real layouts (EX-L1, L4 … L9).

### Node count

**42 prototype nodes** — one per function the change adds or touches:
- **34 new.** Group S1 (`definition_sheet.py`, 17): `sheet_widths`, `StagedOverlay.__getitem__`, `row_kind`, `kind_word`, `build_row`, `value_text`, `preview`, `delta_text`, `short_number`, `limits_cell`, `row_line`, `header_line`, `detail_lines`, `formula_label`, `formula_tail`, `plain`, `name_echo`. Group S2 (`sheet.py`, 10): `StagingSheet.show_page`, `.set_document`, `.action_move`, `.action_edit`, `.action_choose`, `.on_input_submitted`, `.on_input_changed`, `._on_formula_escape`, `.select_next`, `._paint`. Group P (4 new): `PatchEditorPanel.refresh_entries` (override), `.note_staged`, `A2lPickerMixin._compose_use_row`, `._on_staging_sheet_selection_changed`. Group A (3): `ChangeService.stage_definition`, `._stage_encoded`, `PatchMixin.on_staging_sheet_stage_requested`.
- **8 changed** (group P): `LayoutMixin.compose`, `PatchEditorPanel.__init__`, `._show_tab`, `._refresh_inspector_subtitle`, `.set_image_mem_map`, `._TABS`, `A2lPickerMixin._compose_filter_row` (renamed from `_compose_a2l_tab`), `._on_a2l_parameter_picker_view_changed`.
- **0 removed.** `StagedOverlay`'s `__iter__` / `__len__`, the dataclasses `SheetWidths`, `SheetRow`, `Preview`, the widget's `compose` and `BINDINGS`, and the I-8.5 tables are data or toolkit plumbing covered by the nodes that use them.

**After E3R1: 46 prototype nodes** (under the E3R1 stop line of about 48):
- **36 new.** S1 (`definition_sheet.py`, 19): the 17 above less `formula_label` (removed: the label is `KindOps.label`), plus `ops_for`, `row_window`, `formula_fill`. S2 (`sheet.py`, 10): `StagingSheet.select_next` is renamed `select_after` (same count). P (4 new, unchanged). A (3, unchanged).
- **10 changed.** The 8 group P nodes above, plus `A2LParameterPicker.set_parameters` (group S2, E3A-04) and `WINDOW_HELP_SECTIONS` (group A, E3A-06).
- **1 removed** from the E2 graph: `formula_label`.
- Per group: S1 19, S2 11, P 12, A 4. The per-kind callables in `_KIND_OPS` and `_FALLBACK_OPS` (the bit strip, enum options, text rows, the fallback's value text and byte-level staged rule) are table data covered by the dispatching nodes that call them (`ops_for`, `build_row`, `detail_lines`), as the E2 graph covered `_DETAIL_BY_KIND`'s entries.

E2 note: 42 was at the cap of "about 40" (2 over). **PROPOSED D-9** (added to `../E1-rulings.md` §3): **A (recommended)** keep one increment — 3 of the 42 are one-line helpers (`short_number`, `formula_label`, `kind_word`), the requirement count (72) is under its cap, and any split leaves the operator a sheet that shows values but cannot stage them; **B** split into 8a (layout and the read-only sheet: M1–M3, groups P and S without `on_input_submitted`) and 8b (staging: M4–M5, group A and the stage path), visible boundary "see" vs "stage". E4 runs one implementer per group (S1, S2, P, A); S1 and S2 exceed about 8 nodes but cannot be split further by file ownership.

### What a different ruling changes here

- **D-1 B/C:** `_TABS`, `LayoutMixin.compose` and `_compose_use_row` (B: the Use row and the Inspector pane on a hidden container; C: a fifth A2L chip and a second picker). No group S or A node changes.
- **D-2 B:** `_refresh_inspector_subtitle` stays as it is; `compose` keeps a border on `#patch_win_script`.
- **D-3 B:** `_stage_encoded`'s equal-span branch sets `symbol=None` when the name differs.
- **D-4 A:** +1 node `StagingSheet.action_unstage` and +1 service node `ChangeService.unstage_definition` (bits under the mask back to the image's, `UNSTAGE` pilot line).
- **D-5 B:** the group S nodes of `definition_sheet.py` move into `sheet.py`; no contract changes.
- **D-6 B:** `sheet_widths` loses its third class; `_paint` scrolls horizontally.
- **D-7 B:** I-2 fills the layout word for scalars (out of this graph); `detail_lines` already paints a named one since E3R1 (Inc 9 C-6).
- **D-8 B:** `LayoutMixin.compose` gains Inc 10's dock (a shared function, sequential build).

## Nodes

sheet_widths
req: R-PE-DEF.6, R-PE-DEF.7
in: int width
out: SheetWidths widths
func: the column widths of CTX-PE-DEF for a sheet content width; Limits = width − 2 − the others − 1, capped at 64 [D-6]
module: s19_app/tui/definition_sheet.py
examples: (EX-W1) width `96` → name `16`, kind `0`, current `14`, new `12`, unit `0`, limits `41`, delta `10`
examples: (EX-W1) width `118` → name `18`, kind `9`, current `18`, new `13`, unit `7`, limits `34`, delta `16`
examples: (EX-W1) width `200` → name `24`, kind `10`, current `44`, new `20`, unit `8`, limits `64`, delta `22`

StagedOverlay.__getitem__
req: R-PE-DEF.51, R-PE-DEF.62
in: int address
out: int byte
func: I-8.1: the last document-order entry byte at the address, else the image's byte; KeyError when neither holds it
module: s19_app/tui/definition_sheet.py
examples: (EX-O1) image word `1A E7` at 0x800010, entries [(0x800010, `1F F7`)] → address 0x800010 → `0x1F`, 0x800011 → `0xF7`
examples: (EX-R6) image None, entries [] → address 0x800020 → KeyError
examples: (EX-R6) image without 0x800021, entries [] → address 0x800021 → KeyError

row_kind
req: R-PE-DEF.36, R-PE-DEF.37
in: Definition definition
out: str kind
func: number, bit mask, enum, text from I-2's kind and bit_mask; "none" for a refused definition; any other kind is I-2's kind word, which ops_for maps to an entry or the fallback. E3R1 (E3A-02): no editable rule here any more (KindOps.editable)
module: s19_app/tui/definition_sheet.py
examples: (EX-D2) DISPLAY_0001 → "number"; (EX-D3) MASK_FIELD_0001 → "bit mask"; (EX-D1) ENUM_0001 → "enum"; (EX-V1) → "text"
examples: (EX-F1) a software_a curve → "curve"; (EX-R9) the `cuboid` copy → "cuboid"; (EX-R7) a refused definition → "none"

ops_for
req: R-PE-DEF.17, R-PE-DEF.23, R-PE-DEF.36, R-PE-DEF.37, R-PE-DEF.75
in: str kind
out: KindOps ops
func: new at E3R1 (E3A-02, I-8.5): _KIND_OPS.get(kind, _FALLBACK_OPS). _FALLBACK_OPS: label "", editable never, decode None (no I-2 call), value text `<n> values` from the element count (`refused` for a refused definition, `--` without a count), staged = any span byte of the overlay differs from the image's, detail = the definition line only, cells and bar None. E3R2 (E3S-10): staged is one pass over the document entries' bytes inside the span against the image (the image is a Mapping[int, int], so there is no memoryview; the bound is the document, not the span); the text entry's decode is None and its value text `<n> B` for a span over 4,096 B, with the same staged rule
module: s19_app/tui/definition_sheet.py
examples: (EX-T3) a V171 ASCII copy of 1,048,576 B, entries [(span start + 64, `58 59 5A` + 39 × `00`)] over an image of `41` bytes → value text `1048576 B`, staged `True` after `42` image lookups (`S.bounded_row`)
examples: (EX-D2) "number" → label "new =", editable(DISPLAY_0001) `True`; (EX-D3) "bit mask" → label "field ="; (EX-V1) "text" → label "text =", editable(V171 ASCII 42 B) `True`; (EX-T1) editable(a 4,097-byte copy) `False`
examples: (EX-R9) "cuboid" → the fallback: label "", editable `False`, value text `24 values` (element count None → `--`), staged with the raw entry `AA BB` over 0x800020 → `True`
examples: (EX-F1) "curve" under Inc 8 alone → the fallback, value text `8 values`; (EX-R7) "none" → the fallback, value text `refused`

kind_word
req: R-PE-DEF.16
in: Definition definition
out: str word
func: the char type; "MEASUREMENT" for a measurement; "?" when neither
module: s19_app/tui/definition_sheet.py
examples: (EX-D1) ENUM_0001 → "VALUE"; (EX-V1) → "ASCII"; (EX-R5) a MEASUREMENT → "MEASUREMENT"

build_row
req: R-PE-DEF.11, R-PE-DEF.12, R-PE-DEF.17, R-PE-DEF.18, R-PE-DEF.19, R-PE-DEF.23, R-PE-DEF.62, R-PE-DEF.75, R-PE-DEF.88
in: Definition definition; dict? a2l_data; Mapping[int, int]? image; StagedOverlay overlay
out: SheetRow row
func: ops = ops_for(row_kind(definition)); current = ops.decode over the image, staged value = ops.decode over the overlay; is_staged = ops.staged(row, image, overlay). A refused definition has row kind `none` and takes the fallback: no I-2 call, current and staged hold no value (None), not staged (E5, DF-04 b: was "keeps its refusal", which contradicted the I-8.5 fallback row); a decode refusal (span not held) is kept as the refusal. E3R1 (E3A-02): dispatches through I-8.5, never branches on the kind; the fallback never calls I-2 (no A2L-DEF-ELEMENTS). E3R2: `a2l_data` is the page A2L the sheet stored from show_page, never the app's (E3A-13); per-row work is bounded by the document (no decode of a text span over 4,096 B, E3S-10)
module: s19_app/tui/definition_sheet.py
examples: (EX-R12) DISPLAY_0001's old definition with the page A2L (factor 0.5), image `01 1F` → current text `143.5`; with an app payload of factor 1.0 the same call would give `287.0` (the mix E3A-13 forbids)
examples: (EX-T3) 200 rows of the 1 MiB copy, one 42-byte entry → `200` rows built, 0 decodes, median `0.00086` s for the per-row rule (`S.bounded_200_rows`, load 7.7–8.0); the negative control (full decode over image and overlay) ≈ `62` s (`S.negative_control.*`)
examples: (EX-D2) DISPLAY_0001, image `01 1F`, no entries → current `Decoded(287, 143.5, '143.5')`, staged equal, not staged
examples: (EX-S1) entries [(0x800020, `00 33`)] → staged text `25.5` ≠ `143.5` → staged
examples: (EX-R6) image None → current is a Refusal (A2L-DEF-BYTES)
examples: (EX-R9) the `cuboid` copy, entries [(0x800020, `AA BB`)] → current None, is_staged `True`
examples: (EX-M1) MASK_BIT_0001, image word `1A E6`, entries [(0x800010, `1F F7`)] → current `Decoded(0, …, '0')`, staged `Decoded(1, …, '1')`, is_staged `True`

value_text
req: R-PE-DEF.17, R-PE-DEF.18, R-PE-DEF.19, R-PE-DEF.23, R-PE-DEF.24
in: SheetRow row; object decoded
out: str text
func: KindOps.value_text of the four scalar kinds (I-8.5): the value text of CTX-PE-DEF for row.kind; `--` for a decode refusal of the span, `refused` for a describe refusal. E3R1 (E3A-02): takes the row (was: the kind word)
module: s19_app/tui/definition_sheet.py
examples: (EX-D2) a "number" row, Decoded(287, 143.5, '143.5') → `143.5`
examples: (EX-D1) an "enum" row, Decoded(1, 'IDLE', 'IDLE') → `1 IDLE`
examples: (EX-D3) a "bit mask" row, Decoded(174, 174, '174') → `174 (0xAE)`; Decoded(255, …) → `255 (0xFF)`
examples: (EX-V1) a "text" row, Decoded(None, 'Hello ASAM', 'Hello ASAM') → `"Hello ASAM"`
examples: (EX-R6) a Refusal A2L-DEF-BYTES → `--`; (EX-R7) a describe refusal → `refused`

preview
req: R-PE-DEF.24, R-PE-DEF.25, R-PE-DEF.40, R-PE-DEF.51
in: Definition definition; dict a2l_data; str text; StagedOverlay overlay
out: Preview preview
func: encode_definition(definition, a2l_data, text, overlay); for an Encoded, decode over the overlay with its bytes
module: s19_app/tui/definition_sheet.py
examples: (EX-P1) DISPLAY_0001 `25.5` → result `Encoded(0x800020, 00 33, ())`, decoded text `25.5`
examples: (EX-P3) `abc` → result Refusal A2L-DEF-NUMBER, decoded None
examples: (EX-O1) MASK_BIT_0001 `0` over entries [(0x800010, `1F F7`)] → `Encoded(0x800010, 1F F6, ())` (over the bare image it would be `1A E6`: the negative control of R-PE-DEF.51)

delta_text
req: R-PE-DEF.26, R-PE-DEF.27, R-PE-DEF.77
in: SheetRow row; object value; bool staged
out: str text
func: the Δ text of CTX-PE-DEF; `✗ refused` for a refused preview; "" when neither staged nor pending. E3R1 (E3S-05): the percent only while upper > lower, never a division by upper − lower otherwise
module: s19_app/tui/definition_sheet.py
examples: (EX-R10) limits `5 5`, preview 25.5, staged False → `-118.0`; limits `9 1` → `-118.0`
examples: (EX-P1) DISPLAY_0001, preview 25.5, staged False → `-118.0 (-62.1%)`; staged True → `-118.0 staged`
examples: (EX-P2) ENUM_0001 1 → 2 → `1 → 2`; (EX-P5) MASK_FIELD 174 → 255 → `+81`; (EX-P6) V171 ABC → `10 chars`
examples: (EX-P7) a Refusal → `✗ refused`

short_number
req: R-PE-DEF.21
in: float value
out: str text
func: the short number of CTX-PE-DEF
module: s19_app/tui/definition_sheet.py
examples: (EX-W1) `-40` → "-40"; `150` → "150"; `65.349` → "65.3"; `655350` → "655k"; `4294967295` → "4.29G"; E5 correction (relevo-10, P-054 F-1, 3 significant digits from 1000 up): `1000` → "1.00k"; `-1000` → "-1.00k"; `999500` → "1.00M"; `1.5e12` → "1.50e+03G"

limits_cell
req: R-PE-DEF.21, R-PE-DEF.76
in: SheetRow row; object value; int width
out: Text cell
func: `<short lower> <track> <short upper>` with ● current and ◆ preview/staged; ◀ / ▶ beyond the ends; the dots form under 6 track cells; `-` without both limits. E3R1 (E3S-05): the dots form when upper is not greater than lower, before any position is computed
module: s19_app/tui/definition_sheet.py
examples: (EX-R10) limits `5 5`, width `34` → "5 … 5"; limits `9 1` → "9 … 1" (no exception)
examples: (EX-D2) DISPLAY_0001, width `34`, value None → track `22` cells, "●" on cell `19`
examples: (EX-P1) value 25.5 → "◆" on cell `8`; (EX-D4) value 175 → "▶" on the right end
examples: (EX-D2) width `16` (track 4) → "-40 … 150"; (EX-R8) no limits → "-"

row_line
req: R-PE-DEF.15, R-PE-DEF.17, R-PE-DEF.20, R-PE-DEF.22, R-PE-DEF.23, R-PE-DEF.24, R-PE-DEF.25, R-PE-DEF.28, R-PE-DEF.70, R-PE-DEF.71
in: SheetRow row; SheetWidths widths; bool selected; str? pending; Preview? preview
out: Text line
func: mark, Parameter, Kind, Current, New, Unit, Limits, Δ at the widths; every cell plain text and clipped with `…`; New `·` when neither staged nor pending. E5 (F-3): `pending` is the row's formula text, None when it has none; the row is pending while `pending` is not None and differs from its base text, so an empty text on a text row is pending (the sheet passes `StagingSheet.pending.get(name)`). E3R1 (E3A-12): widths and the clip counted in cells (the clip runs before `plain`, so a 1 MiB value text is never cleaned whole); (Inc 9 K-2) when ops_for(row.kind).cells is not None, its (Kind, Current, New, Limits, Δ) cells replace Inc 8's, clipped to the same widths
module: s19_app/tui/definition_sheet.py
examples: (EX-W3) W 118, name `温度`×6 → Parameter cell `温度温度温度温度…` (17 cells); unit `温度温度` → Unit cell `温度温…` (7 cells)
examples: (EX-D2) DISPLAY_0001, W 118, selected, pending "" → starts "▶ DISPLAY_0001", New "·", Unit "deg C"
examples: (EX-P1) pending "25.50" → mark "▶◆", New "25.5"
examples: (EX-V1) V171 ASCII, pending "" (erased) with its preview → mark "▶◆", New `""`, Δ "10 chars" (E5, F-3)
examples: (EX-S1) staged, not selected → mark " ●", New "25.5", Δ "-118.0 staged"
examples: (EX-R4) V171 ASCII name at W 118 → "ASAM.C.ASCII.UBYT…"; (EX-H1) a name "A[b]" → shown "A[b]"

header_line
req: R-PE-DEF.5
in: SheetWidths widths
out: Text line
func: the header labels at their column starts; a 0-width column has no label
module: s19_app/tui/definition_sheet.py
examples: (EX-W1) widths of W 118 → "Parameter" at `2`, "Kind" at `20`, "Current" at `29`, "New" at `47`, "Unit" at `60`, "Limits" at `67`, "Δ" at `101`
examples: (EX-W1) widths of W 96 → no "Kind", no "Unit"

detail_lines
req: R-PE-DEF.30, R-PE-DEF.31, R-PE-DEF.32, R-PE-DEF.33, R-PE-DEF.34, R-PE-DEF.35, R-PE-DEF.79
in: SheetRow row; Preview? preview; int width; object? state; int room
out: list[Text] lines
func: ops_for(row.kind).detail(row, preview, width, state, room) (I-8.5; Inc 9 K-1: `state` = the sheet's states.get(name), None for Inc 8's kinds; `room` = the body lines left for the detail; the cut to `room` lines is row_window's and _paint's, not this node's — E5, F-2). Inc 8's entries: the definition line (or `└ <refusal message>`), then the kind's lines; the fallback gives the definition line only. E3R1: ` · <record layout>` after the byte order when the definition names one (Inc 9 C-6; [D-7]); text rows capped at 4, then `… <n> more B` (E3S-04)
module: s19_app/tui/definition_sheet.py
examples: (EX-R11) a DISPLAY_0001 copy with record_layout "RL_U16" → ["└ LINEAR phys = 0.5*raw · SWORD s16 big-endian · RL_U16 · 0x00800020 · 2 B"]
examples: (EX-T1) a V171 ASCII copy of 4,097 bytes → 6 lines: "└ text · 0x00810200 · 4097 B", "+00 …", "+10 …", "+20 …", "+30 …", "… 4033 more B"
examples: (EX-D2) DISPLAY_0001 → ["└ LINEAR phys = 0.5*raw · SWORD s16 big-endian · 0x00800020 · 2 B"]
examples: (EX-D1) ENUM_0001 → line 1 "└ TAB_VERB 4 pairs · UBYTE u8 big-endian · 0x00800000 · 1 B", line 2 "( ) 0 OFF   (●) 1 IDLE   ( ) 2 RUN   ( ) 3 FAULT   default \"UNKNOWN_STATE\"", line 3 "↔ choose · enter stage"
examples: (EX-P5) MASK_FIELD_0001, preview `1F F7` → line 2 ends "word 1A E7 → 1F F7", line 3 "mask 0x0FF0 · field = (word & mask) >> 4 · other bits kept"
examples: (EX-P6) V171 ASCII, preview ABC → "└ text · 0x00810200 · 42 B", then "+00 41 42 43 00 …", "+10 …", "+20 …"
examples: (EX-R7) a name declared twice → ["└ " + its A2L-DEF-NAME message]

row_window
req: R-PE-DEF.81
in: int selected; int top; int visible; int detail
out: tuple[int, int] (top, detail lines painted)
func: new at E3R1 (E3A-01): the row window of CTX-PE-DEF. E3R2 (E3A-14): the detail is cut to room = visible − 1 lines, need = 1 + the cut detail; the selected row when it is above top; selected + need − visible when its last painted detail line would fall below the body; else top unchanged. The selected row is always painted
module: s19_app/tui/definition_sheet.py
examples: (EX-K4) selected `40`, top `0`, visible `20`, detail `1` → (`22`, `1`); selected `39`, top `22` → `22`; selected `21`, top `22` → `21`
examples: (EX-K4) selected `5`, top `0`, visible `20`, detail `3` → (`0`, `3`); selected `18` → (`2`, `3`)
examples: (EX-K6) selected `3`, top `0`, visible `3`, detail `3` → (`3`, `2`): the selected row on body line 0, its detail cut to 2 lines; selected `10`, visible `8`, detail `10` → (`10`, `7`) (`W2.*`)

formula_fill
req: R-PE-DEF.24, R-PE-DEF.38, R-PE-DEF.39, R-PE-DEF.78, R-PE-DEF.80
in: SheetRow row; str? pending
out: str text
func: new at E3R1 (E3A-11, E3S-04): the row fill of CTX-PE-DEF — the pending text, else the base text (a text row's current text, else ""); "" for a row with no editor; at most the first 4,096 characters. A row is pending while its formula text differs from this base text
module: s19_app/tui/definition_sheet.py
examples: (EX-V1) V171 ASCII, pending None → "Hello ASAM"; (EX-K5) pending "ABC" → "ABC"
examples: (EX-K3) DISPLAY_0001, pending None → ""; pending "25.5" → "25.5"
examples: (EX-T1) a V171 ASCII copy of 4,097 bytes (no editor) → ""; (EX-T2) an enum row, pending 5,000 × "E" → a text of `4096` characters

formula_tail
req: R-PE-DEF.36, R-PE-DEF.40, R-PE-DEF.41
in: SheetRow row; Preview? preview; int width
out: Text tail
func: the formula tail of CTX-PE-DEF, cut at width with one `…`; the no-editor text for every row with no editor (E3R1: the fallback kinds and a text row over 4,096 bytes). Inc 9 K-3: when ops_for(row.kind).bar is not None, _paint uses its (name, tail) instead of this tail
module: s19_app/tui/definition_sheet.py
examples: (EX-T1) a V171 ASCII copy of 4,097 bytes → "edit ASCII objects in the Inspector tab"; (EX-R9) the `cuboid` copy → "edit VALUE objects in the Inspector tab"
examples: (EX-P1) width `120` → "deg C  (-40 … 150)  raw 287→51 · 01 1F → 00 33  ✓ in limits  enter stage ↓"
examples: (EX-P1) width `100` → "deg C  raw 287→51 · 01 1F → 00 33  ✓ in limits  enter stage ↓" (limits words left out under 110)
examples: (EX-D4) `175` → contains "▲ DISPLAY_0001: 175 is outside the limits -40..150 and inside the extended limits -50..200"
examples: (EX-P3) → "✗ DISPLAY_0001: 'abc' is not a number"; (EX-P4) width `100` → length `100`, ends "…"
examples: (EX-P6) → "3/42 chars · NUL-padded  enter stage ↓"; (EX-F1) under Inc 8 alone a software_a curve (char type CURVE) → "edit CURVE objects in the Inspector tab" (Inc 9 replaces it by its bar, C-9)

plain
req: R-PE-DEF.70, R-PE-DEF.71
in: str text
out: str text
func: every U+0000…U+001F, U+007F, U+0080…U+009F → U+FFFD; brackets kept (rendered with markup off by the caller)
module: s19_app/tui/definition_sheet.py
examples: (EX-H2) "A\x1b[2J" → "A\uFFFD[2J"; "%\x85" → "%\uFFFD"; (EX-H1) "A[/x]B" → "A[/x]B"

name_echo
req: R-PE-DEF.58, R-PE-DEF.72
in: str name
out: str echo
func: the name echo of CTX-PE-DEF (first 256 characters, controls → U+FFFD, then `…`); E3R1 (E3A-03, E3S-04 d): also applied to the `shown` text of a stage message
module: s19_app/tui/definition_sheet.py
examples: (EX-S9) shown 300 × "x" → 256 × "x" + "…"
examples: (EX-H4) 300 × "N" → 256 × "N" + "…"; "A\x1bB" → "A\uFFFDB"

StagingSheet.show_page
req: R-PE-DEF.10, R-PE-DEF.11, R-PE-DEF.12, R-PE-DEF.13, R-PE-DEF.14
in: Sequence[str] names; Mapping[str, Definition] definitions; dict? a2l_data; Mapping[int, int]? image
out: None
func: I-8.4 (re-pinned at E3R1, E3A-04; at E3R2, E3A-13): stores a2l_data (the page A2L); rows rebuilt in page order from `definitions` (the picker's population describe) with build_row(…, the stored a2l_data, …); 0 describes; never reads app.current_a2l_data; selection kept by name, else row 0; the row window recomputed (row_window); posts SelectionChanged; the empty-page line; the no-A2L line when a2l_data is None. Overridable (Inc 9 C-2)
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
modify: [Data: StagingSheet.rows] (replace); [Data: StagingSheet.selected] (replace); [Data: StagingSheet.top] (replace); [Data: StagingSheet.a2l_data] (replace)
examples: (EX-R1) names ["MASK_BIT_0001", "MASK_FIELD_0001"], DEFC definitions, DEFC a2l_data → `2` rows in that order, selected "MASK_BIT_0001"
examples: (EX-R3) names [] → body "No parameters on this page: type a filter above."
examples: (EX-R3) a2l_data None, definitions {} → body "Load an A2L file to edit parameters by definition."
examples: (EX-R12) DEFC definitions with their own a2l_data (factor 0.5) while app.current_a2l_data has factor 1.0 → DISPLAY_0001 Current "143.5"; after the picker repopulates and passes the new pair → "287"
examples: (EX-C1) 200 software_a names over a full image → `0` describe_definitions calls, painted median ≤ `0.5` s; (EX-T3) the hostile page of 200 1 MiB text copies → `0` decodes, median ≤ `0.5` s

StagingSheet.set_document
req: R-PE-DEF.11, R-PE-DEF.12, R-PE-DEF.18, R-PE-DEF.23, R-PE-DEF.62
in: Sequence[tuple[int, Sequence[int]]] entries; Mapping[int, int]? image
out: None
func: I-8.4: a new StagedOverlay; every row rebuilt with build_row (no describe; staged state through ops_for, E3R1 E3A-02) with the a2l_data stored by the last show_page (E3R2, E3A-13); per-row work bounded by the document (E3R2, E3S-10); repaint through _paint. Overridable (Inc 9 C-2)
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
modify: [Data: StagingSheet.rows] (replace)
examples: (EX-S1) entries [(0x800020, `00 33`)] → DISPLAY_0001 mark "●", New "25.5"
examples: (EX-O1) entries [] after Remove → MASK_FIELD_0001 and MASK_BIT_0001 not staged
examples: (EX-M1) entries [(0x800010, `1F F7`)], image word `1A E6` → MASK_BIT_0001 mark "●", New "1 (0x01)"
examples: (EX-R12) after a show_page with the page A2L of factor 0.5, entries [(0x800020, `00 33`)] → DISPLAY_0001 New "25.5", whatever app.current_a2l_data holds

StagingSheet.action_move
req: R-PE-DEF.22, R-PE-DEF.30, R-PE-DEF.45, R-PE-DEF.49, R-PE-DEF.81
in: int delta
out: None
func: selection ± 1 within the rows (no wrap); E3R1 (E3A-01): top = row_window(selected, top, visible, the selected row's detail line count), so top ≤ selected < top + visible; posts SelectionChanged; _paint. Overridable (Inc 9 C-2)
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
modify: [Data: StagingSheet.selected] (replace); [Data: StagingSheet.top] (replace)
examples: (EX-K4) 200 rows, visible `20`, number rows: selected `39`, top `0`, delta `1` → selected `40`, top `22`
examples: (EX-K1) 3 rows, selected 0, delta `1` → selected `1`; again → `2`; delta `-1` → `1`
examples: (EX-K1) selected 0, delta `-1` → selected `0`

StagingSheet.action_edit
req: R-PE-DEF.46
in: (none)
out: None
func: Enter on the sheet body: focus to the formula input (a row with an editor only: ops_for(kind).editable). Overridable (Inc 9 C-2)
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
modify: [Data: App.focused] (replace)
examples: (EX-K1) DISPLAY_0001 selected, focus "#patch_sheet_body" → focus "#patch_sheet_input"
examples: (EX-R9) the `cuboid` copy → focus stays "#patch_sheet_body"; (EX-T1) a 4,097-byte text copy → stays

StagingSheet.action_choose
req: R-PE-DEF.47, R-PE-DEF.80
in: int delta
out: None
func: enum rows only: the previous/next table entry (no wrap); the formula text becomes its text, written through formula_fill (at most 4,096 characters, E3R1 E3S-04); _paint. Overridable (Inc 9 C-2)
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
modify: [Data: StagingSheet.pending] (replace)
examples: (EX-P2) ENUM_0001 at IDLE, delta `1` → pending "RUN"; again → "FAULT"; again → "FAULT"
examples: (EX-T2) an entry text of 5,000 characters → input value of `4096` characters

StagingSheet.on_input_submitted
req: R-PE-DEF.46, R-PE-DEF.50, R-PE-DEF.56
in: Input.Submitted event
out: None
func: for a row with an editor, always posts ops_for(kind).submit(selected name, formula text), whatever the preview (F-2): for Inc 8's kinds StageRequested; the app's stage refuses a refused text and shows its status. E3R1 (E3A-02): dispatches through I-8.5, no kind branch
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
examples: (EX-P1) DISPLAY_0001 "25.5" → StageRequested("DISPLAY_0001", "25.5")
examples: (EX-P7) "250" → StageRequested("DISPLAY_0001", "250"); the app refuses it (R-PE-DEF.57)

StagingSheet.on_input_changed
req: R-PE-DEF.24, R-PE-DEF.25, R-PE-DEF.39, R-PE-DEF.40, R-PE-DEF.42
in: Input.Changed event
out: None
func: the formula text becomes the selected row's pending text while it differs from the row's base text, else the row's pending entry is dropped (E3R1, E3A-11); ops_for(kind).preview over the overlay (E3A-02) with the stored page A2L, never app.current_a2l_data (E3R2, E3A-13); _paint
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
modify: [Data: StagingSheet.pending] (replace)
examples: (EX-P1) "25.5" → pending {"DISPLAY_0001": "25.5"}, New "25.5", tail "… ✓ in limits …"
examples: (EX-K5) V171 ASCII filled "Hello ASAM" (its base text) → pending {} (no ◆); "ABC" → pending {"ASAM.C.ASCII.UBYTE.NUMBER_42": "ABC"}
examples: (EX-H3) 5,000 typed characters → value length `4096`; a 65,536-character paste into "" → value ""

StagingSheet._on_formula_escape
req: R-PE-DEF.48
in: (none)
out: None
func: clears the selected row's pending text; focus to the sheet body. Overridable (Inc 9 C-2)
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
modify: [Data: StagingSheet.pending] (replace); [Data: App.focused] (replace)
examples: (EX-P1) pending {"DISPLAY_0001": "25.5"} → pending {}, focus "#patch_sheet_body" (the input is "#patch_sheet_input")

StagingSheet.select_after
req: R-PE-DEF.60, R-PE-DEF.82
in: str name
out: None
func: I-8.4 (renamed from select_next at E3R1, E3A-07): drops pending[name]; selects the row after the row named `name` (whatever the selection is now), or keeps `name` on the last row; the row window recomputed; the input refilled through formula_fill; focus stays in the input
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
modify: [Data: StagingSheet.selected] (replace); [Data: StagingSheet.pending] (replace)
examples: (EX-S1) rows [DISPLAY_0001, ENUM_0001, MASK_BIT_0001], selected 0, name "DISPLAY_0001" → selected `1`; (EX-S6) name "MASK_BIT_0001" (last) → selected `2`
examples: (EX-S10) selected `2` (moved by two downs before the call), name "DISPLAY_0001" → selected `1`
examples: (EX-S11) pending {"DISPLAY_0001": "25.5"}, name "DISPLAY_0001" → pending {}

StagingSheet._paint
req: R-PE-DEF.5, R-PE-DEF.7, R-PE-DEF.30, R-PE-DEF.36, R-PE-DEF.37, R-PE-DEF.38, R-PE-DEF.39, R-PE-DEF.70, R-PE-DEF.78, R-PE-DEF.81
in: (none)
out: None
func: I-8.4's one repaint entry (Inc 9 C-2). body = header_line + row_line for rows top … top + visible − need (the row window, E3R1 E3A-01) + detail_lines(row, preview, width, states.get(name), room) under the selected row, cut to room = visible − 1 lines so the selected row is always painted (E3R2, E3A-14), as one Text (markup never parsed); formula bar = name, ops.label, input value formula_fill(row, pending), formula_tail — or ops.bar's (name, tail) when not None (Inc 9 K-3); the name, label and tail are updated as Text, never as a markup str (E3R1, E3S-07); input disabled for a row with no editor; widths from the body's content region
module: s19_app/tui/screens_directionb/patch_editor/sheet.py
examples: (EX-V1) V171 ASCII selected → label "text =", input "Hello ASAM"
examples: (EX-R9) the `cuboid` copy selected → input disabled `True`, input value ""
examples: (EX-W2) at 80 columns every body line's cell length ≤ the body width
examples: (EX-K4) 200 rows, top `22`, visible `20` → body lines: the header, rows 22 … 40, then row 40's detail line
examples: (EX-H6) a row named "A[/x]B" selected → the bar's name shows "A[/x]B", no MarkupError

LayoutMixin.compose
req: R-TUI-063.1, R-TUI-063.3, R-TUI-063.4, R-PE-DEF.1.1, R-PE-DEF.2, R-PE-DEF.3
in: (none)
out: ComposeResult tree
func: ribbon; Horizontal #patch_filter_row (_compose_filter_row); Container #patch_sheet_win (border title STAGING SHEET, subtitle "enter edit · ↑↓ row" — E3R2, E3A-15: Inc 9's integrator appends " · arrays open the bench" when the bench lands (Inc 9 C-4 split), provisional V-13; `min-height: 12` and the `-bench` rule live in styles.tcss) holding self._sheet; Vertical #patch_inspector (LANDS IN) with the four chips and #patch_tab_switcher (initial "patch_win_script"): #patch_win_script (no border) > the ledger; #patch_pane_inspector > entry form, _compose_use_row, tally; #patch_win_json; #patch_win_checks; file row; self._compose_doc_controls() (I-8.3); legend. #patch_main and #patch_win_a2l leave [D-1]
module: s19_app/tui/screens_directionb/patch_editor/layout.py
examples: (EX-L1) 118×54 → regions top to bottom ribbon, filter row, sheet, LANDS IN, file row, document row, legend
examples: (EX-L2) chips "Patch script", "Inspector", "JSON", "Checks"; shown pane "patch_win_script"
examples: (EX-L7) a 4-row stand-in yielded by _compose_doc_controls → it lies between the document row and the legend; #patch_sheet_win height = panel − the other seven regions' heights
examples: (EX-L1) #patch_sheet_win border subtitle "enter edit · ↑↓ row" (Inc 8 alone; Inc 9 appends its clause)

PatchEditorPanel.__init__
req: R-TUI-063.1
in: (none)
out: PatchEditorPanel panel
func: + self._sheet = StagingSheet(id="patch_sheet") after self._a2l_picker
module: s19_app/tui/screens_directionb/patch_editor/panel.py
modify: [Data: PatchEditorPanel._sheet] (replace)
examples: (EX-L1) a new panel → `_sheet` is a StagingSheet with id "patch_sheet"

PatchEditorPanel._show_tab
req: R-TUI-063.6
in: str chip_id
out: None
func: as today, with every title "LANDS IN" (from _TABS) and without the patch_win_a2l measure branch
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (EX-L2) "patch_tab_json" → switcher current "patch_win_json", border title "LANDS IN"

PatchEditorPanel._refresh_inspector_subtitle
req: R-PE-041, R-TUI-063.8
in: (none)
out: None
func: Patch script or Inspector → the ledger subtitle (count + " ●" while dirty); JSON → "v2 schema"; Checks → its run state [D-2]
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (EX-L3) 3 entries, dirty, Inspector shown → border subtitle "3 entries ●"; JSON shown → "v2 schema"

PatchEditorPanel.refresh_entries
req: R-PE-DEF.62
in: Sequence[object] rows; object mem_map = _UNSET; object document = _UNSET
out: None
func: new override in panel.py: EntriesMixin.refresh_entries (super), then self._sheet.set_document([(row.address, row.encoded_bytes) for row in rows], self._mem_map)
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (EX-S1) rows [ChangeEntryRow(address 0x800020, encoded_bytes (0x00, 0x33))] → sheet DISPLAY_0001 staged
examples: (EX-S7) a Parse pasted document with that entry → the same

PatchEditorPanel.set_image_mem_map
req: R-PE-DEF.18
in: Mapping[int, int]? mem_map
out: None
func: as today, then self._sheet.set_document(the current entries, mem_map); mem_map is the source view every caller passes (E3R1, E3S-01: the map the strip and the stage read)
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (EX-R6) None → DISPLAY_0001 Current "--"
examples: (EX-M1) an image whose word at 0x800010 is `1A E6`, entries [(0x800010, `1F F7`)] → MASK_BIT_0001 mark "●"

PatchEditorPanel.note_staged
req: R-PE-034, R-PE-DEF.60
in: str name; bool advance = True
out: None
func: dirty writer w6: _dirty = True, _refresh_dirty_indicator(); advance → self._sheet.select_after(name) (E3R1, E3A-07); advance False → the selection and the pending text stay (Inc 9 C-8: the record stage)
module: s19_app/tui/screens_directionb/patch_editor/panel.py
modify: [Data: PatchEditorPanel._dirty] (replace)
examples: (EX-S1) name "DISPLAY_0001", dirty False → dirty `True`, the row after DISPLAY_0001 selected
examples: (EX-S10) name "DISPLAY_0001", advance `False`, selected `0` → dirty `True`, selected `0`

A2lPickerMixin._compose_filter_row
req: R-PE-DEF.2, R-PICKER-CORRECT.011
in: (none)
out: ComposeResult tree
func: renamed from _compose_a2l_tab; yields only self._a2l_picker (its table and full-name line hidden by CSS, kept mounted)
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
examples: (EX-L4) → "#patch_param_filter", "#patch_param_bulk_button" on the filter row; "#patch_param_table" display `False`

A2lPickerMixin._compose_use_row
req: R-PE-DEF.3
in: (none)
out: ComposeResult tree
func: new, split from _compose_a2l_tab: the "Use parameter" row and #patch_param_use_status, unchanged ids and classes
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
examples: (EX-L4) → "#patch_param_use_button" inside "#patch_pane_inspector"

A2lPickerMixin._on_a2l_parameter_picker_view_changed
req: R-PE-DEF.10, R-PE-DEF.11
in: A2LParameterPicker.ViewChanged event
out: None
func: as today, then self._sheet.show_page(self._a2l_picker.visible_params, self._a2l_picker.definitions, self._a2l_picker.definitions_source, self._mem_map) (E3R2, E3A-13: the payload the definitions came from) (E3R1, E3A-04: the picker's definitions, no describe; an empty mapping while no A2L is loaded)
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
examples: (EX-R1) filter "MASK" → show_page(["MASK_BIT_0001", "MASK_FIELD_0001"], the picker's definitions, its definitions_source, …)
examples: (EX-R2) a page turn and a filter change → `0` describe_definitions calls

A2lPickerMixin._on_staging_sheet_selection_changed
req: R-PE-DEF.49
in: StagingSheet.SelectionChanged event
out: None
func: new: moves the picker table's cursor to the row of event.name, so highlighted_parameter names it
module: s19_app/tui/screens_directionb/patch_editor/a2l_picker.py
examples: (EX-K1) SelectionChanged("MASK_FIELD_0001") → highlighted_parameter["name"] "MASK_FIELD_0001"

PatchEditorPanel._TABS
req: R-TUI-063.3, R-TUI-063.6
in: (none)
out: tuple tabs
func: class constant: ("patch_tab_script", "Patch script", "patch_win_script", "LANDS IN"), ("patch_tab_inspector", "Inspector", "patch_pane_inspector", "LANDS IN"), ("patch_tab_json", "JSON", "patch_win_json", "LANDS IN"), ("patch_tab_checks", "Checks", "patch_win_checks", "LANDS IN") [D-1]
module: s19_app/tui/screens_directionb/patch_editor/panel.py
examples: (EX-L2) labels → "Patch script", "Inspector", "JSON", "Checks"

ChangeService.stage_definition
req: R-PE-DEF.50, R-PE-DEF.51, R-PE-DEF.56, R-PE-DEF.57, R-PE-DEF.59
in: Definition definition; dict a2l_data; str text; Mapping[int, int]? image
out: ChangeActionResult result
func: overlay = StagedOverlay(image, [(e.address, e.encoded_bytes) for e in document.entries]), `image` being the source view (E3R1, E3S-01); encode_definition(definition, a2l_data, text, overlay); Refusal → ok False, message "Patch Editor: <refusal message>", no write; else _stage_encoded(name, encoded, shown = the decode over the new overlay's text), and each encode notice in result.notices as "Patch Editor: <notice>" — never in issues (E3R1, E3A-10)
module: s19_app/tui/services/change_service.py
examples: (EX-P1) DISPLAY_0001 "25.5" → ok `True`, one entry at 0x800020 `00 33`
examples: (EX-O1) MASK_BIT_0001 "0" with the entry 0x800010 `1F F7` → the entry becomes `1F F6`
examples: (EX-O3) after Apply and Remove, MASK_BIT_0001 "0" over the source view → entry `1A E6`; over the live map it would be `1F F6`
examples: (EX-P7) "250" → ok `False`, message "Patch Editor: DISPLAY_0001: 250 is outside the extended limits -50..200", entries unchanged
examples: (EX-D4) "175" → ok `True`, issues [], notices ("Patch Editor: DISPLAY_0001: 175 is outside the limits -40..150 and inside the extended limits -50..200",)

ChangeService._stage_encoded
req: R-PE-DEF.52, R-PE-DEF.53, R-PE-DEF.54, R-PE-DEF.55, R-PE-DEF.58, R-PE-DEF.61
in: str name; Encoded encoded; str shown
out: ChangeActionResult result
func: I-8.2 (re-pinned at E3R1, E3A-03, E3S-02): equal span → _push_history, replace the entry with ChangeEntry("bytes", address, data, symbol=<the old symbol>) [D-3]; no intersection → _push_history, append bytes entry with symbol name; partial → ok False with the overlap status, no history; message "Patch Editor: <name echo> staged as <shown echo> (<n> B at 0x<X>)."; no decode
module: s19_app/tui/services/change_service.py
modify: [Data: ChangeService.document.entries] (replace); [Data: ChangeService.history] (append)
examples: (EX-S8) a `string` entry 42 × "Q" at 0x810200, "ASAM.C.ASCII.UBYTE.NUMBER_42", Encoded(0x810200, 58 59 5A + 39 × 00), shown "XYZ" → one entry, entry_type "bytes", value None; serialized `"type": "bytes"`; read back, V171 decodes "XYZ"
examples: (EX-S9) shown 300 × "x" → message contains "staged as " + 256 × "x" + "…"
examples: (EX-S1) "DISPLAY_0001", Encoded(0x800020, 00 33), shown "25.5" on an empty document → entries [bytes 0x800020 (0x00, 0x33) symbol "DISPLAY_0001"], message "Patch Editor: DISPLAY_0001 staged as 25.5 (2 B at 0x800020).", undo depth +`1`
examples: (EX-S5) then Encoded(0x800020, 00 3C) → `1` entry, bytes (0x00, 0x3C)
examples: (EX-O1) "MASK_BIT_0001", Encoded(0x800010, 1F F6) over the entry symbol "MASK_FIELD_0001" → symbol "MASK_FIELD_0001", bytes (0x1F, 0xF6)
examples: (EX-F1) a 1-byte entry at 0x800021, then "DISPLAY_0001", Encoded(0x800020, 00 33) → ok `False`, "Patch Editor: DISPLAY_0001 overlaps the entry at 0x800021 — remove that entry first."

PatchMixin.on_staging_sheet_stage_requested
req: R-PE-DEF.51, R-PE-DEF.57, R-PE-DEF.58, R-PE-DEF.59, R-PE-DEF.60, R-PE-DEF.61, R-PE-DEF.62, R-PE-DEF.63, R-PE-DEF.64, R-PE-DEF.73, R-PE-034, R-PE-035, R-PE-110
in: StagingSheet.StageRequested event
out: None
func: E3R1: `if self._refuse_if_busy(): return` first (E3S-03, the stage seam of I-8.2); no current_a2l_data → status "Patch Editor: no A2L is loaded — nothing staged."; else describe_definition(event.name, current_a2l_data) (fresh, F-1), stage_definition(…, self._strip_source_map(self.current_file)) (E3S-01); _report_change_result (plain text), then one set_status per result.notices line (E3A-10); ok → panel.note_staged(event.name) (E3A-07); always _refresh_patch_history_view(). Logs nothing of the formula text (E3S-09)
module: s19_app/tui/app/patch.py
examples: (EX-B1) a session action running → status "busy: <label> is running — wait for it to finish.", entries unchanged, dirty unchanged
examples: (EX-D4) StageRequested("DISPLAY_0001", "175") → status lines "Patch Editor: DISPLAY_0001 staged as 175.0 (2 B at 0x800020)." (the decoded text, R-PE-DEF.58; E5, P-045), then exactly "Patch Editor: DISPLAY_0001: 175 is outside the limits -40..150 and inside the extended limits -50..200"
examples: (EX-S1, root on_staging_sheet_stage_requested) StageRequested("DISPLAY_0001", "25.5") → status "Patch Editor: DISPLAY_0001 staged as 25.5 (2 B at 0x800020).", dirty `True`
examples: (EX-F2) no A2L → status "Patch Editor: no A2L is loaded — nothing staged.", entries unchanged, dirty unchanged
examples: (EX-F3) DISPLAY_0001 moved to 0x800030 by a reload → the entry lands at 0x800030
examples: (EX-P3) "abc" → status "Patch Editor: DISPLAY_0001: 'abc' is not a number", dirty unchanged

A2LParameterPicker.set_parameters
req: R-PE-DEF.11
in: Sequence[dict] rows; object signature = None; Optional[dict] a2l_data = None
out: bool repopulated
func: changed at E3R1 (E3A-04): as today, plus self.definitions = MappingProxyType(definitions) and (E3R2, E3A-13) self.definitions_source = a2l_data right after its one describe_definitions call (`{}` without a2l_data); an equal signature returns False before it and keeps the old mapping. Callers (E3R1 census, C): screens_directionb/check_editor.py:223, patch_editor/a2l_picker.py:40
module: s19_app/tui/a2l_parameter_picker.py
modify: [Data: A2LParameterPicker.definitions] (replace)
examples: (EX-R2) DEFC rows with a2l_data → definitions["ENUM_0001"].enum_entries texts OFF, IDLE, RUN, FAULT; a reload whose table renames entry 1 → the new text; `1` describe_definitions call per real population
examples: (EX-R2) the same signature again → returns `False`, definitions unchanged, `0` describe calls; (EX-R3) a2l_data None → definitions {}

WINDOW_HELP_SECTIONS
req: R-PE-DEF.83, R-PE-DEF.84, R-PE-DEF.85, R-PE-DEF.86, R-PE-DEF.87
in: (none)
out: dict sections
func: changed at E3R1 (E3A-06): the "patch" section's steps. Step 1 names the filter row, STAGING SHEET and LANDS IN with the four tabs; the A2L line leaves; Filter, Prev and Next name the filter row's list, not the A2L PARAMETERS ledger; new lines `Patch script — …`, `STAGING SHEET — …`, `new = — …`, `field = — …`, `text = — …`; `Use parameter — on the Inspector tab, uses the staging sheet's selected row …`. Read by section_body_text (window_help.py:712, C). The wording is a visible item (V-12)
module: s19_app/tui/window_help.py
examples: (EX-HL1) _help_lines("patch") → keys include "Patch script", "STAGING SHEET", "new =", "field =", "text =", "Use parameter"; no key "A2L"; "Inspector" in lines["Use parameter"] and "A2L tab" not in it

## Entities

[Data: StagingSheet.rows]
in: list[SheetRow]
desc: the rows of the shown page (definition, current, staged), rebuilt by show_page (with a describe) and by set_document (without)

[Data: StagingSheet.selected]
in: int
desc: the selected row's position; kept by name across show_page

[Data: StagingSheet.pending]
in: dict[str, str]
desc: pending formula text per row name, held only while it differs from the row's base text (E3R1, E3A-11); dropped by Escape, by select_after(name) after a formula-bar stage of that row (E3A-07), and by show_page for names no longer shown

[Data: StagingSheet.top]
in: int
desc: the first painted row of the row window (E3R1, E3A-01); written by show_page, action_move and select_after through row_window

[Data: StagingSheet.a2l_data]
in: dict | None
desc: the page A2L stored by show_page (E3R2, E3A-13); the only payload build_row, KindOps.decode and KindOps.preview get from the sheet

[Data: StagingSheet.states]
in: dict[str, object]
desc: per-row editor state by row name (I-8.4, Inc 9 C-2/K-1); Inc 8's kinds store none; read by KindOps.detail, .cells and .bar as states.get(name)

[Data: A2LParameterPicker.definitions]
in: Mapping[str, Definition]
desc: the picker's population describe, read only (E3R1, E3A-04); kept with definitions_source, the a2l_data it was described from (E3R2, E3A-13); replaced only by a real population (a new A2L signature); read by the Patch Editor's view-changed handler for show_page

[Data: PatchEditorPanel._sheet]
in: StagingSheet
desc: the one sheet widget, composed in #patch_sheet_win

[Data: PatchEditorPanel._dirty]
in: bool
desc: the dirty flag; writer census C-15.1 gains w6 note_staged
sequence:
  stage: PatchMixin.on_staging_sheet_stage_requested → ChangeService.stage_definition → PatchEditorPanel.note_staged wins → PatchMixin._refresh_patch_history_view

[Data: ChangeService.document.entries]
in: list[ChangeEntry]
desc: the change document's entries; the staging overlay is the image with these written over it in order
sequence:
  stage: ChangeService.stage_definition → ChangeService._stage_encoded wins → PatchEditorPanel.refresh_entries → StagingSheet.set_document

[Data: ChangeService.history]
in: list[ChangeDocument]
desc: the undo stack; one step per stage

[Data: App.focused]
in: Widget
desc: the focused widget (the sheet body or the formula input)

## Edges

[Outside: key up] ──▶ StagingSheet.action_move
when: App.focused is the sheet body
[Outside: key down] ──▶ StagingSheet.action_move
when: App.focused is the sheet body
[Outside: key left] ──▶ StagingSheet.action_choose
when: App.focused is the sheet body and the selected row is an enum
[Outside: key right] ──▶ StagingSheet.action_choose
when: App.focused is the sheet body and the selected row is an enum
[Outside: key enter] ──▶ StagingSheet.on_input_submitted
when: App.focused is the formula input
[Outside: key escape] ──▶ StagingSheet._on_formula_escape
when: App.focused is the formula input
StagingSheet.on_input_submitted ──▶ PatchMixin.on_staging_sheet_stage_requested
StagingSheet.action_move ──▶ A2lPickerMixin._on_staging_sheet_selection_changed
A2lPickerMixin._on_a2l_parameter_picker_view_changed ──▶ StagingSheet.show_page
PatchEditorPanel.refresh_entries ──▶ StagingSheet.set_document
ChangeService._stage_encoded ──▶ [Data: ChangeService.document.entries]
[Data: ChangeService.document.entries] ──▶ ChangeService.stage_definition
PatchEditorPanel.note_staged ──▶ [Data: PatchEditorPanel._dirty]
PatchEditorPanel.note_staged ──▶ StagingSheet.select_after
when: advance is True
A2LParameterPicker.set_parameters ──▶ [Data: A2LParameterPicker.definitions]
[Data: A2LParameterPicker.definitions] ──▶ A2lPickerMixin._on_a2l_parameter_picker_view_changed
StagingSheet.action_move ──▶ row_window
StagingSheet.on_input_submitted ──▶ ops_for
build_row ──▶ ops_for

## Findings

finding F-1 Stage re-describes
anchor: PatchMixin.on_staging_sheet_stage_requested
seen: the page's definitions are from the last ViewChanged; an A2L reload posts ViewChanged asynchronously, so a StageRequested queued before it would carry a name whose page definition is stale
cause: message order between the picker's repopulation and the formula's Enter
effect: an encode with an old address, length or mask (the I-2 note: never clear shared_with; re-describe after an A2L change)
decision: the app re-describes the one name with current_a2l_data at every stage; the message carries the name and the text only, never a Definition (R-PE-DEF.64). E3R1 (E3A-04): the cost is one full walk of the A2L, ≈ 0.12 s at 13,990 tags (E3 probe `P1.describe_definition[1].median_s = 0.1167`, load 9.5), not ≈ 40 ms; once per Enter it is kept. The page change no longer describes (the picker's definitions)

finding F-2 Who refuses a refused preview
anchor: StagingSheet.on_input_submitted
seen: the preview and the stage run the same encode over the same overlay on the UI thread, so they agree (true only since E3R1 E3S-01 makes both read the source view; before, the stage read the live map after an Apply); an R-PE-DEF.57 status needs a sender
cause: E1 wrote R-PE-DEF.56/.57 as Enter with a refused preview
effect: if the sheet swallowed a refused Enter, R-PE-DEF.57's status would never show
decision: the sheet always posts StageRequested for an editable row; the app's stage refuses and reports (one code path for the status; the sheet's tail shows the same message). No row changes

finding F-3 The record layout word
anchor: detail_lines
seen: Definition.record_layout is None for every scalar (pilot DEFC.*.record_layout, V171.*.record_layout)
cause: I-2 fills record_layout only for Inc 3's kinds
effect: the capture's `RL_U16` cannot be painted without an I-2 change
decision: D-7 A (left out); D-7 B would add one I-2 field fill and an E3 on a2l_definition.py

finding F-4 The ruler cell rule
anchor: limits_cell
seen: CTX-PE-DEF named the glyphs but not the cell of a value
cause: the prototype's ruler_track held the rule in code only
effect: no example could fix a position
decision: E2 correction in 01-requirements.md CTX-PE-DEF limits cell (cell = 1 + round(pos × (track − 3)) within 1 … track − 2; a second mark on a taken cell moves one cell right); examples cells 19 and 8 at track 22 (examples_inc8-transcript.txt)
