# Inc 3 — E1 rulings: scope, canon changes, decisions

Base: branch `batch-103` at `9ae92c3` (product tree `e07fb00`). Rows: `01-requirements.md`. Cases: `02-test-cases.md`. Slice: `E1-slice.md`. Inc 2's accepted records (`../inc-2/`, rulings of 2026-11-06T16:18:57) are the base this increment extends; nothing of Inc 2 is changed here — §3 D-14 lists what Inc 3 needs changed there. Evidence (all tool output, `evidence-e1/`; every script that imports `s19_app` ran on the LAN host <runner>, Python 3.11.18, the read-only clone at `e07fb00`, HOME/XDG/LOCALAPPDATA under `/tmp/b103-e1-3/home`, no display, no clipboard; `i3e1-run.sh` is the wrapper, `s19_app.__file__` is printed at the top of each transcript):
- `i3e1-pilot.py` → `i3e1-pilot-transcript.txt` (B): the base tree's parse, tag-table decode, description model, record-layout walk and curve encode on V171, software_a and case 08 (generated at 1 MiB, seed 20260001).
- `i3e1-shapes.py` → `i3e1-shapes-transcript.txt` (C): array and axis shapes of the 35 tracked `.a2l` files, read as text, comments left out.
- `i3e1-counts.py` → `i3e1-counts-transcript.txt` (C): per CURVE/MAP point counts, COM_AXIS counts against their AXIS_PTS, FIX_NO_AXIS_PTS lines.
- `i3e1-callers.py` → `i3e1-callers-transcript.txt` (C): the Code-Wire v3.1.0 extractor (`codewire_extract.py` of tag `v3.1.0` = `e436a08`, sha256 `78d54439…a8599` on both hosts) over a throwaway `git archive e07fb00 s19_app`; copied from Inc 2's `i2e1-callers.py`, only the target list differs.
- `i3e1-index-mode-source.py` → `i3e1-index-mode-source-transcript.txt` (C): the public description of ROW_DIR / COLUMN_DIR / INDEX_DECR (D-2).
- `i3e1-modcommon.txt` (C): MOD_COMMON BYTE_ORDER / ALIGNMENT lines of the files with curves or maps and of the synth, software_a's multi-component layouts, AXIS_PTS_REF names with no AXIS_PTS of that name (D-7, R-A2L-DEF.96).
- `i3e1-id-census.txt` (C): `R-A2L-DEF.64` … `.149` unused.

## 1. Scope

**In (US-103-05, PLAN Inc 3):**
- The array model in `s19_app/tui/a2l_definition.py` (Inc 2's new module, no new file): three kinds — array (VAL_BLK, MATRIX_DIM MEASUREMENT, 1-D to 3-D), curve, map — with shape, element count (Inc 6's PE-D1 row, R-A2L-DEF.73), byte length, record layout, axes, decode by element, encode of an edit into the whole record, the round trip (R-A2L-DEF.131, .132).
- Layouts in: FNC_VALUES with ROW_DIR or COLUMN_DIR (3-D only ROW_DIR, D-2), AXIS_PTS_X/Y with INDEX_INCR or INDEX_DECR, NO_AXIS_PTS_X/Y, FIX_NO_AXIS_PTS_X/Y, ALIGNMENT_* of the layout, DIRECT only. These are every form the tracked files use for curves and maps (C shapes `:111-150`), except RESERVED / NO_RESCALE_X / AXIS_RESCALE_X (RES_AXIS only) and AXIS_PTS_Z / _4 (CUBOID, CUBE_4 only).
- Axes in: STD_AXIS, FIX_AXIS (FIX_AXIS_PAR, FIX_AXIS_PAR_DIST, FIX_AXIS_PAR_LIST), COM_AXIS through its AXIS_PTS object (read only, D-4), each axis with its own conversion (the AXIS_DESCR's, D-11). Monotony on an edited axis (D-5), current counts against point counts (D-3).
- Every failure path its own `If` row with its exact text (25 refusal codes, `01-requirements.md`).
- D6 synth: the definitions case gains two COM_AXIS curves on one AXIS_PTS object, a STD/FIX map with COLUMN_DIR values, a 2-D ROW_DIR VAL_BLK (R-A2L-DEF.133 … .135). Case 08 untouched (Inc 2's R-A2L-DEF.59 pin; not duplicated).

**Out (with reason):**
- CUBOID, CUBE_4, CUBE_5, MAP_BLOCK: they keep Inc 2's A2L-DEF-KIND refusal (R-A2L-DEF.4). 4 CUBOID and 2 CUBE_4 in the tracked files, all in the ASAM demo files; 0 in the tool-made files (C shapes `:19-28`). PLAN names CURVE/MAP/VAL_BLK only (US-103-05). D-9.
- RES_AXIS and CURVE_AXIS: refused (R-A2L-DEF.92); 2 + 2 tracked uses, both in the demo files (C shapes `:60-65`). D-9.
- Editing a COM_AXIS's points (D-4 A: refused through the curve; the AXIS_PTS object is not a defined object), FIX_AXIS points (no bytes), the points of a STD_AXIS whose layout holds none (case 08).
- A record whose current count is below its point count (D-3 A), a 3-D COLUMN_DIR array (D-2 A), a record whose MOD_COMMON alignment would move a component (D-7 C).
- ASCII arrays (ASCII with MATRIX_DIM: 0 tracked, C shapes `:49`); Inc 2 builds every ASCII as one text.
- AXIS_DESCR EXTENDED_LIMITS, STEP_SIZE, MAX_GRAD, DEPOSIT DIFFERENCE, AXIS_PTS's own MONOTONY: 0 tracked uses except `DEPOSIT ABSOLUTE` (34, the default; C shapes `:67-75`, `:108-109`). Not read; noted for E3.
- Changing the number of points of an axis (an edit keeps the current count; R-A2L-DEF.123 keeps the count byte).
- Any change to `a2l.py` (frozen) or to the tag table / description window: the defects found are backlog rows (§5), wrapped in the model where an Inc 3 row needs it (Inc 2's D-2 A pattern).
- The editors (Inc 9), the picker (Inc 6): consumers of I-2 (§4).

## 2. Changes to existing canon rows and notes

- **Rows:** none changed, none split, none retired. Cited rows keep their text (`01-requirements.md`, "Cited rows"); the model meets them.
- **CTX-A2L-DEF** (Inc 2's new note): Inc 3 adds terms, formats and lists only (`01-requirements.md`, "Definitions"). Its *defined object* and *kind* lists grow, as Inc 2's rulings §1 foresaw ("only its case list" of R-A2L-DEF.4 changes, D-14).
- **S2.7** gains S2.7e … S2.7i after Inc 2's S2.7d (D-13).
- **Not changed, flagged for the next `a2l.py` unfreeze (D-13 A, as Inc 2's D-8 A):** R-A2L-014 and R-A2L-016 say "× its MATRIX_DIM" (one number); the files write up to three (C shapes `:30-41`) and the code keeps the first (B lines 7-10). R-A2L-016 does not name NUMBER, which sizes 101 a2ltool VAL_BLKs (C shapes `:45-47`). R-A2L-018 ("with their alignment") does not say whose alignment (D-7). R-A2L-022 reads "the datatype the record layout names", which for a multi-component curve layout gives the first one (UBYTE for an SWORD curve, B line 36). Backlog BL-I3-2 … BL-I3-4, BL-I3-8.

## 3. Decisions — PROPOSED, awaiting orchestrator ruling

Each: options, consequence of each, recommendation. The rows are written for the recommendation; a different ruling withdraws or rewrites the rows named.

**D-1 · Interface I-2 extension** — §4. PROPOSED — awaiting orchestrator ruling. Recommendation: §4 as written.

**D-2 · Element order (ROW_DIR / COLUMN_DIR) and three dimensions.** The ASAM text is not available offline. A public tool guide reproducing the standard's figure (`i3e1-index-mode-source-transcript.txt` lines 5-22, Intrepid Control Systems' ASAP2 editor guide) shows a map whose rows are labelled by the Y points and columns by the X points, ROW_DIR giving `a11, a12, a13, a21 …` (X fastest) and COLUMN_DIR `a11, a21, a12 …` (Y fastest), and INDEX_DECR as "decreasing index with increasing address". No tracked image holds known values for a ROW_DIR/COLUMN_DIR pair (V171 has no image), so no oracle in the repo decides it.
- A — map element (x,y): ROW_DIR at x + nX·y, COLUMN_DIR at y + nY·x; an array element (i,j) the same with i as the first MATRIX_DIM number; 3-D ROW_DIR at i + n1·j + n1·n2·k; 3-D COLUMN_DIR refused (R-A2L-DEF.80: no source for its order; 0 tracked 3-D COLUMN_DIR objects — the two tracked 3-D MEASUREMENTs have no LAYOUT, C shapes `:30-41`, `:51-52`). Consequence: rows .106, .107 state the rule the system applies, as Inc 2's D-4 ruling asked for an unverified rule; E3 checks it against the standard if it can.
- B — the reverse reading (ROW_DIR = second index fastest). Consequence: the same rows with the formulas swapped; contradicts the only source read.
- C — refuse 2-D COLUMN_DIR until the standard is read. Consequence: 87 tracked COLUMN_DIR layouts (C shapes `:130-132`) and all 20 case 08 MAPs not editable.
- Recommendation: **A**.

**D-3 · A record that holds fewer points than its maximum (NO_AXIS_PTS / FIX_NO_AXIS_PTS below the point count).** Whether the later components then move up (a compact record) or stay at the offsets of the maximum (a static record, STATIC_RECORD_LAYOUT) is the standard's; I could not read it and 0 tracked files use STATIC_RECORD_LAYOUT. Today the description window reads 8 points when the count says 5 (B line 15).
- A — refuse (R-A2L-DEF.117): only the reading on which both layouts agree (current count = point count) is in. Consequence: 1 tracked object refused at build (`update_test2.a2l` `Curve_InternalAxis_bad_axis_size`, C counts transcript), and any ECU record with a reduced axis; no wrong cell is ever read or written.
- B — the static reading (offsets of the maximum, the first c points used). C — the compact reading. Consequence of B or C: one of them writes values at the wrong bytes when the file means the other.
- Recommendation: **A**; B or C once the standard is read (E3), with a new row each.

**D-4 · Editing a COM_AXIS's points.** A common axis is shared: V171's two COM_AXIS curves and its COM/FIX map read one axis object (R-A2L-DEF.113/1); in software_a, 161 COM_AXIS references (C counts transcript).
- A — read only through the object (R-A2L-DEF.127); the AXIS_PTS object is not a defined object in this increment; editing a shared axis is backlog BL-I3-10. Consequence: one span per encode (I-2 unchanged); Inc 9 shows the axis, edits values only.
- B — the AXIS_PTS object becomes a defined object of a fourth kind (axis), edited by its own name (+ about 6 rows). Consequence: Inc 6 would have to list AXIS_PTS objects, which `a2l.py`'s tag list does not hold (B line 17) — scope for Inc 6.
- C — edit through the curve, the encode giving a second span with a notice naming the other users. Consequence: `Encoded` gains a list of spans; one keystroke changes several objects, which the G2 prototypes have not shown.
- Recommendation: **A** (remove the feature rather than guard it; it can come with the editor round that shows it).

**D-5 · Monotony on an edited axis.** The tracked files use only STRICT_INCREASE (14) and STRICT_DECREASE (2) (C shapes `:76-78`); 42 of the 58 STD_AXIS have no MONOTONY line.
- A — the seven MONOTONY words of CTX-A2L-DEF (*monotony rule*), STRICT_MON when the line is absent, compared on the stored points in point index order (after INDEX_DECR is undone), checked only when the edit changes a point of that axis (R-A2L-DEF.129). Consequence: no edit can make a duplicate or a zigzag axis, whose interpolation the ECU cannot do; an axis read from the image is never refused for its own order; one rule for number and enum axes (an enum point's value is a text).
- B — STRICT_INCREASE when absent. Consequence: a decreasing axis with no MONOTONY line cannot be edited at all.
- C — no rule when absent. Consequence: 42 tracked axes accept duplicates.
- Recommendation: **A**. Assumption flagged: the standard may relate MONOTONY to the physical values; with an increasing conversion both agree, and every tracked axis conversion with a MONOTONY line is IDENTICAL.

**D-6 · The shape of a VAL_BLK with no MATRIX_DIM.** software_a sizes its 101 VAL_BLKs by NUMBER (C shapes `:45-47`); case 08's 60 VAL_BLKs carry only `LENGTH 256` (B line 30).
- A — NUMBER, else the length divided by the datatype size, else (not a whole multiple) the refusal R-A2L-DEF.70. Consequence: both real shapes editable; a LENGTH-only VAL_BLK is read as 1-D.
- B — NUMBER only; LENGTH-only refused. Consequence: case 08's 60 VAL_BLKs (the release demo) not editable; Inc 2's AT-B103-I2-3 "0 refusals on the clean A2L" cannot hold once VAL_BLKs are defined objects.
- Recommendation: **A**.

**D-7 · Alignment from MOD_COMMON.** Batch-56 chose, as a documented under-model, to honour only the ALIGNMENT lines of the record layout, never MOD_COMMON's (`.dev-flow/2026-07-20-batch-56/01-requirements.md:18, :104, :190`), so the tag table sizes V171's STD_AXIS curve at 25 bytes; under MOD_COMMON's `ALIGNMENT_WORD 2` its values would start at byte 10, not 9 (26 bytes). For a reader the difference is a grey length; for an editor it is every value written one byte off. The two readings differ only on the demo files' mixed-size layouts: software_a's MOD_COMMON declares only `ALIGNMENT_BYTE 1`, its 6 multi-component layouts are single-size, and case 08's arrays have one component (`evidence-e1/i3e1-modcommon.txt`; B lines 30-32).
- A — ASAM reading: a component takes the record layout's ALIGNMENT for its class, else MOD_COMMON's. Consequence: V171's STD_AXIS objects editable at offsets 10 / 12; the model's byte length (26) differs from the tag table's (25) until `a2l.py` follows.
- B — batch-56 reading (layout only). Consequence: matches the tag table; if the standard means A, every V171-style record is written one byte off.
- C — refuse when the two readings place a component differently (R-A2L-DEF.89), else use the layout's. Consequence: the 5 V171 STD_AXIS records (and V161's) refused; nothing else in the tracked files or case 08 changes; no wrong byte either way.
- Recommendation: **C** now (neither the standard text nor an image with known values is at hand); A once E3 or the operator confirms the standard, by withdrawing .89 and changing .88.

**D-8 · A STD_AXIS whose record layout holds no AXIS_PTS component (case 08).** Every case 08 CURVE and MAP declares STD_AXIS over the layout `RL_U16` = `FNC_VALUES` only (B lines 31-32), so its axis points are nowhere; every tracked file puts AXIS_PTS_X/Y in the layout of a STD_AXIS (C shapes `:151-164`).
- A — the axis has no points (R-A2L-DEF.100), its point edits are refused (R-A2L-DEF.128), the values are read and edited. Consequence: case 08's 80 curves and maps (the release demo) are editable by value; the bench view shows the point index for such an axis, as the description window does today (B lines 33-34).
- B — refuse the object (A2L-DEF-LAYOUT-AXIS). Consequence: none of case 08's curves or maps editable; Inc 2's AT-B103-I2-3 breaks.
- Recommendation: **A**. Case 08 stays byte-identical (A1 rule 2); the definitions case carries a proper STD_AXIS (R-A2L-DEF.134).

**D-9 · Kinds in and out.** As §1: in VAL_BLK, MATRIX_DIM MEASUREMENT, CURVE, MAP; out CUBOID and beyond (kept as A2L-DEF-KIND), RES_AXIS and CURVE_AXIS (A2L-DEF-AXIS-KIND), ASCII arrays. Enum and bit-masked elements come with the element definition at no extra row (R-A2L-DEF.105/2, /4; 0 tracked uses, C shapes `:165-167`). Recommendation: **as written**.

**D-10 · FIX_AXIS parameters are stored values.** R-A2L-DEF.110 … .112 take the parameters as stored points, converted by the axis's own method like every other axis kind's points. Every tracked FIX_AXIS uses an IDENTICAL method (C shapes `:80-99` with the files' AXIS_DESCRs), so no fixture tells stored from physical. A — stored (one rule for all axis kinds). B — physical (no conversion). Recommendation: **A**; flagged for E3.

**D-11 · Which conversion and count a COM_AXIS uses.** V171's notes say the AXIS_PTS object's conversion "will be overwritten by computation method of AXIS_DESCR" (`ASAP2_Demo_V171.a2l:4091`) and the AXIS_DESCR's count "will be overwritten by max number of axis points of AXIS_PTS" (`:4059`). A — conversion, limits and FORMAT from the AXIS_DESCR (R-A2L-DEF.102), count from the axis object (R-A2L-DEF.94). Consequence: in every tracked file the two conversions are the same name (181 of 181) and the two counts equal (C counts transcript), so A changes nothing there; INLINE cases pin the rule. B — both from the axis object. Recommendation: **A**.

**D-12 · Where the model reads its facts.** As Inc 2's D-2 A: the model reads the RECORD_LAYOUT lines (comments left out, by `a2l.py`'s `_strip_a2l_comments`), the AXIS_DESCR words, the AXIS_PTS sections and MOD_COMMON's ALIGNMENT lines from `a2l_data["sections"]`, and reuses `_walk_record_layout_components` for the offsets on a cleaned layout (components only, in position order, plus the layout's ALIGNMENT lines), `_decode_scalar` / Inc 2's binary16 read, and Inc 2's element decode/encode. It does not reuse `describe_curve_tag`, `_axis_counts_resolving_external`, `_decode_external_axis_points` or `_encode_curve_record_bytes`: each carries a defect an Inc 3 row contradicts (§5). A — as written, the private helpers pinned by Inc 2's D-9 guard test. B — a walker of its own. Recommendation: **A**.

**D-13 · Where the rows go at the fold.** A — S2.7e … S2.7i after Inc 2's S2.7a … S2.7d, all 72 rows (the three synth rows beside Inc 2's in a test-data block, as Inc 2's D-11 A ruled); R-A2L-014, 016, 018, 022 unchanged, with backlog clarifications (§2). B — also rewrite R-A2L-014 and 016 now ("the product of the numbers of its MATRIX_DIM line"), two changed rows that the frozen tag table does not meet. Recommendation: **A** (the same reasoning as Inc 2's D-8 A).

**D-14 · What Inc 3 needs changed in Inc 2's records** (Inc 2 is in E2; I do not edit `../inc-2/`).
- R-A2L-DEF.4's cases /1 (`VAL_BLK_0001`), /2 (`CURVE_0001`), /3 (`MAP_0001`) and /7 (`ASAM.M.MATRIX_DIM_16_1.UBYTE.IDENTICAL`) become defined objects: withdraw them and add V171 `ASAM.C.CUBE_4.ROW_DIR` (`<kind>` CUBE_4, via the B6 salvage of `a2l.py`); its threshold becomes 4/4 (CUBOID, MAP_BLOCK, the vendor kind, CUBE_4). The row's text is unchanged.
- R-A2L-DEF.24/1 (a MEASUREMENT with `MATRIX_DIM 4` and no ECU_ADDRESS → A2L-DEF-KIND): under Inc 3 that object is an array and gets A2L-DEF-ADDRESS; change the input to a CUBOID with no address (kind before address).
- AT-B103-I2-3 ("build and decode every defined object … 0 refusals on the clean A2L"): scope it to the kinds number, enum and text, or decode arrays with I-2's `decode_values` — a single-value decode of an array gives A2L-DEF-ELEMENTS (R-A2L-DEF.120). Inc 3's AT-B103-I3-3 covers case 08's arrays.
- R-A2L-DEF.58/1, /2 ("every defined object … build, decode and encode"): unchanged in effect (the image and payload stay equal), but the single-value calls on arrays now give A2L-DEF-ELEMENTS; Inc 3's R-A2L-DEF.58/arr-1, /arr-2 cover the array calls.
- CTX-A2L-DEF *placeholders*: `<kind>` "… or MATRIX_DIM <n> MEASUREMENT" no longer occurs (such a MEASUREMENT is an array); leave it or drop it.
- Inc 2's *definition* term ("A definition that cannot be edited carries a refusal and every field the system could read") is relied on by R-A2L-DEF.73/8 and .102/1 (fields of a refused definition); E3 may want it as a row (E6: a note says what the system does).
- Recommendation: **apply** at Inc 2's next record pass (E3 corrections), before Inc 2's E4 tests are written.

**D-15 · The definitions case's new objects.** A — as R-A2L-DEF.133 … .135: two COM_AXIS curves on one AXIS_PTS object (layout `NO_AXIS_PTS_X` + `AXIS_PTS_X` INDEX_INCR, both UWORD, the count = the max; LINEAR axis conversion with a ≠ 1), one MAP (STD_AXIS X in its record with `MONOTONY STRICT_INCREASE`, FIX_AXIS Y with FIX_AXIS_PAR_DIST, COLUMN_DIR values, nX ≠ nY ≥ 3), one VAL_BLK (`MATRIX_DIM n1 n2`, n1 ≠ n2 ≥ 2, ROW_DIR, LINEAR, `FORMAT "%.1"`). Single-size components only, so D-7 never applies to the case. Consequence: Inc 9's acceptance tests get one generated fixture with every in-scope array shape; the planned values are the generator's own list, so the case shows the model agrees with the generator, not with the standard (D-2). B — the COM_AXIS curve only (the brief's minimum); .134, .135 withdrawn. Recommendation: **A**.

**D-16 · Exact texts and names proposed by E1.** The 25 refusal codes and their messages (`01-requirements.md`), the house style of Inc 2 (`<name>: …`, an em dash before a hint); element names `<name>[i,j]` and axis point names `<name>.X[k]`, zero-based (R-A2L-DEF.121); `A2L-DEF-LENGTH` reused for arrays with its own message. Recommendation: as written; E3 reviews the texts.

**D-17 · Split.** 72 rows (cap ~80; the PLAN estimate was ~45: the record-layout and axis failure paths are 23 rows of their own) and about 24 graph nodes plus 2 in the synth (`E1-slice.md` §1; cap 40). No split proposed. If the orchestrator wants margin under the cap, the cleanest cut is S2.7f's COM_AXIS rows (.94, .96, .97, .113, .114, .118, .127, .133) into an Inc 3b — at the cost of software_a's 161 COM_AXIS curves (C counts transcript) waiting.

## 4. Interface I-2 extension — PROPOSED ruling

Producer: Inc 3, on Inc 2's I-2 (`../inc-2/E1-rulings.md` §4, accepted). Consumers: Inc 6 (`element_count`, `byte_length`, `kind`, `shape`, read even from a refused definition), Inc 9 (decode and encode by element). No Inc 2 name changes; every new field has a default, so Inc 2's scalar definitions are unchanged.

```text
Definition (Inc 2) gains, with defaults:
    shape: tuple[int, ...] = ()                  () for Inc 2's kinds
    element_count: int = 1
    index_mode: str | None = None                "ROW_DIR" | "COLUMN_DIR"
    values_offset: int = 0                       FNC_VALUES offset in the record
    record_layout: str | None = None
    axes: tuple[AxisDefinition, ...] = ()        X first
    kind gains "array" | "curve" | "map"; byte_length is the record's (R-A2L-DEF.74, .75)
AxisDefinition(                                   frozen dataclass
    letter: str,                    "X" | "Y"
    axis_kind: str,                 "STD_AXIS" | "FIX_AXIS" | "COM_AXIS"
    point_count: int | None,
    points: Definition | None,      the element definition of its points (R-A2L-DEF.102)
    point_order: str | None,        "INDEX_INCR" | "INDEX_DECR" (STD and COM)
    offset: int | None,             AXIS_PTS_<letter> offset in the record (STD)
    count_offset: int | None,       NO_AXIS_PTS_<letter> offset, or None
    fixed_count: int | None,        FIX_NO_AXIS_PTS_<letter>
    fixed_points: tuple[float, ...] | None,   FIX_AXIS (R-A2L-DEF.110 … .112)
    axis_object: str | None,        COM_AXIS: the AXIS_PTS name
    axis_object_address: int | None, axis_object_record: Definition | None,
    monotony: str,                  the rule word, "STRICT_MON" when absent
    has_points: bool)               False for R-A2L-DEF.100
DecodedAxis(letter: str, points: tuple[Decoded | Refusal, ...] | None)    None: no points
DecodedValues(values: tuple[Decoded | Refusal, ...],                       element order
              axes: tuple[DecodedAxis, ...])
Position = tuple[int, ...] | tuple[str, int]       element index, or (letter, point index)

decode_values(definition: Definition, a2l_data: dict,
              image: Mapping[int, int]) -> DecodedValues | Refusal
encode_values(definition: Definition, a2l_data: dict,
              edit: Mapping[Position, str],
              image: Mapping[int, int]) -> Encoded | Refusal       one span: the whole record
element_name(definition: Definition, position: Position) -> str    R-A2L-DEF.121's names
```

- `describe_definition` builds the new kinds; `decode_definition` / `encode_definition` on them give A2L-DEF-ELEMENTS (R-A2L-DEF.120); `display_text` stays the one display rule, applied per element through the element definitions.
- `Encoded` is unchanged: `address` = the record's address, `data` = the whole record (R-A2L-DEF.123), `notices` = the elements' notices (extended limits) with their element names.
- Pure, never raises on file or image content, reads `a2l_data` and `image` only (R-A2L-DEF.58).
- Inc 6 reads `element_count` and `byte_length` for PE-D1 (its own row composes the label); Inc 9 reads `shape`, `axes` and `DecodedValues` for the bench views and builds `edit` from the operator's cells.

## 5. Reuse, and defects found in the reused code

Real callers from `evidence-e1/i3e1-callers-transcript.txt` (C); lines as of `e07fb00`. `a2l.py` is frozen: each defect is a backlog row, wrapped in the model where an Inc 3 row needs it.

| Read or reused | Real callers today | Inc 3 use | Defects (→ backlog) |
|---|---|---|---|
| `describe_curve_tag` (`a2l.py:2993`) | `S19TuiApp.action_a2l_describe_tag` (`app.py:9776`); its text: `render_curve_description` ← `CurveDescriptionScreen.compose` (`a2l_describe.py:70`) | not reused (D-12); its R5 component walk is reused below | **BL-I3-6** INDEX_DECR points shown in memory order (B line 14); NO_AXIS_PTS_X ignored, 8 points read when the record says 5 (B line 15); FIX_AXIS points shown as indexes 0 … n−1 (B lines 19-20); a TAB_VERB axis fails `unsupported conversion type` (B line 21); a MAP is a flattened run, no grid (B lines 21, 34). The description window shows wrong axis points for 3 of the 4 axis forms. |
| `_axis_counts_resolving_external` (`a2l.py:1348`) | `describe_curve_tag` (`:3079`), `extract_a2l_tags` (`:2788`) | not reused | **BL-I3-1** an AXIS_PTS_REF is looked up among the tags (MEASUREMENT / CHARACTERISTIC); AXIS_PTS sections are not tags (B line 17), so 0 of the 181 tracked references resolve (C shapes `:101-103`): every COM_AXIS curve and map has no length and `axes_unresolved` (B lines 16-18; software_a 139 CURVEs + 11 MAPs, B line 22) — no memory check, no point table. |
| `_decode_external_axis_points` (`a2l.py:3254`) | `describe_curve_tag` (`:3172`) | not reused | part of BL-I3-1 (never reached on a real AXIS_PTS); takes the first value component of the referenced layout (`:3280-3283`). |
| `_walk_record_layout_components` (`a2l.py:1538`) | `_record_layout_full_span` (`:1805`), `_resolve_record_layout_components` (`:1740`), `_encode_curve_record_bytes` (`:2280`), `_decode_external_axis_points` (`:3278`) | **reused** on a cleaned layout (D-12) for offsets | **BL-I3-5** `FIX_NO_AXIS_PTS_X` is an unknown component → no record (B line 23): 12 software_a CURVEs `layout_unresolved` (B line 22); RESERVED requires a count word ASAM does not have and fails on a trailing comment (B line 24); **BL-I3-9** line order, not position numbers (`:1614`; 0 tracked layouts out of order, C shapes `:148-149`, latent). |
| `_collect_declared_alignments`, `align_up` (`a2l.py:1476`, `:1437`) | `_walk_record_layout_components` (`:1609`, `:1672`) | through the walk | **BL-I3-8** MOD_COMMON alignment not honoured (batch-56 R-A, a documented under-model; D-7). |
| `_encode_curve_record_bytes` (`a2l.py:2195`) | `encode_physical_to_raw_bytes` (`:2462`) ← `resolve_symbol_entry` (`change_service.py:649`) ← `ChangeService.add_symbol_entry` ← **no product caller** (Inc 2 C) | not reused | **BL-I3-7** writes 0 into NO_AXIS_PTS_X (the record then says it holds no points, B line 25); writes the points in the order given, ignoring INDEX_DECR (B line 25); converts axis points with the object's method, not the axis's (docstring `:2246-2248`); no monotony check (B line 26); COM_AXIS curves refused whole (B line 27). Latent (no caller); HIGH if one appears — Inc 9 must use I-2's `encode_values`. |
| `_inline_axis_counts` (`a2l.py:1277`) | `extract_a2l_tags` walk (`:2744`), `_encode_curve_record_bytes` (`:2275`), `_decode_external_axis_points` (`:3272`) | not reused (the model reads the AXIS_DESCR words itself) | treats FIX_AXIS as an inline axis with in-record points (`_DERIVABLE_AXIS_KINDS`, `:109`), the root of BL-I3-6's FIX index points. |
| `_infer_length_characteristic`, `_infer_length_measurement` (`a2l.py:1187`, `:1164`); MATRIX_DIM read in `extract_a2l_tags` (`:2702-2707`) | `extract_a2l_tags` walk (`:2723`, `:2721`) | not reused (R-A2L-DEF.67 … .76) | **BL-I3-2** MATRIX_DIM keeps its first number: `8 4 2` → length 8 of 64 (B line 9). **BL-I3-3** a VAL_BLK sized by NUMBER, or whose deposit name spells no datatype, has no length: 101/101 software_a VAL_BLKs and V171's (B lines 7, 11). |
| `_resolve_record_layout`, `enrich_a2l_tags_with_values` (`a2l.py:1241`, `:2878`) | Inc 2's census | not reused | **BL-I3-4** the tag table reads a multi-value tag's first element (B line 12; S2 D2-10, R-A2L-047 "No", known) and a curve's datatype from the layout's first datatype word (UBYTE for an SWORD curve, B line 36). |
| `_strip_a2l_comments`, `_flatten_body_tokens`, `_split_line_respecting_quotes` (`a2l.py:353`, `:422`, `:319`) | `_flatten_body_tokens` (`:456`), `assemble_characteristic_header` (`:653`), the AXIS_DESCR capture (`:2729`) | **reused** (D-12) | none found. |
| `_decode_scalar`, `_apply_compu_method` (`a2l.py:1811`, `:1891`) | Inc 2's census | through Inc 2's element decode | Inc 2's BL-I2-7 (FLOAT16), D2-5 (TAB_VERB). |
| `A2LParameterPicker.set_parameters` (`a2l_parameter_picker.py:526`) | `CheckEditorPanel.set_a2l_parameters` (`screens_directionb.py:7303`), `PatchEditorPanel.set_a2l_parameters` (`:5388`) | read only: the PE-D1 cut is `size = int(row.get("byte_size") or 1)` (`:557`), the enriched row's one-element size; Inc 6 replaces it with I-2's `byte_length` / `element_count` | (PE-D1, Inc 6) |

**Backlog rows (ordered by consequence):** BL-I3-7 (curve encode zeroes the axis count and ignores INDEX_DECR; latent, HIGH with a caller), BL-I3-1 (COM_AXIS never resolves: no length, no table, on every tracked COM_AXIS), BL-I3-6 (description window shows wrong points for INDEX_DECR, NO_AXIS_PTS, FIX_AXIS and enum axes), BL-I3-2 + BL-I3-3 (array lengths: memory check on too few bytes or none), BL-I3-5 (FIX_NO_AXIS_PTS / RESERVED in the walk), BL-I3-4 (first element; curve datatype), BL-I3-8 (MOD_COMMON alignment, with D-7), BL-I3-9 (position order, latent), BL-I3-10 (editing a shared axis, D-4). All need an `a2l.py` unfreeze except BL-I3-10.

## 6. Real A2L shapes checked (beyond the synth)

- **Arrays:** 117 VAL_BLK (101 NUMBER-sized, 16 MATRIX_DIM), 226 MATRIX_DIM MEASUREMENTs > 1 value; MATRIX_DIM with 1 to 3 numbers, 197 of them `n 1 1`; 3-D objects: 1 VAL_BLK, 2 MEASUREMENTs; 0 malformed (C shapes `:19-47`).
- **Curves and maps:** 193 CURVE (1 axis each), 25 MAP (2), 4 CUBOID, 2 CUBE_4 (C shapes `:54-58`); axes 182 COM_AXIS, 58 STD_AXIS, 19 FIX_AXIS (17 PAR_DIST, 2 PAR_LIST, 0 FIX_AXIS_PAR), 2 CURVE_AXIS, 2 RES_AXIS (`:60-99`).
- **Layouts:** FNC_VALUES ROW_DIR 91 / COLUMN_DIR 87, all DIRECT; AXIS_PTS INDEX_INCR 62 / INDEX_DECR 6, all DIRECT; FIX_NO_AXIS_PTS_X/Y 25 lines; layout-local ALIGNMENT in 4 software_a layouts; 209/209 layouts in position order (`:111-150`).
- **COM_AXIS:** 181 references to AXIS_PTS sections + 3 dangling (one is `check_test.a2l`), AXIS_DESCR and AXIS_PTS conversions and counts equal everywhere (`:101-107`, counts transcript).
- **Case 08** (generated, not tracked): 60 VAL_BLK (`LENGTH 256` UWORD, no MATRIX_DIM), 60 CURVE (STD_AXIS 32, layout FNC_VALUES only), 20 MAP (8 × 8, COLUMN_DIR, same) per A2L (B lines 30-35).

## 7. What E1 could not check

- The ASAM MCD-2 MC text: ROW_DIR / COLUMN_DIR (D-2, a secondary source read), the compact vs static record (D-3), MOD_COMMON alignment (D-7), FIX_AXIS parameters stored or physical (D-10), MONOTONY on stored or physical values (D-5). Each is a rule the system applies, flagged for E3.
- A tracked image with known array values: none exists (V171 and software_a have none; case 08 is self-consistent with the generator). The ATs prove agreement with the generator and with hand-built images.
- The model itself: it does not exist yet (Inc 2 is in E2), so no pilot ran the proposed rows; the Base column describes the base tree.
- `trace_check.py` on this increment: it needs `04-validation.md` and tests (E5).
- E1 started at 16:22 by the steps.log of the batch; this folder's `steps.log` first line was written at 16:28 (the brief was read first).

## Orchestrator rulings (2026-11-06T18:03:39-06:00, Opus 5.5)

All recommendations accepted: D-1 A (I-2 extension, pinned in `../inc-2/E2-rulings.md`), D-2 A, D-3 A (refuse; a compact-record reading waits for the standard text — backlog), D-4 A, D-5 A, D-6 A, D-7 **C**, D-8 A, D-9 as written, D-10 A, D-11 A, D-12 A, D-13 A, D-15 A, D-16 as written (E3 reviews the texts), D-17 no split.
- **D-14:** Inc 2's records stay as they are for Inc 2's own E4/E5. The R-A2L-DEF.4 case list, .24/1 and AT-B103-I2-3 change in **this** increment: carry them in `01-requirements.md` / `02-test-cases.md` as `changed` (citing the Inc 2 id), and Inc 3's testers update the Inc 2 tests they break.
- The ten `a2l.py` defects (latent curve encode first) join the batch backlog.
- Every ASAM-text point (D-2, D-3, D-5, D-7, D-10) is a rule the system applies; E3 checks each is stated as such.
