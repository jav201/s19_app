# Inc 12 — E1 rulings: the split, canon changes, decisions

Base: product tree `e07fb00` (branch `batch-103`). Rows: `01-requirements.md`. Cases: `02-test-cases.md`. Slice: `E1-slice.md`. Evidence: Inc 11's records named in `01-requirements.md` (sources W, V, F) and `evidence-e1/i12e1-callers-transcript.txt` (X).

## 0. The split

**Authority:** `../inc-11/E3-rulings.md` "Round-2 correction rulings" (2026-11-07T01:16:25-06:00, orchestrator) and PLAN row 12.

**What moved from Inc 11** (each marked `moved (Inc 12)` in Inc 11's records; nothing of its history deleted):
- rows R-TUI-042a.2 (padding; canon row changed at Inc 11's E1, D-1 A) and R-TUI-042a.3 (Tag cap; new at Inc 11's E3 correction, E3A-03 = E3S-01);
- cases R-TUI-042a.2/1, /2, R-TUI-042a.3/1 … /4 and the acceptance case AT-B103-I11-1, here AT-B103-I12-1;
- the "E5 captures" paragraph and the snapshot-baseline regeneration of Inc 11's group G-T2;
- the two `app.py` nodes of Inc 11's graph, `S19TuiApp._compose_screen_a2l` and `S19TuiApp._build_a2l_table_cells` (noted there as Inc 12's; Inc 12 has no graph yet — its E2 draws them).

**What is new here:** R-TUI-042a.4 (E3A-17 = E3S-20, as ruled at round 2: Address and Length the first two columns, fixed, whole at every width from 80 to 220 columns) and R-TUI-042a.5 (the open item: the Tag cell sized from the width left).

**Reason for the split:**
- E3A-17 = E3S-20's row would have been Inc 11's 81st, past the ~80-row bound (`../inc-11/01-requirements.md` header, round 2).
- The view rows live in `app.py`, a file the reader does not need; without them Inc 11 is the reader only (`a2l.py`, `a2l_extract.py`, `a2l_definition.py`), and its round-3 review checks reader items only.
- The view change is visible, so it waits for the operator's approval of real captures before the merge; the reader's rounds need not wait for that verdict.

**Order:** Inc 12 follows Inc 11. The Length cells it paints are the reader's lengths, and the "after" captures are taken on Inc 12 on top of Inc 11.

## 1. Canon rows and notes changed, and new ids

| Row or note | Change | Reason |
|---|---|---|
| R-TUI-042a.2 (S2.5) | canon "The system shall show the tag table with no padding between cells." → "… at least one blank column between adjacent cells of the tag table." — moved from Inc 11 unchanged (its E1 §1) | This row caused the operator's symptom: with no padding the Address and the computed Length paint as one hex string at every width from 80 to 220 [W220 … W80]. |
| R-TUI-042a.3 (new at Inc 11, not yet in the canon) | U → While: "**While the name width of the tag table is 34 cells or more,** the system shall show a tag name wider than 34 cells in the Tag cell as …"; threshold and cases unchanged | With R-TUI-042a.5, the unconditioned row would ask for a 34-cell name where .5 asks for a *w*-cell one (at 80 columns, both would apply to a 48-character name). The two states are complementary, so exactly one row applies. At *w* = 34 both formulas give 16 + `…` + 17, so the boundary is continuous. |
| R-TUI-042a.4 (new) | "The system shall show the Address and Length cells of every tag table row painted whole, as the first two columns of the table, at every horizontal scroll position." | E3A-17 = E3S-20 as ruled. The ruling's sentence "at every width from 80 to 220 columns" is the threshold (F's 40 width × name cases, both scroll positions); the row states the property, and "first two columns" carries the ruled order. **E3 (E3A-08):** the clause "as the first two columns of the table" is dropped; the current text is in `01-requirements.md`. |
| R-TUI-042a.5 (new) | "While the name width *w* of the tag table is less than 34 cells, the system shall show a tag name wider than *w* cells in the Tag cell as its first ⌊(*w* − 1)/2⌋ cells, `…` and its last ⌈(*w* − 1)/2⌉ cells." | The open item of the ruling. With .3 and .4 alone the 38-cell Tag column has 13 cells at 80 and 35 at 118 (64-bit page), so it is cut at the pane edge with no mark [F A N48 W80], [F A N48 W118]. The middle cut keeps .3's reason: names that share a prefix stay distinct by their ends. |
| CTX-A2L-SCREEN, "tag table columns, in order" | Tag, Address, Length, … → Address, Length, Tag, … (the other 13 in their order) | R-TUI-042a.4; R-A2L-006.1 cites this list, so its text stays and its order changes. |
| CTX-A2L-SCREEN, *Address* | "`0x` + 8 uppercase hexadecimal digits" → "`0x` and at least 8 …; an address above 0xFFFFFFFF takes as many digits as it needs, at most 16" | A defect of the note, fixed in place: the code paints `0x{addr:08X}` (R `app.py:20430`), and R-VAL-036 keeps addresses above 0xFFFFFFFF, so `0x1C2D3E004026` is painted with 12 digits (F). The width rule of .4 depends on it. |
| CTX-A2L-SCREEN, new terms | *painted whole*, *width left*, *name width* | Cited by .3, .4 and .5. |

**Id census** (2026-11-07, read-only): `R-TUI-042a.4` occurs only in the finding that proposes it (`../inc-11/E3-architect.md:215`, E3A-17's fix column) and its draft (`../inc-11/evidence-e3/arch-r2-round2-section.md:49`); `R-TUI-042a.5`, `AT-B103-I12-1` and `AT-B103-I12-2` occur nowhere. Searched: `REQUIREMENTS.md` (R-TUI-042a.1 and .2 only, `:798-799`), `docs/requirements/review/`, `C:\Users\jjgh8\Github\s19w\review\` (0 matches for `.4`/`.5`), every `.dev-flow/*/` folder, and `git grep` on `main`, `b101-canon`, `b101-inc9`, `b101-inc10`, `b101-inc11`, `b101-inc12`, `b101-inc12b`, `b101-inc13` … `b101-inc16` (0 matches).

No other canon row changes. Cited and unchanged: see `01-requirements.md` after the table.

## 2. The visible change, and Inc 11's E3S-18 in the same captures

**Visible change (operator approval before the merge):** every row starts with Address and Length; the in-image glyph moves to the third column; one blank column between cells; long names shortened in the middle with `…` (to 34 cells at 118 and wider on a page of 32-bit addresses, 31 at 118 when an address above 0xFFFFFFFF is on the page; at 80 columns to 14 cells, 5 to 9 with such an address); the detail card keeps the full name (**E3 correction, E2-5:** with a vertical scrollbar the widths are 29 cells at 118 when an address above 0xFFFFFFFF is on the page and 12 at 80 columns; `E2-rulings.md`, `01-requirements.md`). The operator approves the before (`e07fb00`) and after (Inc 12 on Inc 11) real Windows Terminal captures at 80, 118 and 220 columns: AT-B103-I12-2.

**Inc 11's E3S-18 in the same captures:** at `e07fb00`, 300 tracked tags have no length and take the layout's element size as their enriched byte size (`../inc-11/evidence-e3/corr2-e3c2-bytesize-transcript.txt`: CURVE 162, MAP 19, CUBOID 4, CUBE_4 2, VAL_BLK 113; 5 files). After Inc 11 (E3S-18: no length → no enriched byte size), the 113 VAL_BLKs gain a length (classes D5, D6) and the other **187 CURVE/MAP/CUBOID/CUBE_4 tags show blank Raw and Physical cells** in the A2L Explorer where the image holds them, until Inc 3a's lengths land. Inc 11's ruling ("shown to the operator with the E5 captures") is met here: AT-B103-I12-2 adds one tracked file holding such a CURVE, and labels that difference as Inc 11's, so the operator can tell which increment makes which change.

## 3. Decisions — PROPOSED, awaiting the orchestrator's ruling

| # | Question | Options | Recommendation and reason |
|---|---|---|---|
| D-1 | How the shortened Tag cell follows the width left | **A** the page is built with the name width *w*, computed from the table's visible width and the page's Address and Length column widths, and rebuilt when the terminal width changes while the A2L Explorer is shown (R-TUI-042a.5/6). **B** a fixed Tag column width and the toolkit's end ellipsis. **C** one narrow fixed cap for every width (e.g. 9 cells). | **A.** B loses the name's end, so names that share a prefix (`ASAM.C.ARRAY.SWORD.MATRIX_DIM_3_4.ROW_DIR` / `….COLUMN_DIR`) look alike: the reason .3 cuts in the middle. C shortens names at 220 columns, where they fit today. A costs one page rebuild (at most 200 rows, `app.py:2809`) per width change; the mechanism (where the resize lands, the cursor kept) is E2's. **Reason restated as measured (E3 correction, E3A-04, `E3-rulings.md`; no floor):** over the 234,648 tracked tags the middle cut keeps names apart for all but 46 at *w* = 34 and all but 293 at *w* = 14, and fails at *w* ≤ 12 (220,359 share a cell; *w* = 12 is the 80-column page with a vertical scrollbar) (E3A [C]). If the operator objects at AT-B103-I12-2, the remedy is layout (Inc 7, PLAN backlog 5), not Inc 12. |
| D-2 | The captures of AT-B103-I12-2 | **A** two states, before (`e07fb00`) and after (Inc 12 on Inc 11), each difference labelled with its increment. **B** three states: `e07fb00`, Inc 11's tip, Inc 12. | **A.** Half the captures (3 widths × 4 files × 2 instead of × 3). Inc 11's tip alone still glues the cells (the padding is Inc 12's), so its captures would show the operator's symptom again beside the blank cells, which helps less than a label. B if the operator asks to see Inc 11 on its own. |
| D-3 | Inc 1b's *row name* is "the text of a table row's Tag column after its leading glyph and the space" (`../inc-1b/01-requirements.md:55`); after .3 and .5 that text may be a shortened name with `…` | **A** an interface note for Inc 1b's E2: the copy takes the tag's full name (the row's tag, `_a2l_row_key_to_tag`), never the painted cell; Inc 1b rewords *row name* as "the tag's name". **B** an Inc 12 row on what a copy takes. | **A.** The copy is Inc 1b's row (R-COPY.4) and file; Inc 12 changes no copy path. The same issue exists since Inc 11's R-TUI-042a.3 (round 1), so the note is due whichever merges first. |

Not decisions (scope, recorded): under a horizontal scroll the Tag column scrolls under the two fixed columns like every other scrolled column (R-TUI-042a.5 holds at scroll position 0; .4 holds at every position); widths under 80 columns are not supported (R-TUI-042a.2 counts 80 as the narrowest); the columns after Tag that do not fit stay cut at the pane edge (Inc 11's BL-I11-3, PLAN backlog 5, Inc 7's layout), and under a horizontal scroll the first scrolled cell is cut on its left under the two fixed columns with no mark, as on `e07fb00` at the pane edge (E3 correction, E3A-05: routed with BL-I11-3 / PLAN backlog 5 to Inc 7 — snap the scroll to column starts, or mark a left-cut cell).

## 4. Tests that change (E4 work)

These read the tag table by position and assume the name in column 0 (R, `git grep` on `e07fb00`):
- `tests/test_tui_a2l_detail.py:206` (`get_row_at(i)[0]` as the name), `:324` (the hostile-name cell at index 0; a hostile name wider than *w* is now shortened, so the assertion on its literal text is re-checked at E4), `:357-364` (TC-067.1: `_build_a2l_table_cells(...)[0]` starts with the glyph);
- `tests/test_validation_service_supplemental.py:179-180`, `tests/test_tui_a2l_issue_recolor.py:185-186`, `tests/test_b102_a2l_refresh.py:137` (`cells[0]` as the name).

Each moves to the column found by its label `Tag` (the idiom of `tests/test_b101_inc11_acceptance.py:510-512`, which finds `Region` by label and is unaffected). `tests/test_b102_a2l_refresh.py:143` reads index 6 (InMem), which the new order keeps (only the first three columns permute). `tests/test_tui_a2l_issue_recolor.py:561-562` reads the Issues table, not the tag table. None of TC-032's protected files (`test_tui_a2l.py`, `test_validation_a2l.py`, `test_validation_engine.py`, `test_color_policy_round_trip.py`) names `#a2l_tags_list`. The 6 `a2l-*` snapshot baselines are regenerated in the canonical CI env (`02-test-cases.md`, E5 evidence).

## 5. Overlaps

- **Batch-101 (A1 rule 3):** no hunk of `b101-inc9` (6 hunks), `b101-inc10` (48), `b101-inc12` (0) or `b101-inc12b` (6) in `app.py` touches the slice's ranges `:8456-8530`, `:8693-8760`, `:10864-10893` or `:20286-20475` (`git diff e07fb00...<branch> -- s19_app/tui/app.py`, hunk headers, 2026-11-07).
- **Inc 10** (`app.py`, the Patch Editor apply and save-back handlers `:4734-5096`, `../inc-10/E1-slice.md`): disjoint.
- **Inc 1b** (`app.py`, copy from the A2L tag table): D-3.
- **Inc 7** (A2L Viewer list filter, `app.py`): owns the narrow-width layout of the other columns (PLAN backlog 5); it starts from this increment's column order.

## Orchestrator rulings (2026-11-07T01:30:38-06:00, Opus 5.5)

D-1 **A** (the name width follows the visible width; the page rebuilds on a resize while the A2L Explorer is shown; middle-cut keeps names that share a prefix apart). D-2 **A** (before = `e07fb00`, after = Inc 12 on Inc 11; each difference labelled with its increment; B only if the operator asks). D-3 **A** (an interface note for Inc 1b's E2: a copy takes the tag's full name, never the painted cell; Inc 1b rewords *row name*) — recorded in `../inc-1b/E1-rulings.md`. The test re-pointing of §4 and the snapshot regeneration are E4 work.
