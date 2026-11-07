# Inc 10b — Views that follow in-place writes: requirements (E1, split from Inc 10 at E3)

Batch 2026-11-01-batch-101, increment 10b. Records written at base `98d94d7`; E4 starts from main after Inc 6 and Inc 10a are merged (both change `app.py`; 10a goes first). Stage E1 of the design-first flow (`dev-flow-v3-beta`), split from Inc 10 by `../inc-10/E3-rulings.md` (split section).
Decisions: `E1-rulings.md` (history: `../inc-10/E1-rulings.md`, `../inc-10/E3-rulings.md`). Slice: `E1-slice.md` (source files `s19_app/tui/app.py`, `s19_app/tui/segment_split_view.py`). Test cases: `02-test-cases.md`. Graph: `codewire/graph-inc10b.md`. Confirmation runs: `../inc-10/evidence-e1/i10e1-pilot-transcript.txt` (D-4 (a), (b)); E3 probes `../inc-10/E3-security.md` P1 (hex panes) and `../inc-10/E3-architect.md` P4 (tag table cursor and scroll).

Sources: Inc 5 ruling D-4 and its definitions (`../inc-5/E1-rulings.md`, `../inc-5/01-requirements.md`); `../inc-10/E3-rulings.md` rows S-1, A10-04, S-7, A10-09, A10-08, A10-12, S-8; `docs/requirements/review/S2`, `S4`, `S17-ears-strict.md`.

Form column: U = ubiquitous, E = event (`When`), S = state (`While`), N = unwanted (`If … then`). "Base" = what `98d94d7` does, from the pilot or the E3 probe where it says so. Messages are quoted exactly; `<…>` is a placeholder. Rows moved from Inc 10 keep their ids and their text. No row changes a layout; what the operator can notice is in `E1-rulings.md` §1.

## User stories

### US-FRESH-3 — views over the image follow bytes written into it
As the operator, I want the A2L tag table's values, the main, A2L and MAC hex panes and the Split / Join preview and export confirm to describe the image as it is after an apply, a save-back or a Save project commit, without moving what I was looking at, so that I never read a stale value or export against a confirm I gave for other bytes. (Inc 5 ruling D-4 (a), (b), reproduced: `../inc-10/E1-rulings.md` §3; E3 S-1, A10-04, S-7.) **(moved from Inc 10; widened at E3 to the hex panes, the table position and the export confirm)**

## Definitions

- **In-place write** (Inc 5 definition, S9 / S13; scope widened to S2 CTX-A2L, S4 CTX-HEX and S17): a Patch Editor apply (whatever its status), a Patch Editor save-back (whatever its outcome), or a Save project commit that writes the image. The `current_file` object is kept; its bytes change.
- **First shown row** (S2 CTX-A2L, new term): the tag table's top viewport row, the first row painted at the table's scroll position.
- **Highlighted row** (S2 CTX-A2L, canon): the row under the table cursor.
- **Shown window** (S4 CTX-HEX, new term): a hex view's first hex row together with its scroll position (`scroll_x`, `scroll_y`).
- **Fixture three**, **case 08**, **join-fill pick**: as Inc 10 (`../inc-10/01-requirements.md` Definitions). **Guard fixture** (test term): an S19 image of two 8-byte ranges at `0x00000000` and `0x00100000`; Split / Join in join mode, gap fill, pad `0xFF`, both ranges picked (span 1 MiB + 8 B, fill above 50 %: the span guard of R-SEG-EXP.5).

## Requirements

### S2 — the A2L tag table (US-FRESH-3)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-A2L-048 | E | When the system writes bytes into the loaded image in place, the system shall show in the tag table each tag's raw and physical values read from the written bytes. **(new at Inc 10; moved)** | case 08: `VALUE_0001` at `0x00000000` written `6C` → `93`; the tag row's Raw and Physical cells read `147`; 3/3 | the enrichment cache kept across the write → `108` → RED | US-FRESH-3 | No: the row reads `108` / `108` after the apply and a re-show (cache key unchanged; uncached value `147`) |
| R-A2L-049 | E | When the system writes bytes into the loaded image in place, the system shall keep the tag table's first shown row. **(new at Inc 10; moved; threshold amended by E3 A10-04: first shown row defined, a value filter included)** | the table scrolled so the page's row 30 is the first shown row; after the write the first shown row is the same tag, with no filter and with the filter on Raw; 3/3 | the repaint clears and refills the table (`DataTable.clear`) → the first shown row returns to the page's first row (E3 architect P4: `scroll_y` 30 → 0) → RED | US-FRESH-3 | n/a (no refresh today) |
| R-A2L-105 | E | When the system writes bytes into the loaded image in place, the system shall keep the tag table's highlighted row. **(new, E3 A10-04)** | the cursor on the page's row 40 before the write; after it the cursor is on row 40, the same tag, and the detail card names that tag; 3/3 | the repaint clears and refills the table → cursor on row 0 (P4: 40 → 0) → RED | US-FRESH-3 | n/a (no refresh today) |
| R-A2L-106 | E | When the system writes bytes into the loaded image in place, the system shall keep the tags the tag table lists. **(new, E3 A10-04: R-A2L-049 holds with a value filter)** | case 08, filter on Raw with the text `108` (`VALUE_0001` listed): after `0x00000000` = `93` is applied, `VALUE_0001` is still listed, its Raw cell `147`, and the summary's `tags <a>-<b> / <T>` is unchanged; 3/3 | the filter re-run at the write → `VALUE_0001` no longer listed → RED | US-FRESH-3 | n/a (no refresh today) |

### S4 — the hex views (US-FRESH-3)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-TUI-004.7 | E | When the system writes bytes into the loaded image in place, the system shall show the written bytes in the main, A2L and MAC hex views. **(new, E3 S-1)** | fixture three, `0x8013` = `AA` written: the `0x00008010` row reads `FF FF FF AA FF FF FF FF` in `#hex_view`, `#alt_hex_view` and `#mac_hex_view` after keys `1`, `2`, `3`, with no jump after the write; one case per writer (apply, save-back, Save project commit); 3/3 | the hex re-render removed from the write notice → `FF FF FF FF …` → RED | US-FRESH-3 | No: `FF FF FF FF …` in the three panes after keys `1`, `2`, `3`; a forced `update_hex_view()` paints `FF FF FF AA …` (E3 security P1) |
| R-TUI-004.8 | E | When the system shows the written bytes of R-TUI-004.7, the system shall keep each hex view's shown window. **(new, E3 S-1)** | case 08: in each view a go-to `0x00000960` (first hex row `0x00000950`), the pane then scrolled to (x 10, y 40) where it has a horizontal range, else (x 0, y 40) (the A2L and MAC panes at 118 × 54); a Patch Editor apply of the complement of the byte at `0x00000965`: first hex row `0x00000950` and the scroll reached before the write — (10, 40) in the main view, (0, 40) in the A2L and MAC views — in each view; 3/3 **(changed at E5, QA-4)** | the re-render takes the written address as a jump target → the window moves and the scroll resets → RED | US-FRESH-3 | n/a (no re-render today) |
| R-TUI-004.9 | E | When the system shows the written bytes of R-TUI-004.7, the system shall keep each hex view's `> ` marker. **(new, E3 S-1)** | after the go-tos and the apply of R-TUI-004.8: exactly one line starts with `> ` in each view, the `0x00000960` row; 3/3 | the re-render passes a focus address (I-3 clears the marker) → 0 marked lines → RED | US-FRESH-3 | Yes, as the panes are not re-rendered |

### S17 — Split / Join (US-FRESH-3)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-SEG-PREV.21 | E | When the system writes bytes into the loaded image in place while the window is displayed, the system shall show the preview band, the stats line and the state line of the written bytes. **(new at Inc 10; moved)** | fixture three, join-fill pick, `0x8013` = `AA` applied (band `data 8 · fill 11 · conflict 1 · fill 12 · data 8`); `0x8015`, `0x8016` = `BB CC` committed by Save project while displayed → band `data 8 · fill 13 · conflict 2 · fill 9 · data 8`, state `⚠ 2 B would clobber source — abort on export`; 3/3 | the window notice removed → band stays `conflict 1` at `0x8013` → RED | US-FRESH-3 | No: after the commit the band still shows `conflict 1` at `0x8013` and `⚠ 1 B would clobber source …` |
| R-SEG-PREV.22 | E | When the system shows the preview of written bytes (R-SEG-PREV.21), the system shall keep the focus where it is. **(new at Inc 10; moved)** | focused widget before the commit = after it (a widget of the window or the dialog's return focus); 3/3 | the notice calls the window's open refresh (`sje_table` focused) → RED | US-FRESH-3 | n/a |
| R-SEG-EXP.15 | E | When the system writes bytes into the loaded image in place, the system shall disarm the confirm. **(new, E3 S-7 / A10-09)** | guard fixture: `e` arms (state line ends `— e again to confirm`); a Save project commit while the window is displayed → the state line ends `— e will ask` and the next `e` arms again with 0 files written; armed, Esc, a Patch Editor apply, the palette reopens the window → `— e will ask`; 3/3 | the notice keeps the arm (`_sync()` with no disarm) → the `e` after the commit writes the export → RED | US-FRESH-3 | No: the arm survives the commit and the hidden apply; the next `e` writes |

Rows considered and not added: the A2L summary after a write (E3 S-8) — the summary lines read no byte value (`a2l.py:3675-3684`) and `_a2l_summary_start` is 0 on every product path, so the repaint is a consistency step with no observable (`E1-rulings.md` D-10b-3).
