# Inc 7 — A2L Viewer: list of labels — requirements (E1)

Batch `2026-11-05-batch-103`, increment 7. Stage E1 of the design-first flow (skill `dev-flow`, the current flow; it replaces the `dev-flow-v3-beta` the common briefs name). Base `2dbd7d5a` (batch-modular: `s19_app/tui/app.py` is the package `s19_app/tui/app/`); branch `b103-inc7`; line numbers are "as of `2dbd7d5a`". Authority: `../PLAN.md` row Inc 7 (US-103-03), interfaces I-1, I-3, I-4, I-5, amendment A1, backlog note 5; the operator's G2 verdict `../design/G2-verdict-2026-11-12.md` q2 (`q2_av=approve`, `q2_order=reads_right`, from `../evidence/G2/veredicto-b103-r2.json`); the carries of Inc 4 E3 (E3S-01, E3S-04, E3S-05) and Inc 4 E5 round 2 (off-thread ranking, newer keystroke wins; limit ≤ 20, E5S-09). Decisions: `E1-rulings.md` (every one PROPOSED; these rows follow each recommendation). Slice: `E1-slice.md`. Cases: `02-test-cases-L.md`, `02-test-cases-V.md`, `02-test-cases-AT.md`.

**The approved design (DF-04).** The operator approved round 2's scene `av_mix` (G2 page `b103_ux_r2.html`, scene driver `scn_av.py`, variant `av_mix.py` with `_av_common.py`, captures `av_mix.av-{sub,typo,modal,list}.{118,220}.png`). These rows restate what those scenes show; where the scenes leave a case open (hostile input, sizes, threads) a row closes it and `E1-rulings.md` names the decision. The scenes are cited by name only; they live outside the repository and were read, never copied.

**Base column.** What `2dbd7d5a` does today, and how it is known: **R** = read in the code; **B** = a pilot on <runner> (`evidence-e1/i7e1-pilot-transcript.txt` = **P1**, `evidence-e1/i7e1-app-pilot-transcript.txt` = **P2**); **C** = a census (`evidence-e1/i7e1-id-census.txt`). "No" means the behaviour does not exist on base.

**Status.** `new` (family `R-A2L-LIST`, checked unused: `evidence-e1/i7e1-id-census.txt`), `changed` (an existing canon row of `REQUIREMENTS.md`, restated here with its id; the reason is in `E1-rulings.md` §2), `retired` (an existing canon row this increment withdraws).

## User stories

### US-I7-1 — filter the viewer by a list of labels (US-103-03, av_A)
As the operator, I want to paste or type several label names into the A2L Viewer's filter and see one row per name, in my order, marked found, missing, duplicate or hidden, so that I see at once which labels of my list the A2L holds and can jump from the list to the hex view.

### US-I7-2 — build the list in a paste window with live status (US-103-03, av_C)
As the operator, I want a paste window where I paste or add names and see, while I edit, how many are found, which are missing and what names are close to a missing one, so that I can fix the list before it filters the viewer. Nothing is saved (no named label sets).

### US-I7-3 — complete a name by similarity (US-103-03)
As the operator, I want suggestions under the filter box and under the paste window's add line that match the start, middle or end of a name, its words in any order, and forgive a typo, best first, so that I can complete a label without knowing how it begins.

### US-I7-4 — the list and the hex rows readable at 118 columns (US-103-03; PLAN backlog 5)
As the operator, I want the A2L Viewer laid out as the approved scenes show it, so that at 118 columns the list table and each hex row are shown whole.

## Definitions (context note CTX-A2L-LIST, new; terms and formats only)

```text
label-list parser  The batch-102 bulk parser (I-5): new line, carriage return, comma and
                   semicolon become spaces, then the text splits on whitespace; order kept,
                   repeats kept, no empty name.
pasted names       Of a text: the names the label-list parser gives for it, in order;
                   position 1 is the first.
list text          A text whose pasted names number 2 or more (P1 §3: the G2 list -> 12).
list mode          The viewer while the filter text is a list text and the filter field
                   is `name` or `all`.          text mode   The viewer at any other time.
tag name           The `name` of an enriched tag of the current A2L.
entry status       Of a pasted name: found, missing, duplicate or hidden (R-A2L-LIST.002–.005).
glyph              found `●` · missing `✗` · duplicate `=` · hidden `◐`.
status word        found `found` · missing `not in A2L` · duplicate `dup of #<p>` ·
                   hidden `hidden: <mode label>`; mode labels: `All`, `Invalid`, `In-memory`.
found count        The pasted names with the status found or hidden.
counts line        `<n> pasted  ·  ● <f> found  ·  ✗ <m> missing  ·  = <d> duplicate<s>`,
                   <s> = `s` unless <d> is 1; followed by `  ·  ◐ <h> hidden by mode` when
                   <h> ≥ 1 (P1 §3: `12 pasted · 9 found · 2 missing · 1 duplicate`).
ribbon             One glyph per pasted name in pasted order, each followed by a space when
                   2 × <n> fits in the cell budget; at most <budget> glyphs, then ` +<k>`
                   for the rest. Budget: 80 in the viewer, 50 in the paste window.
missing line       `Missing <m> ` + (`▸ #<p> <name>` joined by ` · `, when <m> ≥ 1) + 4 spaces
                   + `Duplicates <d> ` + (`▸ #<p> <name> (= #<q>)` joined by ` · `, when
                   <d> ≥ 1).
display text       Of a name: the name with each character U+0000–U+001F and U+007F–U+009F
                   replaced by U+FFFD, one for one, painted with markup off (I-3 obligations
                   1–2, E3S-04).
short name         Of a name longer than 64 characters: its first 63 characters and `…`.
dropdown           The suggestion box under the filter box (its accept key is tab) or under
                   the paste window's add line (its accept key is enter).
ranked names       Of a text: rank(text, prepared name list, 20) of I-3 (limit 20: I-3
                   obligation 6).
prepared name list The I-3 index of the distinct tag names of one A2L load generation (I-4).
choice             The highlighted row of an open dropdown; the first row when it opens.
rule tag           `<rule>` (exact, prefix, substring, token, subsequence) or
                   `fuzzy · <k> edit` (k = 1) / `fuzzy · <k> edits`.
paste routes       The terminal's paste, Ctrl+V and a right-click with no selection (I-1).
A2L transition     As Inc 5 defines it (attach, image load with an A2L, project install,
                   unload); it ends in the common refresh (R-A2L-REFRESH.001–.005).
```

## Requirements (canon home: S2.5 · The A2L Explorer, new block "List of labels", D-15)

### Resolving a list (US-I7-1, US-I7-2)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-LIST.001 | U | The system shall take as the pasted names of a text the names the label-list parser gives for it. | 3/3: the G2 list (9 lines, commas) → 12 names in order (P1 §3); `A;B  C\r\nD` → `A`, `B`, `C`, `D`; ` ,;\n ` → 0 names | split on new lines only → the G2 list gives 9 names → RED | US-I7-1 | new | No (R: the viewer box keeps one line, R-PASTE.1; the parser exists, `a2l_parameter_picker.py:69`) |
| R-A2L-LIST.002 | E | When the system resolves the pasted names against the current A2L, the system shall give the status found to each first occurrence of a name that equals a tag name, case kept. | 3/3 over case 08: the G2 list → found at #1–#6, #8, #9, #12 (P1 §3); `value_0002` → missing (case kept); `VALUE_0002 ` pasted with a trailing space → found (the parser trims) | case folded → `value_0002` found → RED | US-I7-1 | new | No |
| R-A2L-LIST.003 | If | If a pasted name equals an earlier pasted name, then the system shall give it the status duplicate of the earlier name's position. | 2/2: the G2 list #10 `VALUE_0002` → `dup of #1`; `X X X` (no such tag) → #1 missing, #2 and #3 `dup of #1` | no duplicate check → #10 found → counts `10 found` → RED | US-I7-1 | new | No |
| R-A2L-LIST.004 | If | If a first occurrence of a pasted name equals no tag name, then the system shall give it the status missing. | 3/3: the G2 list #7 `MAP_0024`, #11 `CURVE_0071` → missing; with no A2L loaded every first occurrence → missing | missing treated as found → `11 found` → RED | US-I7-1 | new | No |
| R-A2L-LIST.005 | While | While the viewer's filter mode is not `All`, the system shall give the status hidden to a found name whose tag that mode leaves out of the text-mode table. | 2/2 (P2 §2: case 08 has 0 invalid tags and 402 of 462 in image; P2 §1: the 9 found names of the G2 list are in image): image + A2L, mode `Invalid` → all 9 found names → `hidden: Invalid`; A2L only (no image), mode `In-Memory` → all 9 → `hidden: In-memory` | mode ignored in list mode → `found` → RED | US-I7-1 | new | No |

### The viewer in list mode (US-I7-1)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-LIST.006 | While | While the viewer is in list mode, the system shall show one table row per pasted name, in pasted order. | 3/3: the G2 list → 12 rows, #1 … #12 in pasted order; `CURVE_0017 MAP_0001` typed → 2 rows; field `all` with the G2 list → 12 rows (D-3) | text filter kept → 0 rows (`No A2L tags match …`) → RED | US-I7-1 | new | No (B, P2 §4: today a two-line value is one substring, 0 rows) |
| R-A2L-LIST.007 | While | While the viewer is in list mode, the system shall show `LIST` in the mode tag before the filter box. | 1/1 (the G2 list) | tag left `FILTER` → RED | US-I7-1 | new | No |
| R-A2L-LIST.008 | While | While the viewer is in text mode, the system shall show `FILTER` in the mode tag before the filter box. | 2/2: empty filter; `VALUE` | no tag → RED | US-I7-1 | new | No |
| R-A2L-LIST.009 | While | While the viewer is in list mode, the system shall show the table columns `#`, `Tag`, `Status`, `Kind`, `Address`, `Len`, `Physical`, `Unit` and `Limits`, in that order. | 1/1 at 118×54 (the G2 list) | text-mode columns kept → RED | US-I7-1 | new (D-4 A) | No |
| R-A2L-LIST.010 | While | While the viewer is in list mode, the system shall keep the `#` and `Tag` columns in place under a horizontal scroll. | 1/1 at 80×54, scrolled fully right: the `#` and `Tag` cells of every row painted at the same x as unscrolled | fixed columns 0 → `#` scrolls away → RED | US-I7-1 | new (D-4 A) | No (R: `fixed_columns=2`, `compose_screens.py:697`) |
| R-A2L-LIST.011 | When | When the system shows a pasted name in a list-mode row, the system shall show in its `Tag` cell the glyph of its status, a space and the display text of the name. | 4/4: `● VALUE_0002`, `✗ MAP_0024`, `= VALUE_0002` (#10), `◐ VALUE_0002` (mode In-Memory, no image) | status glyph left out → `VALUE_0002` → RED | US-I7-1 | new | No |
| R-A2L-LIST.012 | When | When the system shows a pasted name in a list-mode row, the system shall show its status word in its `Status` cell. | 4/4: `found`, `not in A2L`, `dup of #1`, `hidden: In-memory` | a fixed word (`found`) → RED | US-I7-1 | new | No |
| R-A2L-LIST.013 | When | When the system shows a found, duplicate or hidden name in a list-mode row, the system shall show in its `Kind` cell the tag's characteristic type, `MEASURE` for a measurement, and the tag's section otherwise. | 3/3 (P2 §1): `VALUE_0002` → `VALUE`, `MAP_0003` → `MAP`, `MEASUREMENT_0005` → `MEASURE` | section always → `CHARACTERISTIC` → RED | US-I7-1 | new | No |
| R-A2L-LIST.014 | When | When the system shows a found, duplicate or hidden name in a list-mode row, the system shall show in its `Address`, `Len`, `Physical`, `Unit` and `Limits` cells the text the text-mode table shows for that tag in its `Address`, `Length`, `Physical`, `Unit` and `Limits` cells. | 9/9: the nine found names of the G2 list at 118×54, each cell equal to the text-mode cell of the same tag (P2 §1: `VALUE_0002` → `0x00000014`, `2`, `347190.0`, `units`, `0..655350`) | `Len` from enriched `byte_size` → `MAP_0003` differs → RED | US-I7-1 | new | No |
| R-A2L-LIST.015 | If | If a list-mode row shows a missing name, then the system shall leave its cells after `Status` blank. | 2/2: `MAP_0024`, `CURVE_0071` | `n/a` painted (R-A2L-006.4) → RED | US-I7-1 | new | No |
| R-A2L-LIST.016 | While | While the viewer is in list mode, the system shall show under the table the summary `LIST  rows <a>-<b> / <n> in pasted order`. | 2/2: the G2 list → `LIST  rows 1-12 / 12 in pasted order`; 250 names, page size 200, page 2 → `LIST  rows 201-250 / 250 in pasted order` | the text-mode summary kept → RED | US-I7-1 | new | No |
| R-A2L-LIST.017 | While | While the viewer is in list mode, the system shall show above the table ` LIST ` and two spaces followed by the counts line. | 2/2: G2 list → ` LIST   12 pasted  ·  ● 9 found  ·  ✗ 2 missing  ·  = 1 duplicate`; mode `Invalid`, image + A2L → `… = 1 duplicate  ·  ◐ 9 hidden by mode` | hidden counted as missing → RED | US-I7-1 | new | No |
| R-A2L-LIST.018 | While | While the viewer is in list mode, the system shall show under the counts line `order ` followed by the ribbon and `   field ignored in LIST mode · esc back to text filter · alt+p edit the list`. | 2/2: G2 list → `order ● ● ● ● ● ● ✗ ● ● = ✗ ● ` + the text; 100 names → 80 unspaced glyphs + ` +20` | no budget → 100 glyphs → RED | US-I7-1 | new | No |
| R-A2L-LIST.019 | While | While the viewer is in text mode, the system shall show above the table ` TEXT `, two spaces, `'<text>' in <field>` or `no text filter`, `  ·  showing <n> of <T>` and `   paste several names, or alt+p, to filter by a LIST`. | 2/2: `VALUE` in name → ` TEXT   'VALUE' in name  ·  showing 208 of 462   paste several names, …`; empty → ` TEXT   no text filter  ·  showing 462 of 462   …` | count of all tags painted as shown → RED | US-I7-1 | new | No |
| R-A2L-LIST.020 | While | While the filter mode is `All`, the system shall show under the filter summary `mode All · no tag hidden by mode (<T> tags)`. | 2/2: list mode and text mode over case 08 → `mode All · no tag hidden by mode (462 tags)` | line left out → RED | US-I7-1 | new | No |
| R-A2L-LIST.021 | While | While the filter mode is not `All`, the system shall show under the filter summary `mode <mode label> · hides <h> of <T> tags  alt+a All`, where <h> counts the tags the mode leaves out with no filter text. | 3/3 (P2 §2): `Invalid` → `mode Invalid · hides 462 of 462 tags  alt+a All`; `In-Memory`, image + A2L → `… hides 60 of 462 …`; `In-Memory`, A2L only → `mode In-memory · hides 462 of 462 tags  alt+a All` | <h> counted with the filter text → RED | US-I7-1 | new | No |
| R-A2L-LIST.022 | While | While the viewer is in list mode, the system shall show the missing line under the mode line. | 2/2: G2 list → `Missing 2 ▸ #7 MAP_0024 · #11 CURVE_0071    Duplicates 1 ▸ #10 VALUE_0002 (= #1)`; a list with no missing and no duplicate → `Missing 0     Duplicates 0 ` | line left out → RED | US-I7-1 | new | No |
| R-A2L-LIST.023 | While | While the viewer is in text mode, the system shall show no missing line. | 1/1 | line kept with `Missing 0` → RED | US-I7-1 | new | No |
| R-A2L-LIST.024 | If | If more than 20 pasted names are missing, or more than 20 are duplicates, then the system shall list the first 20 of that kind in the missing line, followed by ` +<k>` for the rest. | 2/2: 25 missing → 20 listed + ` +5`; 4,906-name hostile paste (P1 §5: 1,636 missing, 2,962 duplicates) → 20 + ` +1616` and 20 + ` +2942` | no cap → 1,636 names in one line → RED | US-I7-1 | new (D-9 A) | No |
| R-A2L-LIST.025 | If | If the filter text matches no tag in text mode with a filter mode other than `All` and matches at least one tag with mode `All`, then the system shall show the summary `No tag matches '<text>' with mode <mode label> — <n> match with mode All alt+a`. | 2/2: `VALUE_0002`, mode In-Memory, A2L only → `… — 1 match with mode All alt+a`; `VALUE`, same → `… — 208 match …` | today's `No A2L tags match 'VALUE_0002'.` kept → RED | US-I7-1 | new (refines R-B102-A2L-003's empty summary for this case, `E1-rulings.md` §2) | No (R: `a2l_view.py:862-867`) |
| R-A2L-LIST.026 | When | When the operator presses alt+a on the A2L Explorer, the system shall set the filter mode to `All`. | 2/2: from `Invalid` and from `In-Memory`, focus in the filter box → mode `all`, `All` marked active (R-A2L-007.9) | binding left out → mode kept → RED | US-I7-1 | new | No (R: no alt+a binding, `Grep Binding\("alt`) |
| R-A2L-LIST.027 | When | When a list-mode row of a missing name becomes the highlighted row, the system shall show in the detail card the lines `✗ <display text>  not in this A2L` and `pasted #<p>`. | 1/1: `MAP_0024` → `✗ MAP_0024  not in this A2L` / `pasted #7` | card cleared (`Highlight a tag…`) → RED | US-I7-1 | new | No |
| R-A2L-LIST.028 | When | When the system has ranked the closest names of the highlighted missing name, the system shall add to the detail card the line `closest <names joined by ' · '>`, or `closest —` when there is none. | 2/2: `VALUE_002` (missing) → `closest VALUE_0020 · VALUE_0021 · VALUE_0022` (P1 §4); `MAP_0024` → `closest —` (P1 §4) | rank with `difflib` → `MAP_0024` lists `MAP_0020` → RED | US-I7-1 | new (D-12 A) | No |
| R-A2L-LIST.029 | When | When a list-mode row of a duplicate name becomes the highlighted row, the system shall show the tag's detail card followed by the line `duplicate of pasted #<p>`. | 1/1: #10 → card of `VALUE_0002` + `duplicate of pasted #1` | line left out → RED | US-I7-1 | new | No |
| R-A2L-LIST.030 | When | When a list-mode row of a hidden name becomes the highlighted row, the system shall show the tag's detail card followed by the line `hidden by the active filter mode`. | 1/1 | line left out → RED | US-I7-1 | new | No |
| R-A2L-LIST.031 | When | When the operator selects a list-mode row of a found, duplicate or hidden name, the system shall show the tag in the hex pane as R-A2L-100, R-A2L-101 and R-A2L-103 say. | 3/3: #3 `MAP_0003` → status `Tag at 0x00804FD0`, hex pane from its row (G2 scene av-list); #10 → `VALUE_0002`'s address; hidden #1 likewise | row key mapped to the pasted position → wrong tag → RED | US-I7-1 | new | No |
| R-A2L-LIST.032 | When | When the operator presses Esc in the filter box while it shows no dropdown and the viewer is in list mode, the system shall clear the filter text. | 1/1: G2 list → filter `''`, text mode, 462 rows | Esc ignored → list kept → RED | US-I7-1 | new | No |
| R-A2L-LIST.033 | When | When a paste route delivers to the filter box a text whose pasted names number 2 or more, the system shall replace the box text with those names joined by `, ` and put the cursor at its start. | 3/3, one per paste route, the G2 list → `VALUE_0002, CURVE_0001, …, VALUE_0118` (P1 §3), cursor 0 | first line kept (R-PASTE.1) → `VALUE_0002` → RED | US-I7-1 | new (D-5 A) | No (R: `os_clipboard_input.py:943`, `:1094` keep the first line) |
| R-A2L-LIST.034 | If | If a text a paste route delivers to the filter box holds unsafe paste characters and 2 or more pasted names, then the system shall remove them before taking its pasted names. | 2/2: `VALUE_0002\x1b[31m\nMAP_0003` → `VALUE_0002[31m, MAP_0003`; `A‮B\nC` → `AB, C` | names taken from the raw text → ESC in the box → RED | US-I7-1 | new | No (R: `_strip_paste_controls`, `os_clipboard_input.py:505`) |
| R-A2L-LIST.035 | When | When the filter box holds a list text of 65,536 characters over an A2L of 13,990 tags, the system shall show the list-mode table, its counts line and its missing line within 1.0 s of the debounce. | median of 3 ≤ 1.0 s on <runner>, `serial_timing`, host load printed (× 2 when `CI` is set: `tests/support/timing.py`), list P1 §5 `software_a` (2,048 names, 683 missing) | resolve each name by a scan of all tags (no map) → 2,048 × 13,990 compares → RED | US-I7-1 | new | No (B, P1 §5: parse + resolve 1.2 ms; the page render is E4's measurement) |
| R-A2L-LIST.036 | When | When the system refits or repaints the tag table while the viewer is in list mode, the system shall keep the list-mode columns and rows. | 3/3: a resize 118 → 80 → 118 columns; a page change (250 names); the Save project commit of R-A2L-048/2 (Inc 12's write route) → the columns of R-A2L-LIST.009 and the rows of .006 after each | the Inc 12 fit rebuilds text-mode cells (`a2l_view.py:1163-1215`, `:1246-1335`) → `Address` cells in the `#` column → RED | US-I7-1 | new | No (R: the fit and the repaint write text-mode cells, `a2l_view.py:1205`, `:1302`) |

### Canon rows this increment changes or retires (US-I7-1, US-I7-4)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-007.1 | When | When the operator stops typing in the filter box for 0.15 s while the viewer is in text mode, the system shall show only the tags whose filter field contains the filter text, ignoring case. | 2/2: `value_00` → the 208 … VALUE names containing it; `cuvre_00` → 0 rows (G2 scene hoy.av-typo) | substring applied to a list text → RED | US-I7-1 | changed (text mode only) | Yes in text mode (R `a2l_view.py:1437-1454`) |
| R-A2L-007.2 | If | If the filter field is `all` while the viewer is in text mode, then the system shall match the filter text against every filter field. | 1/1: `synthetic` in `all` → the tags whose description holds it | list text matched as one text → RED | US-I7-1 | changed (D-3 A: a text with a space is a list in field `all` too) | Yes in text mode |
| R-A2L-007.6 | When | When the operator presses `All` while the viewer is in text mode, the system shall show the tags the filter text selects, whatever their status. | 1/1 | — (unchanged behaviour in text mode; RED control: mode not reset) | US-I7-1 | changed (scope) | Yes |
| R-A2L-007.7 | When | When the operator presses `Invalid` while the viewer is in text mode, the system shall show only the tags whose row is red. | 1/1 | list rows removed instead of marked (R-A2L-LIST.005) → RED in list mode | US-I7-1 | changed (scope) | Yes |
| R-A2L-007.8 | When | When the operator presses `In-Memory` while the viewer is in text mode, the system shall show only the tags that are in image. | 1/1 | as .7 | US-I7-1 | changed (scope) | Yes |
| R-PASTE.1 | When | When the terminal sends a paste into a single-line box, the system shall insert the first line of it at the cursor, except a paste into the A2L Explorer filter box whose pasted names number 2 or more. | 2/2: a two-line paste into the Load box → first line; the same into the A2L filter box → R-A2L-LIST.033 | — | US-I7-1 | changed (D-5 A) | Yes (R `os_clipboard_input.py:926-951`) |
| R-TUI-043.4 | When | When the operator presses Ctrl+V in a single-line box, the system shall insert the first line of the OS clipboard text at the cursor, except in the A2L Explorer filter box when the text's pasted names number 2 or more. | 2/2 as R-PASTE.1 | — | US-I7-1 | changed (D-5 A) | Yes (R `:1038-1104`) |
| R-PASTE.29 | When | When the operator right-clicks a single-line box that shows no selection at the press, the system shall insert the first line of the OS clipboard text at the cursor at the press, except in the A2L Explorer filter box when the text's pasted names number 2 or more. | 2/2 as R-PASTE.1 | — | US-I7-1 | changed (D-5 A) | Yes (R `:953-975`) |
| R-TUI-042a.4 | While | While the viewer is in text mode, the system shall show the Address and Length cells of every tag table row painted whole at every horizontal scroll position. | Inc 12's 82/82 cases, unchanged, in text mode | — | US-I7-1 | changed (D-4 A: list mode keeps `#` and `Tag` fixed, R-A2L-LIST.010) | Yes |
| R-TUI-037.1 | While | While the A2L Explorer is shown, the system shall give the tag table 4/7 of the screen width. — Withdrawn (D-2 A: replaced by R-A2L-LIST.080, .081) | — | — | US-I7-4 | retired | Yes (R `styles.tcss`) |
| R-TUI-037.2 | While | While the A2L Explorer is shown, the system shall give the hex pane 3/7 of the screen width. — Withdrawn (D-2 A: replaced by R-A2L-LIST.080, .081) | — | — | US-I7-4 | retired | Yes |
| R-TUI-069.6 | While | While the A2L Explorer body is 180 columns wide or more, the system shall show the detail card at most 8 lines high, above the hex view. | 1/1 at 220×60: card height ≤ 8, card bottom ≤ hex view top | 5-line cap kept → RED at a 6-line card | US-I7-4 | changed (D-2 A; narrow layout: R-A2L-LIST.080) | Yes in its old form (5 lines) |

### The paste window (US-I7-2)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-LIST.040 | When | When the operator presses alt+p on the A2L Explorer, or its `Paste list…  alt+p` button, the system shall open the paste window titled `Paste a list of labels`. | 2/2: alt+p with the focus in the tag table; the button by click | no binding → nothing opens → RED | US-I7-2 | new | No |
| R-A2L-LIST.041 | When | When the paste window opens while the viewer is in list mode, the system shall fill its text area with the viewer's pasted names, one per line. | 2/2: G2 list → 12 lines; text mode → empty text area | empty text area always (the scene's code) → RED | US-I7-2 | new (D-7 A) | No |
| R-A2L-LIST.042 | When | When the paste window opens, the system shall put the focus in its text area. | 1/1 | focus on the add line → RED | US-I7-2 | new | No |
| R-A2L-LIST.043 | U | The system shall show in the paste window the add line labelled `add` with the placeholder `part of a name — start, middle, end, a typo`, and above the text area the label `or paste names — new line , ; space`. | 1/1 at 118×54 | placeholder text differs → RED | US-I7-2 | new | No |
| R-A2L-LIST.044 | U | The system shall show in the paste window the note `The list filters the viewer (LIST mode, pasted order); nothing is saved. Missing names stay listed so you can fix them.` | 1/1 | note left out → RED | US-I7-2 | new | No |
| R-A2L-LIST.045 | U | The system shall show in the paste window the buttons `Filter viewer by list  alt+f` and `Cancel  esc`. | 1/1 | labels differ → RED | US-I7-2 | new | No |
| R-A2L-LIST.046 | When | When the text area's text has not changed for 0.15 s, the system shall show in the paste window the counts line and, under it, `order ` followed by the ribbon. | 2/2: G2 list pasted → `12 pasted  ·  ● 9 found  ·  ✗ 2 missing  ·  = 1 duplicate` / `order ● ● ● ● ● ● ✗ ● ● = ✗ ● `; 60 names → 50 glyphs + ` +10` | ribbon budget 80 → 60 glyphs → RED | US-I7-2 | new | No |
| R-A2L-LIST.047 | When | When the text area's text has not changed for 0.15 s, the system shall show in the paste window's preview one row per pasted name with the cells `#`, `Name`, `Status`, `Kind` and `Address`, and also `Value` and `Unit` while the A2L Explorer body is 180 columns wide or more. | 2/2: 118×54 → 5 columns, 12 rows (G2 scene av-modal); 220×60 → 7 columns | wide columns at 118 → RED | US-I7-2 | new | No |
| R-A2L-LIST.048 | When | When the text area's text has not changed for 0.15 s, the system shall show the missing line under the preview. | 1/1: G2 list → as R-A2L-LIST.022; the R-A2L-LIST.024 cap applies | line left out → RED | US-I7-2 | new | No |
| R-A2L-LIST.049 | When | When the system has ranked the closest names of one of the first 10 missing names in pasted order, the system shall show under the missing line `  similar to #<p> <short name>: ` followed by those names joined by ` · `. | 2/2: `VALUE_002` at #3 → `  similar to #3 VALUE_002: VALUE_0020 · VALUE_0021 · VALUE_0022` (P1 §4); `value_0002` → `…: VALUE_0002` | each missing name ranked as one query of the whole paste → RED (E3S-01) | US-I7-2 | new | No |
| R-A2L-LIST.050 | If | If a missing name has no ranked name, then the system shall end its similar line with `none (digits must match exactly)`. | 2/2: G2 list → `  similar to #7 MAP_0024: none (digits must match exactly)` and the line of #11 (P1 §4) | line left out → RED | US-I7-2 | new (D-10 A) | No |
| R-A2L-LIST.051 | If | If more than 10 pasted names are missing, then the system shall show after the similar lines `  similar names are shown for the first 10 missing names`. | 2/2: 11 missing → the line; 10 missing → no line | no cap → 11 lines → RED | US-I7-2 | new (D-8 A) | No |
| R-A2L-LIST.052 | If | If the text area's text changes while the closest names of an earlier text are being ranked, then the system shall discard those closest names. | 2/2 with a ranking held in a test seam: text edited before the hold is released → the earlier lines never painted; text unchanged → painted | no stale check → earlier lines painted → RED | US-I7-2 | new (E3S-05) | No |
| R-A2L-LIST.053 | When | When the operator presses alt+f in the paste window or its `Filter viewer by list` button, the system shall close the window and set the viewer's filter text to the window's pasted names joined by `, `. | 2/2: G2 list → viewer in list mode, 12 rows; one name `MAP_0003` → text mode filter `MAP_0003` | names joined by new lines → box keeps one line → RED | US-I7-2 | new | No |
| R-A2L-LIST.054 | If | If the text area holds no name when the operator presses alt+f, then the system shall close the paste window and keep the viewer's filter text. | 1/1: filter `VALUE`, empty text area → filter `VALUE` | filter cleared → RED | US-I7-2 | new | No |
| R-A2L-LIST.055 | When | When the operator presses Esc in the paste window while it shows no dropdown, or its `Cancel` button, the system shall close the window and keep the viewer's filter text. | 2/2: Esc; Cancel; a list typed before each → filter unchanged | apply on Esc → RED | US-I7-2 | new | No |
| R-A2L-LIST.056 | When | When an A2L transition completes while the paste window is open, the system shall resolve the window's pasted names against the current A2L. | 1/1: G2 list open, an A2L holding `MAP_0024` attached → `10 found`, `1 missing` | outgoing statuses kept → RED | US-I7-2 | new | No |
| R-A2L-LIST.057 | When | When the operator presses enter on the add line while its dropdown has a choice, the system shall append the chosen name and a new line to the text area, empty the add line and close the dropdown. | 2/2: `0042 val` → choice `VALUE_0042` appended after `VALUE_0118\n` (G2 scene av-modal); text not ending in a new line → a new line inserted first | appended without new line → `VALUE_0118VALUE_0042` → RED | US-I7-2 | new | No |
| R-A2L-LIST.058 | If | If the operator presses enter on the add line while it shows no dropdown, then the system shall leave the text area and the add line unchanged. | 1/1: `zzzz` (no ranked name) | the typed text appended → RED | US-I7-2 | new | No |
| R-A2L-LIST.059 | When | When the system shows the closest names of a missing name, the system shall leave the text area unchanged. | 1/1: G2 list with `VALUE_002` → text identical before and after the similar lines paint (I-3 obligation 4) | the first closest name replaces the missing one → RED | US-I7-2 | new | No |

### The dropdown (US-I7-3)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-LIST.060 | When | When the filter box's text has not changed for 0.15 s and, stripped, is not empty and not a list text, the system shall open the filter box's dropdown with the ranked names of that text. | 3/3 over case 08 (P1 §2): `0017` → 5 rows, `MAP_0017` first; `cuvre_00` → 8 rows, `CURVE_0001` first; `map_002` → `MAP_0020` first | no dropdown → RED | US-I7-3 | new | No |
| R-A2L-LIST.061 | When | When the add line's text has not changed for 0.15 s and, stripped, is not empty, the system shall open the add line's dropdown with the ranked names of that text. | 1/1: `0042 val` → `VALUE_0042`, `VAL_BLK_0042` (P1 §2) | list-aware check applied → `0042 val` gives no dropdown → RED | US-I7-3 | new | No |
| R-A2L-LIST.062 | If | If the filter box's stripped text is empty or a list text, then the system shall close its dropdown. | 2/2: `0017` then cleared; `0042 val` (a list text, G2 page effect 2) | dropdown kept → RED | US-I7-3 | new | No |
| R-A2L-LIST.063 | When | When the system shows ranked names in a dropdown, the system shall show at most the first 8 of them, one per row, each as `▸ ` for the choice or two spaces otherwise, the display text of the name, and its rule tag. | 2/2: `cuvre_00` → 8 rows, row 1 `▸ CURVE_0001 … fuzzy · 1 edit`; `0017` → 5 rows `… substring` | 20 rows → RED | US-I7-3 | new | No |
| R-A2L-LIST.064 | When | When the system shows a ranked name in a dropdown, the system shall highlight the characters of its match spans. | 2/2: `CURVE_0001` for `cuvre_00` → (0,5), (6,10) highlighted; `MAP_0017` for `0017` → (4,8) (P1 §2) | no highlight → RED | US-I7-3 | new | No |
| R-A2L-LIST.065 | When | When the system shows ranked names in a dropdown, the system shall title it `<k> of <n> similar names`, where <n> is the number of ranked names, written `20+` when it is 20. | 2/2: `0017` → `5 of 5 similar names`; `cuvre_00` → `8 of 20+ similar names` (P1 §2: 60 with no limit) | <n> = <k> → `8 of 8` → RED | US-I7-3 | new (D-6 A) | No |
| R-A2L-LIST.066 | If | If a text has no ranked name, then the system shall title its dropdown `no similar name` and show `nothing matches '<text>'` and `digits must match exactly; a word may have 1–2 typos`. | 2/2: `zzzz`; a 257-character text (R-A2L-MATCH.38) | dropdown closed → RED | US-I7-3 | new | No |
| R-A2L-LIST.067 | U | The system shall end a dropdown with the key line `↑↓ choose  tab complete  esc close` under the filter box or `↑↓ choose  enter add to the list  esc close` under the add line, and the line `rank: exact › prefix › substring › token › fuzzy › subsequence`. | 2/2: each dropdown | key line swapped → RED | US-I7-3 | new | No |
| R-A2L-LIST.068 | When | When the operator presses ↓ or ↑ while a dropdown is open, the system shall move the choice one row down or up, staying within the shown rows. | 3/3: `cuvre_00` ↓ → row 2; ↓ × 9 → row 8; ↑ at row 1 → row 1 | unclamped → no choice → RED | US-I7-3 | new | No |
| R-A2L-LIST.069 | When | When the operator presses tab in the filter box while its dropdown has a choice, the system shall replace the box text with the chosen name, put the cursor at its end and close the dropdown. | 2/2: `cuvre_00` tab → `CURVE_0001`; ↓ tab → `CURVE_0002` | the display text inserted for a name with U+0007 → U+FFFD in the box → RED (I-3 obligation 3) | US-I7-3 | new | No |
| R-A2L-LIST.070 | When | When the operator presses Esc while a dropdown is open, the system shall close it and keep the box text. | 2/2: filter box; add line | Esc clears the box → RED | US-I7-3 | new | No |
| R-A2L-LIST.071 | If | If the box text or the A2L load generation has changed since a ranking started, then the system shall discard its ranked names. | 2/2 with a ranking held in a test seam: `cu` then `cuvre_00` typed before `cu`'s result → only `cuvre_00`'s names painted; an A2L transition before the result → discarded | no stale check → `cu`'s names painted last → RED | US-I7-3 | new (Inc 4 E5 round 2) | No |
| R-A2L-LIST.072 | When | When an A2L transition completes, the system shall prepare the name list of the current A2L's tags off the UI thread. | 2/2: attach case 08 → 462 distinct names prepared on a worker thread (thread id ≠ UI thread); unload → no prepared list | prepared on the UI thread → thread-id assertion RED | US-I7-3 | new (I-4; R-A2L-REFRESH.026) | No |
| R-A2L-LIST.073 | When | When the system ranks a text for a dropdown or for closest names, the system shall rank it off the UI thread. | 2/2: dropdown and closest names → `rank` called on a worker thread | `rank` on the UI thread → RED | US-I7-3 | new (Inc 4 E5 round 2) | No |
| R-A2L-LIST.074 | When | When the prepared name list becomes ready while the filter box has the focus and holds a text that would open its dropdown, the system shall open the dropdown for that text. | 1/1: preparation held in a test seam, `0017` typed, hold released → dropdown with 5 rows | dropdown opened only on the next keystroke → RED | US-I7-3 | new | No |

### Names on every surface of this increment (US-I7-1 … US-I7-3)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-LIST.076 | When | When the system paints a pasted name or a ranked name in the table, the detail card, the counts and missing lines, the paste window or a dropdown, the system shall paint its display text. | 6/6 surfaces with a name holding `[red]`, ESC (U+001B), NUL and U+0085 (a list-mode row; card; missing line; preview row; similar line; dropdown row over an A2L holding such a name): no markup span, 3 U+FFFD, the brackets literal | markup parsed or controls deleted → RED | US-I7-1, US-I7-2, US-I7-3 | new (I-3 obligations 1–2; E3S-04) | No |
| R-A2L-LIST.077 | If | If a name is longer than 64 characters, then the system shall show its short name in the missing line and in a similar line. | 2/2: a 300-character missing name → 63 characters + `…` in both lines; 64 characters → whole | no cap → 300 characters → RED | US-I7-1, US-I7-2 | new | No |

### Layout (US-I7-4; D-2 A)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-A2L-LIST.080 | While | While the A2L Explorer body is less than 180 columns wide, the system shall show the hex pane 14 rows high under the tags pane, with the detail card left of an 86-column hex box. | 2/2 at 118×54 (G2 scene av-list.118): hex pane under the tags pane, its height 14; every painted hex row (81 characters, P2 §3) whole on one line | today's side-by-side panes → the hex view is 42 columns at 118 and 78 at 220, and every hex row wraps in two (P2 §3) → RED | US-I7-4 | new | No (B, P2 §3) |
| R-A2L-LIST.081 | While | While the A2L Explorer body is 180 columns wide or more, the system shall show the tags pane left of a 90-column hex pane. | 1/1 at 220×60 (G2 scene av-list.220) | 4/7 split kept → hex pane wider than 90 → RED | US-I7-4 | new | No |

## Acceptance (black box; `02-test-cases-AT.md`)

Batch-scoped, letter-initial ids outside the registry's authority, checked unused (`evidence-e1/i7e1-id-census.txt`); each drives the real app through keys on case 08 (`firmware.s19` + `firmware.a2l`):
- **AT-B103-I7-1** (US-I7-1): the G2 list is pasted into the filter box by the terminal paste route → list mode, 12 rows in pasted order, the counts and missing lines of the scene; ↓ ↓ enter on #3 → `Tag at 0x00804FD0`; Esc → text mode, 462 rows.
- **AT-B103-I7-2** (US-I7-2): alt+p → the paste window; the G2 list pasted → the counts, preview and similar lines; `0042 val` on the add line, enter → `VALUE_0042` appended (13 names); alt+f → viewer in list mode with 13 rows.
- **AT-B103-I7-3** (US-I7-3): `cuvre_00` typed in the filter box → the dropdown `8 of 20+ similar names`, row 1 `CURVE_0001 … fuzzy · 1 edit`; ↓ tab → box `CURVE_0002`, one row.
- **AT-B103-I7-4** (US-I7-4): the G2 list applied at 118×54 and at 220×60 → the layouts of R-A2L-LIST.080/.081 and every hex row whole.

## Edge cases and hostile input (where they live)

| Case | Rows |
|---|---|
| size: a paste at the I-1 cap (65,536 characters, 4,906 names) | .024 (caps), .035 (time), I-1's cap rows (R-PASTE family, unchanged) |
| many missing names | .024, .051 (first 10 ranked), .052 (off thread, stale dropped) |
| control characters, markup, bidi | .034 (paste strip), .076 (display text) |
| long names | .077; a name over 256 characters ranks to nothing (R-A2L-MATCH.38) → .050 / .066 |
| a name over 1,024 characters or non-ASCII in the A2L | left out of the prepared list (R-A2L-MATCH.39, .43): it is still found or missing by .002, never suggested |
| case variants | .002 (case kept for found); a lowercase miss ranks its tag first (P1 §4) |
| duplicates | .003 |
| no A2L loaded | .004 (all missing); the viewer shows `No A2L tags.` (R-TUI-068.3, unchanged) |
| A2L reload while the list is shown or the window is open | .056, .071, .072; the viewer keeps its filter text across a transition (R-A2L-REFRESH.007) and so stays in list mode |
| depth, paths | n/a — the input is a list of names; no path or nested structure is read |

## Counts

**75 new rows** (R-A2L-LIST.001 … .036, .040 … .074, .076, .077, .080, .081; the numbers .037–.039, .075, .078, .079 are not used), **10 changed canon rows** (R-A2L-007.1, .2, .6, .7, .8, R-PASTE.1, R-TUI-043.4, R-PASTE.29, R-TUI-042a.4, R-TUI-069.6), **2 retired** (R-TUI-037.1, .2): 85 active rows, over the cap of about 80 by 5: `E1-rulings.md` D-0 proposes the split and the recommendation. 1 new context note (CTX-A2L-LIST). 4 black-box cases. PLAN estimate: ~40 rows / ~16 nodes; the growth is the visible text the approved scenes fix (each a message row) and the hostile-input rows.
