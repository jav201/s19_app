# Inc 14 — help, legend and README describe the shipped app: requirements (E1)

Batch 2026-11-01-batch-101, increment 14. Base: `b7b77c4` (branch `b101-inc14` = main, Inc 7 and Inc 8 merged). Stage E1 of the design-first flow (`dev-flow-v3-beta`).
Findings: F-16 (≈ CODE-CHANGES D3-19, the map-keys line), F-30, F-37 (= D7-26), F-38 (= D0-9, D0-10, D0-11), F-41 (DOSSIER §5); the P0 ruling "SECURITY.md joins Inc 14"; the user-guide carries BL-I8-3 (Inc 8) and ch21 (Inc 7); the release note of Inc 8 (`../inc-8/release-note-crc.md`); BL-I8-2 (text half). Operator ruling 3 (P0): help or README text that describes absent features is fixed by changing the text. Scope, decisions and reasons: `E1-rulings.md`. Slice (`s19_app/tui/window_help.py`, `s19_app/tui/legend.py`, documents, tests): `E1-slice.md`. Test cases: `02-test-cases.md`. Graph: `codewire/graph-inc14.md`.

Form column: U = ubiquitous, E = event (`When`), S = state (`While`), N = unwanted (`If … then`), O = optional (`Where`). Canon rows are cited by their `REQUIREMENTS.md` id; "new" rows get ids checked absent from the canon and from every batch-101 increment folder at `b7b77c4`. "Base" = what `b7b77c4` does, read in the code unless a file:line is given. No test was run (operator rule for this PC).

No screen layout changes. The only painted text that changes is inside the help window (`?`) and the Memory Map legend sheet (`k`), which operator ruling 3 covers. The Memory Map's inspector subtitle is a screen string and stays out (`E1-rulings.md` D-6).

## User stories

### US-HELP-1 — each help window describes what its window does
As the operator who presses `?` in a window, I want every step of its help to name only keys, controls, folders and behaviour the window really has, written as plain text, so that I can follow the steps without meeting a control that does not exist, a Markdown mark shown as typed, or a design note I cannot open. (F-37 / D7-26: A2L "section tree" and `/` "jumps to a name"; Split / Join "browse" and an editable naming pattern; Checks "table" and "grouped by reason"; CRC "the image's real ranges"; Workspace "folders.html board", "Change 1"; `**…**` and `*why*` shown as typed. F-30: Declared regions "pre-fills from the loaded A2L". F-41: Generate new report "writes the `*.md` + `*.html` pair". BL-I8-2: the Flow Builder's "CRC template" line names a template the CRC block refuses. Requirement ids in the Flow Builder steps.)

### US-LEGEND-1 — the Memory Map legend names the keys the map handles
As the operator reading the Memory Map legend sheet (`k`), I want its key line and its region-row field line to name only what the keys do today, so that I do not press `j`, `k` or Enter expecting to select a region or open the hex view. (F-16: `↑↓ / j k select · … double-click / ↵ open hex`; `j` writes the A2L JSON, `k` opens the legend, Enter inspects.)

### US-README-1 — the README describes the shipped app
As a reader of the README (also the package's long description), I want it to describe the twelve rail windows and Split / Join / Export, every global key, and only commands and files the app provides, so that what I read matches what I run. (F-38 / D0-9 … D0-11: "ten single-context screens, bound to keys `1`–`0`", no `=` / `]` / `Ctrl+Q` / `d` / `c`, "the footer", `flow.json`, Operations "executes the selected one" although two of its three operations are placeholders, a `project.toml` that the tree no longer holds.)

### US-SEC-1 — a security policy says how to report a vulnerability
As someone who finds a vulnerability, I want a `SECURITY.md` that says how to report it privately and which versions get fixes, so that I do not have to disclose it in a public issue. (P0 ruling, D15-18 thread.)

### US-REL-1 — the 1.0.0 release notes state what changed in written results
As the operator upgrading to 1.0.0, I want release notes that state each change of a written CRC value or report and how to keep an earlier CRC value, so that a MISMATCH after the upgrade has a stated cause and a stated remedy. (Inc 8 D-3 / S-8: `release-note-crc.md`; Inc 7: before/after report title and inputs; Inc 8: a later block reads this run's copy of an external output; Inc 7: escaped names in the Markdown file and whole hex windows.)

### US-GUIDE-1 — the user guide describes 1.0.0
As a reader of the user guide, I want the passages about behaviour that batch-101 changed to describe 1.0.0, and the findings table to mark the findings 1.0.0 fixes, so that the guide does not send me to a refusal text, a report title or a workaround that no longer exists. (BL-I8-3; Inc 7 ch21 carry and F-E3-8; Inc 14's own findings.)

## Definitions

- **Help section, help window, key line of a help window.** S7 CTX-HELP. "All sections" = every key of the help sections table, today 12: `patch`, `checks`, `crc_designer`, `reports`, `map`, `flow`, `a2l`, `workspace`, `split_join_export`, `flow_execution`, `check_editor`, `changes_file_notation`.
- **Key token.** A code span (text between two backticks) in a help step that holds one printable character, or `^` and one letter, or one of `esc`, `space`, `enter`, `pgup`, `pgdn`. Base census: `^L`, `^S`, `/`, `j`, `l`, `o`, `p`, `r`, `s`, `U` (B, scan of the sections at `b7b77c4`).
- **Key that acts on a window.** A key of `S19TuiApp.BINDINGS` (shown as the key bar shows it: `^L` for `ctrl+l`), or a key bound by a widget of that window (Split / Join / Export: `space a n t m g f p d e escape`, `segment_split_view.py:1457-1471`).
- **Markdown mark** (for R-WHELP.14; proposed CTX-HELP term, `E1-rulings.md` D-4). `**` or `__` anywhere, or one `*` or `_` directly before and after a word (`*why*`). A code span in backticks is not a Markdown mark: it marks a key, a path or a value as typed, as the key bar does. The fenced example of the `changes_file_notation` section is outside this increment (no window opens that section; D7-11).
- **Reference** (for R-WHELP.13; proposed CTX-HELP term, D-7). A name in a help step that points at a window, a folder, a file, a document, a design change (`change 1`, `change 2`) or a requirement or ruling id (`LLR-003.7`, `R-B102-FILE-001`, `E3 ruling 1`).
- **Help copy I14.** The exact step texts below. They are what the operator reads; each backslash is one character on screen (two in the Python source). `‹` and `›` are the characters U+2039 and U+203A, as in `segment_split_view.DEFAULT_PATTERN`.

### Help copy I14 — A2L Explorer (`a2l`, title `A2L Explorer`, 5 steps)

1. ``Load an A2L (`^L`) to list its tags (measurements and characteristics) in the tag table, each with its address, length, values and the memory region it falls in.``
2. ``Filter tags narrows the table to the tags that match; All, Invalid and In-Memory choose which tags it lists; type in Find in tag table and press Find next to move to the next matching tag; Page Prev and Page Next turn its pages.``
3. ``` `/` puts the cursor in Search ASCII text, the search box of the hex pane: Find Next finds that text in the loaded image's bytes. `g` puts it in Goto 0xADDR: Goto shows that address. ```
4. ``` `d` describes the highlighted tag, with its points for a CURVE or MAP tag. `j` writes the parsed A2L as JSON into the work area's `temp\` folder. ```
5. ``The Region column comes from the A2L's MEMORY_SEGMENT declarations (flash, ram or unknown); the A2L tab of Split / Join / Export lists the same segments.``

### Help copy I14 — Workspace (`workspace`, title `Workspace`, 5 steps)

1. ``Load files with `^L` / `l` — S19/HEX images, A2L, MAC. Loaded artifacts appear in the Loaded panel with their diagnostics.`` (unchanged)
2. ``Save a project (`^S` / `s`) to gather the loaded files into one project folder; load one back with `p`.``
3. ``` `o` opens the work area folder in the file manager; `r` refreshes the file list. ```
4. ``` `U` unloads everything (with per-artifact unload from the Loaded panel). ``` (unchanged)
5. ``Without a project, the files you save stay in the work area's common folders under `.s19tool\workarea\`: change-set and check files in `patches\`, Split / Join / Export files in `splits\`.``

### Help copy I14 — Checks (`checks`, title `Checks`, 6 steps)

1. ``Checks run in the Patch Editor (Run checks on its Checks tab); this window shows the last run, read-only.``
2. ``The top line tallies Pass / Fail / Uncheck. The list groups the entries by outcome: failed, then uncheckable, then passed, each under a header with its count.``
3. ``Click a row, or press Enter on it, to show the bytes around its address in the Hex Peek pane.``
4. ``An uncheckable entry is not a failure: it could not be verified (no image, address outside the image, declaration fault), and its row names the reason. Fix the change document or load the right image.``
5. ``The list shows at most 40 entries; when the run holds more, its last line says so.``
6. ``Run checks again after every edit.``

### Help copy I14 — CRC Designer (`crc_designer`, title `CRC Designer`, 6 steps)

1. ``Pick a preset (e.g. CRC-32/ISO-HDLC); presets are starting points, and every parameter (width, polynomial, init, reflection in and out, XOR out) stays editable.``
2. ``The self-test computes the CRC of `123456789`; it must read MATCH before you trust a custom set.``
3. ``Coverage computes CRCs over the ranges you type in Ranges, in the loaded image: Intra gap and Join gaps choose how gaps are handled, Pad byte is the fill byte, and On conflict chooses what happens when a padded gap holds image bytes. It is a preview; nothing is written.``
4. ``Store placement shows where the CRC would be written (Address, Bytes, Store endianness). The CRC Designer never writes the image; Operations (`x`) writes CRCs from a CRC config.``
5. ``Save writes the algorithm as a template, `<Name>.crc.json`, into the project's `templates\` folder, or without a project into the common `.s19tool\templates\` folder; Load reads the template typed in Load path.``
6. ``Open templates/ opens the folder Save writes to.``

### Help copy I14 — Reports (`reports`, title `Reports`, 6 steps)

1. ``Reports belong to a project — load or save one first (`p` / `^S`).`` (unchanged)
2. ``The list shows the project's `reports\*.md` files, its generated reports newest first; pick one to view it.``
3. ``Filter picks a filter file from the project's `filters\` folder, or takes a typed filter path, to write only part of a report; blank means the full report.``
4. ``Declared regions holds the regions saved with the open project, empty when it has none; add `name,start,end` lines to annotate region coverage in the generated report.``
5. ``Context bytes sets how many bytes of surrounding memory accompany each change in the report.``
6. ``Generate new report writes one Markdown file, `<time>-report.md`, into the project's `reports\` folder; Open reports/ opens that folder.``

### Help copy I14 — Split / Join / Export (`split_join_export`, title `Split / Join / Export`, 8 steps)

1. ``The window exports parts of the loaded image (`^L`). Open it from the palette (`^K`, Split / Join / Export); `esc` closes it.``
2. ``` `t` chooses where the ranges come from: the A2L's MEMORY_SEGMENTs, the image's own contiguous ranges (the default), or manual lines `0xSTART-0xEND` that you type, one per line, end included. ```
3. ``Tick the ranges to export: `space` ticks the highlighted row, `a` ticks all, `n` none. The coverage column warns when a range has no bytes in the image.``
4. ``` `m` switches the mode. Split writes one file per ticked range. Join packs the ticked ranges into ONE file: concat puts them back to back, fill keeps their offsets and pads the gaps between them. ```
5. ``` `g` switches the gaps: in split mode, skip keeps each file sparse and fill pads the holes in each range; in join mode, concat or fill. `p` switches the pad byte between 0x00 and 0xFF. ```
6. ``` `f` switches the format (S19, HEX or BIN) for both modes. `d` switches the destination: project writes into the project's `splits\` folder (the common one when no project is open), common into `.s19tool\workarea\splits\`. ```
7. ``` `e` exports: split writes `‹stem›_‹segment›.‹ext›` per range, join writes one `‹stem›_joined.‹ext›`, where ‹stem› is the loaded image's file name without its extension. The NAMING line shows the name of the first file. ```
8. ``When the export would write a large padded span or an empty file, the first `e` only warns; press `e` again to write.``

### Help copy I14 — Flow Builder (`flow`, 6 of its steps; every other step unchanged)

- Step 1: the base text with ` (LLR-003.7)` removed, so it ends ``… Save… and Load… use the project's `flows\` folder.``
- Step 5: ``CRC — picks a CRC block: it stamps CRCs from a CRC config file.``
- Step 12: ``CRC template — the CRC config file a CRC block reads (the same format as the Operations CRC config); a template the CRC Designer saves is not a CRC config and is refused.``
- Step 17: the base text with ` (R-B102-FILE-001)` removed, so it ends ``… a bold `missing: <name>` names a ref nothing provides.``
- Step 18: the base text with ` (R-B102-FILE-002/003)` and ` (E3 ruling 1)` removed and the double space after the first full stop made one, so it reads ``… the block changes with Add or Save. A temp or loaded file outside the project is copied into the project's `external\` folder first, so the chain can run it; an existing name gets a `-1`, `-2`, … suffix, never an overwrite.``
- Step 19: the base text with ` (R-B102-FILE-004..006)` removed, so it ends ``… and an unreadable file with `External file not readable: <name>`.``

### Legend copy I14 (S3 CTX-LEGEND map sheet; proposed canon change, D-6)

- **Map key line** (`Map keys` box): `↑↓ move · click / ↵ inspect · double-click open hex · Esc close` (63 cells; base `↑↓ / j k select · click inspect · double-click / ↵ open hex · Esc close`, 71 cells). `Esc close` is the legend window's own close key (R-LEGEND-MODAL-001.12).
- **Region-row field line** (`Region row` box): `glyph · start · size · size vs largest · A2L sym · band · ↵ inspect` (67 cells; base `… · ↵ opens hex`, 69 cells). The canon form proposed: `"glyph · start · size · size vs largest · A2L sym · band · ↵ <what Enter does on a region row>"`, today `inspect` (S4 R-TUI-062.3 is open, D4-21).
- **Width budget.** The box interior at the 80×24 floor is 72 cells (`styles.tcss:1739-1746`); both lines fit (R-LEGEND-MAP.4).

### Documents

- **README, window, key.** S0 CTX-README: `README.md`; the twelve rail windows of S6 CTX-SHELL and Split / Join / Export; the keys of S6 CTX-KEYS (26 rows: `Ctrl+K`, `Ctrl+D`, `Ctrl+L`/`l`, `Ctrl+S`/`s`, `/`, `g`, `q`/`Ctrl+Q`, `?`, the 12 rail keys, `U`, `r`, `o`, `p`, `v`, `j`, `d`, `t`, `x`, `k`, `b`, `+`/`-`, `,`/`.`, `PgDn`/`PgUp`, `Ctrl+Z`/`Ctrl+Y`, `c`, `Ctrl+P`).
- **Security policy.** `SECURITY.md` at the root of the repository (GitHub reads it from there).
- **Release notes.** `CHANGELOG.md` at the root of the repository, one `## <version>` section per release, newest first (D-2; proposed CTX-README-like context in S0).
- **User guide.** `docs/user-guide/ch*.md`; its **findings table** is `docs/user-guide/DOSSIER.md` §5.
- **Fixed mark.** The text `fixed in 1.0.0` appended to the Kind cell of a findings-table row.

## Requirements

### US-HELP-1 — help sections (S7)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-WHELP.12 | U | The system shall name in a help section only keys, controls and behaviour its window has. (canon, unchanged) | (a) key tokens: every key token of all sections acts on the section's window, 0 exceptions (base: 0 exceptions, 10 tokens); (b) controls: each control the six rewritten sections name exists in its mounted window, e.g. A2L Explorer 13/13 (`Filter tags`, `All`, `Invalid`, `In-Memory`, `Find in tag table`, `Find next`, `Page Prev`, `Page Next`, `Search ASCII text`, `Find Next`, `Goto 0xADDR`, `Goto`, the `Region` column); (c) 0 of the stale phrases of `02-test-cases.md` R-WHELP.12/3 in all sections; (d) the six sections and the six changed Flow Builder steps equal Help copy I14, 12/12 | restore the base A2L step 1 (`section tree`) → (c) RED; add a step quoting `` `h` `` to the Checks section → (a) RED | US-HELP-1 | Partly: (c) 18 stale phrases (D7-26, F-30, F-37, F-41) |
| R-WHELP.13 | U | The system shall refer in a help section only to windows, folders and files the operator can open from the app. (canon, unchanged; "reference" per Definitions) | 0 references to `folders.html`, `change 1`, `change 2` (any case) or a requirement or ruling id in all sections; every folder the six rewritten sections name is one the app opens or writes (8/8: `temp\`, `.s19tool\workarea\`, `patches\`, `splits\`, `templates\`, `.s19tool\templates\`, `reports\`, `filters\`) | restore the base Workspace step 5 → RED; restore ` (LLR-003.7)` in Flow Builder step 1 → RED | US-HELP-1 | Partly: Workspace `folders.html` and `Change 1`, CRC Designer `change 1`, `change 2`, Reports `change 2`, Flow Builder 5 ids (B) |
| R-WHELP.14 | U | The system shall write help sections without Markdown marks. (canon, unchanged; "Markdown mark" per Definitions) | 0 Markdown marks in all sections except the fenced example of `changes_file_notation` (D-4) | restore `**Pass / Fail / Uncheck**` in the Checks section → RED | US-HELP-1 | Partly: 22 `**` and 1 `*why*` in Checks, CRC Designer, Reports, Split / Join / Export (B) |
| R-WHELP.7 | E | When the system opens a help window, the system shall show the section title, the steps numbered from 1 with no gap, and the key lines, as CTX-HELP shows. (canon, unchanged; in scope as the guard of the re-bodied TC-707 numbering node) | all 12 sections: the body's paragraphs start `1. ` … `N. ` with N = the section's step count, 12/12 | store a number in a step → that section's body reads `1. 1. …` → RED | US-HELP-1 | Yes |
| R-WHELP.18 | U | The system shall state in the Reports help section that Generate new report writes one Markdown file, `<time>-report.md`, into the project's `reports\` folder. **new** (F-41) | Reports step 6 equals Help copy I14 (1/1); the claim holds: one Generate new report in a project adds exactly 1 file matching `^\d{8}T\d{6}Z(-\d{2})?-report\.md$` and 0 `.html` files to `reports\` (1/1) | restore the base step 6 (`*.md` + `*.html` pair) → /1 RED | US-HELP-1 | No: "writes the `*.md` + `*.html` pair" (`window_help.py:197-199`); the generator writes Markdown only (`report_service.py:494`, `:1399-1403`) |
| R-WHELP.19 | U | The system shall state in the Reports help section that the Declared regions box holds the regions saved with the open project. **new** (F-30) | Reports step 4 equals Help copy I14 (1/1); the claim holds: a project saved with 2 declared regions, loaded again, opens the Reports dialog with those 2 lines in Declared regions (1/1), and a project with none and an A2L loaded opens it empty (1/1) | restore the base step 4 (`pre-fills from the loaded A2L`) → /1 RED | US-HELP-1 | No: "pre-fills from the loaded A2L" (`window_help.py:192`); the box is seeded from the manifest only (`app.py:14032-14036`, `screens.py:3302-3308`) |
| R-WHELP.20 | U | The system shall state in the A2L Explorer help section that `/` puts the cursor in the search box of the A2L Explorer's hex pane. **new** (F-37, D7-26) | A2L step 3 equals Help copy I14 (1/1); the claim holds: `/` on the A2L Explorer focuses `#alt_search_input` (placeholder `Search ASCII text`) (1/1) | restore the base step 2 (`find (/) to jump to a name`) → /1 RED | US-HELP-1 | No: "Use find (`/`) to jump to a name; the tree highlights matches" (`window_help.py:340-341`); `/` focuses `#alt_search_input` (`app.py:9353`), which searches the image's bytes (`app.py:20611-20640`) |
| R-WHELP.21 | U | The system shall state in the Split / Join / Export help section that the window exports parts of the loaded image. **new** (F-37) | step 1 equals Help copy I14 (1/1); the claim holds: with `firmware.s19` loaded the ranges source lists that image's ranges (1/1) | restore the base step 1 (`a project file, or browse to one`) → /1 RED | US-HELP-1 | No: "Pick the source image: the loaded file, a project file, or browse to one" (`window_help.py:368-369`); the window reads `current_file` only (`segment_split_view.py:1539-1552`) |
| R-WHELP.22 | U | The system shall state in the Split / Join / Export help section that split writes `‹stem›_‹segment›.‹ext›` per range and join writes one `‹stem›_joined.‹ext›`. **new** (F-37) | step 7 equals Help copy I14 (1/1); the claim holds: loaded `firmware.s19`, format s19, split with `range_00` ticked → the NAMING line ends `firmware_range_00.s19`; join → `firmware_joined.s19` (2/2) | restore the base step 6 (`the naming pattern. The sample filename updates live`) → /1 RED | US-HELP-1 | Partly: the names are right; step 6 offers a naming pattern to set, but `_pattern` is the constant `DEFAULT_PATTERN` (`segment_split_view.py:163`, `:1488`; no setter) |
| R-WHELP.23 | U | The system shall state in the Checks help section that the list groups the entries by outcome: failed, then uncheckable, then passed. **new** (F-37) | step 2 equals Help copy I14 (1/1); the claim holds: a run with 1 pass, 1 fail, 1 uncheckable renders the group headers in the order FAILED, UNCHECKABLE, PASSED (1/1) | restore the base step 2 (`Grouped view clusters failures by reason`) → /1 RED | US-HELP-1 | No: "the table lists every entry … Grouped view clusters failures by reason" (`window_help.py:150-152`); groups are by outcome (`checks_view.py:57`) |
| R-WHELP.24 | U | The system shall state in the CRC Designer help section that coverage computes its CRCs over the ranges typed in Ranges. **new** (F-37) | step 3 equals Help copy I14 (1/1); the claim holds: Ranges `0x00008000-0x00008008` over an image that maps 0x8000 … 0x8010 gives the concat CRC of exactly those 8 bytes (1/1) | restore the base step 3 (`over the image's real ranges`) → /1 RED | US-HELP-1 | No: "Coverage computes CRCs over the image's real ranges" (`window_help.py:170`); the ranges are the typed field (`crc_designer_view.py:374-379`) |
| R-WHELP.25 | U | The system shall state in the Flow Builder help section that the CRC template field names the CRC config file a CRC block reads. **new** (BL-I8-2, text half) | Flow Builder step 12 equals Help copy I14 (1/1); the TC-B97-32 flow arm still finds one `CRC template — …` line (1/1) | restore the base step 12 (`the CRC configuration a CRC block stamps`) → /1 RED | US-HELP-1 | Partly: "the CRC configuration a CRC block stamps" names no file kind; the block reads a CRC config file (R-FLOW-CRC.1) |
| R-WHELP.26 | U | The system shall state in the Flow Builder help section that a CRC block refuses a template the CRC Designer saves. **new** (BL-I8-2; R-CRC-CONFIG-001.16) | Flow Builder step 12 holds `a template the CRC Designer saves is not a CRC config and is refused` (1/1); the claim holds: a CRC block naming a Designer template stops the flow with a cause that contains `a CRC Designer template is not a CRC config - it has no regions or groups` (1/1, Inc 8's R-FLOW-CRC.4/1) | delete the clause → /1 RED | US-HELP-1 | No: no help line says so (B) |

### US-LEGEND-1 — the Memory Map legend sheet (S3, S4)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-TUI-062.10.1 | U | The system shall name in the Memory Map's key line only keys that the Memory Map handles. **changed** (split of R-TUI-062.10, E7; `.10.2` inspector subtitle and `.10.3` row glyphs are recorded in `E1-rulings.md` §2) | the key line equals Legend copy I14 (1/1); each action it names is the handled one: ↑/↓ on a region row move the focus to the next / previous row and leave the inspector's region unchanged (2/2), Enter and a single click inspect (post `Activated(chain=1)`, 2/2), a double click opens the Workspace hex view at the region start (1/1) | restore the base line → /1 RED; make Enter post `chain=2` (open hex) with the new line kept → /2 RED | US-LEGEND-1 | No: `j k select` (`j`, `k` are not consumed by the row and reach `dump_a2l_json` / `show_legend`, `screens_directionb.py:1457-1490`, `app.py:2692`, `:2699`) and `↵ open hex` (Enter posts `Activated(chain=1)`, inspect, `screens_directionb.py:1481-1486`) |
| R-LEGEND-011 | U | The system shall show the legend rows of CTX-LEGEND. (canon, unchanged; in scope for the map sheet's region-row field line only, CTX-LEGEND's map sheet changed per Legend copy I14, D-6; the A2L, MAC and Issues rows of D3-19 stay out, D-10) | the map sheet shows the region-row field line of Legend copy I14 (1/1) and both changed lines measure ≤ 72 cells (2/2) | restore `↵ opens hex` → /1 RED | US-LEGEND-1 | No for the field line: `↵ opens hex` (`legend.py:484-486`). Partly for the rest (D3-19), unchanged by this increment |

### US-README-1 — the README (S0)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-DOC-README.2 | U | The system shall describe each window of CTX-README in its README. (canon, unchanged) | one `### <window>` section per window, 13/13 (the 12 rail windows by their rail labels, and Split / Join / Export); the rail table lists the 12 rail windows with their CTX-SHELL keys in rail order, 12/12 | delete the `### Check Editor` section → RED | US-README-1 | No: 10 windows and keys `1`–`0` (`README.md:81-95`); no Check Editor, Flow Execution, Split / Join / Export |
| R-DOC-README.3 | U | The system shall list each key of CTX-README in its README with its action. (canon, unchanged) | each of the 26 CTX-KEYS rows has a README table row naming its key(s) and a non-empty action, 26/26 (base 21/26); every single-key cell of a README key table is a key the app binds (test_at285, extended per D-9) | delete the `` `c` `` row → RED; add a row for an unbound key `` `h` `` → test_at285 RED | US-README-1 | No: `=`, `]`, `Ctrl+Q`, `Ctrl+P`, `d`, `c` missing (D0-10; `Ctrl+P` is listed although D0-10 says not to, D-11) |
| R-DOC-README.4 | U | The system shall describe in its README no window, key, command or file that the system does not provide. (canon, unchanged) | 0 of the 11 stale claims of `02-test-cases.md` R-DOC-README.4/1; every document and folder the README links exists in the tree (all links); the Operations section names `extract` and `split_by_segment` as listed but not implemented (1/1) | restore "ten single-context screens" → /1 RED; restore the `project.toml` bullet → /1 RED | US-README-1 | No: 11 stale claims (B) |

### US-SEC-1 — security policy (S0)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-DOC-SECURITY.1 | U | The system shall include a `SECURITY.md` that gives a private path to report a vulnerability. **new** | `SECURITY.md` exists at the repository root (1/1) and names GitHub private vulnerability reporting (the repository's Security tab, Report a vulnerability) as the path (1/1); the path is open: `gh api repos/<owner>/<repo>/private-vulnerability-reporting` returns `"enabled":true` (1/1, evidence at E5 after the operator's setting, D-1) | delete `SECURITY.md` → RED | US-SEC-1 | No: no `SECURITY.md`; private vulnerability reporting `"enabled":false` (probe 2026-11-05) |
| R-DOC-SECURITY.2 | U | The system shall state in its `SECURITY.md` which versions receive security fixes. **new** | a table names `1.0.x` as receiving fixes and every earlier version (0.x and the 1.0.0 release candidates) as not (2/2 lines) | delete the table → RED | US-SEC-1 | No |

### US-REL-1 — release notes (S0)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-DOC-RELNOTE.1 | U | The system shall state in the release notes of 1.0.0 that a CRC config with `reverse` true starts the CRC register at `init` as written. **new** (Inc 8 D-3, S-8) | the `## 1.0.0` section of `CHANGELOG.md` holds the "What changed" and "Am I affected?" text of `../inc-8/release-note-crc.md` (2/2 paragraphs) and its example `0x18026B2A` → `0x0F8B7431` (1/1); the example is true: the Operations CRC engine over `123456789`, poly `0x04C11DB7`, init `0x12345678`, reverse true, final_xor `0xFFFFFFFF` gives `0x0F8B7431` (1/1) | write `0x18026B2A` as the 1.0.0 value → /2 RED | US-REL-1 | No: no release notes |
| R-DOC-RELNOTE.2 | U | The system shall state in the release notes of 1.0.0 how to keep the CRC value that an earlier version gave for a config with `reverse` true. **new** | the section holds "How to keep the earlier value" with the example `0x12345678` → `0x1E6A2C48` (1/1); the example is true: `0x1E6A2C48` is `0x12345678` with its 32 bits reversed (1/1), and the 1.0.0 engine with init `0x1E6A2C48` gives the earlier value `0x18026B2A` (1/1) | write the init unreversed in the remedy → /2 RED | US-REL-1 | No |
| R-DOC-RELNOTE.3 | U | The system shall state in the release notes of 1.0.0 that the before/after report is titled `Before/after report` and names the loaded A2L and MAC. **new** (Inc 7 F-42) | the section holds the title `Before/after report` and the two consequences (artifact lines `a2l=used …`, Symbols column filled from the loaded A2L and MAC) (3/3) | write `Diff report` as the before/after title → RED | US-REL-1 | No |
| R-DOC-RELNOTE.4 | U | The system shall state in the release notes of 1.0.0 that a later flow block reads this run's copy of an external step's output. **new** (Inc 8 F-49) | the section holds the rule and the read suffix ` · read <copy file name> in place of <ref>` (2/2) | write "the first copy" → RED | US-REL-1 | No |
| R-DOC-RELNOTE.5 | U | The system shall state in the release notes of 1.0.0 that the Markdown file of a diff report writes a backslash before each Markdown character of a name or a path. **new** (Inc 7 US-MDESC-1, F-E3-8) | the section holds the rule, the example `CAL\_A`, and that a plain-text search of the `.md` for `CAL_A` no longer matches (3/3) | delete the search consequence → RED | US-REL-1 | No |
| R-DOC-RELNOTE.6 | U | The system shall state in the release notes of 1.0.0 that a diff report file holds every hex window whole. **new** (Inc 7 F6-1, R-CMP-004.14) | the section holds the rule and the earlier 512-row cut (2/2) | write "limited to 512 rows" as the 1.0.0 behaviour → RED | US-REL-1 | No |

### US-GUIDE-1 — user guide (S0)

| Id | Form | Requirement | Threshold | Negative control | US | Base |
|---|---|---|---|---|---|---|
| R-DOC-GUIDE.1 | U | The system shall describe in its user guide no behaviour that the system does not provide. **new** | the 11 passages of `02-test-cases.md` R-DOC-GUIDE.1/1 … /11 describe 1.0.0: each passage's stale phrase absent and its 1.0.0 phrase present (11/11); a capture taken before 1.0.0 beside a changed passage carries the note `(capture taken before 1.0.0)` (4/4: ch06-05, ch17-05, ch19-01, ch21-02; D-5) | restore `CRC config is structurally invalid: 'reverse'` in ch17.5 → /4 RED | US-GUIDE-1 | No: 10 stale passages and 1 missing (the `.md` escaping consequence of Inc 7, F-E3-8) (B) |
| R-DOC-GUIDE.2 | U | The system shall mark each row of the user guide's findings table that 1.0.0 fixes with `fixed in 1.0.0`. **new** | rows F-16, F-28, F-30, F-37, F-38, F-41, F-42, F-49 carry the fixed mark (8/8); no other row carries it (0) | mark F-43 (a limitation, deferred) → /2 RED | US-GUIDE-1 | No: no row is marked |

Rows split or changed in the canon, and every id proposed new: `E1-rulings.md` §2, for the requirements session.
