# S10 — Patch Editor: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S10 (lines 3770–4570): 21 primary rows (R-TUI-027, R-CDFX-016, R-CHG-004, R-PATCH-PASTE-001, R-PATCH-WRITE-REUSE-001, R-PATCH-DOC-DROPDOWN-001, R-PATCH-CHECKS-CLARITY-001, R-PATCH-2X2-LAYOUT-001, R-PATCH-2X2-SNAPSHOT-001, R-PATCH-VARIANT-SELECT-001, R-TUI-045, 046, 049, 052, 053, 054, 056, 057, 058, 063, 064) and four batch-48 amendment records (border title, C-17 observation point, paste-gauge hue, chip buttons). The screen the code shows today is the batch-94 / batch-97 redesign, whose text sits in S0's table (HLR-005 … 008, HLR-144, HLR-161, and the Patch Editor parts of HLR-148, 149, 157); it is absorbed here.
Code: `screens_directionb.py::PatchEditorPanel` (except the two S9 check methods), `BeforeAfterCard`, `before_after_card_text`, `PatchDocumentView`, `json_stamp_text`, `patch_layout`, `cap_json_lines`, `clip_param`, `clip_tail`; `services/change_service.py` (except the check half, S9); `json_highlight.py`; the S10 functions of `app.py` (`_compose_screen_patch`, `on_patch_editor_panel_action_requested`, the undo/redo, Edit JSON, change-file and load handlers, `_patches_dir`, `_change_doc_save_home`, `_scan_patch_change_files`, `_patch_document_view`); the `#patch_editor_panel` section of `styles.tcss`. Every fact read from the code with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: rows and cites in S10.2 (the dropdown and the unsaved-changes popup), S10.3 (the dirty flag) and S10.8 (the busy refusal) and R-PE-102 in S10.9 verified at 570b4b5; the other S10 handlers changed only by the busy check (D10-47) and keep their cells; other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-PE, CTX-PE-DOC, CTX-PE-INPUT, CTX-PE-LEDGER, CTX-PE-STRIP, CTX-PE-JSON.
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; visual changes marked **prototype first**.
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Change-document format, apply and save-back rules stay S8's and are cited, not rewritten. Code changes: `cc-S10.md` (scratch backlog). Nothing is changed in the code.

---

## 1. How S10 was written before

- The chapter is a layer cake of batches 03 … 48. Each batch added a row for its increment, and later batches marked earlier rows superseded or amended instead of rewriting them. Four rows are history only (R-TUI-027, R-CDFX-016, the two 2×2 rows); two describe a variant selector that batch-94 removed (R-PATCH-VARIANT-SELECT-001, R-TUI-056); three describe a three-window layout that batch-97 replaced (R-TUI-045, 063, 064).
- Rows are paragraphs: widget ids, CSS (`grid-size: 2 3`, `1fr 2fr 2fr auto`), message classes, test censuses ("15-id census", "C-26"), git commits (`febd843`, `19bf1eb`), and validation gates sit inside the requirement sentence.
- About 230 of the 800 lines are batch-48 amendment records: why an oracle was constant-true, a hue census table, a "flank rule" for a colour. They record the method, not the product.
- The current screen (ledger + inspector, dirty-load guard, Refresh as folder rescan, hex Bytes field) is written only in S0's HLR table.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-TUI-027, R-CDFX-016, R-PATCH-2X2-LAYOUT-001, R-PATCH-2X2-SNAPSHOT-001 | Superseded rows kept "for history", with retired test ids. | Out (D10-1). |
| R-TUI-063, 064, 045, 046 | Three bordered windows, 3-across at 120 columns and stacked below. The code shows one ledger beside one inspector with tabs, at every width (`screens_directionb.py:4903-4936`, `styles.tcss:2711-2735`). | Layout rows follow the code (S10.1, D10-3). |
| R-PATCH-VARIANT-SELECT-001, R-TUI-056 | A variant dropdown and a variant help modal. Batch-94 HLR-006 removed both; the code composes neither. | Out (D10-4). |
| R-TUI-052 | "Refresh re-reads the loaded file from disk." Since batch-94 (HLR-008) Refresh rescans the folder and leaves the document alone (`app.py:3524-3534`). | Row follows the code (R-TUI-052.1 … .3). |
| R-TUI-054 | Section title `Change document (JSON)`. The title is now the ledger's border title `PATCH SCRIPT`. | Row follows the code (R-TUI-063.7). |
| R-PATCH-CHECKS-CLARITY-001 | Quotes a one-sentence help text; the shipped text has three more sentences (`screens_directionb.py:5155-5160`). | Full text (R-PATCH-CHECKS-CLARITY-001.2). |
| R-CHG-004 | "routing exactly nine actions … through the consolidated `ChangeService`": design. "faults remain visible until the document is re-validated clean": Validate refreshes only collision findings; read-time findings stay for the document's life (`change_service.py:1706-1713`). | Observable rows; what Validate replaces is S8's R-CHG-VAL.1. |
| R-PATCH-PASTE-001 | Most of the row is a parser refactor (`read_change_document` delegates to `parse_change_document` "exactly once"). | Parse rules are S8's; S10 keeps what the operator sees. |
| R-PATCH-WRITE-REUSE-001 | "No new write surface", proven by `git diff febd843`: a process gate. | The observable equality stays (D10-8). |
| R-TUI-057, 058, 053 | "A-01 data-loss guard": Undo, Redo and per-entry Edit JSON are disabled for a file-loaded document, but Add, Edit and Remove still change it, so those changes cannot be undone. Only whole-set Edit JSON has the stated risk (its seed is the paste buffer, not the document). | D10-23. |
| (S0 HLR-005) | The unsaved-changes guard covers the Load button only. Picking a file in the dropdown loads at once (`app.py:5664-5674`). | D10-20. |
| (S0 HLR-141) | "y desde el Patch Editor": the symbol input and Symbol column were never built, and the Patch Editor reads documents without the loaded A2L, so every symbol entry is skipped (`app.py:3516`, `:5691`). | Reading with the loaded A2L: S8 R-CHG-SYM.9 (D8-22). The input: D10-42. |

---

## 3. Context notes (informative)

### CTX-PE · The Patch Editor screen (S10.1)

```text
Patch Editor    Rail screen. Header "Patch Editor" with the ? chip and the
                📂 Open patches/ chip (S5, S7). Top to bottom: the identity ribbon;
                the ledger (border title PATCH SCRIPT) beside the inspector; the
                file row; the document row; the legend.
identity ribbon <file name> · <kind> for a file-backed document;
                draft · <kind> for a draft.
inspector       Tab chips Inspector, JSON and Checks over one pane. Border title:
                INSPECTOR, JSON or CHECKS, after the shown tab.
  Inspector     The before → after strip (border title BEFORE → AFTER); the entry
                form (Address, String, Bytes); Add, Edit, Remove, Edit JSON (per
                entry); the tally.
  JSON          LOADED DOCUMENT · read-only, the JSON stamp, the read-only JSON view;
                the paste heading and the paste gauge, the paste buffer, Parse
                pasted, Edit JSON; the history strip, Undo, Redo; Execute over
                variants (scope button, Execute scope, scope line); the save-back
                prompt and the before/after control (hidden until revealed).
  Checks        The findings list, the check status, the patch strip and the result
                rows (S9.2), Run checks and its help.
file row        File: the dropdown (prompt "Change files in patches/"), the path
                input, Load, Refresh.
document row    Validate, Apply loaded changes, Save.
legend          ✓ check passed   ✗ check failed   ◐ uncheckable   · not checked   -- byte not in the image
save-back prompt  S8 CTX-SAVEBACK. It sits in the JSON tab, hidden until an apply
                reveals it.
before/after control  "Before/after report available:" and Write before/after report.
scope labels    active variant · all variants · per assignment (cycle order).
```

### CTX-PE-DOC · The document (S10.2 … S10.8)

```text
document        The one change document (S8) the Patch Editor edits.
file-backed     The document was read from a file (Load, the dropdown); the file is
                its source.
draft           Any other document: the empty one at start, a parsed paste, and
                edits of those.
dirty flag      Set while the document or the paste buffer holds unsaved changes.
unparsed paste text  The paste buffer's text when it is not empty, not the example, and
                not the text of the last successful Parse pasted.
session action  A file load, an A2L load, a project load or a Save project while it runs
                (S6, the busy refusal).
change home     With an open project: <project>/patches/ for kind change,
                <project>/checks/ for kind check. Without: workarea/patches/ (S5).
change list     Every *.json file of the change home that is not a link, sorted by
                name.
findings list   "Declaration faults: <n>", then one line per finding of the document:
                [<code>] <severity>: <message>
finding line    The status line [<code>] <severity>: <message> (one per finding).
history         Up to 20 earlier copies of the document (undo steps) and the copies
                that undo stepped over (redo steps).
history strip   ↶ <b> back  ↷ <f> fwd  <b+f>/20, then the line ctrl+z / ctrl+y
                (b, f = undo and redo steps).
```

### CTX-PE-INPUT · The entry form (S10.3)

```text
Address field   0x followed by hex digits, or decimal digits (S1 decision 1).
Bytes field     Tokens split by spaces or commas; each token 1–2 hex digits with an
                optional 0x (HLR-161).
String field    Text, encoded with the document's encoding (utf-8 for a new document).
built entry     Bytes field not empty: a bytes entry of those bytes. Otherwise String
                field not empty: a string entry of that text.
placeholders    Address 0x100 · String text (document encoding) ·
                Bytes hex bytes, e.g. DE AD BE EF
```

### CTX-PE-LEDGER · Ledger and tally (S10.4)

```text
ledger row      Kind: the check glyph (S9.2), then string or bytes ·
                Address: 0x<hex, uppercase> ·
                Value / bytes: the string, or the first 8 bytes as XX XX …, then
                " .. (<n> bytes)" when longer ·
                Status: inside, partial, outside or unvalidated-no-image (S8), then
                " / fault" when an ERROR finding names the entry's address ·
                Linkage: from the last apply (S8), "-" before one.
ledger subtitle <n> entry or <n> entries, then " ●" while the dirty flag is set.
tally           DOCUMENT; a 12-cell bar (one cell per entry in its status colour while
                the entries fit, else proportional); "<n> entries · <i> inside ·
                <p> partial"; "<o> outside · <f> faults", then " · <u> no image" when
                u > 0. With no entry: DOCUMENT and "0 entries".
```

### CTX-PE-STRIP · The before → after strip (S10.5)

```text
row width       The largest of 4, 8, 16 or 32 bytes whose line fits the inspector.
strip row       Three lines: the row address (8 hex digits) and "+X" per column
                (X = the low hex digit of that column's address); "was" and the
                image bytes; "now" and the bytes the entry writes. The first row
                starts at the entry's address rounded down to the row width; places
                outside the entry repeat their image byte.
changed byte    A byte of the entry whose image byte is missing or different.
summary line    <m> B @ 0x<8 hex> · <c> changed
missing byte    --
```

### CTX-PE-JSON · The JSON tab (S10.6)

```text
JSON stamp      <n> entry|entries · <HH:MM:SS> · saved|unsaved changes;
                before any document: "no document yet", then " · unsaved changes"
                while the dirty flag is set.
example         S8's example change-set: bytes DE AD BE EF at 0x00000000 and the
                string ABC at 0x00000010.
paste heading   PASTE BUFFER · example, or PASTE BUFFER · editable.
paste gauge     <used ÷ 1024, one decimal>K / 64.0K (K = 1024 characters; the
                64 KiB cap is S7's).
JSON hues       Keys, strings, numbers and true / false / null each in its own hue;
                none of them an outcome colour (S9).
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested**, **Yes; untested**, **Partly** / **No** with the decision.

### S10.1 · The screen (CTX-PE)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-063.1 | U | The system shall show the Patch Editor as the identity ribbon, the ledger beside the inspector, the file row, the document row and the legend, top to bottom. | Yes; tested. |
| R-TUI-063.2 | U | The system shall keep the ledger beside the inspector at every terminal width. | Yes; tested. |
| R-TUI-063.3 | U | The system shall give the inspector the tab chips Inspector, JSON and Checks. | Yes; tested. |
| R-TUI-063.4 | When | When the Patch Editor is first shown, the system shall show the Inspector tab. | Yes; tested. |
| R-TUI-063.5 | When | When the operator activates a tab chip by click, Enter or space, the system shall show that tab's pane. | Yes; tested. |
| R-TUI-063.6 | When | When the shown tab changes, the system shall set the inspector border title to INSPECTOR, JSON or CHECKS after the tab. | Yes. |
| R-TUI-063.7 | U | The system shall give the ledger the border title `PATCH SCRIPT`. | Yes; tested. |
| R-TUI-063.8 | While | While the JSON tab is shown, the system shall show the inspector subtitle `v2 schema`. | Yes. |
| R-TUI-064.1 | While | While the Patch Editor is shown at 118 × 54 or more, the system shall show Validate, Apply loaded changes and Save without scrolling. | Yes; tested. |
| R-TUI-064.2 | While | While the Patch Editor is shown at 118 × 54 or more, the system shall paint no row wider than the screen. | Yes; tested. |
| R-TUI-064.3 | While | While the Patch Editor is shown below 118 × 54, the system shall keep every control reachable by scrolling. | Yes; tested. |
| R-TUI-064.4 | U | The system shall show every Patch Editor button as a one-row chip. | Yes. |
| R-TUI-064.5 | U | The system shall give Save the only filled style of the Patch Editor. | Yes; tested. |
| R-PE-001 | U | The system shall show the Patch Editor legend of CTX-PE under the document row. | Yes. |
| R-PE-002 | While | While the document is file-backed, the system shall show `<file name> · <kind>` in the identity ribbon. | Yes. |
| R-PE-003 | While | While the document is a draft, the system shall show `draft · <kind>` in the identity ribbon. | Yes. |
| R-PE-004 | If | If the file name is wider than the ribbon, then the system shall show one `…` and the end of the name that fits. | Yes; tested. |
| R-PE-005 | U | The system shall show file names, entry values, findings, the JSON view and the paste buffer in the Patch Editor as plain text, never as markup. | Yes; tested. |

### S10.2 · Choosing and loading a document (CTX-PE-DOC)

Reading the file, the load status and the finding lines are S8's (R-CHG-001.19 … .21); symbol entries read with the loaded A2L are S8's R-CHG-SYM.9.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PATCH-DOC-DROPDOWN-001.1 | When | When the Patch Editor is opened, or a Save or a Refresh ends, the system shall fill the File dropdown with the change list. | Partly: lists `workarea/patches/` only, also with a project (D10-25); tested. |
| R-PATCH-DOC-DROPDOWN-001.2 | If | If the change home holds no change document, then the system shall show the dropdown with its prompt `Change files in patches/` and no option. | Yes; tested. |
| R-PATCH-DOC-DROPDOWN-001.3 | When | When the operator picks a file in the dropdown, the system shall load it as the document. | Yes; tested. |
| R-PATCH-DOC-DROPDOWN-001.4 | If | If the picked file is a link or lies outside its folder, then the system shall refuse it with the status `Patch Editor: change file '<name>' is outside the patches folder — not loaded.` | Yes. |
| R-TUI-054.1 | U | The system shall show the path input placeholder `or type a path to the same change-set JSON (alternative to the patches/ dropdown)`. | Yes; tested. |
| R-PE-010 | When | When the operator presses Load, the system shall load the file the path input names as the document (S8 reader). | Yes; tested. |
| R-PE-011 | If | If the path input is empty when Load acts, then the system shall show the status `Patch Editor: enter a change-file path to load.` | Yes. |
| R-TUI-052.1 | When | When the operator presses Refresh, the system shall fill the File dropdown with the change list. | Yes; tested. |
| R-TUI-052.2 | When | When the operator presses Refresh, the system shall keep the document as it is. | Yes; tested. |
| R-TUI-052.3 | When | When the operator presses Refresh, the system shall show the status `Patch Editor: file list refreshed.` | Yes; tested. |
| R-PE-015 | If | If the operator presses Load while the dirty flag is set, then the system shall ask with the unsaved-changes popup before it loads. | Yes; tested (`test_tc_b100_45_patch_editor_load_keeps_its_own_guard`: this popup, not the image-load question of S5). |
| R-PE-012 | When | When the system shows the unsaved-changes popup, the system shall title it `Unsaved changes will be lost`. | Yes. |
| R-PE-013 | When | When the system shows the unsaved-changes popup, the system shall show the text `The change editor and the text editor carry unsaved changes. Loading a new document replaces them.` | Yes. |
| R-PE-014 | When | When the system shows the unsaved-changes popup, the system shall offer the buttons `Accept loss and load` and `Cancel` (focus and Esc: S7.1). | Yes; tested. |
| R-PE-016 | If | If the operator picks a file in the dropdown while the dirty flag is set, then the system shall ask with the unsaved-changes popup before it loads. | Yes; tested (`test_tc_b100_45_change_file_dropdown_keeps_the_guard`). Done in batch-100 Inc 10 (D10-20, D10-45). |
| R-PE-017 | When | When the operator accepts the loss in the unsaved-changes popup, the system shall load the file the operator asked for. | Yes; tested. |
| R-PE-018 | When | When the operator cancels the unsaved-changes popup, the system shall keep the document and the dirty flag. | Yes; tested. |
| R-PE-019 | When | When the operator cancels the unsaved-changes popup, the system shall show the status `Patch Editor: load cancelled — changes kept.` | Yes; tested (`test_tc_b100_45_change_file_dropdown_keeps_the_guard`, dropdown arm). |
| R-PE-019a | When | When the operator cancels the unsaved-changes popup that a dropdown pick opened, the system shall clear the dropdown's choice. | Yes; tested (`test_tc_b100_45_change_file_dropdown_keeps_the_guard`: a second pick of the same file asks again). From batch-100 LLR-174.2t (D10-45). |

### S10.3 · Entries (CTX-PE-INPUT)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PE-020 | U | The system shall show the placeholders of CTX-PE-INPUT in the Address, String and Bytes fields. | Yes; tested. |
| R-PE-021 | When | When the operator presses Add, the system shall append the built entry at the Address field's address to the document. | Yes; tested. |
| R-PE-022 | When | When an Add succeeds, the system shall show the status `Patch Editor: entry added.` | Yes. |
| R-PE-023 | If | If an entry already declares the Address field's address, then the system shall refuse the Add with the status `Patch Editor: an entry at address 0x<X> already exists - use Edit`. | Yes. |
| R-PE-024 | When | When the operator presses Edit, the system shall replace the first entry declared at the Address field's address with the built entry. | Yes; tested. |
| R-PE-025 | When | When an Edit succeeds, the system shall show the status `Patch Editor: entry updated.` | Yes. |
| R-PE-026 | When | When the operator presses Remove, the system shall remove the first entry declared at the Address field's address. | Yes; tested. |
| R-PE-027 | When | When a Remove succeeds, the system shall show the status `Patch Editor: entry removed.` | Yes. |
| R-PE-028 | If | If no entry declares the Address field's address, then the system shall refuse the Edit or Remove with the status `Patch Editor: no change entry at address 0x<X>`. | Partly: the text is wrapped in quotes (D10-28). |
| R-PE-029 | If | If the Address field is empty, then the system shall refuse the action with the status `Patch Editor: memory address must not be empty`. | Yes; tested. |
| R-PE-030 | If | If the Address field is not empty and does not follow CTX-PE-INPUT, then the system shall refuse the action with the status `Patch Editor: bad address '<text>' - use 0x and hex digits, or decimal digits`. | No: `0b101`, `0o17`, `1_000` and `+5` pass; `0100` and other text give Python's message (D10-27). |
| R-PE-031 | If | If a Bytes token is not 1–2 hex digits with an optional `0x`, then the system shall refuse the action with the status `Patch Editor: invalid byte token '<token>' - every token is 1-2 hex digits with an optional 0x prefix; decimals are not accepted`. | Yes; tested. |
| R-PE-032 | If | If the String and Bytes fields are both empty, then the system shall refuse the Add or Edit with the status `Patch Editor: enter a string value or a run of new bytes`. | Yes. |
| R-PE-033 | If | If the String text does not encode in the document's encoding, then the system shall refuse the Add or Edit with the status `Patch Editor: string value does not encode under '<encoding>': <reason>`. | Yes. |
| R-PE-034 | When | When the document changes through Add, Edit, Remove, Parse pasted, undo, redo or a per-entry JSON edit, the system shall set the dirty flag. | Partly: undo, redo and per-entry edits leave it as it was (D10-21). |
| R-PE-035 | If | If an Add, Edit or Remove is refused, then the system shall keep the dirty flag as it was. | No: a refused action sets it (D10-21). |
| R-PE-036 | When | When the operator types in the paste buffer, the system shall set the dirty flag. | Yes; tested (`test_tc_b100_44_patch_editor_reader_follows_its_writers`). |
| R-PE-037 | When | When a Save or a load succeeds, the system shall clear the dirty flag. | Yes; tested (`test_tc_b100_44_patch_editor_reader_follows_its_writers`). |

**(from batch-100 HLR-167: LLR-167.8, LED .72, LED .73)** Save project and its outcome are S11's; these rows state only what it does to the dirty flag.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PE-038 | When | When a Save project places the Patch Editor's draft document in the project and the paste buffer holds no unparsed paste text, the system shall clear the dirty flag. | Yes; tested (`test_tc_b100_70_written_document_clears_the_flag`, `test_tc_b100_70_project_load_asks_only_while_the_document_is_unsaved`). Save project's side: S11 R-PROJ-DOC.15. |
| R-PE-039.1 | If | If a Save project is refused or rolled back, then the system shall keep the dirty flag as it was. | Yes; tested (`test_tc_b100_70_refused_save_keeps_the_flag`). Save project's side: S11 R-PROJ-DOC.16. |
| R-PE-039.2 | If | If a Save project cannot write the Patch Editor's draft document, then the system shall keep the dirty flag as it was. | Yes; tested (`test_tc_b100_70_failed_document_write_keeps_the_flag`). Save project's side: S11 R-PROJ-DOC.16. |
| R-PE-039.3 | If | If the Patch Editor's document is file-backed when a Save project ends, then the system shall keep the dirty flag as it was. | Yes; tested (`test_tc_b100_70_file_backed_document_from_outside_keeps_the_flag`, `test_tc_b100_70_natural_path_load_edit_save_keeps_the_flag`). Save project's side: S11 R-PROJ-DOC.16; its status for a file with unsaved edits: S11 R-PROJ-DOC.17. |
| R-PE-039.4 | If | If the paste buffer holds unparsed paste text when a Save project ends, then the system shall keep the dirty flag as it was. | Yes; tested (`test_tc_b100_70_unparsed_paste_text_keeps_the_flag`). Save project's side: S11 R-PROJ-DOC.16. |

### S10.4 · Ledger, findings and tally (CTX-PE-LEDGER)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHG-004.1 | U | The system shall edit one change document at a time in the Patch Editor. | Yes; tested. |
| R-PE-040 | U | The system shall show one ledger row per entry, in document order. | Yes; tested. |
| R-PE-041 | U | The system shall show the ledger subtitle of CTX-PE-LEDGER. | Yes; tested. |
| R-PE-042 | U | The system shall show every ledger address in full. | Yes; tested. |
| R-PE-043 | If | If a Value / bytes, Status or Linkage cell is wider than its column, then the system shall show its start and one `…`. | Yes; tested. |
| R-PE-044 | If | If the document has no entry and no finding, then the system shall show the ledger line `No entries yet: Add one, paste a change-set or Load a file.` | Yes; tested. |
| R-PE-045 | If | If the document has no entry and has findings, then the system shall show the ledger line `Refused: <first finding line>`. | Yes. |
| R-CHG-004.2 | When | When a Patch Editor action ends, the system shall show the document's findings list on the Checks tab. | Yes; tested. |
| R-CHG-004.3 | While | While the document has no finding, the system shall show no findings count and no findings line. | Yes; tested. |
| R-CHG-004.4 | U | The system shall mark the Status of an entry with ` / fault` while an ERROR finding names its address. | Yes; tested. |
| R-PE-046 | U | The system shall show the tally of CTX-PE-LEDGER at the foot of the Inspector tab. | Yes. |

### S10.5 · The before → after strip (CTX-PE-STRIP)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PE-050 | When | When the operator highlights a ledger row, the system shall show the strip rows of that entry. | Yes; tested. |
| R-PE-051 | U | The system shall show on the `was` lines the image bytes as they were before any apply (S8). | Yes. |
| R-PE-052 | U | The system shall show on the `now` lines the bytes the entry writes, and the image byte at every place outside the entry. | Yes; tested. |
| R-PE-053 | U | The system shall build strip rows of the row width. | Yes; tested. |
| R-PE-054 | If | If an entry needs more than 8 strip rows, then the system shall show the first 8 rows and the line `showing <n> of <m> bytes`. | Yes; tested. |
| R-PE-055 | U | The system shall close the strip with its summary line. | Yes; tested. |
| R-PE-056 | U | The system shall show each changed byte on the `now` line, and a non-zero changed count, in bold patch teal. | Yes; tested. |
| R-PE-057 | If | If an address of a strip row has no image byte, then the system shall show `--` for it. | Yes; tested. |
| R-PE-058 | If | If the document has no entry, then the system shall show the strip line `No entry yet: Add one or Load a file.` | Yes; tested. |
| R-PE-059 | If | If no ledger row is highlighted, then the system shall show the strip line `Select a ledger row to see its bytes.` | Yes. |
| R-PE-060 | If | If no image is loaded, then the system shall show the strip line `No image loaded: ^l loads one.` | Yes; tested. |

### S10.6 · The JSON tab: view, paste buffer, Edit JSON (CTX-PE-JSON)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PE-070 | When | When the document changes, the system shall show its JSON (S8 wire form) in the read-only view of the JSON tab. | Yes; tested. |
| R-PE-071 | If | If the document's JSON equals the JSON shown, then the system shall keep the view's text, cursor, scroll and stamp. | Yes; tested. |
| R-PE-072 | If | If the document's JSON is longer than 5000 lines, then the system shall show its first 5000 lines and the line `showing 5000 of <N> lines`. | Yes; tested. |
| R-PE-073 | While | While no document has been shown, the system shall show `No document yet: Load, paste or Add.` in the JSON view. | Yes; tested. |
| R-PE-074 | When | When the JSON view or the dirty flag changes, the system shall show the JSON stamp above the view. | Yes; tested. |
| R-PE-075 | U | The system shall show the heading `LOADED DOCUMENT · read-only` above the JSON view. | Yes. |
| R-PATCH-PASTE-001.1 | When | When the Patch Editor opens, the system shall fill the paste buffer with the example. | Yes; tested. |
| R-PATCH-PASTE-001.2 | While | While the paste buffer equals the example, the system shall show the paste heading `PASTE BUFFER · example`. | Yes; tested. |
| R-PATCH-PASTE-001.3 | While | While the paste buffer differs from the example, the system shall show the paste heading `PASTE BUFFER · editable`. | Yes; tested. |
| R-PATCH-PASTE-001.4 | When | When the operator presses Parse pasted, the system shall replace the document with the document the paste buffer holds (S8 R-CHG-001.1). | Yes; tested. |
| R-PATCH-PASTE-001.5 | If | If the paste buffer text carries an ERROR finding when Parse pasted acts, then the system shall keep the document as it is. | No: the document is replaced by the refused one (D10-22). |
| R-PATCH-PASTE-001.7 | U | The system shall show the paste buffer text literally, with no markup applied. | Yes; tested. |
| R-PATCH-PASTE-001.8 | U | The system shall colour the paste buffer's JSON with the JSON hues. | Yes; tested. |
| R-PATCH-PASTE-001.9 | U | The system shall show the paste gauge beside the paste heading. | Yes; tested. |
| R-PATCH-PASTE-001.10 | While | While the paste buffer holds 75 % to under 100 % of its cap, the system shall show the gauge's used figure in magenta. | Yes; tested. |
| R-PATCH-PASTE-001.11 | While | While the paste buffer holds 100 % of its cap or more, the system shall show the gauge's used figure in bold magenta. | Yes; tested. |
| R-TUI-046.1 | When | When the operator opens the JSON tab, the system shall show the first line of the paste buffer without scrolling. | Yes; tested. |
| R-PATCH-WRITE-REUSE-001 | U | The system shall apply, save back and name the save-back of a pasted document exactly as for the same document loaded from a file. | Yes; tested. |
| R-TUI-053.1 | When | When the operator presses Edit JSON under the paste buffer, the system shall open the change-set JSON popup (S7) with the paste buffer text. | Yes; tested. |
| R-TUI-053.2 | When | When the operator confirms valid text in the change-set JSON popup, the system shall put the text in the paste buffer and act as Parse pasted. | Yes; tested. |
| R-TUI-053.3 | If | If the confirmed popup text carries an ERROR finding, then the system shall keep the document and show the status `Edit JSON refused: <kind> text carries <n> error(s) — the document is unchanged.` | Yes; tested. |
| R-TUI-053.4 | When | When the operator cancels the change-set JSON popup, the system shall keep the document and the paste buffer as they are. | Yes; tested. |
| R-TUI-053.5 | While | While the document is file-backed, the system shall disable Edit JSON under the paste buffer. | Yes; tested. |
| R-TUI-053.6 | If | If the change-set JSON popup is requested for a file-backed document, then the system shall refuse it with the status `Patch Editor: Edit JSON is available only for a pasted change-set, not a file-loaded document.` | Yes. |
| R-TUI-053.7 | When | When the system shows the change-set JSON popup, the system shall title it `Edit change-set JSON:`. | Yes. |
| R-TUI-053.8 | When | When the system shows the change-set JSON popup, the system shall offer the buttons `Confirm` and `Cancel` (focus and Esc: S7.1). | Yes; tested. |

### S10.7 · History and per-entry JSON (CTX-PE-DOC)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-TUI-057.1 | When | When Add, Edit, Remove, a load, Parse pasted or a per-entry JSON edit changes the document, the system shall first keep a copy of the document as an undo step. | Yes; tested. |
| R-TUI-057.2 | If | If the history holds 20 undo steps when a new one is kept, then the system shall drop the oldest. | Yes; tested. |
| R-TUI-057.3 | When | When the system keeps a new undo step, the system shall drop every redo step. | Yes; tested. |
| R-TUI-057.4 | When | When the operator presses Undo or ctrl+z, the system shall restore the document of the latest undo step. | Yes; tested. |
| R-TUI-057.5 | When | When the operator presses Redo or ctrl+y, the system shall restore the document of the latest redo step. | Yes; tested. |
| R-TUI-057.6 | If | If there is no step in the asked direction, then the system shall keep the document as it is. | Yes; tested. |
| R-TUI-057.7 | While | While the Patch Editor is not shown, the system shall ignore ctrl+z and ctrl+y as history keys. | Yes. |
| R-TUI-057.8 | U | The system shall keep Undo, Redo and their keys enabled for every document. | No: disabled for a file-backed document (D10-23). |
| R-TUI-057.9 | When | When the history changes, the system shall show the history strip above Undo and Redo. | Yes; tested. |
| R-TUI-058.1 | When | When the operator presses Edit JSON in the Inspector tab, the system shall open the entry JSON popup (S7) with the wire JSON (S8) of the highlighted entry only. | Yes; tested. |
| R-TUI-058.2 | When | When the operator confirms the entry JSON popup with text that holds exactly one valid entry, the system shall replace only the highlighted entry with it. | Yes; tested. |
| R-TUI-058.3 | If | If the confirmed entry text is not exactly one valid entry, then the system shall keep the document and show the status `Patch Editor: entry edit rejected - see findings.` | Yes; tested. |
| R-TUI-058.4 | When | When a per-entry edit succeeds, the system shall show the status `Patch Editor: entry at 0x<X> updated.` | Partly: the status names a zero-based index (`entry 0 updated`) (D10-29). |
| R-TUI-058.5 | If | If the ledger has no row, then the system shall ignore Edit JSON in the Inspector tab. | Yes. |
| R-TUI-058.6 | U | The system shall keep the per-entry Edit JSON enabled for every document. | No: disabled for a file-backed document (D10-23). |
| R-TUI-058.7 | When | When the system shows the entry JSON popup, the system shall title it `Edit entry JSON:`. | Yes. |
| R-TUI-058.8 | When | When the system shows the entry JSON popup, the system shall offer the buttons `Confirm` and `Cancel` (focus and Esc: S7.1). | Yes; tested. |

### S10.8 · Validate, Apply, Save, save-back (CTX-PE)

S8 owns what these controls do: Validate (R-CHG-VAL.1 … .4), the apply and its status (R-CHG-002), the save-back prompt with its suggested name, width and write (R-CHG-003, R-HEX-VERIFY-002.3, R-S19-WIDTH-001), and Save with its folder, name and status (R-PATCH-SAVE-FOLDER-001). S10 keeps the controls and what the editor shows. The before/after report is S14's.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PE-080 | U | The system shall label the apply button `Apply loaded changes`. | Yes; tested. |
| R-PE-081 | When | When the operator presses Apply loaded changes, the system shall apply the document to the loaded image (S8). | Yes; tested. |
| R-PE-093 | When | When a Save succeeds, the system shall make the written file the document's source. | No: the document stays a draft and the ribbon keeps `draft` (D10-24). |
| R-TUI-049.1 | When | When a save-back succeeds, the system shall show the before/after control. | Yes; tested. |
| R-TUI-049.2 | When | When the operator presses Write before/after report, the system shall write the before/after report as the `b` key does (S14 R-BEFORE-AFTER-REPORT-001.2). | Yes; tested. |
| R-TUI-049.3 | When | When the document is replaced by a load, a paste, undo or redo, the system shall hide the before/after control and the save-back prompt. | Partly: the control hides after a plain Load and a paste only; the prompt never (D10-30; re-verified at 570b4b5, `app.py:6785-6805`). |

**(from batch-100 HLR-177a: LLR-177.3e; E3 S12b-04)** The busy line, its text and the end of the refusals are S6's.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PE-110 | While | While a session action runs, the system shall refuse Add, Edit, Remove, Load, a dropdown pick, Refresh, Parse pasted, Validate, Apply loaded changes, Save, Run checks, Execute scope, Undo and Redo (buttons, Ctrl+Z and Ctrl+Y), Write file, both Edit JSON popups and their results, and the accept of the unsaved-changes popup. | Yes; tested (`test_tc_b100_53_patch_editor_changes_are_refused_while_busy`, `test_tc_b100_53_patch_editor_continuations_are_refused_while_busy`). |
| R-PE-111 | While | While a project load runs, the system shall make the paste buffer read-only. | Yes; tested (`test_tc_b100_53_paste_box_is_read_only_during_a_project_load`). |

### S10.9 · Checks and the execution scope (CTX-PE)

The check run and its display are S9 (S9.1, S9.2); running a scope is S11.

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-PATCH-CHECKS-CLARITY-001.1 | When | When the operator presses Run checks, the system shall run the document as a check document against the loaded image (S9.1). | Yes; tested. |
| R-PATCH-CHECKS-CLARITY-001.2 | U | The system shall show under Run checks the help text `Checks: runs the loaded change document's checks against the loaded image. Needs kind 'check' (a change-set cannot be checked). Uncheckable rows name their reason (declaration fault, partial/outside range, or no image); healthy entries are still checked.` | Yes; tested. |
| R-PE-100 | When | When the operator presses the scope button, the system shall move to the next scope label in cycle order and label the button `Scope: <label>`. | Yes. |
| R-PE-101 | When | When the scope changes, the system shall show the scope line `Scope <label>`. | Yes. |
| R-PE-102 | When | When the operator presses Execute scope, the system shall run the document over the variants of the shown scope (S11.13). | Partly: once project.json exists and names no file, Execute scope runs the manifest's empty composition and ignores the document (S11 D11-25, re-verified open at 570b4b5, `app.py:5664`). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D10-1 | R-TUI-027, R-CDFX-016, R-PATCH-2X2-LAYOUT-001 and R-PATCH-2X2-SNAPSHOT-001 are superseded rows kept for history, with retired test ids. | Out of the requirements; the batch records and the retired-id register keep them. |
| D10-2 | Rows carry widget ids, CSS values, message classes, test censuses, commits, "frozen-engine diff" notes; four batch-48 records (border title, C-17 observation point, hue census F-1, chip family) record method and measurement. | Out. Their product content is rows: border titles (R-TUI-063.6, .7), literal paste buffer (R-PATCH-PASTE-001.7), gauge escalation (R-PATCH-PASTE-001.10, .11), chips (R-TUI-064.4, .5). |
| D10-3 | Three windows, 3-across at 120 columns and stacked below (R-TUI-045, 046, 063, 064). The code shows a ledger beside an inspector with three tabs at every width (batch-97 HLR-144, HLR-149). | Rows follow the code (S10.1); HLR-144 / 149 absorbed for the Patch Editor, pointers left in S0. |
| D10-4 | The variant dropdown and variant help (R-PATCH-VARIANT-SELECT-001, R-TUI-056) were removed by batch-94 HLR-006; `test_at_b94_08_variant_machinery_retired` pins their absence. | No rows. |
| D10-5 | R-TUI-052: Refresh re-read the loaded file; batch-94 HLR-008 made it a folder rescan (`app.py:3524-3534`). | Rows follow the code (R-TUI-052.1 … .3). |
| D10-6 | R-TUI-054: title `Change document (JSON)`; now the ledger border title `PATCH SCRIPT`. The placeholder is unchanged. | Rows follow the code (R-TUI-063.7, R-TUI-054.1). |
| D10-7 | R-PATCH-CHECKS-CLARITY-001 quotes one sentence; the code shows four (`screens_directionb.py:5155-5160`), the last three from R-CHK-002. | The full text (R-PATCH-CHECKS-CLARITY-001.2). |
| D10-8 | R-PATCH-WRITE-REUSE-001's "no new write surface" is a git-diff gate. | The observable equality stays as a row; the gate stays in the batch record. |
| D10-9 | The Execute over variants row is Patch Editor screen; running it is S11 (`_trigger_execute_scope`). | UI rows here (R-PE-100 … 102), execution in S11. |
| D10-10 | The paste buffer starts with the example, whose bytes entry writes `DE AD BE EF` at 0x00000000 if parsed and applied unchanged. | Keep: the heading says `example`, and writing needs Parse pasted, Apply and Write file. |
| D10-11 | Save has no name input: it writes `changes.json` or the next numbered name (`app.py:3569-3571`; S8 R-PATCH-SAVE-FOLDER-001.4 … .6), never over the loaded file. | Keep (no silent overwrite); no name input is proposed. |
| D10-12 | The current Patch Editor is described only by S0's HLR-005 … 008, HLR-144, HLR-161 and the Patch Editor parts of HLR-148, 149, 157. | Absorbed as rows here; pointers left in S0. |
| D10-45 | Overlap item of the handoff: D10-20 (a dropdown pick skips the unsaved-changes popup) against batch-100 Inc 10 (`5dd2249`). Batch-100 LLR-174.2t (owned with HLR-174 by S5) shows the Load button's popup on a dropdown pick while the panel is dirty, keeps the document and the flag on cancel with the same status, and clears the dropdown so the same pick asks again (`app.py:6768-6782`). It is the Patch Editor's own popup, not S5's image-load question (LLR-174.2j). | D10-20 is settled as it decided: R-PE-016 reads Yes; new row R-PE-019a for the cleared choice. Nothing is superseded. |
| D10-46 | Batch-100 LLR-167.8 (Inc 5, re-pinned at Inc 8a; LED .72, .73): a completed Save project clears the panel's dirty flag only when a file in the project now holds every entry the panel shows: the draft document was written (or reused) there and the paste buffer holds no unparsed text (`app.py:2509-2541`, `:12262-12277`). A refused or rolled-back save, a failed document write and a file-backed document leave the flag set. The read goes through a public reader of the panel (`screens_directionb.py:5867-5876`, LLR-174.1c). | Rows R-PE-038, R-PE-039.1 … .4; "unparsed paste text" defined in CTX-PE-DOC. Save project's own rows and the outcome line for a file-backed document with unsaved edits are S11's (R-PROJ-DOC.15, .16, .17). |
| D10-47 | Batch-100 HLR-177a (Inc 12b, LLR-177.3e): every Patch Editor handler that reaches the change service, the two popup results and the two popup accept arms first refuse while a session action runs (`app.py:4489`, `:4704`, `:4912`, `:4939`, `:4994`, `:5022`, `:5063`, `:5117`, `:5185`, `:5238`, `:6756`, `:6777`, `:6872`, `:6886`); a project load makes the paste buffer read-only until it ends (`app.py:13469-13475`, `:20330-20337`). These handlers changed only by that check. | Rows R-PE-110, R-PE-111 (the Patch Editor part, rule D-9); the busy line and the rules that end the refusal are S6's. The other S10 rows keep their cells. |
| D10-48 | Tests that verify implementation only (not cited as row evidence): `test_tc_b100_44_no_private_dirty_read_outside_the_panel` (a source census) and `test_tc_b100_44_guard_reads_the_public_reader` (the reader seam, LLR-174.1c). | No rows. |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D10-13 | `add_symbol_entry`, `resolve_symbol_entry`, `list_a2l_symbol_names` (`change_service.py:509-697`, `:1260`) and S2's `encode_physical_to_raw_bytes` have no screen: only tests call them. HLR-141 asks for the symbol input. | **Defer** with the symbol-input prototype (D10-42); keep the code; write the encoder rows (S2's pass) with that round. |
| D10-14 | `#patch_checks_section_label`, `#patch_script_section_label` and `#patch_win_json_dock_spacer` are mounted but never displayed, kept for an id census (`screens_directionb.py:5135-5141`, `:5189-5195`, `:5010-5012`). | Delete the widgets and their census entries. |
| D10-44 | Two rows clashed with S8 (rule D-9: one row, one owner). R-PE-084 kept the status `<file kind> save-back not supported` (`app.py:3560-3563`), which S8 D8-17 finds unreachable: an entry is applied only inside an image range, and a session whose current file is not S19 or Intel HEX has none (a MAC file's ranges are empty, `app.py:11535`; S8 R-CHG-002.10, .11). R-PE-085 (the save-back name box filled with the suggested name) restated S8 R-HEX-VERIFY-002.3. | Delete R-PE-084 with S8's branch (not used). Delete R-PE-085: S8 R-HEX-VERIFY-002.3 is the one row; S10.8 cites it. |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D10-20 | Picking a file in the dropdown loads at once, even with the dirty flag set (`app.py:5664-5674`): unsaved changes are lost without the popup the Load button shows. | Same popup (R-PE-016). **Done** in batch-100 Inc 10 (D10-45). |
| D10-21 | Add, Edit and Remove set the dirty flag before the service checks the input (`screens_directionb.py:5625-5628`), so a refused action marks the document unsaved; undo, redo and a per-entry JSON edit change the document without setting it, so a later Load asks nothing. | The flag follows real document changes (R-PE-034, 035). |
| D10-22 | Parse pasted with invalid text replaces the document with the refused, empty one (`change_service.py:1648-1652`); Edit JSON refuses the same text (`app.py:4072-4087`). | Refuse like Edit JSON: the document stays (R-PATCH-PASTE-001.5). |
| D10-23 | Undo, Redo, ctrl+z / ctrl+y and per-entry Edit JSON are disabled for a file-backed document (`app.py:3626-3632`, `:3926-3928`), but Add, Edit and Remove change it, so those changes cannot be undone; a refused load replaces the document with no way back. The stated risk (a stale paste buffer replacing the document) belongs to whole-set Edit JSON only. | Undo, Redo and per-entry Edit JSON for every document; whole-set Edit JSON stays draft-only (R-TUI-057.8, R-TUI-058.6, R-TUI-053.5). The `history off` strip state goes with the guard. |
| D10-24 | After a Save the document stays a draft (`change_service.py:1772-1785` sets no source): the ribbon says `draft` while the stamp says `saved`, and Execute scope cannot use the saved file. | The written file becomes the document's source (R-PE-093); whole-set Edit JSON then disables, as for any file-backed document. |
| D10-25 | The dropdown lists `workarea/patches/` only (`app.py:5427`, `:5507-5513`), while Save writes `<project>/patches/` or `<project>/checks/` when a project is open (`:5464-5469`), as does the 📂 chip: a file saved with a project never appears in the dropdown. | List the change home (both project folders with a project). Same decision as S9 D9-15. |
| D10-27 | The Address field is read with `int(text, 0)` (`change_service.py:276`): `0b101`, `0o17`, `1_000`, `+5` pass; `0100` and other text give Python's raw message (`invalid literal for int() with base 0: …`). | `0x` and hex digits, or decimal digits, with an exact message (R-PE-030). Same rule as the Check Editor (S9 D9-17). |
| D10-28 | Edit or Remove on a missing address shows `Patch Editor: 'no change entry at address 0x100'`: the KeyError text keeps its quotes (`app.py:3597-3598`). | No quotes (R-PE-028). |
| D10-29 | A per-entry edit reports `Patch Editor: entry 0 updated.`: a zero-based index the operator never sees (`change_service.py:1529`). | Name the address (R-TUI-058.4). |
| D10-30 | The before/after control hides only on a plain Load and a paste (`app.py:3507`, `:3515`), not on a dropdown pick, a guarded load, undo or redo; the save-back prompt hides only on its own buttons, so a new document can inherit a stale prompt. | Hide both whenever the document is replaced (R-TUI-049.3). |

**Prototype first** (visual; prototype round with real captures and the operator's verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D10-40 | The save-back prompt, the before/after control, Undo / Redo and Execute over variants live in the JSON tab. Apply is pressed from the document row, usually with the Inspector tab shown, so the prompt it reveals is out of sight. | Where the prompt and the control appear so the operator sees them after Apply and Write file. |
| D10-41 | Edit and Remove act on the address typed in the Address field; the strip and the per-entry Edit JSON act on the highlighted ledger row. Highlighting a row does not fill the form. | One target rule for the entry actions, and how the form shows it. |
| D10-42 | HLR-141 / LLR-141.2: a symbol input with a picker over the loaded A2L and a Symbol column in the ledger; never built (D10-13). | The input, the picker, the column, and the encoder rows S2 passed to S10. |
| D10-43 | The save-back prompt shows `Width: 32 bytes/line` for an Intel HEX image, where the width changes nothing (S8 D8-40, passed to S10). | Hide, disable or relabel the Width control for an Intel HEX image. |

**Passed to other groups**

- **S0**: pointers from HLR-005 … 008, HLR-144, HLR-161 and the Patch Editor parts of HLR-148 / 149 / 157 to S10; R-TUI-027, R-CDFX-016 and the 2×2 rows leave the chapter (D10-1).
- **S1**: the Patch Editor (ledger, ribbon, dropdown, findings list, JSON view, paste buffer) joins the safe-text views (R-PE-005).
- **S2**: the encoder rows S2 passed here are deferred with the symbol input (D10-13, D10-42).
- **S3**: colours outside CTX-LEGEND's one palette: patch teal `#56e0d6` (changed strip bytes), magenta `#f586da` (paste gauge), the four JSON hues; and no legend block for the Patch Editor. Add them to the palette and the legend, or map them onto it.
- **S5**: the 📂 Open patches/ chip and the change home must name the same folders (D10-25).
- **S6**: the ctrl+z / ctrl+y bindings and the key bar that dims them.
- **S7**: the unsaved-changes popup (`LoadGuardScreen`), the change-set and entry JSON popups (size, 64 KiB paste cap), the Patch Editor window help (the hex Bytes note of LLR-161.2).
- **S8**: the example change-set text (`DUMMY_CHANGESET_TEXT`) and the per-entry JSON parse (a one-entry envelope, `change_service.py:1506-1517`) have no S8 row yet; both are parse rules. Everything else the Patch Editor's controls trigger is already an S8 row and is cited, not repeated: load status (R-CHG-001.19 … .21), symbols with the loaded A2L (R-CHG-SYM.9), Validate (R-CHG-VAL), apply (R-CHG-002), save-back and width (R-CHG-003, R-S19-WIDTH-001), Save (R-PATCH-SAVE-FOLDER-001), the `was` bytes (HLR-157).
- **S9**: the check run and its display on the Checks tab and in the ledger glyphs (S9.1, S9.2); the help text stays here.
- **S11**: running a scope (`_trigger_execute_scope`) and its status lines.
- **S14**: R-BEFORE-AFTER-REPORT-001 and the report the before/after control writes (R-TUI-049.2).

**Received from other groups** (absorbed here)

- **S2** (`encode_physical_to_raw_bytes` is Patch Editor behaviour): deferred with the symbol input, D10-13 and D10-42. The note on the TAB_NOINTP asymmetry (read nearest, write exact) goes to that round.
- **S8**: `add_symbol_entry` has no UI caller → D10-13, D10-42. The declaration-fault list shows file-derived text → R-PE-005 and the S1 pass above. The Width control round (D8-40) → D10-43. R-PATCH-PASTE-001 uses R-CHG-001.1 → R-PATCH-PASTE-001.4 cites it. D8-22 (read with the loaded A2L) → stays S8's (R-CHG-SYM.9); no S10 row repeats it.
- **S11**: the Execute over variants controls that start S11.13 → R-PE-100 … 102.
- **S7** (the content of three dialogs is S10's; focus and Esc follow S7.1): the unsaved-changes popup → R-PE-012 … 019; the change-set JSON popup → R-TUI-053.1 … .8; the entry JSON popup → R-TUI-058.1 … .8.

**Received from later groups** (after all groups were written)

- S10.1 (S2: `encode_physical_to_raw_bytes`) → covered by D10-13, D10-42 (block above).
- S10.2 (S7: the unsaved-changes guard and the two JSON editors) → covered by R-PE-012 … 019, R-TUI-053.1 … .8, R-TUI-058.1 … .8.
- S10.3 (S8: symbol input, declaration-fault list, Width round, R-CHG-001.1, conflict on R-PE-084 / 085) → D10-44 deletes R-PE-084 and R-PE-085 (R-HEX-VERIFY-002.3 stays S8's). The rest is covered: D10-13, D10-42; R-PE-005, and S1's CTX-TEXT already lists the Patch Editor; D10-43; R-PATCH-PASTE-001.4.
- S10.4 (S9: Run checks help and button; ledger glyphs) → covered by R-PATCH-CHECKS-CLARITY-001.1, .2; the glyphs are S9 R-CHK-PE-013 on the ledger of CTX-PE-LEDGER.
- S10.5 (S11: Execute over variants controls) → covered by R-PE-100 … 102.
- S10.6 (S14: the check-spec folder) → covered by D10-25 (same decision as S9 D9-15 and S14 D14-17).
- S10.7 (S14: R-TUI-049 and its effect) → row R-TUI-049.2 now cites S14 R-BEFORE-AFTER-REPORT-001.2.

---

**Reconciled with batch-100 (s19_app 570b4b5)**

- Rows added (8): R-PE-019a (the dropdown is cleared on cancel, LLR-174.2t); R-PE-038, R-PE-039.1 … .4 (Save project and the dirty flag, LLR-167.8); R-PE-110, R-PE-111 (busy refusal and the read-only paste buffer, LLR-177.3e).
- Rows changed: R-PE-016 No → Yes (D10-20 done in Inc 10). Cells changed (tests named): R-PE-015, R-PE-019, R-PE-036, R-PE-037; R-TUI-049.3 re-verified (still Partly).
- Rows retired: none. Decisions added: D10-45 … D10-48. Decisions superseded: none; D10-20 is marked done.
- Passed (scratch `passed-sweep.md`): S5 (the Patch Editor dirty flag and unparsed paste text feed the project-load question), S6 (the Patch Editor busy rows live here), S11 (the Save project outcome line for a file-backed document with unsaved edits).
- Consolidation (items from S5, S6, S11): R-PE-110 text adds Ctrl+Z / Ctrl+Y and the accept of the unsaved-changes popup (refused at `app.py:4994`, `:5022`, `:6777`, `:6886`; S6 CTX-BUSY lists them). R-PE-038, R-PE-039.1 … .4 and D10-46 cite S11 R-PROJ-DOC.15 … .17. R-PE-102 Yes → Partly (S11 D11-25, re-verified open). Already here: D10-20 settled (D10-45), the dirty flag's writers (R-PE-036, .037, `test_tc_b100_44_patch_editor_reader_follows_its_writers`), the read-only paste buffer (R-PE-111); batch backlog S10-03 is closed by Inc 12b.

## 6. Counts

| | Old S10 | Strict |
|---|---:|---:|
| Requirement statements | 21 rows + 4 amendment records | 138 rows (130 + 8 from batch-100) |
| Statements the code contradicts or that are not product behaviour | 13 (4 history; 2 retired variant rows; 3 replaced layout rows; R-TUI-052 refresh; R-TUI-054 title; R-PATCH-CHECKS-CLARITY-001 text; R-PATCH-WRITE-REUSE-001 gate) | 0 |
| Rows by form: U / When / While / If / Where | — | 30 / 57 / 16 / 35 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 33 (16 follow the code or move, 3 remove, 10 correct a defect (D10-20 done), 4 prototype first; numbers not contiguous) |

Checked by script (`ears_lint.py`): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", final period, no repeated id across review files.
