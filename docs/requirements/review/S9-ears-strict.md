# S9 — Checks: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S9 (lines 3689–3769): R-CHK-001 and R-CHK-002. The chapter promises the Check Editor, the Checks screen and the Patch Editor check strip, but has no row for any of them; their only text is batch HLR/LLR rows in S0's table (HLR-009, HLR-011, HLR-145, LLR-009.x, LLR-011.x, LLR-145.x) and the batch-49 Checks-screen story (HLR-084), which never entered the requirements.
Code: `s19_app/tui/changes/check.py`, `s19_app/tui/checks_view.py`, the S9 functions of `app.py` (`_compose_screen_checks`, `_compose_screen_check_editor`, `_prefill_check_editor`, `_check_items_to_document`, `on_check_editor_panel_*`, `update_checks_view`, `on_check_row_selected`, `_update_checks_hex_pane`), `screens_directionb.py::CheckEditorPanel`, `IncludeTable`, `TabChip`, `check_layout`, `PatchEditorPanel._check_strip_text` / `refresh_check_results`, and the check half of `services/change_service.py` (`run_checks`, `check_rows`, `check_display_rows`, `check_aggregates`, `_check_glyphs`). Every fact read from the code with `file:line`. No test was run.

Result:
- **Context notes first** (section 3): CTX-CHECK, CTX-CHECK-TEXT, CTX-CHECKS-SCREEN, CTX-CHECK-EDITOR.
- **Rows** (section 4): one EARS form each, one `shall`; none needed another form; none uses `Where`. Counts in section 6.
- **Decisions** (section 5), each with a recommendation already applied; visual changes marked **prototype first**.
- Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `cc-S9.md` (scratch backlog). Nothing is changed in the code.

---

## 1. How S9 was written before

- Two long rows. R-CHK-001 mixes the engine rule (one outcome per entry, nothing written), the result data class (`CheckRunResult` fields), a headless entry point, the TUI colours, and a batch-33 amendment record (before/after, test names, "frozen-engine diff = 0").
- R-CHK-002 is one sentence with six responses: reason codes, reason texts, run-level reason, three render surfaces, `markup=False` construction, and the help text of the Patch Editor.
- The three screens that show checks (Patch Editor Checks tab, Checks screen, Check Editor) have no row in the chapter at all.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-CHK-001 | "same v2 schema family … one reader, one rule set": the format and the reader are S8's. The row restates them. | Cite S8 in CTX-CHECK; S9 rows start where a document is already read (D9-2). |
| R-CHK-001 | "uncheckable covering any entry whose target range is not fully inside the loaded image or when no image is loaded": true only for a runnable document. A blocked run and a collision make an entry uncheckable too. | Outcome rows in check order: blocked, tainted, containment (R-CHK-001.5 … .10). |
| R-CHK-001 | "a headless service entry point (`run_checks_for_project`)": only a test called it (the headless project-run test of `tests/test_checks_engine.py`; both deleted in batch-101 Inc 4). Flows and variant execution call the engine directly (`flow_execution_service.py:754`, `variant_execution_service.py:776`). | Removed (D9-7). |
| R-CHK-001 | "`CheckRunResult` carries per-entry expected/actual bytes …": a data class, not behaviour. | Observable rows only: what the result rows show (CTX-CHECK-TEXT). |
| R-CHK-002 | "`markup=False` at construction", "closes the pre-existing five-message exposure class": implementation and history. | One plain-text row per surface. |
| R-CHK-002 | "the checks help affordance states …": that text is the Patch Editor's Run checks help (R-PATCH-CHECKS-CLARITY-001, S10). | Moved to S10. |
| (none) | The Checks tab and the Checks screen keep showing the last run after the document or the image changed. The ledger glyphs already refuse to (`change_service.py:3018-3023`), so two surfaces of one run disagree. | "Current run" defined once; every surface shows only a current run (D9-10). |
| (none) | The Check Editor's Validate can never fail: Write and Validate take each field's expected bytes from the image they are then compared with (`app.py:5832-5839`, `:5919-5925`). | A field loaded from a spec keeps the spec's bytes (D9-11). |
| (none) | The Check Editor's JSON tab claims to show "the spec document those fields produce" (`screens_directionb.py:7189-7216`) but shows another shape (`"apply": false`, `size`, `name`; no `type`, `bytes`, expected bytes). | The tab shows the document Write would write (D9-13). |

---

## 3. Context notes (informative)

### CTX-CHECK · Running a check document (S9.1)

```text
check document   A change document (S8 CTX-CHGDOC) whose kind is check. Each entry
                 declares an address range and its expected bytes: the entry's
                 encoded bytes.
check run        One pass of a check document over the loaded image.
containment      inside · partial · outside · no image: S8's classification of an
                 entry's range against the image ranges.
outcome          pass · fail · uncheckable, one per entry.
reason pair      (reason code, reason text). Reason codes: doc-kind · doc-fault ·
                 entry-fault · partial · outside · no-image.
blocking fault   An ERROR finding (S8) whose code is none of CHG-ADDRESS-SYNTAX,
                 CHG-BYTES-SYNTAX, CHG-VALUE-EMPTY, CHG-ENCODE-FAIL, MF-ENTRY-LIMIT,
                 CHG-COLLISION, CHG-DECL-STRUCTURE.
blocked run      A run whose document has a kind other than check, or carries a
                 blocking fault. Kind is checked first.
tainted entry    An entry whose start address is the address of a CHG-COLLISION
                 ERROR finding (S8).
checked entry    An entry of a run that is not blocked, and that is not tainted.
aggregate counts passed · failed · uncheckable: the number of entries with each outcome.
kind display     The document kind as a quoted literal (control characters escaped),
                 at most 64 characters, then "…(capped)".
code list        The blocking finding codes: sorted, no repeats, at most 5, then
                 " +<k> more".
linkage          S8's linkage classification of an entry's range against the MAC
                 records and the A2L tags, with S8's linkage symbol (R-CHG-LINK.3);
                 informative only.
```

### CTX-CHECK-TEXT · How a run is shown (S9.2, S9.3)

```text
result row       0x<start>-0x<last> expected [<XX XX …>] actual [<XX XX …>] -> <outcome>
                 then " (<reason text>)" when the entry has a reason. Addresses in
                 uppercase hex without leading zeros; "actual [-]" when the range
                 was not read.
outcome colour   pass: green · fail: red · uncheckable: pale yellow (CTX-LEGEND, S3).
count line       Checks: <p> passed, <f> failed, <u> uncheckable
blocked line     Checks: not run — <run reason text> (<p> passed, <f> failed, <u> uncheckable)
check glyph      ✓ pass · ✗ fail · ◐ uncheckable · · not checked
patch strip      Line 1: ✓<p> ✗<f> ◐<u>. Line 2: an 8-cell bar filled in proportion
                 to passed / all entries; empty when the run has no entry.
current run      The last run started from the Patch Editor, while the document's
                 entries (type, address, bytes, in order) and the loaded image are
                 the ones it ran over. Undo and redo end it.
```

### CTX-CHECKS-SCREEN · The Checks screen (S9.3)

```text
Checks screen    Header "Checks" with the ? chip and the 📂 Open checks/ chip (S5, S7);
                 the aggregate line; the grouped list (border title "Checks",
                 subtitle "grouped") beside the hex peek (border title "Hex Peek").
aggregate line   Pass <p> / Fail <f> / Uncheck <u>  <8-cell bar, passed / all>
group order      fail, uncheckable, pass.
group header     <glyph> <LABEL>  (<count>)    LABEL: FAILED · UNCHECKABLE · PASSED
row cap          40 result rows across all groups.
hex peek window  The 16-byte rows from 6 rows before the row that holds the entry's
                 start address to 6 rows after it.
```

### CTX-CHECK-EDITOR · The Check Editor (S9.4)

```text
Check Editor     Rail screen. Header "Check Editor" with the ? chip and the
                 📂 Open checks/ chip. Left, "A2L PARAMETERS": Filter input, the
                 parameter ledger, the full-name line, Include parameter. Right,
                 "REPORT FIELDS": Fields, JSON and Addendum tabs. Below: the spec row
                 (Spec dropdown, Write as input), the action row (Validate,
                 Write .chk.json, the struck text "APPLY — not available"), the field
                 count, the hint "apply: n/a — check spec" and the legend.
parameter        An A2L tag with an integer address (S2).
ledger row       ✓ when included · Parameter · Address 0x<8 hex> · Fmt · Unit
                 (u<bits>, then the A2L unit when there is one).
memory row       Address (0x and hex digits, or decimal digits), Label (free text),
                 Size in bytes (1–8; empty means 1).
field            An included parameter (its address and byte size) or a memory row.
                 Order: included parameters in inclusion order, then memory rows.
declared field   A field whose whole range has bytes in the loaded image.
spec             The check document Write writes: one bytes entry per declared field,
                 in field order, kind check (S8 wire form). Expected bytes: D9-11.
check home       With an open project: <project>/checks/. Without: workarea/patches/
                 (S5 CTX-WORKAREA).
Fields tab       Head line: <n> field(s): <p> param(s) · <m> memory row(s).
                 One line per field: "◆ 0x<8 hex> <name>" for a parameter,
                 "▪ 0x<8 hex> <u8|u16|u32|u64|<n>B> <label>" for a memory row
                 ("memory row" when it has no label). Then MEMORY LOCATIONS (table
                 Address · Label · Fmt), the memory inputs, Add row, Remove row, the
                 status line and the verdict rows.
Addendum tab     "## Checks", then "· <n> fields → A2B diff report · apply: n/a —
                 check spec", then up to 6 lines "· 0x<address> <name>", then
                 "  … <k> more".
spec list        Every change document (*.json, not a link) of the check home, sorted
                 by name, each labelled " CHECK" (name ends .chk.json) or " PATCH".
legend           ✓ included   ◆ parameter field   ▪ memory-row field
```

---

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested**, **Yes; untested**, **Partly** / **No** with the decision.

### S9.1 · Running a check document (CTX-CHECK)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHK-001.1 | U | The system shall give each entry of a check run exactly one outcome: pass, fail or uncheckable. | Yes; tested. |
| R-CHK-001.2 | U | The system shall write nothing to the image during a check run. | Yes; tested. |
| R-CHK-001.3 | If | If the kind of the document to run is not `check`, then the system shall block the run with the reason code `doc-kind`. | Yes; tested. |
| R-CHK-001.4 | If | If a check document carries a blocking fault, then the system shall block the run with the reason code `doc-fault`. | Yes; tested. |
| R-CHK-001.5 | If | If a run is blocked, then the system shall give every entry the outcome uncheckable. | Yes; tested. |
| R-CHK-001.6 | If | If an entry of a run that is not blocked is tainted, then the system shall give it the outcome uncheckable. | Yes; tested. |
| R-CHK-001.7 | When | When the system checks a checked entry that is inside the image, the system shall compare its expected bytes with the image bytes of its range. | Yes; tested. |
| R-CHK-001.8 | When | When the image bytes of a checked entry equal its expected bytes, the system shall give the entry the outcome pass. | Yes; tested. |
| R-CHK-001.9 | When | When the image bytes of a checked entry differ from its expected bytes, the system shall give the entry the outcome fail. | Yes; tested. |
| R-CHK-001.10 | If | If a checked entry is partial, outside or has no image, then the system shall give it the outcome uncheckable. | Yes; tested. |
| R-CHK-001.11 | U | The system shall give each run its aggregate counts. | Yes; tested. |
| R-CHK-001.12 | U | The system shall classify the linkage of every entry of a run, whatever its outcome. | Yes. |
| R-CHK-002.1 | If | If a run is blocked with `doc-kind`, then the system shall give it the run reason text `this is a change-set (kind <kind display>), not a check-set — Run checks needs kind 'check'`. | Yes; tested. |
| R-CHK-002.2 | If | If a run is blocked with `doc-fault`, then the system shall give it the run reason text `document carries <n> error-severity declaration fault(s) [<code list>] — fix the document before running checks`, where n counts the blocking findings. | Yes; the code-list cap is tested. |
| R-CHK-002.3 | If | If a run is blocked, then the system shall give each entry the reason pair (`<run reason code>`, `run blocked [<run reason code>]`). | Yes; tested. |
| R-CHK-002.4 | If | If an entry is tainted, then the system shall give it the reason pair (`entry-fault`, `entry at 0x<start> carries [CHG-COLLISION] — see declaration faults`). | Yes; untested text. |
| R-CHK-002.5 | If | If a checked entry is partial, then the system shall give it the reason pair (`partial`, `range partially outside the loaded image [partial]`). | Yes; tested. |
| R-CHK-002.6 | If | If a checked entry is outside, then the system shall give it the reason pair (`outside`, `range outside the loaded image [outside]`). | Yes; tested. |
| R-CHK-002.7 | If | If no image is loaded, then the system shall give each checked entry the reason pair (`no-image`, `no image loaded`). | Yes; tested. |
| R-CHK-002.8 | When | When an entry's outcome is pass or fail, the system shall give it no reason. | Yes; tested. |

### S9.2 · Results in the Patch Editor (CTX-CHECK-TEXT)

The Run checks button and its help text are S10 (R-PATCH-CHECKS-CLARITY-001).

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHK-PE-001 | When | When a check run started from the Patch Editor ends, the system shall show one result row per entry, in document order, on the Checks tab. | Yes; tested. |
| R-CHK-PE-002 | When | When a check run started from the Patch Editor ends, the system shall colour each result row with its outcome colour. | Yes; tested. |
| R-CHK-PE-003 | When | When a check run that is not blocked ends, the system shall show the count line as the Checks tab status. | Yes; tested. |
| R-CHK-PE-004 | If | If a check run started from the Patch Editor was blocked, then the system shall show the blocked line as the Checks tab status. | Yes; tested. |
| R-CHK-PE-005 | When | When a check run started from the Patch Editor ends, the system shall show the patch strip on the Checks tab. | Yes; tested. |
| R-CHK-PE-006 | When | When a check run started from the Patch Editor ends, the system shall write its count line or blocked line to the status log. | Yes. |
| R-CHK-PE-007 | When | When a check run started from the Patch Editor ends, the system shall write one status line `[<code>] <severity>: <message>` per finding of the document. | Yes. |
| R-CHK-PE-008 | While | While the Checks tab is shown and a current run with n entries exists, the system shall show the inspector subtitle `<n> checked`. | Partly: a current run with 0 entries shows `no run yet` (D9-10). |
| R-CHK-PE-009 | While | While the Checks tab is shown and no current run exists, the system shall show the inspector subtitle `no run yet`. | Partly: a stale run keeps `<n> checked` (D9-10). |
| R-CHK-PE-010 | While | While no current run exists, the system shall show `No check run yet: press Run checks.` as the Checks tab status. | Partly: shown before any run and after undo or redo; a run made stale by another document or image stays (D9-10). |
| R-CHK-PE-011 | While | While no current run exists, the system shall show the patch strip with zero counts and an empty bar. | Partly: as R-CHK-PE-010 (D9-10). |
| R-CHK-PE-012 | While | While no current run exists, the system shall show no result row on the Checks tab. | Partly: as R-CHK-PE-010 (D9-10). |
| R-CHK-PE-013 | While | While a current run exists, the system shall lead each ledger row's Kind cell with the check glyph of that entry's outcome. | Yes; tested. |
| R-CHK-PE-014 | While | While no current run exists, the system shall lead each ledger row's Kind cell with `·`. | Yes; tested. |
| R-CHK-PE-015 | U | The system shall colour the check glyphs ✓ green, ✗ red, ◐ pale yellow and · grey. | Yes; tested. |
| R-CHK-PE-016 | U | The system shall show result rows and run reasons in the Patch Editor as plain text, never as markup. | Yes; tested. |

### S9.3 · The Checks screen (CTX-CHECKS-SCREEN)

With no file loaded the screen shows the empty state (S5 R-TUI-029.4).

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHKS-001 | When | When the operator opens the Checks screen, the system shall show the current run. | Partly: shows the last run even when it is not current (D9-10). |
| R-CHKS-002 | When | When a check run started from the Patch Editor ends, the system shall update the Checks screen. | Yes. |
| R-CHKS-003 | When | When the operator undoes or redoes a Patch Editor change, the system shall update the Checks screen. | Yes; tested. |
| R-CHKS-004 | If | If a file is loaded and no current run exists, then the system shall show the note `No check run yet — run checks from the Patch Editor.` in the grouped list. | Partly: a stale run is shown instead (D9-10); the no-run case is tested. |
| R-CHKS-005 | When | When the Checks screen shows a current run, the system shall group its result rows by outcome in the group order. | Yes; tested. |
| R-CHKS-006 | When | When the Checks screen shows a current run, the system shall lead each non-empty group with its group header. | Yes; tested. |
| R-CHKS-007 | When | When the Checks screen shows a current run, the system shall colour each group header and result row with the group's outcome colour. | Yes; tested. |
| R-CHKS-008 | When | When the Checks screen shows a current run, the system shall show the aggregate line above the grouped list. | Yes; tested. |
| R-CHKS-009 | While | While no current run exists, the system shall show the aggregate line with zero counts and an empty bar. | Partly: as R-CHKS-001 (D9-10); the cleared state is tested. |
| R-CHKS-010 | If | If a current run holds more than 40 entries, then the system shall show the first 40 result rows in group order and the note `More check entries than shown — see the Patch Editor.` | Yes; tested. |
| R-CHKS-011 | If | If a current run holds no entry, then the system shall show the note `No check entries to group.` | Yes; untested. |
| R-CHKS-012 | When | When a result row's entry is linked, the system shall show the entry's linkage symbol in a cell beside the row. | Yes; tested. |
| R-CHKS-013 | When | When the operator activates a result row by click or Enter, the system shall show the hex peek window of that entry's start address. | Yes; tested. |
| R-CHKS-014 | U | The system shall show reasons and linkage symbols on the Checks screen as plain text, never as markup. | Yes; tested. |

### S9.4 · The Check Editor (CTX-CHECK-EDITOR)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-CHKED-001 | When | When the operator opens the Check Editor, the system shall list in the ledger every parameter of the loaded A2L, one row each. | Yes; tested. |
| R-CHKED-002 | If | If no A2L is loaded, then the system shall show the line `No A2L parameters — load an A2L (^L) to list them.` under the ledger. | Yes; tested. |
| R-CHKED-003 | When | When the operator types in Filter, the system shall list only the parameters whose name contains the filter text, ignoring case. | Yes. |
| R-CHKED-004 | If | If no parameter matches the filter, then the system shall show the line `No parameter matches the filter.` under the ledger. | Yes; untested. |
| R-CHKED-005 | U | The system shall show every ledger address in full. | Yes; tested. |
| R-CHKED-006 | If | If a parameter name is wider than its column, then the system shall show its first dot-separated part, one `…` and the end of the name that fills the column. | Yes; tested. |
| R-CHKED-007 | When | When the operator highlights a ledger row, the system shall show its address, its Fmt · Unit and its name on the full-name line. | Yes; tested. |
| R-CHKED-008 | When | When the operator presses Include parameter, space or Enter on a ledger row, the system shall toggle that parameter's inclusion. | Yes; tested. |
| R-CHKED-009 | U | The system shall mark each included parameter with `✓` in the ledger. | Yes; tested. |
| R-CHKED-010 | When | When the operator returns to the Check Editor, the system shall keep included every parameter that the loaded A2L still lists. | No: every screen entry and every Write clears the included parameters (D9-12). |
| R-CHKED-011 | When | When the operator presses Add row, the system shall add a memory row from the Address, Label and Size inputs. | Yes; tested. |
| R-CHKED-012 | If | If the Address input is not `0x` followed by hex digits, or decimal digits, then the system shall refuse the memory row with the Fields status `Check Editor: bad memory address '<text>'.` | Partly: a leading `+` and `_` between digits pass today (D9-17). |
| R-CHKED-013 | If | If the Size input is a number outside 1–8, then the system shall refuse the memory row with the Fields status `Check Editor: size must be 1..8 bytes, got <n>.` | Yes. |
| R-CHKED-014 | If | If the Size input is not empty and not a number, then the system shall refuse the memory row with the Fields status `Check Editor: bad size '<text>'.` | No: the size becomes 1 (D9-16). |
| R-CHKED-015 | When | When the operator presses Remove row, the system shall remove the highlighted memory row. | Yes. |
| R-CHKED-016 | When | When the field set changes, the system shall show the Fields tab lines of CTX-CHECK-EDITOR. | Yes; tested. |
| R-CHKED-017 | If | If no field is included, then the system shall show `No fields included yet.` under the Fields head line. | Yes; tested. |
| R-CHKED-018 | When | When the field set changes, the system shall show the field count `<n> field(s) → report` in the action row. | Yes; tested. |
| R-CHKED-019 | When | When the operator opens the JSON tab, the system shall show the spec that Write would write. | No: shows a different document shape, without expected bytes (D9-13). |
| R-CHKED-020 | If | If the JSON tab text is longer than 5000 lines, then the system shall show its first 5000 lines and the line `showing 5000 of <N> lines`. | Yes; tested. |
| R-CHKED-021 | When | When the field set changes, the system shall show the Addendum tab text of CTX-CHECK-EDITOR. | Yes. |
| R-CHKED-022 | U | The system shall offer no apply action in the Check Editor. | Yes; tested. |
| R-CHKED-023 | U | The system shall show the struck text `APPLY — not available` in the Check Editor's action row. | Yes. |
| R-CHKED-024 | When | When the operator presses Write .chk.json, the system shall write the spec of the declared fields. | Yes; tested. |
| R-CHKED-025 | When | When the system builds a spec, the system shall take as the expected bytes of a field included in this session the image bytes of its range. | Yes; tested. |
| R-CHKED-026 | When | When the system builds a spec, the system shall take as the expected bytes of a field loaded from a spec the bytes that spec declared. | No: re-read from the image (D9-11). |
| R-CHKED-027 | If | If a field is not a declared field, then the system shall leave it out of the spec. | Yes. |
| R-CHKED-028 | If | If fields were left out of a spec, then the system shall show the status `Check Editor: <k> field(s) outside the loaded image — not declared.` | Yes; untested. |
| R-CHKED-029 | When | When the operator writes a spec, the system shall name it after the Write as input, or `spec.chk.json` when the input is empty. | Yes. |
| R-CHKED-030 | If | If the Write as name does not end with `.chk.json`, then the system shall append `.chk.json` to it. | No: `.json` is appended, and the spec lists as PATCH (D9-14). |
| R-CHKED-031 | When | When the operator writes a spec, the system shall place it in the check home. | Partly: always `workarea/patches/`, also with a project (D9-15). |
| R-CHKED-032 | When | When a spec is written, the system shall show the status `Check Editor: wrote <name> (<n> fields, kind=check).` | Yes. |
| R-CHKED-033 | When | When a spec is written, the system shall refresh the spec lists of the Check Editor, the Patch Editor and the A2B Diff screen. | Yes; tested. |
| R-CHKED-034 | If | If the writer refuses a spec, then the system shall show the status `Check Editor: spec NOT written.` | Yes. |
| R-CHKED-035 | If | If the writer refuses a spec, then the system shall show `Write refused: <codes>.` as the Fields status. | Yes; tested. |
| R-CHKED-036 | When | When the operator presses Validate, the system shall run the spec that Write would write against the loaded image. | Yes; tested. |
| R-CHKED-037 | When | When a Validate run ends, the system shall show one result row per entry, coloured by outcome, under the memory form. | Yes; tested. |
| R-CHKED-038 | When | When a Validate run ends, the system shall show `validation complete` as the Fields status. | Yes. |
| R-CHKED-039 | When | When a Validate run ends, the system shall write its count line to the status log. | Yes. |
| R-CHKED-040 | When | When the operator opens the Check Editor or writes a spec, the system shall fill the Spec dropdown with the spec list. | Partly: lists `workarea/patches/` only (D9-15); tested. |
| R-CHKED-041 | When | When the operator picks a spec, the system shall replace the included parameters and the memory rows with one memory row per entry of the spec. | Yes; tested. |
| R-CHKED-042 | When | When the operator picks a spec, the system shall set the Write as input to the spec's name ending in `.chk.json`. | Yes. |
| R-CHKED-043 | When | When the operator picks a spec, the system shall show the status `Check Editor: loaded '<name>' (<n> fields).` | Yes. |
| R-CHKED-044 | If | If the picked file is a link or lies outside its folder, then the system shall refuse it with the status `Check Editor: file '<name>' is outside the patches folder — not loaded.` | Yes. |
| R-CHKED-045 | If | If the picked file carries an ERROR finding, then the system shall write one status line `[<code>] <severity>: <message>` per finding. | Yes. |
| R-CHKED-046 | If | If the picked file carries an ERROR finding, then the system shall refuse it with the status `Check Editor: spec NOT loaded.` | Yes. |
| R-CHKED-047 | If | If the picked document's kind is not `check`, then the system shall refuse it with the status `Check Editor: '<name>' is a kind='<kind>' document — not a check spec.` | Yes. |
| R-CHKED-048 | U | The system shall show parameter names, labels and file names in the Check Editor as plain text, never as markup. | Yes; tested. |
| R-CHKED-049 | While | While the Check Editor is shown at 118 × 54 or more, the system shall show Validate and Write .chk.json without scrolling. | Yes; tested. |
| R-CHKED-050 | While | While the Check Editor is shown below 118 × 54, the system shall keep every control reachable by scrolling. | Yes; tested. |
| R-CHKED-051 | U | The system shall show every Check Editor button as a one-row chip. | Yes; tested. |
| R-CHKED-052 | U | The system shall give Write .chk.json the only filled style of the Check Editor. | Yes; tested. |
| R-CHKED-053 | U | The system shall show the Check Editor legend of CTX-CHECK-EDITOR under the action row. | Yes. |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D9-1 | R-CHK-001 / 002 carry the result data class, construction flags, test names, batch-33 before/after and "frozen-engine diff". | Out of the requirements; the batch records keep them. Observable rows only. |
| D9-2 | "Same v2 schema family, one reader, one rule set": the format, the reader, containment and linkage are S8's. | CTX-CHECK cites S8; S9 rows start from a read document. |
| D9-3 | The Patch Editor Checks tab, the Checks screen and the Check Editor have no row in S9. Their text is HLR-009, HLR-011, HLR-145 and LLR-009.x, 011.x, 145.x in S0's table; HLR-084 (Checks screen) never entered the requirements. | Rows written here (S9.2 … S9.4); pointers left in S0 (rule D-9, the S1 D-10 precedent). |
| D9-4 | Picking a spec replaces the collector's fields without asking (`screens_directionb.py:7092-7100`). | Keep: the collector is a scratch builder and the written spec is the artifact. R-CHKED-041 states it. |
| D9-5 | The doc-fault reason counts findings (`check.py:321`) while its code list drops repeats (`check.py:186`). | Keep; R-CHK-002.2 says what n counts. |
| D9-6 | The Check Editor's Validate does not feed the Checks screen, which mirrors only Patch Editor runs (`app.py:3594`, `:3835`). | Keep; "current run" is defined as a Patch Editor run. |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D9-7 | `run_checks_for_project` (`change_service.py:3163`): only the headless project-run test of `tests/test_checks_engine.py` called it (both deleted in batch-101 Inc 4); flows and variant execution call the engine directly. | Delete it and its test. |
| D9-8 | `#check_preview_toggle_button` is mounted and never displayed (`screens_directionb.py:7539-7545`); the Addendum tab carries its function. | Delete the widget and its handler (`:7640-7642`). |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D9-10 | The ledger glyphs refuse a run whose document or image changed (`change_service.py:3018-3023`), but the Checks tab rows, status, strip and subtitle and the Checks screen keep showing it (`check_rows` `:2799`, `check_display_rows` `:2878` read `last_check_result` only; load and paste do not reset it). The hex peek then reads the new image (`app.py:11443`). A 0-entry run shows `no run yet` (`screens_directionb.py:6670`). | One "current run" rule for every surface (CTX-CHECK-TEXT): a stale run shows the no-run state (R-CHK-PE-008 … 012, R-CHKS-001, 004, 009). |
| D9-11 | Write and Validate take every field's expected bytes from the loaded image (`app.py:5832-5839`), then Validate compares them with that image (`:5919`): Validate can never fail, and loading a spec then writing it silently re-baselines it. | A field loaded from a spec keeps the spec's bytes; only new fields take the image's (R-CHKED-025, 026). Validate then answers "does this image still match the spec?". |
| D9-12 | `set_a2l_parameters` clears the included parameters (`screens_directionb.py:7071`) and runs on every screen entry (`app.py:7476`) and after every Write (`:5915`). | Keep the included parameters the new list still holds (R-CHKED-010). |
| D9-13 | The JSON tab builds its own document (`"apply": false`, `size`, `name`, `screens_directionb.py:7198-7215`); Write writes another (`type`, `address`, `bytes` with expected bytes, `app.py:5843-5855`). | Show the document Write would write, serialised by S8's writer (R-CHKED-019). |
| D9-14 | `Write as: myspec` is written as `myspec.json` (S8 `_safe_name`, `io.py:1657-1658`), which the lists label PATCH. | Append `.chk.json` when missing (R-CHKED-030). |
| D9-15 | With a project open, Write puts the spec in `workarea/patches/` (no `dest_dir`, `app.py:5894`) and the Spec dropdown lists that folder only (`:5796`), while the 📂 Open checks/ chip and the Patch Editor's Save use `<project>/checks/` (HLR-138). | One check home for writing, listing and the chip (CTX-CHECK-EDITOR; same decision in S10, D10-25). |
| D9-16 | A Size that is not a number silently becomes 1 (`screens_directionb.py:7682-7685`). | Refuse it with `Check Editor: bad size '<text>'.` (R-CHKED-014). |
| D9-17 | The memory Address takes `int(text, 16)` after `0x` and `int(text, 10)` otherwise (`:7669-7671`): a leading `+` and `_` between digits pass, against S1 decision 1. | `0x` and hex digits, or decimal digits only (R-CHKED-012). Same rule as the Patch Editor's Address field (S10, D10-27). |

**Prototype first** (visual; prototype round with real captures and the operator's verdict before implementation)

| # | The situation | What the round must answer |
|---|---|---|
| D9-20 | One run, two strip formats: the Patch Editor's `✓2 ✗1 ◐1` with the bar on a second line, the Checks screen's `Pass 2 / Fail 1 / Uncheck 1  ████░░░░`. | One aggregate form for both surfaces, or a reason to keep two. |

**Passed to other groups**

- **S0**: pointers from HLR-009, HLR-011, HLR-145 (and their LLRs) to S9.4; HLR-084 (Checks screen) is now S9.3.
- **S1**: the Check Editor and the Patch Editor's Checks tab join the safe-text views (R-CHKED-048, R-CHK-PE-016). The Checks screen is already listed as "the Checks view".
- **S3**: CTX-LEGEND has no block for check outcomes (✓ ✗ ◐ ·, green / red / pale yellow / grey) nor for the Spec dropdown's CHECK / PATCH labels; add them so one legend covers every colour-coded surface.
- **S6**: the Checks screen and Check Editor rail positions and keys.
- **S7**: the Check Editor's window help entry.
- **S8**: containment, linkage, the finding codes, the wire form of a spec, and the apply gate that refuses a check document. The `.chk.json` suffix rule may sit in the writer instead of the Check Editor (D9-14).
- **S10**: R-PATCH-CHECKS-CLARITY-001 (the Run checks help) and the Run checks button; the ledger that carries the check glyphs.
- **S11 / S15**: variant execution and the flow CHECK step run the same engine; their outcomes follow S9.1.
- **S14**: the A2B Diff addendum built from a spec (HLR-010); the Addendum tab previews it.

**Received from other groups** (absorbed here)

- **S8**: check documents share CTX-CHGDOC and the linkage rule R-CHG-LINK.3 → CTX-CHECK cites both. `CheckRunResult.to_dict` goes (D8-16) → no S9 row uses it.
- **S11**: R-VAR-002.28 runs a check document's checks (S9) → its outcomes are S9.1's; no new row.
- S1 … S5 passed nothing to S9.

**Received from later groups** (after all groups were written)

- S9.1 (S8: CTX-CHGDOC, R-CHG-LINK.3, D8-16) → covered by the block above (CTX-CHECK cites both; no row uses `to_dict`).
- S9.2 (S10: the check run on the Checks tab and the ledger glyphs) → covered by S9.1 and S9.2 (R-CHK-PE-008 … 016; glyphs R-CHK-PE-013, .15); the Run checks help stays S10's.
- S9.3 (S14: the check-spec folder) → covered by D9-15 and R-CHKED-031 (the check home of CTX-CHECK-EDITOR); S14 R-DIFF-CHK.1 lists the same folder (D14-17).
- S9.4 (S15: CHECK runs the S9.1 engine) → covered by S9.1; S15 R-FLOW-CHECK.1 cites it.

---

## 6. Counts

| | Old S9 | Strict |
|---|---:|---:|
| Requirement statements | 2 rows (one with a batch amendment record) | 103 rows |
| Statements the code contradicts or that are not product behaviour | 2 (both rows mix process and design; the headless entry point is test-only) | 0 |
| Rows by form: U / When / While / If / Where | — | 15 / 45 / 10 / 33 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Decisions | — | 17 (6 follow the code or move, 2 remove, 8 correct a defect, 1 prototype first; numbers not contiguous) |

Checked by script (`ears_lint.py`): one `shall` per row, correct opening words per form, `If … then`, no "unless" / "only if", final period, no repeated id across review files.
