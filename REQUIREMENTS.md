# Requirements — s19_app

Status: the requirements canon. Built 2026-11-01 from the strict EARS review reconciled with s19_app e279c8b (batch-100 closed); it replaces the earlier canon of e273181.

This file holds every requirement of s19_app as one strict EARS sentence, grouped in 18 modules (S0 … S17). Each module gives its **context notes** first (terms, formats and lists the rows use; a note never says what the system does) and then its **requirements**, one row each: `| Id | Form | Requirement |`.

- **Rationale and code state:** the reasons for each wording (the module's decisions `D<n>-k`), what the old text said, and whether the code meets each row today (the "Code today" column) are in `docs/requirements/review/S<n>-ears-strict.md`, a snapshot as of s19_app e273181: its "Code today" column is not kept current. A `D<n>-k` cited in a note refers to that file.
- **Earlier canon:** the text this file replaced is kept verbatim in `docs/requirements/history/`. Every retired batch id (HLR-/LLR-) maps to the rows that absorbed it in S0's table (S0.2). Section references in code comments (for example `§3`, `§6.5 Amendment F-1`) point to that earlier file.
- **Changing a requirement:** edit the row here, in place, through a dev-flow increment; a split keeps the parent id with `.1`, `.2`; a new row gets a new id in the module's prefix. Rows are checked by `tests/test_requirements_canon.py`.

## Rules for every row


- **E1 · Form.** Each row is exactly one of:
  - `The system shall <response>.` (ubiquitous: always true)
  - `When <event>, the system shall <response>.` (something happens at a point in time)
  - `While <state>, the system shall <response>.` (a state of the system that lasts)
  - `If <unwanted condition>, then the system shall <response>.` (a defect in the input, a missing file, a bad argument)
  - `Where <feature>, the system shall <response>.` (a feature a build or configuration may include or leave out)
  The subject is always "the system", never "it", "the loader" or "the parsed record".
- **E2 · Singular.** One `shall`, one verb, one object. No second sentence, no "and" between two responses, no "only if" or "unless" inside the response. An "only when" becomes two rows (one says when it happens, one says when it does not).
- **E3 · Alternatives in a condition.** A condition may list alternatives of the same kind ("type 03 or type 05") only when every alternative gets exactly the same response; each alternative is one test case. Where the response differs by format (S19 vs Intel HEX), the row is split. A condition may also join facts with "and" when all must hold at once (R-READ-006.1: the tally is at most 0xFFFF **and** differs from the S5 count). Each still has one response.
- **E4 · Pattern meaning.** `While` is for a state of the system (the address base the reader is using), never for a property of a record or a line. `Where` is for an optional feature, never for a command option: a command option is an event (`When the operator runs dump-by-range with --output <path>`). S1 has no optional feature, so no row uses `Where`.
- **E5 · Exact text.** A row that produces a message fixes its exact text, with `<placeholders>`, so a test can compare it.
- **E6 · Context notes define, rows require.** A context note holds terms, formats and lists that rows cite. Any sentence in a note that says what the system *does* moves to a row.
- **E7 · Ids.** A row split from an existing row keeps its id with `.1`, `.2` …; a new row gets a new id. Renumbering is for the batch.

---


Form column: U = ubiquitous; When = event; While = state; If = unwanted behaviour; Where = optional feature.

## Modules

| Module | Name | Rationale |
|---|---|---|
| [S0](#s0) | Project, documentation & process meta | [S0-ears-strict.md](docs/requirements/review/S0-ears-strict.md) |
| [S1](#s1) | S19 / Intel HEX reading & parsing | [S1-ears-strict.md](docs/requirements/review/S1-ears-strict.md) |
| [S2](#s2) | A2L & MAC symbols | [S2-ears-strict.md](docs/requirements/review/S2-ears-strict.md) |
| [S3](#s3) | Validation, issues & classification legend | [S3-ears-strict.md](docs/requirements/review/S3-ears-strict.md) |
| [S4](#s4) | Hex view & Memory Map | [S4-ears-strict.md](docs/requirements/review/S4-ears-strict.md) |
| [S5](#s5) | Workspace & file I/O | [S5-ears-strict.md](docs/requirements/review/S5-ears-strict.md) |
| [S6](#s6) | TUI shell, navigation & layout | [S6-ears-strict.md](docs/requirements/review/S6-ears-strict.md) |
| [S7](#s7) | Modal dialogs, input widgets & window help | [S7-ears-strict.md](docs/requirements/review/S7-ears-strict.md) |
| [S8](#s8) | Change documents, apply & save-back | [S8-ears-strict.md](docs/requirements/review/S8-ears-strict.md) |
| [S9](#s9) | Checks | [S9-ears-strict.md](docs/requirements/review/S9-ears-strict.md) |
| [S10](#s10) | Patch Editor | [S10-ears-strict.md](docs/requirements/review/S10-ears-strict.md) |
| [S11](#s11) | Projects, variants & manifest | [S11-ears-strict.md](docs/requirements/review/S11-ears-strict.md) |
| [S12](#s12) | Project reports | [S12-ears-strict.md](docs/requirements/review/S12-ears-strict.md) |
| [S13](#s13) | Operations & CRC | [S13-ears-strict.md](docs/requirements/review/S13-ears-strict.md) |
| [S14](#s14) | A↔B compare & diff reports | [S14-ears-strict.md](docs/requirements/review/S14-ears-strict.md) |
| [S15](#s15) | Flow engine | [S15-ears-strict.md](docs/requirements/review/S15-ears-strict.md) |
| [S16](#s16) | Flow Builder UI | [S16-ears-strict.md](docs/requirements/review/S16-ears-strict.md) |
| [S17](#s17) | Split / Join / Export | [S17-ears-strict.md](docs/requirements/review/S17-ears-strict.md) |


<a id="s0"></a>

## S0 · Project, documentation & process meta

### Context notes (informative)

#### CTX-README · The README (S0.1)

```text
README          README.md at the top of the delivered source tree. It is also the
                package's long description (pyproject.toml:36).
window          A window of S6 CTX-SHELL: the twelve rail windows and Split / Join /
                Export.
key             A key of S6 CTX-KEYS.
```

#### CTX-RETIRED · Classes of a retired batch id (S0.2)

```text
batch id        An HLR-<n> or LLR-<n>.<m> row of the table under "Retired ids"
                (the earlier canon's table of batch ids). An LLR takes the class of
                its HLR and is listed on the HLR's line.
S<n>: <ids>     Rows of review/S<n>-ears-strict.md.
absorbed        Review rows cover the HLR's behaviour. A fragment that no row covers is
                named "Residual" in the note and passed to its owner (section 5).
retired         The HLR records process, history, code placement, a test method or
                tool, or behaviour that was superseded or deleted.
gap             The behaviour is in the code today and no review row covers it. Listed
                with its owner group; S0 writes no row for another group.
batch-100 id    An HLR-<n> (with its letter) or LLR-<n>.<m> of batch-100's
                .dev-flow/2026-10-26-batch-100/01-requirements.md, HLR-163 …
                HLR-178. It takes the same classes as a batch id (D0-13).
AT-B100-NN,     The acceptance and test-case ids of batch-100 (tests/test_b100_*.py).
TC-B100-NN
```

---

#### CTX-CANON · The requirements file (S0.3)

```text
CTX-CANON  The requirements file
  form           One of U, When, While, If, Where.
  opening words  U      "The system shall "
                 When   "When <event>, the system shall "
                 While  "While <state>, the system shall "
                 If     "If <condition>, then the system shall "
                 Where  "Where <feature>, the system shall "
  module         One of S0 … S17, named in the file's module table.
  obligation word  The modal word that the opening words of every form
                 contain, written in lower case.
  one sentence   No full stop followed by a space and a capital letter
                 outside a `code span`.
```

### Requirements


#### S0.1 · The README (CTX-README; from S0 HLR-123)

| Id | Form | Requirement |
|---|---|---|
| R-DOC-README.1 | U | The system shall include a README that gives the steps to install the system and the command that starts the TUI. |
| R-DOC-README.2 | U | The system shall describe each window of CTX-README in its README. |
| R-DOC-README.3 | U | The system shall list each key of CTX-README in its README with its action. |
| R-DOC-README.4 | U | The system shall describe in its README no window, key, command or file that the system does not provide. |

#### S0.2 · Retired batch ids: where each lives now (CTX-RETIRED)

The table below replaces the earlier canon's table of batch ids. It holds no requirement: each line is a pointer. A second table after it points the batch-100 ids (D0-13).

| Id | Where it lives now | Note |
|---|---|---|
| HLR-001 · LLR-001.1 … .4 | **retired** | Code placement (batch-92 move of the hex renderer to `s19_app/render/hexview.py`). Hex rows are S4.1. |
| HLR-002 · LLR-002.1 … .3 | **retired** | Code placement (range-index re-exports removed). |
| HLR-003 · LLR-003.1 … .3 | **retired** | Code placement (`safe_text` moved to `s19_app/utils.py`). The safe-text behaviour is S1: R-TUI-103 … 103b. |
| HLR-004 · LLR-004.1 … .3 | **retired** | Code placement (palette constants moved to `s19_app/render/format.py`). Colours are S3 CTX-LEGEND and S6 CTX-THEME. |
| HLR-005 · LLR-005.1, .2 | **absorbed** · S10: R-PE-012 … R-PE-019 | Unsaved-changes popup; a dropdown pick is guarded since batch-100 Inc 10 (R-PE-016, S10 D10-45; D10-20 done). |
| HLR-006 · LLR-006.1, .2 | **retired** | Deleted behaviour: the variant dropdown and variant help were removed in batch-94 (S10 D10-4). |
| HLR-007 · LLR-007.1, .2 | **absorbed** · S10: R-PE-080, R-PE-081 | The apply itself is S8.5. |
| HLR-008 · LLR-008.1, .2 | **absorbed** · S10: R-PE-010, R-PE-011, R-TUI-052.1 … .3 | Refresh rescans the folder (D10-5). |
| HLR-009 · LLR-009.1 … .3 | **absorbed** · S9: R-CHKED-001 … R-CHKED-053 | The Check Editor, S9.4 (D9-3). |
| HLR-010 · LLR-010.1, .2 | **absorbed** · S14: R-DIFF-CHK.1 … R-DIFF-CHK.11 | Check-spec addendum of the diff report, S14.6 (D14-6). |
| HLR-011 · LLR-011.1, .2 | **absorbed** · S9: R-CHKED-048 | Plain text on the Check Editor (S1 CTX-TEXT). |
| HLR-012 · LLR-012.1, .2 | **absorbed** · S3: R-VAL-032 | S3 replaces the INFO re-label: standard block names raise no issue (D3-12). |
| HLR-013 · LLR-013.1 … .3 | **retired** | Superseded by HLR-146 (one row of cards, S16 D16-3). LLR-013.3 (A2B diff block) is S15: R-FLOW-A2B.1 … .11. |
| HLR-014 · LLR-014.1, .2 | **absorbed** · S15: R-FLOW-A2B.1 … R-FLOW-A2B.11; S16: R-FB-ADD.1 … R-FB-ADD.18 | A2B diff block inputs and provenance. |
| HLR-015 · LLR-015.1, .2 | **absorbed** · S15: R-FLOW-FILE.1 … R-FLOW-FILE.10; S16: R-FB-SAVE.1 … R-FB-LOAD.11 | Flow files. |
| HLR-016 · LLR-016.1 | **absorbed** · S16: R-FB-RIB.3, R-FX-SCR.3 | Plain text on the flow screens. |
| HLR-017 · LLR-017.1, .2 | **absorbed** · S16: R-FX-SCR.1 … R-FX-LANE.12 | Lanes, S16.7. |
| HLR-018 · LLR-018.1, .2 | **absorbed** · S16: R-FX-SCR.1 … R-FX-LANE.12; S15: R-FLOW-CHAIN.1 … R-FLOW-CHAIN.10 | Inputs bound per chain. |
| HLR-019 · LLR-019.1, .2 | **absorbed** · S15: R-FLOW-CHAIN.1 … R-FLOW-CHAIN.10; S16: R-FX-RUN.1 … R-FX-RUN.14 | Sequential and parallel runs; the screen freezes during a run (S16 D16-15). |
| HLR-020 · LLR-020.1, .2 | **absorbed** · S16: R-FX-RUN.1 … R-FX-RUN.14; S15: R-FLOW-CHAIN.11 … R-FLOW-CHAIN.18 | Run log and chain-set report. |
| HLR-021 · LLR-021.1, .2 | **absorbed** · S15: R-FLOW-SET.1 … R-FLOW-SET.6; S16: R-FX-SET.1 … R-FX-SET.14 | Chain-set files. |
| HLR-122 · LLR-122.1 … .5 | **retired** | Process: adopting existing tests into the id registry (batch-91). Its LLRs name behaviour the group files now hold (parsers S1 and S8, A2L and MAC S2, screens S4 … S12); LLR-122.4 is S13.6 … S13.8. |
| HLR-123 | **absorbed** · S0: R-DOC-README.1 … R-DOC-README.4 | README part only; the developer documents are process (D0-7). |
| HLR-124 · LLR-124.1, .2 | **retired** | Process: id-registry hygiene (AT-043, token renames, reserved id blocks). |
| HLR-125 · LLR-125.1, .2 | **absorbed** · S4: R-TUI-074.2, R-TUI-062.10, R-MAP-PANE.1, R-MAP-PANE.2 | Inspector and map pane titles and subtitles; the pane look is design. |
| HLR-126 · LLR-126.1 … .4 | **absorbed** · S4: R-TUI-061.4 … .6, R-TUI-062.1 … .6, R-TUI-073.1, R-TUI-074.1 … .11 | Layout, first region selected, keyboard and mouse. |
| HLR-127 · LLR-127.1 … .4 | **absorbed** · S4: R-TUI-073.1 … .4, R-TUI-062.1 … .5 | Region rows (CTX-MAP); aligned columns are No today (D4-23). |
| HLR-128 · LLR-128.1 | **absorbed** · S4: R-TUI-074.6 … .8 | Peek rows. |
| HLR-129 · LLR-129.1 … .3 | **absorbed** · S4: R-TUI-041.1 … .4, R-TUI-061.1 | Stats line (in view at every scroll position of the region list) and band chips. |
| HLR-130 · LLR-130.1, .2 | **retired** | Test method: the wrap-audit harness. No-overflow rows are S4: R-TUI-103B.5, R-TUI-073.4. |
| HLR-131 · LLR-131.1 … .3 | **absorbed** · S4: R-TUI-061.4 … .6, R-TUI-103B.1, R-TUI-074.7 | Reflow by panel width. |
| HLR-132 · LLR-132.1 … .4 | **absorbed** · S3: R-LEGEND-MAP.1 … .5, R-LEGEND-MODAL-001.8; S4: R-TUI-062.10 | The Memory Map legend sheet (S3 CTX-LEGEND "map sheet", D3-27); its key line is S4's. |
| HLR-133 · LLR-133.1 | **retired** | History: a rule on one batch's diff (no command bar on the map). Find and go-to windows are S6 CTX-KEYS, S4 R-TUI-040.1. |
| HLR-134 | **absorbed** · S3: R-LEGEND-MAP.1 | Title `Map keys` of the sheet's fourth box (S3 CTX-LEGEND "map sheet"). |
| HLR-135 · LLR-135.1 … .7 | **absorbed** · S17: R-SEG-OPEN.1 … .6, R-SEG-SRC.1 … .20, R-SEG-MAN.1 … .9, R-SEG-PREV.1 … .19 | Widths, colours, CSS and SVG frames are out (S17 D17-2). |
| HLR-136 · LLR-136.1 … .6 | **absorbed** · S17: R-SEG-SET.1 … .14, R-SEG-PREV.1 … .19, R-SEG-OUT.1 … .18, R-SEG-EXP.1 … .14 | Split and join content; preview encoding. |
| HLR-137 · LLR-137.1 … .4 | **absorbed** · S17: R-SEG-OUT.1 … .18; S2: R-A2L-036.1 … .6 | The engine recipe is out (S17 D17-3); LLR-137.4 is S2's. |
| HLR-138 · LLR-138.1 … .4 | **absorbed** · S11: R-PROJ-GATHER.1 … R-PROJ-GATHER.9 | The gather, S11.4 (D11-9). |
| HLR-139 · LLR-139.1 … .3 | **absorbed** · S5: R-CHIP-001.1 … .11; S12: R-RPT-CHIP.1; S13: R-CRC-TEMPLATE-001.17 | Open-folder chips (S5 D5-35). |
| HLR-140 · LLR-140.1, .2 | **absorbed** · S7: R-WHELP.1 … R-WHELP.15 | Window help, S7.4. |
| HLR-141 · LLR-141.1, .2 | **absorbed** · S8: R-CHG-SYM.1 … R-CHG-SYM.10 | The Patch Editor symbol input (LLR-141.2) is deferred (S10 D10-13, D10-42). |
| HLR-142 · LLR-142.1, .2 | **absorbed** · S15: R-FLOW-SRC.1 … .10, R-FLOW-PATCH.4; S16: R-FB-ADD.17 | The Builder's A2L field is prototype first (S16 D16-25). |
| HLR-143 · LLR-143.1, .2 | **absorbed** · S15: R-FLOW-RPT.1 … .14; S14: R-DIFF-FLOWCHG.1 … .8 | Flow report and flow changes in the diff report. |
| HLR-144 · LLR-144.1 … .12 | **absorbed** · S10: R-TUI-063.1 … R-TUI-049.3 | The Patch Editor, S10.1 … S10.8 (D10-3, D10-12). |
| HLR-145 · LLR-145.1 … .10 | **absorbed** · S9: R-CHKED-001 … R-CHKED-053 | The Check Editor, S9.4. |
| HLR-146 · LLR-146.1 … .14 | **absorbed** · S16: R-TUI-059.20 … R-FB-PIPE.5 | The Flow Builder, S16.1 … S16.3. |
| HLR-147 · LLR-147.1 … .13 | **absorbed** · S16: R-FX-SCR.1 … R-FX-WAIT.13 | Flow Execution, S16.7 … S16.9. |
| HLR-148 · LLR-148.1 … .10 | **absorbed** · S5: R-CHIP-001.1 … .11; S7: R-WHELP.1 … .15; S9: R-CHKED-002, R-CHKED-017; S10: R-PE-060, R-PE-073; S16: R-FB-RUN.1 | Chips, help entries, empty-state lines. Glyph vocabularies (LLR-148.7) are design. |
| HLR-149 · LLR-149.1 … .6 | **absorbed** · S10: R-TUI-064.1 … .3; S9: R-CHKED-049, R-CHKED-050; S16: R-FB-RIB.5, R-FB-RIB.6, R-FX-SIZE.1, R-FX-SIZE.2 | The four editor windows at 118 × 54 or more and below it. |
| HLR-150 · LLR-150.1 … .7 | **absorbed** · S7: R-KEYBAR.1 … R-KEYBAR.15 | The key bar, S7.5. |
| HLR-151 · LLR-151.1 | **absorbed** · S7: R-LOADDLG.1, R-LOADDLG.54, R-LOADDLG.60, R-LOADDLG.70 | LLR-151.1 (the Load project dialog) is superseded by batch-100 HLR-173 (Inc 9b): the one Load dialog, S7.2. S11 R-TUI-013.4 is retired (S11 D11-55). |
| HLR-152 · LLR-152.1 … .3 | **retired** | Test tooling: the corpus generator `tests/fixtures/synth/generate.py` is not delivered. |
| HLR-153 · LLR-153.1 … .4 | **absorbed** · S1: R-IMG-006; S8: R-IMG-WRITE.1, R-S19-S0HEADER-001.1 | Image from data records; a written image keeps the source S0 (S8 D8-27; exports: S17 D17-33). |
| HLR-154 · LLR-154.1 … .3 | **absorbed** · S1: R-READ-005, R-READ-006.1, R-READ-006.2, R-READ-007.1 … .5, R-READ-008; S15: R-FLOW-SRC.1 … .10 | Integrity notices (S1 D-10); LLR-154.3 is the flow LOAD. |
| HLR-155 · LLR-155.1 … .8 | **absorbed** · S5: R-TUI-002.5, R-TUI-006.1, R-TUI-006.2; S8: R-PATCH-SAVE-FOLDER-001.10, R-CHG-003.18, R-CHG-003.19; S11: R-TUI-012.14; S13: R-CRC-WRITE-001.5 … .26; S15: R-FLOW-WRITE.1 … .8, R-FLOW-CHAIN.1 … .10 | Private staging and exclusive create are design. Reports that probe a free name first: S14 D14-11, S15 D15-12. |
| HLR-156 · LLR-156.1 … .4 | **absorbed** · S15: R-FLOW-PATCH.1 … .11, R-FLOW-RPT.1 … .14, R-FLOW-CHAIN.11 … .18 | PATCH step status. |
| HLR-157 · LLR-157.1 … .4 | **absorbed** · S8: R-CHG-002.1, R-CHG-003.8, R-CHG-003.21, R-CHG-003.23 | Save-back writes source plus document (S8 D8-3); the Patch Editor controls are S10.8 (D10-12). |
| HLR-158 · LLR-158.1 … .3 | **absorbed** · S2: R-A2L-024 … 027, R-A2L-056 … 058.3, R-A2L-006.7 | Decoding. Encoding is deferred with the symbol input (S10 D10-13, D10-42). |
| HLR-159 · LLR-159.1, .2 | **absorbed** · S13: R-CRC-CHECK-002.1 … .4; S15: R-FLOW-CRC.1 … .8 | Empty and partly covered CRC targets. |
| HLR-160 · LLR-160.1 … .5 | **absorbed** · S17: R-SEG-NAME.1 … R-SEG-PLACE.18 | Export names and placement, S17.7 (D17-12). |
| HLR-161 · LLR-161.1, .2 | **absorbed** · S10: R-PE-031 | The help-window note is S7's (passed by S10). |
| HLR-162 · LLR-162.1 … .3 | **absorbed** · S11: R-TUI-013.2; S7: R-LOADDLG.1, R-LOADDLG.24, R-LOADDLG.60; S5: R-WS-FILES.1, R-WS-FILES.3 | Pick by name; list the folder loads write into. The Load project dialog rows (S11 R-TUI-013.1, .3, .4) are retired into the Load dialog (S11 D11-55). |

**Batch-100 ids** (CTX-RETIRED "batch-100 id"; D0-13). One pointer line per HLR of batch-100 (HLR-163 … HLR-178 with every lettered sub-HLR, 42 ids), in the same classes. Rows cited are those of the 570b4b5 reconciliation.

| Id | Where it lives now | Note |
|---|---|---|
| HLR-163 · LLR-163.1 … .7 | **absorbed** · S5: R-TUI-006.1 … .5, R-TUI-002.9; S8: R-PATCH-SAVE-FOLDER-001.5, .6; S11: R-PROJ-002.2, R-PROJ-ROLLBACK.8; S17: R-SEG-PLACE.3, .5, R-SEG-EXP.12 | Reuse for every placement (S5 D5-38). LLR-163.2 (size before bytes) is design; LLR-163.3, .4, .6 were true at 093a7c0 (S8 D8-36, S17 D17-44); LLR-163.5 is the reused-variant status, LLR-163.7 the save plan's action words (S11 CTX-SAVE; `predict_placement` is mechanism, S11 D11-50). |
| HLR-164 · LLR-164.1 … .4 | **absorbed** · S11: R-TUI-012.5 … .15, .20, .21, R-TUI-013.2, R-PROJ-MERGE.1 … .3, R-PROJ-ROLLBACK.1 … .6, .12 | Name guards, merge, a failed save leaves nothing. The AST census of LLR-164.4 is mechanism (S11 D11-50, D11-51). |
| HLR-165 · LLR-165.1 … .4 | **absorbed** · S11: R-PROJ-RESET.1, .3, .4; S2: R-A2L-004.13; S5: R-WS-LOADED.6, .10 | Reset after the read, before the first install; `_session_snapshot` is a test seam (S11 D11-63). LLR-165.4 (an unload drops the parsed A2L) was in the code at 093a7c0 (S2 D2-32); S5's unload rows cite it. |
| HLR-166 · LLR-166.1, .2 | **absorbed** · S6: R-SHELL-FOCUS.3, .4, .5, .7, R-FOCUS-LOAD.1 | Focus after a load completes or is cancelled, and after the Load-result panel closes; the panel's own first focus is S11's (R-LOADRES-8). |
| HLR-167 · LLR-167.1 … .8, .6a … .6g | **absorbed** · S11: R-PROJ-IMAGE.1 … .14, R-PROJ-001.1 … .12, R-TUI-012.16, .17, .28, .29, R-SAVEDLG-16, R-SAVEDLG-24, R-PROJ-DOC.15 … .17; S10: R-PE-038, R-PE-039.1 … .4 | Emit on data (S11 D11-52, LED .14 over LED .13); the LLR-167.7 split is mechanism. LLR-167.8 (the Patch Editor's unsaved mark after Save project) is S10's (D10-46). |
| HLR-168 · LLR-168.1 … .4 | **absorbed** · S11: R-PROJ-SAVEBACK.1 … .3, R-PROJ-002.4, .10, .11, R-PROJ-WRITER.1 … .4, R-VAR-001.1, R-VAR-002.19, R-PROJ-IMAGE.13; S8: R-CHG-003.8, .19, .20 | Every in-project writer rewrites project.json (S11 D11-59). The save-back itself is unchanged; S8 cites the S11 rows (D8-37). |
| HLR-169 · LLR-169.1 … .9 | **absorbed** · S11: R-PROJCHK-1 … R-PROJCHK-18, R-PROJ-OPEN.1, .2, R-VAR-002.2, .14, R-MANIFEST-READ.3 … .11, .17, R-MANIFEST-WRITE.2, .3, R-MAN-WRITE-001.4, R-MAN-VERIFY-001.2, R-MANIFEST-KEEP.1 … .5 | Read cap 1 MiB (S11 D11-57); private staging is mechanism. |
| HLR-170 · LLR-170.1 … .3 | **absorbed** · S11: R-PROJ-DOC.1 … .22, R-MANIFEST-READ.15, R-MANIFEST-WRITE.5, .6 | The active change document is saved and reopened. |
| HLR-171 · LLR-171.1 … .1o, .5, .6 … .6b, .7 … .7c | **absorbed** · S11: R-SAVEAS-1 … R-SAVEAS-14, R-TUI-012.25 … .27, .29, .31, .32, R-PROJ-MERGE.2, R-PROJ-GATHER.10, .11, R-PROJ-ASSIGN-001.5 … .7, R-PROJ-ROLLBACK.14, .15; S16: R-FB-RIB.2; S13: R-CRC-TEMPLATE-001.12 | Save as copies the project. LLR-171.1l (the Flow panels follow the new folder) is S11 R-SAVEAS-8, cited by S16; LLR-171.5's `copied but not recorded` status is S11 R-PROJ-GATHER.10, cited by S13. |
| HLR-171a · LLR-171.2 … .2h | **absorbed** · S11: R-PROJ-A2LONLY.1 … .5, R-TUI-013.8, .20, R-PROJ-RESET.1; S5: R-WS-LOADED.5 | LLR-171.2e was retired by the batch (LLR-173.4a); its branch is a guard (S11 D11-68). LLR-171.2h (the A2L unload of an A2L-only session) is cited by S5's unload row. |
| HLR-171b · LLR-171.3 … .4j | **absorbed** · S11: R-PROJ-CONTAIN.1, R-TUI-012.15, .24, .34, .36, R-TUI-013.2, .15, .16, R-MAN-WRITE-001.5, R-MANIFEST-WRITE.8, R-PROJ-002.8; S15: R-FLOW-FILE.11, R-FLOW-SET.7 | LLR-171.4d was withdrawn by the batch. LLR-171.4i, .4j (a flow or a chain set is not saved outside the work area) are not implemented at 570b4b5: both S15 rows read No (S15 D15-18, code change). |
| HLR-172 · LLR-172.1, .1a … .1n, .2, .2a … .2k, .3 | **absorbed** · S5: R-RECENT-001.1 … .20, R-RECENT-002.1 … .9, R-RECENT-003.1; S7: R-LOADDLG.31, .32 | Per-user recent-sources store (S5 D5-45); the store problem's lines in the Load dialog are S7's. |
| HLR-172a · LLR-172.5, .5a … .5k | **absorbed** · S7: R-TUI-043.2, R-TUI-043.14 … .24, R-LOADDLG.64, .65, .68; S11: R-TUI-013.18 | A typed absolute project path opens the project; refusals by class (S7 CTX-LOADDLG). LLR-172.5j, .5k (one match function, one wording table) are implementation (S7 D7-13). S7 R-LOADDLG.66 is retired into S11 R-TUI-013.18 (S7 D7-34). |
| HLR-172b · LLR-172.4, .4a … .4f, .6, .6a … .6c | **absorbed** · S5: R-WS-FILES.1, .3, .5, .7 … .15; S11: R-TUI-013.2 | LLR-172.4 (one lister, AST census) is design (S5 D5-48); LLR-172.4e (names ending in a dot or a space) is S11's project list. |
| HLR-173 · LLR-173.1, .1e, .1g, .2, .2a … .2e, .2j, .2m, .3 … .3d, .4 … .4g, .4l, .4m, .6d, .6f, .6k … .6n, .7 | **absorbed** · S7: R-TUI-043.1, R-LOADDLG.1 … .53, R-DLG.1, CTX-KEYBAR row 1; S6: R-TUI-022.2; S11: R-TUI-013.2, .17 | One Load dialog (P-A verdict C). LLR-173.1, .1e, .6l are implementation (S7 D7-13); LLR-173.4a's folder rule is S11's project list; the palette labels of LLR-173.2m are S6's (D6-38). S7 R-LOADDLG.67 is retired into S11 R-TUI-013.17 (S7 D7-34). |
| HLR-173a · LLR-173.6, .6a … .6c, .4n | **absorbed** · S7: R-LOADDLG.44 … .50, .82; S11: R-TUI-014.4, R-LOADRES-18 | The `●` marks equal the installed set. The install half of LLR-173.4n and LLR-173.6a are S11's. The work-area row's `becomes the active variant of project <P>` line (LLR-173.6c) promises a sync the pick does not do (S11 D11-29). |
| HLR-173b · LLR-173.1f, .4h … .4k | **absorbed** · S7: R-LOADDLG.35, .36, .51, .52, .62, .71, .81 | A recent row reopens its recorded path; nothing is read at it before the load. |
| HLR-173c · LLR-173.1a … .1c, .2f, .2g | **absorbed** · S7: R-LOADDLG.54 … .63, R-TUI-043.2, R-TUI-043.15 | Enter, Alt+L and Load load the load source. |
| HLR-173d · LLR-173.2h, .2i, .5, .5a … .5e | **absorbed** · S7: R-LOADDLG.69 … .80 | An empty or refused load request is explained in the reason line. |
| HLR-173e · LLR-173.2k, .2l | **absorbed** · S7: R-DLG.2, R-DLG.9, R-TUI-043.3 | Escape and Cancel close the dialog and change nothing. |
| HLR-174 · LLR-174.1, .1b, .1c, .2, .2a, .2g, .2h, .2j, .2r, .2s, .2t, .3b, .4 … .4c | **absorbed** · S5: R-LOADQ-001.1, .4, .6, R-LOADQ-002.1 … .3, R-LOADQ-004.6 … .8, R-LOADQ-005.4, R-LOADQ-006.1 … .4; S6: R-BUSY-REFUSE.6; S10: R-PE-015, R-PE-016, R-PE-019, R-PE-019a | LLR-174.1c, .2a, .3b and the census of .4 are design (S5 D5-46). LLR-174.2j, .2t are the Patch Editor's own popup (S10 D10-45; D10-20 settled). |
| HLR-174a · LLR-174.1, .1a, .1b, .4b, .4c | **absorbed** · S5: R-LOADQ-001.2, .3, .5, R-LOADQ-002.1 … .3 | The cells that load without asking. |
| HLR-174b · LLR-174.2c, .2e, .2f, .2p, .3, .3c | **absorbed** · S5: R-LOADQ-003.1, .5, R-LOADQ-004.2, .4, .5, R-LOADQ-005.4 | LLR-174.3's order (reset after the answer) is design; its observable part is R-LOADQ-003.2. |
| HLR-174c · LLR-174.2b, .2d, .2e, .2f, .2p, .3a, .3c, .3d | **absorbed** · S5: R-LOADQ-003.2 … .5, R-LOADQ-004.1, .3, .4, .5; S6: R-SHELL-FOCUS.4 | The focus after the close is S6's (LLR-166.1). |
| HLR-174d · LLR-174.2i, .2k … .2o, .2q | **absorbed** · S5: R-LOADQ-005.1 … .3, .5 | Texts in S5 CTX-LOADQ. |
| HLR-175 · LLR-175.1, .4, .4c … .4g, .4j, .5, .5a | **absorbed** · S11: R-SAVEDLG-7, R-SAVEDLG-8, R-SAVEDLG-19 … R-SAVEDLG-24, R-SAVEDLG-27, R-PROJ-ASSIGN-UI-001.6 | The 150 ms recompute and the once-per-open digests are mechanism (S11 D11-50). |
| HLR-175a · LLR-175.3c, .4a, .4b, .4k … .4m | **absorbed** · S11: R-SAVEDLG-11 … R-SAVEDLG-18 | `SaveProjectScreen.plan` (LLR-175.4k) is a test seam. |
| HLR-175b · LLR-175.1a … .1p, .3f, .6 | **absorbed** · S11: R-SAVEDLG-9 … R-SAVEDLG-11, R-TUI-012.8 … .18, .23 … .33 | Refusals painted in the dialog (S11 D11-56). LLR-175.6 is mechanism. |
| HLR-175c · LLR-175.3, .3a | **absorbed** · S11: R-TUI-012.2 | Escape closes the dialog and saves nothing. |
| HLR-175d · LLR-175.3b | **absorbed** · S11: R-TUI-012.3, .8, R-SAVEDLG-9 | An empty Save is explained in the dialog. |
| HLR-175e · LLR-175.2, .2a | **absorbed** · S11: R-SAVEDLG-6, R-TUI-012.4 | The dialog saves only into the work area. |
| HLR-175f · LLR-175.3d, .3e, .3g … .3j, .4h, .4i, .5b | **absorbed** · S11: R-TUI-012.1, .7, .22, R-SAVEDLG-1 … R-SAVEDLG-5, R-SAVEDLG-25, R-SAVEDLG-26 | One dialog with the name, the summary and two buttons. LLR-175.5b (first frame first) is mechanism. |
| HLR-176 · LLR-176.1, .1a, .1g, .1n, .1p, .1r, .1t, .2, .2a, .2b, .4 … .4b | **absorbed** · S6: R-PROGRESS-LINE.1, .8, .9, R-PROGRESS-SHOWN.1, .3, R-SHELL-STATUS.5, .6; S2: R-A2L-004.11 | The progress line (S6 CTX-BUSY). LLR-176.2, .2a (the bar-site census) are implementation (S6 D6-33, D6-34); LLR-176.4a, .4b (same result with or without a callback; the frozen-engine list) are implementation (S2 D2-33). |
| HLR-176a · LLR-176.1e, .1f, .1g, .1q | **absorbed** · S6: R-PROGRESS-LINE.3, .4, R-PROGRESS-END.2 | One timer and main-thread writes (.1e count, .1q) are implementation; held steps declared (S6 D6-35). |
| HLR-176b · LLR-176.1b, .1c, .1d | **absorbed** · S6: R-PROGRESS-BAR.1, .2 | The bar value is CTX-BUSY's; the clamp of bad step data (.1d) is an internal contract (S6 D6-34). |
| HLR-176c · LLR-176.1i … .1m, .1o, .1s, .2c, .2d | **absorbed** · S6: R-PROGRESS-END.1 … .5, R-PROGRESS-SHOWN.2, .4, R-PROGRESS-BAR.1, .5, R-PROGRESS-LINE.7; S12: R-RPT-LOG.1 … .4; S14: R-CMP-005.13 … .15, R-BEFORE-AFTER-REPORT-001.31 | Each action's own outcome text stays in its chapter (S5 R-TUI-012L.12, S2 R-A2L-004.1, S11, S12, S14); the report's end follows S6 R-PROGRESS-END.3 (S12 D12-30). |
| HLR-176d · LLR-176.1h, .1j | **absorbed** · S6: R-PROGRESS-LINE.2, R-PROGRESS-END.2 | One owner of the status text while an action runs. |
| HLR-177 · LLR-177.1 … .1k, .2 … .2c, .5, .5a, LLR-176.3 | **absorbed** · S6: R-PROGRESS-LINE.3, .5, R-PROGRESS-BAR.3, R-BUSY-RUN.1; S2: R-A2L-004.3, .6 … .12; S5: R-TUI-012L.5; S11: R-PROJ-RESET.1, R-LOADRES-2, R-PROJ-ROLLBACK.17, .18, R-TUI-013.17 | Worker threads, frozen requests and main-thread writes (.1, .1a, .1b, .1d, .1e, .1i) are implementation (S6 D6-33, S2 D2-33). The results and failures of each action (.1f … .1h, .1j, .1k, .2 … .2c) are in its chapter (S6 D6-42). The copy on the screen's thread is a held step (S6 D6-35, S5 D5-50). |
| HLR-177a · LLR-177.3 … .3i | **absorbed** · S6: R-BUSY-REFUSE.1 … .8; S10: R-PE-110, R-PE-111; S12: R-RPT-002.28 | The busy line and the refused list are S6 CTX-BUSY; reports are never refused (R-BUSY-REFUSE.7). |
| HLR-177b · LLR-177.4, .4a, .4b, .4d | **absorbed** · S6: R-SHELL-START.5, R-QUIT.1 … .6 | Supersedes S6 D6-9 for the "session action running" state (S6 D6-36). |
| HLR-177c · LLR-177.4c, .4e | **absorbed** · S6: R-QUIT.7 … .12 | Quit waits for the end; withdrawn on a failure or unsaved work. |
| HLR-178 · LLR-178.1 … .3 | **absorbed** · S11: R-TUI-013.12, .13, R-LOADRES-1 … R-LOADRES-18; S7: R-LOADDLG.83; S3: R-LEGEND-010 | Problem rows bounded at 102 (S11 D11-54); the panel's colours are the S3 palette. The open project's preview of the last load result (LLR-178.3, last sentence) is not built at 570b4b5: S7 R-LOADDLG.83 reads No (S7 D7-35). |


#### S0.3 · The requirements file (CTX-CANON; from batch-101 Inc 1)

| Id | Form | Requirement |
|---|---|---|
| R-DOC-CANON.1 | U | The system shall keep its requirements in one file, `REQUIREMENTS.md`, at the root of its repository. |
| R-DOC-CANON.2 | U | The system shall give each requirement in `REQUIREMENTS.md` one table row with an id, a form and a sentence. |
| R-DOC-CANON.3 | U | The system shall write each requirement sentence in `REQUIREMENTS.md` in the form its row names, with the opening words of that form (CTX-CANON). |
| R-DOC-CANON.4 | U | The system shall write each requirement sentence in `REQUIREMENTS.md` with the obligation word of CTX-CANON exactly once. |
| R-DOC-CANON.5 | U | The system shall give each requirement row in `REQUIREMENTS.md` an id that no other row in the file uses. |
| R-DOC-CANON.6 | U | The system shall group the requirement rows of `REQUIREMENTS.md` under the modules S0 … S17, in that order. |
| R-DOC-CANON.7 | U | The system shall keep the requirements file that `REQUIREMENTS.md` replaced, byte for byte as committed at e273181, in `docs/requirements/history/`. |
| R-DOC-CANON.8 | U | The system shall cite in the absorbing cell of each line of S0's table (S0.2) only ids of rows that exist in `REQUIREMENTS.md`. |
| R-DOC-CANON.9 | U | The system shall keep, for each module, the decisions behind its rows in `docs/requirements/review/`. |
| R-DOC-CANON.10 | U | The system shall name in `docs/requirements/review/` only tests that are defined under `tests/`. |
| R-DOC-CANON.11 | U | The system shall write each requirement sentence in `REQUIREMENTS.md` as one sentence. |



<a id="s1"></a>

## S1 · S19 / Intel HEX reading & parsing

### Requirements


#### S1.1 · Reading a file

```text
CTX-LOAD  Loading a file
  line              One physical line of the file, without the whitespace around it.
  empty line        A line with no characters left.
  line number       The position of a line in the file, from 1. Empty lines count.
  record            A line parsed into type, count, address, data and checksum.
  end of reading    S19: the first S7, S8 or S9 record (the terminator).
                    Intel HEX: the first type-01 record (the EOF record).
  trailing line     A line that is not empty and comes after the end of reading.
  valid text        A line whose bytes are valid UTF-8 (D-3).
  load result       What a load gives its caller: the records, the image (CTX-IMAGE),
                    the ranges, the overlap addresses, the diagnostics, the integrity
                    notices and, for S19, the out-of-order records.
  diagnostic        A finding about one line: its line number, the line text and a
                    message.
  integrity notice  A finding about the whole file: a code and a message, no line number.
  line defect       A reason to reject a line. L-1 applies to both formats; CTX-S19 and
                    CTX-HEX list the rest. All are checked in order: L-1 first.
    L-1  the line is not valid text.
  reject the line   No record is created from the line, and none of its bytes enter
                    the image.
```

| Id | Form | Requirement |
|---|---|---|
| R-READ-001.1 | When | When the system reads an empty line, the system shall create no record from it. |
| R-READ-001.2 | When | When the system reads an empty line, the system shall record no diagnostic for it. |
| R-READ-002 | U | The system shall treat CR, LF and CR LF as line ends. |
| R-VAL-002.1 | If | If a line before the end of reading has a line defect, then the system shall reject the line. |
| R-VAL-002.2 | If | If a line before the end of reading has one or more line defects, then the system shall record exactly one diagnostic for it. |
| R-VAL-002.3 | If | If a line has more than one line defect, then the system shall give its diagnostic the message of the first defect in check order. |
| R-VAL-002.4 | If | If a line has a line defect, then the system shall read the line that follows it. |
| R-READ-003 | If | If a line has defect L-1, then the system shall record the diagnostic `Invalid UTF-8: not valid UTF-8 text`. |
| R-READ-004.1 | If | If the file to load does not exist, then the system shall end the load with a file-not-found error. |
| R-READ-004.2 | If | If the file to load does not exist, then the system shall give no load result. |
| R-READ-005 | If | If an S19 file has no terminator, then the system shall attach the integrity notice `S19-NO-TERMINATOR`. |
| R-READ-006.1 | If | If the data-record tally of an S19 file is at most 0xFFFF and differs from the count in its S5 record, then the system shall attach the integrity notice `S19-COUNT-MISMATCH`. |
| R-READ-006.2 | If | If the data-record tally of an S19 file is at most 0xFFFFFF and differs from the count in its S6 record, then the system shall attach the integrity notice `S19-COUNT-MISMATCH`. |
| R-READ-006.3 | If | If an S19 file holds more than one S5 record or more than one S6 record, then the system shall compare the data-record tally with the count in the last record of that type. |
| R-READ-007.1 | If | If a file has trailing lines, then the system shall create no record from them. |
| R-READ-007.2 | If | If a file has trailing lines, then the system shall record no diagnostic for them. |
| R-READ-007.3 | If | If an S19 file has trailing lines, then the system shall attach the integrity notice `S19-AFTER-TERMINATOR`. |
| R-READ-007.4 | If | If an Intel HEX file has trailing lines, then the system shall attach the integrity notice `HEX-AFTER-EOF`. |
| R-READ-007.5 | If | If a file has trailing lines, then the system shall state their number in its after-the-end integrity notice. |
| R-READ-008 | If | If an Intel HEX file has no EOF record, then the system shall attach the integrity notice `HEX-NO-EOF`. |
| R-LOG-001.1 | When | When the load of an S19 file ends, the system shall write the INFO log line `S19 load summary: path=<path> records=<n> errors=<e> validation_errors=<v> parse_errors=<p>`. |
| R-LOG-001.2 | When | When the load of an Intel HEX file ends, the system shall write the INFO log line `HEX load summary: path=<path> records=<n> addresses=<a> errors=<e>`. |

#### S1.2 · S19 records

```text
CTX-S19  Motorola S-record (S19)
  A line:  S | type (1 digit) | count (2) | address (4, 6 or 8) | data | checksum (2)
  hexadecimal     The characters 0-9, A-F and a-f, in a fixed-width field, with no
                  prefix, sign, space or separator (decision 1).
  count           The number of bytes in address + data + checksum.
  length          4 + 2 × count characters.
  checksum rule   The checksum is the ones' complement of the low byte of the sum of
                  the count, address and data bytes.
  Types:   S0 header (2 address bytes) · S1/S2/S3 data (2/3/4) · S4 not used ·
           S5/S6 record count, held in the address field (2/3) ·
           S7/S8/S9 terminator (4/3/2).
  data record     An S1, S2 or S3 record.
  data-record tally  The number of data records, plus the rejected lines before the
                  terminator that start with S1, S2 or S3.
  invalid record  A record that does not follow the checksum rule. It is not rejected.
  Line defects, in check order (after L-1):
    S-1  the line does not start with S, or has fewer than 4 characters.
    S-2  the type is not one of S0, S1, S2, S3, S5, S6, S7, S8, S9.
    S-3  the count is not hexadecimal.
    S-4  the length differs from the length the count gives.
    S-5  the count is less than the address bytes of the type + 1.
    S-6  the address is not hexadecimal.
    S-7  a data byte is not hexadecimal.
    S-8  the checksum is not hexadecimal.
  Example: S313000020001011012C000200010F00000000323A
```

| Id | Form | Requirement |
|---|---|---|
| R-PARSE-001 | If | If an S19 line has defect S-1, then the system shall record the diagnostic `Invalid S-record format: <line>`. |
| R-PARSE-001b | If | If an S19 line has defect S-2, then the system shall record the diagnostic `Unsupported S-record type: <type>`. |
| R-PARSE-002 | If | If an S19 line has defect S-3, then the system shall record the diagnostic `Invalid byte count hex: <count>`. |
| R-PARSE-002a | If | If an S19 line has defect S-4, then the system shall record the diagnostic `Length mismatch: expected <n> chars, found <m>`. |
| R-PARSE-003a | If | If an S19 line has defect S-5, then the system shall record the diagnostic `Line too short for address field`. |
| R-PARSE-003 | If | If an S19 line has defect S-6, then the system shall record the diagnostic `Invalid address hex: <address>`. |
| R-PARSE-004 | If | If an S19 line has defect S-7, then the system shall record the diagnostic `Invalid data byte hex: <xx>` for the first such byte. |
| R-PARSE-005 | If | If an S19 line has defect S-8, then the system shall record the diagnostic `Invalid checksum hex: <xx>`. |
| R-PARSE-006 | U | The system shall read the hexadecimal digits a–f as the same values as A–F. |
| R-VAL-001.1 | If | If an S19 record does not follow the checksum rule, then the system shall mark the record invalid. |
| R-VAL-001.2 | If | If an S19 record does not follow the checksum rule, then the system shall record the diagnostic `Checksum mismatch: expected <XX>, found <YY>`. |

#### S1.3 · Intel HEX records

```text
CTX-HEX  Intel HEX
  A line:  : | count (2) | offset (4) | type (2) | data (2 × count) | checksum (2)
  hexadecimal     As CTX-S19.
  length          11 + 2 × count characters.
  checksum rule   The sum of all bytes after the colon, checksum included, is 0
                  modulo 256.
  Types:   00 data · 01 end of file · 02 extended segment address ·
           03 start segment address · 04 extended linear address ·
           05 start linear address.
  data record          A type-00 record.
  address-base record  A type-02 or type-04 record.
  segment base    The 2 data bytes of a type-02 record, read as one number, × 16.
  linear base     The 2 data bytes of a type-04 record, read as one number, × 0x10000.
  invalid record  A record that does not follow the checksum rule. It is not rejected.
  Line defects, in check order (after L-1):
    H-1  the line does not start with ':'.
    H-2  the line has fewer than 11 characters.
    H-3  the count is not hexadecimal.
    H-4  the length differs from the length the count gives.
    H-5  the offset is not hexadecimal.
    H-6  the type is not hexadecimal.
    H-7  the type is not one this note lists (Q-D).
    H-8  a data byte is not hexadecimal.
    H-9  the checksum is not hexadecimal.
  Example: :080200009D187F5FB9B8019061
```

| Id | Form | Requirement |
|---|---|---|
| R-HEX-004 | If | If an Intel HEX line has defect H-1, then the system shall record the diagnostic `Missing ':' prefix`. |
| R-HEX-005.1 | If | If an Intel HEX line has defect H-2, then the system shall record the diagnostic `Line too short: <n> chars`. |
| R-HEX-005.2 | If | If an Intel HEX line has defect H-3, then the system shall record the diagnostic `Invalid byte count hex: <xx>`. |
| R-HEX-006 | If | If an Intel HEX line has defect H-4, then the system shall record the diagnostic `Length mismatch: expected <n>, found <m>`. |
| R-HEX-005.3 | If | If an Intel HEX line has defect H-5, then the system shall record the diagnostic `Invalid address hex: <xxxx>`. |
| R-HEX-005.4 | If | If an Intel HEX line has defect H-6, then the system shall record the diagnostic `Invalid record type hex: <xx>`. |
| R-HEX-005.5 | If | If an Intel HEX line has defect H-8, then the system shall record the diagnostic `Invalid data byte hex: <xx>` for the first such byte. |
| R-HEX-005.6 | If | If an Intel HEX line has defect H-9, then the system shall record the diagnostic `Invalid checksum hex: <xx>`. |
| R-HEX-007.1 | If | If an Intel HEX record does not follow the checksum rule, then the system shall mark the record invalid. |
| R-HEX-007.2 | If | If an Intel HEX record does not follow the checksum rule, then the system shall record the diagnostic `Checksum mismatch`. |
| R-HEX-008 | If | If an Intel HEX line has defect H-7, then the system shall record the diagnostic `Unsupported record type: <XX>`. |
| R-HEX-009 | While | While no address-base record has been applied, the system shall place each data byte at the record offset + the byte index. |
| R-HEX-001 | While | While the most recently applied address-base record is type 04, the system shall place each data byte at the linear base + the record offset + the byte index. |
| R-HEX-001a.1 | If | If a type-04 record does not hold exactly 2 data bytes, then the system shall keep the current address base. |
| R-HEX-001a.2 | If | If a type-04 record does not hold exactly 2 data bytes, then the system shall record the diagnostic `Invalid extended linear address record length`. |
| R-HEX-002 | While | While the most recently applied address-base record is type 02, the system shall place each data byte at the segment base + ((the record offset + the byte index) mod 0x10000). |
| R-HEX-002a.1 | If | If a type-02 record does not hold exactly 2 data bytes, then the system shall keep the current address base. |
| R-HEX-002a.2 | If | If a type-02 record does not hold exactly 2 data bytes, then the system shall record the diagnostic `Invalid extended segment address record length`. |
| R-HEX-003.1 | When | When the system reads a type-03 or type-05 record, the system shall add no byte to the image. |
| R-HEX-003.2 | When | When the system reads a type-03 or type-05 record, the system shall keep the current address base. |
| R-HEX-003.3 | When | When the system reads a type-03 or type-05 record that follows the checksum rule, the system shall record no diagnostic for it. |

#### S1.4 · The memory image

```text
CTX-IMAGE  The memory image
  image             The address → byte pairs a load builds.
  range             A maximal run of consecutive image addresses. Its start is
                    included; its end (one past the last byte) is not.
  gap               The addresses between two consecutive ranges.
  overlap address   An address that more than one data record writes.
  out-of-order record  A data record whose start address is lower than the start
                    address of the data record before it.
  span              A start address and a length.
```

| Id | Form | Requirement |
|---|---|---|
| R-IMG-006 | U | The system shall place in the image only bytes of data records. |
| R-IMG-001 | If | If more than one data record writes an address, then the system shall keep in the image the byte of the data record that comes last in the file. |
| R-IMG-002.1 | If | If a file has overlap addresses, then the system shall include each one in the load result. |
| R-IMG-002.2 | If | If a file has overlap addresses, then the system shall list them in ascending order. |
| R-IMG-003 | If | If an S19 file has an out-of-order record, then the system shall include in the load result its line number, its start address and the start address of the data record before it. |
| R-IMG-004.1 | When | When a load ends, the system shall include the ranges of the image in the load result. |
| R-IMG-004.2 | When | When a load ends, the system shall list the ranges in ascending order of start address. |
| R-IMG-005.1 | When | When a caller asks whether a span that one range holds whole lies in the image, the system shall answer yes. |
| R-IMG-005.2 | When | When a caller asks whether a span that no single range holds whole lies in the image, the system shall answer no. |
| R-IMG-005.3 | If | If a caller asks whether a span of length 0 or less lies in the image, then the system shall answer no. |
| R-VAL-001a | If | If a data record is invalid, then the system shall place its data bytes in the image. |
| R-VAL-001b | If | If a data record is invalid, then the system shall mark as invalid each range that holds its bytes. |
| R-HEX-007a | If | If an Intel HEX address-base record is invalid, then the system shall apply its address base. |

#### S1.5 · Text from a file, on screen

```text
CTX-TEXT  Text from a file, on screen
  file-derived text  Any text the system takes from a loaded or imported file:
                     symbol names, issue codes and messages, file names, region labels.
  control character  U+0000-U+001F (C0), U+007F (DEL), U+0080-U+009F (C1).
  break character    Tab (U+0009), line feed (U+000A), carriage return (U+000D).
                     They are control characters too.
  markup             Square-bracket text that the screen library could read as a
                     style or a link, for example [red].
  safe-text views    The Memory Map, the Issues view, the Checks view, the Flow screens,
                     the Split/Join view (D-7), the A2L Explorer (table and detail
                     card), the MAC View (added from S2, tested there), the
                     Workarea Files list and the status line (added from S5), the
                     message lines (S6), the Select variant, Save project and
                     Reports dialog lists (S7, S11), the Reports
                     dialog's report view with its Markdown structure kept (S12),
                     the verify-mismatch notice (S8), the Patch Editor and its
                     Checks tab, the Check Editor (S9, S10), the CRC Designer and
                     the Operations dialog result area (S13), the A2B Diff (S14);
                     from batch-100: the Load dialog (S7), the load question (S5),
                     the Load-result panel (S11), the progress line, the busy line
                     and the quit question (S6).
  painted name       A file or project name with every character of Unicode
                     category Cc, Cf, Zl or Zp removed, every unpaired surrogate
                     shown as U+FFFD, and cut to 120 characters ending in "…"
                     (as S7 CTX-LOADDLG defines it).
  painted-name views The safe-text views and lines whose group rows show a name
                     as its painted name: the Workarea Files list and the load
                     question (S5), the progress line, the busy line and the
                     quit question (S6), the Load dialog (S7), the Save project
                     dialog, the Load-result panel and the project-load status
                     lines (S11). The file status after a file load is not one
                     (D-16).
```

| Id | Form | Requirement |
|---|---|---|
| R-TUI-103.1 | When | When the system displays file-derived text other than a painted name in one of the safe-text views, the system shall show each run of break characters as one space. |
| R-TUI-103 | When | When the system displays file-derived text in one of the safe-text views, the system shall display no other control character. |
| R-TUI-103a | When | When the system displays file-derived text other than a painted name in one of the safe-text views, the system shall display every other character unchanged and in the same order. |
| R-TUI-103b | When | When the system displays file-derived text in one of the safe-text views, the system shall apply no markup that the text spells out. |

#### S1.6 · Version

| Id | Form | Requirement |
|---|---|---|
| R-VER-001 | When | When the system reports its version, the system shall report the version declared in the package metadata. |

The command-line tool (`python -m s19_app.cli`) is removed (D-11): its 59 strict rows, CTX-CLI, D-12, D-13 and Q-F go with it. The rows stay in revision 1 of this file (`review/archive/S1-ears-strict.rev1.md`) if the decision is reversed.



<a id="s2"></a>

## S2 · A2L & MAC symbols

### Context notes (informative)

Each subchapter opens with its note. A note defines terms and formats; it never says what the system does (rule E6). Rows cite the notes.

#### CTX-A2L-FILE · An A2L file (S2.1)

```text
A2L file        An ASAM MCD-2 MC text file that describes the variables of an ECU.
section         A block from a line that starts with /begin <NAME> to its matching
                /end <NAME>. Sections nest. The words after <NAME> on the /begin
                line are the section's header.
module          A MODULE section. MOD_COMMON inside it holds module-wide defaults.
comment         Text between /* and */, or from // to the end of the line.
quoted string   Text between double quotes; \" inside it is a quote character.
parse error     A defect in the section structure of the file.
tag             A MEASUREMENT or CHARACTERISTIC section, at any depth.
  MEASUREMENT     A value the ECU computes (read-only in calibration).
  CHARACTERISTIC  A value stored in memory that calibration can change. Its kind is
                  VALUE (one value), VAL_BLK (an array), ASCII (a string), CURVE
                  (values over one axis), MAP (over two axes), CUBOID, MAP_BLOCK.
multi-value tag A tag that holds more than one value: VAL_BLK, CURVE, MAP, CUBOID,
                MAP_BLOCK, or a MEASUREMENT whose MATRIX_DIM is more than 1.
A2L load        Loading an A2L file into the session from a typed .a2l path or a recent
                entry of the Load dialog, a .a2l file of the Workarea Files list, or the
                start-up path (routes and copies: S5, S7).
A2L load steps  The steps the progress line (S6) names for an A2L load, in order:
                1 Copy into the work area · 2 Parse · 3 Build the tag table.
```

#### CTX-A2L-TAG · What a tag declares (S2.2)

```text
address         Where the tag starts in ECU memory. A CHARACTERISTIC states it in its
                header; an ECU_ADDRESS line states it for either kind.
length          The number of bytes the tag occupies from its address.
datatype        UBYTE, SBYTE, UWORD, SWORD, ULONG, SLONG, A_UINT64, A_INT64 (1, 1, 2,
                2, 4, 4, 8, 8 bytes; S = signed, two's complement), FLOAT16_IEEE,
                FLOAT32_IEEE, FLOAT64_IEEE (2, 4, 8 bytes).
record layout   A RECORD_LAYOUT section a CHARACTERISTIC names: the order, datatype
                and alignment of the values in its memory record.
deposit name    The record layout name. Some tool chains encode the datatype in it,
                for example __SWORD_Z.
byte order      big (MSB_FIRST or BIG_ENDIAN) or little (MSB_LAST or LITTLE_ENDIAN).
conversion method  The COMPU_METHOD a tag names. NO_COMPU_METHOD names none.
unit            The physical unit of a tag's value, for example "kOhm".
limits          The lower and upper limit a tag declares for its physical value.
memory region   flash, ram or unknown: the MEMORY_SEGMENT that holds the address.
                RAM or VARIABLE segments are ram; FLASH, ROM or CODE are flash.
virtual         A tag with a VIRTUAL line: computed, with no memory of its own.
function group  The FUNCTION a tag declares.
access          read_only (READ_ONLY) or calibratable (CALIBRATABLE).
source          formula: the tag names a conversion method other than NO_COMPU_METHOD,
                or has a FORMULA line. assigned: otherwise.
axis            An AXIS_DESCR of a CURVE or MAP: its points are either in the same
                record (inline) or in another section (AXIS_PTS_REF, external).
```

#### CTX-A2L-VALUE · From bytes to a physical value (S2.3)

```text
tag span        The bytes from the tag's address, as many as its length.
raw bytes       The tag span read from the image (CTX-IMAGE of S1).
raw value       The raw bytes read as the tag's datatype, in its byte order.
physical value  The raw value after the tag's conversion method.
conversion status  ok · identity (no conversion method: physical = raw) ·
                unknown method · unsupported · error · missing (no raw value).
conversion error   The conversion status error, with a message.
Conversion methods (ASAM MCD-2 MC):
  IDENTICAL   physical = raw.
  LINEAR      physical = a × raw + b (COEFFS_LINEAR a b).
  RAT_FUNC    raw = (a·p² + b·p + c) / (d·p² + e·p + f), solved for p (COEFFS a … f).
  TAB_INTP    a COMPU_TAB of raw → physical pairs, interpolated.
  TAB_NOINTP  a COMPU_TAB of raw → physical pairs, not interpolated.
  TAB_VERB    a COMPU_VTAB of raw → text pairs.
  FORM        a formula in text.
```

#### CTX-A2L-CHECK · Checking tags against the image (S2.4)

```text
primary image   The image of the S19 or Intel HEX file the project loads (S1).
checked tag     A tag the system compared with a primary image: it has an address and
                a length, and a primary image is loaded.
in image        A checked tag whose every span byte is in the primary image.
out of image    A checked tag with at least one span byte missing.
schema complete A tag that has an address, or is virtual.
A2L issue       A validation issue (S3) about the A2L file, with a severity and,
                when it is about one tag, that tag's name (its symbol).
A2L summary     The text the Workspace "Context" pane shows for the loaded A2L.
tag status text  OK (in image) · OUT(image) (out of image) · ERR (<reason>)
                (schema not complete) · nothing (not checked).
```

#### CTX-A2L-SCREEN · The A2L Explorer (S2.5)

```text
A2L Explorer    The screen with the tag table (left, with its filter bar, page bar
                and summary line) and the hex pane (right, with the detail card on top).
tag table columns, in order:
  Tag       in-image glyph, a space, the name
  Address   the address as 0x + 8 uppercase hexadecimal digits
  Length    the length in bytes
  Source    assigned or formula
  Raw       the raw value
  Physical  the physical value
  InMem     yes (in image) · no (out of image) · n/a (not checked)
  Region    the memory region
  Limits    <lower>..<upper>
  Unit      the unit
  Bits      the BIT_MASK value
  Endian    the byte order as declared
  Virt      yes or no
  Func      the function group
  Access    the access
  Dtype     the datatype
in-image glyph  ✓ in image · ⚠ out of image · · not checked (D2-16).
row colour      red: the tag needs attention · green: in image · white: out of image,
                or computed (virtual or formula) · grey: not checked.
filter          A text, a filter field and a filter mode that select the rows shown.
filter field    all, name, address, length, raw_value, physical_value, source,
                in_memory, limits, unit, bits, endian, virtual, function_group,
                access, datatype, description, memory_region.
filter mode     All · Invalid (red rows) · In-Memory (in image).
page            A run of consecutive rows of a table; its size is the page size.
detail card     The box above the hex pane that shows the highlighted tag.
description window  The window that describes one CHARACTERISTIC: its axes, its
                point table and the shape of its values.
highlighted row The row under the table cursor.
selected row    A row the operator confirms with Enter or a click.
```

#### CTX-MAC · MAC files and the MAC View (S2.6)

```text
MAC file        A text file that maps tag names to addresses, one per line.
MAC line        <name> = <address>. Spaces around = are allowed.
  name          Letters, digits, _ and -.
  address       Hexadecimal, with or without a 0x prefix. A=10 means 0x10.
comment line    A line whose first non-blank character is #.
MAC record      One MAC line, with its line number, name, address and parse result.
MAC-only session  A session with a MAC file and no primary image.
MAC status      (conditions; the order that decides between them is R-MAC-030)
  ERR_PARSE           the line is not a valid MAC line
  NO_ADDR             the record has no address
  A2L_ADDR_MISMATCH   an A2L tag has the same name and another address
  NOT_IN_A2L          an A2L file is loaded and no tag has the name
  OUT_OF_IMAGE        a primary image is loaded and the address is not in it
  NO_A2L              no A2L file is loaded
  OK                  an A2L tag has the same name and the same address
name match      Same name, ignoring case.
A2L↔MAC match   A MAC record and an A2L tag with an address that name-match and
                have the same address.
MAC View columns, in order: Tag, Address, InA2L, InMem, Status, SourceLine,
                ParseErr, A2LMatch.
coverage strip  The line above the MAC table: MAC→S19 coverage and A2L↔MAC matches.
```

---

### Requirements


#### S2.1 · Reading an A2L file (CTX-A2L-FILE)

Replaces: the "A2L Structural Parsing" block, R-A2L-001, R-A2L-004, R-A2L-005.

| Id | Form | Requirement |
|---|---|---|
| R-A2L-001.1 | When | When the operator loads an A2L file, the system shall build its sections from its /begin and /end lines. |
| R-A2L-001.2 | U | The system shall ignore the text of comments when it builds sections. |
| R-A2L-001.3 | U | The system shall read a quoted string as one value, without its quotes. |
| R-A2L-001.4 | If | If an /end line has no open section, then the system shall record the parse error `Line <n>: /end without /begin`. |
| R-A2L-001.5 | If | If an /end line names a section other than the one it closes, then the system shall record the parse error `Line <n>: /end <name> does not close /begin <name>`. |
| R-A2L-001.6 | If | If a section is still open at the end of the file, then the system shall record the parse error `Unclosed /begin sections detected.` |
| R-A2L-001.7 | If | If an A2L file holds bytes that are not valid UTF-8, then the system shall read each such byte as the character U+FFFD. |
| R-A2L-005.1 | When | When the system reads an A2L file, the system shall create one tag for each MEASUREMENT and each CHARACTERISTIC section, at any depth. |
| R-A2L-005.2 | When | When the system reads an A2L file, the system shall create no tag from any other section. |
| R-A2L-004.1 | When | When an A2L file loads with no parse error, the system shall show the status `A2L loaded: <file name>`. |
| R-A2L-004.2 | If | If an A2L file loads with parse errors, then the system shall show the status `A2L loaded with <n> parse errors: <file name>`. |
| R-A2L-004.3 | If | If the A2L file is missing, or its size cannot be read, when the system starts the A2L load, then the system shall show the status `A2L file not found: <path>`. |
| R-A2L-004.4 | If | If the file to load as A2L does not end in `.a2l`, then the system shall show the status `Unsupported A2L type: <extension>`. |
| R-A2L-004.5 | If | If the project already has an A2L file, then the system shall show the status `Project already has an A2L file.` |
| R-A2L-004.6 | If | If the system cannot copy or parse the A2L file, then the system shall show the status `File NOT loaded: '<file name>' could not be read — check that the file can be opened, then load again.` |

**(from batch-100 HLR-177, HLR-176, HLR-165: LLR-177.1b, 177.2b, 177.2c, 177.5, 176.4, 165.4)**

| Id | Form | Requirement |
|---|---|---|
| R-A2L-004.7 | If | If the system cannot copy or parse the A2L file, then the system shall keep the A2L file and the tags that were loaded before the attempt. |
| R-A2L-004.8 | If | If the work-area guard (S5) refuses the copy of the A2L file, then the system shall show the status `Cannot load A2L: <reason>`. |
| R-A2L-004.9 | If | If the open project's folder cannot be read when the system starts the A2L load, then the system shall show the status `A2L NOT loaded: project '<project name>' could not be read — check that the folder can be opened, then load again.` |
| R-A2L-004.10 | While | While the system copies or parses an A2L file, the system shall keep processing input and screen updates. |
| R-A2L-004.11 | While | While the system parses an A2L file, the system shall move the progress bar within the parse step in proportion to the bytes of the file read so far. |
| R-A2L-004.12 | When | When the system loads an A2L file from the Workarea Files list, the system shall show its progress line at the Parse step from the start of the load. |
| R-A2L-004.13 | When | When the operator loads a primary image after unloading the A2L file, the system shall show no A2L tags. |

#### S2.2 · What a tag declares (CTX-A2L-TAG)

Replaces: the "RECORD_LAYOUT Interpretation" block, the byte-order precedence, the unit precedence of the "Viewer" block.

| Id | Form | Requirement |
|---|---|---|
| R-A2L-010 | When | When the system reads a CHARACTERISTIC, the system shall take its address from its header. |
| R-A2L-011 | If | If a tag has an ECU_ADDRESS line, then the system shall take the tag's address from that line. |
| R-A2L-012 | If | If a MEASUREMENT has no ECU_ADDRESS line, then the system shall give it no address. |
| R-A2L-013 | If | If a tag has a DATA_SIZE or LENGTH line, then the system shall take its length from that line. |
| R-A2L-014 | If | If a MEASUREMENT has no DATA_SIZE or LENGTH line, then the system shall take its length as the size of its datatype × its MATRIX_DIM (1 when absent). |
| R-A2L-015 | If | If a VALUE CHARACTERISTIC has no DATA_SIZE or LENGTH line, then the system shall take its length as the size of its datatype. |
| R-A2L-016 | If | If a VAL_BLK CHARACTERISTIC has no DATA_SIZE or LENGTH line, then the system shall take its length as the size of its datatype × its MATRIX_DIM. |
| R-A2L-017 | If | If an ASCII CHARACTERISTIC has no DATA_SIZE or LENGTH line, then the system shall take its length from its NUMBER line. |
| R-A2L-018 | If | If a CURVE or MAP has no DATA_SIZE or LENGTH line, then the system shall take its length as the size of its whole record: the components of its record layout, with their alignment, for its number of axis points. |
| R-A2L-019 | If | If an axis of a CURVE or MAP takes its points from another section, then the system shall count the points of that section. |
| R-A2L-020 | If | If the system cannot determine a tag's length, then the system shall give the tag no length. |
| R-A2L-021 | If | If a tag has a DATA_TYPE line, then the system shall take its datatype from that line. |
| R-A2L-022 | If | If a CHARACTERISTIC's record layout names a datatype, then the system shall take the tag's datatype from the record layout. |
| R-A2L-023 | If | If a CHARACTERISTIC's record layout names no datatype, then the system shall take the datatype the deposit name spells out. |
| R-A2L-024 | If | If a tag has a BYTE_ORDER line, then the system shall use that byte order for the tag. |
| R-A2L-025 | If | If a tag has no BYTE_ORDER line and its record layout has one, then the system shall use the record layout's byte order. |
| R-A2L-026 | If | If neither a tag nor its record layout has a BYTE_ORDER line, then the system shall use the BYTE_ORDER of the MOD_COMMON of the tag's module. |
| R-A2L-027 | If | If no BYTE_ORDER applies to a tag, then the system shall use little-endian. |
| R-A2L-028 | If | If a BYTE_ORDER line holds a value that is not a byte order, then the system shall raise the WARNING issue `A2L_UNKNOWN_BYTE_ORDER` for that tag. |
| R-A2L-029 | If | If a BYTE_ORDER line holds a value that is not a byte order, then the system shall apply the next rule of R-A2L-024 … 027. |
| R-A2L-030 | If | If a tag has a UNIT or PHYS_UNIT line, then the system shall take as its unit the whole value of that line, without quotes. |
| R-A2L-031 | If | If a tag has no UNIT or PHYS_UNIT line, then the system shall take as its unit the unit of its conversion method. |
| R-A2L-032 | U | The system shall show the same unit for a tag in the tag table, the detail card and the description window. |
| R-A2L-033 | U | The system shall read a conversion method's unit from its conversion line, whether that line is the /begin line or a later one. |
| R-A2L-034 | U | The system shall give each tag the memory region of the MEMORY_SEGMENT that holds its address. |
| R-A2L-035 | If | If no MEMORY_SEGMENT holds a tag's address, then the system shall give the tag the memory region unknown. |
| R-A2L-036.1 | When | When the system reads a MEMORY_SEGMENT block, the system shall take the first word after `/begin MEMORY_SEGMENT` as the segment's name. |
| R-A2L-036.2 | When | When the system reads a MEMORY_SEGMENT block, the system shall take as its record line the first line that splits into at least five words, a quoted text counting as one word. |
| R-A2L-036.3 | When | When the system reads a MEMORY_SEGMENT record line, the system shall take its fourth word as the segment's base and its fifth word as the segment's size. |
| R-A2L-036.4 | If | If the base word of a MEMORY_SEGMENT record line is not a number, then the system shall give the segment no base and no size. |
| R-A2L-036.5 | If | If the size word of a MEMORY_SEGMENT record line is not a number, then the system shall give the segment no size. |
| R-A2L-036.6 | When | When a MEMORY_SEGMENT record line has a sixth word that is a number, the system shall take it as the segment's offset. |

#### S2.3 · From bytes to a physical value (CTX-A2L-VALUE)

Replaces: the "Raw Memory Extraction", "Raw Value Decoding" and "COMPU_METHOD Execution" blocks.

| Id | Form | Requirement |
|---|---|---|
| R-A2L-040 | When | When every byte of a tag's span is in the image, the system shall read the tag's raw bytes. |
| R-A2L-041 | If | If a byte of a tag's span is not in the image, then the system shall give the tag no raw value. |
| R-A2L-042 | If | If a tag's length is more than 1 MiB, then the system shall give the tag no raw value. |
| R-A2L-043 | U | The system shall read a tag's raw value as its datatype, in its byte order. |
| R-A2L-044 | U | The system shall read a signed datatype as two's complement. |
| R-A2L-045 | U | The system shall read FLOAT16_IEEE, FLOAT32_IEEE and FLOAT64_IEEE as IEEE 754 binary16, binary32 and binary64. |
| R-A2L-046 | If | If a tag has no datatype the system can read, then the system shall give the tag no raw value. |
| R-A2L-047 | If | If a tag is a multi-value tag, then the system shall give it one raw value per element. |
| R-A2L-050 | If | If a tag has no raw value, then the system shall give it the conversion status missing. |
| R-A2L-051 | If | If a tag has no conversion method, then the system shall give it a physical value equal to its raw value. |
| R-A2L-052 | If | If a tag has no conversion method, then the system shall give it the conversion status identity. |
| R-A2L-053 | When | When a tag's conversion method is IDENTICAL, the system shall give it a physical value equal to its raw value. |
| R-A2L-054 | When | When a tag's conversion method is LINEAR, the system shall give it the physical value a × raw + b. |
| R-A2L-055 | If | If a LINEAR conversion method lacks a or b, then the system shall use 1 for a missing a and 0 for a missing b. |
| R-A2L-056 | When | When a tag's conversion method is RAT_FUNC, the system shall give it the physical value that solves the RAT_FUNC equation for its raw value. |
| R-A2L-057 | If | If a RAT_FUNC equation has two solutions, then the system shall take the one inside the tag's limits, or the one closer to 0 when both or neither are inside. |
| R-A2L-058.1 | If | If a RAT_FUNC equation has no solution for a tag's raw value, then the system shall give the tag the conversion error `RAT_FUNC has no solution for this value`. |
| R-A2L-058.2 | If | If a RAT_FUNC equation has no real root for a tag's raw value, then the system shall give the tag the conversion error `RAT_FUNC has no real root for this value`. |
| R-A2L-058.3 | If | If every root of a RAT_FUNC equation has a zero denominator, then the system shall give the tag the conversion error `RAT_FUNC root has a zero denominator`. |
| R-A2L-059 | When | When a tag's conversion method is TAB_VERB, the system shall give it the text its COMPU_VTAB pairs with its raw value. |
| R-A2L-060 | When | When a tag's conversion method is FORM, the system shall give it the conversion status unsupported. |
| R-A2L-061 | When | When a tag's conversion method is TAB_INTP, the system shall interpolate its physical value linearly between the two table pairs around its raw value. |
| R-A2L-062 | If | If a TAB_INTP raw value is outside the table, then the system shall give the physical value of the nearest end of the table. |
| R-A2L-063 | When | When a tag's conversion method is TAB_NOINTP, the system shall give it the physical value of the table pair whose raw value is nearest to its raw value. |
| R-A2L-064 | If | If a conversion method names a table that does not exist, then the system shall give the tag the conversion error `lookup table missing`. |
| R-A2L-065 | If | If a conversion method names an empty table, then the system shall give the tag the conversion error `lookup table is empty`. |
| R-A2L-066 | If | If a tag's conversion method has a type this list does not name, then the system shall give it the conversion status unknown method. |

#### S2.4 · Checking tags against the image (CTX-A2L-CHECK)

Replaces: the "A2L Decode Validation" block, R-A2L-002, R-A2L-ISSUE-RECONCILE-002 (the issue half is in S2.5).

| Id | Form | Requirement |
|---|---|---|
| R-A2L-070 | When | When an A2L file and a primary image are both loaded, the system shall check each tag that has an address and a length against the image. |
| R-A2L-071 | If | If only a MAC file is loaded besides the A2L file, then the system shall check no tag. |
| R-A2L-072 | If | If a tag has no address and is not virtual, then the system shall mark its schema as not complete. |
| R-A2L-073 | If | If a checked tag's physical value is outside its limits, then the system shall mark the value as outside the limits. |
| R-A2L-074 | When | When an A2L file is loaded, the system shall show the A2L summary in the Workspace "Context" pane. |
| R-A2L-075 | When | When the system shows the A2L summary, the system shall list the parse errors under the heading `A2L parse errors:`, one `- <error>` line each. |
| R-A2L-076 | When | When the system shows the A2L summary, the system shall list the sections under the heading `A2L Sections:`, one `- <name> <header> (lines <first>-<last>)` line each, indented by depth. |
| R-A2L-077 | When | When the system shows the A2L summary, the system shall list the tags under the heading `A2L Tags:`, one `- <section> <name>: <address> len=<length> mem=<region> <tag status text>` line each. |
| R-A2L-078 | If | If the A2L summary has more than 500 lines, then the system shall replace the rest with the line `... truncated <k> additional tag lines ...`. |
| R-A2L-079 | If | If no A2L file is loaded, then the system shall show `No A2L loaded.` in the A2L summary. |

#### S2.5 · The A2L Explorer (CTX-A2L-SCREEN)

Replaces: the "A2L Viewer" block, R-A2L-003, 006, 007, R-TUI-019, 020, 037, 068, 069, R-A2L-ISSUE-RECONCILE-002. File-derived text on this screen follows S1's R-TUI-103 family (the A2L Explorer joins its list of views).

**Layout and table**

| Id | Form | Requirement |
|---|---|---|
| R-TUI-037.1 | While | While the A2L Explorer is shown, the system shall give the tag table 4/7 of the screen width. |
| R-TUI-037.2 | While | While the A2L Explorer is shown, the system shall give the hex pane 3/7 of the screen width. |
| R-TUI-042a.1 | While | While the operator scrolls the tag table, the system shall keep its column header visible. |
| R-TUI-042a.2 | U | The system shall show the tag table with no padding between cells. |
| R-A2L-006.1 | When | When the system shows the tag table, the system shall show the columns CTX-A2L-SCREEN lists, in that order. |
| R-A2L-006.2 | When | When the system shows a tag in the tag table, the system shall start its Tag cell with its in-image glyph. |
| R-A2L-006.3 | If | If a tag has no name, then the system shall show `UNKNOWN` in its Tag cell. |
| R-A2L-006.4 | If | If a tag has no address, then the system shall show `n/a` in its Address cell. |
| R-A2L-006.5 | If | If a tag has no length, then the system shall show `n/a` in its Length cell. |
| R-A2L-006.6 | If | If a tag has no raw value, then the system shall leave its Raw cell blank. |
| R-A2L-006.7 | If | If a tag has a raw value and no physical value, then the system shall show `n/a` in its Physical cell. |
| R-A2L-006.8 | If | If a tag has no raw value, then the system shall leave its Physical cell blank. |
| R-A2L-006.9 | If | If a tag is a multi-value tag, then the system shall show `<n> values` in its Raw cell and its Physical cell. |
| R-A2L-006.10 | If | If a tag declares one limit only, then the system shall leave the other side of `..` blank in its Limits cell. |
| R-A2L-006.11 | If | If a tag declares no limits, then the system shall leave its Limits cell blank. |
| R-A2L-006.12 | If | If a tag has no value for Unit, Bits, Endian, Func, Access or Dtype, then the system shall leave that cell blank. |
| R-TUI-068.1 | When | When the system shows the tag table, the system shall shade every other row. |
| R-TUI-068.2 | When | When the system shows the tag table, the system shall show under it the summary `Page <p>/<P> \| tags <a>-<b> / <T> (page size <S>; +/- to change page)  ·  <K> in image`, where K counts the filtered tags that are in image. |
| R-TUI-068.3 | If | If no A2L file is loaded, then the system shall show `No A2L tags.` as the summary. |
| R-TUI-068.4 | If | If the filter matches no tag, then the system shall show `No tag matches the filter.` as the summary. |

**Row colour** (colour names are the palette of S3 CTX-LEGEND; today the A2L and MAC tables use terminal colours instead, S3 D3-18)

| Id | Form | Requirement |
|---|---|---|
| R-A2L-080 | If | If an ERROR A2L issue names a tag, ignoring case, then the system shall show the tag's row red. |
| R-A2L-081 | If | If a WARNING A2L issue names a tag, then the system shall not change the tag's row colour. |
| R-A2L-082 | If | If an A2L issue names no tag shown in the table, then the system shall change no row. |
| R-A2L-083 | If | If no ERROR A2L issue names a tag and its schema is not complete, then the system shall show its row red. |
| R-A2L-084 | If | If no row-colour rule above applies and the tag is in image, then the system shall show its row green. |
| R-A2L-085 | If | If no row-colour rule above applies and the tag is out of image, then the system shall show its row white. |
| R-A2L-086 | If | If no row-colour rule above applies and the tag is virtual or its source is formula, then the system shall show its row white. |
| R-A2L-087 | If | If no row-colour rule above applies, then the system shall show the tag's row grey. |
| R-A2L-088 | When | When the system colours a row, the system shall apply the colour to every cell of the row. |

**Filter**

| Id | Form | Requirement |
|---|---|---|
| R-A2L-007.1 | When | When the operator stops typing in the filter box for 0.15 s, the system shall show only the tags whose filter field contains the filter text, ignoring case. |
| R-A2L-007.2 | If | If the filter field is `all`, then the system shall match the filter text against every filter field. |
| R-A2L-007.3 | When | When the operator presses the `Field: <field>` button, the system shall open the list of filter fields with the current one marked `(*)`. |
| R-A2L-007.4 | When | When the operator picks a filter field, the system shall show `Field: <field>` on the button. |
| R-A2L-007.5 | When | When the system matches the filter text against the address field, the system shall compare it with the address as the table shows it. |
| R-A2L-007.6 | When | When the operator presses `All`, the system shall show the tags the filter text selects, whatever their status. |
| R-A2L-007.7 | When | When the operator presses `Invalid`, the system shall show only the tags whose row is red. |
| R-A2L-007.8 | When | When the operator presses `In-Memory`, the system shall show only the tags that are in image. |
| R-A2L-007.9 | When | When the operator picks a filter mode, the system shall mark its button as active. |
| R-A2L-007.10 | When | When the filter changes, the system shall show the first page of the table. |

**Find**

| Id | Form | Requirement |
|---|---|---|
| R-A2L-090 | When | When the operator presses `Find next`, the system shall move the cursor to the next filtered tag, after the current one, whose shown fields contain the find text, ignoring case. |
| R-A2L-091 | If | If no filtered tag after the current one matches, then the system shall continue the search from the first filtered tag. |
| R-A2L-092 | When | When the operator edits the find text, the system shall start the next search from the first filtered tag. |
| R-A2L-093 | When | When a find moves to a tag, the system shall show the page that holds it. |
| R-A2L-094 | When | When a find moves to a tag, the system shall show its address near the top of the hex pane. |
| R-A2L-095 | When | When a find moves to a tag, the system shall show the status `Tag find: <name> (row <i>)`. |
| R-A2L-096 | If | If no filtered tag matches the find text, then the system shall show the status `Tag find: no match.` |
| R-A2L-097 | If | If the find text is empty, then the system shall show the status `Tag find query is empty.` |
| R-A2L-098 | If | If the tag table is empty, then the system shall show the status `No A2L tags to search.` |
| R-A2L-099 | When | When the system compares the find text with the address, the system shall compare it with the address as the table shows it. |

**Paging** (both tables; the MAC table is in S2.6)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-019.1 | While | While the operator has set no page size for the tag table, the system shall show 200 rows per page of it. |
| R-TUI-019.2 | While | While the operator has set no page size for the MAC table, the system shall show 100 rows per page of it. |
| R-TUI-019.3 | When | When the operator opens the page-size choice in the viewer settings, the system shall offer 25, 50, 100, 150 and 200. |
| R-TUI-019.6 | When | When the operator sets a page size for a table, the system shall show that many rows per page of it. |
| R-TUI-019.4 | When | When the operator presses `Page Next` under a table, the system shall show the next page of that table. |
| R-TUI-019.5 | When | When the operator presses `Page Prev` under a table, the system shall show the previous page of that table. |
| R-TUI-020.1 | When | When the operator presses `+` or PgDn on the A2L Explorer or the MAC View, the system shall show the next page of the table of that screen. |
| R-TUI-020.2 | When | When the operator presses `-` or PgUp on the A2L Explorer or the MAC View, the system shall show the previous page of the table of that screen. |
| R-TUI-020.3 | If | If the operator asks for the next page while the last page is shown, then the system shall keep the last page. |
| R-TUI-020.4 | If | If the operator asks for the previous page while the first page is shown, then the system shall keep the first page. |
| R-TUI-020.5 | If | If the operator presses `+` or `-` on a screen other than the A2L Explorer and the MAC View, then the system shall change no page. |

**Detail card**

| Id | Form | Requirement |
|---|---|---|
| R-TUI-069.1 | When | When a row of the tag table becomes the highlighted row, the system shall show that tag in the detail card. |
| R-TUI-069.2 | If | If no row is highlighted, then the system shall show `Highlight a tag to inspect its fields.` in the detail card. |
| R-TUI-069.3 | When | When the system shows a tag in the detail card, the system shall show on its first line the in-image glyph, the tag's display identifier or name, and its address. |
| R-TUI-069.4 | When | When the system shows a tag in the detail card, the system shall show the lines `desc <description>`, `unit <unit> · conv <conversion method>`, `layout <record layout>`, `byteorder <byte order>` and `limits <lower>..<upper>`. |
| R-TUI-069.5 | If | If a detail-card field has no value, then the system shall leave out its line. |
| R-TUI-069.6 | U | The system shall show the detail card at most 5 lines high, above the hex view. |
| R-TUI-069.7 | If | If the detail card's content is longer than 5 lines, then the system shall let the operator scroll it. |

**Selecting a row**

| Id | Form | Requirement |
|---|---|---|
| R-A2L-100 | When | When the operator selects a tag row, the system shall show the tag's address near the top of the hex pane. |
| R-A2L-101 | When | When the operator selects a tag row, the system shall highlight in the hex pane the tag's span, up to 4,096 bytes. |
| R-A2L-102 | If | If the selected tag has no length, then the system shall highlight 1 byte. |
| R-A2L-103 | When | When the operator selects a tag row, the system shall show the status `Tag at <address>`. |
| R-A2L-104 | If | If the selected tag has no address, then the system shall leave the hex pane unchanged. |

**Export to JSON**

| Id | Form | Requirement |
|---|---|---|
| R-A2L-003.1 | When | When the operator presses `j`, the system shall write the parsed A2L data to `<work area>/temp/<A2L file stem>.a2l.json`. |
| R-A2L-003.2 | When | When the system writes the A2L JSON file, the system shall replace a file of the same name. |
| R-A2L-003.3 | When | When the system has written the A2L JSON file, the system shall show the status `A2L JSON saved: <path>`. |
| R-A2L-003.4 | If | If no A2L file is loaded when the operator presses `j`, then the system shall show the status `No A2L data to export.` |
| R-A2L-003.5 | If | If the system cannot write the A2L JSON file, then the system shall show the status `Cannot save A2L JSON: <reason>`. |

**Description window**

| Id | Form | Requirement |
|---|---|---|
| R-A2L-110 | When | When the operator presses `d` on the A2L Explorer with a row highlighted, the system shall open the description window for that tag. |
| R-A2L-111 | If | If no row is highlighted when the operator presses `d`, then the system shall show the status `A2L: no tag row under the cursor.` |
| R-A2L-112 | When | When the system opens the description window, the system shall title it `Parameter: <name>`. |
| R-A2L-113 | When | When the description window shows a CURVE or MAP, the system shall show its kind, name, description, address, byte count, unit and conversion method. |
| R-A2L-114 | When | When the description window shows a CURVE or MAP, the system shall show one `Axis <i>:` line per axis. |
| R-A2L-115 | When | When the description window shows a CURVE or MAP whose values are in the image, the system shall show the table of its axis points and values. |
| R-A2L-116 | If | If a value in the point table is outside the tag's limits, then the system shall mark it `(!)`. |
| R-A2L-117 | When | When the description window shows a CURVE or MAP whose values are in the image, the system shall show the shape of its values as a one-line bar chart after `y shape:`. |
| R-A2L-118 | If | If the tag is not a CURVE or MAP, then the system shall show its value after `Scalar value:` and the line `(this characteristic is not a CURVE/MAP - no point table)`. |
| R-A2L-119 | If | If the point table of a CURVE or MAP cannot be built, then the system shall show `Status: <reason> - point table unavailable`. |
| R-A2L-119a | When | When the operator presses `Close` or Esc in the description window, the system shall close the window. |

#### S2.6 · MAC files and the MAC View (CTX-MAC)

Replaces: R-TUI-039, R-TUI-070, R-TUI-071; MAC behaviour no row stated.

**Reading**

| Id | Form | Requirement |
|---|---|---|
| R-MAC-001 | When | When the system reads a MAC file, the system shall skip empty lines and comment lines. |
| R-MAC-002 | When | When the system reads a MAC file, the system shall create one MAC record from every other line. |
| R-MAC-003 | U | The system shall number MAC lines by their physical position in the file, from 1. |
| R-MAC-004 | If | If a MAC line does not hold exactly one `=`, then the system shall record on its MAC record the parse error `Line <n>: expected one '=' separator`. |
| R-MAC-005 | If | If the name of a MAC line is not a valid name, then the system shall record on its MAC record the parse error `Line <n>: invalid tag name`. |
| R-MAC-006 | If | If the address of a MAC line is not a valid address, then the system shall record on its MAC record the parse error `Line <n>: invalid hex address`. |
| R-MAC-007 | If | If a MAC line has a parse error, then the system shall read the line that follows it. |
| R-MAC-008 | If | If a MAC file cannot be read, then the system shall create no MAC record. |
| R-MAC-009 | If | If a MAC file cannot be read, then the system shall record the diagnostic `Failed to read file: <reason>`. |
| R-MAC-010 | When | When a MAC file loads without a primary image, the system shall show the status `Loaded <file name> (MAC only)`. |
| R-MAC-011 | When | When a MAC file loads with a primary image, the system shall show the status `Loaded <image name> (S19+MAC: <MAC file name>)`. |

**Status of a MAC record**

| Id | Form | Requirement |
|---|---|---|
| R-MAC-030 | If | If more than one MAC status applies to a record, then the system shall give it the first in this order: ERR_PARSE, NO_ADDR, A2L_ADDR_MISMATCH, NOT_IN_A2L, OUT_OF_IMAGE, NO_A2L, OK. |
| R-MAC-031 | When | When the system shows a MAC record, the system shall colour its row red for ERR_PARSE, NO_ADDR and A2L_ADDR_MISMATCH. |
| R-MAC-032 | When | When the system shows a MAC record, the system shall colour its row pale yellow for NOT_IN_A2L. |
| R-MAC-033 | When | When the system shows a MAC record, the system shall colour its row white for OUT_OF_IMAGE. |
| R-MAC-034 | When | When the system shows a MAC record, the system shall colour its row grey for NO_A2L. |
| R-MAC-035 | When | When the system shows a MAC record, the system shall colour its row green for OK. |

**MAC View**

| Id | Form | Requirement |
|---|---|---|
| R-TUI-039.1 | While | While the MAC View is shown, the system shall give the hex pane the larger of 82 columns and 3/7 of the screen width. |
| R-TUI-039.2 | While | While the MAC View is shown, the system shall give the MAC table the rest of the screen width. |
| R-MAC-040 | When | When the system shows the MAC table, the system shall show the columns CTX-MAC lists, in that order. |
| R-MAC-041 | If | If a MAC record has no valid name, then the system shall show `(invalid)` in its Tag cell. |
| R-MAC-042 | If | If a MAC record has no address, then the system shall show `n/a` in its Address cell. |
| R-MAC-043 | If | If no primary image is loaded, then the system shall show `n/a` in every InMem cell. |
| R-MAC-044 | When | When the system shows a MAC record whose name matches an A2L tag, the system shall show `<section>:<name>` of the first such tag in its A2LMatch cell. |
| R-TUI-070.1 | When | When the system shows a MAC record, the system shall start its Tag cell with its status glyph. |
| R-TUI-070.2 | If | If a MAC record has a parse error, then the system shall show the glyph `✗` in red. |
| R-TUI-070.3 | If | If a MAC record is out of the primary image, then the system shall show the glyph `⚠` in orange. |
| R-TUI-070.4 | If | If a MAC record is in the primary image, then the system shall show the glyph `✓` in green. |
| R-TUI-070.5 | If | If a MAC record was not checked against a primary image, then the system shall show the glyph `·` in grey. |
| R-MAC-050 | When | When the system shows the MAC table, the system shall show under it the summary `Page <p>/<P> \| rows <a>-<b> / <T> (page size <S>; +/- for MAC page)` followed by one count per MAC status. |
| R-MAC-051 | If | If a primary image is loaded, then the system shall show under the MAC summary the line `Coverage MAC->S19=<x>%  A2L->S19=<y>%  A2L<->MAC=<z>%`. |
| R-MAC-052 | If | If no MAC file is loaded, then the system shall show `No MAC loaded.` as the MAC summary. |
| R-MAC-053 | If | If a loaded MAC file has no MAC record, then the system shall show `MAC file has no records.` as the MAC summary. |
| R-MAC-054 | When | When the operator selects a MAC row, the system shall show its address near the top of the MAC hex pane. |
| R-MAC-055 | When | When the operator selects a MAC row, the system shall show the status `MAC tag at <address>`. |
| R-MAC-056 | If | If the selected MAC row has a parse error, then the system shall leave the hex pane unchanged. |

**Coverage strip**

| Id | Form | Requirement |
|---|---|---|
| R-TUI-071.1 | While | While a MAC file with at least one MAC record is loaded, the system shall show the coverage strip above the MAC table. |
| R-TUI-071.2 | If | If no MAC file with a MAC record is loaded, then the system shall hide the coverage strip. |
| R-TUI-071.3 | While | While a primary image is loaded, the system shall show the coverage strip as `MAC→S19 <X> of <Y> <bar>  ·  A2L↔MAC <N> matches`. |
| R-TUI-071.4 | While | While no primary image is loaded, the system shall show the coverage strip as `MAC→S19 no image  ·  A2L↔MAC <N> matches`. |
| R-TUI-071.5 | U | The system shall count as Y the MAC records with a valid name and address. |
| R-TUI-071.6 | U | The system shall count as X the records of Y whose address is in the primary image. |
| R-TUI-071.7 | U | The system shall count as N the A2L↔MAC matches. |
| R-TUI-071.8 | U | The system shall draw the bar as 5 cells, filled in proportion to X / Y. |
| R-TUI-071.9 | If | If Y is 0, then the system shall draw the bar with no cell filled. |



<a id="s3"></a>

## S3 · Validation, issues & classification legend

### Context notes (informative)

#### CTX-ISSUE · Validation issues (S3.1, S3.2)

```text
issue           A finding the system reports about the loaded files: a code, a severity,
                a message, an artifact, and when known a symbol, an address, a line
                number and related artifacts.
severity        ERROR (data wrong or unusable) · WARNING (something to check) ·
                INFO (expected, shown for completeness).
artifact        The file kind the issue is about: a2l, mac, s19, hex, or cross (a
                disagreement between files).
symbol          The tag or MAC name the issue is about.
issue list      All issues of the current session, after duplicates are dropped.
same issue      Two issues equal in code, severity, message, artifact, symbol, address
                and line number.
session         primary session: an S19 or Intel HEX file is loaded (the primary image,
                S2 CTX-A2L-CHECK). MAC-only session: a MAC file and no primary image.
                A2L-only session: an A2L file and neither of the others.
shared address  A MAC address that two or more valid MAC records name. Its kind:
  hard conflict      a name of the group is defined twice in the MAC file, or the A2L
                     puts one of the group's names at a different address
  segment ambiguity  the address is an overlap address of the primary image (S1)
  bit-field sharing  a name contains bit, flag, _b, .b or mask
  alias candidate    any other shared address
coverage        MAC→S19 = MAC records in the image / valid MAC records.
                A2L→S19 = checked tags in image / checked tags.
                A2L↔MAC = A2L↔MAC matches (S2 CTX-MAC) / names in both files.
```

#### CTX-ISSUES-SCREEN · The Issues screen (S3.3)

```text
Issues screen   Title "Issues Report"; a button row (Issues: All, Errors, Warnings,
                Legend); the severity strip; the issue list (left) beside the hex peek
                (right); the summary line.
severity strip  Errors <E> <bar>  Warnings <W> <bar>  Info <I> <bar>
                Each bar is 5 cells; filled cells = round(count / total × 5).
summary line    total=<T> | errors=<E> | warnings=<W> | info=<I> | filter=<all|error|warning>
                | page <p>/<P> rows <a>-<b>/<F>
group header    ✗ ERRORS  (<n>) · ⚠ WARNINGS  (<n>) · • INFO  (<n>)   (two spaces)
issue row       code chip (the code, or -) · detail (<symbol or ->  <address or no-addr>
                <message>, two spaces apart) · related (the related artifacts joined by
                ", ", or -)
filter mode     all · error (ERROR issues) · warning (WARNING issues).
issue page      40 consecutive issues of the filtered list.
hex peek        The bytes around the selected issue's address: its 16-byte row, the 6
                rows before and the 6 rows after.
```

#### CTX-LEGEND · Colours and the legend (S3.4)

```text
palette         The colours every colour-coded surface uses:
  Red          #fd8383   error · needs attention
  Pale yellow  #f6ff8f   warning
  Cyan         #7dd3fc   info
  Green        #54efae   ok · verified
  Grey         #969aad   not checked
  White        the default text colour: valid, nothing to report
  Yellow       bold yellow   the search / go-to focus in a hex view
  Orange       orange3       MAC-specific cue: the ⚠ glyph and the MAC address mark
                             in a hex view
legend          The table that explains each colour, per block:
  A2L
    Red          An ERROR issue names the tag, or the tag has no address and is not
                 virtual.
    Green        In image: every byte of the tag is in the loaded S19/HEX.
    White        Out of image, or computed (virtual, or with a conversion method).
    Grey         Not checked: no S19/HEX loaded, or the tag has no address or length.
  MAC
    Red          The line does not parse, or its address differs from the A2L tag of
                 the same name.
    Pale yellow  No A2L tag has this name.
    White        The address is not in the loaded S19/HEX.
    Grey         No A2L file is loaded.
    Green        An A2L tag has the same name and the same address.
    Orange ⚠     The address is not in the loaded S19/HEX (status glyph).
  Issues
    Errors       Data wrong or unusable: parse errors, rejected lines, file integrity
                 notices, duplicate names, A2L↔MAC address mismatch, hard address
                 conflicts, tags with no address.
    Warnings     Something to check: addresses out of the image or overlapped, names in
                 one file only, alias or ambiguous shared addresses, unknown blocks,
                 broken references, addresses over 32 bits, unknown byte order.
    Info         Expected, shown for completeness: MAC names that share an address as
                 bit fields.
  Hex
    Yellow       Search / go-to focus.
    Orange       MAC address.
legend window   A window with the title "Classification legend": a card pane (sample
                lines of the current screen, annotated) and a key pane (the legend
                blocks for the current screen). On the Memory Map: the map sheet in
                place of both panes.
map sheet       Four boxes in one column, each a title and its lines:
  Entropy bands — <window size> B windows, bits/byte
                One band row per band of S4 CTX-ENTROPY, in band order:
                "<glyph>  <band>  <range>  <meaning>"; then the row
                "╱  unmapped gap  (fold)  address hole between runs — not a band".
                <window size>: the entropy window of S4 CTX-ENTROPY, 256.
  Map anatomy   For the band bar, the ruler, the band chips and the stats line of S4
                CTX-MAP: a sample line, then one line that says what it shows.
  Region row    A sample region row (S4 CTX-MAP), then the field line
                "glyph · start · size · size vs largest · A2L sym · band · ↵ opens hex".
  Map keys      The Memory Map's key line (S4 R-TUI-062.10).
```

---

### Requirements


#### S3.1 · Building the issue list (CTX-ISSUE)

| Id | Form | Requirement |
|---|---|---|
| R-VAL-010 | When | When the system adds an issue to the issue list, the system shall remove ANSI escape sequences from its message. |
| R-VAL-011 | When | When the system adds an issue to the issue list, the system shall remove the characters U+0000–U+001F and U+007F from its message. |
| R-VAL-012 | If | If an issue message is longer than 500 characters, then the system shall cut it to 500 characters ending in `…[truncated]`. |
| R-VAL-013 | If | If the issue list would hold the same issue twice, then the system shall keep only the first. |
| R-VAL-014 | When | When the operator loads an S19, Intel HEX, A2L or MAC file, the system shall rebuild the issue list. |
| R-VAL-015 | If | If no file is loaded, then the system shall hold an empty issue list. |
| R-VAL-016 | If | If a load has an integrity notice (S1 R-READ-005 … 008), then the system shall raise an ERROR issue whose code is the notice's code and whose message is the notice's text. |
| R-VAL-017 | If | If a load records a line diagnostic (S1), then the system shall raise the ERROR issue `LOAD_LINE_DIAGNOSTIC` with the diagnostic's line number and message. |
| R-VAL-018 | If | If a MAC file cannot be read, then the system shall raise the ERROR issue `MAC_READ_FAILED` with the read error as its message. |

#### S3.2 · Issue producers (CTX-ISSUE)

**MAC**

| Id | Form | Requirement |
|---|---|---|
| R-VAL-020 | If | If a MAC record has a parse error, then the system shall raise the ERROR issue `MAC_PARSE_ERROR` with the record's line number and its parse error as the message. |
| R-VAL-021 | If | If two or more valid MAC records have the same name, ignoring case, then the system shall raise one ERROR issue `MAC_DUPLICATE_NAME` with the message `MAC symbol '<name>' is defined multiple times.` |
| R-VAL-022 | If | If a shared address is a hard conflict, then the system shall raise one ERROR issue `MAC_DUPLICATE_ADDRESS` for it. |
| R-VAL-023 | If | If a shared address is a segment ambiguity or an alias candidate, then the system shall raise one WARNING issue `MAC_DUPLICATE_ADDRESS` for it. |
| R-VAL-024 | If | If a shared address is a bit-field sharing, then the system shall raise one INFO issue `MAC_DUPLICATE_ADDRESS` for it. |
| R-VAL-025 | When | When the system raises `MAC_DUPLICATE_ADDRESS`, the system shall give it the message `Address <address> has duplicate MAC symbols (<kind>): <names>.` |

**A2L** (any session with an A2L file)

| Id | Form | Requirement |
|---|---|---|
| R-VAL-030 | If | If the A2L file has a parse error (S2 R-A2L-001.4 … 001.6), then the system shall raise the ERROR issue `A2L_STRUCTURE_ERROR` with the parse error as its message. |
| R-VAL-031 | If | If two or more tags have the same name, ignoring case, then the system shall raise one ERROR issue `A2L_DUPLICATE_SYMBOL` with the message `A2L symbol '<name>' is defined multiple times.` |
| R-VAL-032 | If | If an A2L section's name is not a block name of ASAM MCD-2 MC, then the system shall raise the WARNING issue `A2L_UNRECOGNIZED_BLOCK` with the section's line number and the message `Unrecognized A2L block '<NAME>'.` |
| R-VAL-033 | If | If a GROUP or FUNCTION refers, inline or in a child REF_CHARACTERISTIC, REF_MEASUREMENT, DEF_CHARACTERISTIC, IN_MEASUREMENT or OUT_MEASUREMENT block, to a name that no tag has, then the system shall raise the WARNING issue `A2L_BROKEN_REFERENCE` with the message `<GROUP\|FUNCTION> references unknown symbol '<name>'.` |
| R-VAL-034 | U | The system shall compare a reference with tag names respecting case. |
| R-VAL-035 | If | If a tag's schema is not complete (S2 R-A2L-072) and no ERROR A2L issue names it, then the system shall raise the ERROR issue `A2L_TAG_SCHEMA_INCOMPLETE` with the message `A2L tag '<name>' is schema-incomplete: <reason>.` |
| R-VAL-036 | If | If a tag's address is more than 0xFFFFFFFF, then the system shall raise the WARNING issue `A2L_ADDRESS_EXCEEDS_32BIT` with the message `A2L tag '<name>' address <address> exceeds the 32-bit address range (> 0xFFFFFFFF).` |
| R-VAL-037 | If | If a tag's BYTE_ORDER value is not a byte order (S2 R-A2L-028), then the system shall raise the WARNING issue `A2L_UNKNOWN_BYTE_ORDER` with the message `A2L tag '<name>' has unknown byte order '<value>'.` |
| R-VAL-038 | If | If an A2L issue would name an unnamed tag, then the system shall use `Unnamed A2L tag at address <address>` in its message, or `Unnamed A2L tag (no address recorded)` when the tag has no address. |

**Between files** (primary session)

| Id | Form | Requirement |
|---|---|---|
| R-VAL-040 | If | If a valid MAC record's address is not in the primary image, then the system shall raise the WARNING issue `CROSS_MAC_S19_OUT_OF_RANGE` with the message `MAC symbol '<name>' address <address> not present in S19 image.` |
| R-VAL-041 | If | If a valid MAC record's address is an overlap address of the primary image, then the system shall raise the WARNING issue `CROSS_MAC_S19_OVERLAP_AMBIGUOUS` with the message `MAC symbol '<name>' points to overlapped S19 address <address>.` |
| R-VAL-042 | If | If a checked tag is out of image (S2 CTX-A2L-CHECK), then the system shall raise the WARNING issue `CROSS_A2L_S19_OUT_OF_RANGE` with the message `A2L symbol '<name>' range is not fully present in S19 image.` |
| R-VAL-043 | If | If any byte of a checked tag's span is an overlap address, then the system shall raise the WARNING issue `CROSS_A2L_S19_OVERLAP_AMBIGUOUS` with the message `A2L symbol '<name>' points to overlapped S19 address <address>.` |
| R-VAL-044 | If | If an A2L tag and a valid MAC record have the same name, ignoring case, and different addresses, then the system shall raise the ERROR issue `TRIPLE_NAME_ADDRESS_MISMATCH` with the message `Symbol '<name>' has address mismatch (A2L=<address>, MAC=<address>).` |
| R-VAL-045 | If | If a MAC file is loaded and a tag with an address has no valid MAC record of the same name, then the system shall raise the WARNING issue `CROSS_A2L_ONLY_SYMBOL` with the message `A2L symbol '<name>' missing from MAC.` |
| R-VAL-046 | If | If an A2L file is loaded and a valid MAC record has no tag of the same name, then the system shall raise the WARNING issue `CROSS_MAC_ONLY_SYMBOL` with the message `MAC symbol '<name>' missing from A2L.` |
| R-VAL-047 | When | When the system names a tag or MAC record in an issue, the system shall use the name as the file writes it, from its first occurrence. |
| R-VAL-048 | When | When the system raises `TRIPLE_NAME_ADDRESS_MISMATCH`, the system shall give the issue the A2L tag's address. |

**Coverage**

| Id | Form | Requirement |
|---|---|---|
| R-VAL-050 | U | The system shall compute MAC→S19 coverage as CTX-ISSUE defines it, in percent. |
| R-VAL-053 | U | The system shall compute A2L→S19 coverage as CTX-ISSUE defines it, in percent. |
| R-VAL-054 | U | The system shall compute A2L↔MAC coverage as CTX-ISSUE defines it, in percent. |
| R-VAL-051 | If | If the count a coverage divides by is 0, then the system shall give that coverage as 0.0 %. |
| R-VAL-052 | If | If no primary image is loaded, then the system shall compute no coverage. |

#### S3.3 · The Issues screen (CTX-ISSUES-SCREEN)

Replaces: R-TUI-025, R-TUI-042 part (b), R-ISSUES-HEXPANE-001, R-ISSUES-RELATED-001. File-derived text here follows S1's R-TUI-103 family (the Issues view is on its list).

| Id | Form | Requirement |
|---|---|---|
| R-TUI-025.1 | While | While the Issues screen is shown, the system shall give the issue list 2/3 of the width. |
| R-TUI-025.18 | While | While the Issues screen is shown, the system shall give the hex peek 1/3 of the width. |
| R-TUI-025.2 | When | When the system shows the Issues screen, the system shall show the severity strip with the counts of the whole issue list. |
| R-TUI-025.3 | When | When the system shows the Issues screen, the system shall show the summary line. |
| R-TUI-042b.1 | When | When the system shows an issue page, the system shall group its issues by severity in the order ERROR, WARNING, INFO. |
| R-TUI-042b.2 | When | When the system shows a group, the system shall head it with its group header, counting the issues of that severity in the whole filtered list. |
| R-TUI-042b.3 | If | If an issue page holds no issue of a severity, then the system shall show no header for that severity. |
| R-TUI-042b.4 | When | When the system shows an issue, the system shall show its issue row in the colour of its severity. |
| R-ISSUES-RELATED-001 | When | When the system shows an issue row, the system shall show the issue's related artifacts joined by `, `, or `-` when it has none. |
| R-TUI-025.4 | When | When the operator presses `Issues: All`, the system shall show every issue. |
| R-TUI-025.5 | When | When the operator presses `Errors`, the system shall show only ERROR issues. |
| R-TUI-025.6 | When | When the operator presses `Warnings`, the system shall show only WARNING issues. |
| R-TUI-025.7 | When | When the operator picks a filter mode, the system shall mark its button as active. |
| R-TUI-025.8 | When | When the filter mode changes, the system shall show the first issue page. |
| R-TUI-025.9 | When | When the operator presses PgDn on the Issues screen, the system shall show the next issue page. |
| R-TUI-025.10 | When | When the operator presses PgUp on the Issues screen, the system shall show the previous issue page. |
| R-TUI-025.11 | If | If the operator asks for the next issue page while the last one is shown, then the system shall keep the last page. |
| R-TUI-025.12 | If | If the operator asks for the previous issue page while the first one is shown, then the system shall keep the first page. |
| R-TUI-025.13 | If | If the filtered list has more than one issue page, then the system shall show `More issues on other pages — use PgUp/PgDn to page.` under the list. |
| R-TUI-025.14 | If | If the issue list is empty, then the system shall show `No validation issues.` as the summary line. |
| R-TUI-025.15 | If | If the issue list is not empty and the filter mode matches no issue, then the system shall show `No issue matches the filter.` as the summary line. |
| R-TUI-025.16 | When | When the operator presses Down on the issue list, the system shall move the focus to the next issue row. |
| R-TUI-025.17 | When | When the operator presses Up on the issue list, the system shall move the focus to the previous issue row. |
| R-ISSUES-HEXPANE-001.1 | When | When the operator selects an issue row whose issue has an address, the system shall show the hex peek of that address. |
| R-ISSUES-HEXPANE-001.2 | If | If the selected issue has no address, then the system shall show `(issue has no address — nothing to show)` in the hex peek. |
| R-ISSUES-HEXPANE-001.3 | When | When the operator loads a file, the system shall clear the hex peek. |

#### S3.4 · Colours and the legend (CTX-LEGEND)

Replaces: the A2L and MAC colour blocks (their rules are S2 R-A2L-080 … 088 and R-MAC-031 … 035), amendments C and F, R-LEGEND-SOURCE-001, R-LEGEND-MODAL-001, R-LEGEND-GEOMETRY-001, R-TUI-047.

| Id | Form | Requirement |
|---|---|---|
| R-LEGEND-010 | U | The system shall draw every severity colour, on every screen, from the palette of CTX-LEGEND. |
| R-LEGEND-011 | U | The system shall show the legend rows of CTX-LEGEND. |
| R-LEGEND-SOURCE-001 | U | The system shall show the same legend rows in the legend window and in the project report. |
| R-TUI-047 | U | The system shall name each colour of the Hex block after the style the hex view uses for it. |
| R-LEGEND-MODAL-001.1 | When | When the operator presses `k` outside a text box, the system shall open the legend window. |
| R-LEGEND-MODAL-001.2 | When | When the operator presses `Legend` on the MAC View or the Issues screen, the system shall open the legend window. |
| R-LEGEND-MODAL-001.3 | If | If no file is loaded, then the system shall still open the legend window with its blocks. |
| R-LEGEND-MODAL-001.4 | When | When the legend window opens on the A2L Explorer, the system shall show the A2L block. |
| R-LEGEND-MODAL-001.5 | When | When the legend window opens on the MAC View, the system shall show the MAC block. |
| R-LEGEND-MODAL-001.6 | When | When the legend window opens on the Issues or Checks screen, the system shall show the Issues block. |
| R-LEGEND-MODAL-001.7 | When | When the legend window opens on the Workspace, the Patch Editor or the A↔B diff, the system shall show the Hex block. |
| R-LEGEND-MODAL-001.8 | When | When the legend window opens on a screen other than the Memory Map that has no block of its own, the system shall show every block. |
| R-LEGEND-MODAL-001.9 | When | When the system shows a legend row, the system shall show it as `<classification> — <meaning>` in its colour. |
| R-LEGEND-MODAL-001.10 | When | When the legend window opens on the Workspace, the A2L Explorer, the MAC View or the Issues screen, the system shall show in the card pane sample lines of that screen, written as the screen writes them. |
| R-LEGEND-MODAL-001.11 | When | When the legend window opens, the system shall put the focus on `Close`. |
| R-LEGEND-MODAL-001.12 | When | When the operator presses `Close` or Esc in the legend window, the system shall close it. |
| R-LEGEND-GEOMETRY-001.1 | While | While the screen is at least 120 columns wide, the system shall show the card pane on the left, 3/5 of the window width. |
| R-LEGEND-GEOMETRY-001.6 | While | While the screen is at least 120 columns wide, the system shall show the key pane on the right, 2/5 of the window width. |
| R-LEGEND-GEOMETRY-001.2 | While | While the screen is less than 120 columns wide, the system shall show the key pane above the card pane. |
| R-LEGEND-GEOMETRY-001.3 | U | The system shall keep the legend window inside the screen. |
| R-LEGEND-GEOMETRY-001.4 | If | If the key pane's rows do not fit its height, then the system shall let the operator scroll it. |
| R-LEGEND-GEOMETRY-001.5 | While | While the screen is 80 columns wide or more, the system shall show the `Legend` buttons of the MAC View and the Issues screen whole. |

**The map sheet** (from S0 HLR-132, HLR-134)

Focus on `Close` and closing with Esc: R-LEGEND-MODAL-001.11, .12 (tested on the sheet: `test_esc_dismisses_the_sheet`). The keys the `Map keys` box names: S4 R-TUI-062.10 (D4-21). No text from a file appears in the sheet.

| Id | Form | Requirement |
|---|---|---|
| R-LEGEND-MAP.1 | When | When the legend window opens on the Memory Map, the system shall show the map sheet of CTX-LEGEND in place of the card pane and the key pane. |
| R-LEGEND-MAP.2 | When | When the system shows the map sheet, the system shall show one band row per band of S4 CTX-ENTROPY, in band order. |
| R-LEGEND-MAP.3 | When | When the system shows a band row of the map sheet, the system shall show it in its band's colour. |
| R-LEGEND-MAP.4 | While | While the terminal is at least 80 columns by 24 rows, the system shall show each line of the map sheet on one row of its box. |
| R-LEGEND-MAP.5 | U | The system shall show the lines of the map sheet as plain text, never as markup. |



<a id="s4"></a>

## S4 · Hex view & Memory Map

### Context notes (informative)

#### CTX-HEX · Hex views (S4.1 … S4.6)

```text
hex view        A pane that shows image bytes as hex rows:
  main          Workspace, middle pane: the whole image of the primary file.
  A2L hex       A2L Explorer, right pane: the image, focused on the selected tag.
  MAC hex       MAC View, right pane: the image, focused on the selected MAC record.
  hex peek      Issues and Checks screens: 13 rows around the selected entry's address.
  diff hex      A↔B diff: the two images side by side.
  result hex    Operations window: the output image of an operation, from address 0.
hex row         16 bytes from an address that is a multiple of 16 (the row base).
present row     A hex row with at least one byte in the image.
row format      <marker><address>  <16 × "XX ">|<16 text characters>|
                marker: "> " on the target row, else two spaces.
                address: 0x + 8 uppercase hexadecimal digits.
                text: the byte as a character when it is 0x20-0x7E, else ".".
                A byte not in the image: three spaces in hex, one space in text.
byte class      00 or FF: grey #969aad · 0x20-0x7E: cyan #7dd3fc · other: light #e9e9e9.
hex page        A run of consecutive present rows; its size is the hex page size
                (25, 50, 100, 150 or 200 rows, set in the viewer settings).
target          The address a go-to, a search hit or a selection asks a hex view to show.
target row      The present row that holds the target, or, when none does, the first
                present row after it, or the last present row (snapping).
focus colour    bold yellow: a search hit, or the selected A2L tag's span.
MAC mark        orange3 on the byte at a valid MAC record's address.
notice line     A line above the rows that explains the window:
                ... window limited to <n> rows ...
                ... showing from <address> ...
                ... address <address> not present ...
address input   The text typed in a go-to box.
```

#### CTX-ENTROPY · The entropy model (S4.7)

```text
entropy window  256 consecutive image bytes. Windows start at each range's start, every
                256 bytes; the last window of a range may be shorter. No window crosses
                a gap.
entropy         Shannon entropy of the window's bytes: H = -Σ p·log2 p over the 256
                byte values, in bits per byte, 0.0 to 8.0.
low confidence  A window with fewer than 64 bytes.
band            constant/padding  0.0 ≤ H < 1.0   glyph ·  colour #6b7280
                low               1.0 ≤ H < 5.0   glyph ░  colour #5fb98a
                medium            5.0 ≤ H < 7.2   glyph ▒  colour #d9a35b
                high/random       7.2 ≤ H ≤ 8.0   glyph ▓  colour #e06c75
                (A value on a cutoff belongs to the higher band.)
```

#### CTX-MAP · The Memory Map (S4.8)

```text
image span      From the lowest image address to one past the highest.
mapped bytes    The number of addresses in the image.
gap             The addresses between two consecutive ranges (S1 CTX-IMAGE).
coverage        mapped bytes / image span × 100, shown with 4 decimals.
region          A maximal run of consecutive entropy windows with the same band and no
                address break between them. A region has exactly one band; its size is
                a multiple of 256 bytes except at a range's end.
Memory Map      Title, header line, the map pane (band bar, ruler, band chips, region
                list) beside or above the inspector, and the stats line.
band bar        One row: one segment per region, coloured and filled with its band glyph;
                one ╱ column between two regions with a gap between them.
ruler           One row of address labels under the band bar: 8 uppercase hex digits, no 0x.
band chip       <glyph> <regions of that band> <share of mapped bytes>%
region row      " <glyph> 0x<start> <size> [<micro-bar>] <symbols> <band>   ↵"
                size: human-readable, binary units (B, KiB, MiB …, one decimal)
                micro-bar: 4 cells, filled in proportion to region size / largest region
                symbols: the number of named tags whose extent overlaps the region
                band: const, low, medium or high/rand
tag extent      From a tag's address, as many bytes as its length (1 when unknown).
inspector       The pane that describes the selected region: Status, Region, Size,
                Band, Symbols (count, then one name per line), Peek.
peek row        <address, 8 hex digits>  <8 bytes as hh, ·· for a byte not in the image>
stats line      " Mapped <mapped> / <span> span (<coverage>%) · <ranges> ranges (<valid>
                valid) · <gaps> gaps · <issues> issues"; compact form when the line is
                narrower than 84 columns:
                "Mapped <mapped> / <span> <coverage>% · <ranges> rng (<valid> ok) ·
                <gaps> gaps · <issues> iss"
memory strip    The one-row band above the Workspace panes: the whole image span cut
                into cells of equal size.
```

---

### Requirements


#### S4.1 · Hex rows (CTX-HEX)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-004.1 | U | The system shall show every hex row in the row format of CTX-HEX. |
| R-TUI-004.2 | U | The system shall show only present rows in the main, A2L and MAC hex views. |
| R-TUI-004.3 | If | If a valid MAC record's address is outside the image, then the system shall add the row that holds it to the main, A2L and MAC hex views. |
| R-TUI-004.4 | If | If an address of a shown row is not in the image, then the system shall show it as blank in both the hex and the text column. |
| R-TUI-004.5 | U | The system shall colour each byte of the hex column by its byte class. |
| R-TUI-004.6 | U | The system shall show image bytes as plain text, never as markup. |

#### S4.2 · Window and paging

| Id | Form | Requirement |
|---|---|---|
| R-TUI-007.1 | U | The system shall show the main hex view one hex page at a time. |
| R-TUI-007.2 | While | While the operator has set no hex page size, the system shall use 200 rows. |
| R-TUI-007.3 | When | When the operator presses `.` on the Workspace, the system shall show the next hex page. |
| R-TUI-007.4 | When | When the operator presses `,` on the Workspace, the system shall show the previous hex page. |
| R-TUI-007.5 | If | If the operator asks for the next hex page while the last one is shown, then the system shall keep the last page. |
| R-TUI-007.6 | If | If the operator asks for the previous hex page while the first one is shown, then the system shall keep the first page. |
| R-TUI-007.7 | If | If the operator presses `,` or `.` on a screen other than the Workspace, then the system shall leave every hex view unchanged. |
| R-TUI-007.8 | U | The system shall count the rows added for MAC records (R-TUI-004.3) in the hex pages of the main view. |
| R-TUI-007.9 | When | When the operator loads a file, the system shall show the first hex page. |
| R-TUI-007.10 | If | If more present rows follow the shown window, then the system shall show the notice line `... window limited to <n> rows ...`. |
| R-TUI-007.11 | If | If the shown window does not start at the first present row, then the system shall show the notice line `... showing from <address> ...`. |
| R-TUI-007.12 | While | While the A2L or MAC hex view has no target, the system shall show it from the first present row. |
| R-TUI-007.13 | If | If no file is loaded, then the system shall show `No file loaded.` in each hex view. |
| R-TUI-007.14 | If | If a loaded file has no present row, then the system shall show `No data available.` in each hex view. |

#### S4.3 · Go to an address

| Id | Form | Requirement |
|---|---|---|
| R-TUI-040.1 | When | When the operator presses `g` on the Workspace, the A2L Explorer or the MAC View, the system shall put the focus in that screen's go-to box. |
| R-TUI-040.2 | When | When the operator presses `Goto` or Enter in a go-to box, the system shall go to the address typed in it. |
| R-TUI-040.3 | U | The system shall read an address input as hexadecimal, with or without a `0x` or `0X` prefix. |
| R-TUI-040.4 | If | If the address is in the image, then the system shall show its target row second from the top of the hex view. |
| R-TUI-040.5 | If | If the address is in the image, then the system shall mark its row with `> `. |
| R-TUI-040.6 | If | If the address is in the image, then the system shall show the status `Goto <address>`. |
| R-TUI-040.7 | If | If the address is not in the image, then the system shall show the status `Address <address> not in loaded file.` |
| R-TUI-040.8 | If | If the address is not in the image, then the system shall leave the hex view's rows unchanged. |
| R-TUI-040.9 | If | If the go-to box is empty, then the system shall show the status `Goto address is empty.` |
| R-TUI-040.10 | If | If the go-to box does not hold an address, then the system shall show the status `Invalid address format.` |
| R-TUI-040.11 | If | If a go-to fails, then the system shall remove the view's `> ` marker. |
| R-TUI-040.12 | When | When a hex view pages, starts a new search, jumps to a new target or loads a file, the system shall remove its `> ` marker. |

#### S4.4 · Search

| Id | Form | Requirement |
|---|---|---|
| R-TUI-017.1 | When | When the operator presses `Find Next` or Enter in a search box, the system shall find the next place where the image holds the search text, ignoring the case of ASCII letters. |
| R-TUI-017.2 | U | The system shall find a search text only inside one range, never across a gap. |
| R-TUI-017.3 | If | If the search text differs from the last search of that view, then the system shall search from the start of the image. |
| R-TUI-017.4 | If | If the search text is the last search of that view, then the system shall search from the byte after its last hit. |
| R-TUI-038 | If | If the view has paged, jumped to another target, or missed since its last hit, then the system shall search from the first shown row. |
| R-TUI-017.5 | U | The system shall keep the search text, last hit and highlight of each hex view apart from the others. |
| R-TUI-017.6 | When | When a search finds the text, the system shall draw the found bytes in the focus colour. |
| R-TUI-017.7 | When | When a search finds the text, the system shall show its row as the target row. |
| R-TUI-017.8 | When | When a search finds the text, the system shall show the status `Found at <address>`. |
| R-TUI-017.9 | If | If the search finds nothing, then the system shall show the status `Search text not found.` |
| R-TUI-017.10 | If | If the search box is empty, then the system shall show the status `Search text is empty.` |
| R-TUI-017.11 | If | If no file is loaded when the operator searches, then the system shall show the status `No file loaded.` |

#### S4.5 · Jumps and marks

Selecting an A2L tag or a MAC record is in S2 (R-A2L-100 … 104, R-MAC-054 … 056); these rows set where any jump lands.

| Id | Form | Requirement |
|---|---|---|
| R-TUI-018.1 | When | When a hex view jumps to a target, the system shall show the target row second from the top. |
| R-TUI-018.2 | When | When a hex view jumps to a target, the system shall scroll the view back to its left edge. |
| R-TUI-018.3 | If | If no present row holds the target, then the system shall use the target row of CTX-HEX (the next present row, or the last). |
| R-TUI-009.1 | When | When the operator selects a range in the Workspace section list, the system shall jump the main hex view to the range's start. |
| R-TUI-009.2 | When | When the operator selects a range in the Workspace section list, the system shall show the status `Section at <address>`. |
| R-HEX-MARK.1 | When | When the system shows the main, A2L or MAC hex view, the system shall draw the MAC mark on the byte at each valid MAC record's address. |
| R-HEX-MARK.2 | If | If a byte has both the focus colour and the MAC mark, then the system shall draw it in the focus colour. |
| R-HEX-MARK.3 | When | When the system shows a hex peek, the system shall mark the row that holds the entry's address with `> `. |

#### S4.6 · Layout

| Id | Form | Requirement |
|---|---|---|
| R-TUI-010 | While | While the Workspace is shown, the system shall give the main hex view the whole height of the middle pane. |
| R-WS-HEXROW-001.1 | While | While the Workspace is shown, the system shall show each hex row on one line. |
| R-WS-HEXROW-001.2 | If | If the middle pane is narrower than a hex row, then the system shall let the operator scroll it sideways. |
| R-WS-HEXROW-001.3 | While | While the Workspace is shown, the system shall keep its three panes visible. |
| R-HEX-LAYOUT.1 | If | If the A2L or MAC hex pane is narrower than a hex row, then the system shall let the operator scroll it sideways. |

#### S4.7 · Entropy (CTX-ENTROPY)

| Id | Form | Requirement |
|---|---|---|
| R-ENT-001 | When | When a primary image loads, the system shall compute its entropy windows once. |
| R-ENT-002 | U | The system shall cut the image into entropy windows as CTX-ENTROPY defines them. |
| R-ENT-003 | U | The system shall give each entropy window its entropy and its band. |
| R-ENT-004 | If | If an entropy window has fewer than 64 bytes, then the system shall mark it low confidence. |
| R-ENT-005 | If | If the primary image is unloaded, then the system shall drop its entropy windows. |

#### S4.8 · The Memory Map (CTX-MAP)

**Header, layout, empty states**

| Id | Form | Requirement |
|---|---|---|
| R-TUI-060.1 | When | When the Memory Map shows an image with entropy windows, the system shall show the header `Entropy bands - <regions> region(s), <mapped bytes> mapped`, with the size human-readable. |
| R-TUI-060.2 | U | The system shall build the Memory Map's regions as CTX-MAP defines them. |
| R-TUI-061.4 | While | While the Memory Map panel is at least 86 columns wide, the system shall show the inspector beside the map pane. |
| R-TUI-061.6 | While | While the Memory Map panel is at least 86 columns wide, the system shall make the inspector 44 columns wide. |
| R-TUI-061.5 | While | While the Memory Map panel is less than 86 columns wide, the system shall show the inspector under the map pane. |
| R-TUI-060.3 | If | If no file is loaded, then the system shall show `No file loaded - press Ctrl+L (or 'l') to load a file, or 'p' to load a saved project.` instead of the Memory Map. |
| R-TUI-060.4 | If | If no primary image is loaded and another file is, then the system shall show the header `No S19/HEX image loaded.` |
| R-TUI-060.5 | If | If the primary image has no entropy windows, then the system shall show the header `No entropy detail for this image.` |
| R-MAP-PANE.1 | When | When the Memory Map shows regions, the system shall title the map pane `Memory Map`. |
| R-MAP-PANE.2 | When | When the Memory Map shows regions, the system shall show under the map pane the subtitle `<regions> regions · ░▒▓ k`. |

**Band bar, ruler, chips**

| Id | Form | Requirement |
|---|---|---|
| R-TUI-103B.1 | U | The system shall size the band bar to the width the bar has on screen. |
| R-TUI-103B.2 | U | The system shall give each region at least one column of the band bar. |
| R-TUI-103B.3 | U | The system shall give each gap between two regions exactly one column of the band bar, drawn as `╱`. |
| R-TUI-103B.4 | U | The system shall share the remaining columns among the regions in proportion to their mapped bytes, by largest remainder. |
| R-TUI-103B.5 | U | The system shall keep every band-bar column inside the bar. |
| R-TUI-072.1 | U | The system shall label the ruler at each region start and at the last mapped byte. |
| R-TUI-072.2 | If | If the labels do not fit the ruler, then the system shall keep the first and last label and as many evenly spaced others as fit. |
| R-TUI-072.3 | U | The system shall place each ruler label under the column of the band bar where its address starts. |
| R-TUI-061.1 | When | When the Memory Map shows regions, the system shall show one band chip per band that has regions, in band order. |
| R-TUI-062.9 | When | When the operator clicks a band-bar segment, the system shall act as for a click on its region row. |

**Region list and inspector**

| Id | Form | Requirement |
|---|---|---|
| R-TUI-073.1 | When | When the Memory Map shows regions, the system shall show one region row per region, in address order. |
| R-TUI-073.2 | If | If the map pane leaves fewer than 43 columns for the row, then the system shall leave out the micro-bar. |
| R-TUI-073.3 | U | The system shall count in a region row's symbols the named tags whose extent overlaps the region. |
| R-TUI-073.4 | U | The system shall keep the columns of the region rows aligned for any size and symbol count. |
| R-TUI-062.1 | When | When the operator clicks a region row once, the system shall select the region and show it in the inspector. |
| R-TUI-062.2 | When | When the operator double-clicks a region row, the system shall open the main hex view at the region's start. |
| R-TUI-062.3 | When | When the operator presses Enter on a region row, the system shall open the main hex view at the region's start. |
| R-TUI-062.4 | When | When the operator presses Down in the region list, the system shall select the next region and show it in the inspector. |
| R-TUI-062.11 | When | When the operator presses Up in the region list, the system shall select the previous region and show it in the inspector. |
| R-TUI-062.5 | If | If the first or last region is selected, then the system shall keep it when the operator moves past it. |
| R-TUI-062.6 | When | When the Memory Map is drawn again, the system shall select the region that starts at the same address as the one selected before, or the first region when there is none. |
| R-TUI-062.7 | When | When the Memory Map is drawn again, the system shall stay on the Memory Map. |
| R-TUI-062.8 | When | When the system opens the main hex view from the Memory Map, the system shall switch to the Workspace and jump to the region's start (S4.5). |
| R-TUI-074.1 | If | If no region is selected, then the system shall show `Click a region to inspect it.` and `Double-click to open in hex.` in the inspector. |
| R-TUI-074.2 | When | When the inspector shows a region, the system shall title it `Inspector — <start address>`. |
| R-TUI-074.3 | When | When the inspector shows a region, the system shall show its Status: `VALID` or `INVALID` from the validity of its range (S1 R-VAL-001b). |
| R-TUI-074.4 | When | When the inspector shows a region, the system shall show its first and last address. |
| R-TUI-074.10 | When | When the inspector shows a region, the system shall show its size, human-readable. |
| R-TUI-074.11 | When | When the inspector shows a region, the system shall show its band glyph and name. |
| R-TUI-074.5 | When | When the inspector shows a region, the system shall list the names of the tags whose extent overlaps it, ordered by address then name. |
| R-TUI-074.6 | When | When the inspector shows a region, the system shall show peek rows from the 8-byte boundary at or before the region's start. |
| R-TUI-074.7 | When | When the inspector shows peek rows, the system shall show as many as fit the inspector's height. |
| R-TUI-074.8 | If | If a peek byte is not in the image, then the system shall show it as `··`. |
| R-TUI-074.9 | If | If a symbol name is wider than the inspector, then the system shall cut it and end it with `…`. |

**Stats line, key line**

| Id | Form | Requirement |
|---|---|---|
| R-TUI-041.1 | When | When the Memory Map shows an image, the system shall show the stats line of CTX-MAP, with sizes human-readable. |
| R-TUI-041.2 | If | If the stats line is narrower than 84 columns, then the system shall show its compact form. |
| R-TUI-041.3 | U | The system shall count in the stats line's issues every issue of the issue list (S3). |
| R-TUI-041.4 | U | The system shall keep the Memory Map's stats line in view at every scroll position of the region list. |
| R-TUI-062.10 | U | The system shall name in the Memory Map's key line, inspector subtitle and row glyphs only keys that the Memory Map handles. |

**Memory strip** (shown on the Workspace)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-067.1 | U | The system shall show at most as many memory-strip cells as the strip has columns. |
| R-TUI-067.5 | U | The system shall make every memory-strip cell cover the same number of addresses. |
| R-TUI-067.6 | U | The system shall start no memory-strip cell beyond the image span. |
| R-TUI-067.2 | When | When the image has entropy windows, the system shall show each strip cell with the glyph and colour of the band that covers most of its bytes. |
| R-TUI-067.3 | If | If a strip cell holds no image byte, then the system shall show it as `╱` in grey. |
| R-TUI-067.4 | If | If the image has no entropy windows, then the system shall show each strip cell as `█` in the colour of its range validity (valid green, invalid red, gap grey). |



<a id="s5"></a>

## S5 · Workspace & file I/O

### Context notes (informative)

#### CTX-WORKAREA · Folders and copies (S5.1 … S5.3)

```text
start folder     The folder the app is started in.
.s19tool/        <start folder>/.s19tool: the app's own folder.
work area        .s19tool/workarea/. It holds:
  temp/          copies of the files the operator loads
  patches/       change documents and check files when no project is open (S8, S9)
  <project>/     one folder per project (S11)
log folder       .s19tool/logs/ (beside the work area, not in it).
copy             A file the system writes into temp/ from a file outside the work area.
placement        A file the system writes into a folder of the work area: a copy into
                 temp/, a file saved into a project (S11), a save-back (S8), an
                 export (S17).
destination      The folder a placement writes into.
same content     Two files with the same size and the same SHA-256.
numbered name    <stem>_<N><suffix>, N one or more digits (for fw.s19: fw_1.s19,
                 fw_2.s19 …).
name match       Two names are equal; on Windows, equal ignoring case.
reuse candidate  A file of the destination whose name matches the file's name or one
                 of its numbered names, and that is a regular file.
copy limit       256 MiB (268,435,456 bytes).
link             A symbolic link, a junction or another reparse point.
```

#### CTX-FILES · File kinds and loading (S5.3, S5.4)

```text
file kind        By extension, ignoring case:
  S19            .s19 .srec
  Intel HEX      .hex .ihex
  MAC            .mac
  A2L            .a2l
data file        An S19, Intel HEX or MAC file.
primary          The S19 or Intel HEX file of the session (one at a time).
companion        The A2L file and the MAC file of the session (one of each at a time).
path input       What the operator types in the load box. Whitespace around it and
                 double quotes are removed; a leading ~ is the home folder.
work-area pick   A pick of a Workarea Files row, or of a work-area row in the Load
                 dialog (S7 R-LOADDLG.27, .61).
painted name     A file name as shown: every character of Unicode category Cc, Cf,
                 Zl or Zp removed, an unpaired surrogate shown as U+FFFD; a result
                 over 120 characters becomes its first 119 characters and "…".
                 In a status text below, <name> is the painted name.
load status      The status line after a load:
  Loaded <name> with integrity notices: <codes>      (any integrity notice, S1)
  Loaded <name> (<S19|HEX>+MAC: <MAC file name>)     (primary + MAC)
  Loaded <name> (<S19|HEX> only)                     (primary, no MAC)
  Loaded <name> (MAC only)                           (MAC, no primary)
load outcome     Loaded <name>
file-load steps  The long action of a file load (S6 CTX-BUSY): label "Loading <name>";
                 steps "Copy into the work area", "Parse", "Install".
session action   As S6 CTX-BUSY.
```

#### CTX-WORKSPACE · The Workspace screen (S5.6 … S5.8)

```text
Workspace        Header ("Workspace" and a ? chip), the memory strip (S4), the loaded
                 panel, and three panes:
  left           "Workspace" — Load project (p) button, Workarea Files list,
                 Data Sections list
  middle         "Hex View" — search and go-to boxes, the main hex view (S4)
  right          "Context" — Coverage Stats, then the A2L summary (S2)
section row      Three lines:
                 <validity glyph> 0x<start>
                 – 0x<last>  <size, human-readable, 9 wide> <band glyph>
                 <8-cell micro-bar: size / largest range>
MAC row          MAC out-of-range
                 @ 0x<address>
stats pane       Coverage: <coverage, 2 decimals>%   (— when there is no range)
                 Ranges: <ranges>
                 Errors: <ERROR issues>
                 Warnings: <WARNING issues>
                 Loader <N> err · ⚠<K> OOO · Entry <address or —>
                   N: line diagnostics + integrity notices of the primary (S1)
                   K: out-of-order records (S19; 0 for Intel HEX)
                   Entry: address of the first S7/S8/S9 record; — for Intel HEX or
                          when there is none
loaded panel     Title "Loaded"; rows PROJ, <S19|HEX>, MAC, A2L, then "unload all [U]".
  PROJ           (none) · <project> · <project>:<variant> (<i>/<N>)
  primary slot   <file name>  <mapped bytes, human-readable> · <ranges> rng
  MAC slot       <file name>  <n> record(s)
  A2L slot       <file name>  <n> tag(s)
  empty slot     (none), dim, no button
empty state      No file loaded - press Ctrl+L (or 'l') to load a file, or 'p' to load a
                 saved project.
```

---

### Requirements


#### S5.1 · The work area (CTX-WORKAREA)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-001.1 | When | When the system starts, the system shall create the work area under the start folder if it does not exist. |
| R-TUI-001.2 | When | When the system starts, the system shall create `workarea/temp/` if it does not exist. |
| R-TUI-001.3 | When | When the system starts, the system shall create `workarea/patches/` if it does not exist. |
| R-TUI-001.4 | When | When the system starts, the system shall create the log folder if it does not exist. |
| R-TUI-001.5 | If | If the system cannot create one of these folders, then the system shall print an error that names the folder and stop with a non-zero exit status. |

#### S5.2 · Copies

| Id | Form | Requirement |
|---|---|---|
| R-TUI-002.1 | When | When the operator loads a file from outside the work area, the system shall copy it into `temp/` before reading it. |
| R-TUI-002.2 | When | When the operator loads a file that is already in the work area, the system shall read it where it is. |
| R-TUI-006.1 | If | If the destination holds a reuse candidate with the same content, then the system shall use that file and write nothing. |
| R-TUI-006.2 | If | If the file's name is taken in the destination by a different content, then the system shall name the new file with the lowest free numbered name. |
| R-TUI-011 | U | The system shall keep every copy in `temp/` until the operator deletes it. |
| R-TUI-002.3 | If | If the file to copy is a link, then the system shall refuse it with the reason `Refusing to copy: source is a symbolic link or reparse point: <path>`. |
| R-TUI-002.4 | If | If the file to copy is larger than the copy limit, then the system shall refuse it with the reason `Refusing to copy: source size <n> bytes exceeds cap <limit> bytes: <path>`. |
| R-TUI-002.5 | If | If a copy would be written outside the work area, then the system shall refuse it with the reason `Refusing to place: destination is not contained inside <work area>: <path>`, where `<work area>` is the work-area folder's path. |
| R-TUI-002.6 | If | If the target file stays locked after 5 attempts within 1 second, then the system shall refuse the copy with the reason `Not saved: <name> in <folder> is still locked after 5 retries, another program may hold it — close it and retry. Nothing written.` |
| R-TUI-002.7 | If | If the system refuses to copy an S19, Intel HEX or MAC file, then the system shall show the status `Cannot load file: <reason>`. |
| R-TUI-002.8 | If | If the system refuses to copy an A2L file, then the system shall show the status `Cannot load A2L: <reason>`. |

#### (from batch-100 HLR-163) Reuse rules and the destination guard

| Id | Form | Requirement |
|---|---|---|
| R-TUI-006.3 | If | If a file of the destination with the same content is empty, then the system shall not reuse it. |
| R-TUI-006.4 | If | If a file of the destination with the same content is a link, then the system shall not reuse it. |
| R-TUI-006.5 | If | If more than one reuse candidate has the same content, then the system shall reuse the one under the file's own name, else the one with the lowest number. |
| R-TUI-002.9 | If | If the destination, or a folder on its path inside the work area, is a link, then the system shall refuse the placement with the reason `Refusing to place: destination traverses a symbolic link or reparse point: <path>`. |

#### S5.3 · Path input and file kinds (CTX-FILES)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-005.1 | U | The system shall take a file's kind from its extension, ignoring case. |
| R-TUI-005.2 | When | When the operator submits a path input, the system shall remove the whitespace around it. |
| R-TUI-005.9 | When | When the operator submits a path input, the system shall remove its double quotes. |
| R-TUI-005.3 | When | When a path input starts with `~`, the system shall read `~` as the operator's home folder. |
| R-TUI-005.4 | If | If a relative path input does not name an existing file from the current folder, then the system shall look for it under the start folder. |
| R-TUI-005.5 | U | The system shall not look for a path input in any parent folder of the start folder. |
| R-TUI-005.6 | If | If the file of a load can no longer be found when the load starts, then the system shall show the status `File not found: <path>`. |

R-TUI-005.7 and .8 (status for a typed folder or an unsupported typed path) are retired here: since batch-100 every typed path gets a class in the Load dialog before any load (S7 R-TUI-043.14 … .24, R-LOADDLG.71 … .77; D5-42).

#### S5.4 · Loading

| Id | Form | Requirement |
|---|---|---|
| R-TUI-012L.1 | When | When the operator loads a primary, the system shall replace the session's primary with it. |
| R-TUI-012L.2 | When | When the operator loads a primary, the system shall keep the session's A2L and MAC. |
| R-TUI-012L.3 | When | When the operator loads a MAC file, the system shall replace the session's MAC with it. |
| R-TUI-012L.4 | When | When the operator loads a MAC file, the system shall keep the session's primary and A2L. |
| R-TUI-012L.5 | U | The system shall keep the screen responsive while it parses an S19, Intel HEX or MAC file. |
| R-TUI-012L.6 | When | When the system copies and parses an S19, Intel HEX or MAC file, the system shall show the progress (S6 CTX-BUSY, R-PROGRESS-LINE.1 … .11) with the file-load steps of CTX-FILES. |
| R-TUI-012L.8 | When | When a load ends, the system shall show the load status of CTX-FILES for the file just loaded. |
| R-TUI-012L.12 | When | When a file load ends, the system shall show the status `Loaded <name>` after the load status. |
| R-TUI-012L.9 | If | If parsing a file fails, then the system shall show the status `Load failed: <reason>`. |
| R-TUI-012L.10 | If | If copying or parsing an A2L file fails for a reason other than a refused copy, then the system shall show the status `File NOT loaded: '<name>' could not be read — check that the file can be opened, then load again.` |
| R-TUI-012L.11 | If | If copying or parsing an A2L file fails, then the system shall keep the A2L that was loaded before. |

R-TUI-012L.7 (a load requested while another runs) is retired here: S6 R-BUSY-REFUSE.1 and .6 state the refusal and that no load question opens (D5-40).

#### S5.5 · Files list, open folder, log

| Id | Form | Requirement |
|---|---|---|
| R-WS-FILES.1 | When | When the system shows the Workarea Files list, the system shall list the regular files directly in `temp/` whose kind is in CTX-FILES, ordered by name ignoring case. |
| R-WS-FILES.2 | When | When the system starts, ends a load or the operator presses `r`, the system shall refresh the Workarea Files list. |
| R-WS-FILES.3 | When | When the operator selects a row in the Workarea Files list, the system shall load the file whose on-disk name the row holds. |
| R-WS-FILES.4 | If | If the selected file no longer exists, then the system shall show the status `File NOT loaded: '<name>' not found — pick another file.` |
| R-WS-FILES.5 | U | The system shall show file names in the Workarea Files list as plain text, never as markup. |
| R-TUI-008.1 | When | When the operator presses `o`, the system shall open the work area in the system's file manager. |
| R-TUI-008.2 | When | When the system has opened the work area, the system shall show the status `Opened workarea: <path>`. |
| R-TUI-008.3 | If | If the file manager cannot be started, then the system shall show the status `Failed to open workarea: <reason>`. |
| R-TUI-008.4 | If | If the work area is not a real folder inside `.s19tool/`, then the system shall refuse to open it with the status `Refused to open workarea: not a real folder inside <root>/`. |
| R-TUI-015.1 | U | The system shall write its log to `.s19tool/logs/s19tui.log`. |
| R-TUI-015.2 | If | If the log file reaches 5 MiB, then the system shall start a new log file. |
| R-TUI-015.3 | U | The system shall keep one previous log file. |
| R-TUI-015.4 | When | When a load ends, the system shall write the log line `Load summary: file_type=<kind> path=<path> addresses=<n> range_count=<n> range_bytes=<n> errors=<n>`. |

R-WS-FILES.6 (list the loadable files written at the work-area root, `splits/`, `crc/`) is retired: batch-100 keeps the list to `temp/` (D5-43).

#### (from batch-100 HLR-172b) Workarea Files names and picks

| Id | Form | Requirement |
|---|---|---|
| R-WS-FILES.7 | If | If an entry of `temp/` is a link, then the system shall leave it out of the Workarea Files list. |
| R-WS-FILES.8 | If | If the name of a file in `temp/` ends in a dot or a space, then the system shall leave the file out of the Workarea Files list. |
| R-WS-FILES.9 | If | If `temp/` is missing, is a link or cannot be listed, then the system shall show an empty Workarea Files list. |
| R-WS-FILES.10 | U | The system shall show each file name of the Workarea Files list as its painted name. |
| R-WS-FILES.11 | If | If the picked file no longer exists, then the system shall not ask the load question. |
| R-WS-FILES.12 | If | If a work-area pick is not a regular file when the load runs, then the system shall refuse the load with the status `File NOT loaded: '<name>' is not a regular file — pick another file.` |
| R-WS-FILES.13 | If | If a work-area pick is larger than the copy limit when the load runs, then the system shall refuse the load with the status `File NOT loaded: '<name>' is too large to open — load a smaller file.` |
| R-WS-FILES.14 | When | When the operator makes a work-area pick while a project is open, the system shall leave the project unchanged. |
| R-WS-FILES.15 | If | If a work-area pick of an A2L file fails, then the system shall keep the rows and the cursor of the Workarea Files list. |

The busy refusal of a work-area pick, `U` and the Loaded panel's unload is S6's (R-BUSY-REFUSE.1, .6; CTX-BUSY refused list).

#### S5.6 · The Workspace screen (CTX-WORKSPACE)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-029.1 | While | While the Workspace is shown at 120 columns or more, the system shall make the left pane 22 columns wide. |
| R-TUI-029.6 | While | While the Workspace is shown at 120 columns or more, the system shall make the right pane 40 columns wide. |
| R-TUI-029.2 | While | While the Workspace is shown at less than 120 columns, the system shall make the left pane 24 % of the width. |
| R-TUI-029.7 | While | While the Workspace is shown at less than 120 columns, the system shall make the right pane 30 % of the width. |
| R-TUI-029.3 | While | While the Workspace is shown, the system shall give the middle pane the rest of the width. |
| R-TUI-029.4 | If | If no file is loaded, then the system shall show the empty state on the Workspace, Issues, Memory Map and Checks screens. |
| R-TUI-066.1 | When | When the system shows the primary's ranges, the system shall show one section row per range, in address order. |
| R-TUI-066.2 | When | When the system shows a section row, the system shall colour it green for a valid range and red for an invalid one. |
| R-TUI-066.3 | When | When the system shows a section row, the system shall show a validity glyph that matches the range's validity. |
| R-TUI-066.4 | If | If the primary has more than 200 ranges, then the system shall show the first 200 and the row `... <n> more ranges (see log) ...`. |
| R-TUI-066.5 | When | When a valid MAC record's address is outside the primary image, the system shall add a MAC row for it after the section rows, in address order. |
| R-TUI-066.6 | If | If there are more than 50 MAC rows, then the system shall show the first 50 and the row `... <n> more MAC out-of-range (see Issues panel) ...`. |
| R-TUI-066.7 | When | When the operator selects a MAC row, the system shall jump the main hex view to its address. |
| R-TUI-066.8 | When | When a primary is loaded, the system shall show the stats pane of CTX-WORKSPACE. |
| R-TUI-066.9 | If | If no file is loaded, then the system shall show the stats pane with `Coverage: —` and zero counts. |
| R-TUI-066.11 | If | If no file is loaded, then the system shall leave out the loader line. |
| R-TUI-066.10 | When | When the issue list changes, the system shall update the stats pane's error and warning counts. |

R-TUI-029.5 (keep the left pane visible with no file loaded) is retired: the Load dialog lists the work-area files in the empty state (D5-44).

#### S5.7 · The loaded panel and unloading

| Id | Form | Requirement |
|---|---|---|
| R-WS-LOADED.1 | U | The system shall show the loaded panel of CTX-WORKSPACE above the Workspace panes. |
| R-WS-LOADED.2 | U | The system shall label the primary slot `S19` or `HEX` after the primary's kind. |
| R-WS-LOADED.3 | While | While an A2L file is loaded, the system shall show its A2L slot, with or without a primary. |
| R-WS-LOADED.4 | While | While a slot holds a file, the system shall show a `[u]` button on it. |
| R-WS-LOADED.5 | When | When the operator presses `[u]` on a slot, the system shall unload that slot's file. |
| R-WS-LOADED.6 | When | When the operator presses `U` or `[U]`, the system shall unload the primary, the A2L and the MAC. |
| R-WS-LOADED.7 | When | When the system unloads the primary, the system shall keep the A2L and the MAC loaded. |
| R-WS-LOADED.8 | When | When the system unloads the primary, the system shall drop the primary's image, ranges and entropy windows. |
| R-WS-LOADED.16 | When | When the system unloads the primary, the system shall drop the primary's line diagnostics and integrity notices. |
| R-WS-LOADED.9 | When | When the system unloads the MAC, the system shall keep the primary and the A2L loaded. |
| R-WS-LOADED.10 | When | When the system unloads the A2L, the system shall keep the primary and the MAC loaded. |
| R-WS-LOADED.11 | When | When the system unloads files, the system shall keep the open project. |
| R-WS-LOADED.12 | When | When the system unloads files, the system shall keep their copies in `temp/`. |
| R-WS-LOADED.13 | When | When the system unloads files, the system shall show the status `Unloaded primary image.`, `Unloaded MAC.`, `Unloaded A2L.` or `Unloaded all artifacts.` |
| R-WS-LOADED.14 | If | If nothing is loaded when the operator asks to unload, then the system shall show the status `Nothing to unload.` |
| R-WS-LOADED.15 | U | The system shall show file names in the status line and the loaded panel without control characters. |
| R-WS-LOADED.17 | U | The system shall show file names in the status line and the loaded panel as plain text, never as markup. |

#### S5.8 · Open-folder chips (CTX-CHIPS; from S0 HLR-139, LLR-139.x, LLR-148.x)

```text
CTX-CHIPS  Open-folder chips
  chip           A 📂 button in a window header that opens one folder in the
                 system file manager (explorer on Windows, open on macOS,
                 xdg-open elsewhere).
  chip target    Patch Editor:   <project>/patches/, else workarea/patches/
                 Checks:         <project>/checks/,  else workarea/patches/
                 CRC Designer:   <project>/templates/, else .s19tool/templates/
                 Reports:        <project>/reports/;  none with no project
                 Flow Builder:   <project>/flows/;    none with no project
                 Flow Execution: the project folder;  none with no project
  chip folder    The last name of the chip target; with no target, the name
                 the table above gives (patches, checks, templates, reports,
                 flows).
  chip root      The project folder; with no project, .s19tool/.
```

| Id | Form | Requirement |
|---|---|---|
| R-CHIP-001.1 | U | The system shall label each chip other than the Flow Execution chip `📂 Open <chip folder>/`. |
| R-CHIP-001.2 | U | The system shall label the Flow Execution chip `📂 Open session`. |
| R-CHIP-001.3 | When | When the operator presses an enabled chip, the system shall open its chip target in the system file manager. |
| R-CHIP-001.4 | While | While a chip has no chip target, the system shall show the chip disabled. |
| R-CHIP-001.5 | When | When a chip becomes disabled, the system shall show the status `<label>: no active project — load a project first.` |
| R-CHIP-001.6 | While | While a project is open and the target of a chip other than the Flow Execution chip does not exist, the system shall show the chip dimmed with the tooltip `folder does not exist yet`. |
| R-CHIP-001.12 | While | While no project is open and a chip's target does not exist, the system shall show the chip dimmed with the tooltip `no project — files are in the common folders`. |
| R-CHIP-001.13 | While | While the Flow Execution chip's target does not exist, the system shall show the chip dimmed with the tooltip `project folder is missing`. |
| R-CHIP-001.14 | While | While a chip has no chip target, the system shall show the tooltip `no project — files are in the common folders` on the disabled chip. |
| R-CHIP-001.7 | When | When the operator presses a chip other than the Flow Execution chip whose chip target does not exist, the system shall create the chip target before opening it. |
| R-CHIP-001.8 | If | If the system cannot create a chip target, then the system shall show the status `Failed to create folder: <reason>`. |
| R-CHIP-001.9 | If | If a chip target is not a folder, has a link on its path, or resolves outside the chip root, then the system shall refuse to open it with the status `Refused to open <target>: not a real folder inside <chip root name>/`. |
| R-CHIP-001.10 | When | When the system opens a chip target, the system shall show the status `Opened folder: <path>`. |
| R-CHIP-001.11 | If | If the system file manager cannot be started, then the system shall show the status `Failed to open folder: <reason>`. |

#### S5.9 · Recent sources (CTX-RECENT; from batch-100 HLR-172)

```text
CTX-RECENT  Recent sources
  recent-sources store  The file <LOCALAPPDATA>\s19_app\recent_sources.json: one per
                        user, in the local (not roaming) profile, outside every work
                        area and every start folder.
  store folder          <LOCALAPPDATA>\s19_app
  usable LOCALAPPDATA   The variable is set, starts with a drive letter, a colon and
                        \ or /, and names a folder that exists.
  store format          JSON {"schema_version": 1, "sources": [{"path": <absolute
                        path>, "kind": <kind>}, ...]}, newest first, ASCII only.
  kind                  s19 (.s19 .srec), hex (.hex .ihex), mac (.mac), a2l (.a2l);
                        the suffix compared ignoring case.
  absolute path         The source path made absolute by text only: . and .. folded,
                        no link followed, the drive letter as typed (a mapped network
                        drive keeps its letter).
  same source           Two absolute paths that are equal (on Windows, ignoring case).
  accepted entry        An object with a text "path" and a text "kind", where the path
                        starts with a drive letter, a colon and \ or /,
                        holds no control character (U+0000-U+001F, U+007F-U+009F),
                        holds none of < > : " | ? * after its first two characters,
                        holds no character of Unicode category Cf, Zl, Zp or Cs,
                        has no component that is a device name (S11 CTX-SAVE),
                        and the kind is the kind of the path's suffix.
  store problem         too large, or could not be read (the Load dialog shows it, S7).
```

| Id | Form | Requirement |
|---|---|---|
| R-RECENT-001.1 | U | The system shall keep each user's recent sources in the recent-sources store. |
| R-RECENT-001.2 | When | When a load copies a data file from outside the work area into `temp/`, the system shall record the file's absolute path and kind first in the recent-sources store. |
| R-RECENT-001.19 | When | When an A2L file from outside the work area has been copied and parsed, the system shall record the file's absolute path and kind first in the recent-sources store. |
| R-RECENT-001.20 | If | If copying or parsing an A2L file fails, then the system shall leave the recent-sources store unchanged. |
| R-RECENT-001.3 | U | The system shall record the absolute path of a source without following links. |
| R-RECENT-001.4 | When | When the system records a source that is already in the store, the system shall keep one entry for it, in first place. |
| R-RECENT-001.5 | U | The system shall keep at most 20 entries in the recent-sources store, dropping the oldest first. |
| R-RECENT-001.6 | U | The system shall keep the store file at most 65,536 bytes long, dropping the oldest entries first. |
| R-RECENT-001.7 | If | If the new entry alone would make the store file longer than 65,536 bytes, then the system shall leave the store unchanged. |
| R-RECENT-001.8 | When | When the system writes the store, the system shall carry over only the existing entries that are accepted entries. |
| R-RECENT-001.9 | When | When the system writes the store, the system shall replace the previous store file in one step. |
| R-RECENT-001.10 | If | If a load fails before its copy into `temp/` completes, then the system shall leave the store unchanged. |
| R-RECENT-001.11 | If | If the source lies inside the work area, then the system shall not record it. |
| R-RECENT-001.12 | If | If the path input was found only under the start folder or a repository root (R-TUI-005.4, .5), then the system shall not record the source. |
| R-RECENT-001.13 | If | If the absolute path of the source would not be an accepted entry, then the system shall not record it. |
| R-RECENT-001.14 | If | If `LOCALAPPDATA` is not usable, then the system shall write no store file. |
| R-RECENT-001.15 | If | If the store folder is a link, then the system shall not write the store. |
| R-RECENT-001.16 | If | If the store has the store problem `could not be read` when the system records a source, then the system shall leave the store unchanged. |
| R-RECENT-001.17 | If | If writing the store fails, then the system shall leave the store unchanged. |
| R-RECENT-001.18 | If | If the system does not record a source, then the system shall complete the load with no status about the store. |
| R-RECENT-002.1 | When | When the system reads the store, the system shall take at most the first 20 accepted entries, in stored order. |
| R-RECENT-002.2 | If | If a store entry is not an accepted entry, then the system shall drop it. |
| R-RECENT-002.3 | If | If the store file is larger than 65,536 bytes, then the system shall read the store as empty with the store problem `too large`. |
| R-RECENT-002.4 | If | If the store file or the store folder is a link, or the store file cannot be opened or read, then the system shall read the store as empty with the store problem `could not be read`. |
| R-RECENT-002.5 | If | If the store file is not a JSON object holding `schema_version` 1 and a `sources` list, then the system shall read the store as empty with no store problem. |
| R-RECENT-002.6 | If | If the store file does not exist or `LOCALAPPDATA` is not usable, then the system shall read the store as empty with no store problem. |
| R-RECENT-002.7 | U | The system shall read any store file content without stopping on an error. |
| R-RECENT-002.8 | When | When the system reads the store, the system shall write no file. |
| R-RECENT-002.9 | When | When the system reads the store, the system shall write no store entry to the log. |
| R-RECENT-003.1 | U | The system shall not copy an entry of the recent-sources store into any file under the start folder. |

The Load dialog's Recent section, its store-problem line and a refused recent row (which keeps its entry, R-LOADDLG.81) are S7's.

#### S5.10 · The load question (CTX-LOADQ; from batch-100 HLR-174, HLR-174a, HLR-174b, HLR-174c, HLR-174d)

```text
CTX-LOADQ  The load question
  load route         A request that loads into the session: the Load dialog (a typed
                     path, a recent source, a project row, a work-area row; S7
                     R-LOADDLG.60 … .62, R-TUI-043.2, .15), a
                     Workarea Files pick, a variant switch (v, and the v of the
                     Load-result panel, S11).
  load kind          image replacement   an S19 or Intel HEX file, or a variant
                     attach              a MAC or A2L file
                     project load        a project
  unsaved image      The loaded image holds a byte other than the byte last loaded,
                     saved by Save project (S11) or saved back (S8).
  unsaved entries    The Patch Editor's dirty flag is set (S10 CTX-PE-DOC; when Save
                     project clears it: S10 R-PE-038, R-PE-039.1 … .4).
  unsaved flow       The Flow Builder holds edits not yet saved (S16).
  unsaved work       For an image replacement: an unsaved image. For a project load:
                     an unsaved image, unsaved entries or an unsaved flow. For an
                     attach: none.
  load question      A dialog, top to bottom:
    title            Replace <current>?
                       <current>: the open project's name; else the loaded image's
                       file name; else "the current session".
    body             There are unsaved changes in <items>. Load <target> anyway?
                       <items>: the unsaved work, in the order image, entries, flow,
                       as "A", "A and B" or "A, B and C".
                       image: the loaded image's file name. entries: "Patch Editor
                       entries". flow: "flow <flow name>".
                       <target>: "project <name>" for a project load; else the
                       file name of the requested file.
    buttons          Replace (y)   Cancel (n)
  answer             replace or cancel.
  Every <name> in the question is a painted name (CTX-FILES).
```

| Id | Form | Requirement |
|---|---|---|
| R-LOADQ-001.1 | When | When a load route requests an image replacement while the loaded image is unsaved, the system shall ask the load question before the session changes. |
| R-LOADQ-001.2 | When | When a load route requests an image replacement while the loaded image is not unsaved, the system shall load without the load question. |
| R-LOADQ-001.3 | When | When a load route requests an attach, the system shall attach the file without the load question. |
| R-LOADQ-001.4 | When | When a load route requests a project load while the loaded image is unsaved, the Patch Editor holds unsaved entries or the Flow Builder holds an unsaved flow, the system shall ask the load question before the session changes. |
| R-LOADQ-001.5 | When | When a load route requests a project load while there is no unsaved work, the system shall load without the load question. |
| R-LOADQ-001.6 | U | The system shall ask the load question at most once per load request. |
| R-LOADQ-002.1 | When | When the operator makes a work-area pick, the system shall take the load kind from the file's suffix. |
| R-LOADQ-002.2 | When | When the operator loads a typed path or a recent source, the system shall take the load kind from the suffix of the file the path resolves to. |
| R-LOADQ-002.3 | If | If a typed path or a recent source ends in a MAC suffix and resolves to a file with another suffix, then the system shall treat the load as an image replacement. |
| R-LOADQ-003.1 | When | When the operator answers the load question with replace, the system shall run the load that asked. |
| R-LOADQ-003.2 | When | When the operator cancels the load question, the system shall leave the session and the unsaved work unchanged. |
| R-LOADQ-003.3 | When | When the operator cancels the load question, the system shall show no status. |
| R-LOADQ-003.4 | If | If the operator cancels the load question of a variant switch, then the system shall not apply that variant to a later load. |
| R-LOADQ-003.5 | If | If a project load the operator confirmed is refused before the project opens, then the system shall keep the unsaved work. |
| R-LOADQ-004.1 | When | When the load question opens, the system shall put the focus on `Cancel (n)`. |
| R-LOADQ-004.2 | When | When the operator presses `y` in the load question, the system shall answer replace. |
| R-LOADQ-004.3 | When | When the operator presses `n` or `escape` in the load question, the system shall answer cancel. |
| R-LOADQ-004.4 | When | When the operator presses `enter` in the load question, the system shall give the answer of the focused button. |
| R-LOADQ-004.5 | When | When the operator clicks a button of the load question, the system shall give that button's answer. |
| R-LOADQ-004.6 | If | If the operator presses a key other than `y`, `n`, `escape`, `enter`, `tab`, `shift+tab` or a priority key while the load question is open, then the system shall keep the question open with the session unchanged. |
| R-LOADQ-004.7 | If | If the operator presses `ctrl+l`, `ctrl+s`, `ctrl+k` or `ctrl+d` while the load question is open, then the system shall ignore the key. |
| R-LOADQ-004.8 | If | If a second answer reaches the load question after the first, then the system shall ignore the second answer. |
| R-LOADQ-005.1 | U | The system shall title the load question `Replace <current>?`. |
| R-LOADQ-005.2 | U | The system shall show the body `There are unsaved changes in <items>. Load <target> anyway?` in the load question. |
| R-LOADQ-005.3 | U | The system shall name in `<items>` every kind of unsaved work that made the system ask. |
| R-LOADQ-005.4 | U | The system shall show the load question with the two buttons `Replace (y)` and `Cancel (n)` and no other button or text box. |
| R-LOADQ-005.5 | U | The system shall show every name in the load question as its painted name, never as markup. |
| R-LOADQ-006.1 | U | The system shall show the title of the load question above its body, and the body above the buttons. |
| R-LOADQ-006.2 | U | The system shall show the buttons of the load question on one right-aligned row, `Replace (y)` first. |
| R-LOADQ-006.3 | While | While the load question is shown at 99 columns or more, the system shall keep its body and both buttons fully on screen. |
| R-LOADQ-006.4 | U | The system shall give the confirm accent of the load question to `Cancel (n)`. |



<a id="s6"></a>

## S6 · TUI shell, navigation & layout

### Context notes (informative)

#### CTX-SHELL · The frame, the rail and the status bar (S6.1 … S6.5)

```text
window          One of the twelve rail windows below, or Split / Join / Export.
                One window is shown at a time.
frame           Top to bottom, the same on every window:
  header        The title "Hex Edit Tool".
  palette       The command palette, hidden until Ctrl+K (S6.4).
  settings menu The viewer settings menu, hidden until "Viewer settings" (S6.7).
  rail, window  The rail on the left, the shown window on the right.
  status bar    The status line, the progress bar, the message lines.
  key bar       Two rows of keys (S7, CTX-KEYBAR).
rail            One item per rail window, in this order:
  pos  key  glyph  label            owner of the window
   1    1    ◫     Workspace         S5
   2    2    ≡     A2L Explorer      S2
   3    3    ◉     MAC View          S2
   4    4    ▤     Memory Map        S4
   5    5    !     Issues Report     S3
   6    6    ✎     Patch Editor      S10
   7    =    ✔     Check Editor      S9
   8    7    ⏚     A2B Diff          S14
   9    8    ✦     Flow Builder      S16
  10    ]    ▶     Flow Execution    S16
  11    9    ☑     Checks            S9
  12    0    ⊕     CRC Designer      S13
  Split / Join / Export (S17) has no rail item and no key; the palette opens it.
active item     The rail item of the shown window, in the accent colour.
rail key        The key of a rail item.
wide, narrow    Wide: the terminal is 120 columns or more. Narrow: less than 120.
focus target    The widget a window gives the focus to:
  Workspace         Workarea Files list      Patch Editor     the editor panel
  A2L Explorer      tag table                Check Editor     the editor panel
  MAC View          record table             A2B Diff         Compare button
  Memory Map        map panel (then the      Flow Builder     the builder panel
                    selected region row)     Flow Execution   the execution panel
  Issues Report     grouped issue list       Checks           grouped check list
  CRC Designer      the designer panel       Split/Join/Export  the range table
                Each focus target takes the focus and is not a text box.
load completes  A file, A2L or project load installs what it read.
load cancelled  The operator closes the Load dialog without a choice, or answers the
                load question with Cancel (S5, S7).
frame widget    A widget of the frame outside the windows: a rail item, the palette
                filter.
text box        A single-line or multi-line box the operator types in.
status bar      Three parts:
  status line   Left: the status text. Right: the context line.
  status text   While a long action runs: the progress line of the shown action
                (CTX-BUSY). Otherwise: the file status.
  file status   The last file status the system set (a load's load status, S5
                CTX-FILES; a project load's project line, S11). "Ready." until the
                first.
  progress bar  0 to 100 %, with the percentage beside it (bar value: CTX-BUSY).
  message lines The 4 newest messages, the newest at the bottom. "Show the status
                <text>", in every chapter, means: add <text> as the newest message.
context line    <project>, two spaces, a vertical bar, two spaces, <A2L file name>.
  <project>     "(none)"; or the project name; or "<project>:<variant> (<i>/<N>)"
                while the open project holds N > 1 variants and <variant> is the i-th.
                Open project, variant, variant order: S11 CTX-PROJECT.
  <A2L name>    The loaded A2L file name, or "(none)".
context fit     B = floor((terminal width - 4) x 0.7) - 5 columns.
                Both names fit in B: both are shown whole.
                Otherwise P = floor(B / 2). If the project fits in P, it is whole and
                the A2L gets the rest of B; else if the A2L fits in B - P, it is
                whole and the project gets the rest; else the project gets P and
                the A2L gets B - P. A shortened name ends with "…".
                Widths count terminal columns (a CJK character is 2).
```

#### CTX-KEYS · The global keys (S6.3)

Keys a window adds for itself are in CTX-KEYBAR (S7) and in the window's own chapter.

```text
key            label in palette       acts on                          chapter
Ctrl+K         Palette                every window                     S6
Ctrl+D         Density                every window                     S6
Ctrl+L, l      Load                   every window                     S5, S7
Ctrl+S, s      Save project           every window                     S11
/              Find                   Workspace, A2L Explorer, MAC View S6, S4
g              Go-to                  Workspace, A2L Explorer, MAC View S4
q, Ctrl+Q      Quit                   every window                     S6
?              Help                   every window                     S6, S7
rail keys      (window label)         every window                     S6
U              Unload all             every window                     S5
r              Refresh workarea       every window                     S5
o              Open workarea          every window                     S5
p              Projects               every window                     S11
v              Select variant         every window                     S11
j              Dump A2L JSON          every window                     S2
d              Describe tag           A2L Explorer                     S2
t              View reports           every window                     S12
x              Operations             every window                     S13
k              Legend                 every window                     S3
b              Before/After report    every window                     S14
+ , -          Page+ , Page-          A2L Explorer, MAC View           S2
, (comma) , .  Hex- , Hex+            Workspace                        S4
PgDn , PgUp    Page+ , Page-          Issues Report, A2L Explorer,     S3, S2
                                      MAC View
Ctrl+Z, Ctrl+Y Undo, Redo             Patch Editor                     S10
c              Confirm                Flow Execution                   S16
Ctrl+P         palette (Textual's)    every window                     S6 (D6-13)
```

#### CTX-THEME · Colours and sizes (S6.6)

The severity colours (red, pale yellow, cyan, green, grey) are S3's palette (CTX-LEGEND); they are not repeated here.

```text
dark theme      background #0a0e1b · panel #0f1525 · text #e9e9e9 ·
                border #1b233a · odd table row #131a2c
accent          #91abec: window titles, the active rail item, the palette border,
                key-bar descriptions of row 2, the status text while a long action
                runs (S6.5b).
human-readable size
                Less than 1024 bytes: "<n> B".
                Else the largest of KiB, MiB, GiB, TiB, PiB (1 KiB = 1024 bytes)
                that keeps the number under 1024, with one decimal:
                1024 -> "1.0 KiB", 0x10000 -> "64.0 KiB", 2^30 -> "1.0 GiB".
viewer settings menu
                Title "Viewer limits (max 200)", a rule, then one row per option:
                "[<mark>] <view>: <n>"  with <view> = Hex rows, A2L tags, MAC rows,
                <n> = 25, 50, 100, 150, 200, and <mark> "*" on the size in use.
```

#### CTX-BUSY · Long actions, the busy line and the quit question (S6.5b, S6.8; batch-100)

The chapter of each action owns what the action does, its own steps and its outcome text: the loads S5, S2 (R-A2L-004.10 … .12, CTX-A2L-FILE) and S11, Save project S11, the project report S12 (R-RPT-LOG.1 … .4, CTX-RPT-RUN), the diff and before/after reports S14 (R-CMP-005.13 … .15, R-BEFORE-AFTER-REPORT-001.31, CTX-DIFFREPORT, CTX-BEFOREAFTER). The labels and steps below are the code's (`_BUSY_ACTIONS`, `app.py:366-400`), the same words those notes use. This note holds only the shared progress, refusal and quit terms.

```text
long action     An action that shows its progress while it runs. Seven, each with its
                label and its steps in order (* = held step):
  action          label                              steps
  file load       Loading <name>                     Copy into the work area* ·
                                                     Parse · Install*
  A2L load        Loading <name>                     Copy into the work area ·
                                                     Parse · Build the tag table*
  project load    Loading project <name>             Check the files · Parse the A2L ·
                                                     Parse the image · Install*
  Save project    Saving project <name>              Create the folder · Place the
                                                     files · Gather the project
                                                     files · Write project.json
  project report  Generating the project report      Prepare the results ·
                                                     Write the report
  diff report     Writing the diff report            Write Markdown · Write HTML
  before/after    Writing the before/after report    Compose the report
held step       A step marked * above: the screen waits for it to end (D6-35).
session action  A file load, an A2L load, a project load or Save project. The three
                reports are not session actions.
shown action    The long action whose progress the status text and the progress bar
                show.
progress        Of an action: its progress line and its bar value.
<name>          The file or project name with every control and format character
                removed (Unicode Cc, Cf, Zl, Zp), then cut to 120 characters, the
                last one "…".
progress line   <glyph> <label>  ·  step <n>/<m> <step name>  ·  <mm>:<ss>
                Between the parts: two spaces, a middle dot, two spaces.
                Example: ⠋ Loading x.s19  ·  step 1/3 Copy into the work area  ·  00:00
  <glyph>       One of ⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏; the frame after ⠏ is ⠋.
  <n>/<m>       The step reached and the number of steps of the action.
  <mm>:<ss>     Whole minutes and seconds since the action began, two digits each;
                the minutes go past 59 (4503 s is 75:03).
amount          What a step reports of its work: done of total.
                  A2L parse     bytes read of the A2L file's size.
                  Place the files (Save project)   files placed of files planned.
bar value       Step n of m with no amount: floor(100 × (n − 1) / m) %.
                Step n of m with an amount: floor(100 × (n − 1 + f) / m) %, where
                f = done / total, kept within 0 … 1, never below the step's last f.
outcome         The status an action ends with, set by its chapter (for example
                "Loaded <name>", S5 R-TUI-012L.12), or "<label> failed" (an
                unexpected error).
complete        A session action completes when it ends with its success outcome;
                otherwise it fails (a refusal found by the action counts as failed).
busy line       busy: <label> is running — wait for it to finish.
                <label> is the label of the newest running session action.
refused list    The requests the system refuses while a session action runs:
  Load          l, Ctrl+L, p, the Workspace's "Load project (p)" button, the
                palette's Load and Projects.
  load route    a Workarea Files pick; a pick in the variant selector; a choice in
                the Load dialog.
  start         a file load, an A2L load, a project load or Save project that
                reaches its start, also one asked for before the running action
                began (the Save project dialog confirmed while a load runs).
  variant       v, the palette's Select variant, v in the Load-result panel.
  unload        U, the palette's Unload all, an unload in the Loaded panel.
  Save project  s, Ctrl+S, the palette's Save project.
  Patch Editor  the requests S10 R-PE-110 lists (Add … Write file, both Edit JSON
                dialogs and their results), Ctrl+Z, Ctrl+Y, and the accept of the
                Patch Editor's unsaved-document question.
session         The loaded image, MAC and A2L files, the change document, the open
                project and its variant, the declared regions.
quit question   Title "Quit?". Text "still working: <label> — wait, or quit after it
                finishes" (<label> as in the busy line). Buttons "Quit (y)" and
                "Stay (n)"; "Stay (n)" is the emphasised button.
  Quit          y, or Enter or a click on "Quit (y)".
  Stay          n, Escape, or Enter or a click on "Stay (n)".
confirmed quit  The operator answered the quit question with Quit while a session
                action ran, and no later answer or rule withdrew it.
unsaved-work line  A line of a completed Save project (S11) that names Patch Editor
                work the save did not write: a change-document line, or
                "Change document <name> has unsaved edits — the project records the
                file as it is on disk; save it from the Patch Editor to keep them".
```

---

### Requirements


#### S6.1 · The frame and the start (CTX-SHELL)

| Id | Form | Requirement |
|---|---|---|
| R-SHELL-START.1 | U | The system shall show the frame of CTX-SHELL on every window. |
| R-SHELL-START.2 | U | The system shall show the title `Hex Edit Tool` in the header. |
| R-SHELL-START.3 | When | When the system starts, the system shall show the Workspace. |
| R-SHELL-START.4 | When | When the system is started with `--load <path>`, the system shall load `<path>` as a typed path input (S5.3) once the frame is shown. |
| R-SHELL-START.5 | When | When the operator presses `q` or Ctrl+Q outside a text box while no session action runs, the system shall quit. |

#### S6.2 · The rail and the windows (CTX-SHELL)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-021.1 | U | The system shall show the rail items of CTX-SHELL, in that order, with their glyph and label. |
| R-TUI-021.2 | U | The system shall mark exactly one rail item as active: the item of the shown rail window. |
| R-TUI-021.3 | When | When the operator presses a rail key outside a text box, the system shall show that key's window. |
| R-TUI-021.4 | When | When the operator clicks a rail item, the system shall show its window. |
| R-TUI-021.5 | When | When the operator presses Enter on the focused rail item, the system shall show its window. |
| R-TUI-021.6 | When | When the system shows a window, the system shall hide every other window. |
| R-TUI-021.7 | U | The system shall show each rail item's rail key beside its glyph. |
| R-TUI-021.8 | While | While the terminal is wide, the system shall show the rail 22 columns wide. |
| R-TUI-021.9 | While | While the terminal is narrow, the system shall show the rail 4 columns wide, with each item's glyph only. |
| R-TUI-021.10 | When | When the operator runs `Split / Join / Export` from the palette, the system shall show that window in the window area. |
| R-TUI-021.11 | When | When the operator presses a rail key while Split / Join / Export is shown, the system shall close it and show that key's window. |
| R-TUI-030.1 | When | When the operator opens a window while no file is loaded, the system shall show at least one line of text in it. |
| R-TUI-030.2 | When | When the operator opens a window while no file is loaded, the system shall show no error. |

#### S6.3 · Keys and focus (CTX-KEYS)

| Id | Form | Requirement |
|---|---|---|
| R-SHELL-KEYS.1 | When | When the operator presses a key of CTX-KEYS outside a text box, the system shall run its command on the windows CTX-KEYS names. |
| R-SHELL-KEYS.2 | If | If the operator presses `+`, `-`, `,`, `.` or `c` on a window that CTX-KEYS does not name for it, then the system shall do nothing. |
| R-TUI-031.1 | While | While a text box has the focus, the system shall type every printable key into it. |
| R-TUI-031.2 | While | While a text box of the shown window has the focus, the system shall run the commands of Ctrl+K, Ctrl+D, Ctrl+L and Ctrl+S. |
| R-TUI-033.1 | When | When the operator presses `/` on the Workspace, the A2L Explorer or the MAC View, the system shall put the focus in that window's search box. |
| R-TUI-033.2 | If | If the operator presses `/` on any other window, then the system shall show the status `This screen has no find input. Use the rail to switch to Workspace, A2L or MAC.` |
| R-TUI-033.3 | If | If the operator presses `g` on any window other than the Workspace, the A2L Explorer or the MAC View, then the system shall show the status `This screen has no go-to input. Use the rail to switch to Workspace, A2L or MAC.` |
| R-TUI-033.4 | When | When the operator presses Escape in a search box or a go-to box, the system shall take the focus out of the box. |
| R-SHELL-FOCUS.1 | When | When the system starts, the system shall put the focus on the active rail item. |
| R-SHELL-FOCUS.2 | When | When the operator shows another window with a key, the system shall put the focus on that window's focus target. |
| R-SHELL-FOCUS.3 | When | When a load completes or is cancelled while the focus behind any dialog is on a widget that is hidden, has no size, or sits in a hidden window, the system shall put the focus on the shown window's focus target. |
| R-SHELL-FOCUS.4 | When | When a load completes or is cancelled while the focus is on a shown widget of the shown window or on a frame widget, the system shall keep the focus there. |
| R-SHELL-FOCUS.5 | If | If the shown window's focus target is not shown, then the system shall put the focus on the first shown widget of that window that takes the focus and is not a text box. |
| R-SHELL-FOCUS.6 | If | If the shown window has no such widget, then the system shall put the focus on the active rail item. |
| R-SHELL-FOCUS.7 | While | While a dialog is open, the system shall keep the dialog's focus when a load ends. |
| R-TUI-DISCOVER-001.1 | When | When the operator presses `?` outside a text box and outside a window that has a help section (S7), the system shall show the key panel that lists the keys active on the focused widget. |
| R-TUI-DISCOVER-001.2 | When | When the operator presses `?` while the key panel is shown, the system shall hide the key panel. |

#### S6.3b · Focus after the load dialogs (from batch-100 HLR-166, LLR-166.1, LLR-166.2)

R-SHELL-FOCUS.3 and .4 above now cover a cancelled load as well (D6-39). The Load-result panel's own focus (its problem list first) is S11's (HLR-178).

| Id | Form | Requirement |
|---|---|---|
| R-FOCUS-LOAD.1 | When | When the operator closes the Load-result panel, the system shall return the focus to the widget that held it behind the panel. |

#### S6.4 · The command palette

| Id | Form | Requirement |
|---|---|---|
| R-TUI-022.1 | When | When the operator presses Ctrl+K, the system shall open the palette with an empty filter and the focus in the filter. |
| R-TUI-022.2 | U | The system shall list in the palette one command per command of CTX-KEYS, then `Viewer settings` and `Split / Join / Export`. |
| R-TUI-022.3 | U | The system shall give each palette command a label no other palette command has. |
| R-TUI-022.4 | When | When the operator types in the palette filter, the system shall list the commands whose label contains the filter text, ignoring case. |
| R-TUI-022.5 | When | When the operator clears the palette filter, the system shall list every command again. |
| R-TUI-022.6 | When | When the operator selects a palette command, the system shall close the palette and run the command. |
| R-TUI-022.7 | When | When the operator presses Enter in the palette filter, the system shall close the palette and run the first listed command. |
| R-TUI-022.8 | If | If no command is listed when the operator presses Enter in the palette filter, then the system shall keep the palette open. |
| R-TUI-022.9 | When | When the operator presses Escape in the palette, the system shall close the palette. |
| R-TUI-022.10 | While | While a command cannot act on the shown window, the system shall leave it out of the palette list. |
| R-TUI-022.11 | U | The system shall offer no command palette other than the palette of R-TUI-022.1. |
| R-TUI-035.1 | U | The system shall not write the text typed in the palette, a search box or a go-to box to the log. |

#### S6.5 · The status bar (CTX-SHELL)

| Id | Form | Requirement |
|---|---|---|
| R-SHELL-STATUS.1 | When | When the system starts, the system shall show `Ready.` as the file status. |
| R-SHELL-STATUS.2 | U | The system shall show the 4 newest messages in the message lines, the newest at the bottom. |
| R-SHELL-STATUS.3 | If | If a message is empty or holds only spaces, then the system shall not add it to the message lines. |
| R-SHELL-STATUS.4 | U | The system shall show the message lines as plain text, never as markup. |
| R-SHELL-STATUS.5 | U | The system shall show the message lines without control characters. |
| R-SHELL-STATUS.6 | When | When a long action begins, the system shall set the progress bar to 0 %. |
| R-TUI-036.1 | U | The system shall show the context line at the right of the status line on every window. |
| R-TUI-016.1 | U | The system shall name the open project in the context line in the form of CTX-SHELL. |
| R-TUI-016.2 | U | The system shall name the loaded A2L file in the context line. |
| R-TUI-016.3 | If | If no project is open, then the system shall show `(none)` as the project in the context line. |
| R-TUI-016.4 | If | If no A2L file is loaded, then the system shall show `(none)` as the A2L file in the context line. |
| R-TUI-036.2 | If | If the context line is wider than its budget, then the system shall shorten the names by the context fit of CTX-SHELL. |
| R-TUI-036.3 | When | When the terminal is resized, the system shall fit the context line to the new width. |
| R-TUI-036.4 | U | The system shall show the context line without control characters and without markup. |

#### S6.5b · The progress of a long action (from batch-100 HLR-176, HLR-176a, HLR-176b, HLR-176c, HLR-176d; CTX-BUSY)

The look (one row in the accent colour, the glyph, the step, the elapsed time, no cancel) is the P-D prototype verdict A of batch-100; it is written here as requirements, not prototype first (D6-32).

| Id | Form | Requirement |
|---|---|---|
| R-PROGRESS-LINE.1 | When | When a long action begins, the system shall show its progress line at step 1 and `00:00` as the status text. |
| R-PROGRESS-LINE.2 | While | While a long action runs, the system shall show the progress line of the shown action as the status text. |
| R-PROGRESS-LINE.3 | While | While the shown action runs a step that is not a held step, the system shall advance the glyph of the progress line to the next frame every 0.1 s. |
| R-PROGRESS-LINE.4 | While | While the shown action runs a step that is not a held step, the system shall show in the progress line the elapsed time since the action began. |
| R-PROGRESS-LINE.5 | When | When a long action reaches a step, the system shall show the step's number and name in the progress line before the step's work starts. |
| R-PROGRESS-LINE.6 | If | If a long action has no work for one of its steps, then the system shall leave that step out of the progress line. |
| R-PROGRESS-LINE.7 | If | If a long action is refused before its work begins, then the system shall show no progress line for it. |
| R-PROGRESS-LINE.8 | U | The system shall show each name inside a progress line, a busy line or a quit question in the `<name>` form of CTX-BUSY. |
| R-PROGRESS-LINE.9 | U | The system shall show the progress line as plain text, never as markup. |
| R-PROGRESS-LINE.10 | While | While a long action runs, the system shall draw the status text in the accent colour `#91abec`. |
| R-PROGRESS-LINE.11 | While | While a long action runs, the system shall keep the status text on one row, cutting a longer progress line with `…`. |
| R-PROGRESS-SHOWN.1 | If | If a long action begins while another long action runs, then the system shall show the progress of the newer action. |
| R-PROGRESS-SHOWN.2 | When | When a long action ends while other long actions still run, the system shall show the progress of the most recently begun one still running. |
| R-PROGRESS-SHOWN.3 | If | If a long action begins while the same action already runs, then the system shall restart its progress line at step 1 and `00:00`. |
| R-PROGRESS-SHOWN.4 | If | If a run of a long action that a newer run of the same action replaced ends, then the system shall leave the shown progress unchanged. |
| R-PROGRESS-BAR.1 | When | When the shown action reaches step n of m without an amount, the system shall set the progress bar to the bar value of CTX-BUSY. |
| R-PROGRESS-BAR.2 | When | When a step of the shown action reports an amount, the system shall set the progress bar to the bar value of CTX-BUSY. |
| R-PROGRESS-BAR.3 | When | When Save project places one file of its save plan, the system shall report the files placed of the files planned as the amount of the step `Place the files`. |
| R-PROGRESS-BAR.4 | U | The system shall show no time estimate beside the progress bar. |
| R-PROGRESS-BAR.5 | U | The system shall show the message lines at the same rows whether or not a long action runs. |
| R-PROGRESS-END.1 | When | When a long action ends with an outcome, the system shall show the outcome as the newest message. |
| R-PROGRESS-END.2 | When | When the last running long action ends, the system shall show the file status as the status text. |
| R-PROGRESS-END.3 | When | When the last running long action ends, the system shall set the progress bar to 0 %. |
| R-PROGRESS-END.4 | If | If an unexpected error stops a long action whose chapter gives no outcome for that error, then the system shall end the action with the outcome `<label> failed`. |
| R-PROGRESS-END.5 | U | The system shall add no progress line and no step name to the message lines. |

#### S6.6 · Layout, density and theme (CTX-THEME)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-023.1 | U | The system shall switch every window between its wide and its narrow layout at a terminal width of 120 columns. |
| R-TUI-023.2 | When | When the terminal is resized across 120 columns, the system shall switch the layout without a restart. |
| R-TUI-023.3 | U | The system shall lay out every window at 80×24, 120×30 and 160×40 as its approved captures show. |
| R-TUI-023.4 | When | When the system starts, the system shall use the comfortable density. |
| R-TUI-023.5 | When | When the operator presses Ctrl+D, the system shall switch between the comfortable and the compact density. |
| R-TUI-023.6 | When | When the density changes, the system shall show the status `Density: compact` or `Density: comfortable`. |
| R-TUI-023.7 | While | While the density is compact, the system shall draw the Workspace panes without top and bottom padding. |
| R-TUI-024.1 | U | The system shall draw every window in the dark theme of CTX-THEME. |
| R-TUI-024.2 | U | The system shall use one accent colour, `#91abec`. |
| R-TUI-024.3 | U | The system shall offer no light theme. |
| R-TUI-024.4 | U | The system shall draw the odd rows of striped tables in `#131a2c`. |
| R-TUI-065.1 | U | The system shall write every human-readable size in the format of CTX-THEME. |

#### S6.7 · Viewer settings (CTX-THEME)

Shared with S2 R-TUI-019.3 (A2L and MAC page sizes) and S4 (the main hex view's page size).

| Id | Form | Requirement |
|---|---|---|
| R-SHELL-SETTINGS.1 | When | When the system starts, the system shall use page sizes of 200 hex rows, 200 A2L tags and 100 MAC rows. |
| R-SHELL-SETTINGS.2 | When | When the operator runs `Viewer settings` from the palette, the system shall show the viewer settings menu of CTX-THEME. |
| R-SHELL-SETTINGS.3 | When | When the operator selects a size in the viewer settings menu, the system shall use it as that view's page size. |
| R-SHELL-SETTINGS.4 | When | When the operator selects a size in the viewer settings menu, the system shall show the status `Updated <view> to <n>.` with the menu's view name. |
| R-SHELL-SETTINGS.5 | When | When the operator presses Escape in the viewer settings menu, the system shall close the menu. |

#### S6.8 · Session actions: the busy refusal and the quit question (CTX-BUSY; batch-100)

What each session action does, refuses on its own and reports on failure stays in its chapter (S5, S2, S11; D6-42). This section holds what happens around it. Rows that live with their surface: the Patch Editor's refused controls and its read-only paste buffer during a project load (S10 R-PE-110, R-PE-111); Generate new report keeps the session's regions during a session action (S12 R-RPT-002.28).

#### S6.8a · Keys and refusals while a session action runs (from batch-100 HLR-177, HLR-177a)

| Id | Form | Requirement |
|---|---|---|
| R-BUSY-RUN.1 | While | While a long action runs a step that is not a held step, the system shall act on the keys the operator presses. |
| R-BUSY-REFUSE.1 | If | If the operator makes a request of the refused list of CTX-BUSY while a session action runs, then the system shall show the busy line. |
| R-BUSY-REFUSE.2 | When | When the system refuses a request as busy, the system shall leave the session unchanged. |
| R-BUSY-REFUSE.3 | When | When the system refuses a request as busy, the system shall keep the focus on the widget that held it. |
| R-BUSY-REFUSE.4 | When | When the system refuses a request as busy, the system shall open no dialog. |
| R-BUSY-REFUSE.5 | When | When the system refuses a request as busy, the system shall keep the progress line as the status text. |
| R-BUSY-REFUSE.6 | If | If a load route that would ask the load question is refused as busy, then the system shall ask no load question. |
| R-BUSY-REFUSE.7 | While | While a session action runs, the system shall accept a request for a project report, a diff report or a before/after report. |
| R-BUSY-REFUSE.8 | While | While no session action runs, the system shall accept every request of the refused list of CTX-BUSY. |

#### S6.8b · Quit while a session action runs (from batch-100 HLR-177b, HLR-177c)

| Id | Form | Requirement |
|---|---|---|
| R-QUIT.1 | When | When the operator presses `q` or Ctrl+Q, or runs `Quit` from the palette, while a session action runs, the system shall show the quit question of CTX-BUSY. |
| R-QUIT.2 | When | When the system shows the quit question, the system shall put the focus on its `Stay (n)` button. |
| R-QUIT.3 | U | The system shall draw `Stay (n)` as the emphasised button of the quit question. |
| R-QUIT.4 | U | The system shall show the quit question's text as plain text, never as markup. |
| R-QUIT.5 | If | If the operator asks to quit while the quit question is open, then the system shall open no second quit question. |
| R-QUIT.6 | When | When the operator answers the quit question with Stay, the system shall keep running after the session action ends. |
| R-QUIT.7 | While | While a quit is confirmed and the session action still runs, the system shall keep running. |
| R-QUIT.8 | When | When a session action completes while a quit is confirmed, the system shall quit. |
| R-QUIT.9 | If | If a session action fails while a quit is confirmed, then the system shall withdraw the confirmed quit. |
| R-QUIT.10 | If | If Save project completes with an unsaved-work line while a quit is confirmed, then the system shall withdraw the confirmed quit. |
| R-QUIT.11 | When | When the operator answers the quit question with Quit after the session action has ended, the system shall quit. |
| R-QUIT.12 | When | When the system quits on a confirmed quit, the system shall leave no partly written project folder in the work area. |



<a id="s7"></a>

## S7 · Modal dialogs, input widgets & window help

### Context notes (informative)

#### CTX-DIALOG · Dialogs (S7.1, S7.2)

```text
dialog          A window over the screen: a title, its content, a row of buttons.
                While it is open the window behind it stays visible but dim.
confirm button  The dialog's main button, drawn in the accent colour.
confirm box     A single-line box whose Enter means the confirm button: the path box
                of the Load dialog; the name box of Save project; the name box of
                Save flow.
text dialog     A dialog whose content starts with a text box: Save project,
                Save flow, Edit change-set JSON, Edit entry JSON. (The Load dialog's
                first focus depends on the key that opens it: R-TUI-043.1,
                R-LOADDLG.1.)
confirmation    A dialog that asks before work is lost or a file is written:
dialog          Unsaved changes will be lost, Discard unsaved flow edits?,
                the CRC write confirmation, the load question, the quit question.
cancel button   The button that keeps everything as it is: Cancel; on the quit
                question, Stay (n).
dialogs today (owner = the chapter of the content):
  title                                     owner  buttons                          focus today     Esc today
  Load                                      S7     Load (alt+l) · Cancel (esc)      path box or     yes
                                                                                    list (S7.2)
  Project name (Save project)               S11    Save (alt+s) · Cancel (esc)      name box        yes
  Select variant (project '<name>'):        S11    Activate · Cancel                variant list    no
  Project <name> opened[ with <n>           S11    Select variant (v) ·             result list     yes
    problem(s)] (the Load-result panel)            Close (esc)
  Replace <what>? (the load question)       S5     Replace (y) · Cancel (n)         Cancel (n)      yes
  Quit? (the quit question)                 S6     Quit (y) · Stay (n)              Stay (n)        yes
  Save flow as:                             S16    Save · Cancel                    name box        no
  Load flow:                                S16    Import… · Load · Cancel          flow list       no
  Discard unsaved flow edits?               S16    Discard · Cancel                 Discard         no
  Edit change-set JSON:                     S10    Confirm · Cancel                 text            yes
  Edit entry JSON:                          S10    Confirm · Cancel                 text            no
  Unsaved changes will be lost              S10    Accept loss and load · Cancel    Cancel          yes
  Write the computed CRC(s) into a new      S13    Width: <n> bytes/line ·          Width           no
    modified S19 under the work area?              Confirm · Cancel
  Operations:                               S13    Load config · Execute ·          operation list  no
                                                   Write CRC · Close
  Reports (project '<name>'):               S12    Generate new report · Close      report list     no
  Classification legend                     S3     Close                            Close           yes
  Parameter: <name>                         S2     Close                            Close           yes
  <help section title>                      S7     Close  esc                       Close           yes
```

#### CTX-LOADDLG · The Load dialog (S7.2; from batch-100 HLR-172a, HLR-173 … HLR-173e)

```text
Load dialog     The one dialog that loads a project, a work-area file, a recent source
                or a typed path. Its layout is the prototype verdict P-A = C of
                batch-100: two panes, the preview on the right.
  at 100 columns or wider:
      Load
      ┌ left pane ───────────────────────┐ ┌ right pane ──────────────────┐
      │ path box                         │ │ preview                      │
      │ list                             │ │                              │
      └──────────────────────────────────┘ └──────────────────────────────┘
      reason line
      [Load (alt+l)]  [Cancel (esc)]
  narrower than 100 columns: the right pane below the left pane, each as wide
  as the dialog.
path box        A single-line box. Empty when the dialog opens; hint
                "C:\path\to\file.s19, .hex, .mac, .a2l, or a project folder".
                Holds at most 4,096 characters and no control character.
list            Three sections, each under its heading line:
                  Projects    project rows, or one token line
                  Work area   work-area file rows, or one token line
                  Recent      recent rows, or one token line
heading line    "Projects", "Work area", "Recent".
token line      A line that says why a section holds no row:
                  no projects — ctrl+s saves a project
                  could not be read — check that the folder can be opened, then load again
                  no work-area files — l loads a file
                  no recent sources
                  too large — the next load starts a new list
                  could not be read — check that the recent-sources file can be opened
loadable row    A project row, a work-area file row or a recent row (not a heading
                line, not a token line).
project row     <project name>                    the painted folder name
work-area       <file name>                       the painted file name
file row
recent row      <file name> (<kind>)              the painted file name of the recorded
                                                  path; the recorded kind s19, hex,
                                                  mac or a2l (S5's recent sources)
loadable file   A file that the Workarea Files list shows (S5) and whose extension
                is an S19, Intel HEX, MAC or A2L extension (S5 CTX-FILES).
painted name    A name taken from disk, shown with every character of Unicode
                category Cc, Cf, Zl or Zp removed, every unpaired surrogate as U+FFFD,
                no markup, and cut to 120 characters ending in "…".
load source     The list or the path box, whichever had the focus last. It is the path
                box when the dialog opens with l or Ctrl+L, the list when it opens
                with p. The focus on the preview or a button keeps it. A printable key
                typed on the list makes the path box the load source.
load request    Enter in the path box, in the list or in the preview; Alt+L anywhere
                in the dialog; the Load button.
accepted        A load request whose row or typed path is not refused (S7.2d).
reason line     "<reason> — <next step>" (U+2014 between), one line under the panes.

preview         Lines about the highlighted row. A marked line starts with "● ".
  project row     variant <file name>        one per variant, in variant order (S11)
                  MAC <file name>            one per MAC file of the project
                  A2L <file name>            the project's first A2L file
                  project file: <state>      ok · no project.json · manifest damaged
                                             (manifest damaged: S11 CTX-MANIFEST)
  work-area       S19 or HEX row: image <this file>; MAC <the session's MAC>;
  file row          A2L <the session's A2L>;
                    becomes the active variant of project <project name>
                  MAC row: image <the session's S19 or HEX image>; MAC <this file>;
                    A2L <the session's A2L>
                  A2L row: image <the session's S19 or HEX image>;
                    MAC <the session's MAC>; A2L <this file>
                  (a session line shows only when the session holds that file)
  recent row      <recorded path>            the whole recorded path
                  kind <kind>
                  checked when loaded
installed set   The variant, MAC and A2L files that loading the highlighted row
                installs: for a project row, S11's project-load install rule; for a
                work-area file row, the image, MAC and A2L the session holds after the
                load (S5).

typed path      The text of the path box, a recent row's recorded path, or the path
                the app is started with. Spaces and double quotes around it are
                removed first (S5 R-TUI-005.2, R-TUI-005.9).
late typed path The path the app is started with, or a typed path whose class is
                decided again after the Load dialog has closed (the folder changed
                between the load request and the load).
typed-path      The first of these that applies:
class             not found             the operating system refuses to check the
                                        text (a NUL, too long, no access), or nothing
                                        exists at it (after S5's look-up of a relative
                                        path under the start folder)
                  relative path (no drive and root):
                    a folder                                  -> not a supported file
                    an A2L extension                          -> A2L file
                    an S19, Intel HEX or MAC extension        -> data file
                    any other                                 -> not a supported file
                  absolute path outside the work area:
                    a project.json, or a folder               -> outside
                    an A2L extension                          -> A2L file
                    an S19, Intel HEX or MAC extension        -> data file
                    any other                                 -> not a supported file
                  absolute path inside the work area, each step from the work area down:
                    a step that does not exist                -> not found
                    a step that cannot be inspected           -> unreadable
                    a step that is a link or junction, when the
                      path names a data or A2L file           -> link file
                    a step that is a link or junction         -> link
                  then, for the path itself:
                    a regular file with an A2L extension      -> A2L file
                    a regular file with an S19, HEX or MAC ext -> data file
                    any other file but project.json           -> not a supported file
                    a folder (for project.json: its folder) that is
                      not one level below the work area       -> not a project
                    a project list that cannot be read        -> unreadable
                    a name the project list does not hold     -> not a project
                    a listed folder whose content cannot be read -> unreadable
                    a listed folder with no project content   -> not a project
                    any other                                 -> project
refused         Each typed-path class that is not project, data file or A2L file;
                and "nothing selected" (an empty load request).
refusal table   class                  reason line (dialog)
                nothing selected       nothing selected — pick a row or type a path
                not found              not found — check the path
                not a supported file   not a supported file — check the path
                not a project          not a project — pick a project in the list
                outside                outside the work area — copy the folder into the work area
                link                   link or junction — pick a project in the list
                link file              is a link or junction — open the file it points to
                unreadable             could not be read — check that the folder can be opened, then load again
```

#### CTX-PASTE · Text boxes and paste (S7.3)

```text
single-line box  A one-line text box. Every one-line box of the app: the Load
                 dialog's path box, the search and go-to boxes, the palette filter,
                 the dialog boxes, the fields of the Patch Editor, Check Editor, Flow
                 screens, CRC Designer, A↔B diff.
multi-line box   A text box of several lines that the operator edits: the two JSON
                 editors, the Patch Editor paste buffer, the CRC config, the declared
                 regions of Reports, the manual ranges of Split / Join / Export.
OS clipboard     The operating system's clipboard (text copied in another program).
app clipboard    Text copied inside the app.
terminal paste   A paste the terminal sends itself (Ctrl+Shift+V in Windows Terminal).
paste limit      65,536 characters. (The Load dialog's path box has its own limit of
                 4,096 characters: R-LOADDLG.19.)
paste failure    The warning notice "Clipboard read failed — try Ctrl+Shift+V or type
warning          the path manually.", shown for 6 seconds.
```

#### CTX-HELP · Window help (S7.4)

```text
help section    A title and numbered steps written for one window.
                Today: Workspace, A2L Explorer, Memory Map, Checks, CRC Designer,
                Patch Editor, Check Editor, Flow Builder, Flow Execution,
                Split / Join / Export, Reports (the Reports dialog), and
                Changes file notation (no window opens it).
                No section: MAC View, Issues Report, A2B Diff.
help chip       A "?" button beside a window's title, in the accent colour.
help window     A dialog:
                  <section title>
                  1. <step>
                  (blank line)
                  2. <step> …
                  (blank line)
                  <key> — <label>     one line per window key of the window's
                                      key-bar row 2 (CTX-KEYBAR), no go keys
                  [Close  esc]
key panel       The panel that lists the keys active on the focused widget (S6).
```

#### CTX-KEYBAR · The key bar (S7.5)

```text
key bar         Two rows at the bottom of every window, below the status bar.
token           " <key> <label> ": <key> as the app paints it (^k for Ctrl+K, pgdn,
                esc, space …); <label> the palette label of the key's command (S6).
row 1           ^k Palette · ^d Density · ^l Load · ^s Save project ·
                x Operations · ? Help · q Quit
row 2           The shown window's name (title colours), its window keys, then
                " · go" and its go keys; "? more" ends the row when tokens were left
                out.
dimmed token    The whole token in one dim colour.
owned key       A window key that belongs to a widget; it acts while the focus is in
                that widget's window.
window keys and go keys, today:
  window             window keys                       go keys   dimmed while
  Workspace          / g , . k p o r U                 —         , . U: no image
  A2L Explorer       / g + - d k                       —
  MAC View           / g + - k                         —
  Memory Map         k                                 —
  Issues Report      pgdn pgup k                       —
  Patch Editor       ^z ^y v k                         = 9       ^z ^y: document from a
                                                                 file; v: no variants
  Check Editor       space (owned: parameter table)    6 9
  A2B Diff           k; f esc ] [ (owned: diff panel)  —
  Flow Builder       —                                 ] 6 =
  Flow Execution     c                                 8 t
  Checks             k                                 —
  CRC Designer       —                                 —
  Split/Join/Export  space a n t m g f p d e esc       —
                     (owned: the window)
```

---

### Requirements


#### S7.1 · Rules every dialog shares (CTX-DIALOG)

| Id | Form | Requirement |
|---|---|---|
| R-DLG.1 | While | While a dialog is open, the system shall act on no key of the window behind it. |
| R-DLG.2 | When | When the operator presses Escape in a dialog, the system shall do what the dialog's Cancel or Close button does. |
| R-DLG.3 | When | When the operator presses Enter in a confirm box, the system shall do what its dialog's confirm button does. |
| R-DLG.4 | When | When the operator presses Enter on an item of a dialog's list, the system shall do what the confirm button does for that item. |
| R-DLG.5 | When | When a text dialog opens, the system shall put the focus in its first text box. |
| R-DLG.6 | When | When a confirmation dialog opens, the system shall put the focus on its cancel button. |
| R-DLG.7 | When | When a dialog with a list and no text box first opens, the system shall put the focus on its list. |
| R-DLG.8 | When | When a dialog whose only button is Close opens, the system shall put the focus on Close. |
| R-DLG.9 | When | When the operator presses a dialog's Cancel or Close button, the system shall close the dialog and change nothing more. |
| R-DLG.10 | If | If a required text box is empty when the operator presses its dialog's confirm button, then the system shall keep the dialog open. |
| R-DLG.11 | U | The system shall show on each dialog button the key that presses it. |
| R-DLG.12 | When | When the operator presses the key a dialog button shows, the system shall press that button. |
| R-DLG.13 | U | The system shall show file and folder names in dialogs as plain text, never as markup. |

#### S7.2 · The Load dialog: opening, layout and keys (CTX-LOADDLG; from batch-100 HLR-173, HLR-173e)

Escape: R-DLG.2. Cancel: R-DLG.9. Keys behind the dialog: R-DLG.1. Button keys: R-DLG.11, R-DLG.12. Names: R-DLG.13.

| Id | Form | Requirement |
|---|---|---|
| R-TUI-043.1 | When | When the operator presses Ctrl+L, or `l` outside a text box, the system shall open the Load dialog with the focus in its path box. |
| R-LOADDLG.1 | When | When the operator presses `p` outside a text box, or presses `Load project (p)` on the Workspace, the system shall open the Load dialog with the focus on its list. |
| R-LOADDLG.2 | U | The system shall lay out the Load dialog as CTX-LOADDLG shows. |
| R-LOADDLG.3 | While | While the terminal is at least 100 columns wide, the system shall show the Load dialog's preview to the right of its list. |
| R-LOADDLG.4 | While | While the terminal is narrower than 100 columns, the system shall show the Load dialog's preview below its list. |
| R-LOADDLG.5 | U | The system shall show each line of the Load dialog's list and preview on one terminal line, cut with `…` when it is wider than its pane. |
| R-LOADDLG.6 | U | The system shall show the whole path box hint at 118 columns. |
| R-LOADDLG.7 | When | When the operator presses Tab in the Load dialog, the system shall move the focus one step along the path box, the list, the preview, `Load`, `Cancel`, and from `Cancel` back to the path box. |
| R-LOADDLG.8 | When | When the operator presses Shift+Tab in the Load dialog, the system shall move the focus one step back along the order of R-LOADDLG.7. |
| R-LOADDLG.9 | When | When the operator types a printable character while the list has the focus, the system shall add the character to the end of the path box text. |
| R-LOADDLG.10 | When | When the operator types a printable character while the list has the focus, the system shall move the focus to the path box. |
| R-LOADDLG.11 | When | When the operator presses ↑ or ↓ while the list has the focus, the system shall keep the focus on the list. |
| R-LOADDLG.12 | U | The system shall never highlight a heading line or a token line of the Load dialog's list. |
| R-LOADDLG.13 | When | When the operator clicks a loadable row, the system shall highlight that row. |
| R-LOADDLG.14 | When | When the operator clicks or double-clicks a loadable row, the system shall keep the Load dialog open. |
| R-LOADDLG.15 | When | When the Load dialog opens, the system shall highlight the open project's row. |
| R-LOADDLG.16 | When | When the Load dialog opens and its list holds no row of an open project, the system shall highlight the first project row. |
| R-LOADDLG.17 | When | When the Load dialog opens and its list holds no project row, the system shall highlight the first loadable row. |
| R-LOADDLG.18 | U | The system shall show no internal decision id (`D<n>`, `O-<n>`, `VS-…`, `LLR-…`, `HLR-…`) in the Load dialog. |
| R-LOADDLG.19 | If | If a paste or a typed key would make the path box text longer than 4,096 characters, then the system shall leave the path box text unchanged. |
| R-LOADDLG.20 | If | If a paste or a typed key would put a control character into the path box, then the system shall leave the path box text unchanged. |
| R-TUI-043.3 | When | When the operator presses Escape or Cancel in the Load dialog, the system shall leave the session unchanged. |

#### S7.2a · Sections and rows (from batch-100 HLR-173)

| Id | Form | Requirement |
|---|---|---|
| R-LOADDLG.21 | U | The system shall show the Load dialog's list as three sections in this order: `Projects`, `Work area`, `Recent`. |
| R-LOADDLG.22 | U | The system shall start each section of the Load dialog's list with its heading line. |
| R-LOADDLG.23 | When | When the Load dialog opens, the system shall show one project row per project of the project list (S11), in the project list's order. |
| R-LOADDLG.24 | If | If the project list holds no project, then the system shall show the token line `no projects — ctrl+s saves a project` in the `Projects` section. |
| R-LOADDLG.25 | If | If the work area cannot be listed, then the system shall show the token line `could not be read — check that the folder can be opened, then load again` in the `Projects` section. |
| R-LOADDLG.26 | If | If the work area cannot be listed, then the system shall still fill the `Work area` and `Recent` sections. |
| R-LOADDLG.27 | When | When the Load dialog opens, the system shall show one work-area file row per loadable file, in the order of the Workarea Files list. |
| R-LOADDLG.28 | If | If `temp/` holds no loadable file, then the system shall show the token line `no work-area files — l loads a file` in the `Work area` section. |
| R-LOADDLG.29 | When | When the Load dialog opens, the system shall show one recent row per entry of the recent-sources read (S5), in the read's order. |
| R-LOADDLG.30 | If | If the recent-sources read returns no entry and no problem, then the system shall show the token line `no recent sources` in the `Recent` section. |
| R-LOADDLG.31 | If | If the recent-sources read reports the problem `too large`, then the system shall show the token line `too large — the next load starts a new list` in the `Recent` section. |
| R-LOADDLG.32 | If | If the recent-sources read reports the problem `could not be read`, then the system shall show the token line `could not be read — check that the recent-sources file can be opened` in the `Recent` section. |
| R-LOADDLG.33 | U | The system shall show a project row as the painted name of the project folder. |
| R-LOADDLG.34 | U | The system shall show a work-area file row as the painted name of the file. |
| R-LOADDLG.35 | U | The system shall show a recent row as `<file name> (<kind>)` of CTX-LOADDLG. |
| R-LOADDLG.36 | U | The system shall read nothing at a recent row's path before the operator loads that row. |

#### S7.2b · The preview and its marks (from batch-100 HLR-173, HLR-173a)

| Id | Form | Requirement |
|---|---|---|
| R-LOADDLG.37 | When | When a loadable row is highlighted while the list is the load source, the system shall show that row's preview. |
| R-LOADDLG.38 | When | When the path box becomes the load source, the system shall clear the preview. |
| R-LOADDLG.39 | When | When the Load dialog opens with the focus in its path box, the system shall show an empty preview. |
| R-LOADDLG.40 | When | When a project row is highlighted, the system shall show in the preview one `variant <file name>` line per variant of the project, in variant order. |
| R-LOADDLG.41 | When | When a project row is highlighted, the system shall show in the preview one `MAC <file name>` line per MAC file of the project. |
| R-LOADDLG.42 | When | When a project row is highlighted, the system shall show in the preview an `A2L <file name>` line for the project's first A2L file. |
| R-LOADDLG.43 | When | When a project row is highlighted, the system shall show in the preview the line `project file: <state>` with the state `ok`, `no project.json` or `manifest damaged` of the project's project.json. |
| R-LOADDLG.44 | When | When a project row is highlighted, the system shall mark with `● ` the variant, MAC and A2L lines of the project's installed set. |
| R-LOADDLG.82 | If | If the project load would refuse a project's first A2L file (S11: a link or junction, too large to open, or unreadable), then the system shall show that file's `A2L <file name>` line in the preview without the mark. |
| R-LOADDLG.45 | If | If a project holds more than one MAC file or more than one A2L file, then the system shall mark no line of its preview. |
| R-LOADDLG.46 | If | If a file in a project folder is a link or a reparse point, then the system shall leave it out of the project's preview. |
| R-LOADDLG.47 | If | If a project's folder or its project.json cannot be read, then the system shall show as the project's preview only the line `could not be read — check that the folder can be opened, then load again`. |
| R-LOADDLG.48 | If | If a project's project.json is a link, a reparse point or not a regular file, then the system shall show as the project's preview only the line `could not be read — check that the folder can be opened, then load again`. |
| R-LOADDLG.49 | When | When a work-area file row is highlighted, the system shall show in the preview the lines of CTX-LOADDLG for that file, each marked with `● `. |
| R-LOADDLG.50 | While | While a project is open, the system shall show in the preview of a highlighted S19 or Intel HEX work-area file row the line `becomes the active variant of project <project name>`. |
| R-LOADDLG.83 | When | When the open project's row is highlighted, the system shall show in the preview the load reason and the problem rows of that project's last project load (S11 CTX-LOADRES). |
| R-LOADDLG.51 | When | When a recent row is highlighted, the system shall show in the preview the whole recorded path, the line `kind <kind>` and the line `checked when loaded`. |
| R-LOADDLG.52 | When | When a recent row is highlighted, the system shall mark no line of the preview. |
| R-LOADDLG.53 | U | The system shall show every file, variant and project name in the Load dialog's preview as a painted name. |

#### S7.2c · Loading from the dialog (from batch-100 HLR-173b, HLR-173c)

| Id | Form | Requirement |
|---|---|---|
| R-LOADDLG.54 | When | When the operator makes a load request while the list is the load source, the system shall load the highlighted row. |
| R-LOADDLG.55 | When | When the operator makes a load request while the path box is the load source, the system shall load the typed path of the path box. |
| R-LOADDLG.56 | When | When the system accepts a load request, the system shall close the Load dialog. |
| R-LOADDLG.57 | When | When the operator presses Alt+L with the focus in the path box, the system shall type nothing into the path box. |
| R-LOADDLG.58 | If | If a second load request arrives after the system has accepted a load request, then the system shall ignore it. |
| R-LOADDLG.59 | If | If a load request arrives after the operator has pressed Escape in the Load dialog, then the system shall ignore it. |
| R-LOADDLG.60 | When | When the Load dialog closes on a project row, the system shall load that project through the project load of S11. |
| R-LOADDLG.61 | When | When the Load dialog closes on a work-area file row, the system shall load that file as a pick of the same file in the Workarea Files list loads it (S5). |
| R-LOADDLG.62 | When | When the Load dialog closes on a recent row, the system shall load the row's recorded path, unchanged, as a typed path. |
| R-LOADDLG.63 | When | When the operator loads a project row or a work-area file row, the system shall load the name as it is on disk, not the painted name. |
| R-LOADDLG.64 | When | When a picked or typed project name equals a name of the project list, the system shall load the project of that name. |
| R-LOADDLG.65 | When | When a picked or typed project name equals no name of the project list but matches one by the file system's letter-case rule, the system shall load that project under its listed name. |
| R-LOADDLG.68 | If | If the system refuses a loaded project row, then the system shall leave the session unchanged. |

R-LOADDLG.66 (a project row whose name the list no longer holds: `… is not a project …`) and R-LOADDLG.67 (a project row whose folder cannot be read: `… could not be read …`) are retired: S11 R-TUI-013.18 and R-TUI-013.17 state the same status lines for every project load and now cite their tests (D7-34).

#### S7.2d · An empty or refused load request (from batch-100 HLR-173d)

| Id | Form | Requirement |
|---|---|---|
| R-LOADDLG.69 | If | If the operator makes a load request while the path box is the load source and holds no text or only spaces, then the system shall show the reason line `nothing selected — pick a row or type a path`. |
| R-LOADDLG.70 | If | If the operator makes a load request while the list is the load source and no loadable row is highlighted, then the system shall show the reason line `nothing selected — pick a row or type a path`. |
| R-LOADDLG.71 | If | If the typed path of a load request is in the class `not found`, then the system shall show the reason line `not found — check the path`. |
| R-LOADDLG.72 | If | If the typed path of a load request is in the class `not a supported file`, then the system shall show the reason line `not a supported file — check the path`. |
| R-LOADDLG.73 | If | If the typed path of a load request is in the class `not a project`, then the system shall show the reason line `not a project — pick a project in the list`. |
| R-LOADDLG.74 | If | If the typed path of a load request is in the class `outside`, then the system shall show the reason line `outside the work area — copy the folder into the work area`. |
| R-LOADDLG.75 | If | If the typed path of a load request is in the class `link`, then the system shall show the reason line `link or junction — pick a project in the list`. |
| R-LOADDLG.76 | If | If the typed path of a load request is in the class `link file`, then the system shall show the reason line `is a link or junction — open the file it points to`. |
| R-LOADDLG.77 | If | If the typed path of a load request is in the class `unreadable`, then the system shall show the reason line `could not be read — check that the folder can be opened, then load again`. |
| R-LOADDLG.78 | If | If the system refuses a load request, then the system shall keep the Load dialog open. |
| R-LOADDLG.79 | If | If the system refuses a load request, then the system shall leave the path box text unchanged. |
| R-LOADDLG.80 | If | If the system refuses a load request, then the system shall show no status line. |
| R-LOADDLG.81 | If | If the system refuses a recent row, then the system shall keep the row's entry in the recent sources. |

#### S7.2e · A typed path (from batch-100 HLR-172a)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-043.14 | U | The system shall give a typed path the first typed-path class of CTX-LOADDLG that applies. |
| R-TUI-043.15 | When | When the Load dialog closes on a typed path in the class `project`, the system shall load that project through the project load of S11. |
| R-TUI-043.2 | When | When the Load dialog closes on a typed path in the class `data file` or `A2L file`, the system shall load that file as S5.3 and S5.4 say. |
| R-TUI-043.16 | If | If the system refuses a typed path, then the system shall leave the session unchanged. |
| R-TUI-043.17 | If | If the system refuses a typed path, then the system shall write no file. |
| R-TUI-043.18 | If | If a late typed path is in the class `not found`, then the system shall show the status `File NOT loaded: '<path>' not found — check the path.` |
| R-TUI-043.19 | If | If a late typed path is in the class `not a supported file`, then the system shall show the status `File NOT loaded: '<path>' is not a supported file — check the path.` |
| R-TUI-043.20 | If | If a late typed path is in the class `not a project`, then the system shall show the status `Project NOT loaded: '<path>' is not a project — pick a project in the list.` |
| R-TUI-043.21 | If | If a late typed path is in the class `outside`, then the system shall show the status `Project NOT loaded: '<path>' is outside the work area — copy the folder into the work area.` |
| R-TUI-043.22 | If | If a late typed path is in the class `link`, then the system shall show the status `Project NOT loaded: '<path>' passes through a link or junction — pick a project in the list.` |
| R-TUI-043.23 | If | If a late typed path is in the class `link file`, then the system shall show the status `File NOT loaded: '<path>' is a link or junction — open the file it points to.` |
| R-TUI-043.24 | If | If a late typed path is in the class `unreadable`, then the system shall show the status `Project NOT loaded: '<path>' could not be read — check that the folder can be opened, then load again.` |

`<path>` is the painted name of the typed text; `<project name>` the painted name of the project.

#### S7.3 · Paste into text boxes (CTX-PASTE)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-043.4 | When | When the operator presses Ctrl+V in a single-line box, the system shall insert the first line of the OS clipboard text at the cursor. |
| R-TUI-043.5 | When | When the system pastes into a text box that holds a selection, the system shall replace the selection with the pasted text. |
| R-TUI-043.6 | If | If the system cannot read the OS clipboard, then the system shall paste the app clipboard. |
| R-TUI-043.7 | If | If neither clipboard holds text, then the system shall show the paste failure warning. |
| R-TUI-043.8 | If | If neither clipboard holds text, then the system shall select the whole text of the box. |
| R-TUI-043.9 | U | The system shall keep the screen responsive while it reads the OS clipboard. |
| R-TUI-043.10 | U | The system shall end an OS clipboard read within 1 second. |
| R-TUI-043.11 | U | The system shall paste characters outside the system code page unchanged. |
| R-TUI-043.12 | If | If the system cannot read the OS clipboard, then the system shall write a WARNING line to the log. |
| R-TUI-043.13 | U | The system shall not write clipboard text to the log. |
| R-TUI-044.1 | U | The system shall give every single-line box the paste of R-TUI-043.4 to R-TUI-043.13. |
| R-TUI-044.2 | If | If a paste into any box but the Load dialog's path box holds more characters than the paste limit, then the system shall insert only its first 65,536 characters. |
| R-TUI-044.3 | When | When the operator presses Ctrl+V in a multi-line box, the system shall insert the OS clipboard text at the cursor. |
| R-TUI-044.4 | When | When the terminal sends a paste into a multi-line box, the system shall insert every line of it. |
| R-TUI-044.5 | U | The system shall show pasted text as plain text, never as markup. |

#### S7.4 · Window help (CTX-HELP)

Where the help window's focus starts and how it closes: R-DLG.8, R-DLG.2, R-DLG.9.

| Id | Form | Requirement |
|---|---|---|
| R-WHELP.1 | U | The system shall have a help section for every rail window, for Split / Join / Export and for the Reports dialog. |
| R-WHELP.2 | U | The system shall show a help chip beside the title of every window that has a help section. |
| R-WHELP.3 | U | The system shall show a help chip on the MAC View, the Issues Report and the A2B Diff. |
| R-WHELP.4 | When | When the operator presses a help chip, the system shall open the help window of its window. |
| R-WHELP.5 | When | When the operator presses `?` outside a text box while the focus is in a window that has a help section, the system shall open that window's help window. |
| R-WHELP.6 | When | When the operator presses `?` in the Reports dialog outside a text box, the system shall open the Reports help window. |
| R-WHELP.7 | When | When the system opens a help window, the system shall show the section title, the steps numbered from 1 with no gap, and the key lines, as CTX-HELP shows. |
| R-WHELP.8 | U | The system shall take a help window's key lines from the same table as the window's key-bar row 2. |
| R-WHELP.9 | When | When the operator presses ↑, ↓, PgUp, PgDn, Home or End in a help window, the system shall scroll its text. |
| R-WHELP.10 | While | While a help window's text is taller than the terminal, the system shall keep the title and `Close  esc` on screen. |
| R-WHELP.11 | U | The system shall show help text as plain text, never as markup. |
| R-WHELP.12 | U | The system shall name in a help section only keys, controls and behaviour its window has. |
| R-WHELP.13 | U | The system shall refer in a help section only to windows, folders and files the operator can open from the app. |
| R-WHELP.14 | U | The system shall write help sections without Markdown marks. |
| R-WHELP.16 | U | The system shall state in the Patch Editor's help section that each Bytes token is a hex byte of 1–2 digits with an optional `0x`, and that decimals are not accepted. |
| R-WHELP.17 | U | The system shall state in the Flow Builder's help section that a run pauses at an external step until the step is confirmed in Flow Execution. |
| R-WHELP.15 | When | When the operator opens the Patch Editor's help window, the system shall include the steps of the Changes file notation section. |

#### S7.5 · The key bar (CTX-KEYBAR)

| Id | Form | Requirement |
|---|---|---|
| R-KEYBAR.1 | U | The system shall show the key bar of CTX-KEYBAR at the bottom of every window. |
| R-KEYBAR.2 | U | The system shall show in row 1 the global keys of CTX-KEYBAR, in that order, and no other key. |
| R-KEYBAR.3 | U | The system shall show in row 2 the shown window's name, its window keys, then its go keys after `· go`. |
| R-KEYBAR.4 | U | The system shall label each token with the palette label of its key's command. |
| R-KEYBAR.5 | While | While a key's command is switched off on the shown window, the system shall leave its token out of row 2. |
| R-KEYBAR.6 | While | While a key's condition in CTX-KEYBAR is false, the system shall show its token dimmed. |
| R-KEYBAR.7 | While | While the focus is outside the window of an owned key, the system shall show that key's token dimmed. |
| R-KEYBAR.8 | If | If row 1 is wider than the terminal, then the system shall leave out whole tokens from its end and keep `? Help`. |
| R-KEYBAR.9 | If | If row 2 is wider than the terminal, then the system shall keep the window name, leave out whole tokens from its end and end it with `? more`. |
| R-KEYBAR.10 | When | When the operator clicks a token that is not dimmed, the system shall run its key's command. |
| R-KEYBAR.11 | When | When the operator clicks a token, the system shall type nothing into the focused text box. |
| R-KEYBAR.12 | When | When the operator clicks a dimmed token, the system shall ring the bell. |
| R-KEYBAR.13 | When | When the operator clicks `? more`, the system shall show the key panel. |
| R-KEYBAR.14 | When | When the focus, the shown window or a key's condition changes, the system shall repaint the key bar. |
| R-KEYBAR.15 | When | When the operator presses a key whose token is shown and not dimmed, the system shall run its command. |



<a id="s8"></a>

## S8 · Change documents, apply & save-back

### Context notes (informative)

#### CTX-CHGDOC · The change document (S8.1 … S8.4)

```text
change document   A JSON file or pasted JSON text in the format below.
                  kind "change": entries to write into the image.
                  kind "check": expected values (S9). Same format.
envelope          The top-level JSON object. Fields:
  format            "s19app-changeset"
  version           "2.0"
  kind              "change" or "check"
  encoding          The name of a text codec, for example "utf-8". It turns string
                    values into bytes.
  value_mode        "text" or "codes"
  entries           A JSON array of entries.
entry             A JSON object. Fields:
  type              "bytes" or "string"
  address           Address form: a JSON string "0x" + one or more hexadecimal digits
                    (either case), or a JSON integer 0 or more (not true/false).
                    A byte address.
  bytes             (type "bytes") Byte tokens separated by whitespace. A byte token is
                    exactly two hexadecimal digits.
  value             (type "string") value_mode "text": a JSON string.
                    value_mode "codes": a JSON array of Unicode code points.
  symbol            (optional) The name of an A2L tag, beside the address, never in
                    its place.
encoded bytes     The bytes an entry writes: its byte tokens, or its value encoded
                  with the document's encoding.
span              address … address + number of encoded bytes (end not included).
v1 document       A JSON object whose format is "s19app-unified-changeset", or that has
                  both a "parameters" and a "memory" field.
declared A2L      The A2L the reader resolves symbols against.
read cap          268,435,456 bytes (256 MiB) per change file.
entry ceiling     100,000 entries per document.
run ceiling       1,048,576 bytes per entry; for a string value also 1,048,576
                  characters or code points before encoding.
Example (fake values):
  {"format": "s19app-changeset", "version": "2.0", "kind": "change",
   "encoding": "utf-8", "value_mode": "text",
   "entries": [{"type": "bytes", "address": "0x00000000", "bytes": "DE AD BE EF"},
               {"type": "string", "address": "0x00000010", "value": "ABC"}]}

File defects (each ends the read):
  F-1  the path names no file.
  F-2  the file is larger than the read cap.
  F-3  the file cannot be opened.
  F-4  the text is not JSON: not well-formed, nested deeper than the JSON reader
       allows, or not valid UTF-8.
  F-5  the top level is not a JSON object.
  F-6  the text is a v1 document.
Envelope defects (each one is reported):
  M-1  format is not "s19app-changeset".
  M-2  kind is not "change" or "check".
  M-3  encoding is not the name of a text codec.
  M-4  value_mode is not "text" or "codes".
  M-5  entries is missing or is not an array.
  M-6  version is not "2.0" (D8-20).
Entry defects, in check order:
  C-1  the entry is not a JSON object.
  C-2  type is not "string" or "bytes".
  C-3  address is not an address form.
  C-4  symbol is present but is not text, or is blank.
  C-5  symbol names no usable tag: no declared A2L, no tag of that name, or a tag
       without an address or a length.
  C-6  symbol is present and type is "string".
  C-7  (string) value is missing, empty, or of the wrong JSON type for value_mode.
  C-8  (string) value has more characters or code points than the run ceiling.
  C-9  (string) value cannot be encoded with the encoding.
  C-10 (string) the encoded value is longer than the run ceiling.
  C-11 (bytes) bytes is missing, not text, or blank.
  C-12 (bytes) a token is not a byte token.
  C-13 (bytes) there are more tokens than the run ceiling.
  C-14 the symbol's tag has another address, or another length than the encoded bytes.
collision         Two entries whose spans share an address.
```

#### CTX-FINDING · Findings and status texts (S8.1 … S8.8)

```text
finding        A code, a severity (error or warning) and a message about a change
               document or a save. The same shape as an issue (S3 CTX-ISSUE), with
               artifact "changes".
finding line   [<code>] <severity>: <message>
               e.g. [CHG-COLLISION] error: change entry 0 at address 0x100 (4 bytes) …
<i>            The entry's position in the entries array, from 0.
<A>, <B>, <T>  An address: uppercase hexadecimal digits, no leading zeros.
<A8>           An address: 8 uppercase hexadecimal digits.
quoted value   <path>, <format>, <version>, <kind>, <encoding>, <value_mode>, <type>,
               <symbol>, <tag>, <typed name>, <image kind>: the value as found —
               text in single quotes, a number as its digits, a missing field or
               null as None.
<error type>   The name of the error the system got from the file system or the JSON
               reader, for example PermissionError or JSONDecodeError.
<reason>       The refusal text of the placement (S5 CTX-WORKAREA refusals).
<n> entries    "entry" when the count is 1, "entries" otherwise.
```

#### CTX-APPLY · Applying a change document (S8.5)

```text
source image      The image as loaded from the primary file (S1), before any apply.
source byte       The byte the source image holds at an address.
containment       Where an entry's span lies in the image:
  inside            every address of the span is in one range.
  partial           some address is in a range, but no single range holds the whole
                    span (it crosses a range end or a gap).
  outside           no address of the span is in the image.
  no image          no primary image is loaded.
disposition       applied (inside, written) · skipped-partial · skipped-outside ·
                  skipped-no-image · blocked.
blocked document  A change document with an error finding, or whose kind is not
                  "change".
MAC span          One address: that of a MAC record that parsed and has an address (S2).
A2L span          A tag's address … address + length; 1 byte when the tag has no
                  length or a length below 1.
owner             Among the spans of one kind that hold an address: the one with the
                  lowest start; on equal starts, the one declared first.
linkage           mac-linked (the span shares an address with a MAC span) ·
                  a2l-linked (with an A2L span) · both · standalone (neither).
lowest linked address  The lowest address of the entry's span that a span of that
                  kind holds.
change summary    Per entry, in document order: span, bytes before (applied entries
                  only), encoded bytes, disposition, linkage, linkage symbol, the
                  entry's own symbol. Per document: the count of each disposition,
                  the findings, the time of the apply (UTC, ISO 8601).
```

#### CTX-SAVEBACK · Save-back (S8.6)

```text
save-back         Writing the Patch Editor's image to a new file after an apply.
save-back prompt  The row "Save patched image as:" with a name box and the controls
                  "Width: <w> bytes/line", "Write file" and "Don't save" (layout: S10).
width             Data bytes per S19 record: 32 or 16.
suggested name    <stem of the loaded file>-patched.s19, or …-patched.hex for an
                  Intel HEX image.
save name         The confirmed name reduced to its last path part (either separator;
                  a drive removed), without the spaces around it.
kind suffix       .s19 for an S19 image, .hex for an Intel HEX image.
reserved device name  A name whose part before the first dot, without trailing dots and
                  spaces, compared case-folded with ¹ ² ³ read as 1 2 3, is CON, PRN,
                  AUX, NUL, CONIN$, CONOUT$, COM0 … COM9 or LPT0 … LPT9 (the shared
                  rule of the project names, S11).
destination       The open project's folder; the work area (.s19tool/workarea/) when no
                  project is open.
saved image       The source image plus the encoded bytes of every inside entry of the
                  open change document.
invalid range     A range that holds a byte of an invalid record (S1 R-VAL-001b).
header data       The data of the S0 record of a written S19 file.
save suffix       " — <n> entries applied before this save (<A8>, …)", then, when the
                  saved image holds entries the last apply did not apply,
                  "; includes <m> entries not applied before this save (<A8>, …)".
                  No parentheses when n is 0. Addresses in document order.
```

#### CTX-WRITE · Image files the system writes (S8.7)

```text
S19 record types by the highest address of the image:
  up to 0xFFFF       data S1, terminator S9
  up to 0xFFFFFF     data S2, terminator S8
  above 0xFFFFFF     data S3, terminator S7
S19 record rules     S1 CTX-S19 (count, address width, checksum rule).
Intel HEX records    type 04 (upper 16 address bits), type 00 (data), type 01 (end of
                     file, the line :00000001FF). Record rules: S1 CTX-HEX.
```

#### CTX-VERIFY · Verify on save (S8.8)

```text
verify            Reading a written file back and comparing its image with the saved
                  image.
difference kinds  changed (both hold the address, the bytes differ) ·
                  missing in file (the saved image holds the address, the file does not) ·
                  extra in file (the file holds the address, the saved image does not).
run               A longest run of consecutive addresses of one difference kind.
mismatch summary  changed <r> run(s) / <b> byte(s), missing in file <r> run(s) / <b>
                  byte(s), extra in file <r> run(s) / <b> byte(s)
```

---

### Requirements


#### S8.1 · Reading a change document: file and envelope (CTX-CHGDOC, CTX-FINDING)

| Id | Form | Requirement |
|---|---|---|
| R-CHG-001.1 | When | When the system reads pasted change-document text, the system shall apply the same rules as to a change file, except file defects F-1, F-2 and F-3. |
| R-CHG-001.2 | When | When the operator loads a change file by its path, the system shall find the file by the path-input rules of S5.3. |
| R-CHG-001.3 | If | If the path names no file, then the system shall record the finding `MF-PATH-UNRESOLVED` with the message `the change-file path could not be resolved — no file was opened: <path>`. |
| R-CHG-001.4 | If | If the change file is larger than the read cap, then the system shall record the finding `MF-SIZE-CAP` with the message `the change file is <n> bytes, over the 268435456-byte read cap — the file was not loaded into memory`. |
| R-CHG-001.5 | If | If the change file is larger than the read cap, then the system shall read none of its content. |
| R-CHG-001.6 | If | If the change file cannot be opened, then the system shall record the finding `MF-PATH-UNRESOLVED` with the message `the change file could not be opened — no document was loaded: <error type>`. |
| R-CHG-001.7 | If | If the text is not JSON, then the system shall record the finding `MF-JSON-PARSE` with the message `the change file is not well-formed JSON — the load produced an empty document: <error type>`. |
| R-CHG-001.8 | If | If the top level of the text is not a JSON object, then the system shall record the finding `MF-BAD-STRUCTURE` with the message `the change file is well-formed JSON but its top level is not a JSON object — the load produced an empty document`. |
| R-CHG-001.9 | If | If the text is a v1 document, then the system shall record the finding `CHG-V1-FORMAT` with the message `this is a retired v1 unified change-set document — the v2 format is 's19app-changeset' version '2.0'; v1 files are not supported and are not migrated`. |
| R-CHG-001.10 | If | If the text has a file defect, then the system shall give a document with no entries. |
| R-CHG-001.11 | If | If the text has a file defect, then the system shall record no finding other than the one of that defect. |
| R-CHG-001.12 | If | If the envelope has an envelope defect, then the system shall read none of its entries. |
| R-CHG-001.13 | If | If the envelope has more than one envelope defect, then the system shall record one finding for each of them. |
| R-CHG-001.14 | If | If the envelope has defect M-1, then the system shall record the finding `CHG-FORMAT` with the message `the change file declares format <format>, not the v2 format 's19app-changeset' — no entries were read`. |
| R-CHG-001.15 | If | If the envelope has defect M-2, then the system shall record the finding `CHG-KIND-UNKNOWN` with the message `the change file declares kind <kind>, not one of 'change' / 'check' — no entries were read`. |
| R-CHG-001.16 | If | If the envelope has defect M-3, then the system shall record the finding `CHG-ENCODING-UNKNOWN` with the message `the change file declares encoding <encoding>, which does not resolve to a text codec — no entries were read`. |
| R-CHG-001.17 | If | If the envelope has defect M-4, then the system shall record the finding `CHG-VALUE-MODE-UNKNOWN` with the message `the change file declares value_mode <value_mode>, not one of 'text' / 'codes' — no entries were read`. |
| R-CHG-001.18 | If | If the envelope has defect M-5, then the system shall record the finding `MF-BAD-STRUCTURE` with the message `the change file's 'entries' field is absent or not a JSON array — no entries were read`. |
| R-CHG-VER.1 | If | If the envelope has defect M-6, then the system shall record the finding `CHG-VERSION-UNKNOWN` with the message `the change file declares version <version>, not the v2 version '2.0' — no entries were read`. |
| R-CHG-001.19 | When | When the operator loads a change document that has no file or envelope defect, the system shall show the status `Loaded <kind>: <n> entries, <e> error(s)`. |
| R-CHG-001.20 | If | If a change document the operator loads has a file or envelope defect, then the system shall show the status `Change file not loaded: <e> error(s)`. |
| R-CHG-001.21 | When | When the operator loads a change document, the system shall show a finding line for each of its findings after the status. |

#### S8.2 · Reading entries (CTX-CHGDOC)

| Id | Form | Requirement |
|---|---|---|
| R-CHG-001.22 | If | If an entry has an entry defect, then the system shall leave the entry out of the document. |
| R-CHG-001.23 | If | If an entry has an entry defect, then the system shall go on reading the entries that follow it. |
| R-CHG-001.24 | If | If an entry has more than one entry defect, then the system shall record only the finding of the first one in check order. |
| R-CHG-001.25 | If | If the entries array holds more than the entry ceiling, then the system shall read only the first 100,000 entries. |
| R-CHG-001.26 | If | If the entries array holds more than the entry ceiling, then the system shall record the finding `MF-ENTRY-LIMIT` with the message `the change file declares <n> entries, over the 100000-entry ceiling — the <m> entries past the ceiling were dropped`. |
| R-CHG-001.27 | If | If an entry has defect C-1, then the system shall record the finding `CHG-DECL-STRUCTURE` with the message `entry <i> is not a JSON object — the entry was skipped`. |
| R-CHG-001.28 | If | If an entry has defect C-2, then the system shall record the finding `CHG-DECL-STRUCTURE` with the message `entry <i> declares type <type>, not one of 'string' / 'bytes' — the entry was skipped`. |
| R-CHG-001.29 | If | If an entry has defect C-3, then the system shall record the finding `CHG-ADDRESS-SYNTAX` with the message `entry <i> has no valid address — expected a '0x...' hex string or a non-negative integer — the entry was skipped`. |
| R-CHG-001.30 | If | If an entry has defect C-7, then the system shall record the finding `CHG-VALUE-EMPTY` with the message `the string entry at address 0x<A> has a missing, empty, or wrong-typed 'value' field — the entry was skipped`. |
| R-CHG-001.31 | If | If an entry has defect C-8, then the system shall record the finding `MF-ENTRY-LIMIT` with the message `the string entry at address 0x<A> declares a raw value of <n> characters/code points, over the 1048576 run-length ceiling — the entry was dropped before encoding`. |
| R-CHG-001.32 | If | If an entry has defect C-9, then the system shall record the finding `CHG-ENCODE-FAIL` with the message `the string entry at address 0x<A> could not be encoded with <encoding>: <error type> — the entry was skipped`. |
| R-CHG-001.33 | If | If an entry has defect C-10, then the system shall record the finding `MF-ENTRY-LIMIT` with the message `the string entry at address 0x<A> encodes to <n> bytes, over the 1048576-byte run-length ceiling — the entry was dropped`. |
| R-CHG-001.34 | If | If an entry has defect C-11, then the system shall record the finding `CHG-VALUE-EMPTY` with the message `the bytes entry at address 0x<A> has a missing or empty 'bytes' field — the entry was skipped`. |
| R-CHG-001.35 | If | If an entry has defect C-12, then the system shall record the finding `CHG-BYTES-SYNTAX` with the message `the bytes entry at address 0x<A> has a token outside the wire grammar (whitespace-separated two-hex-digit tokens only) — the entry was skipped`. |
| R-CHG-001.36 | If | If an entry has defect C-13, then the system shall record the finding `MF-ENTRY-LIMIT` with the message `the bytes entry at address 0x<A> declares <n> bytes, over the 1048576-byte run-length ceiling — the entry was dropped`. |
| R-CHG-001.37 | U | The system shall read the hexadecimal digits a–f of an address or a byte token as the same values as A–F. |
| R-CHG-001.38 | U | The system shall measure the span of an entry in encoded bytes. |
| R-CHG-001.39 | U | The system shall put in no finding message the value or the bytes that an entry declares. |
| R-CHG-001.40 | If | If the spans of two entries share an address, then the system shall record the error finding `CHG-COLLISION` for each of the two entries. |
| R-CHG-001.41 | If | If an entry collides, then the system shall give its collision finding the message `change entry <i> at address 0x<A> (<n> bytes) collides with the entry at address 0x<B> — two declarations target the same memory`, with <B> the first entry in document order that it collides with. |
| R-CHG-001.42 | If | If an entry collides with more than one entry, then the system shall record one collision finding for it. |
| R-CHG-001.43 | U | The system shall read the example of CTX-CHGDOC as a change document with two entries and no finding. |
| R-CHG-001.44 | When | When the system reads the text of a per-entry edit (S10 R-TUI-058.2), the system shall read it as the only entry of a document with the open document's format, version, kind, encoding and value_mode. |

#### S8.3 · Symbol entries (CTX-CHGDOC; from LLR-141.1)

| Id | Form | Requirement |
|---|---|---|
| R-CHG-SYM.1 | If | If an entry has defect C-4, then the system shall record the finding `CHG-SYMBOL-UNRESOLVED` with the message `entry <i> declares a 'symbol' that is not a tag name string — the entry was skipped`. |
| R-CHG-SYM.2 | If | If an entry has a symbol and the read has no declared A2L, then the system shall record the finding `CHG-SYMBOL-UNRESOLVED` with the message `entry <i>: the symbol <symbol> cannot be resolved — no A2L context is declared for this change-set — the entry was skipped`. |
| R-CHG-SYM.3 | If | If an entry's symbol names no tag of the declared A2L, then the system shall record the finding `CHG-SYMBOL-UNRESOLVED` with the message `entry <i>: the symbol <symbol> resolves to no tag in the declared A2L — the entry was skipped`. |
| R-CHG-SYM.4 | If | If an entry's symbol names a tag without an address or a length, then the system shall record the finding `CHG-SYMBOL-UNRESOLVED` with the message `entry <i>: the symbol <symbol> resolves to a tag without an address or length — the entry was skipped`. |
| R-CHG-SYM.5 | If | If an entry has defect C-6, then the system shall record the finding `CHG-SYMBOL-VALUE` with the message `the symbol entry at address 0x<A> (<tag>) declares a string 'value' — symbol-referenced entries carry their value as encoded bytes — the entry was skipped`. |
| R-CHG-SYM.6 | If | If an entry has defect C-14, then the system shall record the finding `CHG-SYMBOL-VALUE` with the message `the symbol <tag> resolves to address 0x<T> length <L>, which drifts from the declared address 0x<A> / <n> encoded bytes — the entry was skipped`. |
| R-CHG-SYM.7 | When | When the system resolves a symbol, the system shall match tag names without regard to case. |
| R-CHG-SYM.8 | When | When the system resolves a symbol, the system shall store the tag's own spelling as the entry's symbol. |
| R-CHG-SYM.9 | When | When the operator loads or pastes a change document while an A2L is loaded, the system shall use that A2L as the declared A2L. |
| R-CHG-SYM.10 | If | If no A2L is loaded when the operator loads or pastes a change document, then the system shall read the document with no declared A2L. |

#### S8.4 · Writing and saving a change document (CTX-CHGDOC)

| Id | Form | Requirement |
|---|---|---|
| R-CHG-WRITE.1 | When | When the system writes a change document, the system shall write the envelope fields in the order format, version, kind, encoding, value_mode, entries. |
| R-CHG-WRITE.2 | When | When the system writes a change document, the system shall write each address as `0x` and uppercase hexadecimal digits with no leading zeros. |
| R-CHG-WRITE.3 | When | When the system writes a change document, the system shall write the bytes of a bytes entry as uppercase byte tokens separated by one space. |
| R-CHG-WRITE.4 | When | When the system writes a change document, the system shall write the value of a string entry as it was declared. |
| R-CHG-WRITE.5 | When | When the system writes an entry that has a symbol, the system shall write its symbol field after its other fields. |
| R-CHG-WRITE.6 | When | When the system writes a change document, the system shall write the entries in document order. |
| R-CHG-WRITE.7 | When | When the system writes a change document, the system shall indent the JSON by 2 spaces. |
| R-CHG-WRITE.8 | When | When the system writes a change document, the system shall write each character outside ASCII as a JSON `\u` escape. |
| R-CHG-WRITE.9 | When | When the system writes a change document, the system shall end the file with a line feed. |
| R-CHG-WRITE.10 | When | When the system writes the same change document twice, the system shall write the same bytes. |
| R-CHG-WRITE.11 | When | When the system reads a change document it wrote, the system shall read the same envelope and entries. |
| R-PATCH-SAVE-FOLDER-001.1 | When | When the operator saves the open change document with no project open, the system shall place the file in `patches/` of the work area. |
| R-PATCH-SAVE-FOLDER-001.2 | When | When the operator saves an open change document of kind change with a project open, the system shall place the file in `<project>/patches/`. |
| R-PATCH-SAVE-FOLDER-001.3 | When | When the operator saves an open change document of kind check with a project open, the system shall place the file in `<project>/checks/`. |
| R-PATCH-SAVE-FOLDER-001.4 | When | When the operator saves the open change document, the system shall name the file `changes.json`. |
| R-PATCH-SAVE-FOLDER-001.5 | If | If the folder holds a file with the same content under that name or a numbered name, then the system shall use that file and write nothing. |
| R-PATCH-SAVE-FOLDER-001.6 | If | If the name is taken in the folder by a file with different content, then the system shall name the new file with the lowest free numbered name. |
| R-PATCH-SAVE-FOLDER-001.7 | When | When the system has saved the change document, the system shall show the status `Saved change-set to <name>`. |
| R-PATCH-SAVE-FOLDER-001.8 | If | If the system cannot place the change document, then the system shall record the warning finding `MF-WRITE-CONTAINMENT` with the message `the change-file write target failed work-area containment validation — no file was written: <error type>: <reason>`. |
| R-PATCH-SAVE-FOLDER-001.9 | If | If the system cannot place the change document, then the system shall show the status `Change-set write rejected - see issues`. |
| R-PATCH-SAVE-FOLDER-001.10 | When | When a change-document save ends, the system shall leave no staging file in the work area. |

#### S8.5 · Validating and applying (CTX-APPLY)

| Id | Form | Requirement |
|---|---|---|
| R-CHG-VAL.1 | When | When the operator validates the open change document, the system shall recompute its collision findings from its current entries. |
| R-CHG-VAL.2 | When | When the operator validates the open change document, the system shall keep its other findings. |
| R-CHG-VAL.3 | When | When the operator validates the open change document, the system shall set the containment of each entry against the image. |
| R-CHG-VAL.4 | When | When a validation ends, the system shall show the status `Validate: <n> entries, <e> error(s), <w> warning(s)`. |
| R-CHG-002.1 | When | When the operator applies the open change document, the system shall first set every address that an earlier apply changed back to its source byte. |
| R-CHG-002.2 | When | When the operator applies the open change document, the system shall recompute its collision findings from its current entries. |
| R-CHG-002.3 | If | If the document is a blocked document, then the system shall give every entry the disposition `blocked`. |
| R-CHG-002.4 | If | If the document is a blocked document, then the system shall write no byte into the image. |
| R-CHG-002.5 | If | If the document has an error finding when the operator applies it, then the system shall show the status `Apply blocked: the document has <e> error(s)`. |
| R-CHG-002.6 | If | If the document's kind is not change when the operator applies it, then the system shall show the status `Apply blocked: kind <kind> cannot be applied`. |
| R-CHG-002.7 | When | When the system applies a document that is not blocked, the system shall write the encoded bytes of each inside entry at its span. |
| R-CHG-002.8 | When | When the system applies a document that is not blocked, the system shall give each inside entry the disposition `applied`. |
| R-CHG-002.9 | If | If an entry of a document that is not blocked is partial, then the system shall give it the disposition `skipped-partial`. |
| R-CHG-002.10 | If | If an entry of a document that is not blocked is outside, then the system shall give it the disposition `skipped-outside`. |
| R-CHG-002.11 | If | If no primary image is loaded when the operator applies a document that is not blocked, then the system shall give every entry the disposition `skipped-no-image`. |
| R-CHG-002.12 | If | If an entry is not inside, then the system shall write none of its bytes. |
| R-CHG-002.13 | U | The system shall add no address to the image when it applies a change document. |
| R-CHG-002.14 | When | When the system applies a change document, the system shall record the change summary of CTX-APPLY. |
| R-CHG-002.15 | When | When the system applies an entry, the system shall record its source bytes as its bytes before. |
| R-CHG-002.16 | When | When an apply ends, the system shall show the status `Apply: <a> applied, <s> skipped, <b> blocked`, with <s> the number of entries of the three skipped dispositions. |
| R-CHG-LINK.1 | When | When the system applies a change document, the system shall give each entry its linkage. |
| R-CHG-LINK.2 | U | The system shall give an entry the same disposition whatever its linkage. |
| R-CHG-LINK.3 | When | When the system gives an entry the linkage mac-linked or a2l-linked, the system shall take as its linkage symbol the name of the owner of its lowest linked address. |
| R-CHG-LINK.4 | When | When the system gives an entry the linkage both, the system shall take the MAC owner's name as its linkage symbol. |
| R-CHG-LINK.5 | If | If an entry's linkage is both and its MAC owner has no name, then the system shall take the A2L owner's name as its linkage symbol. |
| R-CHG-LINK.6 | When | When the system gives an entry the linkage standalone, the system shall give it no linkage symbol. |

#### S8.6 · Save-back (CTX-SAVEBACK)

| Id | Form | Requirement |
|---|---|---|
| R-CHG-003.1 | When | When an apply ends with at least one applied entry on an S19 or Intel HEX image, the system shall show the save-back prompt. |
| R-HEX-VERIFY-002.3 | When | When the system shows the save-back prompt, the system shall fill the name box with the suggested name. |
| R-S19-WIDTH-001.1 | When | When the system shows the save-back prompt, the system shall set the width to 32. |
| R-S19-WIDTH-001.2 | When | When the operator presses the Width control, the system shall switch the width between 32 and 16. |
| R-CHG-003.2 | When | When the operator presses `Don't save`, the system shall hide the save-back prompt. |
| R-CHG-003.3 | When | When the operator presses `Don't save`, the system shall write no file. |
| R-CHG-003.4 | When | When the operator presses `Don't save`, the system shall show the status `Patch Editor: save-back declined`. |
| R-CHG-003.5 | When | When the operator presses `Write file`, the system shall hide the save-back prompt. |
| R-CHG-003.6 | If | If no image is loaded when the operator presses `Write file`, then the system shall write no file. |
| R-CHG-003.7 | If | If no image is loaded when the operator presses `Write file`, then the system shall show the status `Patch Editor: no image loaded - nothing saved`. |
| R-CHG-003.8 | When | When the operator presses `Write file`, the system shall write the saved image to a new file in the destination. |
| R-HEX-SAVE-001.1 | When | When the system writes a save-back, the system shall write the file in the kind of the loaded image, S19 or Intel HEX. |
| R-CHG-003.9 | If | If the open change document is a blocked document when the operator presses `Write file`, then the system shall write no file. |
| R-CHG-003.10 | If | If the open change document is a blocked document when the operator presses `Write file`, then the system shall show the status `Patched image not saved - <n> entries blocked - see issues`. |
| R-CHG-003.11 | When | When the system writes a save-back, the system shall use the save name as the file name. |
| R-HEX-SAVE-001.2 | If | If the save name does not end with the kind suffix in any letter case, then the system shall add the kind suffix. |
| R-CHG-003.12 | If | If the save name is empty or ends with a dot, then the system shall refuse the save-back with the warning finding `MF-WRITE-CONTAINMENT` and the message `the requested save-back filename is empty or ends with a dot or space after sanitization — the patched image was not written: <typed name>`. |
| R-CHG-003.13 | If | If the save name is a reserved device name, then the system shall refuse the save-back with the warning finding `MF-WRITE-CONTAINMENT` and the message `the requested save-back filename is a Windows reserved device name — the patched image was not written: <typed name>`. |
| R-CHG-003.14 | If | If the destination is not inside the work area, then the system shall refuse the save-back with the warning finding `MF-WRITE-CONTAINMENT` and the message `the save-back destination is not inside this .s19tool/workarea/ tree — the patched image was not written: <reason>`. |
| R-CHG-003.15 | If | If the system cannot place the save-back file, then the system shall refuse the save-back with the warning finding `MF-WRITE-CONTAINMENT` and the message `the save-back target failed work-area containment validation — the patched image was not written: <reason>`. |
| R-CHG-003.16 | If | If the loaded image is neither S19 nor Intel HEX, then the system shall refuse the save-back with the warning finding `CHG-SAVE-UNSUPPORTED` and the message `save-back is not supported for a <image kind> source — only an S19- or Intel HEX-loaded image can be persisted; the patched image was not written`. |
| R-CHG-003.17 | If | If the system refuses a save-back, then the system shall show the status `Patched image not saved - see issues`. |
| R-CHG-003.18 | If | If the destination holds a file with the same content under the save name or a numbered name, then the system shall use that file and write nothing. |
| R-CHG-003.19 | If | If the save name is taken in the destination by a file with different content, then the system shall name the new file with the lowest free numbered name. |
| R-CHG-003.20 | U | The system shall leave the copy of the loaded file unchanged when it writes a save-back. |
| R-CHG-003.21 | When | When the system has written a save-back, the system shall show the status `Patched image saved as <name><save suffix>`. |
| R-CHG-003.22 | If | If the saved image holds an invalid range, then the system shall show the status `Warning: <n> invalid source ranges written with new checksums, first at 0x<A8>`. |
| R-CHG-003.23 | If | If an entry of the open document is not inside when the system writes a save-back, then the system shall leave its address out of the save suffix. |
| R-S19-SAVE-REUSE-001.1 | When | When the system writes a save-back of an Intel HEX image, the system shall put at most 16 data bytes in each record whatever the width. |
| R-S19-S0HEADER-001.1 | When | When the system writes a save-back of an S19 image whose source has an S0 record with data, the system shall use that data as header data. |
| R-S19-S0HEADER-001.2 | When | When the system writes at width 32 a save-back of an S19 image whose source has no S0 record with data, the system shall use as header data the written file name without its non-ASCII characters, cut to 252 bytes. |
| R-S19-S0HEADER-001.3 | When | When the system writes at width 16 a save-back of an S19 image whose source has no S0 record with data, the system shall write empty header data. |
| R-S19-EMIT.11 | When | When the system writes a save-back of an S19 image whose source has a terminator, the system shall write the address of the source's terminator in the terminator. |

#### S8.7 · Writing an image file (CTX-WRITE; HLR-153 statement 2)

| Id | Form | Requirement |
|---|---|---|
| R-IMG-WRITE.1 | U | The system shall write into an image file only the addresses of the image. |
| R-IMG-WRITE.2 | U | The system shall write image files that its own reader (S1) reads back to the same image with no diagnostic. |
| R-IMG-WRITE.3 | When | When the system writes a save-back file, the system shall end each line with CR LF on Windows and with LF on other systems. |
| R-S19-EMIT.1 | When | When the system writes an image as S19, the system shall write an S0 record first, with address 0 and the header data. |
| R-S19-EMIT.2 | When | When the system writes an image as S19, the system shall write the data records in ascending address order. |
| R-S19-EMIT.3 | When | When the system writes as S19 an image whose highest address is at most 0xFFFF, the system shall write S1 data records. |
| R-S19-EMIT.4 | When | When the system writes as S19 an image whose highest address is above 0xFFFF and at most 0xFFFFFF, the system shall write S2 data records. |
| R-S19-EMIT.5 | When | When the system writes as S19 an image whose highest address is above 0xFFFFFF, the system shall write S3 data records. |
| R-S19-EMIT.6 | When | When the system writes an image as S19, the system shall write as last record the terminator of CTX-WRITE that matches the data record type. |
| R-S19-EMIT.7 | When | When the system writes an image as S19, the system shall put at most the width in data bytes in each data record. |
| R-S19-EMIT.8 | When | When the system writes an image as S19, the system shall start a new data record at the start of each range. |
| R-S19-EMIT.9 | When | When the system writes an image as S19, the system shall make every record follow the checksum rule of S1 CTX-S19. |
| R-S19-EMIT.10 | When | When the system writes an image as S19, the system shall write the records in uppercase hexadecimal. |
| R-S19-EMIT.12 | When | When the system writes an S19 file with no source terminator address, the system shall write address 0 in the terminator. |
| R-HEX-EMIT-001.1 | When | When the system writes an image as Intel HEX, the system shall put at most 16 data bytes in each type-00 record. |
| R-HEX-EMIT-001.2 | When | When the system writes an image as Intel HEX, the system shall write a type-04 record before the first data record. |
| R-HEX-EMIT-001.3 | When | When the system writes an image as Intel HEX, the system shall write a type-04 record before each data record whose upper 16 address bits differ from those of the data record before it. |
| R-HEX-EMIT-001.4 | When | When the system writes an image as Intel HEX, the system shall write the data records in ascending address order. |
| R-HEX-EMIT-001.5 | When | When the system writes an image as Intel HEX, the system shall start a new data record at the start of each range. |
| R-HEX-EMIT-001.6 | When | When the system writes an image as Intel HEX, the system shall make every record follow the checksum rule of S1 CTX-HEX. |
| R-HEX-EMIT-001.7 | When | When the system writes an image as Intel HEX, the system shall write `:00000001FF` as the last line. |
| R-HEX-EMIT-001.8 | When | When the system writes an image as Intel HEX, the system shall write no other type-01 record. |
| R-HEX-EMIT-001.9 | When | When the system writes an empty image as Intel HEX, the system shall write only the line `:00000001FF`. |
| R-HEX-EMIT-001.10 | When | When the system writes an image as Intel HEX, the system shall write the records in uppercase hexadecimal. |

#### S8.8 · Verify on save (CTX-VERIFY)

| Id | Form | Requirement |
|---|---|---|
| R-HEX-VERIFY-001.1 | When | When the system has written a save-back file, the system shall read the file back with the S1 reader of its kind. |
| R-HEX-VERIFY-001.2 | When | When the system has read a save-back file back, the system shall compare its image with the saved image. |
| R-HEX-VERIFY-001.3 | When | When the image read back equals the saved image, the system shall mark the save `verified`. |
| R-HEX-VERIFY-001.4 | If | If the image read back differs from the saved image, then the system shall mark the save `mismatch`. |
| R-HEX-VERIFY-001.5 | If | If the file read back has a diagnostic or an integrity notice, then the system shall mark the save `mismatch`. |
| R-HEX-VERIFY-001.6 | If | If the save is marked `mismatch`, then the system shall keep the written file. |
| R-HEX-VERIFY-002.1 | When | When the system marks a save `verified`, the system shall show the status `Saved + verified: <name><save suffix>`. |
| R-HEX-VERIFY-002.2 | When | When the system marks a save `verified`, the system shall show no notice. |
| R-HEX-VERIFY-002.4 | If | If the save is marked `mismatch`, then the system shall show the status `Verify MISMATCH: <name><save suffix>`. |
| R-HEX-VERIFY-002.5 | If | If the save is marked `mismatch`, then the system shall show an error notice titled `Verify mismatch - file may not match` with the text `<name>: <mismatch summary>`. |
| R-HEX-VERIFY-002.6 | If | If the save is marked `mismatch`, then the system shall show the notice for 10 seconds. |



<a id="s9"></a>

## S9 · Checks

### Context notes (informative)

#### CTX-CHECK · Running a check document (S9.1)

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

#### CTX-CHECK-TEXT · How a run is shown (S9.2, S9.3)

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

#### CTX-CHECKS-SCREEN · The Checks screen (S9.3)

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

#### CTX-CHECK-EDITOR · The Check Editor (S9.4)

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

### Requirements


#### S9.1 · Running a check document (CTX-CHECK)

| Id | Form | Requirement |
|---|---|---|
| R-CHK-001.1 | U | The system shall give each entry of a check run exactly one outcome: pass, fail or uncheckable. |
| R-CHK-001.2 | U | The system shall write nothing to the image during a check run. |
| R-CHK-001.3 | If | If the kind of the document to run is not `check`, then the system shall block the run with the reason code `doc-kind`. |
| R-CHK-001.4 | If | If a check document carries a blocking fault, then the system shall block the run with the reason code `doc-fault`. |
| R-CHK-001.5 | If | If a run is blocked, then the system shall give every entry the outcome uncheckable. |
| R-CHK-001.6 | If | If an entry of a run that is not blocked is tainted, then the system shall give it the outcome uncheckable. |
| R-CHK-001.7 | When | When the system checks a checked entry that is inside the image, the system shall compare its expected bytes with the image bytes of its range. |
| R-CHK-001.8 | When | When the image bytes of a checked entry equal its expected bytes, the system shall give the entry the outcome pass. |
| R-CHK-001.9 | When | When the image bytes of a checked entry differ from its expected bytes, the system shall give the entry the outcome fail. |
| R-CHK-001.10 | If | If a checked entry is partial, outside or has no image, then the system shall give it the outcome uncheckable. |
| R-CHK-001.11 | U | The system shall give each run its aggregate counts. |
| R-CHK-001.12 | U | The system shall classify the linkage of every entry of a run, whatever its outcome. |
| R-CHK-002.1 | If | If a run is blocked with `doc-kind`, then the system shall give it the run reason text `this is a change-set (kind <kind display>), not a check-set — Run checks needs kind 'check'`. |
| R-CHK-002.2 | If | If a run is blocked with `doc-fault`, then the system shall give it the run reason text `document carries <n> error-severity declaration fault(s) [<code list>] — fix the document before running checks`, where n counts the blocking findings. |
| R-CHK-002.3 | If | If a run is blocked, then the system shall give each entry the reason pair (`<run reason code>`, `run blocked [<run reason code>]`). |
| R-CHK-002.4 | If | If an entry is tainted, then the system shall give it the reason pair (`entry-fault`, `entry at 0x<start> carries [CHG-COLLISION] — see declaration faults`). |
| R-CHK-002.5 | If | If a checked entry is partial, then the system shall give it the reason pair (`partial`, `range partially outside the loaded image [partial]`). |
| R-CHK-002.6 | If | If a checked entry is outside, then the system shall give it the reason pair (`outside`, `range outside the loaded image [outside]`). |
| R-CHK-002.7 | If | If no image is loaded, then the system shall give each checked entry the reason pair (`no-image`, `no image loaded`). |
| R-CHK-002.8 | When | When an entry's outcome is pass or fail, the system shall give it no reason. |

#### S9.2 · Results in the Patch Editor (CTX-CHECK-TEXT)

The Run checks button and its help text are S10 (R-PATCH-CHECKS-CLARITY-001).

| Id | Form | Requirement |
|---|---|---|
| R-CHK-PE-001 | When | When a check run started from the Patch Editor ends, the system shall show one result row per entry, in document order, on the Checks tab. |
| R-CHK-PE-002 | When | When a check run started from the Patch Editor ends, the system shall colour each result row with its outcome colour. |
| R-CHK-PE-003 | When | When a check run that is not blocked ends, the system shall show the count line as the Checks tab status. |
| R-CHK-PE-004 | If | If a check run started from the Patch Editor was blocked, then the system shall show the blocked line as the Checks tab status. |
| R-CHK-PE-005 | When | When a check run started from the Patch Editor ends, the system shall show the patch strip on the Checks tab. |
| R-CHK-PE-006 | When | When a check run started from the Patch Editor ends, the system shall write its count line or blocked line to the status log. |
| R-CHK-PE-007 | When | When a check run started from the Patch Editor ends, the system shall write one status line `[<code>] <severity>: <message>` per finding of the document. |
| R-CHK-PE-008 | While | While the Checks tab is shown and a current run with n entries exists, the system shall show the inspector subtitle `<n> checked`. |
| R-CHK-PE-009 | While | While the Checks tab is shown and no current run exists, the system shall show the inspector subtitle `no run yet`. |
| R-CHK-PE-010 | While | While no current run exists, the system shall show `No check run yet: press Run checks.` as the Checks tab status. |
| R-CHK-PE-011 | While | While no current run exists, the system shall show the patch strip with zero counts and an empty bar. |
| R-CHK-PE-012 | While | While no current run exists, the system shall show no result row on the Checks tab. |
| R-CHK-PE-013 | While | While a current run exists, the system shall lead each ledger row's Kind cell with the check glyph of that entry's outcome. |
| R-CHK-PE-014 | While | While no current run exists, the system shall lead each ledger row's Kind cell with `·`. |
| R-CHK-PE-015 | U | The system shall colour the check glyphs ✓ green, ✗ red, ◐ pale yellow and · grey. |
| R-CHK-PE-016 | U | The system shall show result rows and run reasons in the Patch Editor as plain text, never as markup. |

#### S9.3 · The Checks screen (CTX-CHECKS-SCREEN)

With no file loaded the screen shows the empty state (S5 R-TUI-029.4).

| Id | Form | Requirement |
|---|---|---|
| R-CHKS-001 | When | When the operator opens the Checks screen, the system shall show the current run. |
| R-CHKS-002 | When | When a check run started from the Patch Editor ends, the system shall update the Checks screen. |
| R-CHKS-003 | When | When the operator undoes or redoes a Patch Editor change, the system shall update the Checks screen. |
| R-CHKS-004 | If | If a file is loaded and no current run exists, then the system shall show the note `No check run yet — run checks from the Patch Editor.` in the grouped list. |
| R-CHKS-005 | When | When the Checks screen shows a current run, the system shall group its result rows by outcome in the group order. |
| R-CHKS-006 | When | When the Checks screen shows a current run, the system shall lead each non-empty group with its group header. |
| R-CHKS-007 | When | When the Checks screen shows a current run, the system shall colour each group header and result row with the group's outcome colour. |
| R-CHKS-008 | When | When the Checks screen shows a current run, the system shall show the aggregate line above the grouped list. |
| R-CHKS-009 | While | While no current run exists, the system shall show the aggregate line with zero counts and an empty bar. |
| R-CHKS-010 | If | If a current run holds more than 40 entries, then the system shall show the first 40 result rows in group order and the note `More check entries than shown — see the Patch Editor.` |
| R-CHKS-011 | If | If a current run holds no entry, then the system shall show the note `No check entries to group.` |
| R-CHKS-012 | When | When a result row's entry is linked, the system shall show the entry's linkage symbol in a cell beside the row. |
| R-CHKS-013 | When | When the operator activates a result row by click or Enter, the system shall show the hex peek window of that entry's start address. |
| R-CHKS-014 | U | The system shall show reasons and linkage symbols on the Checks screen as plain text, never as markup. |

#### S9.4 · The Check Editor (CTX-CHECK-EDITOR)

| Id | Form | Requirement |
|---|---|---|
| R-CHKED-001 | When | When the operator opens the Check Editor, the system shall list in the ledger every parameter of the loaded A2L, one row each. |
| R-CHKED-002 | If | If no A2L is loaded, then the system shall show the line `No A2L parameters — load an A2L (^L) to list them.` under the ledger. |
| R-CHKED-003 | When | When the operator types in Filter, the system shall list only the parameters whose name contains the filter text, ignoring case. |
| R-CHKED-004 | If | If no parameter matches the filter, then the system shall show the line `No parameter matches the filter.` under the ledger. |
| R-CHKED-005 | U | The system shall show every ledger address in full. |
| R-CHKED-006 | If | If a parameter name is wider than its column, then the system shall show its first dot-separated part, one `…` and the end of the name that fills the column. |
| R-CHKED-007 | When | When the operator highlights a ledger row, the system shall show its address, its Fmt · Unit and its name on the full-name line. |
| R-CHKED-008 | When | When the operator presses Include parameter, space or Enter on a ledger row, the system shall toggle that parameter's inclusion. |
| R-CHKED-009 | U | The system shall mark each included parameter with `✓` in the ledger. |
| R-CHKED-010 | When | When the operator returns to the Check Editor, the system shall keep included every parameter that the loaded A2L still lists. |
| R-CHKED-011 | When | When the operator presses Add row, the system shall add a memory row from the Address, Label and Size inputs. |
| R-CHKED-012 | If | If the Address input is not `0x` followed by hex digits, or decimal digits, then the system shall refuse the memory row with the Fields status `Check Editor: bad memory address '<text>'.` |
| R-CHKED-013 | If | If the Size input is a number outside 1–8, then the system shall refuse the memory row with the Fields status `Check Editor: size must be 1..8 bytes, got <n>.` |
| R-CHKED-014 | If | If the Size input is not empty and not a number, then the system shall refuse the memory row with the Fields status `Check Editor: bad size '<text>'.` |
| R-CHKED-015 | When | When the operator presses Remove row, the system shall remove the highlighted memory row. |
| R-CHKED-016 | When | When the field set changes, the system shall show the Fields tab lines of CTX-CHECK-EDITOR. |
| R-CHKED-017 | If | If no field is included, then the system shall show `No fields included yet.` under the Fields head line. |
| R-CHKED-018 | When | When the field set changes, the system shall show the field count `<n> field(s) → report` in the action row. |
| R-CHKED-019 | When | When the operator opens the JSON tab, the system shall show the spec that Write would write. |
| R-CHKED-020 | If | If the JSON tab text is longer than 5000 lines, then the system shall show its first 5000 lines and the line `showing 5000 of <N> lines`. |
| R-CHKED-021 | When | When the field set changes, the system shall show the Addendum tab text of CTX-CHECK-EDITOR. |
| R-CHKED-022 | U | The system shall offer no apply action in the Check Editor. |
| R-CHKED-023 | U | The system shall show the struck text `APPLY — not available` in the Check Editor's action row. |
| R-CHKED-024 | When | When the operator presses Write .chk.json, the system shall write the spec of the declared fields. |
| R-CHKED-025 | When | When the system builds a spec, the system shall take as the expected bytes of a field included in this session the image bytes of its range. |
| R-CHKED-026 | When | When the system builds a spec, the system shall take as the expected bytes of a field loaded from a spec the bytes that spec declared. |
| R-CHKED-027 | If | If a field is not a declared field, then the system shall leave it out of the spec. |
| R-CHKED-028 | If | If fields were left out of a spec, then the system shall show the status `Check Editor: <k> field(s) outside the loaded image — not declared.` |
| R-CHKED-029 | When | When the operator writes a spec, the system shall name it after the Write as input, or `spec.chk.json` when the input is empty. |
| R-CHKED-030 | If | If the Write as name does not end with `.chk.json`, then the system shall append `.chk.json` to it. |
| R-CHKED-031 | When | When the operator writes a spec, the system shall place it in the check home. |
| R-CHKED-032 | When | When a spec is written, the system shall show the status `Check Editor: wrote <name> (<n> fields, kind=check).` |
| R-CHKED-033 | When | When a spec is written, the system shall refresh the spec lists of the Check Editor, the Patch Editor and the A2B Diff screen. |
| R-CHKED-034 | If | If the writer refuses a spec, then the system shall show the status `Check Editor: spec NOT written.` |
| R-CHKED-035 | If | If the writer refuses a spec, then the system shall show `Write refused: <codes>.` as the Fields status. |
| R-CHKED-036 | When | When the operator presses Validate, the system shall run the spec that Write would write against the loaded image. |
| R-CHKED-037 | When | When a Validate run ends, the system shall show one result row per entry, coloured by outcome, under the memory form. |
| R-CHKED-038 | When | When a Validate run ends, the system shall show `validation complete` as the Fields status. |
| R-CHKED-039 | When | When a Validate run ends, the system shall write its count line to the status log. |
| R-CHKED-040 | When | When the operator opens the Check Editor or writes a spec, the system shall fill the Spec dropdown with the spec list. |
| R-CHKED-041 | When | When the operator picks a spec, the system shall replace the included parameters and the memory rows with one memory row per entry of the spec. |
| R-CHKED-042 | When | When the operator picks a spec, the system shall set the Write as input to the spec's name ending in `.chk.json`. |
| R-CHKED-043 | When | When the operator picks a spec, the system shall show the status `Check Editor: loaded '<name>' (<n> fields).` |
| R-CHKED-044 | If | If the picked file is a link or lies outside its folder, then the system shall refuse it with the status `Check Editor: file '<name>' is outside the patches folder — not loaded.` |
| R-CHKED-045 | If | If the picked file carries an ERROR finding, then the system shall write one status line `[<code>] <severity>: <message>` per finding. |
| R-CHKED-046 | If | If the picked file carries an ERROR finding, then the system shall refuse it with the status `Check Editor: spec NOT loaded.` |
| R-CHKED-047 | If | If the picked document's kind is not `check`, then the system shall refuse it with the status `Check Editor: '<name>' is a kind='<kind>' document — not a check spec.` |
| R-CHKED-048 | U | The system shall show parameter names, labels and file names in the Check Editor as plain text, never as markup. |
| R-CHKED-049 | While | While the Check Editor is shown at 118 × 54 or more, the system shall show Validate and Write .chk.json without scrolling. |
| R-CHKED-050 | While | While the Check Editor is shown below 118 × 54, the system shall keep every control reachable by scrolling. |
| R-CHKED-051 | U | The system shall show every Check Editor button as a one-row chip. |
| R-CHKED-052 | U | The system shall give Write .chk.json the only filled style of the Check Editor. |
| R-CHKED-053 | U | The system shall show the Check Editor legend of CTX-CHECK-EDITOR under the action row. |



<a id="s10"></a>

## S10 · Patch Editor

### Context notes (informative)

#### CTX-PE · The Patch Editor screen (S10.1)

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

#### CTX-PE-DOC · The document (S10.2 … S10.8)

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

#### CTX-PE-INPUT · The entry form (S10.3)

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

#### CTX-PE-LEDGER · Ledger and tally (S10.4)

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

#### CTX-PE-STRIP · The before → after strip (S10.5)

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

#### CTX-PE-JSON · The JSON tab (S10.6)

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

### Requirements


#### S10.1 · The screen (CTX-PE)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-063.1 | U | The system shall show the Patch Editor as the identity ribbon, the ledger beside the inspector, the file row, the document row and the legend, top to bottom. |
| R-TUI-063.2 | U | The system shall keep the ledger beside the inspector at every terminal width. |
| R-TUI-063.3 | U | The system shall give the inspector the tab chips Inspector, JSON and Checks. |
| R-TUI-063.4 | When | When the Patch Editor is first shown, the system shall show the Inspector tab. |
| R-TUI-063.5 | When | When the operator activates a tab chip by click, Enter or space, the system shall show that tab's pane. |
| R-TUI-063.6 | When | When the shown tab changes, the system shall set the inspector border title to INSPECTOR, JSON or CHECKS after the tab. |
| R-TUI-063.7 | U | The system shall give the ledger the border title `PATCH SCRIPT`. |
| R-TUI-063.8 | While | While the JSON tab is shown, the system shall show the inspector subtitle `v2 schema`. |
| R-TUI-064.1 | While | While the Patch Editor is shown at 118 × 54 or more, the system shall show Validate, Apply loaded changes and Save without scrolling. |
| R-TUI-064.2 | While | While the Patch Editor is shown at 118 × 54 or more, the system shall paint no row wider than the screen. |
| R-TUI-064.3 | While | While the Patch Editor is shown below 118 × 54, the system shall keep every control reachable by scrolling. |
| R-TUI-064.4 | U | The system shall show every Patch Editor button as a one-row chip. |
| R-TUI-064.5 | U | The system shall give Save the only filled style of the Patch Editor. |
| R-PE-001 | U | The system shall show the Patch Editor legend of CTX-PE under the document row. |
| R-PE-002 | While | While the document is file-backed, the system shall show `<file name> · <kind>` in the identity ribbon. |
| R-PE-003 | While | While the document is a draft, the system shall show `draft · <kind>` in the identity ribbon. |
| R-PE-004 | If | If the file name is wider than the ribbon, then the system shall show one `…` and the end of the name that fits. |
| R-PE-005 | U | The system shall show file names, entry values, findings, the JSON view and the paste buffer in the Patch Editor as plain text, never as markup. |

#### S10.2 · Choosing and loading a document (CTX-PE-DOC)

Reading the file, the load status and the finding lines are S8's (R-CHG-001.19 … .21); symbol entries read with the loaded A2L are S8's R-CHG-SYM.9.

| Id | Form | Requirement |
|---|---|---|
| R-PATCH-DOC-DROPDOWN-001.1 | When | When the Patch Editor is opened, or a Save or a Refresh ends, the system shall fill the File dropdown with the change list. |
| R-PATCH-DOC-DROPDOWN-001.2 | If | If the change home holds no change document, then the system shall show the dropdown with its prompt `Change files in patches/` and no option. |
| R-PATCH-DOC-DROPDOWN-001.3 | When | When the operator picks a file in the dropdown, the system shall load it as the document. |
| R-PATCH-DOC-DROPDOWN-001.4 | If | If the picked file is a link or lies outside its folder, then the system shall refuse it with the status `Patch Editor: change file '<name>' is outside the patches folder — not loaded.` |
| R-TUI-054.1 | U | The system shall show the path input placeholder `or type a path to the same change-set JSON (alternative to the patches/ dropdown)`. |
| R-PE-010 | When | When the operator presses Load, the system shall load the file the path input names as the document (S8 reader). |
| R-PE-011 | If | If the path input is empty when Load acts, then the system shall show the status `Patch Editor: enter a change-file path to load.` |
| R-TUI-052.1 | When | When the operator presses Refresh, the system shall fill the File dropdown with the change list. |
| R-TUI-052.2 | When | When the operator presses Refresh, the system shall keep the document as it is. |
| R-TUI-052.3 | When | When the operator presses Refresh, the system shall show the status `Patch Editor: file list refreshed.` |
| R-PE-015 | If | If the operator presses Load while the dirty flag is set, then the system shall ask with the unsaved-changes popup before it loads. |
| R-PE-012 | When | When the system shows the unsaved-changes popup, the system shall title it `Unsaved changes will be lost`. |
| R-PE-013 | When | When the system shows the unsaved-changes popup, the system shall show the text `The change editor and the text editor carry unsaved changes. Loading a new document replaces them.` |
| R-PE-014 | When | When the system shows the unsaved-changes popup, the system shall offer the buttons `Accept loss and load` and `Cancel` (focus and Esc: S7.1). |
| R-PE-016 | If | If the operator picks a file in the dropdown while the dirty flag is set, then the system shall ask with the unsaved-changes popup before it loads. |
| R-PE-017 | When | When the operator accepts the loss in the unsaved-changes popup, the system shall load the file the operator asked for. |
| R-PE-018 | When | When the operator cancels the unsaved-changes popup, the system shall keep the document and the dirty flag. |
| R-PE-019 | When | When the operator cancels the unsaved-changes popup, the system shall show the status `Patch Editor: load cancelled — changes kept.` |
| R-PE-019a | When | When the operator cancels the unsaved-changes popup that a dropdown pick opened, the system shall clear the dropdown's choice. |

#### S10.3 · Entries (CTX-PE-INPUT)

| Id | Form | Requirement |
|---|---|---|
| R-PE-020 | U | The system shall show the placeholders of CTX-PE-INPUT in the Address, String and Bytes fields. |
| R-PE-021 | When | When the operator presses Add, the system shall append the built entry at the Address field's address to the document. |
| R-PE-022 | When | When an Add succeeds, the system shall show the status `Patch Editor: entry added.` |
| R-PE-023 | If | If an entry already declares the Address field's address, then the system shall refuse the Add with the status `Patch Editor: an entry at address 0x<X> already exists - use Edit`. |
| R-PE-024 | When | When the operator presses Edit, the system shall replace the first entry declared at the Address field's address with the built entry. |
| R-PE-025 | When | When an Edit succeeds, the system shall show the status `Patch Editor: entry updated.` |
| R-PE-026 | When | When the operator presses Remove, the system shall remove the first entry declared at the Address field's address. |
| R-PE-027 | When | When a Remove succeeds, the system shall show the status `Patch Editor: entry removed.` |
| R-PE-028 | If | If no entry declares the Address field's address, then the system shall refuse the Edit or Remove with the status `Patch Editor: no change entry at address 0x<X>`. |
| R-PE-029 | If | If the Address field is empty, then the system shall refuse the action with the status `Patch Editor: memory address must not be empty`. |
| R-PE-030 | If | If the Address field is not empty and does not follow CTX-PE-INPUT, then the system shall refuse the action with the status `Patch Editor: bad address '<text>' - use 0x and hex digits, or decimal digits`. |
| R-PE-031 | If | If a Bytes token is not 1–2 hex digits with an optional `0x`, then the system shall refuse the action with the status `Patch Editor: invalid byte token '<token>' - every token is 1-2 hex digits with an optional 0x prefix; decimals are not accepted`. |
| R-PE-032 | If | If the String and Bytes fields are both empty, then the system shall refuse the Add or Edit with the status `Patch Editor: enter a string value or a run of new bytes`. |
| R-PE-033 | If | If the String text does not encode in the document's encoding, then the system shall refuse the Add or Edit with the status `Patch Editor: string value does not encode under '<encoding>': <reason>`. |
| R-PE-034 | When | When the document changes through Add, Edit, Remove, Parse pasted, undo, redo or a per-entry JSON edit, the system shall set the dirty flag. |
| R-PE-035 | If | If an Add, Edit or Remove is refused, then the system shall keep the dirty flag as it was. |
| R-PE-036 | When | When the operator types in the paste buffer, the system shall set the dirty flag. |
| R-PE-037 | When | When a Save or a load succeeds, the system shall clear the dirty flag. |

**(from batch-100 HLR-167: LLR-167.8, LED .72, LED .73)** Save project and its outcome are S11's; these rows state only what it does to the dirty flag.

| Id | Form | Requirement |
|---|---|---|
| R-PE-038 | When | When a Save project places the Patch Editor's draft document in the project and the paste buffer holds no unparsed paste text, the system shall clear the dirty flag. |
| R-PE-039.1 | If | If a Save project is refused or rolled back, then the system shall keep the dirty flag as it was. |
| R-PE-039.2 | If | If a Save project cannot write the Patch Editor's draft document, then the system shall keep the dirty flag as it was. |
| R-PE-039.3 | If | If the Patch Editor's document is file-backed when a Save project ends, then the system shall keep the dirty flag as it was. |
| R-PE-039.4 | If | If the paste buffer holds unparsed paste text when a Save project ends, then the system shall keep the dirty flag as it was. |

#### S10.4 · Ledger, findings and tally (CTX-PE-LEDGER)

| Id | Form | Requirement |
|---|---|---|
| R-CHG-004.1 | U | The system shall edit one change document at a time in the Patch Editor. |
| R-PE-040 | U | The system shall show one ledger row per entry, in document order. |
| R-PE-041 | U | The system shall show the ledger subtitle of CTX-PE-LEDGER. |
| R-PE-042 | U | The system shall show every ledger address in full. |
| R-PE-043 | If | If a Value / bytes, Status or Linkage cell is wider than its column, then the system shall show its start and one `…`. |
| R-PE-044 | If | If the document has no entry and no finding, then the system shall show the ledger line `No entries yet: Add one, paste a change-set or Load a file.` |
| R-PE-045 | If | If the document has no entry and has findings, then the system shall show the ledger line `Refused: <first finding line>`. |
| R-CHG-004.2 | When | When a Patch Editor action ends, the system shall show the document's findings list on the Checks tab. |
| R-CHG-004.3 | While | While the document has no finding, the system shall show no findings count and no findings line. |
| R-CHG-004.4 | U | The system shall mark the Status of an entry with ` / fault` while an ERROR finding names its address. |
| R-PE-046 | U | The system shall show the tally of CTX-PE-LEDGER at the foot of the Inspector tab. |

#### S10.5 · The before → after strip (CTX-PE-STRIP)

| Id | Form | Requirement |
|---|---|---|
| R-PE-050 | When | When the operator highlights a ledger row, the system shall show the strip rows of that entry. |
| R-PE-051 | U | The system shall show on the `was` lines the image bytes as they were before any apply (S8). |
| R-PE-052 | U | The system shall show on the `now` lines the bytes the entry writes, and the image byte at every place outside the entry. |
| R-PE-053 | U | The system shall build strip rows of the row width. |
| R-PE-054 | If | If an entry needs more than 8 strip rows, then the system shall show the first 8 rows and the line `showing <n> of <m> bytes`. |
| R-PE-055 | U | The system shall close the strip with its summary line. |
| R-PE-056 | U | The system shall show each changed byte on the `now` line, and a non-zero changed count, in bold patch teal. |
| R-PE-057 | If | If an address of a strip row has no image byte, then the system shall show `--` for it. |
| R-PE-058 | If | If the document has no entry, then the system shall show the strip line `No entry yet: Add one or Load a file.` |
| R-PE-059 | If | If no ledger row is highlighted, then the system shall show the strip line `Select a ledger row to see its bytes.` |
| R-PE-060 | If | If no image is loaded, then the system shall show the strip line `No image loaded: ^l loads one.` |

#### S10.6 · The JSON tab: view, paste buffer, Edit JSON (CTX-PE-JSON)

| Id | Form | Requirement |
|---|---|---|
| R-PE-070 | When | When the document changes, the system shall show its JSON (S8 wire form) in the read-only view of the JSON tab. |
| R-PE-071 | If | If the document's JSON equals the JSON shown, then the system shall keep the view's text, cursor, scroll and stamp. |
| R-PE-072 | If | If the document's JSON is longer than 5000 lines, then the system shall show its first 5000 lines and the line `showing 5000 of <N> lines`. |
| R-PE-073 | While | While no document has been shown, the system shall show `No document yet: Load, paste or Add.` in the JSON view. |
| R-PE-074 | When | When the JSON view or the dirty flag changes, the system shall show the JSON stamp above the view. |
| R-PE-075 | U | The system shall show the heading `LOADED DOCUMENT · read-only` above the JSON view. |
| R-PATCH-PASTE-001.1 | When | When the Patch Editor opens, the system shall fill the paste buffer with the example. |
| R-PATCH-PASTE-001.2 | While | While the paste buffer equals the example, the system shall show the paste heading `PASTE BUFFER · example`. |
| R-PATCH-PASTE-001.3 | While | While the paste buffer differs from the example, the system shall show the paste heading `PASTE BUFFER · editable`. |
| R-PATCH-PASTE-001.4 | When | When the operator presses Parse pasted, the system shall replace the document with the document the paste buffer holds (S8 R-CHG-001.1). |
| R-PATCH-PASTE-001.5 | If | If the paste buffer text carries an ERROR finding when Parse pasted acts, then the system shall keep the document as it is. |
| R-PATCH-PASTE-001.7 | U | The system shall show the paste buffer text literally, with no markup applied. |
| R-PATCH-PASTE-001.8 | U | The system shall colour the paste buffer's JSON with the JSON hues. |
| R-PATCH-PASTE-001.9 | U | The system shall show the paste gauge beside the paste heading. |
| R-PATCH-PASTE-001.10 | While | While the paste buffer holds 75 % to under 100 % of its cap, the system shall show the gauge's used figure in magenta. |
| R-PATCH-PASTE-001.11 | While | While the paste buffer holds 100 % of its cap or more, the system shall show the gauge's used figure in bold magenta. |
| R-TUI-046.1 | When | When the operator opens the JSON tab, the system shall show the first line of the paste buffer without scrolling. |
| R-PATCH-WRITE-REUSE-001 | U | The system shall apply, save back and name the save-back of a pasted document exactly as for the same document loaded from a file. |
| R-TUI-053.1 | When | When the operator presses Edit JSON under the paste buffer, the system shall open the change-set JSON popup (S7) with the paste buffer text. |
| R-TUI-053.2 | When | When the operator confirms valid text in the change-set JSON popup, the system shall put the text in the paste buffer and act as Parse pasted. |
| R-TUI-053.3 | If | If the confirmed popup text carries an ERROR finding, then the system shall keep the document and show the status `Edit JSON refused: <kind> text carries <n> error(s) — the document is unchanged.` |
| R-TUI-053.4 | When | When the operator cancels the change-set JSON popup, the system shall keep the document and the paste buffer as they are. |
| R-TUI-053.5 | While | While the document is file-backed, the system shall disable Edit JSON under the paste buffer. |
| R-TUI-053.6 | If | If the change-set JSON popup is requested for a file-backed document, then the system shall refuse it with the status `Patch Editor: Edit JSON is available only for a pasted change-set, not a file-loaded document.` |
| R-TUI-053.7 | When | When the system shows the change-set JSON popup, the system shall title it `Edit change-set JSON:`. |
| R-TUI-053.8 | When | When the system shows the change-set JSON popup, the system shall offer the buttons `Confirm` and `Cancel` (focus and Esc: S7.1). |

#### S10.7 · History and per-entry JSON (CTX-PE-DOC)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-057.1 | When | When Add, Edit, Remove, a load, Parse pasted or a per-entry JSON edit changes the document, the system shall first keep a copy of the document as an undo step. |
| R-TUI-057.2 | If | If the history holds 20 undo steps when a new one is kept, then the system shall drop the oldest. |
| R-TUI-057.3 | When | When the system keeps a new undo step, the system shall drop every redo step. |
| R-TUI-057.4 | When | When the operator presses Undo or ctrl+z, the system shall restore the document of the latest undo step. |
| R-TUI-057.5 | When | When the operator presses Redo or ctrl+y, the system shall restore the document of the latest redo step. |
| R-TUI-057.6 | If | If there is no step in the asked direction, then the system shall keep the document as it is. |
| R-TUI-057.7 | While | While the Patch Editor is not shown, the system shall ignore ctrl+z and ctrl+y as history keys. |
| R-TUI-057.8 | U | The system shall keep Undo, Redo and their keys enabled for every document. |
| R-TUI-057.9 | When | When the history changes, the system shall show the history strip above Undo and Redo. |
| R-TUI-058.1 | When | When the operator presses Edit JSON in the Inspector tab, the system shall open the entry JSON popup (S7) with the wire JSON (S8) of the highlighted entry only. |
| R-TUI-058.2 | When | When the operator confirms the entry JSON popup with text that holds exactly one valid entry, the system shall replace only the highlighted entry with it. |
| R-TUI-058.3 | If | If the confirmed entry text is not exactly one valid entry, then the system shall keep the document and show the status `Patch Editor: entry edit rejected - see findings.` |
| R-TUI-058.4 | When | When a per-entry edit succeeds, the system shall show the status `Patch Editor: entry at 0x<X> updated.` |
| R-TUI-058.5 | If | If the ledger has no row, then the system shall ignore Edit JSON in the Inspector tab. |
| R-TUI-058.6 | U | The system shall keep the per-entry Edit JSON enabled for every document. |
| R-TUI-058.7 | When | When the system shows the entry JSON popup, the system shall title it `Edit entry JSON:`. |
| R-TUI-058.8 | When | When the system shows the entry JSON popup, the system shall offer the buttons `Confirm` and `Cancel` (focus and Esc: S7.1). |

#### S10.8 · Validate, Apply, Save, save-back (CTX-PE)

S8 owns what these controls do: Validate (R-CHG-VAL.1 … .4), the apply and its status (R-CHG-002), the save-back prompt with its suggested name, width and write (R-CHG-003, R-HEX-VERIFY-002.3, R-S19-WIDTH-001), and Save with its folder, name and status (R-PATCH-SAVE-FOLDER-001). S10 keeps the controls and what the editor shows. The before/after report is S14's.

| Id | Form | Requirement |
|---|---|---|
| R-PE-080 | U | The system shall label the apply button `Apply loaded changes`. |
| R-PE-081 | When | When the operator presses Apply loaded changes, the system shall apply the document to the loaded image (S8). |
| R-PE-093 | When | When a Save succeeds, the system shall make the written file the document's source. |
| R-TUI-049.1 | When | When a save-back succeeds, the system shall show the before/after control. |
| R-TUI-049.2 | When | When the operator presses Write before/after report, the system shall write the before/after report as the `b` key does (S14 R-BEFORE-AFTER-REPORT-001.2). |
| R-TUI-049.3 | When | When the document is replaced by a load, a paste, undo or redo, the system shall hide the before/after control and the save-back prompt. |

**(from batch-100 HLR-177a: LLR-177.3e; E3 S12b-04)** The busy line, its text and the end of the refusals are S6's.

| Id | Form | Requirement |
|---|---|---|
| R-PE-110 | While | While a session action runs, the system shall refuse Add, Edit, Remove, Load, a dropdown pick, Refresh, Parse pasted, Validate, Apply loaded changes, Save, Run checks, Execute scope, Undo and Redo (buttons, Ctrl+Z and Ctrl+Y), Write file, both Edit JSON popups and their results, and the accept of the unsaved-changes popup. |
| R-PE-111 | While | While a project load runs, the system shall make the paste buffer read-only. |

#### S10.9 · Checks and the execution scope (CTX-PE)

The check run and its display are S9 (S9.1, S9.2); running a scope is S11.

| Id | Form | Requirement |
|---|---|---|
| R-PATCH-CHECKS-CLARITY-001.1 | When | When the operator presses Run checks, the system shall run the document as a check document against the loaded image (S9.1). |
| R-PATCH-CHECKS-CLARITY-001.2 | U | The system shall show under Run checks the help text `Checks: runs the loaded change document's checks against the loaded image. Needs kind 'check' (a change-set cannot be checked). Uncheckable rows name their reason (declaration fault, partial/outside range, or no image); healthy entries are still checked.` |
| R-PE-100 | When | When the operator presses the scope button, the system shall move to the next scope label in cycle order and label the button `Scope: <label>`. |
| R-PE-101 | When | When the scope changes, the system shall show the scope line `Scope <label>`. |
| R-PE-102 | When | When the operator presses Execute scope, the system shall run the document over the variants of the shown scope (S11.13). |



<a id="s11"></a>

## S11 · Projects, variants & manifest

### Context notes (informative)

#### CTX-PROJECT · Projects and variants (S11.1, S11.6 … S11.8)

```text
project          A folder directly in the work area (S5 CTX-WORKAREA) that is not a
                 reserved home, whose name does not end in a dot or a space, that is
                 not a link and resolves inside the work area, and that holds a
                 project.json that is a regular file or at least one project file.
project name     The project folder's name.
reserved home    temp, patches, templates, logs, crc, flows, flowsets, splits,
                 reports; compared ignoring case.
project file     A regular file directly in the project folder, not a link, whose kind
                 (S5 CTX-FILES) is S19, Intel HEX, MAC or A2L.
data file        A project file of kind S19, Intel HEX or MAC.
variant          An S19 or Intel HEX project file.
A2L-only project A project with one A2L file and no data file.
variant order    By file name ignoring case, then by file name.
variant id       The variant's file name without its last extension; the full file
                 name when two variants share that stem (fw.s19 and fw.hex).
active variant   The variant whose image the session shows.
recorded variant The variant that project.json names as active_variant.
readable image   A variant file that reads as an S19 or Intel HEX image with at least
                 one data byte.
next valid       Starting at the recorded variant (at the first variant when the
variant          recorded one is not a variant of the project) and going on in
                 variant order, wrapping to the first: the first variant that is a
                 readable image.
open project     The project the session last loaded or saved; none at start.
project homes    patches/ (change documents), checks/ (check documents), templates/
                 (CRC templates). Other subfolders (flows/, flowsets/, reports/,
                 splits/, crc/) belong to other screens.
project document A .json file other than project.json, directly in the project
                 folder, in patches/ or in checks/; named by its entry (CTX-MANIFEST).
session state    The loaded primary, MAC and A2L; the Patch Editor document with its
                 undo history; the declared regions; the last comparison and check
                 spec; the last flow run; the last execution; the report filter; the
                 CRC template record; the A2L and MAC view state; the issue list.
count words      In texts below, "<n> entries" stands for "1 entry" when n is 1; the
                 same for files, problems, variants and bytes.
painted name     As S7 CTX-LOADDLG defines it (the same rule paints project names):
                 the characters of the Unicode categories Cc, Cf, Zl and Zp
                 removed, each unpaired surrogate replaced by U+FFFD, clipped to
                 120 characters.
painted list     Painted names joined by ", "; after the 10th name, ", and <k> more"
                 (k: the names not shown).
```

#### CTX-SAVE · Saving a project (S11.2 … S11.5, S11.14)

```text
Save dialog      The title "Project name"; the name box (placeholder "letters,
                 digits, - and _"); the target line; the summary; when the open
                 project has variants and the dialog has documents to offer,
                 "Project-wide batch files (.json):" with the batch list and one
                 "Assign files to '<variant id>':" list per variant; the buttons
                 "Save (alt+s)" and "Cancel (esc)".
confirm Save     Pressing Save, alt+s, or Enter in the name box.
typed name       The text in the name box.
clean name       The typed name without the whitespace around it, keeping only
                 letters and digits (any script), - and _.
device name      A name whose part before the first dot, with trailing spaces and
                 dots removed and the digits ¹ ² ³ read as 1 2 3, is CON, PRN, AUX,
                 NUL, CONIN$, CONOUT$, COM0-COM9 or LPT0-LPT9, ignoring case.
name limit       64 characters of clean name.
path limit       length of the work-area path + 1 + length of the clean name + 53
                 must be at most 259 (53 is the longest file name a project later
                 receives, a before/after report).
save target      <work area>/<clean name>; when the clean name is the open project's
                 name ignoring case and no folder has exactly the clean name, the
                 open project's folder under its own spelling.
target line      <painted clean name> — <target kind>
target kind      new folder                         the save target does not exist
                 updates the open project           it is the open project's folder
                 merges into an existing project    it is another folder that holds
                                                    a project
                 new project in an existing folder  it is a folder that holds no
                                                    project
save as          A save to a new folder while a project is open.
merge            A save whose target kind is "merges into an existing project".
session document The change or check document open in the Patch Editor (S10) when
                 the save starts.
used document    The session document, when its file is outside the project folder.
used template    The CRC template last loaded in the CRC Designer (S13), when its
                 file is outside the project folder.
gather finding   GATHER-SOURCE-MISSING  warning  a used document or template no
                                                 longer exists
                 GATHER-CONTAINMENT     warning  a project home failed the work-area
                                                 checks, or the copy failed
patched image    The Patch Editor's change document applied again to the source's
                 data (S8).
saved image      The patched image when it differs from the source's data;
                 otherwise the source file.
image description
                 Saved image is the patched image:
                   <source file name> + <n> change entries, <k> applied by this save
                   n: entries the patched image carries; k: of those, the entries no
                   apply had written before the save.
                 Otherwise: <source file name> unchanged copy
image clause     Empty when the saved image is the source file; otherwise
                  — <image description>
save plan        What the save will write, decided before anything is written: the
                 save target and its target kind; one row per file the save writes
                 or keeps (the saved image, the MAC, the A2L, the session document,
                 and for a save as each top-level file it copies); one row per
                 sub-folder a save as copies; the links a save as skips; one row for
                 project.json. Or the refusal text of the first failed save check.
                 The gather of S11.4 (used template, composition documents) is
                 outside the plan.
action word      new      the save writes the file
                 keep     the folder already holds the file with the same content;
                          nothing is written
                 merge    project.json of a merge, rewritten
                 rewrite  project.json of another existing target, rewritten
plan file row    <label> <landing> — <action word>; when the source's name differs
                 from the landing: <label> <source file name> → <landing> — <action
                 word>. label: image · MAC · A2L · document · file; landing: the path
                 relative to the save target. Names are painted names.
summary rows     In this order:
                   the open project's folder name, when a save as finds it gone;
                   the dropped-document line of R-PROJ-DOC.13;
                   the image description, while a data file is loaded;
                   the pending line;
                   one plan file row per file row of the save plan;
                   one sub-folder row per sub-folder a save as copies;
                   the links row;
                   the active-variant row;
                   the project.json row.
pending line     unsaved changes in <image file name>
sub-folder row   folder <name>/ (<n> files) — new
links row        links or junctions not copied: <painted list>
active-variant   active variant <variant id> (before: <recorded variant id, or
row              none recorded>)
project.json row project.json — <action word>; when the target's project.json has a
                 keep reason, followed by
                 ; the current one <keep reason>, a copy is kept as
                 project.json.previous-<UTC>
keep reason      is damaged · was written by a newer version · was written by an
                 unknown version · holds keys this version does not know · holds a
                 change document path this version cannot use
backup name      project.json.previous-<YYYYMMDD>T<HHMMSS>Z (UTC); -1 … -9 is added
                 when that name is taken.
copy cap         256 MiB per file (the copy limit of S5).
save size        For a save to a new folder: every file the save writes or copies,
                 each rounded up to a multiple of 4 096 bytes, plus 65 536 bytes for
                 project.json and the folders. Nothing reached through a link counts.
refusal text     The text of a failed save check, listed below. The Save dialog
                 paints it as it is; a status line puts "Project NOT saved: " before
                 it (C-1 excepted).
save checks      In this order, with the refusal text of each:
  C-1   nothing is loaded
          (status only) Nothing to save: load a data file or A2L first.
  C-2   the clean name is empty
          name is empty — type a project name.
  C-3   the typed name, a part of it between / or \, or the clean name is a device
        name
          '<painted typed name>' is a device name — choose another name.
  C-4   the clean name is a reserved home
          '<clean name>' is a reserved name — choose another name.
  C-5   the clean name is longer than the name limit
          name too long (at most 64 characters) — shorten the name.
  C-6   the path limit is broken
          path too long — shorten the name.
  C-13  the work area cannot be listed
          the work area could not be read — check that the folder can be opened,
          then save again.
  C-7   a project that is not open has the clean name ignoring case, and the typed
        name differs from that project's name
          '<painted typed name>' is already a project as '<painted project name>'
          — choose another name.
  C-8   a loaded file no longer exists
          source file missing: <painted file name> — reload it or remove it from
          the project.
  C-12  a loaded file cannot be read
          <painted file name> could not be read: <reason> — check that the file
          can be opened, then save again. Nothing written.
  C-10  the change document holds blocked entries (S8)
          <n> blocked entries (<addresses>) — fix them in the Patch Editor.
          (each address 0x and 8 hex digits, joined by ", ")
  C-11  the saved image would be patched, and the image is neither S19 nor
        Intel HEX
          a patched <image kind> image cannot be written — only S19 and HEX images
          carry change entries.
  C-9   the save target exists and is a link
          '<clean name>' is a link or junction — choose another name.
  C-14  the save target cannot be inspected
          '<painted clean name>' could not be read — check that the folder can be
          opened, then save again.
  C-15  save as: the open project's folder is a link, cannot be inspected or is
        outside the work area
          the open project folder '<painted folder name>' <is a link or junction ·
          could not be read · is outside the work area> — pick a project in the
          list.
  C-16  save as: over 2 000 files to copy, a tree of over 10 000 entries, or a
        folder over 32 levels deep
          '<painted folder name>' has too many files to copy (over 2 000) — move
          files out of the project, then save again.
          '<painted folder name>' has too many files to copy (over 10 000 entries)
          — move files out of the project, then save again.
          '<painted folder name>' has folders nested too deep (over 32 levels) —
          move files out of the project, then save again.
  C-17  save as: a sub-folder cannot be listed or an entry cannot be classified
          <painted list of entries> could not be read — check that they can be
          opened, then save again.
  C-18  the target holds a MAC file and the session's MAC file is another file
          '<painted target name>' already has a MAC file (<painted list>) —
          choose another name.
  C-19  the target holds an A2L file that is neither the session's A2L file nor a
        file of the same name with the same bytes
          '<painted target name>' already has an A2L file (<painted list>) —
          choose another name.
  C-20  a file of the session is larger than the copy cap
          <painted file name> is too large to copy (over 256 MiB) — a project
          cannot hold files over 256 MiB.
  C-21  save as: a file to copy is larger than the copy cap
          <painted path> is too large to copy (over 256 MiB) — move it out of the
          project folder, then save again.
  C-22  merge: the target holds more than one MAC or more than one A2L file
          Project already has more than one MAC file.
          Project already has more than one A2L file.
  C-23  save to a new folder: the save size is larger than the free space of the
        work area's volume
          not enough free space (needs <n> bytes, <m> free) — free disk space or
          remove files from the project.
  C-24  save to a new folder: the free space cannot be read
          could not save — the free space of the work area could not be read —
          check the folder.
created by the save   A file or folder that did not exist before the save started
                 and that the save wrote.
document reasons Why the session document is not recorded (R-PROJ-DOC.10):
                 it is in the project's <home> folder, but its name is not one
                 project.json records · it is in the project but not in its <home>
                 folder · its file is missing or is a link · the file could not be
                 read · it could not be placed in the project's <home> folder
drop reasons     Why a carried active_document is dropped (R-PROJ-DOC.13):
                 the file is missing · the file is a link · the file is not a change
                 or check document the app can read
```

#### CTX-MANIFEST · project.json (S11.9 … S11.12)

```text
manifest         <project folder>/project.json: UTF-8 JSON text, one object, indented
                 by 2 spaces, keys in this order:
  schema_version    1. Version 1 is the only version.
  active_variant    The active variant's id; null when the project has no variant.
  batch             Array of entries: documents for every in-scope variant (CTX-EXEC).
  assignments       Object: variant id -> array of entries for that variant.
  declared_regions  Optional. Array of {"name": text, "start": number, "end": number}.
  gathered          Optional. Object: patches, checks, templates -> sorted array of
                    the entries gathered into that home.
  files             Optional. Object: entry of a recorded file -> {"size": number,
                    "sha256": 64 lowercase hex digits}.
  derived_from      Optional. Object: entry of a patched variant -> {"base": the
                    base's file name, "sha256": the base's SHA-256, "differ": the
                    number of bytes that differ from the base}.
  active_document   Optional. The entry of the session document:
                    patches/<name>.json or checks/<name>.json.
recorded file    A project file directly in the project folder with a data or A2L
                 suffix, and the file active_document names.
entry            A path relative to the project folder, written with / separators.
unsafe entry     An entry that is empty or not a string; holds a NUL character or a
                 ':'; has a drive or a root (C:\x, /x); has a part that ends in a dot
                 or a space or is a device name (CTX-SAVE); is longer than 32 767
                 characters or has more than 32 parts; resolves outside the project
                 folder; or passes through a link inside it.
context          Where an entry sits, as messages name it: batch ·
                 assignments['<variant id>'] · gathered['<home>'] · files ·
                 derived_from · active_document.
region rules     name: text, not empty once control characters and terminal escape
                 sequences are removed; start: whole number, at least 0; end: whole
                 number, at least start.
read cap         1 MiB (1,048,576 bytes).
entry cap        1 000 entries in each of batch, declared_regions, files and
                 derived_from; 1 000 keys and 1 000 entries in total in each of
                 assignments and gathered.
finding bound    At most 100 skipped-entry findings are recorded one by one; the rest
                 are counted in one finding.
manifest finding A finding (S3 CTX-ISSUE) with artifact "manifest":
  MANIFEST-SIZE-CAP           error    the file is over the read cap
  MANIFEST-JSON-PARSE         error    the file is not readable, well-formed JSON
  MANIFEST-BAD-STRUCTURE      error    a key or an entry has the wrong type, or a
                                       key is over the entry cap
  MANIFEST-PATH-ESCAPE        error    an unsafe entry, on read
  MANIFEST-WRITE-ESCAPE       error    an unsafe entry, on write
  MANIFEST-WRITE-CONTAINMENT  warning  project.json is outside the work area, passes
                                       through a link, or cannot be written
damaged manifest A manifest whose read gives MANIFEST-SIZE-CAP or MANIFEST-JSON-PARSE,
                 whose top level is not an object, or with a key over the entry cap.
carried records  batch, assignments, declared_regions, gathered, derived_from and
                 active_document of a manifest that is not damaged, as entries
                 relative to the project folder.
rewrite refusal  A reason not to rewrite an existing project.json: a keep reason
                 (CTX-SAVE), or "holds entries that were skipped".
finding line     [<code>] <severity>: <message>      (severity: error, warning)
```

#### CTX-LOADRES · The result of a project load (S11.6, S11.15, S11.16)

```text
problem          One finding about one file of a loaded project: a problem word, the
                 file, a reason in user terms and a next step.
problem words    In precedence order, highest first:
                   manifest damaged · no project.json    (same rank)
                   missing
                   not readable
                   changed on disk
                   not recorded
                   no digests saved
next step        manifest damaged   Save project rewrites it
                 no project.json    Save project writes it
                 missing            restore the file, or Save project to drop it
                 not readable       replace the file, or Save project to drop it
                 changed on disk    Save project records the new state
                 not recorded       Save project records it
                 no digests saved   Save project records them
                 Exceptions: the project's A2L left out (link or over the copy
                 cap): replace the A2L file, then Load again · the active document
                 too large to reopen: open it from the Patch Editor (it can take a
                 while) · the active document that could not be read now: check
                 that the file can be opened, then Load again.
problem reasons  manifest damaged: too large to read - defaults used · not valid JSON
                   - defaults used · not a manifest object - defaults used · too
                   many recorded entries - defaults used · a recorded entry has the
                   wrong shape · a file path points outside the project · a file
                   path is not a plain name in the project · a file path goes
                   through a link or junction
                 missing: recorded in project.json, not on disk · recorded as the
                   active variant
                 not readable: not a regular file · the file cannot be read · not
                   an S19 or HEX file · 0 data bytes · link or junction · too large
                   to open · could not be read · the file is a link and is not
                   opened · too large to reopen · not a change or check document
                   the app can read · the recorded change document path is not one
                   the app can use
                 changed on disk: saved <n> B, now <m> B · same size (<n> B),
                   different content
                 not recorded: in the project, not in project.json
load reason      recorded          recorded as the active variant (the latest saved)
                 none recorded     the first variant by name (the manifest records
                                   no active variant)
                 manifest damaged  the first variant by name (the manifest could
                                   not be read)
                 no project.json   the first variant by name (the project has no
                                   project.json)
                 next valid        the next valid variant (the recorded one is
                                   missing or not readable)
relation line    patched, <n> bytes differ from <base>
                   (files records a file named <base> with the recorded SHA-256)
                 patched from <base> (not in this project); <n> bytes differ from it
                   (otherwise)
load target      <opened variant file name> + <MAC file name>; one of the two when
                 the other is absent; (no image) when both are absent.
load position    variant <k> of <n> when an image opened (k: its place in variant
                 order); <n> variants otherwise.
file status      Loaded project '<project name>' -> <load target>
summary line     Loaded project '<project name>' -> <load target> - <load position>,
                 <p> problems - details: p
Load-result      Title: Project <project name> opened, followed by
panel              " with <p> problems" when p is not 0.
                 Summary grid: Opened <opened file name, or (no image)>; the load
                   reason; the relation line, when derived_from records the opened
                   variant; Variants <n> in the project; Others: one other variant
                   file name per line, followed by "   not readable" when it did not
                   read; MAC <file name, or (none)>; A2L <file name, or (none)>.
                 Heading: Problems found (the rest loaded) · No problems found.
                 One problem row per problem:
                   "  ! <problem word>: <file>  <reason> - <next step>"
                 Buttons: Select variant (v) · Close (esc).
problem bound    At most 102 problem rows; the rest are counted in one row:
                 "  ! more problems: <h> more files  not listed one by one - each has
                 one of the problems above"
```

#### CTX-EXEC · Executing over variants (S11.13)

```text
Execute controls The Patch Editor's "Execute over variants" row (S10): the Scope
                 button cycles active variant · all variants · per assignment;
                 "Execute scope" runs it. Status lines name the scope by its token:
                 active · all · assignments.
in-scope variants  active: the active variant · all: every variant · assignments:
                 every variant whose assignments list is not empty.
file list        For each in-scope variant, in this order:
                   the manifest names a file, scope active or all:
                     batch, then assignments[<variant id>]
                   the manifest names a file, scope assignments:
                     assignments[<variant id>]
                   no manifest, or a manifest that names no file (D11-25):
                     the Patch Editor's document
patched name     <variant id>-patched.s19 (S19 variant) · <variant id>-patched.hex
                 (Intel HEX variant)
```

---


### Requirements


#### S11.1 · Projects and their files (CTX-PROJECT)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-014.3 | U | The system shall accept a project with any number of variants. |
| R-TUI-014.1 | If | If a project folder holds more than one MAC file, then the system shall show the status `Project already has more than one MAC file.` |
| R-TUI-014.2 | If | If a project folder holds more than one A2L file, then the system shall show the status `Project already has more than one A2L file.` |
| R-TUI-014.4 | U | The system shall take as project files only the regular files directly in the project folder that are not links. |
| R-TUI-014.5 | U | The system shall give each variant the variant id of CTX-PROJECT. |
| R-TUI-014.6 | U | The system shall list a project's variants in variant order. |
| R-PROJ-CONTAIN.1 | U | The system shall write no byte outside the work area when it saves a project, saves back into the open project, adds a file to the open project or writes project.json. |

#### S11.2 · Save: dialog, name and target (CTX-SAVE)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-012.1 | When | When the operator presses `s` or Ctrl+S while a data file or an A2L file is loaded, the system shall open the Save dialog. |
| R-TUI-012.2 | When | When the operator presses Cancel or escape in the Save dialog, the system shall close the dialog without saving. |
| R-TUI-012.3 | If | If the operator confirms Save while the clean name is empty, then the system shall keep the Save dialog open. |
| R-TUI-012.4 | When | When the operator confirms Save, the system shall use the save target as the project folder. |
| R-TUI-012.5 | U | The system shall run the save checks of CTX-SAVE before it creates any folder. |
| R-TUI-012.6 | If | If a save fails more than one save check, then the system shall give the refusal text of the first one in check order. |
| R-TUI-012.7 | If | If check C-1 fails when the operator asks Save project, then the system shall show the status `Nothing to save: load a data file or A2L first.` |
| R-TUI-012.22 | If | If check C-1 fails when the operator asks Save project, then the system shall open no Save dialog. |
| R-TUI-012.8 | If | If check C-2 fails, then the system shall refuse the save with the refusal text `name is empty — type a project name.` |
| R-TUI-012.9 | If | If check C-3 fails, then the system shall refuse the save with the refusal text `'<painted typed name>' is a device name — choose another name.` |
| R-TUI-012.10 | If | If check C-4 fails, then the system shall refuse the save with the refusal text `'<clean name>' is a reserved name — choose another name.` |
| R-TUI-012.11 | If | If check C-5 fails, then the system shall refuse the save with the refusal text `name too long (at most 64 characters) — shorten the name.` |
| R-TUI-012.12 | If | If check C-6 fails, then the system shall refuse the save with the refusal text `path too long — shorten the name.` |
| R-TUI-012.13 | If | If check C-7 fails, then the system shall refuse the save with the refusal text `'<painted typed name>' is already a project as '<painted project name>' — choose another name.` |
| R-TUI-012.14 | If | If check C-8 fails, then the system shall refuse the save with the refusal text `source file missing: <painted file name> — reload it or remove it from the project.` |
| R-TUI-012.15 | If | If check C-9 fails, then the system shall refuse the save with the refusal text `'<clean name>' is a link or junction — choose another name.` |
| R-TUI-012.16 | If | If check C-10 fails, then the system shall refuse the save with the refusal text `<n> blocked entries (<addresses>) — fix them in the Patch Editor.`, each address as `0x` and 8 hex digits, joined by `, `. |
| R-TUI-012.17 | If | If check C-11 fails, then the system shall refuse the save with the refusal text `a patched <image kind> image cannot be written — only S19 and HEX images carry change entries.` |
| R-TUI-012.18 | If | If check C-12 fails, then the system shall refuse the save with the refusal text `<painted file name> could not be read: <reason> — check that the file can be opened, then save again. Nothing written.` |
| R-TUI-012.23 | If | If check C-13 fails, then the system shall refuse the save with the refusal text `the work area could not be read — check that the folder can be opened, then save again.` |
| R-TUI-012.24 | If | If check C-14 fails, then the system shall refuse the save with the refusal text `'<painted clean name>' could not be read — check that the folder can be opened, then save again.` |
| R-TUI-012.25 | If | If check C-15 fails, then the system shall refuse the save with the refusal text `the open project folder '<painted folder name>' <state> — pick a project in the list.`, the state being `is a link or junction`, `could not be read` or `is outside the work area`. |
| R-TUI-012.26 | If | If check C-16 fails, then the system shall refuse the save with the refusal text of C-16 for the limit it breaks. |
| R-TUI-012.27 | If | If check C-17 fails, then the system shall refuse the save with the refusal text `<painted list of entries> could not be read — check that they can be opened, then save again.` |
| R-TUI-012.28 | If | If check C-20 fails, then the system shall refuse the save with the refusal text `<painted file name> is too large to copy (over 256 MiB) — a project cannot hold files over 256 MiB.` |
| R-TUI-012.29 | If | If check C-21 fails, then the system shall refuse the save with the refusal text `<painted path> is too large to copy (over 256 MiB) — move it out of the project folder, then save again.` |
| R-TUI-012.30 | If | If check C-22 fails, then the system shall refuse the save with the refusal text of R-TUI-014.1 or R-TUI-014.2. |
| R-TUI-012.31 | If | If check C-23 fails, then the system shall refuse the save with the refusal text `not enough free space (needs <n> bytes, <m> free) — free disk space or remove files from the project.`, n being the save size. |
| R-TUI-012.32 | If | If check C-24 fails, then the system shall refuse the save with the refusal text `could not save — the free space of the work area could not be read — check the folder.` |
| R-TUI-012.19 | If | If a save that the Save dialog did not prepare fails check C-8, C-10, C-11, C-12, C-15 … C-23, then the system shall also show the refusal as an error notice titled `Project not saved`. |
| R-TUI-012.33 | If | If a save that the Save dialog did not prepare is refused, then the system shall show the status `Project NOT saved: <refusal text>`. |
| R-TUI-012.20 | If | If the typed name is the name of an existing project that is not open, then the system shall save into that project. |
| R-TUI-012.21 | If | If the clean name is the open project's name ignoring case and no folder has exactly the clean name, then the system shall save into the open project under its folder's spelling. |
| R-TUI-012.34 | If | If a save names a parent folder that is not the work area, then the system shall refuse the save with the status `Project NOT saved: <parent folder> is not the work area folder — choose the work area as the parent folder (<work area>).` |
| R-TUI-012.35 | If | If a save names a parent folder that does not exist, then the system shall show the status `Parent folder not found or not a directory.` |
| R-TUI-012.36 | When | When a save names the work area under another spelling as its parent folder, the system shall save into the work area. |

#### Save dialog (from batch-100 HLR-175, HLR-175a … HLR-175f)

| Id | Form | Requirement |
|---|---|---|
| R-SAVEDLG-1 | When | When the Save dialog opens, the system shall place the focus in the name box. |
| R-SAVEDLG-2 | While | While a project is open, the system shall open the Save dialog with the open project's name in the name box, all of it selected. |
| R-SAVEDLG-3 | U | The system shall put every printable key pressed in the name box into the name box. |
| R-SAVEDLG-4 | When | When the operator presses alt+s in the Save dialog or Enter in the name box, the system shall act as when Save is pressed. |
| R-SAVEDLG-5 | If | If the operator presses Ctrl+L, Ctrl+S, Ctrl+K or Ctrl+D while the Save dialog is open, then the system shall run no app action for that key. |
| R-SAVEDLG-6 | U | The system shall offer no choice of parent folder in the Save dialog. |
| R-SAVEDLG-7 | When | When the typed name changes, the system shall paint the target line for the new name. |
| R-SAVEDLG-8 | While | While the Save dialog is open, the system shall paint in the summary the summary rows of the save plan for the typed name. |
| R-SAVEDLG-9 | If | If the save for the typed name is refused, then the system shall paint its refusal text in the target line. |
| R-SAVEDLG-10 | If | If the save for the typed name is refused, then the system shall paint no summary row. |
| R-SAVEDLG-11 | If | If the operator confirms Save while the save for the typed name is refused or its plan differs from the painted plan, then the system shall keep the Save dialog open. |
| R-SAVEDLG-12 | If | If the operator confirms Save while the plan for the typed name differs from the painted plan, then the system shall paint the plan for the typed name. |
| R-SAVEDLG-13 | If | If the operator confirms Save while the plan for the typed name differs from the painted plan, then the system shall add the line `the summary changed — check it, then save again` to the target line. |
| R-SAVEDLG-14 | When | When the operator confirms Save while the painted plan is the plan for the typed name and is not refused, the system shall close the Save dialog. |
| R-SAVEDLG-15 | When | When the Save dialog closes on a confirmed Save, the system shall run the save of the painted plan. |
| R-SAVEDLG-16 | When | When the system runs the save of a painted plan, the system shall write exactly the files that the plan's rows name, besides the gather of S11.4. |
| R-SAVEDLG-17 | When | When the system runs a save that the Save dialog did not prepare, the system shall prepare the save plan for its name and run that plan. |
| R-SAVEDLG-18 | If | If a load lands while the Save dialog is open, then the system shall compute the next plan from the session after that load. |
| R-SAVEDLG-19 | While | While a data file is loaded, the system shall paint the image description as a summary row. |
| R-SAVEDLG-20 | While | While the session image differs from the image last loaded or saved, the system shall paint the pending line as a summary row. |
| R-SAVEDLG-21 | If | If the save plan skips links or junctions, then the system shall paint the links row. |
| R-SAVEDLG-22 | While | While the save plan is a merge with an image row, the system shall paint the active-variant row. |
| R-SAVEDLG-23 | If | If the target's project.json has a keep reason, then the system shall add the keep note of CTX-SAVE to the project.json row. |
| R-SAVEDLG-24 | When | When the save plan copies the open project's sub-folders, the system shall paint one sub-folder row per sub-folder with its file count. |
| R-SAVEDLG-25 | While | While the summary holds more rows than it shows, the system shall keep Save and Cancel visible. |
| R-SAVEDLG-26 | U | The system shall let the operator scroll the summary to its last row with the keyboard alone. |
| R-SAVEDLG-27 | U | The system shall paint each summary row on one line, ending a cut row with `…`. |
| R-SAVEDLG-28 | U | The system shall paint no internal decision id in the Save dialog. |

#### S11.3 · Save: what is written

| Id | Form | Requirement |
|---|---|---|
| R-PROJ-001.1 | When | When the system saves a project, the system shall place the saved image in the project folder. |
| R-PROJ-001.2 | When | When the system saves a project, the system shall place a copy of the session's MAC file in the project folder. |
| R-PROJ-001.3 | When | When the system saves a project, the system shall place a copy of the session's A2L file in the project folder. |
| R-PROJ-001.4 | If | If the project folder holds a file with the same content under the file's name or a numbered name (S5), then the system shall use that file and write nothing. |
| R-PROJ-001.5 | If | If the file's name is taken in the project folder by a different content, then the system shall place the file under the lowest free numbered name. |
| R-PROJ-001.11 | If | If check C-18 fails, then the system shall refuse the save with the refusal text `'<painted target name>' already has a MAC file (<painted list>) — choose another name.` |
| R-PROJ-001.12 | If | If check C-19 fails, then the system shall refuse the save with the refusal text `'<painted target name>' already has an A2L file (<painted list>) — choose another name.` |
| R-PROJ-001.6 | When | When the system saves a project, the system shall make the saved image's variant the active variant. |
| R-PROJ-001.7 | When | When the system saves a project, the system shall make it the open project. |
| R-PROJ-001.10 | When | When the system saves a project, the system shall write the manifest (S11.10). |
| R-PROJ-001.8 | When | When a save ends with a saved variant, the system shall show the status `Saved project to <project folder> (variant '<variant id>')<image clause>`. |
| R-PROJ-001.9 | If | If the saved project has no variant, then the system shall show the status `Saved project to <project folder><image clause>`. |
| R-PROJ-IMAGE.1 | If | If the Patch Editor's change document gives data that differ from the source's data, then the system shall save the patched image instead of a copy of the source. |
| R-PROJ-IMAGE.2 | If | If the Patch Editor holds a check document, then the system shall save a copy of the source. |
| R-PROJ-IMAGE.3 | If | If the change document gives the source's own data, then the system shall save a copy of the source. |
| R-PROJ-IMAGE.4 | When | When the system saves a patched image, the system shall name it as the source file with the extension `.s19` or `.hex` of its image kind. |
| R-PROJ-IMAGE.5 | When | When the system has saved a patched image, the system shall show the patched image in the session. |
| R-PROJ-IMAGE.6 | When | When the system has saved a patched image, the system shall show the verify result of S8's image save. |
| R-PROJ-IMAGE.7 | When | When the system saves a patched image, the system shall write it as S8.7 states, with 32 data bytes in each S19 data record. |
| R-PROJ-IMAGE.8 | When | When the system saves a patched S19 image whose source has an S0 record with data, the system shall use that data as header data (S8 CTX-SAVEBACK). |
| R-PROJ-IMAGE.9 | When | When the system saves a patched S19 image whose source has a terminator, the system shall write the address of the source's terminator in the terminator. |
| R-PROJ-IMAGE.10 | When | When the system has written a patched image, the system shall verify it as S8.8 states. |
| R-PROJ-IMAGE.11 | U | The system shall offer no choice of data bytes per record for Save project. |
| R-PROJ-IMAGE.12 | When | When a Save project completes, the system shall record the session image as last saved. |
| R-PROJ-IMAGE.13 | When | When the system has saved a patched image, the system shall record in derived_from the source file as the base of the saved variant. |
| R-PROJ-IMAGE.14 | If | If the system saves a copy of the source, then the system shall record no derived_from for it. |

#### Merge (from batch-100 HLR-164)

| Id | Form | Requirement |
|---|---|---|
| R-PROJ-MERGE.1 | When | When the system saves into a project that is not open, the system shall keep the target's variants. |
| R-PROJ-MERGE.2 | When | When the system saves into an existing project folder, the system shall copy none of the open project's sub-folders into it. |
| R-PROJ-MERGE.3 | When | When the system saves into an existing project folder, the system shall write into its project.json the target's carried records that the save does not set. |

#### S11.4 · Save: the gather (from S0 HLR-138)

| Id | Form | Requirement |
|---|---|---|
| R-PROJ-GATHER.1 | When | When the system saves a project, the system shall copy the used document into the project home of its kind: `patches/` for a change document, `checks/` for a check document. |
| R-PROJ-GATHER.2 | When | When the system saves a project, the system shall copy the used template into `templates/`. |
| R-PROJ-GATHER.3 | When | When the system gathers a file, the system shall leave the original unchanged. |
| R-PROJ-GATHER.4 | If | If the project home holds a file with the same content under the file's name or a numbered name, then the system shall use that file and write nothing. |
| R-PROJ-GATHER.5 | If | If the file's name is taken in the project home by a different content, then the system shall copy the file under the lowest free numbered name. |
| R-PROJ-GATHER.6 | If | If the used document no longer exists, then the system shall show the finding line `[GATHER-SOURCE-MISSING] warning: gather: active document <path> no longer exists — skipped`. |
| R-PROJ-GATHER.7 | If | If the used template no longer exists, then the system shall show the finding line `[GATHER-SOURCE-MISSING] warning: gather: active template <path> no longer exists — skipped`. |
| R-PROJ-GATHER.8 | If | If the copy of a used file fails, then the system shall show the finding line `[GATHER-CONTAINMENT] warning: gather: refused to copy <source> into <home>: <error type>: <reason>`. |
| R-PROJ-GATHER.9 | If | If a used file cannot be gathered, then the system shall go on with the save. |
| R-PROJ-GATHER.10 | If | If the system copies into the project a file whose name project.json cannot record, then the system shall show the status `<painted name> was copied but not recorded in project.json (<why>) — rename it in the common folder, select the new name, then Save project.`, why being `Windows reserves that name` for a device name and `the name is not one project.json records` otherwise. |
| R-PROJ-GATHER.11 | If | If more than 10 copied files are not recorded, then the system shall show the status `and <k> more files not recorded in project.json` after the first 10. |

#### The Patch Editor document (from batch-100 HLR-170, HLR-167)

| Id | Form | Requirement |
|---|---|---|
| R-PROJ-DOC.1 | When | When the system saves a project while the session document has no file and at least one entry, the system shall write that document as `changes.json` in the project home of its kind. |
| R-PROJ-DOC.2 | If | If that home already holds a different `changes.json`, then the system shall write the document under the lowest free numbered name (`changes_1.json` …). |
| R-PROJ-DOC.3 | If | If that home already holds a `changes.json` with the same content, then the system shall write no document. |
| R-PROJ-DOC.4 | If | If the session document has no file and no entry, then the system shall write no document. |
| R-PROJ-DOC.5 | When | When the save places the session document in the project home of its kind, the system shall record its entry as active_document. |
| R-PROJ-DOC.6 | If | If the session document's file is already in the project home of its kind, then the system shall record it as active_document without copying it. |
| R-PROJ-DOC.7 | If | If the session document cannot be written, then the system shall complete the save without it. |
| R-PROJ-DOC.8 | If | If the session document cannot be written, then the system shall show the status `Change document <name> was not saved into the project — the file could not be written; its entries stay in the Patch Editor`. |
| R-PROJ-DOC.9 | If | If the project home of the session document's kind is a link or outside the work area, then the system shall show the status `Change document changes.json was not saved into the project — the project's <home> folder is a link or is outside the work area; its entries stay in the Patch Editor`. |
| R-PROJ-DOC.10 | If | If the save records no session document for another reason, then the system shall show the status `Change document <name> was not recorded in the project — <document reason>`. |
| R-PROJ-DOC.11 | If | If a save into an existing project records no session document, then the system shall keep the target's active_document. |
| R-PROJ-DOC.12 | If | If the kept active_document's file is missing, is a link, or is not a change or check document the app can read, then the system shall drop the record. |
| R-PROJ-DOC.13 | If | If the system drops a kept active_document, then the system shall show the status `Change document record <entry> was dropped from project.json — <drop reason>`. |
| R-PROJ-DOC.14 | If | If the kept active_document's file cannot be read now, then the system shall show the status `Change document <entry> could not be read — it stays recorded; check that the file can be opened, then Load again`. |
| R-PROJ-DOC.15 | When | When a Save project writes the session document into the project, the system shall clear the Patch Editor's unsaved mark. |
| R-PROJ-DOC.16 | If | If a save leaves the Patch Editor's edits only in memory, then the system shall keep the Patch Editor's unsaved mark. |
| R-PROJ-DOC.17 | If | If the save records the session document's file as it is on disk while the Patch Editor holds unsaved edits of it, then the system shall show the status `Change document <name> has unsaved edits — the project records the file as it is on disk; save it from the Patch Editor to keep them`. |
| R-PROJ-DOC.18 | When | When the system loads a project whose project.json records an active document, the system shall open that document in the Patch Editor after the project's A2L is attached. |
| R-PROJ-DOC.19 | When | When the system reopens the recorded document, the system shall apply none of its entries. |
| R-PROJ-DOC.20 | When | When the system reopens the recorded document, the system shall leave the Patch Editor's unsaved mark clear. |
| R-PROJ-DOC.21 | If | If the recorded document is a link, is larger than 1 MiB, holds more than 1 000 entries, is not a change or check document the app can read, or cannot be read, then the system shall list it as a `not readable` problem. |
| R-PROJ-DOC.22 | If | If the recorded document is listed as a problem, then the system shall open no document in the Patch Editor. |

#### S11.5 · Save: failure after the folder exists

| Id | Form | Requirement |
|---|---|---|
| R-PROJ-ROLLBACK.1 | If | If a save fails after the system has created the project folder, then the system shall remove the project folder. |
| R-PROJ-ROLLBACK.2 | If | If a save fails, then the system shall remove every file and folder created by the save. |
| R-PROJ-ROLLBACK.3 | If | If a save fails, then the system shall keep every file and folder that existed before the save. |
| R-PROJ-ROLLBACK.4 | If | If a save fails after it has replaced project.json, then the system shall put the previous project.json back. |
| R-PROJ-ROLLBACK.5 | If | If a save fails, then the system shall keep the open project and its active variant as they were before the save. |
| R-PROJ-ROLLBACK.6 | If | If a save fails with an operating-system error, a locked file or a refused destination, then the system shall keep running. |
| R-PROJ-ROLLBACK.7 | If | If the patched image cannot be written, then the system shall show the status `Project NOT saved: could not save — the patched image was not written: <reason>`. |
| R-PROJ-ROLLBACK.8 | If | If a file lands at another place than the system predicted before the save, then the system shall show the status `Project NOT saved: the plan named <path> (<new or keep>) but the file landed at <path> (<new or keep>) — save again.` |
| R-PROJ-ROLLBACK.9 | If | If project.json cannot be written, then the system shall show the status `Project NOT saved: could not save — project.json was not written. check the folder.` |
| R-PROJ-ROLLBACK.10 | If | If a file of the save stays locked, then the system shall show the reason of S5 R-TUI-002.6 as the status. |
| R-PROJ-ROLLBACK.11 | If | If the work-area checks refuse a destination of the save, then the system shall show the status `Cannot save project: <reason>`. |
| R-PROJ-ROLLBACK.12 | If | If an operating-system error stops the save, then the system shall show the status `Project NOT saved: could not save — <error>. check the folder.` |
| R-PROJ-ROLLBACK.13 | If | If an operating-system error or a locked file stops the save, then the system shall also show the refusal as an error notice titled `Project not saved`. |
| R-PROJ-ROLLBACK.14 | If | If a failed save's rollback finds a file it wrote under a folder that is now a link, or a file that is no longer the one it wrote, then the system shall keep that file. |
| R-PROJ-ROLLBACK.15 | If | If a failed save's rollback keeps a file it wrote, then the system shall show the status `Not removed after the failed save: <painted list> — a folder changed while saving; check the project folders.` |
| R-PROJ-ROLLBACK.16 | If | If a failed save cannot put the previous project.json back, then the system shall show the status `project.json could not be restored; its previous content is kept as <backup name> in <project folder> - rename it to project.json`. |
| R-PROJ-ROLLBACK.17 | If | If a save fails, then the system shall keep the session image as it was before the save. |
| R-PROJ-ROLLBACK.18 | If | If an error other than an operating-system error stops the save, then the system shall show the status `Project NOT saved: could not save — an unexpected error stopped the save. check the folder.` |

#### S11.6 · Load project (from S0 HLR-162; batch-100 HLR-165, HLR-171b)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-013.2 | U | The system shall list in the Load dialog's projects section only the projects of CTX-PROJECT. |
| R-TUI-013.6 | If | If the chosen project folder no longer exists, then the system shall show the status `Project not found: <painted project name>`. |
| R-TUI-013.7 | If | If the project folder breaks rule R-TUI-014.1 or R-TUI-014.2, then the system shall load nothing from it. |
| R-TUI-013.8 | If | If the project folder holds neither a data file nor an A2L file, then the system shall show the status `Project NOT loaded: '<painted project name>' has no data or A2L file — load a file and Save project.` |
| R-TUI-013.9 | When | When the system loads a project, the system shall load its active variant, its MAC file and its A2L file. |
| R-TUI-013.10 | If | If the project has no variant, then the system shall load its MAC file as the session's MAC. |
| R-TUI-013.11 | When | When the system loads a project, the system shall make it the open project. |
| R-TUI-013.12 | When | When a project load completes, the system shall set the file status to the file status of CTX-LOADRES. |
| R-TUI-013.13 | When | When a project load completes, the system shall show the summary line of CTX-LOADRES as the status. |
| R-TUI-013.14 | If | If reading the manifest during a project load gives manifest findings, then the system shall list each as a problem of CTX-LOADRES. |
| R-TUI-013.15 | If | If the picked project folder is a link, then the system shall show the status `Project NOT loaded: '<painted project name>' is a link or junction — pick a project in the list.` |
| R-TUI-013.16 | If | If the picked project folder is not a folder directly in the work area or resolves outside it, then the system shall show the status `Project NOT loaded: '<painted project name>' is outside the work area — copy the folder into the work area.` |
| R-TUI-013.17 | If | If the picked project folder, its file list or its project.json cannot be read, or its project.json is not a regular file, then the system shall show the status `Project NOT loaded: '<painted project name>' could not be read — check that the folder can be opened, then load again.` |
| R-TUI-013.18 | If | If the picked name is not a project of the project list, then the system shall show the status `Project NOT loaded: '<painted name>' is not a project — pick a project in the list.` |
| R-TUI-013.19 | If | If no variant of the project is a readable image and the project has no MAC and no A2L file, then the system shall show the status `No supported files in project: <painted project name>`. |
| R-TUI-013.20 | If | If the A2L file of a project with no data file is a link, is larger than the copy cap or cannot be inspected, then the system shall show the status `Project NOT loaded: <painted A2L file name> in '<painted project name>' <state> — replace the A2L file, then Load again.`, the state being `is a link or junction`, `is too large to open` or `could not be read`. |
| R-PROJ-RESET.1 | When | When the system loads a project, the system shall clear the session state of CTX-PROJECT after it has read the project's files and before it installs the first file. |
| R-PROJ-RESET.3 | If | If a project load is refused, then the system shall keep the session state. |
| R-PROJ-RESET.4 | When | When the operator loads a file outside a project load, the system shall keep the session state that S5 does not replace. |

#### A2L-only projects (from batch-100 HLR-171a)

| Id | Form | Requirement |
|---|---|---|
| R-PROJ-A2LONLY.1 | When | When the system loads an A2L-only project, the system shall attach its A2L file from the project folder. |
| R-PROJ-A2LONLY.2 | If | If the A2L file of a project with a data file is a link or is larger than the copy cap, then the system shall open the project without that A2L file. |
| R-PROJ-A2LONLY.3 | If | If the system opens a project without its A2L file because the file is a link or is larger than the copy cap, then the system shall list that file as a `not readable` problem with the next step `replace the A2L file, then Load again`. |
| R-PROJ-A2LONLY.4 | If | If the project's A2L file does not parse, then the system shall open the project without that A2L file. |
| R-PROJ-A2LONLY.5 | If | If the project's A2L file does not parse, then the system shall list that file as a `not readable` problem with the reason `the file cannot be read`. |

#### S11.7 · Variants

| Id | Form | Requirement |
|---|---|---|
| R-VAR-001.1 | When | When the system loads a project, the system shall make the recorded variant the active variant. |
| R-VAR-001.2 | If | If the project has no manifest or its manifest names no active variant, then the system shall make the first variant in variant order the active variant. |
| R-VAR-001.3 | If | If the recorded variant is not a variant of the project, then the system shall make the first readable image in variant order the active variant. |
| R-PROJ-OPEN.1 | If | If the recorded variant is not a readable image, then the system shall make the next valid variant the active variant. |
| R-PROJ-OPEN.2 | If | If no variant of the project is a readable image, then the system shall load the project's MAC and A2L files without an image. |
| R-VAR-001.5 | When | When the operator presses `v`, the system shall open the Select variant dialog with the open project's variants in variant order. |
| R-VAR-001.6 | When | When the Select variant dialog opens, the system shall highlight the active variant and mark it ` (active)`. |
| R-VAR-001.7 | If | If the open project has no variant when the operator presses `v`, then the system shall show the status `No project variants to select.` |
| R-VAR-001.8 | When | When the operator presses Activate in the Select variant dialog, the system shall make the highlighted variant the active variant. |
| R-VAR-001.9 | When | When the operator activates a variant, the system shall load the variant's file from the project folder. |
| R-VAR-001.10 | When | When the operator activates a variant, the system shall add nothing to the project folder. |
| R-VAR-001.11 | If | If the variant's file no longer exists, then the system shall show the status `Variant file missing: <painted file name>`. |

#### S11.8 · Loads into an open project (R-PROJ-002)

| Id | Form | Requirement |
|---|---|---|
| R-PROJ-002.1 | When | When the operator loads an S19 or Intel HEX file while a project is open, the system shall place it in the project folder as a variant. |
| R-PROJ-002.2 | If | If the project already holds a variant with the same content, then the system shall show the status `Variant '<variant id>' already in project '<project name>'`. |
| R-PROJ-002.3 | When | When the system adds a variant to the open project, the system shall show the status `Added variant '<variant id>' to project '<project name>'`. |
| R-PROJ-002.4 | When | When the system places an S19 or Intel HEX file in the open project, the system shall make its variant the active variant. |
| R-PROJ-002.5 | When | When the operator loads a MAC file while the open project has no MAC file, the system shall copy the MAC file into the project folder. |
| R-PROJ-002.6 | If | If the operator loads a MAC file while the open project holds another MAC file, then the system shall refuse the load with the status `Project already has a MAC file.` |
| R-PROJ-002.7 | When | When the operator loads an A2L file while the open project has no A2L file, the system shall copy the A2L file into the project folder. |
| R-PROJ-002.8 | If | If the work-area checks refuse the copy of an S19, Intel HEX or MAC file into the open project, then the system shall show the status `Project sync rejected: <reason>`. |
| R-PROJ-002.9 | If | If the work-area checks refuse the copy of an A2L file into the open project, then the system shall show the status `A2L sync rejected: <reason>`. |
| R-PROJ-002.10 | When | When the system places a file in the open project outside Save project, the system shall rewrite project.json with the carried records of the existing project.json. |
| R-PROJ-002.11 | When | When the system has made a placed file the open project's active variant and rewritten project.json, the system shall show the status `Project '<project name>' now opens <file name>`. |
| R-PROJ-002.12 | If | If the open project's folder cannot be read or no longer exists when the system adds an S19, Intel HEX or MAC file to it, then the system shall show the status `Project sync NOT done: project '<painted project name>' could not be read — check that the folder can be opened, then load again.` |
| R-PROJ-002.13 | If | If the open project's folder cannot be read or no longer exists when the system adds an A2L file to it, then the system shall show the status `A2L sync NOT done: project '<painted project name>' could not be read — check that the folder can be opened, then load again.` |

#### Writes into the open project (from batch-100 HLR-168)

| Id | Form | Requirement |
|---|---|---|
| R-PROJ-WRITER.1 | If | If the open project's project.json has a rewrite refusal when the system places a file in the project outside Save project, then the system shall leave project.json unchanged. |
| R-PROJ-WRITER.2 | If | If the system leaves project.json unchanged for a rewrite refusal, then the system shall show the status `project.json in project '<project name>' <rewrite refusal> and was not rewritten - <file name> stays in the project; Save project rewrites it`. |
| R-PROJ-WRITER.3 | If | If the open project has no project.json when the system places a file in it, then the system shall write a new project.json. |
| R-PROJ-WRITER.4 | U | The system shall write the integer 1 as schema_version and keep every other value of a rewritten project.json as it was read. |
| R-PROJ-SAVEBACK.1 | When | When a save-back (S8) writes an image into the open project, the system shall make that image's variant the active variant. |
| R-PROJ-SAVEBACK.2 | When | When a save-back writes an image into the open project, the system shall record in derived_from the loaded image's file as the base of the written variant. |
| R-PROJ-SAVEBACK.3 | If | If no project is open when a save-back writes an image, then the system shall write no project.json. |

#### S11.9 · Manifest: read (CTX-MANIFEST)

| Id | Form | Requirement |
|---|---|---|
| R-VAR-002.1 | When | When the system loads a project or runs Execute scope, the system shall read the project's manifest. |
| R-VAR-002.2 | If | If the manifest is larger than the read cap, then the system shall record the finding MANIFEST-SIZE-CAP `the project manifest is <n> bytes, over the 1048576-byte read cap - the file was not loaded`. |
| R-VAR-002.3 | If | If the manifest is not readable, well-formed JSON, then the system shall record the finding MANIFEST-JSON-PARSE `the project manifest is not readable well-formed JSON - ignored: <error type>`. |
| R-VAR-002.4 | If | If the manifest's top level is not a JSON object, then the system shall record the finding MANIFEST-BAD-STRUCTURE `the project manifest top level is not a JSON object - ignored`. |
| R-VAR-002.5 | If | If the manifest is over the read cap, is not readable well-formed JSON or is not a JSON object, then the system shall read no key from it. |
| R-VAR-002.6 | If | If `schema_version` is neither a number nor a string, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest schema_version is neither a number nor a string`. |
| R-VAR-002.7 | U | The system shall read every manifest as version 1, whatever its `schema_version`. |
| R-VAR-002.8 | If | If `active_variant` is present and is not a string, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest active_variant is not a string - ignored`. |
| R-VAR-002.9 | If | If `batch` is not an array, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest batch is not an array - ignored`. |
| R-VAR-002.10 | If | If `assignments` is not an object, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest assignments is not an object - ignored`. |
| R-VAR-002.11 | If | If an `assignments` value is not an array, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest assignments['<variant id>'] is not an array - ignored`. |
| R-VAR-002.12 | If | If an entry is not a string or is blank, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest <context> entry is not a path string - entry skipped`. |
| R-VAR-002.13 | If | If an entry holds a NUL character, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry carries a NUL character - not a path; entry skipped: '<entry>'`. |
| R-VAR-002.14 | If | If an entry has a drive or a root, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry has a drive or a root - entry skipped: '<entry>'`. |
| R-VAR-002.15 | If | If an entry resolves outside the project folder, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry escapes the project directory - entry skipped: '<entry>'`. |
| R-VAR-002.16 | If | If an entry passes through a link inside the project folder, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry traverses a symbolic link or reparse point - entry skipped: '<entry>'`. |
| R-VAR-002.17 | If | If a key or an entry gives a manifest finding, then the system shall read the other keys and entries. |
| R-VAR-002.18 | U | The system shall ignore manifest keys that CTX-MANIFEST does not list. |
| R-VAR-002.19 | When | When the system reads the manifest, the system shall read the gathered entries as it reads batch entries. |

#### New keys and caps (from batch-100 HLR-168, HLR-169, HLR-170)

| Id | Form | Requirement |
|---|---|---|
| R-MANIFEST-READ.1 | If | If gathered is not an object, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest gathered is not an object - ignored`. |
| R-MANIFEST-READ.2 | If | If a gathered value is not an array, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest gathered['<home>'] is not an array - ignored`. |
| R-MANIFEST-READ.3 | If | If a key breaks the entry cap, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest <key> holds <n> entries, over the 1000-entry cap - defaults used`. |
| R-MANIFEST-READ.4 | If | If an entry is longer than 32 767 characters, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry is longer than 32767 characters - entry skipped`. |
| R-MANIFEST-READ.5 | If | If an entry has more than 32 parts, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry has more than 32 path components - entry skipped`. |
| R-MANIFEST-READ.6 | If | If an entry holds a `:`, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry carries a ':' (a drive or a stream name) - entry skipped: '<entry>'`. |
| R-MANIFEST-READ.7 | If | If a part of an entry ends in a dot or a space, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry has a path component ending in a dot or a space: '<part>' - entry skipped: '<entry>'`. |
| R-MANIFEST-READ.8 | If | If a part of an entry is a device name, then the system shall record the finding MANIFEST-PATH-ESCAPE `manifest <context> entry names a device: '<part>' - entry skipped: '<entry>'`. |
| R-MANIFEST-READ.9 | If | If files is not an object, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest files is not an object - ignored`. |
| R-MANIFEST-READ.10 | If | If a files key names neither a recorded file of the project folder's top level nor the active document, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest files key is not a top-level data or A2L file - entry skipped: '<key>'`. |
| R-MANIFEST-READ.11 | If | If a files record has no whole-number size of at least 0 or no sha256 of 64 hex digits, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest files record is malformed - entry skipped: '<key>'`. |
| R-MANIFEST-READ.12 | If | If derived_from is not an object, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest derived_from is not an object - ignored`. |
| R-MANIFEST-READ.13 | If | If a derived_from record is malformed, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest derived_from record is malformed - entry skipped: '<key>'`. |
| R-MANIFEST-READ.14 | If | If a derived_from base is not a plain file name, then the system shall record the finding `manifest derived_from base is not a plain file name - entry skipped: '<base>'`. |
| R-MANIFEST-READ.15 | If | If active_document is not a `.json` entry directly in `patches/` or `checks/`, then the system shall record the finding `manifest active_document is not a document in a project home - ignored: '<value>'`. |
| R-MANIFEST-READ.16 | If | If gathered, files, derived_from or active_document is absent or null, then the system shall record no finding for it. |
| R-MANIFEST-READ.17 | If | If a read skips more entries than the finding bound, then the system shall record one finding `<n> more manifest entries were skipped` for the rest. |

#### S11.10 · Manifest: write and verify

| Id | Form | Requirement |
|---|---|---|
| R-MAN-SER-001.1 | When | When the system writes the manifest, the system shall write the keys of CTX-MANIFEST in their listed order. |
| R-MAN-SER-001.2 | When | When the system writes the manifest, the system shall write `schema_version` as 1. |
| R-MAN-SER-001.3 | When | When the system writes the manifest, the system shall write `active_variant` as the active variant's id, or null when the project has no variant. |
| R-MAN-SER-001.4 | When | When the system writes an entry, the system shall write it with `/` as separator. |
| R-MAN-SER-001.5 | U | The system shall write the same manifest bytes for the same project content. |
| R-MAN-SER-001.6 | U | The system shall write a manifest that reads back with the written values and no manifest finding. |
| R-MAN-SER-001.7 | If | If any entry to write is an unsafe entry, then the system shall write no manifest. |
| R-MAN-SER-001.8 | If | If an entry to write is an unsafe entry, then the system shall record the finding MANIFEST-WRITE-ESCAPE `refusing to serialize manifest <context> entry that is absolute or escapes the project directory: '<entry>'`. |
| R-MAN-SER-001.9 | If | If the last save gathered no file, then the system shall leave `gathered` out of the manifest. |
| R-MAN-SER-001.10 | When | When the save has gathered files, the system shall write `gathered` as the sorted entries of each project home that received a file. |
| R-MANIFEST-WRITE.1 | When | When the system writes gathered for a merge or a save as, the system shall write per home the sorted union of the carried entries and the entries this save gathered. |
| R-MANIFEST-WRITE.2 | When | When the system writes the manifest, the system shall write files with the size and the SHA-256 of every recorded file as it is on disk after every file of the write has landed. |
| R-MANIFEST-WRITE.3 | If | If no file is recorded, then the system shall leave files out of the manifest. |
| R-MANIFEST-WRITE.4 | If | If no derived_from record is set, then the system shall leave derived_from out of the manifest. |
| R-MANIFEST-WRITE.5 | If | If no active document is recorded, then the system shall leave active_document out of the manifest. |
| R-MANIFEST-WRITE.6 | If | If the active_document to write is not a `.json` entry directly in `patches/` or `checks/`, then the system shall record the finding MANIFEST-WRITE-ESCAPE `refusing to serialize manifest active_document that is not a .json file directly in patches/ or checks/: '<value>'`. |
| R-MANIFEST-WRITE.7 | If | If a files key to write names neither a top-level file nor the active document, then the system shall record the finding MANIFEST-WRITE-ESCAPE `refusing to serialize manifest files key that is neither a top-level file nor the active document: '<key>'`. |
| R-MAN-WRITE-001.1 | When | When the system writes the manifest, the system shall write it to `<project folder>/project.json` in place of any earlier one. |
| R-MAN-WRITE-001.2 | U | The system shall never write the manifest under a numbered name. |
| R-MAN-WRITE-001.3 | When | When the system writes the manifest, the system shall leave no half-written project.json. |
| R-MAN-WRITE-001.4 | When | When the system writes the manifest, the system shall change no other file of the work area. |
| R-MAN-WRITE-001.5 | If | If project.json is outside the work area or passes through a link, then the system shall record the finding MANIFEST-WRITE-CONTAINMENT `the manifest write target failed work-area containment validation — no file was written`. |
| R-MAN-WRITE-001.6 | If | If writing project.json fails with an operating-system error, then the system shall record the finding MANIFEST-WRITE-CONTAINMENT of R-MAN-WRITE-001.5. |
| R-MANIFEST-WRITE.8 | If | If project.json lands outside the work area because the project folder changed during the write, then the system shall record the finding MANIFEST-WRITE-CONTAINMENT `the project folder changed during the manifest write - project.json landed outside this work area at <path>`. |
| R-MAN-TUI-001.1 | If | If the system cannot write the manifest, then the system shall show the status `Manifest write failed`. |
| R-MAN-TUI-001.2 | If | If the system cannot write the manifest, then the system shall show an error notice titled `Manifest write failed - project.json not written` with the finding messages joined by `; `. |
| R-MAN-TUI-001.3 | If | If the system cannot write the manifest, then the system shall refuse the whole save (S11.5). |
| R-MAN-VERIFY-001.1 | When | When the system has written the manifest, the system shall read it back from `<project folder>/project.json`. |
| R-MAN-VERIFY-001.2 | If | If the read-back active_variant, batch, assignments, files, derived_from or active_document differ from what the system wrote, or the read-back gives a manifest finding, then the system shall report a verify mismatch. |
| R-MAN-VERIFY-001.3 | If | If the read-back declared_regions or gathered differ from what the system wrote, then the system shall report a verify mismatch. |
| R-MAN-VERIFY-001.4 | If | If the read-back manifest equals what the system wrote, then the system shall show the status `Project saved + manifest verified`. |
| R-MAN-VERIFY-001.5 | If | If the system reports a verify mismatch, then the system shall show an error notice titled `Manifest verify mismatch - project.json may be wrong` with the text `drift: <differing keys>; <finding messages>`. |
| R-MAN-VERIFY-001.6 | If | If the system reports a verify mismatch, then the system shall show `Manifest verify MISMATCH` as the newest status line, after the save status. |
| R-MAN-VERIFY-001.7 | If | If the system reports a verify mismatch, then the system shall keep the save. |
| R-MAN-VERIFY-001.8 | U | The system shall show finding messages in manifest notices as plain text, never as markup. |
| R-MANIFEST-VERIFY.1 | When | When a rewrite of project.json outside Save project reads back equal to what the system wrote, the system shall show the status `project.json updated + verified`. |

#### Keeping a project.json this version cannot rewrite (from batch-100 HLR-169)

| Id | Form | Requirement |
|---|---|---|
| R-MANIFEST-KEEP.1 | If | If the target's project.json has a keep reason, then the system shall keep its content under the backup name before it writes the new project.json. |
| R-MANIFEST-KEEP.2 | If | If the system keeps the previous project.json, then the system shall show the status `project.json <keep reason>: its previous content is kept as <backup name> in <project folder>`. |
| R-MANIFEST-KEEP.3 | If | If the previous content cannot be kept, then the system shall refuse the save with the status `Project NOT saved: project.json <keep reason> and its content could not be kept beside it in <project folder>`. |
| R-MANIFEST-KEEP.4 | If | If the save completes, then the system shall remove no backup it kept. |
| R-MANIFEST-KEEP.5 | If | If the kept project.json recorded a change document path this version cannot use, then the system shall show the status `Change document record <entry> was dropped from project.json — its previous content is kept as <backup name>`. |

#### S11.11 · Composition in the Save dialog

| Id | Form | Requirement |
|---|---|---|
| R-PROJ-ASSIGN-UI-001.1 | When | When the Save dialog opens for an open project with variants and project documents, the system shall show the batch list and one assignment list per variant. |
| R-PROJ-ASSIGN-UI-001.2 | When | When the Save dialog opens with no open project, the system shall show no batch or assignment list. |
| R-PROJ-ASSIGN-UI-001.3 | When | When the Save dialog shows the lists, the system shall offer in each list the open project's project documents. |
| R-PROJ-ASSIGN-UI-001.4 | When | When the Save dialog shows the lists, the system shall leave project.json out of them. |
| R-PROJ-ASSIGN-UI-001.5 | When | When the Save dialog shows the lists, the system shall select in them the documents the manifest already names. |
| R-PROJ-ASSIGN-UI-001.6 | U | The system shall show folder, file and variant names in the Save dialog as plain text, never as markup. |
| R-PROJ-ASSIGN-001.1 | When | When the system saves a project, the system shall write the documents selected in the batch list as `batch`. |
| R-PROJ-ASSIGN-001.2 | When | When the system saves a project, the system shall write the documents selected for each variant as that variant's `assignments` list. |
| R-PROJ-ASSIGN-001.3 | When | When the system writes `assignments`, the system shall key each list by the variant id. |
| R-PROJ-ASSIGN-001.4 | If | If a variant has no selected document, then the system shall leave the variant out of `assignments`. |
| R-PROJ-ASSIGN-001.5 | If | If no document is selected in the batch list, then the system shall write as batch the carried batch of the target, or an empty array when there is none. |
| R-PROJ-ASSIGN-001.6 | If | If no document is selected for any variant, then the system shall write as assignments the carried assignments of the target, or an empty object when there are none. |
| R-PROJ-ASSIGN-001.7 | When | When the system gathers composition documents, the system shall take their names from the batch and the assignments it writes. |
| R-PROJ-ASSIGN-SEC-001.1 | If | If a selected document is an unsafe entry, then the system shall refuse the whole save. |

#### S11.12 · Declared regions in the manifest

| Id | Form | Requirement |
|---|---|---|
| R-RPT-REGION-PERSIST-001.1 | When | When the operator presses Generate in the Reports dialog (S12), the system shall keep the dialog's declared regions for the next project save. |
| R-RPT-REGION-PERSIST-001.2 | If | If the operator closes the Reports dialog without Generate, then the system shall keep the regions it kept before. |
| R-RPT-REGION-PERSIST-001.3 | When | When the system saves a project, the system shall write the kept regions as `declared_regions`. |
| R-RPT-ADDENDUM-PERSIST-001.1 | If | If no region is kept, then the system shall leave `declared_regions` out of the manifest. |
| R-RPT-ADDENDUM-PERSIST-001.2 | If | If the manifest has no `declared_regions` key, then the system shall read no declared region. |
| R-RPT-ADDENDUM-PERSIST-001.3 | If | If `declared_regions` is not an array, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest declared_regions is not an array - ignored`. |
| R-RPT-ADDENDUM-PERSIST-001.4 | If | If a `declared_regions` entry is not an object with a text `name` and whole-number `start` and `end`, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest declared_regions entry is malformed - ignored: <entry>`. |
| R-RPT-ADDENDUM-PERSIST-001.5 | If | If a `declared_regions` entry breaks the region rules, then the system shall record the finding MANIFEST-BAD-STRUCTURE `manifest declared_regions entry is invalid - ignored: <entry>`. |
| R-RPT-ADDENDUM-PERSIST-001.6 | When | When the system reads a declared region, the system shall remove control characters and terminal escape sequences from its name. |
| R-RPT-ADDENDUM-PERSIST-001.7 | If | If a declared region's name is longer than 80 characters, then the system shall cut it to 80 characters ending in `…[truncated]`. |
| R-RPT-REGION-PERSIST-002.1 | When | When the system loads a project, the system shall keep the manifest's declared regions for the Reports dialog. |
| R-RPT-REGION-PERSIST-002.2 | If | If the loaded project's manifest declares no region, then the system shall keep no declared region. |
| R-RPT-REGION-PERSIST-002.3 | When | When the operator opens the Reports dialog, the system shall fill its region box with one line `<name>,<start>,<end>` per kept region. |

#### S11.13 · Executing over variants (CTX-EXEC)

| Id | Form | Requirement |
|---|---|---|
| R-VAR-002.20 | If | If no project with variants is open when the operator runs Execute scope, then the system shall show the status `Execute: no project variants - load a project first.` |
| R-VAR-002.21 | If | If neither the manifest nor the Patch Editor names a document when the operator runs Execute scope, then the system shall show the status `Execute: no manifest and no loaded change/check file - nothing to execute.` |
| R-VAR-002.22 | If | If the project folder breaks rule R-TUI-014.1 or R-TUI-014.2 when the operator runs Execute scope, then the system shall refuse the run with that rule's status. |
| R-VAR-002.23 | When | When a run starts, the system shall show the status `Execute: scope '<scope>' started...`. |
| R-VAR-002.24 | When | When the operator runs Execute scope, the system shall run the file list of each in-scope variant, variants in variant order. |
| R-VAR-002.25 | When | When the system runs a variant, the system shall read the variant's image from its file in the project folder. |
| R-VAR-002.26 | When | When the system runs a variant, the system shall leave the session's image unchanged. |
| R-VAR-002.27 | When | When the system runs a variant, the system shall use the project's MAC and A2L files. |
| R-VAR-002.28 | When | When the system runs a document whose kind is check, the system shall run its checks (S9). |
| R-VAR-002.29 | When | When the system runs a document of any other kind, the system shall apply it as a change document (S8). |
| R-VAR-002.30 | When | When the system runs a document on a variant, the system shall mark its results with the variant id. |
| R-VAR-002.31 | If | If a change document applies at least one entry to an S19 variant, then the system shall save the patched variant in the project folder under the patched name. |
| R-VAR-002.32 | If | If a change document applies at least one entry to an Intel HEX variant, then the system shall save the patched variant in the project folder under the patched name. |
| R-VAR-002.33 | When | When the system saves a patched S19 variant, the system shall keep the variant's S0 header. |
| R-VAR-002.43 | When | When the system saves a patched S19 variant whose source has a terminator, the system shall write the address of the source's terminator in the terminator. |
| R-VAR-002.34 | If | If one variant fails, then the system shall run the remaining variants. |
| R-VAR-002.35 | When | When a variant starts, the system shall show the status `Executing variant '<variant id>' (<n> file(s))...`. |
| R-VAR-002.36 | When | When a variant ends, the system shall show the status `Variant '<variant id>': <ok or error> - <c> change, <k> check` once. |
| R-VAR-002.37 | When | When a variant ends with diagnostics, the system shall show each as `Variant '<variant id>': <diagnostic>`. |
| R-VAR-002.38 | When | When the run ends, the system shall show each manifest finding as a finding line before the variant lines. |
| R-VAR-002.39 | When | When the run ends, the system shall show the status `Execute: scope '<scope>' finished - <n> variant(s), <e> error(s)`. |
| R-VAR-002.40 | If | If reading the project's MAC or A2L file, or any other error, stops the run, then the system shall show the status `Execute failed: <error type>: <reason>`. |
| R-VAR-002.41 | U | The system shall keep the screen responsive while it runs Execute scope. |
| R-VAR-002.42 | When | When an Execute scope run ends, the system shall keep its results, with the project folder, as the kept execution of S12 CTX-RPT-RUN. |
| R-PROJ-EXEC.1 | When | When an Execute scope run has saved a patched variant into the project, the system shall rewrite project.json with the carried records. |

#### S11.14 · Save as (from batch-100 HLR-171; CTX-SAVE)

| Id | Form | Requirement |
|---|---|---|
| R-SAVEAS-1 | When | When the system saves as, the system shall copy each regular file of the open project that the save does not write itself, at the top level and at every depth of its sub-folders, to the same path in the new project folder. |
| R-SAVEAS-2 | When | When the system saves as, the system shall copy no backup of project.json. |
| R-SAVEAS-3 | When | When the system saves as, the system shall copy no file reached through a link or junction. |
| R-SAVEAS-4 | If | If a save as skips links or junctions, then the system shall show, after the save status, the status `Save as: links or junctions not copied: <painted list> — copy those files into the project if it needs them.` |
| R-SAVEAS-5 | When | When the system saves as, the system shall leave every file of the open project unchanged. |
| R-SAVEAS-6 | When | When the system saves as, the system shall write into the new project.json the carried records of the open project. |
| R-SAVEAS-7 | If | If the open project's project.json is a link, then the system shall carry no record from it into the new project. |
| R-SAVEAS-8 | When | When a save as completes, the system shall make the new project folder the Flow panels' session folder. |
| R-SAVEAS-9 | When | When a save as completes, the system shall bind a Patch Editor document whose file lies in the previous project folder to that file's copy in the new project folder. |
| R-SAVEAS-10 | If | If the open project's folder no longer exists when the system saves to a new folder, then the system shall save the session's files without a copy from the open project. |
| R-SAVEAS-11 | If | If the open project's folder no longer exists when the system saves to a new folder, then the system shall show, after the save status, the status `The open project folder '<painted folder name>' was not found — its other files were not copied; copy them into '<painted clean name>' if you still have them.` |
| R-SAVEAS-12 | If | If a folder from the work area down to a file the save as copies is a link when the system reads that file, then the system shall refuse the save with the status `Project NOT saved: could not save — <painted path> changed while saving — check the folder.` |
| R-SAVEAS-13 | If | If a save-as copy fails after the project folder exists, then the system shall refuse the save with the status `Project NOT saved: could not save — <painted path> could not be copied — check the folder.` |
| R-SAVEAS-14 | If | If a top-level file of a save as lands at another name than its plan row because the new project already holds the same bytes, then the system shall refuse the save with the status `Project NOT saved: the plan named <name> (<action word>) but the file landed at <name> (<action word>) — <landed name> already holds the same bytes as <name> — remove the duplicate copy from the open project folder '<painted folder name>', then save again.` |

#### S11.15 · Load result: problems (from batch-100 HLR-169; CTX-LOADRES)

| Id | Form | Requirement |
|---|---|---|
| R-PROJCHK-1 | When | When the system loads a project, the system shall check every recorded file of project.json against the project folder. |
| R-PROJCHK-2 | If | If the project has no project.json, then the system shall list a `no project.json` problem for project.json. |
| R-PROJCHK-3 | If | If project.json is a damaged manifest, then the system shall list a `manifest damaged` problem with the reason of the first finding. |
| R-PROJCHK-4 | If | If a recorded file is absent, then the system shall list a `missing` problem with the reason `recorded in project.json, not on disk`. |
| R-PROJCHK-5 | If | If a recorded file is not a regular file or cannot be read, then the system shall list a `not readable` problem with the reason `not a regular file` or `the file cannot be read`. |
| R-PROJCHK-6 | If | If a recorded file's size differs from its record, then the system shall list a `changed on disk` problem with the reason `saved <n> B, now <m> B`. |
| R-PROJCHK-7 | If | If a recorded file has its recorded size and another SHA-256, then the system shall list a `changed on disk` problem with the reason `same size (<n> B), different content`. |
| R-PROJCHK-8 | If | If a project file with a data or A2L suffix directly in the project folder has no files record, then the system shall list a `not recorded` problem with the reason `in the project, not in project.json`. |
| R-PROJCHK-9 | If | If project.json is not damaged and records no files, then the system shall list a `no digests saved` problem for project.json. |
| R-PROJCHK-10 | If | If a variant file does not read as an S19 or Intel HEX image, then the system shall list a `not readable` problem with the reason `not an S19 or HEX file`. |
| R-PROJCHK-11 | If | If a variant file reads without errors and holds no data byte, then the system shall list a `not readable` problem with the reason `0 data bytes`. |
| R-PROJCHK-12 | If | If a variant file reads with diagnostics and holds at least one data byte, then the system shall open it. |
| R-PROJCHK-13 | If | If the recorded variant is not a variant of the project, then the system shall list a `missing` problem for its file with the reason `recorded as the active variant`. |
| R-PROJCHK-14 | If | If one file has more than one problem, then the system shall list only its problem of highest precedence. |
| R-PROJCHK-15 | U | The system shall list the problems of a project load in precedence order. |
| R-PROJCHK-16 | If | If a project load finds problems, then the system shall open every project file that reads. |
| R-PROJCHK-17 | U | The system shall write the issue codes and exception class names of a project load to the log only. |
| R-PROJCHK-18 | U | The system shall give each problem the next step of CTX-LOADRES. |

#### S11.16 · Load result: status and panel (from batch-100 HLR-178; CTX-LOADRES)

| Id | Form | Requirement |
|---|---|---|
| R-LOADRES-1 | If | If the summary line is longer than 118 characters, then the system shall shorten the load target, then the project name, each to no fewer than 8 characters ending in `…`. |
| R-LOADRES-2 | When | When a project load that the operator started from the Load dialog completes, the system shall open the Load-result panel. |
| R-LOADRES-3 | When | When the Load-result panel opens, the system shall show the title, the summary grid, the heading and the problem rows of CTX-LOADRES. |
| R-LOADRES-4 | When | When the system composes the result of a project load, the system shall give the load reason that applies. |
| R-LOADRES-5 | If | If derived_from records the opened variant, then the system shall show the relation line. |
| R-LOADRES-6 | U | The system shall call a variant the latest saved only when it is the recorded variant. |
| R-LOADRES-7 | If | If more problems are found than the problem bound, then the system shall list the first 102 and one row that counts the rest. |
| R-LOADRES-8 | When | When the Load-result panel opens, the system shall put the focus on the problem list. |
| R-LOADRES-9 | When | When the operator presses tab in the Load-result panel, the system shall move the focus to Close. |
| R-LOADRES-10 | When | When the operator presses escape in the Load-result panel or Enter on Close, the system shall close the panel. |
| R-LOADRES-11 | When | When the operator presses v in the Load-result panel, the system shall open the Select variant dialog in place of the panel. |
| R-LOADRES-12 | U | The system shall let the operator scroll the problem list to its last row with the keyboard alone. |
| R-LOADRES-13 | U | The system shall show names in the Load-result panel, the file status and the summary line as plain text, never as markup. |
| R-LOADRES-14 | If | If the opened variant is the recorded variant, then the system shall paint the load reason in the OK colour (S3 CTX-LEGEND). |
| R-LOADRES-15 | If | If the opened variant is not the recorded variant, then the system shall paint the load reason in the warning colour (S3 CTX-LEGEND). |
| R-LOADRES-16 | U | The system shall paint the mark and the problem word of each problem row in the warning colour (S3 CTX-LEGEND). |
| R-LOADRES-17 | If | If a manifest entry cannot be checked because it is too long or loops through a junction, then the system shall list it as a skipped row and go on with the load. |
| R-LOADRES-18 | If | If a variant of the project did not read during the load, then the system shall follow its name in the Others list of the Load-result panel with `   not readable`. |



<a id="s12"></a>

## S12 · Project reports

### Context notes (informative)

#### CTX-RPT-FILE · The project report file (S12.1 … S12.5)

```text
report file      <project>/reports/<timestamp>-report.md     (<project>: S11 CTX-PROJECT)
  <timestamp>    The UTC time of generation, YYYYMMDDTHHMMSSZ, e.g. 20261030T121500Z.
  same second    The next names of the same second are <timestamp>-01-report.md …
                 <timestamp>-99-report.md.
report name      A file name of the form <timestamp>-report.md or <timestamp>-NN-report.md.
encoding         UTF-8 text, LF line ends, Markdown with GitHub tables.
sections, in this order (a section that a rule leaves out keeps the others in order):
  title          # Project report: <project>
  filter block   ## Report filter applied                 (only with a filter; CTX-RPT-FILTER)
  header lines   - Project: <project>
                 - Generated (UTC): <time>
                 - Tool version: <version>                (S1 R-VER-001)
                 - Context bytes: <c>
                 - Execution mode: <mode>
                 - Assignment source: <source>
  inventory      ## Variant inventory      table: Variant · File · Type · Active
  overview       ## Consolidated overview  table: Variant · Status · Changes applied ·
                                           Checks passed · Checks failed · Checks uncheckable
  legend         ## Legend                 one "### <block>" per block of S3 CTX-LEGEND
  per reported variant, in run order:
    ## Variant: <variant id>
    ### Modified files        modified-file lines (CTX-RPT-CELLS)
    ### Modifications         table: Address · Length · Before · After · Linkage · Symbol
    ### Declaration errors    issue lines (CTX-RPT-CELLS)
    ### Checklists            per check document: #### Checklist: <path>, the count line,
                              table: Address · Length · Expected · Actual · Result
    ### Memory regions        hexdump blocks (CTX-RPT-HEX)
    ### Entropy               band lines
  addendum       ## Addendum: declared regions             (only with declared regions)
  appendix       ## Truncation appendix                    (only with truncation notes)
  omitted block  ## Omitted content                        (only when a section was left out)
Each heading and each table is followed by one blank line.
<time>           ISO 8601 with the UTC offset, e.g. 2026-10-30T12:15:00.123456+00:00
                 (microseconds left out when they are 0).
<c>              Context bytes: a whole number from 0 to 4096; 64 by default.
<mode>           The scope of the reported run (S11 CTX-EXEC), written as:
                 active-only (scope active) · batch (scope all) ·
                 per-assignment (scope assignments).
<source>         manifest (the run took its documents from project.json) ·
                 default (it did not).
reported variant A variant of the reported run (S11 CTX-EXEC), with its run status ok or error.
Type             s19 or hex.    Active: yes for the project's active variant, else no.
Changes applied  The number of the variant's change entries with disposition applied
                 (S8 CTX-APPLY).
Checks passed …  The variant's aggregate counts (S9 CTX-CHECK), summed over its check
                 documents.
band lines       - **<band>**: <n> window(s)[ (<k> low-confidence)]
                 (bands and low confidence: S4 CTX-ENTROPY)
```

#### CTX-RPT-CELLS · Lines and cells (S12.3, S12.6)

```text
hex address      0x + uppercase hexadecimal digits, no leading zeros (0x1F00).
address cell     0x + uppercase hexadecimal digits, at least 8 (0x00001F00).
length cell      The entry's byte count, in decimal.
byte cell        Each byte as two uppercase hexadecimal digits, one space apart (01 AB FF);
                 - when the entry has no such bytes (Before of an entry not applied,
                 Actual of an entry not read).
byte cell cap    171 bytes per cell.
symbol cell      The entry's own symbol; when it has none, its linkage symbol (S8
                 R-CHG-LINK.3); when it has neither, -.
Linkage          mac-linked · a2l-linked · both · standalone (S8 CTX-APPLY).
Result           pass · fail · uncheckable (S9 CTX-CHECK).
modified-file    - `<document path>` (applied entries: <n>)[ - saved as `<saved path>`]
line             (in-memory document) stands, without backticks, for a document with no file.
<path>           In "#### Checklist: <path>" and its notices: `<document path>`, or
                 (in-memory document).
issue line       - [<code>] <severity>: <message>[ @ <hex address>][ symbol=<symbol>]
                 [ related=<artifact>,<artifact>…]
                 (issue, code, symbol, related artifacts: S3 CTX-ISSUE;
                 severity: error · warning · info)
count line       Passed: <p> - Failed: <f> - Uncheckable: <u>
kept rows        The rows of a table that pass the report filter (all rows when no filter
                 is selected). The row caps count kept rows.
row cap          200 kept rows per variant: Modifications rows, and Checklists rows
                 counted over all the variant's check documents.
```

#### CTX-RPT-HEX · Hexdumps (S12.4)

```text
applied entry    A change entry of the run with disposition applied (S8 CTX-APPLY); its
                 span is start … end, end exclusive.
image            The variant's image after its run (S11 CTX-EXEC).
image top        The highest address of the image, plus 1.
window           For an applied entry and context <c>: from (start − c) rounded down to a
                 multiple of 16, not below 0, up to (end + c) rounded up to a multiple of
                 16, not above the image top rounded up to a multiple of 16; the upper
                 bound exclusive. Windows that overlap or touch are one window.
region cap       128 applied entries per variant (their windows are dumped).
block            Window 0x<first address, 8 digits>-0x<last address, 8 digits>:
                 (blank line)
                 ```text
                 [... window limited to 512 rows ...]
                 up to 512 rows, one per 16 addresses of the window
                 ```
                 (blank line)
row              0x<row address, 8 digits>  <16 cells, one space apart>  |<16 characters>|
                 cell: the byte as two uppercase hexadecimal digits; two spaces for an
                 address not in the image.
                 character: the byte when it is 0x20-0x7E, else "."; an address not in the
                 image also shows ".". (The screens' row format is S4 CTX-HEX.)
```

#### CTX-RPT-TEXT · Text from a file, in a report (S12.7)

```text
file-derived text  Text a report takes from a file, a folder name or the operator: the
                   project name, variant ids, file names, file types, run statuses,
                   linkages, symbols, issue codes, messages and related artifacts, check
                   results, the filter file name, region names. (Screens: S1 CTX-TEXT.)
report-safe text   The text after these steps, in this order:
                   1. each tab, CR and LF becomes one space;
                   2. each character of Unicode category Cc, Cf, Cs, Zl or Zp becomes �;
                   3. white space at both ends is removed;
                   4. text longer than the field limit is cut to the limit, white space at
                      its end removed, and "… (truncated)" added;
                   5. a backslash goes before each \ & | * _ [ ] < > # ~ / . @ and `;
                   6. a leading - + or = gets a backslash before it; a leading
                      <1 to 9 digits>) gets a backslash before the );
                   7. empty text becomes (empty).
path text          Steps 1 to 3, then each backtick becomes �, then empty text becomes
                   (empty). Never cut. Written between two backticks.
field limit        region name 80 · issue message 500 · every other field 512 characters.
Markdown reader    A CommonMark reader with GitHub tables, links made from bare web
                   addresses, and raw HTML turned on (markdown-it "gfm-like" defaults).
shows as text      Shows the characters of the value and opens no link, image, raw HTML,
                   heading, list, quote, rule, code span, emphasis, strikethrough or new
                   table cell.
```

#### CTX-RPT-BUDGET · Size of a report (S12.8)

```text
size budget       2,097,152 bytes (2 MiB).
line cost         The line's UTF-8 bytes + 1.
section           A part the system admits or leaves out as a whole:
                  preamble: the filter block, the inventory, the overview, the legend;
                  per variant: Modified files, Modifications, Declaration errors,
                  Checklists, the Memory regions heading with its empty text, each
                  hexdump block, Entropy;
                  after the variants: the addendum.
section kind      preamble · modified-files · modifications · declaration-errors ·
                  checklists · memory-regions · entropy · addendum
always written    The title, the header lines, each variant heading, the TRUNCATED lines
                  of a Memory regions section, the truncation appendix and the omitted
                  block. They do not count against the size budget.
variant share     The larger of: (size budget left after the legend) ÷ (number of
                  reported variants), and 624 bytes.
size ceiling      2,097,152 + 63,726 + 1,321 × <number of reported variants> bytes on a
                  64-bit host, for variant ids of at most 255 UTF-16 units (a file name).
truncation note   Variant '<variant id>': <the text of a Memory regions TRUNCATED line
                  without its "> TRUNCATED: " prefix>
appendix          ## Truncation appendix
                  (blank line)
                  - <truncation note>          at most 64, taken one per variant in turn
                  [- <n> further note(s) across <d> variant(s) not itemised (cap: 64 notes).]
                  (blank line)
omitted block     ## Omitted content
                  (blank line)
                  - <kind>: sections <s>, lines <l>, bytes <b>[ (variants <list>)]
                  one line per section kind with a section left out, in kind order;
                  <b>: the summed line cost of what was left out;
                  <list>: up to 8 variant positions (0 = first in run order), ", "
                  between them, then " +<k> more" for the others.
                  (blank line)
```

#### CTX-RPT-ADDENDUM · Declared regions (S12.9)

```text
declared region   A name and an address range start … end, both included (region rules:
                  S11 CTX-MANIFEST).
region box        The Reports dialog's multi-line box: one region per line,
                  <name>,<start>,<end>. Pre-filled from the kept regions (S11 S11.12).
region number     A whole number in decimal (no leading zero), or after 0x (hexadecimal),
                  0o (octal) or 0b (binary); _ may stand between digits; a leading -
                  makes it negative.
skipped line      A line of the region box that is not blank and either does not hold
                  exactly three comma-separated fields, or holds a field that is not a
                  region number, or breaks the region rules.
hit               modification: a change entry of a reported variant, any disposition,
                  whose start address is in the region;
                  change-file issue: an issue of a change document of a reported variant
                  whose address is in the region;
                  check-file issue: the same for a check document.
hit line          - modification @ <hex address> (variant <variant id>)
                  - issue [<code>] @ <hex address> (variant <variant id>)
hit order         Variants in run order; per variant, each change document's entries and
                  then its issues, document by document; then the check documents' issues.
addendum          ## Addendum: declared regions
                  (blank line)
                  per region, in the order of the region box:
                  ### <name> (<hex start>-<hex end>)
                  its hit lines, or None.
                  its truncation notices
                  (blank line)
hit cap           200 hits of one kind per region.
```

#### CTX-RPT-FILTER · The report filter (S12.10, S12.11)

```text
filter file      A UTF-8 JSON file of at most 4,194,304 bytes (4 MiB):
                   {"format": "s19app-report-filter", "version": "1.0",
                    "include": {"symbols": [<pattern>, …],
                                "addresses": [{"start": <a>, "end": <b>}, …]}}
                 include, symbols and addresses may be left out: an empty list.
                 At most 4096 patterns and 4096 ranges.
<a>, <b>         A JSON whole number, or text "0x<hexadecimal digits>"; 0 ≤ a < b ≤ 2^32;
                 b is exclusive.
filters folder   <project>/filters/
filter selection The filter file the next project report and before/after report use
                 (S14), or none. One per session.
pattern match    A name matches a pattern when it is equal to it, or matches it as a
                 case-sensitive wildcard pattern (* ? [set]).
matched set      The filter's address ranges, plus, for each loaded A2L tag and MAC record
                 (S2) whose name matches a pattern, address … address + size, end
                 exclusive; size: the tag's byte size when it is above 0, else 1; MAC: 1.
item match       An entry matches when its own symbol or its linkage symbol matches a
                 pattern, or its span shares an address with the matched set.
filtered parts   The Modifications rows, the Checklists rows and the applied entries whose
                 windows are dumped. Every other section is written in full.
filter block     ## Report filter applied
                 (blank line)
                 - Filter file: <filter file name>
                 - Modifications rows: shown <s> of <t> (hidden <h>)
                 - Checklist rows: shown <s> of <t> (hidden <h>)
                 - Applied regions: shown <s> of <t> (hidden <h>)
                 - Note: windows seeded by matched regions may include excluded addresses
                   as merged context.
                 (blank line)
                 <s>, <t>, <h>: matching, all, not matching; summed over the reported
                 variants; Applied regions counts applied entries.
zero-match text  filter matched 0 of <n> items          (<n>: the items before the filter)
diagnostic       One text per fault of a filter file (S12.10). <path>: the path as typed,
                 in single quotes. <value>, <key>: the value or key as found — text in
                 single quotes, a number as its digits, null as None, true as True.
                 <error>: the text of the reader's error. <field>:
                 include.addresses[<i>].start or include.addresses[<i>].end; <i> counts
                 from 0.
```

#### CTX-RPT-DIALOG · The Reports dialog (S12.12)

```text
Reports dialog    Title "Reports (project '<project>'):" with the 📂 Open reports/ chip and
                  the ? chip (S7 CTX-HELP); then, top to bottom:
  report list     The project's report files, or the empty text
                  "No reports in this project yet - use 'Generate new report' below."
  report view     The selected report file, rendered as Markdown.
  region box      Label "Declared regions (name,start,end per line):" (CTX-RPT-ADDENDUM).
  filter row      "Filter:", the filter dropdown (a blank option, then the filter files),
                  the filter path box (hint "filter path (blank = full report)").
  bottom row      "Context bytes:" box (64 when the dialog opens), the buttons
                  Generate new report and Close.
report files      The .md files of <project>/reports/. Flow reports use the report name
                  form too (S15 CTX-FLOWREPORT); before/after, diff and chain-set reports
                  do not (S14, S15).
list order        Report names first, newest first by (timestamp, NN), a name with no NN
                  counting as 00; then the other report files, by name.
viewer cap        4,194,304 bytes (twice the size budget).
too-large text    "This report file is larger than the viewer cap and was not rendered. It
                  remains available on disk."
unreadable text   "This report file could not be read."
Dialog behaviour common to all dialogs (Escape, focus, button keys, paste limit): S7.
```

#### CTX-RPT-RUN · Generating a report (S12.13, S12.14)

```text
kept execution    The results of the last "Execute over variants" run (S11 S11.13), kept
                  with the project folder they belong to.
new run           A run of the active variant's documents (S11 CTX-EXEC, scope active)
                  that the report starts itself.
progress bar      The progress bar of the status bar (S6).
report progress line  The progress line (S6) of a project report: label
                  `Generating the project report`; steps 1 `Prepare the results`,
                  2 `Write the report`.
log line          report kind=project source=<project folder name> output=<report path
                  or -> outcome=<outcome>
                  <outcome>: ok · rejected: <reason> · failed: <error type> ·
                  refused: <status text>
<error type>      The name of the error, e.g. FileExistsError, OSError.
```

---

### Requirements


#### S12.1 · The report file (CTX-RPT-FILE)

| Id | Form | Requirement |
|---|---|---|
| R-RPT-001.1 | When | When the system generates a project report, the system shall write it as one report file in `<project>/reports/`. |
| R-RPT-001.2 | When | When the system generates a project report, the system shall name the file `<timestamp>-report.md` after the UTC time of generation. |
| R-RPT-001.3 | If | If that name is taken, then the system shall use the first free name from `<timestamp>-01-report.md` to `<timestamp>-99-report.md`. |
| R-RPT-001.4 | If | If all 100 names of that second are taken, then the system shall refuse the report with the status `Report failed: FileExistsError: 100 reports already exist for second <timestamp> - refusing to overwrite an existing report`. |
| R-RPT-001.5 | If | If `<project>/reports/` does not exist when the system writes a report, then the system shall create it. |
| R-TUI-097.1 | U | The system shall write a report file as UTF-8 text with LF line ends on every host. |
| R-RPT-001.6 | U | The system shall write the sections of a report in the order of CTX-RPT-FILE. |
| R-RPT-001.7 | U | The system shall write no report content to the log. |

#### S12.2 · Header, inventory, overview, legend

| Id | Form | Requirement |
|---|---|---|
| R-RPT-001.8 | When | When the system writes a report, the system shall start it with the title and the header lines of CTX-RPT-FILE. |
| R-RPT-001.9 | When | When the system writes a report built from the kept execution, the system shall write that execution's scope as the execution mode. |
| R-RPT-001.10 | When | When the system writes a report built from the kept execution, the system shall write that execution's assignment source. |
| R-RPT-001.11 | When | When the system writes a report built from a new run, the system shall write `- Execution mode: active-only`. |
| R-RPT-001.12 | When | When the system writes a report built from a new run of a project that has a `project.json`, the system shall write `- Assignment source: manifest`. |
| R-RPT-001.13 | When | When the system writes a report built from a new run of a project that has no `project.json`, the system shall write `- Assignment source: default`. |
| R-RPT-001.14 | When | When the system writes a report, the system shall write one inventory row per variant of the project, in the project's variant order. |
| R-RPT-001.15 | When | When the system writes a report, the system shall write one overview row per reported variant, in run order. |
| R-LEGEND-REPORT-001.1 | When | When the system writes a report, the system shall write the legend section with one `### <block>` part per block of S3 CTX-LEGEND. |
| R-LEGEND-REPORT-001.2 | When | When the system writes a legend row whose label is its colour name, the system shall write it as `- **<label>** — <meaning>`. |
| R-LEGEND-REPORT-001.3 | When | When the system writes a legend row whose label is not its colour name, the system shall write it as `- **<label>** (<colour>) — <meaning>`. |

The legend rows themselves, and the rule that the report and the legend window show the same rows, are S3's (R-LEGEND-SOURCE-001, R-LEGEND-011).

#### S12.3 · The sections of a variant (CTX-RPT-FILE, CTX-RPT-CELLS)

| Id | Form | Requirement |
|---|---|---|
| R-RPT-001.16 | When | When the system writes a reported variant, the system shall write the heading `## Variant: <variant id>`. |
| R-RPT-001.17 | When | When the system writes a variant's Modified files section, the system shall write one modified-file line per change document of the run with at least one applied entry, in run order. |
| R-RPT-001.18 | If | If no change document of the variant's run has an applied entry, then the system shall write `No files were modified for this variant.` in its Modified files section. |
| R-RPT-001.19 | When | When the system writes a variant's Modifications section, the system shall write one table row per change entry of the run, in document order. |
| R-RPT-001.20 | When | When the system writes a Modifications row, the system shall fill Address, Length, Before, After, Linkage and Symbol from the entry's change summary (S8 CTX-APPLY) as CTX-RPT-CELLS defines them. |
| R-RPT-001.21 | If | If the variant's run has no change entry, then the system shall write `No change entries were executed for this variant.` in its Modifications section. |
| R-RPT-001.22 | When | When the system writes a variant's Declaration errors section, the system shall write one issue line per issue of its change documents and then of its check documents, in run order. |
| R-RPT-ISSUE-FIELDS-001.1 | When | When the system writes an issue line for an issue with an address, the system shall add ` @ <hex address>` after the message. |
| R-RPT-ISSUE-FIELDS-001.2 | If | If the issue has no address, then the system shall write no address part in its issue line. |
| R-RPT-ISSUE-FIELDS-001.3 | When | When the system writes an issue line for an issue with a symbol, the system shall add ` symbol=<symbol>`. |
| R-RPT-ISSUE-FIELDS-001.4 | If | If the issue has no symbol, then the system shall write no symbol part in its issue line. |
| R-RPT-ISSUE-FIELDS-001.5 | When | When the system writes an issue line for an issue with related artifacts, the system shall add ` related=<artifacts>` with the artifacts separated by commas. |
| R-RPT-ISSUE-FIELDS-001.6 | If | If the issue has no related artifact, then the system shall write no related part in its issue line. |
| R-RPT-001.23 | If | If the variant has no issue, then the system shall write `None.` in its Declaration errors section. |
| R-RPT-001.24 | If | If a variant has more than 200 issues, then the system shall write the issue lines of the first 200. |
| R-RPT-001.25 | If | If a variant has more than 200 issues, then the system shall add the line `> TRUNCATED: <n> of <total> declaration errors omitted (cap: 200 issues per variant).` after them. |
| R-RPT-001.26 | When | When the system writes a check document of a variant's Checklists section, the system shall write the heading `#### Checklist: <path>`. |
| R-RPT-001.27 | When | When the system writes a check document of a variant's Checklists section, the system shall write its count line with the document's aggregate counts before any filter. |
| R-RPT-001.28 | When | When the system writes a check document of a variant's Checklists section, the system shall write one table row per entry with Address, Length, Expected, Actual and Result, in document order. |
| R-RPT-001.29 | If | If the variant's run has no check document, then the system shall write `No checklists were executed for this variant.` in its Checklists section. |

#### S12.4 · Hexdumps (CTX-RPT-HEX)

| Id | Form | Requirement |
|---|---|---|
| R-RPT-001.30 | When | When the system writes a variant's Memory regions section, the system shall write one block per window of its applied entries, in address order. |
| R-RPT-001.31 | U | The system shall compute each window as CTX-RPT-HEX defines it. |
| R-RPT-001.32 | U | The system shall write each block's rows in the row format of CTX-RPT-HEX inside a fenced code block marked `text`. |
| R-RPT-001.39 | When | When the system writes a block, the system shall head it `Window 0x<first address>-0x<last address>:` with both addresses inside the window. |
| R-RPT-001.33 | If | If a window has more than 512 rows, then the system shall write its first 512 rows after the line `... window limited to 512 rows ...`. |
| R-RPT-001.34 | If | If the variant's run has no applied entry, then the system shall write `No modified regions.` in its Memory regions section. |
| R-RPT-001.35 | If | If the variant's image after the run is not available, then the system shall write `Post-change memory map unavailable - hexdumps omitted.` in its Memory regions section. |
| R-RPT-001.36 | If | If a variant has more than 128 applied entries, then the system shall dump the windows of the first 128 in document order. |
| R-RPT-001.37 | If | If a variant has more than 128 applied entries, then the system shall write `> TRUNCATED: <n> of <total> modified regions omitted (cap: 128 regions per variant).` before its blocks. |
| R-RPT-001.38 | If | If some blocks of a variant were left out by the size budget, then the system shall write `> TRUNCATED: <n> hexdump block(s) omitted (report size cap: 2097152 bytes).` after its blocks. |
| R-RPT-001.40 | When | When the system writes a TRUNCATED line in a Memory regions section, the system shall add its truncation note to the truncation appendix. |

#### S12.5 · Entropy (from S4)

| Id | Form | Requirement |
|---|---|---|
| R-RPT-ENT.1 | When | When the system writes a reported variant, the system shall write an Entropy section after its Memory regions section. |
| R-RPT-ENT.2 | When | When the system writes an Entropy section, the system shall write one band line per band of S4 CTX-ENTROPY that holds a window of the variant's image, in band order. |
| R-RPT-ENT.3 | If | If some of a band's windows are low confidence (S4 R-ENT-004), then the system shall add ` (<k> low-confidence)` to its band line. |
| R-RPT-ENT.4 | If | If the variant's image holds no byte, then the system shall write `No mapped bytes - entropy not computed.` in its Entropy section. |
| R-RPT-ENT.5 | U | The system shall write no byte value in an Entropy section. |

#### S12.6 · Cells and row caps (CTX-RPT-CELLS)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-101.1 | If | If a variant has more than 200 kept Modifications rows, then the system shall write the first 200. |
| R-TUI-101.2 | If | If a variant has more than 200 kept Modifications rows, then the system shall add `> TRUNCATED: Modifications: <n> of <kept> rows omitted (cap: MAX_REPORT_ROWS_PER_VARIANT = 200 rows per variant).` under the table. |
| R-TUI-101.3 | If | If a variant has more than 200 kept Checklists rows over all its check documents, then the system shall write the first 200. |
| R-TUI-101.4 | If | If a check document loses kept rows to the row cap, then the system shall add `> TRUNCATED: Checklist: <path>: <n> of <kept> rows omitted (cap: MAX_REPORT_ROWS_PER_VARIANT = 200 rows per variant).` with that document's own counts. |
| R-TUI-101.5 | If | If a check document with kept rows comes after the row cap is spent, then the system shall write no table header for it. |
| R-TUI-101.6 | If | If a byte cell would hold more than 171 bytes, then the system shall write the first 171 followed by ` … (+<n> more bytes)`. |
| R-TUI-101.7 | U | The system shall write an address cell with at least 8 hexadecimal digits. |
| R-TUI-101.8 | If | If an address has more than 16 hexadecimal digits, then the system shall write `0x`, its first 16 digits and ` … (+<n> more hex digits)` in its address cell. |
| R-TUI-102.8 | U | The system shall write a length cell in decimal. |

#### S12.7 · Text from files (CTX-RPT-TEXT)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-077.1 | When | When the system writes file-derived text into a report, the system shall write it as report-safe text with its field limit. |
| R-TUI-077.2 | When | When the system writes a file path into a report, the system shall write it as path text. |
| R-TUI-077.3 | U | The system shall write file-derived text into a report so that a Markdown reader shows it as text. |
| R-TUI-077.4 | U | The system shall keep every table row of a report at the column count of its table. |

Known limit (informative): readers with extra syntax (`:emoji:`, `$…$`, `==mark==`) are not covered by "a Markdown reader" (CTX-RPT-TEXT); the old R-TUI-077 called this residual risk RR-1.

#### S12.8 · Size budget (CTX-RPT-BUDGET)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-102.1 | When | When a section's line cost fits both the size budget left and the variant share left, the system shall admit the section into the report. |
| R-TUI-102.2 | If | If a section does not fit, then the system shall leave the whole section out. |
| R-TUI-102.3 | When | When the system has left a section out, the system shall still admit each later section that fits. |
| R-TUI-102.4 | U | The system shall write the always-written lines of CTX-RPT-BUDGET whatever budget is left. |
| R-TUI-102.5 | U | The system shall give each reported variant the variant share of CTX-RPT-BUDGET. |
| R-TUI-102.6 | If | If the system left a section out, then the system shall end the report with the omitted block of CTX-RPT-BUDGET. |
| R-TUI-102.7 | U | The system shall keep a report file within the size ceiling of CTX-RPT-BUDGET. |
| R-TUI-102.9 | If | If a truncation note exists, then the system shall write the appendix of CTX-RPT-BUDGET after the addendum. |
| R-TUI-102.10 | If | If there are more than 64 truncation notes, then the system shall write 64 of them, taken one per variant in turn. |
| R-TUI-102.11 | If | If there are more than 64 truncation notes, then the system shall add `- <n> further note(s) across <d> variant(s) not itemised (cap: 64 notes).` to the appendix. |

#### S12.9 · Declared regions and the addendum (CTX-RPT-ADDENDUM)

| Id | Form | Requirement |
|---|---|---|
| R-RPT-ADDENDUM-002.1 | When | When the operator presses Generate new report, the system shall take as declared regions the lines of the region box that are neither blank nor skipped lines, in box order. |
| R-RPT-ADDENDUM-001.1 | When | When the system reads a line of the region box, the system shall remove the white space around each field. |
| R-RPT-ADDENDUM-001.2 | When | When the system reads a line of the region box, the system shall read start and end as region numbers. |
| R-RPT-ADDENDUM-001.3 | When | When the system reads a region name from the region box, the system shall remove its control characters and terminal escape sequences. |
| R-RPT-ADDENDUM-001.4 | If | If a region name is longer than 80 characters, then the system shall cut it to 80 characters ending in `…[truncated]`. |
| R-RPT-REGION-SKIP-001.1 | If | If a line of the region box is a skipped line, then the system shall leave it out of the declared regions. |
| R-RPT-REGION-SKIP-001.2 | If | If one or more lines of the region box are skipped lines, then the system shall show the notice `<n> region line(s) skipped`. |
| R-RPT-REGION-SKIP-001.3 | If | If no line of the region box is a skipped line, then the system shall show no skip notice. |
| R-RPT-REGION-SKIP-001.4 | U | The system shall count no blank line of the region box as skipped. |
| R-RPT-ADDENDUM-002.2 | When | When the system writes a report with declared regions, the system shall write the addendum of CTX-RPT-ADDENDUM after the last reported variant. |
| R-RPT-ADDENDUM-002.3 | If | If a report has no declared region, then the system shall write no addendum. |
| R-RPT-ADDENDUM-002.4 | When | When the system writes a declared region in the addendum, the system shall list its hit lines in hit order over all reported variants. |
| R-RPT-ADDENDUM-002.5 | U | The system shall take an address as in a declared region when it is at least start and at most end. |
| R-RPT-ADDENDUM-002.6 | If | If a declared region has no hit, then the system shall write `None.` under its heading. |
| R-RPT-ADDENDUM-002.7 | When | When a hit lies in several declared regions, the system shall list it under each of them. |
| R-TUI-098.1 | If | If more than 200 hits of one kind fall in one declared region, then the system shall list the first 200 of that kind in hit order. |
| R-TUI-098.2 | If | If more than 200 hits of one kind fall in one declared region, then the system shall add under that region `> TRUNCATED: <kind> hits in this region were capped at 200; <n> more not listed (variants affected: <variants>).` |
| R-TUI-098.3 | When | When the system writes such a notice, the system shall name in `<variants>` the first 8 variants that lost a hit of that kind, then `+<k> more` for the others. |

`<kind>`: modification · change-file issue · check-file issue. Keeping the regions for the next project save, the pre-filled box and the manifest form are S11's (R-RPT-REGION-PERSIST-001.x, 002.x, R-RPT-ADDENDUM-PERSIST-001.x).

#### S12.10 · Report filter: reading a filter file (CTX-RPT-FILTER)

Each diagnostic row's message is one of the diagnostics the refusal status of R-RPT-FILTER-001.19 lists.

| Id | Form | Requirement |
|---|---|---|
| R-RPT-FILTER-001.18 | When | When the system generates a project report with a filter selected, the system shall read the filter file again. |
| R-RPT-FILTER-001.22 | If | If the filter path names no file, then the system shall give the diagnostic `report filter path could not be resolved: <path>`. |
| R-RPT-FILTER-001.23 | If | If the filter path is a link, then the system shall give the diagnostic `report filter path is a symlink and was refused: <path>`. |
| R-RPT-FILTER-001.24 | If | If the filter path names something that is not a regular file, then the system shall give the diagnostic `report filter path is not a regular file: <path>`. |
| R-RPT-FILTER-001.25 | If | If the filter file is larger than 4,194,304 bytes, then the system shall give the diagnostic `report filter file is <n> bytes, over the 4194304-byte read cap — the file was not read`. |
| R-RPT-FILTER-001.26 | If | If the filter file is larger than 4,194,304 bytes, then the system shall read none of its content. |
| R-RPT-FILTER-001.27 | If | If the filter file is not UTF-8, then the system shall give the diagnostic `report filter file is not valid UTF-8: <error>`. |
| R-RPT-FILTER-001.28 | If | If the filter file cannot be read, then the system shall give the diagnostic `report filter file could not be read: <error>`. |
| R-RPT-FILTER-001.29 | If | If the filter text is not JSON, then the system shall give the diagnostic `report filter is not valid JSON: <error>`. |
| R-RPT-FILTER-001.30 | If | If the top level of the filter text is not a JSON object, then the system shall give the diagnostic `report filter top level must be a JSON object`. |
| R-RPT-FILTER-001.31 | If | If `format` is missing or is not `s19app-report-filter`, then the system shall give the diagnostic `'format' must be 's19app-report-filter', got <value>`. |
| R-RPT-FILTER-001.32 | If | If `version` is missing or is not `1.0`, then the system shall give the diagnostic `'version' must be '1.0', got <value>`. |
| R-RPT-FILTER-001.33 | If | If the top level has a key other than `format`, `version` and `include`, then the system shall give the diagnostic `unknown top-level key <key>` for that key. |
| R-RPT-FILTER-001.34 | If | If `include` is not a JSON object, then the system shall give the diagnostic `'include' must be a JSON object`. |
| R-RPT-FILTER-001.35 | If | If `include` has a key other than `symbols` and `addresses`, then the system shall give the diagnostic `unknown 'include' key <key>` for that key. |
| R-RPT-FILTER-001.36 | If | If `include.symbols` is not a list, then the system shall give the diagnostic `'include.symbols' must be a list`. |
| R-RPT-FILTER-001.37 | If | If `include.symbols` holds more than 4096 patterns, then the system shall give the diagnostic `'include.symbols' declares <n> patterns, over the 4096-pattern ceiling`. |
| R-RPT-FILTER-001.38 | If | If a pattern is not text, then the system shall give the diagnostic `'include.symbols[<i>]' must be a string, got <value>`. |
| R-RPT-FILTER-001.39 | If | If `include.addresses` is not a list, then the system shall give the diagnostic `'include.addresses' must be a list`. |
| R-RPT-FILTER-001.40 | If | If `include.addresses` holds more than 4096 ranges, then the system shall give the diagnostic `'include.addresses' declares <n> ranges, over the 4096-range ceiling`. |
| R-RPT-FILTER-001.41 | If | If a range is not a JSON object, then the system shall give the diagnostic `'include.addresses[<i>]' must be a JSON object`. |
| R-RPT-FILTER-001.42 | If | If a range's start or end is true or false, then the system shall give the diagnostic `'<field>' must be an integer or '0x' hex string, got a boolean`. |
| R-RPT-FILTER-001.43 | If | If a range's start or end is text starting with `0x` that is not hexadecimal, then the system shall give the diagnostic `'<field>' is not a parsable hex string: <value>`. |
| R-RPT-FILTER-001.44 | If | If a range's start or end is missing, or is neither a whole number nor text starting with `0x`, then the system shall give the diagnostic `'<field>' must be an integer or '0x' hex string, got <value>`. |
| R-RPT-FILTER-001.45 | If | If a range's start is below 0, then the system shall give the diagnostic `'include.addresses[<i>].start' (<start>) is outside the pinned address domain (must be >= 0)`. |
| R-RPT-FILTER-001.46 | If | If a range's end is above 2^32, then the system shall give the diagnostic `'include.addresses[<i>].end' (0x<end>) is outside the pinned address domain (must be <= 2^32)`. |
| R-RPT-FILTER-001.47 | If | If a range's start is not below its end, then the system shall give the diagnostic `'include.addresses[<i>]': 'start' (0x<start>) must be less than 'end' (0x<end>) — 'end' is exclusive`. |
| R-RPT-FILTER-001.48 | When | When the system reads a filter text, the system shall give one diagnostic per fault it finds. |
| R-RPT-FILTER-001.49 | If | If a filter file has no `include`, `symbols` or `addresses` key, then the system shall read that key as an empty list. |

#### S12.11 · Report filter: selection and use (CTX-RPT-FILTER)

| Id | Form | Requirement |
|---|---|---|
| R-RPT-FILTER-001.1 | When | When the system opens the Reports dialog, the system shall list in the filter dropdown the `.json` files of the filters folder, sorted by name. |
| R-RPT-FILTER-001.2 | If | If a `.json` file of the filters folder is a link, then the system shall leave it out of the filter dropdown. |
| R-RPT-FILTER-001.3 | U | The system shall show filter file names in the filter dropdown as plain text, never as markup. |
| R-RPT-FILTER-001.4 | When | When the operator picks a filter file in the dropdown, the system shall make it the filter selection. |
| R-RPT-FILTER-001.5 | When | When the operator makes a filter file the filter selection, the system shall show the status `Report filter: <file name>`. |
| R-RPT-FILTER-001.6 | When | When the operator picks the blank option of the dropdown, the system shall clear the filter selection. |
| R-RPT-FILTER-001.7 | When | When the operator clears the filter selection, the system shall show the status `Report filter: none (full report)`. |
| R-RPT-FILTER-001.8 | When | When the operator submits a filter path, the system shall find the file by the path-input rules of S5.3. |
| R-RPT-FILTER-001.9 | If | If the submitted filter path names no file, then the system shall show the status `Filter path not found: <path>`. |
| R-RPT-FILTER-001.10 | If | If the submitted filter path is a link, then the system shall show the status `Filter path is a symlink - refused: <path>`. |
| R-RPT-FILTER-001.11 | If | If the submitted filter path names something that is not a file, then the system shall show the status `Filter path is not a file: <path>`. |
| R-RPT-FILTER-001.12 | If | If the system refuses a submitted filter path, then the system shall keep the filter selection it had. |
| R-RPT-FILTER-001.13 | When | When the system accepts a submitted filter path, the system shall make that file the filter selection. |
| R-RPT-FILTER-001.14 | When | When the operator submits a blank filter path, the system shall clear the filter selection. |
| R-RPT-FILTER-001.15 | When | When the system opens the Reports dialog while the filter selection is a file of the filters folder, the system shall show that file in the dropdown. |
| R-RPT-FILTER-001.58 | When | When the system opens the Reports dialog while the filter selection is a file outside the filters folder, the system shall show its path in the filter path box. |
| R-RPT-FILTER-001.16 | When | When the system loads a project, a file or a variant, or saves a project, the system shall clear the filter selection. |
| R-RPT-FILTER-001.17 | U | The system shall apply the filter selection to every project report until the selection changes. |
| R-RPT-FILTER-001.19 | If | If a filter file gives a diagnostic when the operator generates a project report, then the system shall show the status `Project report refused: <diagnostics>` with the diagnostics separated by `; `. |
| R-RPT-FILTER-001.20 | If | If the system refuses a project report for its filter, then the system shall write no report file. |
| R-RPT-FILTER-001.21 | If | If the system refuses a project report for its filter, then the system shall run no variant. |
| R-RPT-FILTER-001.50 | U | The system shall match an entry against the filter as CTX-RPT-FILTER "item match" defines it. |
| R-RPT-FILTER-001.51 | When | When the system writes a filtered report, the system shall write only the Modifications rows that match the filter. |
| R-RPT-FILTER-001.52 | When | When the system writes a filtered report, the system shall write only the Checklists rows that match the filter. |
| R-RPT-FILTER-001.53 | When | When the system writes a filtered report, the system shall dump only the windows of the applied entries that match the filter. |
| R-RPT-FILTER-001.54 | When | When the system writes a filtered report, the system shall write the filter block of CTX-RPT-FILTER right after the title. |
| R-RPT-FILTER-001.55 | If | If no item of a variant's Modifications, Checklists or Memory regions section matches the filter, then the system shall write the zero-match text in place of that section's content. |
| R-RPT-FILTER-001.56 | When | When the system writes a filtered report, the system shall write every section other than the filtered parts in full. |
| R-RPT-FILTER-001.57 | U | The system shall write the filter file name in the filter block as report-safe text. |

The same filter selection drives the before/after report, and the A↔B diff report ignores it: those rows are S14's.

#### S12.12 · The Reports dialog and the report view (CTX-RPT-DIALOG)

| Id | Form | Requirement |
|---|---|---|
| R-RPT-002.1 | When | When the operator asks for the Reports dialog with a project open, the system shall open the Reports dialog of CTX-RPT-DIALOG. |
| R-RPT-002.2 | If | If no project is open when the operator asks for the Reports dialog, then the system shall show the status `Reports: no active project - load a project first.` |
| R-RPT-002.3 | When | When the system opens the Reports dialog, the system shall list the project's report files in the list order of CTX-RPT-DIALOG. |
| R-RPT-002.4 | If | If the project has no report file, then the system shall show the empty text of CTX-RPT-DIALOG in place of the report list. |
| R-RPT-002.5 | When | When the operator selects a report file in the list, the system shall show it in the report view, rendered as Markdown. |
| R-RPT-002.6 | If | If the selected file is larger than the viewer cap, then the system shall show the too-large text in the report view. |
| R-RPT-002.7 | If | If the selected file cannot be read, then the system shall show the unreadable text in the report view. |
| R-RPT-002.8 | If | If the selected file holds a byte sequence that is not UTF-8, then the system shall show `�` in its place. |
| R-RPT-002.9 | When | When the operator clicks a link in the report view, the system shall open nothing. |
| R-RPT-002.10 | U | The system shall show a bare web address in the report view as text, not as a link. |
| R-RPT-002.11 | U | The system shall show raw HTML in the report view as text. |
| R-RPT-002.27 | While | While the screen is at least 80 columns wide, the system shall show the whole Reports dialog, the filter row and Generate new report included. |
| R-RPT-CHIP.1 | When | When the operator presses the `📂 Open reports/` chip of the Reports dialog, the system shall open `<project>/reports/` in the system's file manager. |

The key that opens the dialog (`t`, every window) is S6's; Escape, focus, and the plain-text rule for the report list are S7's (R-DLG.2, R-DLG.7, R-DLG.13); the Reports help window is S7's (R-WHELP.6). R-RPT-CHIP.1 comes from S0 HLR-139; the chip mechanism itself has no rows yet (passed to S5).

#### S12.13 · Generating a report (CTX-RPT-RUN)

| Id | Form | Requirement |
|---|---|---|
| R-RPT-002.12 | When | When the operator presses Generate new report with a whole number in the context-bytes box, the system shall close the Reports dialog. |
| R-RPT-002.13 | If | If the context-bytes box does not hold a whole number when the operator presses Generate new report, then the system shall show the status `Report rejected: context_bytes must be an integer in 0..4096, got '<text>' - the value is rejected, not clamped`. |
| R-RPT-002.14 | If | If the context bytes are outside 0 … 4096, then the system shall show the status `Report rejected: context_bytes must be an integer in 0..4096, got <n> - the value is rejected, not clamped`. |
| R-RPT-002.15 | If | If the open project has no variant when the operator generates a report, then the system shall show the status `Report: no project variants - load a project first.` |
| R-RPT-002.16 | When | When the kept execution belongs to the open project, the system shall build the report from it. |
| R-RPT-002.17 | When | When the system builds a report from the kept execution, the system shall show the status `Report: generating from last execution...`. |
| R-RPT-002.18 | If | If no kept execution belongs to the open project, then the system shall build the report from a new run. |
| R-RPT-002.19 | When | When the system starts a new run for a report, the system shall show the status `Report: no prior execution - running active scope...`. |
| R-RPT-002.20 | If | If no kept execution belongs to the open project, the project has no `project.json` and no change or check document is loaded, then the system shall show the status `Report: no manifest and no loaded change/check file - nothing to report.` |
| R-RPT-002.21 | U | The system shall keep the screen responsive while it builds and writes a project report. |
| R-RPT-002.22 | When | When the system has written a report, the system shall show the status `Report: reports/<file name>`. |
| R-RPT-002.23 | When | When the system has written a report, the system shall drop the kept execution. |
| R-RPT-002.24 | If | If the new run or the writing of the report fails, then the system shall show the status `Report failed: <error type>: <reason>`. |
| R-RPT-002.25 | If | If the system rejects a report or the report fails, then the system shall leave no report file. |
| R-RPT-002.26 | If | If the system rejects a report or the report fails, then the system shall keep the kept execution. |

**(from batch-100 HLR-177a: LLR-177.3i)** Keeping the declared regions for the next project save is S11's (R-RPT-REGION-PERSIST-001.1); this row is the exception while a session action runs.

| Id | Form | Requirement |
|---|---|---|
| R-RPT-002.28 | While | While a file load, an A2L load, a project load or a Save project runs, the system shall keep the session's declared regions unchanged when the operator presses Generate new report. |

#### S12.14 · Progress and log (CTX-RPT-RUN)

| Id | Form | Requirement |
|---|---|---|
| R-RPT-LOG.1 | When | When the system starts a project report, the system shall show the report progress line at step 1. |
| R-RPT-LOG.2 | When | When the system starts writing a project report after its run is ready, the system shall move the report progress line to step 2. |
| R-RPT-LOG.3 | When | When the system has written a project report, the system shall end the report's long action (S6 CTX-BUSY) once. |
| R-RPT-LOG.4 | If | If the system rejects a project report or the report fails, then the system shall end the report's long action (S6 CTX-BUSY) once. |
| R-RPT-LOG.5 | When | When the system has written a report, the system shall log at INFO the log line with outcome `ok`. |
| R-RPT-LOG.6 | If | If the system rejects a report, then the system shall log at WARNING the log line with outcome `rejected: <reason>`. |
| R-RPT-LOG.7 | If | If a report fails, then the system shall log at WARNING the log line with outcome `failed: <error type>`. |
| R-RPT-LOG.8 | If | If a report fails, then the system shall write the error's traceback to the log. |
| R-RPT-LOG.9 | If | If the system refuses a project report before it runs (no variant, nothing to report, filter refused), then the system shall log at WARNING the log line with outcome `refused: <status text>`. |



<a id="s13"></a>

## S13 · Operations & CRC

### Context notes (informative)

#### CTX-OPS · The Operations dialog (S13.1, S13.3 … S13.5)

```text
Operations dialog   A dialog (S7 CTX-DIALOG), title "Operations:". From the top:
  operation list    One row per operation, "<id> - <title>":
                      crc - CRC
  CRC controls      Shown while the crc row is selected:
                      label "CRC config (editable JSON):"
                      config path box   hint "config file path (.json)"
                      Load config button
                      config editor     multi-line text box (S7 CTX-PASTE)
  result area       The result text, then a hex view (S4) of at most 512 rows.
  buttons           Execute (confirm button) · Write CRC · Close
load error text     "CRC config load error:", then the reason on the next line.
config error text   "CRC config error - no check was run:", then the reason on the
                    next line.
CRC write           Dialog titled "Write the computed CRC(s) into a new modified S19
confirmation        under the work area?"; buttons "Width: <n> bytes/line" · Confirm ·
                    Cancel.
record width        Data bytes per S19 data record of the written file: 32 or 16.
internal error      A fault that is none of the reasons this chapter lists (a program
                    defect).
```

#### CTX-CRC · The CRC model and the algorithms (S13.2, S13.6, S13.7)

```text
parametric model  Every CRC here is defined by these parameters:
  width           register size in bits
  poly            generator polynomial, normal form (the top bit is left out)
  init            register value before the first byte, not reflected
  refin           true: each input byte is taken low bit first
  refout          true: the register is reflected before the final XOR
  xorout          value XORed into the register at the end
  check           the CRC of the 9 ASCII bytes "123456789" (0x31 … 0x39)
algorithms
  name                width  poly                init                refin  refout xorout              check
  CRC-8/SMBUS            8   0x07                0x00                false  false  0x00                0xF4
  CRC-16/CCITT-FALSE    16   0x1021              0xFFFF              false  false  0x0000              0x29B1
  CRC-16/MODBUS         16   0x8005              0xFFFF              true   true   0x0000              0x4B37
  CRC-16/XMODEM         16   0x1021              0x0000              false  false  0x0000              0x31C3
  CRC-32/ISO-HDLC       32   0x04C11DB7          0xFFFFFFFF          true   true   0xFFFFFFFF          0xCBF43926
  CRC-32C/Castagnoli    32   0x1EDC6F41          0xFFFFFFFF          true   true   0xFFFFFFFF          0xE3069283
  CRC-64/XZ             64   0x42F0E1EBA9EA3693  0xFFFFFFFFFFFFFFFF  true   true   0xFFFFFFFFFFFFFFFF  0x995DC9BBDF1939FA
  CRC-32/BZIP2          32   0x04C11DB7          0xFFFFFFFF          false  false  0xFFFFFFFF          0xFC891918
  The first seven are the CRC Designer's presets, in its order. CRC-32/BZIP2 is a
  reference only (no preset). CRC-32/ISO-HDLC is the zlib / PKZIP CRC-32.
operation model   The CRC operation: width 32; config key polynomial = poly, init = init,
                  reverse = refin and refout together, final_xor = xorout. Defaults:
                  CRC-32/ISO-HDLC.
Designer model    The CRC Designer: width 8 to 64; refin and refout set one by one.
                  The two surfaces share no setting: a CRC Designer template is not a
                  CRC config, and the CRC operation cannot use one.
span              A half-open address range [start, end): start is in it, end is not.
present byte      An address of a span that holds a byte in the image.
absent byte       An address of a span that holds no byte in the image.
CRC input         Of a span: its present bytes in ascending address order; nothing for
                  an absent byte. Of a target (CTX-CRCCONFIG): the CRC inputs of its
                  spans in declared order, as one byte stream.
stored field      N bytes from the output address up: byte i is at output address + i
                  and holds bits 8i … 8i+7 (little-endian, low byte first).
                  N is the field width (CTX-CRCCONFIG).
stored value      The number the N bytes of the stored field hold, low byte first;
                  none while one of the N bytes is absent.
field value       The CRC's low 8N bits: the low byte(s) for N = 1 or 2, the CRC for
                  N = 4, the CRC with four 0x00 high bytes for N = 8.
field hex         0x and 2N uppercase hexadecimal digits.
widths            Three different widths:
                  CRC width      bits of the register, 8 to 64 (32 in the operation)
                  field width    N, bytes of the stored field, 1, 2, 4 or 8
                  record width   S19 data bytes per record of a written file, 16 or 32
stage words       check   compute and compare with the stored value; changes nothing
                  write   put the field values into a copy and write it as a file
                  verify  read the written file back (S8.8)
                  self-test  the CRC Designer's comparison of Check with the CRC of
                          "123456789" (not the S9 Checks)
```

#### CTX-CRCCONFIG · The CRC config (S13.3)

```text
CRC config        A JSON object:
  polynomial      number, required
  init            number, required
  reverse         true or false, required
  final_xor       number, required
  regions         list of regions; may be empty or left out
  groups          list of groups; may be empty or left out
                  At least one of regions and groups holds an entry.
region            {"start", "end", "output_address"}: one span, field width 4.
group             {"regions": list of {"start", "end"} spans (at least one),
                   "output_address", "output_bytes"}: one CRC over all its spans.
                  output_bytes is 1, 2, 4 or 8; 4 when left out.
target            A region or a group: one CRC, one stored field at output_address.
target order      The regions in config order, then the groups in config order.
number            A JSON integer (decimal), or a JSON string of hexadecimal digits with
                  or without 0x (the string "10" is 16).
span rules        start ≥ 0; end > start; end ≤ 0x100000000;
                  output_address ≥ 0; output_address + N ≤ 0x100000000.
span limit        At most 4096 spans in all (regions plus group spans).
parameter range   polynomial, init and final_xor: 0x0 … 0xFFFFFFFF.
read limit        256 MiB (268,435,456 bytes), the same as S5's copy limit.
example config    The text the config editor starts with (a copy is
                  examples/crc_config.example.json). All values are dummies:
                  CRC-32/ISO-HDLC parameters;
                  regions [0x10000, 0x1FFFC) → field at 0x1FFFC,
                          [0x20000, 0x2FFFC) → field at 0x2FFFC;
                  one group of [0x30000, 0x34000) and [0x40000, 0x42000) → field at
                  0x42000, 4 bytes.
rule texts        The <rule text> of R-CRC-CONFIG-001.10. <where> is "region <i>" or
                  "group <k> span <j>"; i, k and j count from 1.
  field 'reverse' must be a boolean
  field 'regions' must be a list
  field 'groups' must be a list
  at least one of 'regions' / 'groups' must be present and non-empty
  region <i> must be a JSON object
  group <k> must be a JSON object
  group <k>: field 'regions' must be a list
  group <k>: field 'regions' must not be empty
  group <k> span <j> must be a JSON object
  group <k> span <j>: 'output_address' is not allowed inside a group span (a group has exactly one output_address)
  <where>: 'start' must be non-negative
  <where>: 'end' (0x<end>) exceeds the 32-bit address space
  <where>: 'end' (0x<end>) must be greater than 'start' (0x<start>)
  group <k>: 'output_bytes' must be one of [1, 2, 4, 8], got <value>
  region <i> / group <k>: 'output_address' must be non-negative
  region <i> / group <k>: output window [0x<address>, 0x<address>+<N>) exceeds the 32-bit address space
  config declares <n> spans, over the 4096-span ceiling
```

#### CTX-CRCRESULT · What the result area shows (S13.4, S13.5)

```text
check result      status: ok   or   status: error
                  CRC: <n> region(s): <m> matched, <k> mismatched, <j> no-stored-value
                  the notes, in this order: coverage notes, truncation notes, overlap
                  notes, the empty-target note
                  one region line per target, in target order
region line       region @ 0x<output address, 8 digits>: computed <field hex of the
                  CRC>, stored <stored> -> <verdict>
  <stored>        the field hex of the stored value, or (absent)
  <verdict>       MATCH · MISMATCH · no stored value
write result      verified   status: ok
                             wrote <path> (verified)
                             one write line per target
                  mismatch   VERIFY MISMATCH - the written image did not verify:
                             wrote <path> but it did not verify (verify status: mismatch)
                             one write line per target
                  failed     WRITE FAILED - no file was written:
                             <finding>
                             one region line per target (the check's verdicts)
write line        region @ 0x<output address, 8 digits>: wrote <field hex of the field
                  value> (<N> LE bytes)
CRC file          <work area>/crc/<stem of the primary>-crc.s19, or its numbered name
                  (S5 CTX-WORKAREA).
```

#### CTX-DESIGNER · The CRC Designer (S13.6 … S13.9)

```text
CRC Designer      Rail screen (S6: key 0). Header "CRC Designer" with the ? chip and the
                  📂 Open templates/ chip (S5, S7). Then, from the top:
  help line       CRC Designer (preview-only): pick a preset or edit the parameters;
                  presets are read-only starting points.
  top row         the coverage window (two thirds of the width) · the Warnings group
  bench           three columns:
                    1  Algorithm: Preset · Width (bits) · Polynomial · Init ·
                       Reflection  in [toggle]  out [toggle] · XOR out · Check ·
                       Self-test  123456789  <verdict>
                    2  Coverage · preview-only: Ranges · Intra gap · Join gaps ·
                       Pad byte · On conflict · the coverage preview;
                       Store placement: Address · Bytes · Store endianness
                    3  Custom test vector: Mode · Vector · CRC;
                       Template: Name · Aliases;
                       Load / Save: Load path · Save · Load · the Load / Save status
  JSON strip      Full width, below the bench: the template file of the form.
narrow            While the terminal is narrow (S6), the top row and the three columns
                  stack one under the other.
result surfaces   The self-test verdict, the custom-vector CRC, the JSON strip, the
                  Warnings, the coverage preview and the coverage window.
verdict           ✓ MATCH (green) · ✗ MISMATCH (red) · ○ NO-EXPECTED (grey); S3 palette.
fields            Width: decimal. Polynomial, Init, XOR out, Check, Address, Pad byte:
                  hexadecimal, 0x optional; empty reads as 0, except Check (empty = no
                  expected value) and Pad byte (empty = 0xFF).
shown CRC         0x and uppercase hexadecimal, 2 digits per byte of ceil(width / 8)
                  bytes (coverage values: per byte of Bytes).
coverage target   Ranges: "start-end, start-end, …", hexadecimal spans in declared
                  order, with:
  Intra gap       skip: absent bytes inside a range are left out
                  fill: they read as the pad byte
  Join gaps       concat: the ranges follow one another
                  fill: the addresses between two ranges read as the pad byte
  On conflict     abort · warn · ignore: what to do on a gap conflict
  Store placement the preview's stored field: Address, Bytes (1 to 8), Store
                  endianness (little or big)
  coverage rules  the span rules of CTX-CRCCONFIG; pad byte 0x00 … 0xFF; Bytes 1 … 8
gap conflict      A present byte in a space Join gaps fills, whose value differs from
                  the pad byte.
concat CRC        The coverage target's CRC with Join gaps = concat.
fill CRC          The coverage target's CRC with Join gaps = fill.
coverage window   Line 1: one bar of block glyphs, ranges in the accent colour and gaps
                  in grey (concat) or pale yellow (fill), scaled so the whole target
                  takes at most about 48 glyphs.
                  Line 2: concat <concat CRC>   fill <fill CRC>
                  Line 3: store <stored-field bytes of the active CRC, hex pairs>
template          A CRC Designer algorithm with a name and aliases.
template file     <clean name (S11 CTX-SAVE)>.crc.json:
                  {"schema_version": 1, "name", "aliases": [...], "operation": "crc",
                   "algorithm": {"width", "poly", "init", "refin", "refout", "xorout",
                   "check" (or null)}}; numbers as 0x hexadecimal strings.
template home     <project>/templates/ while a project is open; otherwise
                  .s19tool/templates/ (beside the work area, S5 CTX-WORKAREA).
template reasons  CRC template path could not be resolved: '<path>'
                  CRC template file is over the 268435456-byte read cap — not read
                  CRC template file could not be read: <reason>
                  CRC template is not valid JSON: <parser message>
                  CRC template top level must be a JSON object
                  CRC template is structurally invalid: <rule>
                    (rules: a non-empty name; width 8 to 64; refin and refout true or
                    false; every algorithm field present)
```

---

### Requirements


#### S13.1 · The Operations dialog (CTX-OPS)

| Id | Form | Requirement |
|---|---|---|
| R-OPS-003.1 | When | When the operator presses `x` while a primary is loaded, the system shall open the Operations dialog. |
| R-OPS-003.2 | If | If no primary is loaded when the operator presses `x`, then the system shall show the status `Operations: no file loaded - load a file first.` |
| R-OPS-003.3 | If | If no primary is loaded when the operator presses `x`, then the system shall open no dialog. |
| R-OPS-002.1 | U | The system shall list in the operation list one row per operation of CTX-OPS. |
| R-OPS-003.4 | When | When the Operations dialog opens, the system shall select the first row of the operation list. |
| R-OPS-003.5 | While | While the crc row is selected, the system shall show the CRC controls of CTX-OPS. |
| R-OPS-003.6 | When | When a CRC check ends, the system shall show under the result text the hex view (S4) of the primary's image. |
| R-OPS-003.7 | U | The system shall keep the screen responsive while it runs a CRC check or a CRC write. |
| R-OPS-003.8 | If | If the operator presses Execute while a CRC check runs, then the system shall show only the result of the later press. |
| R-OPS-003.9 | If | If the operator confirms a CRC write while another CRC write runs, then the system shall show only the result of the later write. |
| R-OPS-003.11 | If | If a CRC check fails with an internal error, then the system shall show `CRC operation failed: <error type>: <message>` in the result area. |
| R-OPS-003.12 | If | If a CRC write fails with an internal error, then the system shall show `CRC write failed: <error type>: <message>` in the result area. |
| R-OPS-003.13 | U | The system shall show file-derived text in the Operations dialog as plain text, never as markup. |

#### S13.2 · Computing a CRC (CTX-CRC)

| Id | Form | Requirement |
|---|---|---|
| R-CRC-ENGINE-001.1 | U | The system shall compute each CRC of the CRC operation by the parametric model of CTX-CRC, with width 32 and the parameters of the CRC config. |
| R-CRC-ENGINE-002.1 | U | The system shall give, for the parameters of each 32-bit algorithm of CTX-CRC, that algorithm's check value as the CRC of "123456789". |
| R-CRC-ENGINE-001.2 | U | The system shall take into the CRC input of a span only the span's present bytes. |
| R-CRC-ENGINE-001.3 | U | The system shall take the present bytes of a span in ascending address order. |
| R-CRC-ENGINE-001.4 | U | The system shall add no byte to the CRC input for an absent byte. |
| R-CRC-ENGINE-001.5 | U | The system shall compute one CRC per target over the CRC inputs of its spans in declared order, without restarting between spans. |
| R-CRC-GROUP-001.1 | U | The system shall take a span into a group's CRC input once for each time the group declares it. |
| R-CRC-CONTRACT-001.1 | When | When the system checks CRCs, the system shall leave every byte of the loaded image unchanged. |
| R-CRC-CONTRACT-001.2 | When | When the system writes CRCs, the system shall leave every byte of the loaded image unchanged. |

#### S13.3 · The CRC config (CTX-CRCCONFIG)

| Id | Form | Requirement |
|---|---|---|
| R-CRC-CONFIG-001.1 | When | When the Operations dialog opens, the system shall fill the config editor with the example config of CTX-CRCCONFIG. |
| R-CRC-CONFIGLOAD-001.1 | When | When the operator presses Load config with a path in the config path box, the system shall replace the config editor's text with the text of the file. |
| R-CRC-CONFIGLOAD-001.2 | When | When the system has loaded a config file into the editor, the system shall show `Loaded CRC config from <path as typed>` in the result area. |
| R-CRC-CONFIGLOAD-001.3 | When | When the operator presses Load config, the system shall run no CRC check. |
| R-CRC-CONFIGLOAD-001.4 | U | The system shall find the config file the way S5.3 finds a path input. |
| R-CRC-CONFIGLOAD-001.5 | If | If the config path box is empty when the operator presses Load config, then the system shall show `CRC config load: enter a config file path first.` in the result area. |
| R-CRC-CONFIGLOAD-001.6 | If | If no file matches the config path, then the system shall show the load error text with the reason `CRC config path could not be resolved: '<path>'`. |
| R-CRC-CONFIGLOAD-001.7 | If | If the config file is larger than the read limit, then the system shall show the load error text with the reason `CRC config file is <n> bytes, over the 268435456-byte read cap — the file was not read`. |
| R-CRC-CONFIGLOAD-001.8 | If | If the config file is larger than the read limit, then the system shall read none of it. |
| R-CRC-CONFIGLOAD-001.9 | If | If the config file cannot be read, then the system shall show the load error text with the reason `CRC config file could not be read: <reason>`. |
| R-CRC-CONFIGLOAD-001.10 | If | If the config file cannot be loaded, then the system shall leave the config editor's text unchanged. |
| R-CRC-CONFIG-001.2 | When | When the operator presses Execute, the system shall read the CRC config from the config editor's text. |
| R-CRC-CONFIG-001.3 | U | The system shall read a number given as a JSON string as hexadecimal, with or without `0x`. |
| R-CRC-WIDTH-001.1 | U | The system shall give each region a field width of 4. |
| R-CRC-WIDTH-001.2 | U | The system shall give each group the field width its `output_bytes` names, or 4 when `output_bytes` is left out. |
| R-CRC-CONFIG-001.4 | If | If the config editor's text is not a valid CRC config when the operator presses Execute, then the system shall show the config error text of CTX-OPS with one reason. |
| R-CRC-CONFIG-001.5 | If | If the config editor's text is not a valid CRC config when the operator presses Execute, then the system shall run no CRC check. |
| R-CRC-CONFIG-001.6 | If | If the config editor's text is not a valid CRC config when the operator presses Execute, then the system shall show no hex view in the result area. |
| R-CRC-CONFIG-001.7 | If | If the config text is not JSON, then the system shall give the reason `CRC config is not valid JSON: <parser message>`. |
| R-CRC-CONFIG-001.8 | If | If the top level of the config text is not a JSON object, then the system shall give the reason `CRC config top level must be a JSON object`. |
| R-CRC-CONFIG-001.9 | If | If the CRC config breaks a rule of CTX-CRCCONFIG, then the system shall give the reason `CRC config is structurally invalid: <rule text>` with that rule's text. |
| R-CRC-CONFIG-001.10 | If | If a required field is missing, then the system shall give the reason `CRC config is structurally invalid: field '<name>' is missing`. |
| R-CRC-CONFIG-001.11 | If | If a number field holds something other than a number of CTX-CRCCONFIG, then the system shall give the reason `CRC config is structurally invalid: field '<name>' is not a number: <value>`. |
| R-CRC-CONFIG-001.12 | If | If the CRC config breaks more than one rule, then the system shall give the reason of the first rule it finds only. |
| R-CRC-CONFIG-001.13 | If | If a region breaks a span rule of CTX-CRCCONFIG, then the system shall reject the config with that rule's text. |
| R-CRC-CONFIG-001.14 | If | If polynomial, init or final_xor is outside the parameter range, then the system shall give the reason `CRC config is structurally invalid: field '<name>' must be 0x0..0xFFFFFFFF`. |
| R-CRC-CONFIG-001.15 | If | If the config declares more spans than the span limit, then the system shall give the reason `CRC config is structurally invalid: config declares <n> spans, over the 4096-span ceiling`. |

#### S13.4 · The CRC check (CTX-CRCRESULT)

| Id | Form | Requirement |
|---|---|---|
| R-CRC-CHECK-001.1 | When | When the operator presses Execute with a valid CRC config, the system shall compute one CRC per target, in target order. |
| R-CRC-CHECK-001.2 | If | If a byte of a target's stored field is absent, then the system shall give the target the verdict `no stored value`. |
| R-CRC-CHECK-001.3 | When | When a target's stored value equals its field value, the system shall give the target the verdict `MATCH`. |
| R-CRC-CHECK-001.4 | If | If a target's stored value differs from its field value, then the system shall give the target the verdict `MISMATCH`. |
| R-CRC-CHECK-001.5 | When | When a CRC check ends, the system shall show the check result of CTX-CRCRESULT in the result area. |
| R-CRC-CHECK-001.6 | When | When a CRC check ends, the system shall show each region line with the field hex of the CRC and of the stored value. |
| R-CRC-WIDTH-001.3 | If | If a target's field width is less than 4, then the system shall add the note `CRC target at 0x<output address, 8 digits>: output bytes <N> truncates the 32-bit CRC to the low byte(s) — weakened error detection`. |
| R-CRC-GROUP-001.2 | If | If a target's stored field overlaps one of its own spans, then the system shall add the note `CRC target at 0x<output address, 8 digits>: output window overlaps one of its own input spans — a write invalidates the just-computed CRC`. |
| R-CRC-GROUP-001.3 | If | If a target's stored field overlaps a span of another target, then the system shall add for each such target the note `CRC target at 0x<output address, 8 digits>: output window overlaps another target's input span — that target's stored-vs-computed comparison becomes flash-order-dependent`. |
| R-CRC-WRITE-001.1 | When | When the Operations dialog opens, the system shall disable Write CRC. |
| R-CRC-WRITE-001.2 | When | When a CRC check ends with status `ok`, the system shall enable Write CRC. |
| R-CRC-WRITE-001.3 | If | If a CRC check ends with status `error`, then the system shall disable Write CRC. |
| R-CRC-WRITE-001.4 | If | If the config is invalid when the operator presses Execute, then the system shall disable Write CRC. |

#### S13.4b · Coverage of a target (from S0 HLR-159 / LLR-159.1)

| Id | Form | Requirement |
|---|---|---|
| R-CRC-CHECK-002.1 | If | If a region's span holds some of its bytes but not all, then the system shall add the note `CRC region 0x<start>-0x<end>: <n> absent byte(s) - the CRC covers present bytes only`. |
| R-CRC-CHECK-002.2 | If | If a group's spans hold some of their bytes but not all, then the system shall add the note `CRC group <k>: <n> absent byte(s) in declared span(s) <spans> — the CRC covers present bytes only`, <spans> being each span with an absent byte as `[0x<start>, 0x<end>)`, comma-separated. |
| R-CRC-CHECK-002.3 | If | If a target's spans hold no present byte, then the system shall end the check with status `error`. |
| R-CRC-CHECK-002.4 | If | If a target's spans hold no present byte, then the system shall add as last note `CRC region 0x<start>-0x<end> holds 0 image bytes - nothing written`, with the first span of the first such target. |

#### S13.5 · The CRC write (CTX-CRCRESULT; from S0 LLR-155.8)

| Id | Form | Requirement |
|---|---|---|
| R-CRC-WRITE-001.5 | When | When the operator presses Write CRC, the system shall open the CRC write confirmation of CTX-OPS. |
| R-CRC-RECWIDTH-001.1 | When | When the CRC write confirmation opens, the system shall set the record width to 32. |
| R-CRC-RECWIDTH-001.2 | When | When the operator presses the Width button, the system shall switch the record width between 32 and 16. |
| R-CRC-RECWIDTH-001.3 | When | When the record width changes, the system shall show the button label `Width: <record width> bytes/line`. |
| R-CRC-WRITE-001.6 | When | When the operator presses Cancel in the CRC write confirmation, the system shall write no file. |
| R-CRC-WRITE-001.7 | When | When the operator presses Confirm, the system shall read the CRC config from the config editor's text again. |
| R-CRC-WRITE-001.8 | If | If the config editor's text is not a valid CRC config when the operator presses Confirm, then the system shall show `CRC config error - nothing was written:` with the reason on the next line. |
| R-CRC-WRITE-001.9 | If | If the config editor's text is not a valid CRC config when the operator presses Confirm, then the system shall write no file. |
| R-CRC-WRITE-001.10 | When | When the operator confirms with a valid CRC config, the system shall compute the targets' CRCs again over the primary's image. |
| R-CRC-WRITE-001.11 | If | If a target's spans hold no present byte when the operator confirms, then the system shall write no file. |
| R-CRC-WRITE-001.12 | When | When the system writes CRCs, the system shall put each target's field value into its stored field in a copy of the primary's image. |
| R-CRC-WRITE-001.13 | If | If a stored field's addresses are outside every range of the image, then the system shall add them to the ranges of the copy. |
| R-CRC-WRITE-001.14 | When | When the system writes CRCs, the system shall write the copy as an S19 file (S8.7) under the CRC file name of CTX-CRCRESULT. |
| R-CRC-RECWIDTH-001.4 | When | When the system writes a CRC file, the system shall put at most the record width in data bytes in each data record. |
| R-CRC-WRITE-001.15 | If | If `crc/` holds a file with the same content under the CRC file's name or a numbered name, then the system shall use that file and write nothing. |
| R-CRC-WRITE-001.16 | If | If the CRC file's name is taken in `crc/` by a different content, then the system shall write under the lowest free numbered name. |
| R-CRC-WRITE-001.17 | When | When the system writes a CRC file of a primary whose S0 record has data, the system shall use that data as header data. |
| R-CRC-WRITE-001.18 | When | When the system writes a CRC file of a primary that has a terminator, the system shall write the address of the primary's terminator in the terminator. |
| R-CRC-WRITE-001.19 | When | When the system has written a CRC file, the system shall verify it against the copy as S8.8 says. |
| R-CRC-WRITE-001.20 | When | When the verify marks the CRC file verified, the system shall show the write result `verified` of CTX-CRCRESULT. |
| R-CRC-WRITE-001.21 | If | If the verify marks the CRC file mismatch, then the system shall show the write result `mismatch` of CTX-CRCRESULT. |
| R-CRC-WRITE-001.22 | If | If the system cannot place the CRC file, then the system shall show the write result `failed` with the finding `CRC write failed — no file was written: <error type>: <message>`. |
| R-CRC-WRITE-001.23 | If | If a target's spans hold no present byte when the operator confirms, then the system shall show the write result `failed` with the finding `CRC region 0x<start>-0x<end> holds 0 image bytes - nothing written`. |
| R-CRC-WRITE-001.24 | When | When the system shows a write line, the system shall show in it the field hex of the field value written. |
| R-CRC-WRITE-001.25 | When | When the system has written a CRC file, the system shall show under the result text the hex view of the copy. |
| R-CRC-WRITE-001.26 | If | If no CRC file is written, then the system shall keep the hex view of the check. |

#### S13.6 · The CRC Designer: algorithm and self-test (CTX-CRC, CTX-DESIGNER; from S0 LLR-122.4)

| Id | Form | Requirement |
|---|---|---|
| R-CRC-PRESET-001.1 | U | The system shall offer as presets the first seven algorithms of CTX-CRC, in that order. |
| R-CRC-PRESET-001.2 | When | When the CRC Designer is first shown, the system shall fill the algorithm fields with CRC-32/ISO-HDLC. |
| R-CRC-PRESET-001.3 | When | When the operator picks a preset, the system shall fill the algorithm fields with the preset's parameters. |
| R-CRC-PRESET-001.4 | When | When the operator picks a preset, the system shall fill Name with the preset's name. |
| R-CRC-PRESET-001.5 | When | When the operator picks a preset, the system shall empty Aliases. |
| R-CRC-PRESET-001.6 | When | When the operator picks a preset, the system shall set Bytes to ceil(width / 8) of the preset. |
| R-CRC-PRESET-001.7 | When | When the operator picks a preset, the system shall keep Address and Store endianness as they are. |
| R-CRC-PRESET-001.8 | When | When the operator edits a field filled from a preset, the system shall leave the preset unchanged. |
| R-CRC-DESIGNER-001.1 | U | The system shall compute every CRC of the CRC Designer by the parametric model of CTX-CRC. |
| R-CRC-DESIGNER-001.2 | When | When the operator changes a field of the CRC Designer, the system shall recompute every result surface of CTX-DESIGNER. |
| R-CRC-DESIGNER-002.1 | While | While Check holds the CRC of "123456789" under the form's algorithm, the system shall show the verdict `✓ MATCH`. |
| R-CRC-DESIGNER-002.2 | While | While Check holds another value, the system shall show the verdict `✗ MISMATCH`. |
| R-CRC-DESIGNER-002.3 | While | While Check is empty, the system shall show the verdict `○ NO-EXPECTED`. |
| R-CRC-DESIGNER-002.4 | If | If Width is outside 8 to 64, then the system shall show the verdict `⚠ Cannot compute: width <width> out of range [8, 64]`. |
| R-CRC-DESIGNER-002.5 | If | If an algorithm field does not hold a number, then the system shall show `Invalid parameters: <field> is not a number: <text>` in the self-test, the JSON strip, the coverage preview and the coverage window. |
| R-CRC-DESIGNER-003.1 | While | While Mode is `ascii`, the system shall show as custom-vector CRC the CRC of the UTF-8 bytes of Vector. |
| R-CRC-DESIGNER-003.2 | While | While Mode is `hex`, the system shall show as custom-vector CRC the CRC of the bytes the hexadecimal pairs of Vector give, whitespace left out. |
| R-CRC-DESIGNER-003.3 | If | If Mode is `hex` and Vector is not whole hexadecimal pairs, then the system shall show `Invalid vector: <reason>` as custom-vector CRC. |
| R-CRC-DESIGNER-004.1 | U | The system shall show in the JSON strip the template file of the current form. |
| R-CRC-DESIGNER-005.1 | If | If Bytes is less than ceil(width / 8), then the system shall show in Warnings `⚠ store width <Bytes> bytes < required <ceil(width / 8)> bytes (ceil(width/8)); the stored CRC will be truncated`. |
| R-CRC-DESIGNER-005.2 | If | If Intra gap or Join gaps is `fill` while Pad byte is empty, then the system shall show in Warnings `⚠ fill policy selected but pad_byte is unset; the filled bytes default to 0xFF — set an explicit pad byte`. |
| R-CRC-DESIGNER-005.3 | While | While no warning of the CRC Designer applies, the system shall show `✓ none` in Warnings. |

#### S13.7 · The CRC Designer: coverage preview (CTX-DESIGNER)

| Id | Form | Requirement |
|---|---|---|
| R-CRC-PREVIEW-001.1 | If | If no image is loaded, then the system shall show `Load an image to preview coverage CRCs over real bytes.` in the coverage preview and the coverage window. |
| R-CRC-PREVIEW-001.2 | While | While an image is loaded, the system shall show in the coverage preview the three lines `Active policy: join=<Join gaps>`, `concat: <concat CRC>`, `fill: <fill CRC>`. |
| R-CRC-PREVIEW-001.3 | While | While an image is loaded, the system shall show the coverage window of CTX-DESIGNER. |
| R-CRC-PREVIEW-001.4 | If | If Join gaps is `fill` with a gap conflict while On conflict is `abort`, then the system shall show in the coverage preview `Preview refused (on_gap_conflict=abort): <n> present byte(s) at <first 8 addresses as 0x<address>, comma-separated> conflict with a filled gap; no CRC shown.` |
| R-CRC-PREVIEW-001.5 | If | If Join gaps is `fill` with a gap conflict while On conflict is `abort`, then the system shall show `store — refused (on_gap_conflict=abort)` as line 3 of the coverage window. |
| R-CRC-PREVIEW-001.6 | If | If Join gaps is `fill` with a gap conflict while On conflict is `warn`, then the system shall add `gap-safety: <n> present byte(s) at <addresses> in a filled gap differ from pad_byte 0x<pad byte> — proceeding (on_gap_conflict=warn)` to the coverage preview. |
| R-CRC-PREVIEW-001.7 | If | If Join gaps is `fill` with a gap conflict while On conflict is `ignore`, then the system shall show the coverage preview with no gap note. |
| R-CRC-PREVIEW-001.8 | If | If a coverage field breaks a coverage rule of CTX-DESIGNER, then the system shall show `Invalid coverage: <reason>` in the coverage preview and the coverage window. |
| R-CRC-PREVIEW-001.9 | U | The system shall change no byte of the loaded image from the CRC Designer. |
| R-CRC-PREVIEW-001.10 | U | The system shall write no image file from the CRC Designer. |

#### S13.8 · The CRC Designer: templates (CTX-DESIGNER; from S0 LLR-122.4 and HLR-139)

| Id | Form | Requirement |
|---|---|---|
| R-CRC-TEMPLATE-001.1 | When | When the operator presses Save, the system shall write the template file of the form to `<template home>/<clean name>.crc.json`. |
| R-CRC-TEMPLATE-001.2 | When | When the system has saved a template, the system shall show `Saved template to <file name>` in the Load / Save status. |
| R-CRC-TEMPLATE-001.3 | When | When the operator saves a template whose file name exists in the template home, the system shall replace that file. |
| R-CRC-TEMPLATE-001.4 | If | If Check holds a value other than the CRC of "123456789" when the operator presses Save, then the system shall show `Saved <file name> with warning: check does not match the computed CRC of 123456789 (saved anyway)`. |
| R-CRC-TEMPLATE-001.5 | If | If the clean name of Name is empty when the operator presses Save, then the system shall show `Cannot save: template name is empty after sanitization; nothing written.` |
| R-CRC-TEMPLATE-001.6 | If | If the clean name of Name is empty when the operator presses Save, then the system shall write no file. |
| R-CRC-TEMPLATE-001.7 | If | If the clean name of Name is a device name (S11 CTX-SAVE) when the operator presses Save, then the system shall show `Cannot save: <clean name> is a reserved device name; nothing written.` |
| R-CRC-TEMPLATE-001.8 | If | If an algorithm field does not hold a number when the operator presses Save, then the system shall show `Cannot save: invalid parameters: <field> is not a number: <text>`. |
| R-CRC-TEMPLATE-001.9 | If | If the template file cannot be written, then the system shall show `Cannot save: <reason>`. |
| R-CRC-TEMPLATE-001.10 | When | When the operator presses Load with a path in Load path, the system shall fill the algorithm fields, Name and Aliases from the template file. |
| R-CRC-TEMPLATE-001.11 | When | When the system has loaded a template, the system shall show `Loaded template from file.` in the Load / Save status. |
| R-CRC-TEMPLATE-001.12 | When | When the system has loaded a template, the system shall record its file as the used template (S11 CTX-SAVE). |
| R-CRC-TEMPLATE-001.13 | U | The system shall find the template file the way S5.3 finds a path input. |
| R-CRC-TEMPLATE-001.14 | If | If Load path is empty when the operator presses Load, then the system shall show `Cannot load: enter a template path.` |
| R-CRC-TEMPLATE-001.15 | If | If the template file cannot be read, then the system shall show `Load failed: <reason>` with the first template reason of CTX-DESIGNER. |
| R-CRC-TEMPLATE-001.16 | If | If the template file cannot be read, then the system shall leave the form unchanged. |
| R-CRC-TEMPLATE-001.17 | When | When the operator presses the 📂 Open templates/ chip, the system shall open the template home in the system's file manager. |

#### S13.9 · The CRC Designer: layout and text (CTX-DESIGNER)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-100.1 | U | The system shall lay out the CRC Designer as CTX-DESIGNER shows. |
| R-TUI-100.2 | U | The system shall show the two Reflection toggles on one row, each after its own label `in` or `out`. |
| R-TUI-100.3 | U | The system shall show the Self-test row directly below Check. |
| R-TUI-100.4 | U | The system shall place no toggle of the CRC Designer directly below another toggle. |
| R-TUI-100.5 | While | While the terminal is narrow, the system shall stack the top row and the three bench columns one under the other. |
| R-CRC-DESIGNER-006.1 | U | The system shall show file-derived text in the CRC Designer as plain text, never as markup. |



<a id="s14"></a>

## S14 · A↔B compare & diff reports

### Context notes (informative)

#### CTX-COMPARE · Two images, runs, usage (S14.1 … S14.3)

```text
image A, image B  The two images the operator compares.
source            An open-project variant (S11 CTX-PROJECT), or an external path the
                  operator types, resolved as S5 resolves a path input (S5 S5.3).
same file         Both sides name the same variant, or the same typed text, or two
                  external paths that resolve to one file.
run               A maximal run of consecutive addresses that share one kind.
kind              changed   mapped in both images, the bytes differ
                  only A    mapped in image A only (report: "only in A")
                  only B    mapped in image B only (report: "only in B")
                  An address mapped in both with equal bytes is in no run.
run range         Today: 0x<start>-0x<end>, <end> one past the last byte (D14-16).
statistics        Per kind: the number of runs and the number of bytes.
label             A variant's id, or an external file's name.
artifact usage    Per image and per artifact (the loaded A2L, the loaded MAC):
                    absent   no such file is loaded
                    used     at least one of its addresses lies in the image's ranges
                    unused   loaded; none of its addresses lies in the image's ranges
                  A2L address: a tag with an integer address. MAC address: a record
                  with an integer address.
usage summary     both · one (a2l) · one (mac) · none (by the "used" statuses).
load failure      A side whose file is not empty but whose image has no byte.
```

#### CTX-DIFFSCREEN · The A2B Diff screen (S14.4 … S14.6)

```text
A2B Diff        Rail window (S6: position 8, key 7). Title "A2B Diff", then rows:
  row A         "A:", the A variant list, the "external path A" box
  row B         "B:", the B variant list, the "external path B" box
  check row     "Check spec:" and the check-spec list (S14.6)
  action row    Compare, Report, the box "report destination dir (no-project only)"
  status        One line, shown in full. At start: "Select two images and press Compare."
  run list      "Runs: <n>", "A artifacts: <summary>", "B artifacts: <summary>",
                "Keys: Up/Down move the selection", then one run row per shown run,
                then the cap line when runs were left out.
  windows       The image A window above the image B window.
  notice        Replaces the run list and the windows in the notice regime.
variant list    The open project's variant ids in variant order (S11), then
                "(external path below)"; with no open project, only the latter.
run row         <index, 3 wide> 0x<start, 8 hex>-0x<end, 8 hex> <changed|only A|only B>,
                coloured by kind.
display caps    At most 128 runs; runs are added while their bytes total at most
                2,097,152; the first run is always shown.
cap line        (showing <k> of <n> runs — full report is complete)
window          "Image A — Run #<i> 0x<start>-0x<end> <kind>" (B alike), then hex rows
                (S4 row format) from the 16-aligned address at or below start − 16 up
                to end + 16, grown to the window's height with the run centred; no
                address below 0.
page            The rows one window height shows; ] and [ move both windows a page.
regime          By terminal size, W columns × H rows:
  notice        W < 94 or H < 29
  wide          W ≥ 139 and H ≥ 29: the run list (26 columns) beside the windows
  narrow        94 ≤ W < 139 and H ≥ 29: the windows take the full width; the run
                list is an overlay 32 columns wide, hidden until f
notice text     "The A2B diff result windows need a larger terminal." then, one per
                failed axis, "  width <W> - needs at least 94 columns" and
                "  height <H> - needs at least 29 rows".
compare status  Compared <label A> vs <label B>: <n> runs.
                Compare refused: <reason>[; <reason>]
                Compare failed: <label>[, <label>] loaded no image (file has content
                but no valid records).
```

#### CTX-DIFFREPORT · The diff report (S14.7 … S14.8)

```text
diff report     A Markdown file and an HTML file with the same content, written together.
file name       <ts>-diff-report.md and <ts>-diff-report.html; <ts> = UTC time as
                YYYYMMDDTHHMMSSZ. If the name exists: <ts>-<NN>-diff-report.md,
                NN = 01 … 99, the first free one.
destination     With an open project: <project>/reports/. With none: the folder typed
                in the report destination box.
sections        In this order:
  header        "# Diff report"; "Generated (UTC)"; "Tool version"; per image: label,
                [source kind and variant id], path, parse-errors=<n>; per image:
                "artifacts: summary=<s>; a2l=<status> (<covered>/<total>); mac=…"
  Statistics    Classification · Runs · Bytes, one row per kind.
  Runs          Start · End · Length · Classification · Symbols, one row per run; or
                "No differing runs - the images are identical."
  Hex windows   Each run ± 64 bytes; windows 5 rows (80 bytes) or less apart merge.
                Per window: "### Run <range> (<kind>)" ("Runs …, …" when merged); a
                diff block (A rows as "-" lines, B rows as "+" lines) when a member
                is changed; then the A window and the B window. "No differing runs
                to dump." when there is no run.
  Flow change attribution   S14.8, only for a flow-written image B.
  Checks        S14.6, only with a check spec loaded.
symbols         The names of the loaded A2L tags and MAC records whose address lies in
                the run, comma-separated; "-" when none.
HTML form       One page: inline style only, no script, no external resource; every
                embedded value HTML-escaped; run kinds in three colours; A and B side
                by side with the changed bytes highlighted.
report status   Diff report written: <md path>  |  <html path>
                Report refused: <reason>
                Diff report failed: <error type>: <message>
                HTML report refused: <reason>
diff report progress line  The progress line (S6) of a diff report: label
                `Writing the diff report`; steps 1 `Write Markdown`, 2 `Write HTML`.
```

#### CTX-BEFOREAFTER · The before/after report (S14.9)

```text
before/after    A diff report (CTX-DIFFREPORT) of the loaded image's file (before, A)
report          against the saved patched file of the last save-back (after, B), with
                the stem before-after-report: <ts>-before-after-report.md / .html in
                <project>/reports/.
extra sections  After the header:
  provenance    "## Before/after provenance": original image (before), saved patched
                image (after), applied (UTC), change document or "(in-memory document)".
  linkage       "## Change-entry linkage": # · Type · Start · End · Disposition ·
                Linkage · Symbol · Before · After, one row per entry of the last apply;
                "No entries." when there is none.
bytes cell      "<hex bytes> |<ASCII>|"; "(none - created into hole)" when the entry had
                no prior bytes; "-" for no bytes.
  <hex bytes>   Two uppercase hex digits per byte, separated by one space.
  <ASCII>       One character per byte: the byte itself for 0x20 … 0x7E, "." for any
                other byte.
offer           A notification titled "Before/after report".
status          Before/after report written: <md path> | <html path>
                Before/after report refused: <reason>
                Before/after report failed: <error type>: <message>
before/after progress line  The progress line (S6) of a before/after report: label
                `Writing the before/after report`; one step, `Compose the report`.
```

---

### Requirements


#### S14.1 · Classifying two images (CTX-COMPARE)

| Id | Form | Requirement |
|---|---|---|
| R-CMP-001.1 | U | The system shall give every address mapped in either image exactly one kind of CTX-COMPARE or none. |
| R-CMP-001.2 | U | The system shall put no address that both images map with equal bytes into a run. |
| R-CMP-001.3 | U | The system shall join consecutive addresses of the same kind into one run. |
| R-CMP-001.4 | U | The system shall start a new run where the kind changes. |
| R-CMP-001.5 | U | The system shall list the runs in ascending start address. |
| R-CMP-001.6 | U | The system shall count, per kind, the runs and the bytes of its runs. |
| R-CMP-001.7 | When | When the system compares two images of 819,200 mapped bytes each (200 ranges of 4,096 bytes), the system shall classify them within 2.0 s. |

#### S14.2 · Sources, refusals and load failures (CTX-COMPARE)

| Id | Form | Requirement |
|---|---|---|
| R-CMP-002.1 | When | When the operator presses Compare, the system shall read both images from their files, not from the image loaded in the session. |
| R-CMP-002.2 | When | When a side names an open-project variant, the system shall read that variant's file. |
| R-CMP-002.3 | When | When a side names an external path, the system shall resolve it as S5 resolves a path input. |
| R-CMP-002.4 | When | When the system reads an external image whose name ends in `.hex` or `.ihex`, ignoring case, the system shall parse it as Intel HEX. |
| R-CMP-002.5 | When | When the system reads an external image whose name has any other ending, the system shall parse it as S19. |
| R-CMP-002.6 | If | If both sides name the same file, then the system shall refuse the compare with the status `Compare refused: both sides are the same file.` |
| R-CMP-002.7 | If | If no project is open and a side names a variant, then the system shall refuse the compare with the reason `No active project: cannot resolve variant '<id>'.` |
| R-CMP-002.8 | If | If a side names a variant that the open project does not have, then the system shall refuse the compare with the reason `Unknown project variant '<id>'.` |
| R-CMP-002.9 | If | If an external path names no file, then the system shall refuse the compare with the reason `Could not resolve external image path: <typed path>`. |
| R-CMP-002.10 | If | If reading an image raises an error, then the system shall refuse the compare with the reason `<error type>: <message>`. |
| R-CMP-002.11 | If | If both sides are refused, then the system shall show both reasons in one status, separated by `; `. |
| R-DIFF-LOADFAIL-001.1 | If | If a side is a load failure, then the system shall show the status `Compare failed: <label> loaded no image (file has content but no valid records).` |
| R-DIFF-LOADFAIL-001.2 | If | If both sides are load failures, then the system shall name both labels in that status, separated by `, `. |
| R-DIFF-LOADFAIL-001.3 | When | When a side's image has at least one byte, the system shall not report that side as a load failure. |
| R-CMP-002.12 | When | When a compare succeeds, the system shall show the status `Compared <label A> vs <label B>: <n> runs.` |
| R-DIFF-LOADFAIL-001.4 | U | The system shall show the A2B Diff status as plain text, never as markup. |

#### S14.3 · Artifact usage (CTX-COMPARE)

| Id | Form | Requirement |
|---|---|---|
| R-CMP-003.1 | When | When a compare succeeds, the system shall compute each image's artifact usage against the loaded A2L and the loaded MAC. |
| R-CMP-003.2 | If | If no A2L or no MAC is loaded, then the system shall give that artifact the status absent. |
| R-CMP-003.3 | U | The system shall compute the runs without regard to the artifact usage. |
| R-CMP-003.4 | When | When a compare succeeds, the system shall show each image's usage summary in the run list. |

#### S14.4 · The A2B Diff screen: selection, run list, windows (CTX-DIFFSCREEN)

| Id | Form | Requirement |
|---|---|---|
| R-CMP-006.1 | When | When the A2B Diff is shown, the system shall fill both variant lists of CTX-DIFFSCREEN. |
| R-CMP-006.2 | When | When the A2B Diff is shown, the system shall select the first entry of each variant list. |
| R-CMP-006.3 | When | When a side's variant list shows `(external path below)`, the system shall take that side from its external path box. |
| R-CMP-006.4 | U | The system shall show the variant ids in the variant lists as plain text, never as markup. |
| R-CMP-006.5 | When | When a compare succeeds, the system shall show the run list of CTX-DIFFSCREEN. |
| R-CMP-006.6 | If | If a compare has more runs than the display caps allow, then the system shall show the capped runs and the cap line. |
| R-CMP-006.7 | U | The system shall apply the display caps to the screen only, never to the report. |
| R-CMP-006.8 | When | When a compare with at least one run succeeds, the system shall select its first run. |
| R-DIFF-SCR.1 | When | When the operator moves the selection in the run list, the system shall show the selected run in both windows from its first page. |
| R-DIFF-SCR.2 | U | The system shall let Up and Down reach every shown run and no header line of the run list. |
| R-DIFF-SCR.3 | When | When a run is selected, the system shall show in each window the rows of CTX-DIFFSCREEN window. |
| R-DIFF-SCR.4 | U | The system shall show the same addresses on the same rows of the image A and image B windows. |
| R-DIFF-SCR.5 | If | If a compare has no run, then the system shall show the windows `Image A — no differing runs` and `Image B — no differing runs`. |
| R-DIFF-SCR.6 | When | When the operator presses `]`, the system shall show the next page of both windows. |
| R-DIFF-SCR.7 | When | When the operator presses `[`, the system shall show the previous page of both windows. |
| R-DIFF-SCR.8 | If | If the operator presses `]` on the last page or `[` on the first page, then the system shall keep the page shown. |
| R-CMP-006.9 | U | The system shall show a run's range as its first and its last address, on screen and in the reports. |

#### S14.5 · The A2B Diff screen: size regimes (CTX-DIFFSCREEN)

| Id | Form | Requirement |
|---|---|---|
| R-DIFF-SCR.9 | While | While the A2B Diff is in the wide regime, the system shall show the run list 26 columns wide beside the windows. |
| R-DIFF-SCR.10 | While | While the A2B Diff is in the narrow regime, the system shall give the windows the full width. |
| R-DIFF-SCR.11 | When | When the operator presses `f` in the narrow regime, the system shall toggle the run list over the windows. |
| R-DIFF-SCR.12 | When | When the run-list overlay opens, the system shall move the focus to the run list. |
| R-DIFF-SCR.13 | When | When the operator presses Escape with the run-list overlay open, the system shall close the overlay. |
| R-DIFF-SCR.14 | When | When the run-list overlay closes, the system shall return the focus to the widget that held it before the overlay opened. |
| R-DIFF-SCR.15 | When | When the operator presses Escape with the run-list overlay closed, the system shall leave the key to the rest of the app. |
| R-DIFF-SCR.16 | While | While the A2B Diff is in the wide or notice regime, the system shall ignore `f`. |
| R-DIFF-SCR.17 | While | While the A2B Diff is in the notice regime, the system shall ignore `]` and `[`. |
| R-DIFF-SCR.18 | While | While the A2B Diff is in the notice regime, the system shall show the notice text of CTX-DIFFSCREEN in place of the run list and the windows. |
| R-DIFF-SCR.19 | When | When the terminal size changes, the system shall apply the regime of the new size. |
| R-DIFF-SCR.20 | When | When the regime changes while a run is shown, the system shall fit the windows to their new height. |

#### S14.6 · Check spec for the report (from S0 HLR-010, LLR-010.1, LLR-010.2)

| Id | Form | Requirement |
|---|---|---|
| R-DIFF-CHK.1 | When | When the A2B Diff is shown, the system shall list in the check-spec list the `.json` files of the folder where the Check Editor saves check specs, by name, links left out. |
| R-DIFF-CHK.2 | U | The system shall label a file ending in `.chk.json` as `<name> CHECK` and any other file as `<name> PATCH`. |
| R-DIFF-CHK.3 | If | If the check-spec folder holds no `.json` file, then the system shall leave out the check row. |
| R-DIFF-CHK.4 | When | When the operator picks `(no check spec)`, the system shall show the status `Check spec: none — the report gains no addendum.` |
| R-DIFF-CHK.5 | If | If the picked file is a link or lies outside the check-spec folder, then the system shall show the status `Check spec: '<name>' is outside the patches folder — not loaded.` |
| R-DIFF-CHK.6 | If | If reading the picked file gives errors, then the system shall show the status `Check spec not loaded — <first three findings as [<code>] <severity>: <message>, separated by "; ">`. |
| R-DIFF-CHK.7 | If | If the picked document is not a check document, then the system shall show the status `Check spec: '<name>' is a kind='<kind>' document, not a check spec — the report gains no addendum.` |
| R-DIFF-CHK.8 | When | When a check spec loads, the system shall show the status `Check spec '<name>' loaded — <n> declared field(s) will ride the report.` |
| R-DIFF-CHK.9 | While | While a check spec is loaded, the system shall end each diff report with the section `## Checks`: `- Check spec: <name>`, `- Declared fields: <n> (0 byte changes — image never modified)` and the table # · Field · Address · Expected. |
| R-DIFF-CHK.10 | If | If the loaded check spec has no entry, then the system shall write `No declared fields.` in place of the table. |
| R-DIFF-CHK.11 | U | The system shall name each declared field by the loaded A2L or MAC symbol at its address, or `entry <i>` when no symbol is there. |

#### S14.7 · The diff report (CTX-DIFFREPORT)

| Id | Form | Requirement |
|---|---|---|
| R-CMP-006.10 | If | If no compare has succeeded since the last refused or failed one, then the system shall refuse Report with the status `No comparison yet — press Compare first.` |
| R-CMP-005.1 | While | While a project is open, the system shall write the diff report into `<project>/reports/`, creating the folder if it does not exist. |
| R-CMP-005.2 | While | While no project is open, the system shall write the diff report into the folder typed in the report destination box. |
| R-CMP-005.3 | If | If no project is open and the destination box is empty, then the system shall refuse the report with the reason `No destination directory supplied for a no-project diff report - refusing to write (no implicit default).` |
| R-CMP-005.4 | If | If no project is open and the typed destination is not an existing folder, then the system shall refuse the report with the reason `Destination is not an existing directory: '<typed>' (resolved to <path>) - refusing to write.` |
| R-CMP-005.5 | If | If `<project>/reports/` is a link, then the system shall refuse the report with the reason `Reports destination is a symbolic link - refusing to write: <path>`. |
| R-CMP-005.6 | U | The system shall name the report files as CTX-DIFFREPORT file name. |
| R-CMP-005.7 | U | The system shall never replace an existing file with a report. |
| R-CMP-005.8 | If | If 100 report names for the same second are taken, then the system shall show the status `Diff report failed: FileExistsError: 100 diff reports already exist for second <ts>.md - refusing to overwrite an existing report`. |
| R-CMP-005.9 | When | When both report files are written, the system shall show the status `Diff report written: <md path>  \|  <html path>`. |
| R-CMP-005.10 | If | If writing the report raises an error, then the system shall show the status `Diff report failed: <error type>: <message>`. |
| R-CMP-005.11 | U | The system shall keep the screen responsive while it writes the diff report. |
| R-CMP-004.1 | U | The system shall write the sections of CTX-DIFFREPORT in their order. |
| R-CMP-004.2 | U | The system shall list every run in the report, without any cap. |
| R-CMP-004.3 | When | When a hex window holds a changed run, the system shall write its diff block. |
| R-CMP-004.4 | U | The system shall merge two hex windows that are 5 rows or less apart. |
| R-CMP-004.5 | U | The system shall fill the Symbols column as CTX-DIFFREPORT symbols. |
| R-CMP-004.6 | If | If both images have no byte, then the system shall write `Memory maps unavailable - hex windows omitted.` in place of the hex windows. |
| R-CMP-004.7 | U | The system shall write the HTML file as CTX-DIFFREPORT HTML form. |
| R-CMP-004.8 | U | The system shall HTML-escape every value it embeds in the HTML file. |
| R-CMP-004.9 | U | The system shall write image labels, paths and symbol names into the Markdown file as inert text. |
| R-CMP-004.10 | U | The system shall write no report content to the log. |
| R-CMP-004.11 | U | The system shall write the diff report files as S12 R-TUI-097.1 states: UTF-8 with LF line ends on every host. |
| R-CMP-004.12 | When | When both diff report files are written, the system shall log at INFO `report kind=diff source=<source> output=<md path>\|<html path> outcome=ok`, with <source> the open project's folder name, else the typed destination, else `-`. |
| R-CMP-004.13 | If | If the diff report is refused or fails, then the system shall log at WARNING `report kind=diff source=<source> output=- outcome=<refused, refused (html) or failed: <error type>>`. |
| R-CMP-005.12 | U | The system shall write the A2B Diff report without the report filter (S12 CTX-RPT-FILTER). |

**(from batch-100 HLR-176: LLR-176.2c)** The progress line's format, spinner, elapsed time and end rules are S6's.

| Id | Form | Requirement |
|---|---|---|
| R-CMP-005.13 | When | When the system starts a diff report, the system shall show the diff report progress line at step 1. |
| R-CMP-005.14 | When | When the system has written the Markdown file of a diff report, the system shall move the diff report progress line to step 2. |
| R-CMP-005.15 | When | When a diff report ends, the system shall also write its report status to the status log. |

#### S14.8 · Flow changes in the diff report (from S0 LLR-143.2)

| Id | Form | Requirement |
|---|---|---|
| R-DIFF-FLOWCHG.1 | When | When the operator writes a diff report whose image B is a file that the last flow run wrote, and that run recorded a change or a refusal, the system shall add the section `## Flow change attribution`. |
| R-DIFF-FLOWCHG.2 | If | If image B is not a file that the last flow run wrote, then the system shall leave the section out. |
| R-DIFF-FLOWCHG.3 | U | The system shall write one row per change record of that run: change document · symbol or `-` · address · length · disposition · the runs its range overlaps. |
| R-DIFF-FLOWCHG.4 | If | If an applied change overlaps no run, then the system shall write `(no diff)` in its runs cell. |
| R-DIFF-FLOWCHG.5 | If | If a change was not applied, then the system shall write `—` in its runs cell. |
| R-DIFF-FLOWCHG.6 | When | When a run overlaps no change of the flow, the system shall write the line `- 0x<start>–0x<end> <kind>: no flow change`. |
| R-DIFF-FLOWCHG.7 | When | When the flow run recorded a refusal, the system shall write the line `- refused: <change document>[ symbol '<symbol>'][ @ 0x<address>] [<code>] <message>`. |
| R-DIFF-FLOWCHG.8 | U | The system shall write the same attribution in the HTML file. |

#### S14.9 · The before/after report (CTX-BEFOREAFTER)

R-TUI-049.2 (S10) gives the Patch Editor's Write before/after report control the same effect as `b`.

| Id | Form | Requirement |
|---|---|---|
| R-BEFORE-AFTER-REPORT-001.1 | When | When a save-back succeeds with a project open, the system shall show the offer `Before/after report ready - press b to write it to the project reports directory.` |
| R-BEFORE-AFTER-REPORT-001.2 | When | When the operator presses `b`, the system shall write the before/after report pair. |
| R-BEFORE-AFTER-REPORT-001.3 | When | When the system writes the before/after report, the system shall read the original image and the saved patched image from their files. |
| R-BEFORE-AFTER-REPORT-001.4 | If | If no change document has been applied this session, then the system shall refuse the report with the reason `No applied change summary - apply a change document and save the patched image first.` |
| R-BEFORE-AFTER-REPORT-001.5 | If | If the last apply has no saved patched image, then the system shall refuse the report with the reason `No saved patched image - the save-back was declined or refused.` |
| R-BEFORE-AFTER-REPORT-001.6 | If | If no image is loaded, then the system shall refuse the report with the reason `No image loaded - the original (before) side is unavailable.` |
| R-BEFORE-AFTER-REPORT-001.7 | If | If the original image file no longer exists, then the system shall refuse the report with the reason `Original image no longer on disk: <path>`. |
| R-BEFORE-AFTER-REPORT-001.8 | If | If the saved patched file no longer exists, then the system shall refuse the report with the reason `Saved patched image no longer on disk: <path>`. |
| R-BEFORE-AFTER-REPORT-001.9 | If | If the loaded image is not the image the patched file was saved from, then the system shall refuse the report with the reason `Stale change summary: the loaded image (<path>) is not the image the patched file was saved from (<path or unknown>) - re-apply and save in the current session.` |
| R-BEFORE-AFTER-REPORT-001.10 | If | If the saved patched file lies outside the open project folder, or outside the work area with no project open, then the system shall refuse the report with the reason `Stale change summary: saved patched image <path> lies outside the current <project directory or work area> <folder>.` |
| R-BEFORE-AFTER-REPORT-001.11 | If | If no project is open, then the system shall refuse the report with the reason `No active project - the before/after report needs a project reports/ destination; use the manual A<->B Diff report (key 7) with an explicit destination instead.` |
| R-BEFORE-AFTER-REPORT-001.12 | If | If `<project>/reports/` is a link, then the system shall refuse the report with the reason `Reports destination is a symbolic link - refusing to write: <path>`. |
| R-BEFORE-AFTER-REPORT-001.13 | If | If more than one refusal applies, then the system shall give the reason of the first in the order of rows .4 to .12. |
| R-BEFORE-AFTER-REPORT-001.14 | If | If the system refuses the before/after report, then the system shall write no file. |
| R-BEFORE-AFTER-REPORT-001.15 | If | If the system refuses the before/after report, then the system shall show the status `Before/after report refused: <reason>`. |
| R-BEFORE-AFTER-REPORT-001.16 | When | When both before/after files are written, the system shall show the status `Before/after report written: <md path> \| <html path>`. |
| R-BEFORE-AFTER-REPORT-001.17 | If | If writing the before/after report raises an error, then the system shall show the status `Before/after report failed: <error type>: <message>`. |
| R-BEFORE-AFTER-REPORT-001.18 | U | The system shall write the before/after report with the provenance and linkage sections of CTX-BEFOREAFTER. |
| R-BEFORE-AFTER-REPORT-001.19 | U | The system shall list every entry of the last apply in the linkage table, whatever its disposition. |
| R-BEFORE-AFTER-REPORT-001.20 | If | If an entry had no prior bytes, then the system shall write `(none - created into hole)` in its Before cell. |
| R-BEFORE-AFTER-REPORT-001.21 | U | The system shall remove control characters from the provenance and linkage values in both files. |
| R-BEFORE-AFTER-REPORT-001.22 | U | The system shall escape `\|` in the Markdown linkage cells. |
| R-BEFORE-AFTER-REPORT-001.23 | When | When a report filter is set (S12), the system shall apply it to the before/after report. |
| R-BEFORE-AFTER-REPORT-001.24 | U | The system shall fill the run table's Symbols column of the before/after report from the loaded A2L and MAC. |
| R-BEFORE-AFTER-REPORT-001.25 | U | The system shall show only paths and reasons in the before/after status, never entry bytes. |
| R-BEFORE-AFTER-REPORT-001.26 | U | The system shall keep the screen responsive while it writes the before/after report. |
| R-BEFORE-AFTER-REPORT-001.27 | If | If a report filter is set and its file cannot be read or parsed, then the system shall write no file and show the status `Before/after report refused: <findings, separated by "; ">`. |
| R-BEFORE-AFTER-REPORT-001.28 | When | When the system writes an entry's bytes in the Before or After cell, the system shall write them as the bytes cell of CTX-BEFOREAFTER. |
| R-BEFORE-AFTER-REPORT-001.29 | When | When both before/after files are written, the system shall log at INFO `report kind=before-after source=<loaded file name> output=<md path>\|<html path> outcome=ok`. |
| R-BEFORE-AFTER-REPORT-001.30 | If | If the before/after report is refused or fails, then the system shall log at WARNING `report kind=before-after source=<loaded file name> output=- outcome=<refused or failed: <error type>>`. |
| R-BEFORE-AFTER-REPORT-001.31 | When | When the system starts a before/after report, the system shall show the before/after progress line. |



<a id="s15"></a>

## S15 · Flow engine

### Context notes (informative)

#### CTX-FLOW · Blocks, refs and statuses (S15.1 … S15.10)

```text
flow            A name, an ordered list of blocks and a variable table (the funnel).
block kinds     Kind (file tag)   shown as   what it does
                source            LOAD       reads an image file: the working image
                patch             PATCH      applies a change document (S8) to the image
                check             CHECK      runs a check document (S9) on the image
                crc               CRC        computes and writes a CRC (S13) into the image
                write_out         WRITE-OUT  writes the image to a file
                a2b               A2B-DIFF   writes a diff report of two images (S14)
                external_step     EXT-STEP   waits for a human step outside the app
                report            REPORT     writes the flow report
working image   The image a run carries from block to block; a LOAD sets it.
project ref     A file name a block carries, read under the open project folder by
                S11's manifest-entry rules: no NUL, not absolute, no escape, no link.
                A refused ref gives one finding [MANIFEST-PATH-ESCAPE] <message>.
block result    Status, summary, findings (warnings) and diagnostics; the last
                diagnostic is the cause.
block status    ok · notices · error · skipped · waiting
stop the flow   End the block error and skip every later block that is not a REPORT
                block, with the summary "skipped (upstream error)".
pause the flow  End the block waiting and skip every later block that is not a REPORT
                block, with the summary "skipped (waiting on external step)".
run status      ok (shown CLEAN) · completed-with-issues · error (shown FAILED) ·
                paused
written files   The files WRITE-OUT blocks and confirmed external steps wrote; reports
                are not written files.
integrity codes The integrity notices of S1 (S19 and Intel HEX).
funnel          Up to 32 pairs NAME = value; NAME is [A-Z0-9_], 1 to 32 characters;
                value 1 to 256 characters. A placeholder is the exact text ${NAME}.
```

#### CTX-FLOWFILE · Flow files (S15.12)

```text
flows home      <project>/flows/
flow file       <flows home>/<name>.json: {"schema_version": 1, "name", "blocks": [...],
                ["funnel": [[NAME, value], ...]]}; each block {"kind", its fields};
                refs stored as typed.
block fields    source: image_ref, file_type (s19|hex), [a2l_ref]
                patch: change_doc_ref, [a2l_ref]
                check: check_doc_ref, gating (advisory|block-own-op)
                crc: config_ref        write_out: output_name, fmt (s19|hex)
                a2b: image_a, image_b, each {"source": flow|file, "ref"}
                external_step: mode (terminal|manual), instruction, log_ref, output_path
                report: no field
limits          At most 1 MiB; 1 to 64 blocks; name at most 64 characters.
saved name      The typed name cleaned as S11 cleans a project name; on a clash
                <name>_<N>.json, the lowest free N.
load findings   Each refused rule gives one finding, code then message:
  FLOW-SIZE-CAP           flow file is <n> bytes, over the 1048576-byte cap - not loaded
  FLOW-JSON-PARSE         flow file is not well-formed JSON - <error type>
  FLOW-BAD-STRUCTURE      top level not an object · blocks not an array · no blocks ·
                          over 64 blocks · a block not an object
  FLOW-SCHEMA-UNSUPPORTED schema_version other than 1
  FLOW-UNKNOWN-KIND       a kind not in the list above
  FLOW-BAD-FIELD          an unknown or missing field · an enum value not allowed · a
                          bad name · a bad funnel
  FLOW-UNSAFE-REF         a ref with NUL · a Windows drive-relative ref
  FLOW-UNSAFE-OUTPUT-NAME an output_name with a separator, "..", an absolute path or a
                          leading "."
  MANIFEST-PATH-ESCAPE    a read ref that S11's rules refuse
```

#### CTX-CHAIN · Chain sets (S15.13 … S15.15)

```text
chain set       Lanes run together in Flow Execution (S16), with a set name.
lane            A flow loaded from a flow file (its template), a lane name, and the
                LOAD refs bound for this lane (the template's own refs where not bound).
mode            sequential (one lane after the other, in lane order) · parallel (all
                lanes at once, each on its own working image).
flowsets home   <project>/flowsets/
chain-set file  <flowsets home>/<name>.json: name and, per lane: chain (lane name),
                template (a flows/ file name), inputs ([LOAD index, ref] pairs),
                outputs (the files its last run wrote).
                Limits: 1 to 32 lanes; names at most 64 characters; at most 64 inputs and
                64 outputs per lane; template a plain file name; refs as project refs.
                Saved name and clash rule as a flow file. Refusal codes: CHAIN-SET-SIZE-CAP,
                CHAIN-SET-JSON-PARSE, CHAIN-SET-BAD-STRUCTURE, CHAIN-SET-SCHEMA-UNSUPPORTED,
                CHAIN-SET-BAD-FIELD, CHAIN-SET-UNSAFE-REF.
```

#### CTX-FLOWREPORT · The flow report and the chain-set report (S15.11, S15.14)

```text
reports home    <project>/reports/
flow report     <ts>-report.md (S12's project report name, so the Reports dialog lists
                it). Sections in order:
  header        "# Flow report — <flow name>", Generated (YYYY-MM-DD HH:MM:SS UTC),
                Status, "Blocks reported: <n> (up to the report block)"
  Pipeline ledger      # · Block · Status · Summary, one row per block before the report
  Change attribution   Patch · Change document · Address · Length · Before · After ·
                       Symbol · A2L reference, one row per applied entry; or
                       "- (no changes applied)"
  Not applied          Patch · Change document · Address · Disposition; or "- none"
  Refusals             Patch · Change document · Code · Detail; or "- none"
  Findings             "- **[<KIND> #<i>]** (<severity>) <text>" per finding and
                       "(diagnostic) <text>" per diagnostic; left out when there is none
  Image footprint      "Before CRC" (after a CRC ran) and "Final": ranges and byte total
  Written files        paths relative to the project folder; or "- (none)"
report status   CLEAN · COMPLETED WITH ISSUES · FAILED
report limits   A cell at most 240 characters; at most 200 findings per block, then
                "*<k> more findings omitted (per-block cap 200).*"; the document at most
                S12's report byte budget, then "> **Truncated:** … omitted section(s): …".
chain-set report  <ts>-chain-set-report.md (clash: <ts>-<NN>-chain-set-report.md).
                "# Chain-set report — <set name>", Generated, Mode, Chains; then the
                sections Chain ledger (# · Chain · Template · Status · Blocks · Elapsed),
                Input provenance ("- Chain <lane> input <j>: <ref> [bound] path=`<path>`"),
                Written files, Not applied, Refusals, Notices — each lane "none" when it
                has nothing.
flow-A2B report  <ts>-flow-a2b.md: a diff report (S14 CTX-DIFFREPORT), Markdown only.
```

---

### Requirements


#### S15.1 · Running a flow (CTX-FLOW; engine half of R-TUI-059)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-059.1 | When | When a flow runs, the system shall run its blocks in order on one working image. |
| R-TUI-059.2 | When | When a flow runs, the system shall give every block exactly one block result. |
| R-TUI-059.3 | If | If a block raises an error, then the system shall stop the flow with the summary `error` and the cause `<error type>: <message>`. |
| R-TUI-059.4 | If | If a block stops the flow, then the system shall still run every later REPORT block. |
| R-TUI-059.5 | U | The system shall read every ref of a block as a project ref before it opens the file. |
| R-TUI-059.6 | If | If a project ref is refused, then the system shall add its finding to the block's diagnostics before the cause. |
| R-FLOW-RUN.1 | U | The system shall leave the flow and its file unchanged by a run. |
| R-FLOW-RUN.2 | U | The system shall read no A2L or MAC loaded in the session during a flow run. |

#### S15.2 · LOAD (from S0 LLR-154.3, HLR-142, LLR-142.1)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-SRC.1 | When | When a LOAD block runs, the system shall replace the working image with the image of its file. |
| R-FLOW-SRC.2 | When | When a LOAD block declares Intel HEX, the system shall read its file as Intel HEX. |
| R-FLOW-SRC.3 | When | When a LOAD block declares S19, the system shall read its file as S19. |
| R-FLOW-SRC.4 | If | If a LOAD block's file is refused or does not exist, then the system shall stop the flow with the summary `source unresolved` and the cause `source image not found or not inside the project`. |
| R-FLOW-SRC.5 | If | If the loaded image carries a notice with an integrity code, then the system shall stop the flow with the summary `loaded <file> with integrity notices` and one diagnostic `[<code>] <file>: <message>` per such notice. |
| R-FLOW-SRC.6 | If | If the load rejected lines and carries no integrity code, then the system shall end the block notices with the summary `loaded <file> (<n> ranges, <k> integrity notice(s))` and one finding `line <n>: <message>` per rejected line. |
| R-FLOW-SRC.7 | When | When a LOAD reads its file with no rejected line, the system shall end the block ok with the summary `loaded <file> (<n> ranges)`. |
| R-FLOW-SRC.8 | When | When a LOAD block declares an A2L reference, the system shall read that A2L file as the run's symbol context before any PATCH applies. |
| R-FLOW-SRC.9 | If | If a LOAD block's A2L reference is refused or does not exist, then the system shall stop the flow with the summary `a2l reference unresolved` and the cause `a2l reference '<ref>' not found or not inside the project`. |
| R-FLOW-SRC.10 | If | If a LOAD block's A2L reference cannot be read, then the system shall stop the flow with the summary `a2l reference unreadable` and the cause `a2l reference '<ref>' could not be read: <error type>`. |

#### S15.3 · PATCH and the funnel (from S0 HLR-156, LLR-156.1, HLR-142, LLR-143.1)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-PATCH.1 | When | When a PATCH block runs, the system shall apply its change document to the working image as S8 applies a document. |
| R-FLOW-PATCH.2 | If | If no LOAD has run before a PATCH, CRC or WRITE-OUT block, then the system shall stop the flow with the cause `<kind> block has no upstream <source image or image>`. |
| R-FLOW-PATCH.3 | If | If the change document is refused or does not exist, then the system shall stop the flow with the summary `change doc unresolved` and the cause `change document not found or not inside the project`. |
| R-FLOW-PATCH.4 | When | When a PATCH block reads symbol entries, the system shall resolve them against its own A2L reference, else the LOAD block's, else none (S8 R-CHG-SYM.2 … .4). |
| R-FLOW-PATCH.5 | If | If a PATCH block's own A2L reference is refused, missing or unreadable, then the system shall stop the flow as R-FLOW-SRC.9 and .10 state for a LOAD. |
| R-FLOW-PATCH.6 | If | If the change document cannot be read, then the system shall stop the flow with the summary `change document unreadable` and the cause `[<first code>] <message>`. |
| R-FLOW-PATCH.7 | If | If every entry of the document is blocked, then the system shall stop the flow with the summary `change document blocked` and the cause `[<first refusal code>] <message>`. |
| R-FLOW-PATCH.8 | If | If the document applied 0 of at least 1 entry, then the system shall stop the flow with the summary `applied 0 of <n> entries` and the cause `applied 0 of <n> entries: 0x<address> <disposition>`. |
| R-FLOW-PATCH.9 | If | If some entries were applied and some were not, then the system shall end the block notices with the summary `applied <k> of <n> entries, <m> not applied` and one finding `0x<address> <disposition>` per entry not applied. |
| R-FLOW-PATCH.10 | When | When every entry is applied, the system shall end the block ok with the summary `applied <n> entries` (`applied 1 entry` for one). |
| R-FLOW-PATCH.11 | When | When a PATCH block ends, the system shall record each entry it read (document, A2L reference, type, symbol, address range, disposition, bytes before and after) and each refusal (code, symbol, address, message) for the run's reports. |
| R-FLOW-FUNNEL.1 | When | When a flow with a funnel runs a PATCH block, the system shall replace each `${NAME}` the funnel declares by its value in the document text before reading it. |
| R-FLOW-FUNNEL.2 | If | If the document holds a `${NAME}` the funnel does not declare, then the system shall leave it unchanged and end the block notices with the finding `funnel: ${<NAME>} is not declared in the flow — the placeholder stays intact`. |
| R-FLOW-FUNNEL.3 | While | While a flow has no funnel, the system shall read change documents unchanged. |

#### S15.4 · CHECK

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-CHECK.1 | When | When a CHECK block runs, the system shall run its check document on the working image as S9 runs a check document. |
| R-FLOW-CHECK.2 | U | The system shall leave the working image unchanged by a CHECK block. |
| R-FLOW-CHECK.3 | U | The system shall never stop the flow at a CHECK block. |
| R-FLOW-CHECK.4 | When | When a CHECK block runs, the system shall give it the summary `passed=<p> failed=<f> uncheckable=<u>`. |
| R-FLOW-CHECK.5 | If | If a check entry failed, then the system shall end the CHECK block notices with the finding `<f> check entries failed` (`1 check entry failed` for one). |
| R-FLOW-CHECK.6 | If | If a CHECK block cannot run its document and its gating is advisory, then the system shall end it notices with the summary `could not check`. |
| R-FLOW-CHECK.7 | If | If a CHECK block cannot run its document and its gating is block-own-op, then the system shall end it error with the summary `check operation invalid`. |

#### S15.5 · CRC (from S0 HLR-159, LLR-159.2; the CRC itself is S13's)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-CRC.1 | When | When a CRC block runs, the system shall compute its CRCs as S13.2 computes them, from a template read as S13 CTX-CRCCONFIG, over the working image as it stands after the blocks before it. |
| R-FLOW-CRC.2 | When | When a CRC block writes a CRC outside the image's ranges, the system shall add those addresses to the working image. |
| R-FLOW-CRC.3 | If | If the CRC template is refused or does not exist, then the system shall stop the flow with the summary `config unresolved` and the cause `crc config not found or not inside the project`. |
| R-FLOW-CRC.4 | If | If the CRC template is invalid, then the system shall stop the flow with the summary `config malformed` and the cause `crc config invalid: <first three errors, separated by "; ">`. |
| R-FLOW-CRC.5 | If | If a CRC region holds no image byte, then the system shall stop the flow, writing no CRC, with the cause `CRC region 0x<start>-0x<end> holds 0 image bytes - nothing written`. |
| R-FLOW-CRC.6 | If | If a CRC region holds some but not all of its bytes, then the system shall end the block notices with the finding `CRC: <k> of <n> region bytes absent (0x<start>-0x<end>) - the CRC covers present bytes only`. |
| R-FLOW-CRC.7 | If | If a CRC block comes before every PATCH block, or the flow has none, then the system shall end it notices with the finding `CRC before PATCH: the image is finalized before any patch is applied`. |
| R-FLOW-CRC.8 | When | When a CRC block ends with no notice, the system shall end it ok with the summary `injected <n> CRC regions` (`region` for one). |

#### S15.6 · WRITE-OUT (from S0 LLR-155.6; the writing is S8.7)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-WRITE.1 | When | When a WRITE-OUT block runs, the system shall write the working image into the open project folder in its declared format, as S8.7 writes an image file. |
| R-FLOW-WRITE.2 | When | When a WRITE-OUT block writes S19, the system shall write 32 data bytes per record. |
| R-FLOW-WRITE.3 | When | When a WRITE-OUT block writes S19 from an S19 source with an S0 record, the system shall write that S0 record. |
| R-FLOW-WRITE.4 | When | When a WRITE-OUT block writes S19 from an S19 source with a terminator, the system shall write the source's terminator address in the terminator. |
| R-FLOW-WRITE.5 | If | If the file cannot be written, then the system shall stop the flow with the summary `write failed` and the cause `write-out produced no file`. |
| R-FLOW-WRITE.6 | When | When a WRITE-OUT block has written its file, the system shall read the file back and compare it with the working image. |
| R-FLOW-WRITE.7 | If | If the file read back differs from the working image, then the system shall stop the flow with the summary `wrote <file> but read-back differs`, one diagnostic per differing run and the cause `first difference at 0x<address>`. |
| R-FLOW-WRITE.8 | When | When the read-back matches, the system shall end the block ok with the summary `wrote <file>`. |

#### S15.7 · A2B diff block (from S0 HLR-014, LLR-013.3, LLR-014.1, LLR-014.2)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-A2B.1 | U | The system shall bind each A2B input either to the image after an earlier block of the same flow (`#<n>`, 1-based) or to a project ref. |
| R-FLOW-A2B.2 | If | If both A2B inputs are files, then the system shall refuse the block with the reason `at least one A2B input must come from the current flow (both-external pairs would false the report)`. |
| R-FLOW-A2B.3 | If | If an A2B input names a block that is not earlier in the flow, then the system shall refuse the block with the reason `<image_a or image_b>: flow binding references block <n>, but only <k> upstream block(s) exist in this flow`. |
| R-FLOW-A2B.4 | If | If an A2B input names an A2B-DIFF, EXT-STEP or REPORT block, then the system shall refuse the block with the reason `<image_a or image_b>: block <n> (<kind>) produces no image output`. |
| R-FLOW-A2B.5 | When | When an A2B block runs, the system shall write a flow-A2B report of image A against image B into `<project>/reports/`. |
| R-FLOW-A2B.6 | U | The system shall name in the flow-A2B report each input's origin: the file's name and path, or `block <n> (<kind>).out`. |
| R-FLOW-A2B.7 | U | The system shall leave the working image unchanged by an A2B block. |
| R-FLOW-A2B.8 | If | If an A2B input file is refused, missing or unreadable, then the system shall stop the flow with the cause `A2B image <A or B> file not found or not inside the project` or `A2B image <A or B>: <error type>: <message>`. |
| R-FLOW-A2B.9 | If | If the block an A2B input names produced no image, then the system shall stop the flow with the cause `A2B image <A or B>: flow block <n> produced no image (failed or skipped upstream)`. |
| R-FLOW-A2B.10 | If | If the flow-A2B report cannot be written, then the system shall end the block error with the summary `report write failed` and keep the flow running. |
| R-FLOW-A2B.11 | When | When the flow-A2B report is written, the system shall end the block ok with the summary `wrote reports/<file>`. |

#### S15.8 · External step

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-EXT.1 | If | If an external step is not confirmed, then the system shall pause the flow with the summary `paused - waiting for a human: <command or instruction> '<text>' \| LOG '<log>' + OUTPUT '<output>' pending`. |
| R-FLOW-EXT.2 | When | When a confirmed external step runs, the system shall read a relative log path and a relative output path under the open project folder. |
| R-FLOW-EXT.3 | If | If a confirmed step's log file does not exist, then the system shall stop the flow with the summary `external step refused` and the cause `log '<log>' does not exist - the log is mandatory evidence, never optional`. |
| R-FLOW-EXT.4 | If | If a confirmed step's output file does not exist, then the system shall stop the flow with the summary `external step refused` and the cause `output '<output>' does not exist - run the external step before confirming`. |
| R-FLOW-EXT.5 | When | When a confirmed step's log and output exist, the system shall copy the output into the open project folder as S5 copies a file. |
| R-FLOW-EXT.6 | If | If the copy is refused, then the system shall stop the flow with the summary `external step copy failed` and the cause `<error type>: <message>`. |
| R-FLOW-EXT.7 | When | When the copy succeeds, the system shall end the block ok with the summary `log '<log file>' received · output copied to <copy name> (session)`. |
| R-FLOW-EXT.8 | U | The system shall leave the working image unchanged by an external step. |

#### S15.9 · Run status (CTX-FLOW)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-STATUS.1 | If | If a block stopped the flow, then the system shall end the run error. |
| R-FLOW-STATUS.2 | If | If no block stopped the flow and a block paused it, then the system shall end the run paused. |
| R-FLOW-STATUS.3 | If | If the flow neither stopped nor paused and a block ended notices or error or has a finding, then the system shall end the run completed-with-issues. |
| R-FLOW-STATUS.4 | When | When the flow neither stopped nor paused and every block ended ok without a finding, the system shall end the run ok. |
| R-FLOW-STATUS.5 | When | When a run ends, the system shall record the working image's ranges, and the ranges before the first CRC block. |

#### S15.10 · The flow report (CTX-FLOWREPORT; from S0 LLR-143.1, LLR-156.4)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-RPT.1 | When | When a REPORT block runs, the system shall write a flow report of the blocks before it into `<project>/reports/`. |
| R-FLOW-RPT.2 | U | The system shall write the sections of CTX-FLOWREPORT in their order. |
| R-FLOW-RPT.3 | If | If the flow stopped before the REPORT block, then the system shall give the report the status FAILED. |
| R-FLOW-RPT.13 | If | If the flow did not stop and a block before the report ended notices or error, has a finding, or left an entry not applied or refused, then the system shall give the report the status COMPLETED WITH ISSUES. |
| R-FLOW-RPT.14 | When | When every block before the report ended ok without a finding and no entry was left unapplied or refused, the system shall give the report the status CLEAN. |
| R-FLOW-RPT.4 | If | If the flow is paused when a REPORT block runs, then the system shall give the report the status PAUSED. |
| R-FLOW-RPT.5 | U | The system shall list every applied entry in Change attribution, every entry not applied in Not applied and every refusal in Refusals. |
| R-FLOW-RPT.6 | U | The system shall write every text taken from a file or typed by the operator into the report as inert Markdown. |
| R-FLOW-RPT.7 | U | The system shall write paths into the flow report relative to the project folder, never absolute. |
| R-FLOW-RPT.8 | U | The system shall keep the flow report within the limits of CTX-FLOWREPORT. |
| R-FLOW-RPT.9 | U | The system shall write each footprint range as its first and last address and the byte total as the number of bytes in the ranges. |
| R-FLOW-RPT.10 | If | If the flow report cannot be written, then the system shall end the REPORT block error with the summary `report write failed` and keep the flow running. |
| R-FLOW-RPT.11 | When | When the flow report is written, the system shall end the REPORT block ok with the summary `wrote reports/<file>`. |
| R-FLOW-RPT.12 | U | The system shall write the flow report and the chain-set report as S12 R-TUI-097.1 states: UTF-8 with LF line ends on every host. |

#### S15.11 · Flow files (CTX-FLOWFILE; from S0 HLR-015, LLR-015.1, LLR-015.2)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-FILE.1 | When | When the operator saves a flow, the system shall write it as a flow file under its saved name. |
| R-FLOW-FILE.2 | If | If a flow file of that saved name exists, then the system shall save under `<name>_<N>.json` with the lowest free N from 1. |
| R-FLOW-FILE.3 | If | If the typed name is empty after cleaning, then the system shall write no file. |
| R-FLOW-FILE.4 | U | The system shall keep every field of every block kind through a save and a load. |
| R-FLOW-FILE.5 | If | If a flow file breaks a rule of CTX-FLOWFILE, then the system shall load nothing from it. |
| R-FLOW-FILE.6 | If | If a flow file breaks rules of CTX-FLOWFILE, then the system shall give one finding per broken rule with its code. |
| R-FLOW-FILE.7 | When | When the system loads a flow file, the system shall check its size before it reads it. |
| R-FLOW-FILE.8 | When | When the system loads a flow file, the system shall open none of the files its refs name. |
| R-FLOW-FILE.9 | When | When the operator imports a flow file, the system shall copy it into the flows home as S5 copies a file, with a 1 MiB limit. |
| R-FLOW-FILE.10 | U | The system shall list the saved flows as the file names of the flows home without `.json`, sorted. |

**(from batch-100 HLR-171b: LLR-171.4i)**

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-FILE.11 | If | If the flows home resolves to a folder outside the work area, then the system shall save no flow file. |

#### S15.12 · Chain-set runs (CTX-CHAIN; from S0 HLR-019, LLR-018.2, LLR-019.1, LLR-019.2, LLR-155.5)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-CHAIN.1 | When | When a chain set runs, the system shall run each lane's flow with that lane's bound LOAD refs. |
| R-FLOW-CHAIN.2 | U | The system shall leave the lane's flow file unchanged by its bound refs. |
| R-FLOW-CHAIN.3 | When | When a chain set runs in sequential mode, the system shall run the lanes one after the other in lane order. |
| R-FLOW-CHAIN.4 | When | When a chain set runs in parallel mode, the system shall start every lane before it waits for any. |
| R-FLOW-CHAIN.5 | If | If a lane stops or raises, then the system shall still run the other lanes. |
| R-FLOW-CHAIN.6 | U | The system shall report the lanes' outcomes in lane order. |
| R-FLOW-CHAIN.7 | If | If two or more lanes write a WRITE-OUT file of the same name, ignoring case, then the system shall run no lane and give the reason `Chain set not run: lanes '<lane>', '<lane>' <both or all> write '<name>' — give each lane its own output name. Nothing written.` |
| R-FLOW-CHAIN.8 | If | If a chain set has no lane, then the system shall run nothing and give the reason `no chains in set - nothing was executed`. |
| R-FLOW-CHAIN.9 | When | When the operator confirms a lane's external step, the system shall run that lane again with every step confirmed so far in its current wait. |
| R-FLOW-CHAIN.10 | U | The system shall give each report of a run a name no other file holds, also when lanes write reports in the same second. |

#### S15.13 · The chain-set report (CTX-FLOWREPORT; from S0 HLR-020, LLR-020.2, LLR-156.3)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-CHAIN.11 | When | When a chain set has run, the system shall write a chain-set report into `<project>/reports/`. |
| R-FLOW-CHAIN.12 | U | The system shall write the sections of the chain-set report of CTX-FLOWREPORT in their order. |
| R-FLOW-CHAIN.13 | U | The system shall write one Input provenance line per LOAD ref each lane read, with its resolved path, or an empty path when the ref was refused. |
| R-FLOW-CHAIN.14 | U | The system shall record the run's mode in the chain-set report. |
| R-FLOW-CHAIN.15 | U | The system shall list per lane its written files, its entries not applied, its refusals and its findings, or `none`. |
| R-FLOW-CHAIN.16 | U | The system shall show each lane's status in the Chain ledger with the mark `✓` ok, `◈` completed-with-issues, `✗` error or `□` paused. |
| R-FLOW-CHAIN.17 | U | The system shall write every lane name, set name, ref and message into the chain-set report as inert Markdown. |
| R-FLOW-CHAIN.18 | If | If the chain-set report cannot be written, then the system shall keep the lanes' outcomes and give the reason `chain-set report write failed: <error type>: <message>`. |

#### S15.14 · Chain-set files (CTX-CHAIN; from S0 HLR-021, LLR-021.1, LLR-021.2)

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-SET.1 | When | When the operator saves a chain set, the system shall write a chain-set file with each lane's name, template, bound LOAD refs and last written files. |
| R-FLOW-SET.2 | If | If the chain set has no lane or its name is empty after cleaning, then the system shall write no file. |
| R-FLOW-SET.3 | If | If a chain-set file of that saved name exists, then the system shall save under `<name>_<N>.json` with the lowest free N from 1. |
| R-FLOW-SET.4 | If | If a chain-set file breaks a rule of CTX-CHAIN, then the system shall load nothing from it. |
| R-FLOW-SET.5 | When | When the system loads a chain-set file, the system shall load each lane's template from the flows home. |
| R-FLOW-SET.6 | U | The system shall list the saved chain sets as the file names of the flowsets home without `.json`, sorted. |

**(from batch-100 HLR-171b: LLR-171.4j)**

| Id | Form | Requirement |
|---|---|---|
| R-FLOW-SET.7 | If | If the flowsets home resolves to a folder outside the work area, then the system shall save no chain-set file. |



<a id="s16"></a>

## S16 · Flow Builder UI

### Context notes (informative)

Block kinds, statuses, run statuses, flow files and chain sets are S15's (CTX-FLOW, CTX-FLOWFILE, CTX-CHAIN). Colours and glyphs below are today's; D16-27 and D16-28 put them through a prototype round.

#### CTX-BUILDER · The Flow Builder (S16.1 … S16.6)

```text
Flow Builder    Rail window (S6: position 9, key 8). Header "Flow Builder" with the
                📂 Open flows/ chip and the ? chip (S5, S7). Then, top to bottom:
  ribbon        "Flow: <name>  · saved|· unsaved  <kind summary>" and, at the right,
                "session <project folder, tail kept>" or "session (no active project)".
  pipeline      The chain as one row of cards joined by cables "───▶"; with no block:
                "No blocks yet — a chain starts with ◉ LOAD: pick it below, type the
                image file, press Add."
  palette       "add block" and one chip per kind: ◉ LOAD · ▣ PATCH · ✓ CHECK · ⊕ CRC ·
                ▼ WRITE-OUT · ⏚ A2B-DIFF · » EXT-STEP
  add form      The chosen kind's tag, its inputs, then "+ Add".
  clip row      "copy block #" box (empty means the last block), Copy, Paste, the
                clipboard status, "Variables (<n>)".
  variables     "variable" box, "value" box, "+ Add var", then the variable list;
                hidden until Variables is pressed.
  notice        One warning line; hidden when empty.
  foot row      Run (the one filled control), Clear, Save…, Load…
  result        The last run's result, or "No run yet — Run executes this chain against
                the loaded image; the block verdicts land here."
  legend        ◉ load ▣ patch ✓ check ⊕ CRC ▼ write-out ⏚ A2B diff » external step
                [≡ report, while the chain has one] ─ cable ▶ feeds the next block
add inputs      LOAD "image file" · PATCH "change doc" · CHECK "check doc" and gating
                (advisory, block-own-op) · CRC "CRC template" · WRITE-OUT "output file" ·
                A2B-DIFF "image A", "image B" (a file name, or #<n> for the image after
                block n) · EXT-STEP "mode" (Terminal, Manual), "command" or
                "instruction", "log", "output file".
card            "<n>" on the top border; "<glyph> <KIND>"; what it does; each input as
                "in · <name>" and its value; a note; "out" and the output.
clip            A ref or path keeps its tail, a label or command its head; the cut
                side ends or starts with "…".
card width      The pipeline width shared by the cards, at least 21 columns; a longer
                chain scrolls sideways inside the pipeline frame.
result          The banner; one node per block: "<glyph> <kind> <status>", the summary,
                the findings (warning colour), the diagnostics (error colour); the
                memory ribbon (48 cells: █ mapped, ░ gap) and "<n> range(s) · 0x<low>‥
                0x<high>"; "before:" and "after:" ribbons when a CRC grew the image;
                "wrote <path>" per written file; then the run's own diagnostics.
banner          CLEAN · NOTICES (issues, no block in error) · ISSUES · FAILED ·
                PAUSED - WAITING FOR A HUMAN
block glyph     ● ok · ◈ notices · ✗ error · ○ skipped · □ waiting
Save flow as:   Name box (prefilled with the flow name), the hint "Name is sanitised
                (letters, numbers, - _); identity is the filename.", the notice line,
                Save, Cancel.
Load flow:      The saved flows (S15 R-FLOW-FILE.10), the import line, Import…, Load,
                Cancel.
Discard unsaved "Loading '<name>' replaces the current unsaved flow.", Discard, Cancel.
flow edits?
```

#### CTX-FXSCREEN · Flow Execution (S16.7 … S16.10)

```text
Flow Execution  Rail window (S6: position 10, key ]). Header "Flow Execution" with the
                📂 Open session chip and the ? chip (S5, S7). Then:
  ribbon        "Set: <set name>  · saved|· unsaved" … "session <folder>", Import…,
                the mode switch "sequential · parallel", Run (filled).
  set row       "set name" box, Save Set, "saved sets" list ("flowsets/<name>.json", or
                "(no saved sets)"), Load Set.
  notice        One warning line; hidden when empty.
  lanes         One lane per imported flow, top to bottom; with none: "No chains yet —
                Import… adds a lane from a saved flow."
  REQUIRED      "log + output file: REQUIRED for <lane> · press c to confirm", shown
                while a lane waits.
  run log       At most 8 lines. Before any run: "No run yet — Run executes every lane."
                With more: "… <k> earlier lines — the full log is in the run report",
                then the newest 7.
  legend        ▓ done ░ not run / skipped ✗ error ◇ notices □ waiting for a human
                ▪ owed before the lane goes on
lane            Head "<mark> <lane> · <status>[ at #<n>][ · <mm:ss.mmm>] · <n> blocks
                [ · tpl <template>][ · wrote <files>]"; red pending lines; one row of
                cards joined by cables; Confirm after the last card while it waits.
lane status     ░ not run · ▓ done · ◇ done with notices · ✗ failed · □ waiting for a human
card            Border title "<glyph> <KIND>". LOAD: the ref box, Bind, "fmt <type>".
                Other kinds: two io lines. Then "<mark> <status word>".
cable mark      □ into a waiting block; else ▓ ok, ◇ notices, ✗ error, ░ skipped /
                waiting / not run.
pending lines   "▪ '<ref>' missing - re-bind" per reloaded ref whose file is gone;
                "▪ log '<log>' pending" and "▪ output file not confirmed — waiting for a
                human" while the lane waits.
attention lane  The first lane, in lane order, that waits at a step it has not confirmed.
log lines       Per lane and run: "<mm:ss.mmm> <lane> · started" (a confirm re-run:
                "· re-run after confirming the external step (block <i>/<n>)"), then
                "<mm:ss.mmm> <mark> <lane>" and one of:
                  " · done" or " · done with notices", then
                  [" · PATCH: <k> of <n> entries not applied (0x<address> <disposition>)"]
                  [" · <the CRC absent-bytes finding>"] [" · wrote <files>"]
                  " · block <i>/<n> <KIND> — <cause> · chain halted"
                  " · WAITING FOR A HUMAN — external step (block <i>/<n>) · log '<log>'
                  pending"
dwell           0.5 s: how long the attention lane must have waited before c confirms it.
```

---

### Requirements


#### S16.1 · The Flow Builder window (CTX-BUILDER; R-TUI-059 screen half, from S0 HLR-146, LLR-146.1, 146.5, 146.11)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-059.20 | U | The system shall offer the Flow Builder of CTX-BUILDER as a rail window. |
| R-TUI-059.21 | U | The system shall show the parts of the Flow Builder in the order of CTX-BUILDER. |
| R-TUI-059.22 | U | The system shall show the flow's name and its saved state on the ribbon. |
| R-FB-RIB.1 | When | When the chain or the variables change after a load or a save, the system shall show `· unsaved` on the ribbon. |
| R-FB-RIB.2 | While | While a project is open, the system shall show the project folder on the ribbon. |
| R-FB-RIB.3 | U | The system shall show every name, ref, command, path and finding on the Flow Builder as plain text, never as markup. |
| R-FB-RIB.4 | When | When the operator presses Space on a chip of a Flow window, the system shall press that chip. |
| R-FB-RIB.5 | While | While the Flow Builder is shown at 118 columns by 54 rows or more, the system shall keep the foot row in view without scrolling. |
| R-FB-RIB.6 | While | While the Flow Builder is shown at less than 118 columns or less than 54 rows, the system shall keep every control reachable by scrolling. |

#### S16.2 · Adding blocks (CTX-BUILDER; from S0 HLR-146, LLR-146.2, 146.3, 146.14, HLR-014, HLR-142)

| Id | Form | Requirement |
|---|---|---|
| R-FB-ADD.1 | When | When the operator presses a kind chip, the system shall show only that kind's add inputs. |
| R-FB-ADD.2 | When | When the operator presses a kind chip, the system shall clear the notice. |
| R-FB-ADD.3 | When | When the operator presses + Add with the chosen kind's inputs filled, the system shall append a block of that kind to the chain. |
| R-FB-ADD.4 | If | If a required add input is empty, then the system shall add nothing and show the notice `Add needs <field> — nothing added`. |
| R-FB-ADD.5 | If | If a path input of the add form holds a NUL character, then the system shall add nothing and show the notice `Add refused: [FLOW-UNSAFE-REF] <KIND> <field> holds a NUL character - not a path`. |
| R-FB-ADD.6 | If | If an A2B binding is empty or malformed, then the system shall add nothing and show the notice `A2B wiring refused: empty or malformed binding — use a file name or #<n> (a flow output).` |
| R-FB-ADD.7 | If | If the A2B bindings break S15 R-FLOW-A2B.2 … .4, then the system shall add nothing and show the notice `A2B wiring refused: <reasons, separated by "; ">`. |
| R-FB-ADD.8 | If | If an EXT-STEP's command or instruction is empty, then the system shall add nothing and show the notice `External step refused: <the exact command or the instruction> to run outside the app is missing.` |
| R-FB-ADD.9 | If | If an EXT-STEP's log is empty, then the system shall add nothing and show the notice `External step refused: the log file is required (the record of the step, never optional).` |
| R-FB-ADD.10 | If | If an EXT-STEP's output file is empty, then the system shall add nothing and show the notice `External step refused: the output file is missing (an absolute path is preferred).` |
| R-FB-ADD.11 | If | If an added block breaks a rule of S15 CTX-FLOWFILE, then the system shall add nothing and show the notice `Add refused: <first finding message>`. |
| R-FB-ADD.12 | When | When the operator adds a LOAD or WRITE-OUT block whose file name ends in `.hex` or `.ihex`, ignoring case, the system shall declare it Intel HEX. |
| R-FB-ADD.13 | When | When the operator adds a LOAD or WRITE-OUT block whose file name has any other ending, the system shall declare it S19. |
| R-FB-ADD.14 | When | When the operator sets the EXT-STEP mode to Terminal, the system shall label its text box `command`. |
| R-FB-ADD.15 | When | When the operator sets the EXT-STEP mode to Manual, the system shall label its text box `instruction`. |
| R-FB-ADD.16 | U | The system shall offer a REPORT kind in the palette. |
| R-FB-ADD.17 | U | The system shall offer an A2L reference input for LOAD and PATCH blocks. |
| R-FB-ADD.18 | When | When a block is added, the system shall clear the add inputs it used. |

#### S16.3 · The pipeline (CTX-BUILDER; from S0 LLR-146.1, 146.4, 146.6)

| Id | Form | Requirement |
|---|---|---|
| R-FB-PIPE.1 | U | The system shall show the chain as one row of cards in block order, with one cable between neighbours. |
| R-FB-PIPE.2 | U | The system shall give every card the same width, at least 21 columns. |
| R-FB-PIPE.3 | If | If the cards do not fit the pipeline's width, then the system shall scroll the pipeline sideways inside its frame. |
| R-FB-PIPE.4 | U | The system shall clip card texts as CTX-BUILDER clip. |
| R-FB-PIPE.5 | U | The system shall paint CRC cards in the CRC colour. |

#### S16.4 · Copy, paste and variables (CTX-BUILDER; funnel is S15 R-FLOW-FUNNEL)

| Id | Form | Requirement |
|---|---|---|
| R-FB-CLIP.1 | When | When the operator presses Copy with the block box empty, the system shall copy the last block and show `clipboard: <kind>`. |
| R-FB-CLIP.2 | When | When the operator presses Copy with a block number n, the system shall copy block n and show `clipboard: <kind>`. |
| R-FB-CLIP.3 | If | If the block number names no block, then the system shall show the notice `Copy refused: there is no block #<n> (the chain has <k>).` |
| R-FB-CLIP.4 | If | If the chain is empty when the operator presses Copy, then the system shall show the notice `Copy refused: the chain is empty.` |
| R-FB-CLIP.5 | When | When the operator presses Paste, the system shall append a new block equal to the copied one and show `pasted: <kind>`. |
| R-FB-CLIP.6 | If | If nothing was copied, then the system shall show the notice `Paste: the clipboard is empty - nothing to paste.` |
| R-FB-CLIP.7 | If | If no project is open when the operator presses Paste, then the system shall show the notice `Paste refused: load a project first (the paste is checked against the session directory).` |
| R-FB-CLIP.8 | If | If the pasted block breaks a rule of S15 CTX-FLOWFILE, then the system shall add nothing and show the notice `Paste refused: <first finding message>`. |
| R-FB-VAR.1 | When | When the operator presses Variables, the system shall show or hide the variable editor and list. |
| R-FB-VAR.2 | U | The system shall label the Variables chip `Variables (<n>)`, n the number of declared variables. |
| R-FB-VAR.3 | When | When the operator presses + Add var with a valid name and value, the system shall declare the variable, replacing the value of a variable of the same name. |
| R-FB-VAR.4 | If | If the name is not 1 to 32 characters of `A-Z`, `0-9` and `_`, then the system shall show the notice `Variable refused: the name must be a placeholder [A-Z0-9_] (e.g. BOOST) - no lower case, no spaces.` |
| R-FB-VAR.5 | If | If the value is empty, then the system shall show the notice `Variable refused: the value cannot be empty.` |
| R-FB-VAR.6 | If | If the value is longer than 256 characters or the flow already has 32 variables, then the system shall show the notice `Variable refused: at most 32 variables, each value at most 256 characters.` |
| R-FB-VAR.7 | U | The system shall list each variable as `${<NAME>} = <value>`, or `no variables — ${NAME} placeholders in change docs pass through unchanged` when there is none. |

#### S16.5 · Run, Clear and the result (CTX-BUILDER; R-TUI-059 screen half)

| Id | Form | Requirement |
|---|---|---|
| R-TUI-059.23 | When | When the operator presses Run, the system shall run the chain once over the open project as S15 states. |
| R-TUI-059.24 | If | If no project is open when the operator presses Run, then the system shall show a FAILED result with `no project loaded - load a project first`. |
| R-FB-RUN.1 | If | If the chain is empty when the operator presses Run, then the system shall show the notice `No blocks to run — add a block first.` |
| R-FB-RUN.2 | When | When a run ends, the system shall show the result of CTX-BUILDER. |
| R-FB-RUN.3 | If | If a run completed with issues and no block ended error, then the system shall show the banner NOTICES. |
| R-FB-RUN.4 | U | The system shall keep the screen responsive while a run is in progress. |
| R-FB-RUN.5 | When | When a Builder run reaches an external step, the system shall pause the run there. |
| R-FB-RUN.6 | When | When the operator presses Clear, the system shall empty the chain, the variables, the clipboard, the notice and the result. |
| R-FB-RUN.7 | If | If the flow has unsaved changes when the operator presses Clear, then the system shall ask `Discard unsaved flow edits?` first. |

#### S16.6 · Save, load and import a flow (CTX-BUILDER; from S0 HLR-015, LLR-015.1, LLR-015.2)

| Id | Form | Requirement |
|---|---|---|
| R-FB-SAVE.1 | When | When the operator presses Save…, the system shall open the dialog `Save flow as:` of CTX-BUILDER. |
| R-FB-SAVE.2 | If | If a flow of the cleaned typed name exists, then the system shall show the notice `(exists — saves as <name>_<N>.json)`. |
| R-FB-SAVE.3 | If | If the name box is empty when the operator presses Save, then the system shall keep the dialog open. |
| R-FB-SAVE.4 | When | When a flow is saved, the system shall show `✓ saved flows/<name>.json` in the result area. |
| R-FB-SAVE.5 | When | When a flow is saved, the system shall show its saved name on the ribbon with `· saved`. |
| R-FB-SAVE.6 | If | If the typed name is empty after cleaning, then the system shall show the status `Flow name is empty after sanitising - not saved.` |
| R-FB-SAVE.7 | If | If no project is open when the operator presses Save… or Load…, then the system shall show a FAILED result with `no project loaded - load or save a project first`. |
| R-FB-LOAD.1 | When | When the operator presses Load…, the system shall open the dialog `Load flow:` of CTX-BUILDER. |
| R-FB-LOAD.2 | When | When the operator presses Load on a listed flow, the system shall load that flow file into the Builder. |
| R-FB-LOAD.3 | If | If the flow has unsaved changes when a flow loads, then the system shall ask `Discard unsaved flow edits?` first. |
| R-FB-LOAD.4 | When | When the operator presses Cancel in `Discard unsaved flow edits?`, the system shall keep the current chain. |
| R-FB-LOAD.5 | When | When a flow loads, the system shall show its file name on the ribbon with `· saved` and the empty result. |
| R-FB-LOAD.6 | If | If the flow file is refused (S15 R-FLOW-FILE.5), then the system shall keep the chain and show the card `✗ LOAD REJECTED — flows/<name>.json (<n> findings)`, one line `[<code>] <message>` per finding, and `Current flow unchanged.` |
| R-FB-LOAD.7 | If | If the flow file is refused, then the system shall show `load refused: flows/<name>.json — this chain is kept` on the pipeline frame. |
| R-FB-LOAD.8 | When | When the operator presses Import…, the system shall open the system's file picker for `.json` files. |
| R-FB-LOAD.9 | When | When the operator picks a file to import, the system shall copy it as S15 R-FLOW-FILE.9 states, add it to the list and show `imported flows/<file>`. |
| R-FB-LOAD.10 | If | If the import is refused, then the system shall show `import refused: <error type>` in the dialog. |
| R-FB-LOAD.11 | If | If no file picker is available, then the system shall show `import unavailable in this environment` in the dialog. |

#### S16.7 · Flow Execution: lanes and binding (CTX-FXSCREEN; from S0 HLR-017, 018, LLR-017.1, 017.2, 018.1, HLR-147, LLR-147.2, 147.4)

| Id | Form | Requirement |
|---|---|---|
| R-FX-SCR.1 | U | The system shall offer the Flow Execution of CTX-FXSCREEN as a rail window. |
| R-FX-SCR.2 | U | The system shall show the parts of the Flow Execution in the order of CTX-FXSCREEN. |
| R-FX-SCR.3 | U | The system shall show every lane name, set name, ref, command and path on the Flow Execution as plain text, never as markup. |
| R-FX-LANE.1 | When | When the operator presses Import…, the system shall open the dialog `Load flow:` of CTX-BUILDER. |
| R-FX-LANE.2 | When | When the operator loads a flow from that dialog, the system shall add a lane for it below the others. |
| R-FX-LANE.3 | If | If a lane of that name exists, then the system shall name the new lane `<name>_<N>` with the lowest free N from 1. |
| R-FX-LANE.4 | If | If the flow file is refused, then the system shall keep the lanes and show the notice `import refused: flows/<name>.json — [<code>] <message>`. |
| R-FX-LANE.5 | If | If no project is open when the operator presses Import…, then the system shall show the notice `import refused: no project loaded - load or save a project first`. |
| R-FX-LANE.6 | When | When a lane is added, the system shall show in each LOAD card's box the ref that lane reads. |
| R-FX-LANE.7 | When | When the operator presses Bind on a LOAD card, the system shall bind that lane's LOAD ref to the box's text. |
| R-FX-LANE.8 | U | The system shall leave every other lane's refs unchanged by a Bind. |
| R-FX-LANE.9 | If | If the box is empty when the operator presses Bind, then the system shall show the notice `binding refused: lane '<lane>' input <n> needs a non-empty ref`. |
| R-FX-LANE.10 | If | If the box holds the ref the lane already reads, then the system shall change nothing on Bind. |
| R-FX-LANE.11 | When | When a lane's binding changes, the system shall drop that lane's confirmed external steps. |
| R-FX-LANE.12 | U | The system shall give every card of every lane the same width, so the k-th cards line up. |

#### S16.8 · Flow Execution: Run and the run log (CTX-FXSCREEN; from S0 HLR-019, 020, LLR-020.1, HLR-147, LLR-147.1, 147.8, 147.9, 147.10)

| Id | Form | Requirement |
|---|---|---|
| R-FX-RUN.1 | When | When the operator presses Run, the system shall run the lanes as a chain set (S15) in the mode the switch shows. |
| R-FX-RUN.2 | When | When the operator presses or clicks the mode switch, the system shall switch between sequential and parallel. |
| R-FX-RUN.3 | When | When the Flow Execution first shows, the system shall show the mode sequential. |
| R-FX-RUN.4 | If | If there is no lane when the operator presses Run, then the system shall show the log line `No chains to run — Import… adds a lane first.` |
| R-FX-RUN.5 | If | If no project is open when the operator presses Run, then the system shall show the log line `✗ no project loaded - load or save a project first`. |
| R-FX-RUN.6 | While | While a run is in progress, the system shall disable Run and every Confirm. |
| R-FX-RUN.7 | U | The system shall keep the screen responsive while a run is in progress. |
| R-FX-RUN.8 | When | When a run ends, the system shall show each lane's head, card statuses and cable marks of CTX-FXSCREEN from that run. |
| R-FX-RUN.9 | When | When a run ends, the system shall replace the run log with the log lines of CTX-FXSCREEN for that run. |
| R-FX-RUN.10 | If | If the run log holds more than 8 lines, then the system shall show the earlier-lines line and the newest 7. |
| R-FX-RUN.11 | If | If the chain set is refused (S15 R-FLOW-CHAIN.7), then the system shall show the reason in the run log and on the status line. |
| R-FX-RUN.12 | If | If a run raises an error, then the system shall show the log line `✗ run failed - <error type>: <first line of the message>`, at most 160 characters. |
| R-FX-RUN.13 | When | When a run ends, the system shall show the chain-set report's path in the run log. |
| R-FX-RUN.14 | U | The system shall use the typed set name for the report of a run and of a confirm re-run. |
| R-FX-SIZE.1 | While | While the Flow Execution is shown at 118 columns by 54 rows or more, the system shall show Import…, the mode switch, Run, Save Set and Load Set without scrolling. |
| R-FX-SIZE.2 | While | While the Flow Execution is shown at less than 118 columns or less than 54 rows, the system shall keep every control reachable by scrolling. |

#### S16.9 · Waiting and confirming (CTX-FXSCREEN; from S0 HLR-147, LLR-147.3, 147.13)

| Id | Form | Requirement |
|---|---|---|
| R-FX-WAIT.1 | While | While a lane waits at an external step, the system shall show its pending lines and its Confirm. |
| R-FX-WAIT.2 | While | While a lane waits, the system shall paint its waiting elements in the waiting colour, which no other element of the Flow windows uses. |
| R-FX-WAIT.3 | While | While an attention lane exists, the system shall show the REQUIRED line naming it. |
| R-FX-WAIT.4 | When | When the attention lane changes, the system shall scroll its waiting card and its Confirm into view without moving the focus. |
| R-FX-WAIT.5 | When | When the operator presses a waiting lane's Confirm, the system shall run that lane again as S15 R-FLOW-CHAIN.9 states. |
| R-FX-WAIT.6 | When | When the operator presses `c` and the attention lane has waited for the dwell, the system shall confirm it with the status `Confirmed <lane> — re-running from block <i>/<n>.` |
| R-FX-WAIT.7 | If | If the attention lane has waited less than the dwell when the operator presses `c`, then the system shall show the status `c ignored — <lane> started waiting a moment ago. Press c again to confirm.` |
| R-FX-WAIT.8 | If | If no lane waits when the operator presses `c`, then the system shall show the status `c: no lane is waiting for confirmation.` |
| R-FX-WAIT.9 | If | If a run is in progress when the operator presses `c`, then the system shall show the status `c: a run is in progress — wait for it to finish.` |
| R-FX-WAIT.10 | While | While another window is shown, the system shall ignore `c`. |
| R-FX-WAIT.11 | U | The system shall confirm each waiting step of a lane at most once. |
| R-FX-WAIT.12 | If | If a confirm re-run stops the flow, then the system shall show the status `<lane> failed at block <i>/<n> — <cause>; Run re-runs the set.` |
| R-FX-WAIT.13 | If | If a confirm re-run raises an error or the lane no longer waits there, then the system shall add the log line `✗ <lane> · confirm re-run failed - <reason>` and keep the lane waiting, unconfirmed. |

#### S16.10 · Save and load a chain set (CTX-FXSCREEN; from S0 HLR-021, LLR-021.2)

| Id | Form | Requirement |
|---|---|---|
| R-FX-SET.1 | When | When the operator presses Save Set, the system shall save the lanes as a chain set under the typed set name (S15 R-FLOW-SET.1). |
| R-FX-SET.2 | When | When a chain set is saved, the system shall show its saved name on the ribbon with `· saved`. |
| R-FX-SET.3 | When | When a chain set is saved, the system shall refresh the saved sets list. |
| R-FX-SET.4 | If | If the chain set is not saved (S15 R-FLOW-SET.2), then the system shall show the status `Chain set not saved - the set is empty or the name sanitised away.` |
| R-FX-SET.5 | If | If no project is open when the operator presses Save Set or Load Set, then the system shall show the status `No project loaded - load or save a project first.` |
| R-FX-SET.6 | When | When the Flow Execution is shown, the system shall fill the saved sets list from the flowsets home. |
| R-FX-SET.7 | When | When the operator presses Load Set with a set chosen, the system shall replace the lanes with that set's lanes. |
| R-FX-SET.8 | If | If the lanes have unsaved changes when the operator presses Load Set, then the system shall ask `Discard unsaved flow edits?` first. |
| R-FX-SET.9 | If | If the chain-set file is refused, then the system shall keep the lanes and show the notice `load refused: flowsets/<name>.json — [<code>] <message>`. |
| R-FX-SET.10 | If | If the chain-set file is refused, then the system shall show the status `Chain set load refused: <first message>`. |
| R-FX-SET.11 | If | If a lane's flow file is missing or refused, then the system shall leave that lane out and name it in the notice `chain(s) skipped, template missing: <lanes>`. |
| R-FX-SET.12 | When | When a chain set loads, the system shall show the notice `<n> chain(s) restored`. |
| R-FX-SET.13 | If | If a loaded lane's bound ref names no file, then the system shall show the pending line `▪ '<ref>' missing - re-bind` on that lane. |
| R-FX-SET.14 | When | When a chain set loads, the system shall show every lane as not run. |



<a id="s17"></a>

## S17 · Split / Join / Export

### Context notes (informative)

#### CTX-SJE · Terms (S17.1 … S17.4)

```text
window          Split / Join / Export. The palette opens it (S6 R-TUI-021.10); it has
                no rail item and no rail key.
loaded file     The session's primary (S5 CTX-FILES), or the MAC file in a MAC-only
                session. Its image and ranges: S1 CTX-LOAD.
source          Where the table's rows come from. One is shown at a time:
                ranges · manual · a2l.
row             A name, a base (first address) and a size in bytes.
row span        The addresses base … base + size − 1.
<ii>            A row's position, from 00, at least two digits.
locality line   One line of the manual box: <start>-<end>, two hexadecimal numbers, each
                with or without 0x or 0X. <end> is the last address.
                Example: 0x0000EB00-0x0000EBFF is 256 bytes.
manual box      The multi-line box of the manual source (S7 CTX: multi-line box).
covered byte    An address of a row span that the loaded image holds.
coverage        full (every address of the span covered) · partial · zero (none).
selection       The ticked rows of one source. Each source has its own.
mode            split · join.
gaps            split: skip · fill.    join: concat · fill.
pad byte        0x00 or 0xFF.
format          S19 · HEX · BIN. File extension <ext>: s19, hex, bin.
destination     project: <work area>/<project>/splits/
                common:  <work area>/splits/            (work area: S5 CTX-WORKAREA)
stem            The name of the loaded file without its extension.
export request  The e key, or the EXPORT button.
confirm         A second export request that the system asks for (CTX-SJE-PLAN).
```

#### CTX-SJE-PLAN · What an export holds (S17.5, S17.6, S17.8)

```text
export file     A file the export writes: one per selected row in split mode, one for
                all selected rows in join mode. A BIN file comes with its sidecar.
split file      An export file of split mode. join file: the one of join mode.
empty file      An export file whose selected rows hold no covered byte.
join span       Join fill: the lowest selected base … the highest last address of the
                selected rows.
join gap        The addresses of the join span that no selected row spans.
conflict byte   An address of a join gap where the loaded image holds a byte that
                differs from the pad byte.
fill file       A split file with gaps fill, or the join file with join fill.
guard file      A fill file whose span is at least 1 MiB (1,048,576 bytes) and whose
                pad bytes are at least 50 % of that span.
guard span      The span of the largest guard file.
```

#### CTX-SJE-BAND · Preview band classes (S17.5)

```text
data       the export writes the image's byte at this address
fill       the export writes the pad byte at this address
conflict   a conflict byte
context    the loaded image holds this address; no export file does
absent     neither the loaded image nor an export file holds this address
band span  split and join fill: the lowest to the highest address of the loaded image
           and the selected row spans. join concat: the bytes of the join file, from
           its first.
```

#### CTX-SJE-FORMAT · Export file formats (S17.6)

```text
S19 export      An S19 file by S8.7 (R-S19-EMIT.1 … .10, CTX-WRITE), with at most 32
                data bytes per data record.
HEX export      An Intel HEX file by S8.7 (R-HEX-EMIT-001.1 … .10, CTX-WRITE).
BIN file        The export file's bytes, nothing else: no address, no header, no
                record structure.
sidecar         One line, 0x<A8> and a line end, ASCII.
line end        CR LF on Windows, LF on other systems.
<A8>            An address as 8 uppercase hexadecimal digits.
```

#### CTX-SJE-NAME · Export file names (S17.7)

```text
segment part    The row name with every character outside A-Z a-z 0-9 _ - replaced by
                _, cut to its first 100 characters.
split name      <stem>_<segment part>.<ext>
join name       <stem>_joined.<ext>
sidecar name    The BIN file's name with .addr in place of .bin.
numbered name   <name>_<N>.<ext>, N = 1, 2, … (S5 CTX-WORKAREA).
name limit      200 characters, counting a two-digit numbered suffix and the extension.
path limit      260 characters, the full path.
staging path    <work area>/temp/.staging/stage-<8 characters>/<name>: where a file is
                written before it is placed.
copy limit      256 MiB, 268,435,456 bytes (S5 CTX-WORKAREA).
```

#### CTX-SJE-TEXT · Texts (S17.3, S17.5, S17.7, S17.8)

```text
notice            A status-line text that also shows as a notification.
size              <n> B below 1 KiB · <x.x> KiB below 1 MiB · <x.xx> MiB from 1 MiB.
<pct>             A percentage with 2 decimals.
file(s)           "file" when the count is 1, else "files".
<raw>             A row name through S1's safe-text rule, first 80 characters.
dropped list      Up to 3 dropped manual lines, without surrounding whitespace, joined
                  by ", ", then " (+<k> more)" when there are more.
split summary     Selected <k>/<n> <noun> · <size> · export → <FORMAT> × <k> file(s) ·
                  intra_gap=<skip|fill>, then " (pad 0x<PP>)" for fill, then
                  " → <destination folder>". One line. <size>: the covered bytes.
concat summary    Join <k> <noun> → 1 file · join=concat · <size> packed from base
                  0x<A8> · <FORMAT> → <destination folder>
fill summary      Join <k> <noun> → 1 file · join=fill · span 0x<A8>–0x<A8> = <size>
                  (packed <size>) · pad 0x<PP> · <FORMAT> → <destination folder>
                  (first and last address of the join span)
  <noun>          segments (a2l) · ranges (ranges) · localities (manual)
confirm reasons   "span guard: <guard span size> span from <size> of data (<pct>% pad)"
                  and "<n> empty file(s) — 0 B of source", in that order, joined by
                  " — ", each when it applies.
refusal notice    Export refused: <reason>, then " — segment <raw> → <segment part>"
                  for each row the reason is about.
written list      "wrote <name>" for up to 3 written files, joined by "; ", then
                  "; +<k> more wrote" when more; then "; reused <name>, <name>, <name>"
                  (" +<k> more" when more) when files were reused.
part-way notice   Export failed: Export stopped: <error>. Already written: <names, or
                  nothing>, then "; reused: <names>" when files were reused.
```

#### CTX-SJE-LAYOUT · The screen today (informative; changes need a prototype round)

```text
Left        SEGMENTS chip line (a2l(<n>) ranges(<n>) manual(<n>), the shown source as
            ‹name(n)›, "[a]ll [n]one"), the table, the manual box (manual source only),
            then one line each: MODE, INTRA GAP / JOIN GAPS (+ PAD when fill), FORMAT,
            DEST, NAMING (‹stem›_‹segment› → <sample>).
Right       Pane titled PREVIEW: output label, band, per-file rows, legend, ruler,
            stats (two lines: metrics, state line), summary, EXPORT  e button.
Widths      Measured screen width ≥ 118: preview 58 columns, band 54 cells.
            < 100: preview 30, per-file rows hidden, stats show the state line only.
            Between: preview 40.
Band        data ▓ #91abec · fill ░ #6b7280 · conflict ▒ #f6ff8f · context · #46557a ·
            absent (space). Every run of one class keeps at least one cell.
Table row   ●/○ selected, name, base 0x<A8>, size, coverage:
            ✓ <size> (green #54efae) · ◐ <covered> of <size> (amber #d9a35b) ·
            ✗ 0 B of <size> (red #fd8383). Narrower tiers shorten the name and the
            coverage text, then drop the size.
Per-file    Split mode with 1 to 6 files: <file label> <band> <size>; an empty file:
rows        ∅ empty — 0 B of source in span.
Output      join: <stem>_joined.<ext> · split: <n> file(s) · ‹<first selected row name>›
label
Ruler       0x<first> … 0x<middle> … 0x<last> address of the band span.
Legend      ▓ data ░ pad ▒ conflict · source ctx (narrow: data pad clash src).
```

---

### Requirements


#### S17.1 · Opening and closing (from S0 HLR-135, LLR-135.6)

The palette entry and closing by a rail key are S6's (R-TUI-021.10, R-TUI-021.11, R-TUI-022.2); the window's keys in the key bar and its help section are S7's.

| Id | Form | Requirement |
|---|---|---|
| R-SEG-OPEN.1 | When | When the operator opens the window, the system shall focus its table. |
| R-SEG-OPEN.2 | When | When the operator presses Esc in the window, the system shall show the window that was shown before it opened. |
| R-SEG-OPEN.3 | When | When the operator opens the window again with the same loaded file, the system shall show the source, selections and settings it had. |
| R-SEG-OPEN.4 | When | When the loaded file changes, the system shall clear the selections of the ranges and a2l sources. |
| R-SEG-OPEN.5 | When | When the loaded file changes, the system shall keep the text of the manual box. |
| R-SEG-OPEN.6 | While | While the window is hidden, the system shall keep the focus out of it. |

#### S17.2 · Sources and the table (from S0 LLR-135.7)

| Id | Form | Requirement |
|---|---|---|
| R-SEG-SRC.1 | When | When the operator opens the window for the first time in a session, the system shall show the ranges source. |
| R-SEG-SRC.2 | When | When the operator presses `t`, the system shall show the next source in the order ranges, manual, a2l, ranges. |
| R-SEG-SRC.3 | U | The system shall show the number of rows of each source beside the source's name. |
| R-SEG-SRC.4 | U | The system shall list in the ranges source one row per range of the loaded image, in address order. |
| R-SEG-SRC.5 | U | The system shall name the rows of the ranges source `range_<ii>`. |
| R-SEG-SRC.6 | U | The system shall list in the a2l source one row per MEMORY_SEGMENT of the session's A2L that has a base and a size above 0. |
| R-SEG-SRC.7 | U | The system shall name each row of the a2l source after its MEMORY_SEGMENT. |
| R-SEG-SRC.8 | If | If a MEMORY_SEGMENT has no name, then the system shall name its row `segment_<ii>`, where `<ii>` is the segment's position among the A2L's MEMORY_SEGMENTs. |
| R-SEG-SRC.9 | If | If no A2L is loaded, then the system shall show in the a2l source the note `no A2L loaded — load one (^L) or use ranges/manual`. |
| R-SEG-SRC.10 | If | If the session's A2L has no MEMORY_SEGMENT with a base and a size above 0, then the system shall show in the a2l source the note `the A2L has no MEMORY_SEGMENT with a base and a size`. |
| R-SEG-SRC.11 | If | If the loaded image has no range, then the system shall show in the ranges source the note `no ranges — load an image (^L) or switch to manual`. |
| R-SEG-SRC.12 | If | If the manual box holds no locality line, then the system shall show in the manual source the note `type localities (0xSTART-0xEND, one per line)`. |
| R-SEG-SRC.13 | When | When the system shows a table row, the system shall show the row's name, base and coverage. |
| R-SEG-SRC.14 | When | When the system shows a table row, the system shall show whether the row is selected. |
| R-SEG-SRC.15 | When | When the operator presses up or `k`, the system shall move the table cursor one row up. |
| R-SEG-SRC.16 | When | When the operator presses down or `j`, the system shall move the table cursor one row down. |
| R-SEG-SRC.17 | When | When the operator presses space, the system shall switch the selection of the row under the cursor. |
| R-SEG-SRC.18 | When | When the operator presses `a`, the system shall select every row of the shown source. |
| R-SEG-SRC.19 | When | When the operator presses `n`, the system shall clear the selection of the shown source. |
| R-SEG-SRC.20 | When | When the operator shows another source, the system shall keep the selection of every source. |

#### S17.3 · Manual localities (from S0 LLR-135.7)

| Id | Form | Requirement |
|---|---|---|
| R-SEG-MAN.1 | When | When the operator edits the manual box, the system shall list one manual row per locality line, in line order. |
| R-SEG-MAN.2 | U | The system shall name the rows of the manual source `locality_<ii>`. |
| R-SEG-MAN.3 | U | The system shall read the end of a locality line as the last address of the locality. |
| R-SEG-MAN.4 | U | The system shall ignore spaces and tabs in a locality line. |
| R-SEG-MAN.5 | U | The system shall accept each number of a locality line with or without `0x` or `0X`. |
| R-SEG-MAN.6 | U | The system shall ignore empty lines of the manual box. |
| R-SEG-MAN.7 | If | If a line of the manual box is not a locality line, then the system shall list no row for it. |
| R-SEG-MAN.8 | If | If the end of a locality line is below its start, then the system shall list no row for it. |
| R-SEG-MAN.9 | When | When the set of lines dropped from the manual box changes and is not empty, the system shall show the status `manual: dropped <dropped list>`. |

#### S17.4 · Settings (from S0 HLR-136, LLR-136.4, LLR-136.5)

| Id | Form | Requirement |
|---|---|---|
| R-SEG-SET.1 | When | When the system starts, the system shall set the mode to split. |
| R-SEG-SET.2 | When | When the system starts, the system shall set the gaps to skip. |
| R-SEG-SET.3 | When | When the system starts, the system shall set the pad byte to 0x00. |
| R-SEG-SET.4 | When | When the system starts, the system shall set the format to S19. |
| R-SEG-SET.5 | When | When the system starts, the system shall set the destination to project. |
| R-SEG-SET.6 | When | When the operator presses `m`, the system shall switch the mode between split and join. |
| R-SEG-SET.7 | When | When the mode changes to join, the system shall set the gaps to concat. |
| R-SEG-SET.8 | When | When the mode changes to split, the system shall set the gaps to skip. |
| R-SEG-SET.9 | When | When the operator presses `g` in split mode, the system shall switch the gaps between skip and fill. |
| R-SEG-SET.10 | When | When the operator presses `g` in join mode, the system shall switch the gaps between concat and fill. |
| R-SEG-SET.11 | When | When the operator presses `p`, the system shall switch the pad byte between 0x00 and 0xFF. |
| R-SEG-SET.12 | When | When the operator presses `f`, the system shall change the format in the order S19, HEX, BIN, S19. |
| R-SEG-SET.13 | When | When the operator presses `d`, the system shall switch the destination between project and common. |
| R-SEG-SET.14 | If | If no project is open, then the system shall export to the common destination. |

#### S17.5 · The preview (from S0 HLR-135, HLR-136, LLR-135.5, LLR-136.6)

| Id | Form | Requirement |
|---|---|---|
| R-SEG-PREV.1 | When | When the rows, the selection or a setting changes, the system shall update the preview. |
| R-SEG-PREV.2 | When | When the system shows the preview band, the system shall show each address of the band span in the class of CTX-SJE-BAND that the planned export gives it. |
| R-SEG-PREV.3 | While | While no row is selected and the loaded image has no range, the system shall show in the band `· nothing selected — tick a row with ␣ or press a for all`. |
| R-SEG-PREV.4 | When | When the system shows the naming line, the system shall show as its sample the name the export would give its first file. |
| R-SEG-PREV.5 | While | While split mode is chosen with no row selected, the system shall show the naming sample `<stem>_segment.<ext>`. |
| R-SEG-PREV.6 | While | While no row is selected, the system shall show the state line `∅ nothing selected — tick a row (␣) or press a`. |
| R-SEG-PREV.7 | If | If the planned export has a conflict byte, then the system shall show the state line `⚠ <size> would clobber source — abort on export`. |
| R-SEG-PREV.8 | If | If the planned export has a guard file and no conflict byte, then the system shall show the state line `⚠ GUARD  <guard span size> span — e will ask`. |
| R-SEG-PREV.9 | If | If the planned export has an empty file, no guard file and no conflict byte, then the system shall show the state line `⚠ <n> empty file(s) — 0 B of source — e will ask`. |
| R-SEG-PREV.10 | While | While the confirm is armed, the system shall show `— e again to confirm` in place of `— e will ask` in the state line. |
| R-SEG-PREV.11 | If | If a row is selected and the planned export has no conflict byte, no guard file and no empty file, then the system shall show the state line `ready — e exports`. |
| R-SEG-PREV.12 | While | While split mode is chosen with a row selected, the system shall show the stats line `<n> file(s) · <size> data`. |
| R-SEG-PREV.13 | While | While split mode is chosen and the planned files hold pad bytes, the system shall end the stats line with `  ·  <size> pad`. |
| R-SEG-PREV.14 | While | While join concat is chosen with a row selected, the system shall show the stats line `packed <size>  ·  concat: offsets remapped, no pads`. |
| R-SEG-PREV.15 | While | While join fill is chosen with a row selected, the system shall show the stats line `packed <size>  ·  span <size>  ·  fill <pct>%`. |
| R-SEG-PREV.16 | While | While split mode is chosen, the system shall show the split summary of CTX-SJE-TEXT. |
| R-SEG-PREV.17 | While | While join concat is chosen with a row selected, the system shall show the concat summary of CTX-SJE-TEXT. |
| R-SEG-PREV.18 | While | While join fill is chosen with a row selected, the system shall show the fill summary of CTX-SJE-TEXT. |
| R-SEG-PREV.19 | While | While join mode is chosen with no row selected, the system shall show the summary `Join mode — select at least one range to join`. |

#### S17.6 · What an export holds (from S0 HLR-136, HLR-137, LLR-160.3)

| Id | Form | Requirement |
|---|---|---|
| R-SEG-OUT.1 | When | When the system exports in split mode, the system shall write one export file per selected row. |
| R-SEG-OUT.2 | When | When the system exports in split mode with gaps skip, the system shall put in each split file the covered bytes of its row span, at their addresses. |
| R-SEG-OUT.3 | When | When the system exports in split mode with gaps fill, the system shall put in each split file every address of its row span, with the pad byte where the image holds no byte. |
| R-SEG-OUT.4 | If | If a split file is an empty file, then the system shall write it with no data byte. |
| R-SEG-OUT.5 | When | When the system exports in join mode, the system shall write one export file for all selected rows. |
| R-SEG-OUT.6 | When | When the system exports in join concat, the system shall put in the join file the covered bytes of the selected rows, in ascending order of base, back to back from the lowest selected base. |
| R-SEG-OUT.7 | When | When the system exports in join fill, the system shall put in the join file every address of the join span, with the pad byte where no selected row has a covered byte. |
| R-SEG-OUT.8 | U | The system shall take the bytes of an export only from addresses inside the ranges of the loaded image. |
| R-SEG-OUT.9 | When | When the system writes a BIN file, the system shall write its bytes in ascending address order. |
| R-SEG-OUT.10 | When | When the system writes a BIN file, the system shall write a sidecar that holds the address of the BIN file's first byte. |
| R-SEG-OUT.11 | If | If a BIN file holds no byte, then the system shall write in its sidecar the lowest base of its selected rows. |
| R-SEG-OUT.12 | If | If a BIN split file with gaps skip would hold covered bytes that are not contiguous, then the system shall refuse the export with the reason `"<name>" has gaps; a BIN file cannot keep their addresses — choose gaps fill (g)`. |
| R-SEG-OUT.13 | When | When the system writes an S19 file of an export, the system shall write it as an S19 export of CTX-SJE-FORMAT. |
| R-SEG-OUT.14 | When | When the system writes an S19 file of an export from an image loaded from an S19 file, the system shall write the source's S0 data in the S0 record. |
| R-SEG-OUT.15 | When | When the system writes an S19 file of an export, the system shall write address 0 in the terminator. |
| R-SEG-OUT.16 | When | When the system writes a HEX file of an export, the system shall write it as a HEX export of CTX-SJE-FORMAT. |
| R-SEG-OUT.17 | When | When the system writes an S19 file, a HEX file or a sidecar of an export, the system shall end each line with the line end of CTX-SJE-FORMAT. |
| R-SEG-OUT.18 | If | If an export file holds bytes of an invalid range (S8 CTX-SAVEBACK), then the system shall show the warning notification `Warning: <n> invalid source ranges exported, first at 0x<A8>`. |

#### S17.7 · Names and placement (from S0 HLR-160, LLR-160.1, 160.2, 160.4, 160.5)

| Id | Form | Requirement |
|---|---|---|
| R-SEG-NAME.1 | When | When the system plans a split export, the system shall give each split file the split name of CTX-SJE-NAME. |
| R-SEG-NAME.2 | When | When the system plans a join export, the system shall give the join file the join name of CTX-SJE-NAME. |
| R-SEG-NAME.3 | When | When the system plans a BIN file, the system shall give its sidecar the sidecar name of CTX-SJE-NAME. |
| R-SEG-NAME.4 | U | The system shall shorten the stem of an export file name so that the name stays within the name limit. |
| R-SEG-NAME.5 | If | If no file is loaded, then the system shall use the stem `output`. |
| R-SEG-PLACE.1 | When | When the system writes an export, the system shall create the destination folder if it does not exist. |
| R-SEG-PLACE.2 | When | When the system shows or refreshes the window, the system shall create no folder. |
| R-SEG-PLACE.3 | If | If the destination holds a file with the same content as an S19 or HEX export file, under its name or one of its numbered names, then the system shall reuse that file. |
| R-SEG-PLACE.4 | If | If the name of an S19 or HEX export file is taken in the destination by a different content, then the system shall write the file under the lowest free numbered name. |
| R-SEG-PLACE.5 | If | If the destination holds a BIN file and a sidecar with the same contents as a planned pair, under the pair's names or one shared numbered suffix, then the system shall reuse both files. |
| R-SEG-PLACE.6 | If | If a BIN pair is not reused and one of its names is taken in the destination, then the system shall write both files under the lowest numbered suffix that is free for both names. |
| R-SEG-PLACE.7 | If | If the destination folder is not inside the work area, then the system shall refuse the export with the notice `Export refused: Refusing to place: destination is not contained inside <base>/.s19tool/workarea/: <path>`. |
| R-SEG-PLACE.8 | If | If the path to the destination folder passes through a link (S5 CTX-WORKAREA), then the system shall refuse the export with the notice `Export refused: Refusing to place: destination traverses a symbolic link or reparse point: <path>`. |
| R-SEG-PLACE.9 | If | If the destination folder cannot be created, then the system shall refuse the export with the notice `Export refused: Refusing to export: destination cannot be created: <folder> (<error>)`. |
| R-SEG-PLACE.10 | If | If a link exists at the name of an export file, then the system shall refuse the export with the reason `"<name>" already exists as a link or reparse point — refusing to write through it`. |
| R-SEG-PLACE.11 | If | If the full path of an export file with a two-digit numbered suffix would exceed the path limit, then the system shall refuse the export with the reason `"<name>" resolves to <n> characters — over the platform limit of 260`. |
| R-SEG-PLACE.12 | If | If the staging path of an export file with a two-digit numbered suffix would exceed the path limit, then the system shall refuse the export with the reason `"<name>" stages at <n> characters — over the platform limit of 260`. |
| R-SEG-PLACE.13 | If | If two export file names are equal when compared case-folded, then the system shall refuse the export with the reason `export names collide (compared case-folded): "<name>" (segment <raw>) and "<name>" (segment <raw>)`. |
| R-SEG-PLACE.14 | If | If an export file would be larger than the copy limit, then the system shall refuse the export with the reason `"<name>" would be <n> bytes — over the copy limit of 268435456 bytes`. |
| R-SEG-PLACE.15 | If | If the system refuses an export with a reason, then the system shall show the reason as the refusal notice of CTX-SJE-TEXT. |
| R-SEG-PLACE.16 | If | If the system refuses an export, then the system shall write no file of it. |
| R-SEG-PLACE.17 | If | If writing a BIN pair fails, then the system shall leave neither file of the pair in the destination. |
| R-SEG-PLACE.18 | If | If writing an export fails after a file is placed, then the system shall show the part-way notice of CTX-SJE-TEXT. |

#### S17.8 · Exporting (from S0 HLR-136, LLR-135.5, LLR-136.4, LLR-136.6)

| Id | Form | Requirement |
|---|---|---|
| R-SEG-EXP.1 | When | When the operator makes an export request, the system shall start an export. |
| R-SEG-EXP.2 | If | If no row is selected when an export starts, then the system shall show the status `nothing selected — tick a row with ␣ or press a`. |
| R-SEG-EXP.3 | If | If the planned export has a conflict byte, then the system shall refuse it with the notice `Export aborted: <n> source byte(s) in a padded gap differ from the pad byte 0x<PP>, first at 0x<A8>. Nothing written.` |
| R-SEG-EXP.4 | If | If two selected rows of a join export share an address, then the system shall refuse it with the notice `Export aborted: rows 0x<A8>–0x<A8> and 0x<A8>–0x<A8> overlap. Nothing written.` |
| R-SEG-EXP.5 | If | If an export starts while the confirm is not armed and the planned export has a guard file or an empty file, then the system shall arm the confirm without writing. |
| R-SEG-EXP.6 | When | When the system arms the confirm, the system shall show the warning notification `<confirm reasons> — press e again to confirm`. |
| R-SEG-EXP.7 | When | When an export starts while the confirm is armed, the system shall write the export. |
| R-SEG-EXP.8 | When | When the operator changes the selection, the source, the mode, the gaps, the pad byte, the format or the destination, the system shall disarm the confirm. |
| R-SEG-EXP.9 | When | When the operator edits the manual box, the system shall disarm the confirm. |
| R-SEG-EXP.10 | When | When the loaded file changes, the system shall disarm the confirm. |
| R-SEG-EXP.11 | When | When an export is written or refused, the system shall disarm the confirm. |
| R-SEG-EXP.12 | When | When every file of an export is written or reused, the system shall show the status `Exported <n> file(s): <written list> → <destination folder>`. |
| R-SEG-EXP.13 | When | When every file of an export is written or reused, the system shall show the notification `Exported <n> file(s): <written list>`. |
| R-SEG-EXP.14 | If | If an export fails for a reason that no other row of S17.7 or S17.8 names, then the system shall show the notice `Export failed: <error>`. |


