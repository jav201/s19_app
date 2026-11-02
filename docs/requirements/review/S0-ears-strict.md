# S0 — Project, documentation & process meta: context notes and strict EARS rows (2026-10-30)

Input: `REQUIREMENTS.by-module.md` chapter S0 (lines 55–468): 4 primary rows (R-TUI-032, R-TUI-034, R-DOC-001, R-TUI-048), the "Retired ids" section (21 AT-/TC- ids, a note on burned ids) and its table of batch ids (62 HLR and 225 LLR rows, batches 91–99, lines 177–465). Pointers to S0 from the finished groups S1–S17 (`grep -n "HLR-\|LLR-" review/S*-ears-strict.md`).
Code: `base/README.md`, `base/pyproject.toml`, `base/tests/test_tui_snapshot.py`, `test_tui_helpers.py`, `test_examples_smoke.py`, `test_id_registry.py`, `base/AT-TC-REGISTRY.jsonl`, and, for the gaps, `s19_app/tui/screens.py::LegendScreen`, `legend.py`, `screens_directionb.py`, `app.py::action_show_legend`. Every fact with `file:line`. No test was run.
Reconciled with s19_app 570b4b5 (batch-100) on 2026-11-01: the S0.2 lines HLR-005, HLR-151, HLR-162 and the 42 batch-100 lines, CTX-RETIRED and decisions D0-8, D0-13 verified at 570b4b5 (`REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl`, the batch-100 `01-requirements.md`); other cites refer to 093a7c0.

Result:
- **Context notes first** (section 3): CTX-README, CTX-RETIRED.
- **Rows** (section 4.1): the README the operator reads. One EARS form each, one `shall`; none uses `Where`. The four old rows are repository and process rules: they leave (section 5).
- **Retired batch ids** (section 4.2): one line per HLR, each **absorbed**, **retired** or **gap**. Counts by script in section 6.
- **Decisions** (section 5), each with a recommendation already applied. Rules E1–E7: `review/S1-ears-strict.md` section 1. Code changes: `cc-S0.md`. Nothing is changed in the code yet.

---

## 1. How S0 was written before

- Four rows about the repository, not the tool: a dev-only test dependency and its CI jobs (R-TUI-032), which fixtures snapshot baselines may use (R-TUI-034), module docstrings (R-DOC-001), and a one-time move of example fixtures with sizes and git commands (R-TUI-048).
- A "Retired ids" section that is two things: 21 AT-/TC- ids whose tests are gone (copied from the id registry), and 287 batch requirement rows (HLR-/LLR-) from batches 91–99, all marked `active`. Many of those describe shipped behaviour that no R-row described; the other groups have now written rows for them and left pointers here.
- No row about the README, the one document the operator reads before starting the tool.

## 2. What did not make sense

| Where | What did not make sense | Fix |
|---|---|---|
| R-TUI-032 | A dependency list, version pins, CI jobs and a `.gitattributes` rule: repository tooling, and library names are implementation. It is also stale: it says the legacy `project.toml` is "kept aligned", but no `project.toml` exists; it says the runtime set is `rich` and `textual`, but `pyproject.toml:57` adds `markdown-it-py`. | Out (D0-1). |
| R-TUI-034 | A rule for the test suite of a public repository (which fixtures a snapshot may render). No operator sees it. | Out of the requirements; written as a repository rule (D0-2, D0-12). |
| R-DOC-001 | "high-level documentation and key method docstrings to aid maintenance": developer documentation, verified only as "a docstring exists". | Out (D0-3). |
| R-TUI-048 | A batch-36 record: `git mv`, `git rm`, "96 MB to ~42 MB", gate evidence, a census taken "BEFORE the irreversible `git rm`". History. | Out (D0-4). |
| "Retired ids" heading | Its own definition: "a retired id was live and its verifier is gone". The 287 HLR/LLR rows under it are marked `active`, and most describe behaviour the code has today. They sit there because the registry guard lets a non-live id appear only under this heading. | Each HLR classified (section 4.2, D0-6). |
| HLR/LLR rows | Written as batch records: "When Inc-A lands", "the batch's diff shall", function names, `file:line`, NEW markers, ruling ids. Not one is a single EARS sentence. | Behaviour now lives in the group files; S0 keeps one pointer line per HLR. |
| HLR-013 vs HLR-146 | A block-diagram canvas with cable routing vs one row of cards. Both `active`. | HLR-146 wins (newer, shipped; S16 D16-3). HLR-013 retired. |
| HLR-012 vs S3 R-VAL-032 | Standard ASAP2 block names re-labelled INFO on the Issues screen vs not raised at all. | S3 decided (D3-12); HLR-012 points there. |
| HLR-123 | One sentence for four documents: the README (read by the operator) and three developer documents. | README rows (S0.1); the rest out (D0-7). |

---

## 3. Context notes (informative)

### CTX-README · The README (S0.1)

```text
README          README.md at the top of the delivered source tree. It is also the
                package's long description (pyproject.toml:36).
window          A window of S6 CTX-SHELL: the twelve rail windows and Split / Join /
                Export.
key             A key of S6 CTX-KEYS.
```

### CTX-RETIRED · Classes of a retired batch id (S0.2)

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

### CTX-CANON · The requirements file (S0.3)

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

## 4. The chapter, rewritten

Form column: U = ubiquitous. "Code today": **Yes**, **Yes; tested**, **Partly** / **No** with the decision.

### S0.1 · The README (CTX-README; from S0 HLR-123)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-DOC-README.1 | U | The system shall include a README that gives the steps to install the system and the command that starts the TUI. | Yes. |
| R-DOC-README.2 | U | The system shall describe each window of CTX-README in its README. | Partly: no Check Editor, Flow Execution or Split / Join / Export; it says "ten single-context screens" (D0-9). |
| R-DOC-README.3 | U | The system shall list each key of CTX-README in its README with its action. | Partly: `=`, `]`, Ctrl+Q, `d` and `c` are missing (D0-10). |
| R-DOC-README.4 | U | The system shall describe in its README no window, key, command or file that the system does not provide. | Partly: the Operations section says `extract` and `split_by_segment` run, and flows are said to persist to `flow.json` (D0-11). |

### S0.2 · Retired batch ids: where each lives now (CTX-RETIRED)

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
| HLR-158 · LLR-158.1 … .3 | **absorbed** · S2: R-A2L-024, R-A2L-025, R-A2L-026, R-A2L-027, R-A2L-056, R-A2L-057, R-A2L-058.1, R-A2L-058.2, R-A2L-058.3, R-A2L-006.7 | Decoding. Encoding is deferred with the symbol input (S10 D10-13, D10-42). |
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


### S0.3 · The requirements file (CTX-CANON; from batch-101 Inc 1)

| Id | Form | Requirement | Code today |
|---|---|---|---|
| R-DOC-CANON.1 | U | The system shall keep its requirements in one file, `REQUIREMENTS.md`, at the root of its repository. | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |
| R-DOC-CANON.2 | U | The system shall give each requirement in `REQUIREMENTS.md` one table row with an id, a form and a sentence. | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |
| R-DOC-CANON.3 | U | The system shall write each requirement sentence in `REQUIREMENTS.md` in the form its row names, with the opening words of that form (CTX-CANON). | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |
| R-DOC-CANON.4 | U | The system shall write each requirement sentence in `REQUIREMENTS.md` with the obligation word of CTX-CANON exactly once. | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |
| R-DOC-CANON.5 | U | The system shall give each requirement row in `REQUIREMENTS.md` an id that no other row in the file uses. | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |
| R-DOC-CANON.6 | U | The system shall group the requirement rows of `REQUIREMENTS.md` under the modules S0 … S17, in that order. | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |
| R-DOC-CANON.7 | U | The system shall keep the requirements file that `REQUIREMENTS.md` replaced, byte for byte as committed at e273181, in `docs/requirements/history/`. | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |
| R-DOC-CANON.8 | U | The system shall cite in the absorbing cell of each line of S0's table (S0.2) only ids of rows that exist in `REQUIREMENTS.md`. | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |
| R-DOC-CANON.9 | U | The system shall keep, for each module, the decisions behind its rows in `docs/requirements/review/`. | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |
| R-DOC-CANON.10 | U | The system shall name in `docs/requirements/review/` only tests that are defined under `tests/`. | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |
| R-DOC-CANON.11 | U | The system shall write each requirement sentence in `REQUIREMENTS.md` as one sentence. | No: `REQUIREMENTS.md` at e273181 is the earlier canon; batch-101 Inc 1 replaces it (D0-14). |

---

## 5. Decisions: recommendation applied

**Requirement follows the code, or moves (no code change)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D0-14 | The requirements file itself had no rows: what `REQUIREMENTS.md` must hold and keep was written only in process notes. Batch-101 Inc 1 makes this review the canon. | S0.3 rows R-DOC-CANON.1 … .9 state it; a guard test (`tests/test_requirements_canon.py`) checks them. |
| D0-1 | R-TUI-032: the `[dev]` extra pins `pytest-textual-snapshot==1.1.0` and `textual==8.2.8` (`pyproject.toml:66`, `:73`); CI runs the snapshot suite in a non-blocking job; baselines regenerate in CI only. Repository tooling, partly stale (no `project.toml`; `markdown-it-py` is a runtime dependency, `pyproject.toml:57`). | Out of the requirements. The pins and their reasons stay in `pyproject.toml` comments and the CI workflows. |
| D0-2 | R-TUI-034: snapshot baselines render only public synthetic fixtures (`examples/case_00_public/`, the `tests/conftest.py` generators). `tests/test_tui_snapshot.py:64-89` imports only those; `test_tc016s_snapshot_setup_loads_only_public_fixtures` checks it. A rule for the test suite, not product behaviour. | Out of the requirements; kept as a written repository rule (D0-12). The test stays. |
| D0-3 | R-DOC-001: docstrings on `s19_app/tui/__init__.py` and `app.py`, checked by `test_tui_module_has_docstring` and `test_tui_app_has_docstring` (`tests/test_tui_helpers.py:385`, `:389`). Developer documentation. | Out of the requirements. The two tests stay as repository checks. |
| D0-4 | R-TUI-048: the batch-36 move of `tmp/stress_smoke/` to `examples/case_07_stress_smoke/` and the prune of a 54 MB duplicate. Done: `tmp/` is gone, `SLOW_CASE_IDS` is empty (`tests/test_examples_smoke.py:46`), checked by `test_at060a_fixtures_relocated_heavy_duplicate_pruned` and `test_tc323_discovery_and_coverage_map` (`:170`, `:229`). | Out of the requirements (history). The tests stay. |
| D0-5 | The 21 AT-/TC- retired ids and the burned-id note are copied from `AT-TC-REGISTRY.jsonl`, which the section itself names the authority ("if the two ever disagree, the registry wins"). | Out of the requirements; the registry keeps them. |
| D0-6 | 62 HLR and 225 LLR rows sit under "Retired ids", marked `active`. The groups S1–S17 have written rows for most of them and left pointers. | One line per HLR in S0.2 (absorbed, retired or gap). The table leaves the requirements; each group file keeps its "(from S0 …)" pointers. |
| D0-7 | HLR-123 also asks `docs/overview.md`, `docs/architecture.md` and `docs/crc-algorithm-designer/01-requirements.md` to describe the current app. Developer documents. | Out of the requirements. Only the README, which the operator reads, gets rows (S0.1). |
| D0-13 | Batch-100 (s19_app 570b4b5, not closed: `05-close.md` is a template) wrote HLR-163 … HLR-178 (42 HLR ids with the lettered sub-HLRs) and their LLRs in its `01-requirements.md`, with AT-B100-01 … 21 and TC-B100-NN. They enter `REQUIREMENTS.md` at the batch close; at 570b4b5 `REQUIREMENTS.md` holds none of them (only LLR-151.1, marked retired) and `AT-TC-REGISTRY.jsonl` holds no AT-B100 / TC-B100 id. The groups wrote rows for their behaviour in the 570b4b5 reconciliation. | One pointer line per batch-100 HLR in S0.2, in the same classes as D0-6; batch-14 LLR-015.3 as amended by LED .13 is S8 R-S19-WIDTH-001.1, .2 and S11 R-PROJ-IMAGE.7, .8, .11 (S8 D8-35, S11 D11-53). When the batch closes, its rows in `REQUIREMENTS.md` give way to these pointers as D0-6 says. D0-8's registry update also covers the AT-B100 and TC-B100 ids (cc D0-8). |

**Remove (rule use/defer/delete)**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D0-8 | The registry guard (`tests/test_id_registry.py`, rules G3 and G4) scans `REQUIREMENTS.md` (`EXPECTED_SCANNED_TOTAL`, `:218`) and lets a non-live id appear only under the headings `## Retired ids` and `## History / superseded` (`AT-TC-REGISTRY.jsonl`, `g4_exempt_anchors`). D0-5 and D0-6 empty those headings. | Keep the guard (used: it stops a requirement from naming a test that is gone). The batch that writes the new `REQUIREMENTS.md` updates the exempt headings in the same change, and registers the AT-B100 and TC-B100 ids of batch-100 (D0-13) (cc D0-8). |

**Code change: correct a defect**

| # | The situation | Recommendation (applied) |
|---|---|---|
| D0-9 | The README lists ten windows on keys `1` … `0` (`README.md:81-95`); the system has twelve rail windows and Split / Join / Export (S6 CTX-SHELL). | Describe the Check Editor, Flow Execution and Split / Join / Export (R-DOC-README.2). |
| D0-10 | The README key table (`README.md:84-122`) lacks the rail keys `=` and `]`, Ctrl+Q, `d` (describe tag) and `c` (confirm). | Add them (R-DOC-README.3). Ctrl+P is not added: S6 D6-13 removes it. |
| D0-11 | The README says the Operations dialog executes `crc`, `extract` and `split_by_segment` (`README.md:205-207`); the last two run nothing (S13 D13-13). It says flows persist to `flow.json` (`README.md:186-187`); a flow is `<project>/flows/<name>.json` (S15 CTX-FLOWFILE). | Correct both (R-DOC-README.4). The command-line section goes with the command-line tool (S1 D-11). |
| D0-12 | The rule of D0-2 is written nowhere outside `REQUIREMENTS.md`; `docs/engineering-rules.md` has no such rule. | Add it to `docs/engineering-rules.md` when D0-2 takes it out of the requirements. |

**Prototype first**

None: S0 has no screen.

**Passed to other groups**

- **S3** (gap, HLR-132 and HLR-134): `k` on the Memory Map opens the legend window with a sheet of four boxes, `Entropy bands — <n> B windows, bits/byte`, `Map anatomy`, `Region row` and `Map keys`, and no legend block (`screens.py:1341-1355`, `:1299-1304`; the map maps to no block, `app.py:7306`). No row covers the sheet; S3 R-LEGEND-MODAL-001.8 ("a screen with no block of its own shows every block") contradicts it. The keys line inside it is already S4 R-TUI-062.10 (D4-21). No text from a file appears in the sheet, so it needs no safe-text entry.
- **S4** (residuals): the map pane's title `Memory Map` and subtitle `<N> regions · ░▒▓ k` (`screens_directionb.py:2609-2610`, HLR-125); the stats line stays in view without scrolling the region list (LLR-129.1). Neither has a row.
- **S16** (residual, HLR-149): the Flow Execution has no size rows (actions in view at 118 × 54 or more, reachable by scrolling below), and the Flow Builder has no "reachable by scrolling below 118 × 54" row.
- **All groups**: every pointer to S0 is resolved in S0.2.

**Received from later groups** (after all groups were written)

- The three passes above are settled: S3 rows R-LEGEND-MAP.1 … .5 with R-LEGEND-MODAL-001.8 narrowed (S3 D3-27); S4 rows R-MAP-PANE.1, .2 and R-TUI-041.4; S16 rows R-FB-RIB.6, R-FX-SIZE.1, .2. HLR-125, HLR-129, HLR-132, HLR-134 and HLR-149 are now absorbed with no residual (S0.2); no gap is left.

**Reconciled with batch-100 (s19_app 570b4b5)**

- S0.2 lines added (42): HLR-163 … HLR-178 with every lettered sub-HLR, all **absorbed**, from the five group agents' side files merged per HLR (S2, S3, S5 … S8, S10 … S17). CTX-RETIRED terms "batch-100 id" and "AT-B100-NN, TC-B100-NN" added; decision D0-13 added (follow / move).
- S0.2 lines changed: HLR-151 (LLR-151.1 superseded by batch-100 HLR-173, Inc 9b; pointer moved from S11 R-TUI-013.4 to S7 R-LOADDLG.1, .54, .60, .70), HLR-162 (S11 R-TUI-013.1, .3, .4 retired; pointer to S11 R-TUI-013.2 and S7 R-LOADDLG.1, .24, .60), HLR-005 (the dropdown pick is guarded since Inc 10, S10 D10-45).
- D0-8 extended: the registry update also covers the AT-B100 and TC-B100 ids (D0-13).
- Checked by script: `s0_count.py` (counts below) and a reference check that every row id the 104 lines cite is a row of the named group file (473 ids, none missing).
- Rows (S0.1): none added, changed or retired.

---

## 6. Counts

| | Old S0 | Strict |
|---|---:|---:|
| Requirement statements | 4 rows + 21 retired AT-/TC- ids + 287 batch rows (62 HLR, 225 LLR) | 15 rows (4 README + 11 requirements-file rows, S0.3) |
| Statements the code contradicts or that are not product behaviour | 4 (all four rows are repository or process rules; R-TUI-032 also stale) | 0 |
| Rows by form: U / When / While / If / Where | — | 15 / 0 / 0 / 0 / 0 |
| Rows that could not be written in EARS | — | 0 |
| Retired batch ids (one line per HLR) | 62 HLR | 104 lines (62 + 42 batch-100): 93 absorbed · 11 retired · 0 gap (`s0_count.py`: `lines 104 unique 104  absorbed 93  retired 11  gap 0`) |
| Decisions | — | 14 (9 follow the code or move, 1 remove rule (keep), 4 correct a defect, 0 prototype first) |

Checked by script: one `shall` per row, correct opening words per form, no "unless" / "only if", no repeated id across the review files (`ears_lint.py`). HLR classes counted from this file by `s0_count.py`; `s0_hlr_build.py` checks that the table names each of the 62 HLR once and that every row id a line cites is a row of that group's file.
