# Inc 8 F8 — finding F-I10-1: the Inspector pane against the file and document rows

Writer F8 (claude-opus-5-5), sole writer of `b103-inc8` for this step; brief `brief-F8-inc8-inspector-overlap.md` (relevo-11). Base `8c090f6d`. Runner `<runner>`, scratch `~/work/zq-f8/` (deleted at the end, explicit list), HT-02 environment (HOME basename per HT-02, `timeout 300`, `-n` ≤ 2, `-p no:cacheprovider`), `s19_app.__file__` the second line of every transcript. Host load 9 to 12 during the runs (other workers); nothing here is a timing result (HT-08). Skills: `diagnose`, `tui-design`.

Commits (no push): `3e3b78ac` tests (step 4) · `80c2c965` captures (step 5) · the closing commit holds this record, `evidence/f8/` and `steps.log` (step 6). Source files changed: **0**.

## Verdict

**F-I10-1 is not a layout defect, and no product code changed.** No two painted widgets share a cell at 118×54, 220×60 or 80×24. Bytes, the four entry chips (Add, Edit, Remove, Edit JSON), Use parameter and the tally sit **below the fold** of the Inspector tab. That tab scrolls inside LANDS IN's 6 content rows by the approved design (R-PE-DEF.1.1; E3R1 E3A-09, `E1-rulings.md` §6 V-1).

How the misreading arises: for a child scrolled out of its container, Textual's `widget.region` keeps the child's virtual cells, and here those cells are the file row's and the document row's. So `pilot.click("#patch_entry_add_button")` aims at a cell where Validate is painted, and Validate takes the click. A person cannot hit that: at that cell they see Validate, not Add. Add is reached by Tab (focus scrolls the pane) or the mouse wheel, and then a click on it adds the entry.

DF-04 (a): the code matches the approved design, so there is nothing to fix to it. The 8 Inc 10 nodes fail in **their tests**: they use a bare `pilot.click` where Inc 8's own tests use `click_visible` (`tests/support/b103_inc8_p.py:139`, written at E4 integration for exactly this case).

## 1. Reproduction (step 1, rtx, tree `8c090f6d`)

Probe: DEFC loaded, Inspector chip pressed, for every displayed widget of `#patch_pane_inspector`: `widget.region`, whether it lies in the pane, and `get_widget_at(region.center)`. Pane = `#patch_pane_inspector`: 6 rows, virtual height 13, `max_scroll_y` 7, `scroll_y` 0.

| Size | Pane rows | `patch_entry_bytes_input` `.region` | widget at its centre | `patch_entry_add_button` `.region` | widget at its centre | Painted region (compositor) of Bytes / Add |
|---|---|---|---|---|---|---|
| 118×54 | y 33..38 | y 40 (outside the pane) | `patch_doc_path_input` | x 7, y 41 | `patch_doc_validate_button` | height 0 / height 0 |
| 220×60 | y 39..44 | y 46 (outside) | `patch_doc_path_input` | x 25, y 47 | `patch_doc_validate_button` | height 0 / height 0 |
| 80×24 | y 13..18 (the panel itself scrolled 7) | y 20 (outside) | `workspace_status_bar` | x 7, y 21 | `key_bar_global` | — |

The painted screen at 118×54 (rows 31–41): LANDS IN holds the chips, BEFORE → AFTER, its empty line, a blank row, `Address 0x100`, `String text (document encoding)`, with a scrollbar thumb at the right edge; row 40 is the file row and row 41 the document row, both painted whole. The "overlap" exists only in `widget.region`. Real Windows Terminal sidecars agree: `inspector.118x54.png.txt` gives Bytes `height=0` and Add `height=0` with `hit_at_centre=None`.

## 2. Origin (step 2)

| Tree | Inspector layout | Bytes / Add at 118×54 | at 220×60 |
|---|---|---|---|
| `2dbd7d5a` (batch-modular) | right-hand column, `width: 2fr; height: 100%` | painted in the pane (x 82, y 14 / x 74, y 15), each its own hit | painted, own hit |
| `d5d48685` (Inc 8 base) | the same (product identical to `a95d0ea9`) | the same | the same |
| `8c090f6d` (Inc 8 tip) | LANDS IN `height: 9` (6 content rows) | below the fold | below the fold |

Introduced by Inc 8, commit `894bb3db` ("group P: staging sheet over LANDS IN"), which set `#patch_editor_panel #patch_inspector { height: 9 }` (`git log -S"height: 9;"`). It is **Inc 8's, by design, not a regression**:

- E3A-09 (`E3-architect.md:19`) measured that "the Inspector tab needs the form, the Use row … and the tally" in 6 rows and ruled that it scrolls.
- E3R1 added that ruling to V-1: "the JSON and Inspector tabs scroll inside 6 content rows at 118×54" (`E1-rulings.md` §6, `E3-rulings.md:56`).
- CAP8 did not capture that state (`E5-captures.md` V-1: "the JSON/Inspector 6-row scroll (E3A-09) is not the state here"), so the operator has never judged it. F8 adds the captures (§6).

## 3. Requirements (step 3)

| Row | What it asks | Holds on the tip |
|---|---|---|
| R-PE-DEF.1.1 | LANDS IN 9 rows while no bench is shown; the sheet takes the rest | yes (`test_r_pe_def_1_1_the_landing_pane_has_9_rows…`) |
| R-TUI-063.1 | the seven regions top to bottom | yes |
| R-TUI-064.1 | at 118×54 or more, Validate, Apply loaded changes and Save shown without scrolling | yes (only these three are named) |
| R-TUI-064.3 | below 118×54, every control reachable by scrolling | yes (80×24: pane and Add reached, §4) |
| R-PE-DEF.3 | Use parameter row and status in the Inspector tab, under the entry form | yes |
| R-PE-020, R-PE-021 | the three fields' placeholders; Add appends the entry | yes (§4 test b) |
| E3A-09 / V-1 note | the Inspector tab scrolls inside 6 content rows | yes, as designed |

None of these rows asks that Bytes or Add be visible without scrolling, at any size. Fixing to the approved design (DF-04 a) therefore changes nothing. Making Add visible without scrolling would change R-PE-DEF.1.1 or the Inspector's design, which is DF-04 (b)/(c) and the operator's call (DF-09, V-1). See §7.

## 4. Tests (step 4): GREEN on the tip, RED only under the negative controls

No RED-first is possible: the tip has no painted overlap and Add adds. Two tests in `tests/test_b103_inc8_p_layout.py` (no new module, so the TC-607 file count does not move), each at 118×54, 220×60 and 80×24 with DEFC loaded:

- (a) `test_r_pe_def_1_1_inspector_widgets_share_no_painted_cell_at_the_top_and_the_end`: with the pane scrolled to its top and to its end, every painted Inspector widget lies inside the pane's painted region, shares no cell with any other painted widget that is not its ancestor or descendant, and owns the cell at its painted centre. "Painted" means the compositor's visible region (`screen.find_widget(w).visible_region`), not `widget.region`.
- (b) `test_r_pe_021_a_click_on_the_painted_add_adds_the_entry_and_never_validates`: Address `0x800021` and Bytes `11` are typed, Add is scrolled into view, and a mouse click lands on **the screen cell at Add's painted centre**. Expected: the last status is `Patch Editor: entry added.`, no `Validate:` status appears, and the document holds `[(0x800021, b"\x11")]`.

GREEN on `8c090f6d` + the tests (`new-tip.txt`): **6 passed**.

Negative controls, each on a copy of the tree (HT-09), 6 nodes each:

| Control | Change | (a) | (b) | First message |
|---|---|---|---|---|
| M1 product | `#patch_editor_panel #patch_doc_file_row { offset: 0 -2; }` (the file row painted over the pane) | 3/3 RED | 3/3 RED | `(118, 54) top: Vertical#patch_doc_entry_inputs Region(x=7, y=36, width=107, height=3) and Horizontal#patch_doc_file_row Region(x=5, y=38, width=112, height=1) share Region(x=7, y=38, width=107, height=1)`; (b) `click missed #patch_entry_bytes_input` |
| M2 product | `"patch_entry_add_button": "validate_doc"` in `actions.py` | 3/3 GREEN (layout untouched) | 3/3 RED | `last status 'Validate: 0 entries, 0 error(s), 0 warning(s)'` |
| M3 test side | F-I10-1's reading: `.region` in place of `.visible_region` | 3/3 RED | 3/3 GREEN | `(118, 54) top: #patch_doc_entry_inputs Region(x=7, y=36, width=107, height=5) leaves the pane Region(x=7, y=33, width=108, height=6)` |

M3 reproduces the Inc 10 reading exactly, and the test tells it apart from a real overlap (M1).

Re-run on an exact clone of `3e3b78ac` (a bundle of `main`, `b103-inc8`, `b103-inc10`), one file at a time, `-n 2` (`evidence/f8/inc8-14-files.txt`):

| Set | Result |
|---|---|
| The 14 `tests/test_b103_inc8_*.py` files | **all GREEN**: a1 23, a2 23, a3 9, at_help 2, at 11, p_layout **31** (25 + the 6 new), p_ledger 10, p_wiring 12, s1_detail 43, s1 118, s2_picker_definitions 6, s2_sheet_formula 27, s2_sheet_keys 21, s2_sheet_rows 35 = 377 passed |
| Laws: docs_canon, b101_doc_hygiene, b101_help_legend_docs, no_private_tokens, filename_markup_safety, report_markup_safety, id_registry, deps_seam_law (the law `CLAUDE.md` names), engine_unchanged, requirements_canon (`evidence/f8/bat-laws.txt`) | 317 passed, **1 failed** = `test_requirements_canon.py::test_canon_rows_hold_the_obligation_word_once` (`REQUIREMENTS.md` R-A2L-DEF.153, R-PICKER-CORRECT.004, .008 hold `shall` twice). This is pre-existing: Inc 10 records it RED on `439860c4`, and F8 does not touch `REQUIREMENTS.md`. Owner P-026. |
| On a clone of the closing commit `bad3fed7`: no_private_tokens, id_registry, deps_seam_law (`evidence/f8/final-laws-a.txt`) | 20 passed |
| Same clone: `test_suite_hygiene.py -k r_tst_070` (`final-laws-b.txt`) | 1 passed, **1 failed** = `test_r_tst_070_2`. Every hit is the HOME basename in a file that already held it at `8c090f6d`, none of them F8's: `04-validation.md` (1), `E4-mutants.md` (1), `evidence-e4/mutants/run_env.sh` (2), `evidence/captures/capture_i8.ps1` (1) (`git grep -c` at `8c090f6d` and `bad3fed7`, same counts). So the failure is **pre-existing on the Inc 8 tip** and was not edited away (PP-06). It goes to the orchestrator (finding F-F8-1). F8's own files build the basename at run time. |
| `test_tui_directionb.py -k tc031` (engine-frozen guard) | 3 passed |

The id-registry law stays GREEN at 329 scanned files, because the tests went into an existing module.

## 5. The 8 Inc 10 nodes on a scratch merge (step 4)

Setup: a scratch clone in `~/work/zq-f8/merge10`, not a worktree. `b103-inc10` (`4dffe1ca`) with `git merge --no-ff b103-inc8` (`3e3b78ac`): merged clean (`MERGE_RC=0`, `evidence/f8/merge.txt`). No product change came in, so the result before any test change is the same as Inc 10 recorded.

| Node | On the merge (as shipped) | With the test-side changes on a scratch copy |
|---|---|---|
| `test_b100_active_variant.py::test_at_b100_06_reopen_opens_the_saved_back_variant` [size0-A, size0-B, size1-A, size1-B] | 4 FAILED (`click missed`, the bare click on `#patch_entry_bytes_input`) | **4 passed** with `click_visible` |
| `test_b100_active_variant.py::test_at_b100_20_inc8a_every_writer_carries_the_active_document` [size0, size1] | 2 FAILED (the same click) | with `click_visible`: 2 FAILED at a **second, separate** cause, `assert '1 entry' in '<blank row>'`: `_script_border` reads the bottom row of `#patch_win_script`, which since D-2 A has no border (the subtitle rides LANDS IN, R-PE-041). Reading `#patch_inspector` instead: **2 passed** (`evidence/f8/m10fix2-b100.txt`) |
| `test_b99_editor_image.py::test_at_b99_08_save_back_keeps_editor_image`, `::test_tc_b99_22_verify_mismatch_status_still_names_entries` | 2 FAILED (`click missed #patch_entry_bytes_input`) | **2 passed** with `click_visible`; the whole file: 8 passed |
| (outside the 8) `test_b99_s0.py::test_at_b99_02_save_back_excludes_s0` | FAILED `click missed #patch_entry_address_input` | still FAILED: the test never presses the Inspector chip, so the pane is not shown. This is the I-6 retarget that Inc 10 lists as pre-existing |

The scratch change was a `conftest.py` wrapper that scrolls a selector's widget into view before `Pilot.click` (Inc 8's `click_visible` idiom for every selector click), plus the one-line `_script_border` change. It was never committed. Transcripts: `evidence/f8/m10-*.txt` (as shipped) and `m10fix*.txt` (with the changes). **All 8 nodes go GREEN with test-only changes in Inc 10's files and no I-8.x change.** The owner is Inc 10 (D-F8-2).

## 6. Captures (step 5)

Four real Windows Terminal captures, added to `E5-captures.md` as F8-1 and F8-2: `evidence/captures/inspector.{118x54,220x60}.png` (the tab as it lands) and `inspector-add.{118x54,220x60}.png` (Tab from Address to Bytes, then to Add). They were taken with CAP8's `capture_i8.ps1` and the driver, which gained the two scenarios. Truecolor, stubbed clipboard, isolated HOME/XDG/LOCALAPPDATA, `python -I -B`. Each window closed itself (the launcher's PID route), and the script's check found no window of ours left open. No other window was touched.

Every capture shows the same thing: LANDS IN paints 6 content rows, and the file row and document row are never covered. With focus on Add, Add is painted inside LANDS IN and is the widget at its own centre.

## 7. Decisions and open items

- **D-F8-1 (decided, DF-04 a):** no product change. No I-8.x interface touched.
- **D-F8-2 (for the Inc 10 owner, test side):**
  - In `test_b100_active_variant.py::_add_and_apply_through_the_panel` and in `test_b99_editor_image.py`'s `_type` and Add clicks, replace the bare `pilot.click` with Inc 8's `click_visible` idiom (scroll into view, then click).
  - In `test_b100_active_variant.py::_script_border`, read `#patch_inspector`'s bottom border, not `#patch_win_script`'s (R-PE-041, D-2 A).
  - `test_b99_s0.py::test_at_b99_02` also needs the Inspector chip press (I-6).
  - §5 shows the effect.
- **Evidence:** `evidence/f8/` holds the probe, the mutants and battery scripts (scratch copies; the HOME basename is built at run time) and the sanitised transcripts (`~`, `<user>`).
- **Q-F8-1 (operator, DF-09, V-1; for PENDING):** what the operator sees.
  - At every size, the Inspector tab lands showing only BEFORE → AFTER, Address and String.
  - Bytes, Add / Edit / Remove / Edit JSON, Use parameter and the tally need a Tab or a wheel scroll.
  - At 220×60 the sheet shows about 16 empty rows above the formula bar meanwhile (about 11 at 118×54).

  The options:
  - (A) keep it (the approved E3A-09 design);
  - (B) LANDS IN grows to fit the Inspector (13 content rows) while the Inspector tab is shown. This changes R-PE-DEF.1.1 and the R-PE-DEF.74 budget at 118×54;
  - (C) a denser Inspector form at wide widths (for example Address and Bytes on one row, the chips beside them). This is a new design and goes to a prototype first.

  The captures F8-1 and F8-2 are the evidence for the verdict.
- The `TREE` header line of the transcripts prints `-n` instead of the tree name: a scratch-script slip (`$1` read after `shift`). The second line, `s19_app.__file__`, names the tree.

## F-F8-1 redaction (relevo-11)

Ruling P-050 O-2 (as applied to Inc 9 by `71997e20`): an increment's own unpushed records are redacted forward; inherited records are never edited (PP-06).

- Run: `test_r_tst_070_2` on `7ae7fa44` (rtx, scratch `~/work/zq-r8/`, HT-02 env, `timeout 300`) was RED with 7 hits in 4 files: `04-validation.md:11` and `E4-mutants.md:24` (HOME basename, local-name token); `evidence/captures/capture_i8.ps1:42` (local-name token); `evidence-e4/mutants/run_env.sh:5,6` (posix-home-path form and local-name token, two hits each).
- Own or inherited: `git log origin/main origin/batch-modular -- <file>` is empty for all four, and none of the four is reachable from either remote branch. All 7 hits are Inc 8's own; 0 inherited.
- Fix: the two `.md` records now say `<runner-home>`; `run_env.sh` and `capture_i8.ps1` read the basename from `RUNNER_HOME_NAME` (comment added; the caller exports the HT-02 basename, which is not written into the repo, PP-03).
- Result: `test_r_tst_070_2` and `test_r_tst_070_3` GREEN on the edited tree (2 passed). No `test_b103_inc8_*` reads either script (grep over `tests/`: no match), so none was re-run.
- Side effect: both scripts now need `RUNNER_HOME_NAME` set before use (an unset value makes `run_env.sh` create `home/` itself and the PS1 fail on a null path); the already-recorded transcripts were produced with the old literal and are unchanged.
