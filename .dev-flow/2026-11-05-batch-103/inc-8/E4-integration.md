# Inc 8 E4 — integration record (integrator `O`, claude-opus-5-5)

Branch `b103-inc8` (worktree `~/Github/s19_app-b103-inc8`), base `d5d48685`. Times in `steps.log` (from `date`).
This file is the integrator's handoff: kept current at every step. Runs: `<runner>`, a clone of this branch
(`git bundle` of `b103-inc8` + `main`) under `~/work/zq-e4-8-int/wt` (second pass: `wt2`, a fresh bundle of
the named branches at `0885e854`, PF-07), HT-02 environment, `-n 2`, `timeout 300`, one file or chunk per run,
`s19_app.__file__` and `uptime` at the top of every transcript. Base runs: `base2` (`git archive d5d48685`) and
`base3` (a git clone checked out at `d5d48685`, for the laws that read git).

## Commits
| Step | Sha | Subject |
|---|---|---|
| 1 merge | `495a3c5b` | merge `b103-inc8-tests` (`c9251418`) into `b103-inc8` (`9bb77577`); `steps.log` conflict kept both sides in time order; carries the trailer missing from `fdf7738e` |
| 2 I-8.5 `mark` | `0a247737` | the amendment, its test, graph §Interfaces |
| 1b merge | `7a2a15b1` | merge test-r's record commit `68ba1b0b` (`E4-test-r.md`) |
| 4 GREEN (pass 1) | `47db0104`, `4314a98b`, `7e50e67b`, `0885e854` | F1–F15, records, handoff |
| 4 GREEN (pass 2) | `3b8b3585` + the records commit after it | F16–F30, RR-1…RR-4, r017_2, laws, trace SLICE |

## Rulings applied (one per bullet of the integrator notes and the orchestrator's later message)
- **I-8.5 amendment `mark` (Inc 9 E3A-05).** `KindOps.mark: Callable[[SheetRow, object | None], str | None] | None = None` added as the last field of `definition_sheet.KindOps`; one call site in `row_line` (`ops.mark(row, state)` → the mark column's second glyph; a None field or a None answer keeps Inc 8's rule, R-PE-DEF.23/.24). `_mark` gains an optional `glyph` argument; `●` keeps the OK style, `◆` the accent. Every Inc 8 kind and `_FALLBACK_OPS` leave it None. Recorded in `codewire/graph-inc8.md` §Interfaces (I-8.5 block and the line under the table). Test: `tests/test_b103_inc8_s1.py::test_r_pe_def_23_i85_mark_field_none_keeps_inc8_rule_and_a_kind_mark_overrides`.
- **impl-a A-1 (EX-D4 `staged as 175`).** Requirement R-PE-DEF.58 holds (`<text>` = the decoded text, `175.0`). `test_r_pe_def_59_1_app_notice_is_a_status_line_of_its_own` asserted `175`: test fixed to `175.0` with the ruling cited. The example EX-D4's wording is a record fix → PENDING P-045 (below).
- **impl-a A-2** (decode refusal → typed text): accepted, no change.
- **impl-s2 F-1** (lazy import): applied by impl-s1 (`_submit_stage`); verified (S1 AST purity test passes).
- **impl-s2 F-2 / test-s1 shape assumptions.** Reconciled by running the merged tree: `SheetRow.name/.definition/.kind/.current/.staged/.is_staged`, `Preview.result/.decoded`, `row_window -> (top, painted)` all exist as both sides assumed (S1 176/176, S2 56/56 GREEN). One mismatch, fixed in code: `limits_cell(row, value, width)` ignored a plain number `value` (graph node examples pass `25.5`, `175`) → `_ruler_value` now takes a plain number too (R-PE-DEF.21).
- **impl-s2 deviations.** (a) Escape in `on_key`, not a sixth binding: accepted (AT-2 GREEN). (b) Arrow/enter actions ignored while the input has focus: accepted; R-PE-DEF.45/.46/.47 say "while the staging sheet holds the focus", the input is not the sheet body. (c) `show_page` does not prune `states`: accepted (Inc 9 owns `states`). No steps.log start line: noted.
- **impl-s1 extras** (`SheetRow.is_staged/.image/.overlay`, optional `clip(clean)`, `row_line(state)`, `detail_lines(state, room)`, `StagedOverlay.written_in`): accepted as additive; Inc 9 reads `is_staged` (E3A-10 list). `_DATATYPE_FORMATS` duplication → backlog (move to a pure shared module). 917-line module → note only (DF-05). R-PE-DEF.40 idle tail → E5 / PENDING.
- **test-a F-1/F-2** (`history_depths()["back"]`, `is_dirty` property): tests use the shipped names; requirement wording → P-045.
- **test-a F-3** (`A2L` help line): impl-a's help has no `A2L` key and no `A2L PARAMETERS` wording (EX-HL1); `test_b103_inc8_a3_help.py` 9/9 GREEN. No conflict.
- **test-at finding 1 (marks share one column).** No conflict: CTX-PE-DEF `mark` is a 2-cell column (cell 1 `▶`, cell 2 `●`/`◆`), so a selected pending row paints `▶◆`. The AT reader assumed one glyph: test fixed (below).
- **test-at finding 2 (AT-5b reachability).** Confirmed unreachable by keys: the unload repaints the no-A2L line and disables the input (R-PE-DEF.14). Applied the notes' ruling: R-PE-DEF.63 holds through the app handler; AT-5b now posts Enter's `StageRequested`, then unloads before the app handles it (the race R-PE-DEF.63 guards), and also asserts the input is disabled after the unload. Assertions unchanged.
- **test-at finding 3 / test-p pin proposals.** `selected_name` is a property (as I-8.4 already states); the bar's child ids are `#patch_sheet_name`, `#patch_sheet_label`, `#patch_sheet_input`, `#patch_sheet_tail` (inside `#patch_sheet_bar`). Proposal to the orchestrator: pin the bar ids in I-8.4 (no code change).
- **test-p R-TUI-064.1-.3 gap** → E5 / trace (not added here).
- **test-s2 R-PE-DEF.11/3** (`287` vs `287.0`) → P-045 wording; **R-PE-DEF.12** timing → quiet-host E5 (HT-08).
- **impl-p D-P1…P7**: accepted as recorded (each within group P's files). F-P1 → V-1. F-P2 (6 dirty writers) noted. F-P3 → backlog.
- **D-1 (P-047): option A kept**, the four chips as built by impl-p (894bb3db). Reason: approved E1/E3 design, built and tested; the three-chip capture would drop the Patch script tab that holds the ledger. Shown to the operator at the end; the real capture goes on the review page (DF-09).
- **RR-1 … RR-5, snapshot marks** (orchestrator message, relevo-8): see "Retarget rulings" below.
- **Trailer of `fdf7738e`**: carried by merge commit `495a3c5b`.

## Failures and fixes (cause · side · requirement)
| # | Test(s) | Cause | Side | Requirement |
|---|---|---|---|---|
| F1 | s1 `limits_cell_puts_the_preview_mark…`, `…above_the_upper_limit…`, `…below_the_lower_limit…` | `limits_cell` drew no mark for a plain-number value | code (`definition_sheet._ruler_value`) | R-PE-DEF.21 (graph examples EX-P1, EX-D4) |
| F2 | s2 `test_r_pe_def_11_9_definitions_are_read_only` | `definitions` / `definitions_source` were plain writable attributes | code (`a2l_parameter_picker`: read-only properties over private fields) | I-8.4 "read only" (R-PE-DEF.11) |
| F3 | s2 `test_r_pe_def_40_2_…_shows_the_notice` | the formula input was `1fr` wide (CTX says 18 cells), so the tail was cut | code (`sheet.py` DEFAULT_CSS: input `width: 18`, tail `1fr`) | R-PE-DEF.40 (CTX-PE-DEF formula bar) |
| F4 | a2 `test_r_pe_def_59_1_…` | asserted the typed `175` | test | R-PE-DEF.58 (ruling A-1) |
| F5 | a2 `62_1`, `62_2`, `62_3`, `62_4`; p_wiring `62_1`, `62_3` | `"●" in row` also matches the Limits ruler's current-value `●` (R-PE-DEF.21) | test (read cell 2 of the mark column) | R-PE-DEF.23/.62 |
| F6 | a2 `62_2` | staged only the field; EX-O1 stages FIELD 255 then BIT 0 (bit 0 unchanged by the field alone → not staged) | test (setup per EX-O1) | R-PE-DEF.62/2 |
| F7 | AT reader `parse_rows` (AT-1, 2, 3, 7, 8) | read one stripped glyph; `▶●NAME` lost the name | test (2-cell mark per CTX) | R-PE-DEF.22/.23/.24 |
| F8 | AT-1, AT-3, AT-8 | `ChangeEntry.data` does not exist (`encoded_bytes`) | test | R-PE-DEF.50/.53 |
| F9 | AT-1, AT-7, AT-8 | after a stage the focus was lost (None) when the advance landed on a row with no editor: the input was disabled under the focus | code (`sheet.py` `_disable_input`: the body takes a focus the input held) | R-PE-DEF.45 with .36/.60 |
| F10 | AT-1, AT-7, AT-8 | arrows pressed into the formula input after a stage (focus stays there, I-8.4) | test (Escape first, R-PE-DEF.48) | R-PE-DEF.45 |
| F11 | AT-5b | see the ruling above | test (trigger) | R-PE-DEF.63, .14 |
| F12 | p_layout `test_r_pe_def_2_…` | no A2L → the count line is hidden by design (R-B102-SEL-002) | test (load DEFC's A2L) | R-PE-DEF.2 |
| F13 | p_layout `r_picker_correct_020[80x24]`, p_ledger dirty marker, p_wiring `62_3`; b100 ×3; b101 ×12 | `pilot.click` on a widget below the visible rows of the 9-row LANDS IN (or of the 80×24 panel) | test (scroll into view, then click) | R-PE-DEF.1.1, R-TUI-064.3 |
| F14 | b100 `tc_b100_10` | retarget queried `#patch_inspector` as `Container`; it is a `Vertical` | test | R-PE-041 |
| F15 | b103_picker_editor `r020[80x24]` | all surfaces measured after one scroll; at 80×24 the Use row scrolls the filter row out | test (scroll and measure each) | R-PICKER-CORRECT.020 |
| F16 | b97_patch_editor `tc_b97_02` ×2, `at_b97_01`; b97_width `tc_b97_37` ×6 | the 9-row LANDS IN gives the ledger table 6 rows, 5 painted (was ≥ 7 rows, 6 painted) | test (RR-1: heights retargeted to R-PE-DEF.1.1, `landing == 9`; distinct-rows kept; `at_b97_01` also reads the 6th entry by scrolling the ledger) | R-PE-DEF.1.1 |
| F17 | b97_patch_editor `tc_b97_39` ×2; b97_width `tc_b97_34`; patch_card `tc080_6` ×2 | the Inspector pane is LANDS IN's full width: the strip is 32 bytes/row at 118 and 220 (16 at 80), the card budget ~105, the ledger Value column holds the 8-byte run; the tests held base-layout constants | test (RR-2: per_row by the D5 (f) rule from the measured `#patch_inspector` width; budget = that width − 3; clip derived from the measured Value width; an 80×24 arm added so a resize still changes the strip, M15) | R-PE-DEF.1.1 |
| F18 | b97_patch_editor `tc_b97_40` ×4 | the 6-row Inspector pane shows neither the whole form nor the 8-row capped strip; `scroll_end` passes the chips (Use row, tally follow, R-PE-DEF.3) | test (RR-2: each widget scrolled into view, rows read in the scrolled content; strip read over every scroll offset; entry size 8 × per_row; below-fold rows derived from the stack read at another offset, `> 0`; chips scrolled to) | R-PE-DEF.1.1, .3 |
| F19 | b97_patch_editor `tc_b97_60` ×3 | controls below the 6 visible rows; the 8-row paste buffer is taller than its home | test (scroll into view; a widget taller than its home must lie in its columns and cover every visible row) — **flag**: the one non-literal form | R-PE-DEF.1.1 |
| F20 | `tc_b97_05`, `at_b97_02`, v2 `at068a`/`at068b`, patch_big `at075c` | click or read below the visible rows (F13 class); at 120×30 the 12-row sheet fills the first screenful | test (scroll into view) | R-PE-DEF.1.1, .74 |
| F21 | patch_layout `at064b` | the 15-row first screenful at 120×30 holds the filter row and the 12-row sheet; LANDS IN starts at row 14 (`evidence-e4/integrator/rr3_first_screenful_probe.py`) | test (RR-3 as measured: the scroll-0 check reads the filter row and the sheet window; file row, entry buttons (Inspector shown) and doc row are reached by scrolling) — **flag**: RR-3's literal text cannot hold | R-PE-DEF.74, .1.1 |
| F22 | chips_help TC-B97-32 (`Add list`, `Pick`), AT-B97-14[patch] | the Patch help had no `Pick —` / `Add list —` line (both RED on base) | code (`window_help.py`, two lines) | LLR-148.6 law 2 (ruling) |
| F23 | chips_help TC-B97-33 | measured cause: the strip was read on the Patch script tab (F-P1), so no `--` token was painted; `--` is in `PATCH_GLYPHS` and the legend | test (Inspector tab; row 6's Kind cell read after the cursor scrolls it in) — the ruling expected a legend code fix; none was needed | LLR-148.7, R-TUI-063.3 |
| F24 | chips_help TC-B97-58 `strip_no_image`, `strip_no_entries` | same tab cause | test (Inspector tab) | LLR-148.9, R-TUI-063.4 |
| F25 | picker_editor `r011` /1, /3; b102 `tc_b102_pe_02` | the table is hidden (RR-4); through the Include control `space` did nothing (a `Button` binds only `enter`) | test (route: Tab from the filter to the include control) + code (`a2l_parameter_picker.IncludeButton`: `space` presses it, as on the ledger) | R-PICKER-CORRECT.011/1, R-PE-DEF.2 |
| F26 | picker_model `r017_2` | the hidden full-name line clipped the name; the sheet has no rows without an A2L | test (ruling: an A2L with the same parameter and hostile unit is loaded; the Patch arm asserts the formula bar's name label == `HOSTILE_UNIT` and its tail starts with the literal unit; the check arm keeps the full-name form) | R-PICKER-CORRECT.017/2, R-PE-DEF.2 |
| F27 | suite_hygiene `r_tst_002` | test-s2's two timing arms had no `serial_timing` mark | test (mark) | R-TST-002 |
| F28 | id_registry G1/G3, `tc607`, `at280`, `at281` | `AT-5b` in a comment (pass 1); a test name `…capped_at_4096…` read as `AT-4096`; 18 new test modules | test (comment → `AT-B103-I8-5b`; name → `…capped_to_4096…`, case files updated; `EXPECTED_SCANNED_TEST_FILES` 311 → 329 with the list) | registry law |
| F29 | address_census `at_b83_08` | `panel.query(sdb.A2LParameterPicker)` (attribute form) in test-a's support | test (imported name) | address law |
| F30 | key_bar `at_b97_26` | the filter row's input is now the section's first Tab stop; `?` typed there is text | test (tab past the input) — **finding K-1** for V-1: the key bar shows `? Help` while the filter input holds focus | R-TUI-063.1 |

Visible consequence for V-1 (not a defect): with LANDS IN at 9 rows, the entry form, the JSON paste area and the Edit JSON button are reached by scrolling inside the pane.

## PENDING P-045 (requirement / record wording; the orchestrator moves these)
- EX-D4 (graph examples, handler form): `staged as 175` → `staged as 175.0` (R-PE-DEF.58 decoded text).
- R-PE-DEF.11/3: `→ 287` → the decode's text `287.0` (display format `%.1`), as test-s2 asserts.
- Requirement texts naming `history_depths()["undo"]` → `"back"`; `is_dirty()` → the property `is_dirty`.
- R-PE-DEF.63 case text "A2L unloaded between the selection and Enter" → "between Enter and the stage's handling" (keys cannot reach it after R-PE-DEF.14 disables the input).
- I-8.4 `select_after` comment "focus unchanged" → "focus unchanged, except that a focus held by a formula input that becomes disabled falls to the body" (F9). Interface comment: proposed, the orchestrator rules.

## Retarget rulings (orchestrator, relevo-8) — what was done
- **RR-5 (CSS supersessions): applied.** test-r's three entries assumed whole-rule deletions; impl-p's probe shows in-place edits. Replaced by one `supersede` per in-place edit of a b514b07 rule (`#patch_main`→`#patch_sheet_win`, borderless `#patch_win_script`, 9-row `#patch_inspector`, the focus-within selector, the tab-window height list), plus impl-p's inserted Inc 8 block and its anchor; every `INC8` → `894bb3db`. The `.ce-*` re-scope needs no entry (inside db1a8f7's inserted block). `startswith` not edited.
- **Snapshot marks: applied.** The `xfail(strict=False)` reason now names PENDING P-048.
- **RR-4 / `r011`: applied** (relevo-8 ruling): probe `rr4_hidden_table_focus_probe*` (the table is out of the focus chain). `r011` /1, /3 and `tc_b102_pe_02` reach the filter row's include control (`Pick`) by Tab from the filter input and fire it by `space` then `enter`; assertions unchanged (`picked_params` `["ARR12"]` then `[]`; net `[]`). Code: `IncludeButton` (space binding) — the control was reachable, but `space` did not fire it (F25). No new sheet key.
- **RR-1: applied** (F16). **RR-2: applied** (F17, F18), every number derived in the test from measured widths (`evidence-e4/integrator/landing_geometry_probe.py`). **RR-3: applied as measured** (F21) — the literal "visible at scroll 0 with the Inspector tab shown" cannot hold at 120×30 (R-PE-DEF.74's 12-row sheet fills the 15-row viewport); the scroll-0 check stays, on the regions R-TUI-063.1 puts first. Orchestrator to confirm.
- **`r017_2`: applied** (F26): the relaxation is gone; the hidden line's assertion leaves only together with the formula-bar retarget (R-PE-DEF.2).
- **TC-B97-32 / TC-B97-33:** law assertions unchanged. TC-B97-32: the two help rows added (F22); it stays RED on one label `''` (open item O-1). TC-B97-33: cause measured test-side (F23), no code change. **TC-B97-58 ×2:** cause = tab (F24). **AT-B97-14[patch]:** RED on base (`b1`), GREEN after F22.
- **trace SLICE ×3: applied** — module names added to the owning rows' Base cell ("code `…` (E4 trace)"): `definition_sheet.py` → R-PE-DEF.6 (S1 `sheet_widths`), `sheet.py` → R-PE-DEF.45 (S13 bindings), `styles.tcss` → R-PE-DEF.74 (P12').

## Orchestrator rulings on pass 2's open items (PENDING P-050) — pass 3
- **O-1 (TC-B97-32 label `''`): ruled pre-existing on base `d5d48685`; left failing.** Base evidence: `b1-tests_test_b97_chips_help.py__test_tc_b97_32_patch_help_names_every_label.txt` (base labels `['', 'Add list', 'Pick']`; now `['']`). No label change.
- **O-2 (runner HOME path): applied.** The runner HOME basename and path were replaced by `<runner-home>` in `E3-architect.md`, `E3-security.md`, `E4-impl-p.md`, `E4-test-at.md`, `E4-test-s1.md`; `evidence-e1/run_e3r1.sh` and `run_pilot.sh` now read it from `$RUNNER_HOME_NAME` (`${RUNNER_HOME_NAME:?...}`), so they still run. Commit 8ba0926b. Result of `test_suite_hygiene::test_r_tst_070_2` in the final GREEN below.
- **O-3: RR-3 "as measured" (F21) and F19 accepted** (approved design wins).
- **K-1 (`? Help` on the key bar while the filter input holds focus): pre-existing, app-wide, by requirement; no code change.** On base `d5d48685` LLR-150.2 / TC-B97-67 (`test_tc_b97_67_row_one_is_the_eight_globals_whatever_the_focus`, present on base at line 356) requires row 1 to paint exactly the eight globals, `? Help` included, whatever the focus, with the focus in a text `Input`; `KeyBar.row_tokens("global")` applies no focus or `check_action` filter. Same code path and test GREEN here (q5, 38 passed). For the backlog: `?` is advertised while any text input holds focus.

## Runs (GREEN counts; transcripts on the runner, `~/work/zq-e4-8-int/*.txt`, volatile)
Pass 1 (tree `wt`, before `0885e854`):
| Chunk | Files | Result |
|---|---|---|
| G1 | `test_b103_inc8_s1`, `_s1_detail`, `_s2_picker_definitions`, `_a1_service`, `_a3_help` | 176 passed |
| G2/G6 | `_s2_sheet_rows`, `_s2_sheet_keys`, `_s2_sheet_formula`, `_a2_app` | 101 passed |
| G4 | `_at`, `_at_help` | 13 passed |
| G5 | `_p_layout`, `_p_ledger`, `_p_wiring` | 46 + 12 passed |
| r2 | `test_b97_flow_execution` 75; `test_b101_symbol_reads` 24 | passed |

Pass 2 (tree `wt2` = `0885e854` + this pass's working changes, synced file by file; quiet host, load 0.1–3.7):
| Chunk | Files | Result |
|---|---|---|
| q2/q3/q4 | `test_b97_patch_editor` | 38 passed (was 24 / 14 failed) |
| q2 | `test_b97_chips_help` | 78 passed, 1 failed (TC-B97-32, label `''`, O-1) |
| q2 | `test_tui_patch_editor_v2` 52, `test_tui_patch_layout` 9, `test_tui_patch_big` 24 | passed |
| q3 | `test_tui_patch_card` | 25 passed, 1 failed (`tc080_2` purity, pre-existing on base) |
| q3/q4 | `test_b103_picker_model` 44, `test_b103_picker_editor` 33 (r011 ×3 again 3 passed), `test_b102_patch_picker` 17 | passed |
| q3 | `test_b102_bulk_add` 12, `test_b102_parameter_picker` 10, `test_b103_inc8_p_layout` 25 | passed |
| q3 | `test_b97_check_editor` | 34 passed, 2 failed (`tc_b97_12`, `at_b97_05` hostile names: = base, `b5`) |
| q4 | `_s1_detail` 43, `_a2_app` 23, `_at` 11, `_s2_sheet_rows` 33 | passed |
| p1 | `test_b100_session_reset` | 17 passed, 3 failed (= base, P-038) |
| p1 | `test_tui_snapshot` | 25 passed, 2 xfailed (patch, P-048), 6 failed (a2l ×6, = base) |
| n1/n2 | `test_b97_width` by node ranges w00–w03 | 37 + 37 + 37 + 34 = 145 passed |
| n2 | `test_tui_directionb` by node ranges d00–d04 (incl. the `tc031` law nodes) | 37 × 4 + 36 = 184 passed |
| l1/q4 | laws: `engine_unchanged` 1, `deps_seam_law` 6, `docs_canon` 2, `b101_doc_hygiene` 45, `b101_help_legend_docs` 71, `no_private_tokens` 2, `filename_markup_safety` 2, `report_markup_safety` 166, `id_registry` 12 (after F28) | passed |
| l1/q4 | `requirements_canon` 1 failed; `address_census` 1 failed; `suite_hygiene` 66 passed, 1 failed (`r_tst_070_2`) | see "Pre-existing on base" |
| q5 | `test_b97_key_bar` after F30 | 38 passed |

## Pre-existing on base `d5d48685` (shown failing there, left)
- `test_b100_session_reset` × 3 (`tc_b100_08`, `tc_b100_09` ×2; P-038): base2 `b1`, the same three nodes.
- `test_b97_chips_help::test_tc_b97_32_patch_help_names_every_label`: base `['', 'Add list', 'Pick']`; now `['']` (O-1).
- `test_b97_chips_help::test_at_b97_14…[patch]`: RED on base (`b1`), GREEN now.
- `test_tui_patch_card::test_tc080_2_c7_purity_probe`: base RED; the two `self.app` sites are in `patch_editor/a2l_picker.py` on base (lines 38, 116).
- `test_tui_snapshot` a2l × 6: base RED (8 = a2l ×6 + patch ×2; the patch ×2 are now `xfail`, P-048).
- `test_requirements_canon::test_canon_rows_hold_the_obligation_word_once`: base RED, the same three canon rows (R-A2L-DEF.153, R-PICKER-CORRECT.004, .008).
- `test_address_census::test_at_b83_08…`: base RED, the same 8 offenders (`test_b103_a2l_refresh` ×2, `test_b103_picker_model` ×6; lines shifted only); F29 removed the one Inc 8 added.
- `test_suite_hygiene::test_r_tst_070_2…` (fixed by O-2 in pass 3, GREEN): base RED on Inc 8's E1/E3 records (14 lines: `E3-architect.md`, `E3-security.md`, `evidence-e1/run_e3r1.sh`, `run_pilot.sh`); the E4 records `E4-impl-p.md`, `E4-test-at.md`, `E4-test-s1.md` add hits (O-2). This record no longer names the HOME basename.
- `test_suite_hygiene::test_r_tst_002_2_parallel_lane_collection…`: RED on base2 only (archive tree); GREEN in `wt2`.

## Final GREEN (pass 3) — `evidence-e4/integrator/final_green_pass3.txt`
Tree: fresh bundle clone of `b103-inc8` a2af8da4 (+ `main`) under the runner `~/work/zq-e4-8-int/fin` (PF-07); `b103-inc8-tests` had nothing after 68ba1b0b (already merged). `s19_app.__file__` printed at the top of each transcript (the clone). Quiet host (load 0.1–3.6), `-n 2`, no full suite. Every chunk of pass 1 and pass 2 was rerun.
| Chunk | Result |
|---|---|
| `b103_inc8_` s1 95, s1_detail 43, s2_picker_definitions 6, a1_service 23, a3_help 9, s2_sheet_rows 33, s2_sheet_keys 21, s2_sheet_formula 24, a2_app 23, at 11, at_help 2, p_layout 25, p_ledger 10, p_wiring 12 | all passed (337) |
| `b97_flow_execution` 75, `b101_symbol_reads` 24 | passed |
| `b97_patch_editor` 38, `tui_patch_editor_v2` 52, `tui_patch_layout` 9, `tui_patch_big` 24 | passed |
| `b97_chips_help` | 78 passed, 1 failed (TC-B97-32, O-1: base) |
| `tui_patch_card` | 25 passed, 1 failed (`tc080_2`: base) |
| `b103_picker_model` 44, `b103_picker_editor` 33, `b102_patch_picker` 17, `b102_bulk_add` 12, `b102_parameter_picker` 10 | passed |
| `b97_check_editor` | 34 passed, 2 failed (`tc_b97_12`, `at_b97_05`: base) |
| `b100_session_reset` | 17 passed, 3 failed (base, P-038) |
| `tui_snapshot` | 25 passed, 2 xfailed (patch, P-048), 6 failed (a2l ×6: base) |
| `b97_width` w00–w03 | 37 + 37 + 37 + 34 = 145 passed |
| `tui_directionb` d00–d04 | 37 × 4 + 36 = 184 passed |
| laws: `deps_seam_law` 6, `docs_canon` 2, `b101_doc_hygiene` 45, `b101_help_legend_docs` 71, `no_private_tokens` 2, `filename_markup_safety` 2, `report_markup_safety` 166, `id_registry` 12, `b97_key_bar` 38 | passed |
| `engine_unchanged` | 1 passed on the rerun (the first run skipped: the bundle clone had no local `main` ref; created it and reran, no code touched) |
| `suite_hygiene` | **67 passed, 0 failed**: `r_tst_070_2` no longer flags any Inc 8 file (O-2); it was the one failure of pass 2 |
| `requirements_canon` 1 failed, `address_census` 1 failed | same offenders as base (diff of the `E` lines against base2 transcripts `b3-*`: identical modulo digits) |

All failures are in "Pre-existing on base" above (base evidence: runner transcripts `b1-*`, `b2-*`, `b3-*`); none is new.

## Open items
- **Base-only failures stay** (list above); `test_b97_check_editor::test_tc_b97_12…`, `::test_at_b97_05…` RED on base (`b5`) and here: pre-existing, not diagnosed (outside Inc 8's files) → PENDING.
- **K-1** recorded for the backlog: `? Help` is advertised while any text input holds focus (LLR-150.2 by design).
- **EVID** (no `04-validation.md`): expected before E5.
- The runner tree `~/work/zq-e4-8-int` is deleted (PF-04, orchestrator-authorised).

## Inc 9 check (E3A-10, E3S-06) — `evidence-e4/integrator/inc9_names_probe*.{py,txt}`
- Every name in Inc 9's list exists with its name and shape: `SheetRow.name/.definition/.kind/.current/.staged/.is_staged`; `SheetWidths.kind/.current/.new/.limits/.delta` (int); `Preview(result, decoded)`; `short_number`, `plain`, `name_echo`; `KindOps` fields end `cells, bar, mark`; `_KIND_OPS` = number, bit mask, enum, text; `ops_for("array") is _FALLBACK_OPS`; `_FALLBACK_OPS.detail(row, None, 118, None, 1)[0]` is the `└ …` definition line.
- `staged` on a 1 MiB entry over a 1 MiB span (array and text-over-4,096 kinds, entry equal or last byte different): **1,048,576 image lookups** in `build_row` and 1,048,576 in one `staged` call — one pass over the entry's bytes, no early exit (a count, no timing; HT-08). Inc 9 decides whether that bound is acceptable per page.

## trace_check (step 8) — `evidence-e4/integrator/trace_check.txt`
```
EVID   no 04-validation.md beside .dev-flow/2026-11-05-batch-103/inc-8/01-requirements.md
trace_check: 2 US, 89 active requirements (3 withdrawn), checks run: US, CASE, TEST, SLICE, EVID, 1 gap(s)
```
- SLICE ×3 closed by the trace ruling (module names on R-PE-DEF.6, .45, .74). EVID expected before E5.

## Folded cases (step 7)
`02-test-cases.md` regenerated by `evidence-e4/integrator/fold_test_names.py` (run on the runner; transcript beside it) from the five group files: 210 of 210 rows carry a test name and full/partial; 20 tester-added cases stay in their group files (listed in the transcript).
- Pass 2 renamed one test (`test_r_pe_def_80_a_fill_is_capped_at_4096_characters` → `…_capped_to_4096_characters`, F28) in `02-test-cases.md` and `02-test-cases-S1.md`; no other name changed.

## State / next step (handoff)
Pass 3 is complete: rulings applied, final GREEN recorded above, `b103-inc8` not pushed. Next: the orchestrator reviews and moves P-045 and the K-1 backlog entry; E5 follows.

## E5 correction (relevo-10)

### P-054 F-1: `short_number` keeps 3 significant digits (DF-04 a: defect, fix to the design)
- **Defect.** CTX-PE-DEF: "else 3 significant digits and `k`, `M` or `G`". `short_number(1000)` gave `1k` and `short_number(-1000)` `-1k` (`.3g` drops trailing zeros). Inc 9's EX-G10 and R-PE-BENCH.17/2 already expect `-1.00k … 1.00k`.
- **Rule now.** `|x| < 1000` unchanged (one decimal, trailing `.0` dropped). From 1000 up: the mantissa `|x|/unit` is written with 2, 1 or 0 decimals (3 significant digits, trailing zeros kept, no trailing dot); a mantissa that rounds to 1000 moves to the next unit (`999500` → `1.00M`); past `G` the mantissa takes an exponent (`1.5e12` → `1.50e+03G`, the old `1.5e+03G`).
- **Fix.** `s19_app/tui/definition_sheet.py::short_number` (the `.3g` loop replaced). Cross-check on the runner: 200,000 random values from 1e3 to ~8e11, both signs, old versus new: 0 differences in value or unit (only the zero padding differs).
- **Tests (first, RED then GREEN).** `tests/test_b103_inc8_s1.py`: `test_r_pe_def_21_short_number_keeps_three_significant_digits` (10 cases incl. ±1000, 1500, 65535), `…_rounding_carries_into_the_next_unit` (4), `…_below_1000_stays_one_decimal` (6), `…_past_the_last_unit_uses_an_exponent` (1). No existing assertion asserted the `1k` form; none was changed. RED on `2a71f46c` (tree shipped as is): `-k short_number` → `11 failed, 20 passed`. GREEN after the fix: whole file `118 passed in 1.25s`.
- **Observation (not changed).** The `|x| < 1000` branch is the requirement's literal "rounded to one decimal": `999.96` → `1000` (4 digits). Candidate for a requirement note; left as written.
- **Effect elsewhere in Inc 8.** `short_number` is called only by `limits_cell` (limits text). No Inc 8 test or example has a limit of 1000 or more, so no rendered text in Inc 8 changes; `evidence-e2/examples_inc8.py::short` keeps the old `.3g` form for values ≥ 1000 and is not used by the new cases (they carry literal texts).
- **Re-run on the final tree** (rtx, `-n 2`, one file at a time; `s19_app.__file__` printed in each transcript; host load 1.5): `tests/test_b103_inc8_*.py` (14 files) all pass: a1 23, a2 23, a3 9, at_help 2, at 11, p_layout 25, p_ledger 10, p_wiring 12, s1_detail 43, s1 118, s2_picker_definitions 6, s2_sheet_formula 25, s2_sheet_keys 21, s2_sheet_rows 34; `tests/test_deps_seam_law.py` (the only law `CLAUDE.md` names) 6 passed.

### Diagnosis: the two base failures (`tests/test_b97_check_editor.py::test_tc_b97_12_hostile_names_render_literally`, `::test_at_b97_05_hostile_parameter_reads_literally`)
- **Failing assertion.** TC-B97-12: `panel._visible_params.index(HOSTILE_CONTENT)` raises `ValueError`; AT-B97-05: `_settled_delay` raises "did not settle: the filter isolates the hostile parameter" (`tests/test_b97_check_editor.py:466`, `:1131`). The pane holds 75 names, one of them `b97[bold]x[/]y[red]z[link=https:` instead of the full `HOSTILE_CONTENT`.
- **Cause.** The fixture name (`tests/b97_fixtures.py:90`) contains `https://e.invalid`; the A2L reader of Inc 11 treats `//` outside a quoted string as a line comment (`s19_app/tui/a2l.py:839`, the post-Inc-11 reader; `:1278` the same rule in `_strip_a2l_comments`), so the name is cut at `https:`. This is Inc 11 ruling D-10 option A (`inc-11/E1-rulings.md:85-87`), which told E4 to re-point the hostile inputs holding `//` to a token without it (`x[link=https:x]`) but listed only `test_tui_a2l_issue_recolor.py`; `inc-11/E1-rulings.md:113` also lists `test_b97_check_editor.py` as "expected to stay green". The fixture was missed.
- **Predates batch-103?** No. Runner results (same env, `-k "test_tc_b97_12 or test_at_b97_05"`): `10d01dc1` (parent of Inc 11's `d8ddd2a5`) `2 passed`; `2dbd7d5a` `2 failed`; `d5d48685` `2 failed`; tip `2 failed`. Introduced by `d8ddd2a5` (Inc 11 E4: A2L reader), not by Inc 8.
- **Proposed fix and owner.** Test-side, one line: change `https://e.invalid` in `HOSTILE_CONTENT` to a `//`-free token (`https:e.invalid`), keeping the markup payload able to fail (the TC-B97-12 mutation `Text.from_markup` stays RED). Not Inc 8 (no Inc 8 file involved): owner batch close P-026 (it belongs to Inc 11's D-10 re-point list), to be done with a pre/post run of the two nodes. Nothing was changed.
