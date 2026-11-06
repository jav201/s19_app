# Inc 6 E4 tester 1 (group "lifecycle") - notes

Node file: `tests/test_b101_patch_lifecycle.py` (43 nodes). Edited bodies, names kept: `tests/test_before_after_report.py::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` (offer filter keys on the title `Before/after report`; it now also pins the exact offer text), `tests/test_tui_checks_screen.py::test_tc084_3_update_checks_view_groups_and_aggregates` and `::test_at084g_hostile_input_renders_literal` (the injected run carries the provenance stamp).

RED run: base `823d0c93` (main with Inc 5), LAN Linux host, detached worktree, `s19_app.__file__` printed in the worktree; transcript `.dev-flow/2026-11-01-batch-101/evidence/inc-6/red-01-tester1-base.txt` (one complete run: 38 failed, 8 passed, 165 s). State: `executed` on base. GREEN on the integrated tree: `not-run` (the implementers were still editing).

## How the nodes read and drive

- Presses go through the shipped controls: keys `6`, `9`, `ctrl+l`, `ctrl+z`, `ctrl+y`, the Load dialog (`ctrl+l`, typed path, `#load_ok`), the question's `y`, buttons (Load, Apply, Write file, Add, Remove, Run checks, Refresh, Parse pasted, Accept loss and load), the dropdown's `value`, the tab chips (clicked).
- Hidden/shown rows are asserted on the painted Patch Editor (compositor strips of `#patch_editor_panel`); every absence read first proves the JSON tab is painted (`LOADED DOCUMENT`) and the precondition was painted. The Checks-tab subtitle is read off the inspector's painted border; the Checks screen note, groups and aggregate line off the painted `#checks_grouped` / `#checks_aggregate_strip`. The Checks-tab status label, patch strip and result-row count are read from the widgets' own rendered text and children (the product's output, not a class).
- Every read after a press waits through `tests.b97_probes.settled` for the press's own sign (document name, ledger row count, status line since a mark, popup/question screen, current file/project). Absence waits are bounded at 6 s so they fail fast.
- Isolation: `projects.run_app` (fresh app per node, LOCALAPPDATA per fixtures); no OS clipboard (the paste buffer is filled with `TextArea.load_text`, then Parse pasted is pressed).

## Cases -> nodes (all marked `full` unless stated), RED on base

| Case | Node | Base |
|---|---|---|
| R-BEFORE-AFTER-REPORT-001.1/1 | `test_r_before_after_report_001_1_1_offer_text_in_a_project`; `test_at_038a_...` (partial) | RED: text ends `(action: before_after_report).` (both) |
| R-BEFORE-AFTER-REPORT-001.36/1 | `test_r_before_after_report_001_36_1_no_offer_without_a_project` | RED: 1 offer |
| R-BEFORE-AFTER-REPORT-001.11/1 | existing nodes, not re-run by me | `not-run` here (covered by the E1 case) |
| R-TUI-049.3.1/1-/8 | `test_r_tui_049_3_1_control_hidden[load, pick, guarded, project, paste, undo, redo, image]` | RED for pick, guarded, project, undo, redo, image (control still painted). **Standing guards (pass on base):** `[load]`, `[paste]` - base already hides there (pilot P) |
| R-TUI-049.3.1/9 | `test_r_tui_049_3_1_control_kept_on_save_project` | standing guard (passes on base; fails if the hide moves to the shared load tail) |
| R-TUI-049.3.2/1-/8 | `test_r_tui_049_3_2_prompt_hidden[...]` (same 8 ids; also asserts no `img-patched*.s19` under the work area) | RED, prompt still painted, all 8 |
| R-TUI-049.3.2/7 negative arm | `test_r_tui_049_3_2_prompt_redo_with_no_step_keeps_it` | RED at its first read (the redo arm); the empty-redo arm itself is only reached with the fix |
| R-TUI-049.3.2/9 | `test_r_tui_049_3_2_prompt_kept_on_save_project` | standing guard |
| R-CHK-PE-008/1 | `test_r_chk_pe_008_subtitle[two]` | standing guard |
| R-CHK-PE-008/2, /3 | `[zero]`, `[revert]` | RED: `no run yet` for a 0-entry run; no `no run yet` after Add |
| R-CHK-PE-009/1-/6 | `test_r_chk_pe_009_no_run[load, image, project, add, apply, mac]` | RED: `2 checked` (`1 checked` for apply) stays |
| R-CHK-PE-010/1-/2 | `test_r_chk_pe_010_status[load, project]` | RED |
| R-CHK-PE-011/1-/2 | `test_r_chk_pe_011_strip[load, project]` | RED: `✓1 ✗1 ◐0` stays |
| R-CHK-PE-012/1-/2 | `test_r_chk_pe_012_rows[load, project]` | RED: 2 rows stay |
| R-CHK-PE-014/1 | `test_r_chk_pe_014_glyph_after_save_back` | RED: `◐` stays |
| R-CHKS-001/1, /2 | `test_r_chks_001_screen[current, stale]` | `[current]` standing guard; `[stale]` RED |
| R-CHKS-004/1 | `test_r_chks_004_note_after_image_load` | RED |
| R-CHKS-004/2 | `test_r_chks_004_note_while_displayed` | RED: groups stay |
| R-CHKS-009/1 | `test_r_chks_009_zero_line` | RED: `Pass 1 / Fail 1 ...` |
| R-CHKS-009/2 | `test_r_chks_009_zero_line_while_displayed` | RED (see finding 1) |

Edited existing nodes on base: `test_tc084_3_...` and `test_at084g_...` pass (the stamp is already a base concept); `test_at_038a_...` fails on base only at the new exact-text assertion (the offer text), as intended.

Uncovered in this group: none planned; no case exists for R-CHK-PE-013 (unchanged behaviour; its existing node `test_tui_patch_glyphs.py` is in the E4 re-census list). Mutant table (E1 negative controls) not run: E5.

## Findings

1. **E3A-16 cannot be built as written.** A project with no variant is refused (`'proj' has no data or A2L file`) or, as A2L-only, installs no image and the Checks content is replaced by the empty state, so there is nothing painted to read. R-CHKS-009/2 uses a project with a variant (`v.s19`); on base the stale line still stays, so the node is RED for the right reason. Whether it also fails without reset #7 on the fixed tree is not shown (it needs a mutant run in E5). Suggest recording the deviation in the E3 rulings.
2. **Image load with unsaved bytes asks first.** After an Apply (prompt painted) `ctrl+l` + a typed image path raises the load question (`ConfirmQuestionScreen`); the nodes answer `y` (Replace). Case R-TUI-049.3.2/8 should say so in its inputs.
3. **The save-back status line is longer than the case text:** `Patched image saved as img-patched.s19 - 1 entry applied before this save (0x00008003)`; the node matches the prefix. Case R-BEFORE-AFTER-REPORT-001.36/1 reads as a prefix.
4. **Project load route.** The project-load nodes use the shipped handler (`_handle_load_project` via `projects.load_project`); only R-CHKS-009/2 goes through key `p` and the dialog (it then closes the Load-result panel with `escape`). Save project goes through the shipped `_handle_save_dialog` (`projects.save_project`), not the `ctrl+s` dialog.
5. **Trial on the in-flight tree (not evidence):** the same 43 nodes passed 43/43 on a copy of this worktree taken mid-implementation, which shows the GREEN paths (including the empty-redo arm and the Save project guards) are reachable. The integration step owns the real GREEN run.
6. Standing guards that pass on base (8): 3.1 `[load]`, `[paste]`, /9; 3.2 /9; 008 `[two]`; R-CHKS-001 `[current]`; and the two edited existing nodes.

Nothing was committed. Remote worktree and helper files (`i6t1-` prefix) removed.
