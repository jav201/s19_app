# Inc 6 — E5 coverage audit

Batch 2026-11-01-batch-101, increment 6, design-first flow (`dev-flow-v3-beta`, E5: "someone who did not write the test cases re-checks their `full`/`partial` marks and coverage"). Mode: **validation** (an audit of marks and results; no test was run). Auditor: the QA reviewer agent, which wrote no case and no node. Worktree `b101-inc6`, head `8530ebe`. Inputs: `01-requirements.md`, `02-test-cases.md` (81 cases), `E4-tester1-notes.md`, `E4-tester2-notes.md`, `E4-integration-notes.md` (with its mutant table), the transcripts in `../evidence/inc-6/`, `tests/test_b101_patch_lifecycle.py` (**L**), `tests/test_b101_document_homes.py` (**H**), the cited existing nodes, the test support modules they call, and the product code that those modules enter. `02-test-cases.md` is not edited; the marks below are this audit's proposal for it.

## 1. Verdict

- **Coverage: 66 `covered`, 15 `partial`, 0 `gap`, 0 `conflict`, 0 `not-testable`.** The previous record had 81 `covered`. Marks changed on **17 of 81 rows (21 %)**: the row coverage of 15 rows, plus the secondary-node mark of 2 rows whose coverage stays `covered`.
- **Results: every row is `verified` on Linux.** Each named node passed in a transcript of this commit's product source. 36 rows are re-cited from int-01 to int-07, the transcript of the exact final test file. **Windows: `not_run` on all 81 rows** (operator rule). On 10 of them the Windows arm is a different code path: a junction in place of a symbolic link, or a file link that skips without a privilege.
- **Negative controls: `pending mutants` on all 81 rows.** The E4 mutant table names no mutant for 13 rows. On 7 rows, a mutant is expected or allowed to survive.
- **Black-box ATs: owed and mostly present, with 12 holes.** Most nodes drive keys, buttons, the Load dialog, the dropdown and the popups. 9 rows drive the project-load or Save-project trigger through the private handler in place of `p` / `ctrl+s`. 3 rows press a button that the current tab hides. Those 12 rows are the route half of the 15 partials (§4).

## 2. Evidence checks made by this audit

- **The trees are the commit.** Tree recomputed with git plumbing only: a scratch object directory, a scratch index, no `s19_app` import, nothing written to the worktree. Base `98d94d7` plus `git diff 98d94d7 8530ebe -- s19_app tests docs README.md` gives `4d71b9b7…`, the tree of int-05 and int-07. The same tree with `tests/test_b101_document_homes.py` and `tests/test_tui_check_editor.py` taken at `778eeb4` gives `60737950…`, the tree of int-01 … int-04. So int-01 … int-04 ran this commit's product source and every other test file byte for byte. Only the H file differs there, by the I-D10 import line.
- **Per-node results are inferred from whole-file totals.** The transcripts are `-q`, with no per-node line. int-01 reads `215 passed`, int-07 reads `261 passed`: no failure, no skip, no deselection. No named node is marked `serial_timing`. Every node of those files therefore passed. In int-02, `test_at030a…` and `test_tc_b94_15…` are absent from the 4 FAILED lines. Their files have no SKIPPED line, and the one xfail is in neither file.
- **Product routes read, not run.** `_handle_load_project` runs with `routed=False` when called directly (app.py:14136). The shipped `p` route is `_route_load_project` → `_confirm_then_load`: it asks the replace question when unsaved work would be lost, then calls `_handle_load_project(name, routed=True)`, which pushes `LoadResultScreen` (app.py:9120-9152, :14563). Its docstring says: "A direct `_handle_load_project` call (tests, fixtures) meets no question and no modal". The shipped Save project is `ctrl+s` → `SaveProjectScreen` (preview, `_confirm_project_save`) → `_handle_save_dialog` (app.py:8838-8869).
- **Tab panes read, not run.** In the Patch Editor, Add / Remove sit in `#patch_pane_inspector`, and Write file and the before/after control in `#patch_win_json`. Both panes are children of `ContentSwitcher#patch_tab_switcher` (screens_directionb.py:4976-5155). Load / Refresh / the dropdown / Apply / Save sit outside it (:5232-5274). Textual's `Button.press()` tests only the button's own `display`, not its ancestors'. Add, Remove and Write file have no key binding. The passing runs show that these presses reached the handler while the pane was hidden.

## 3. Per case

L = `tests/test_b101_patch_lifecycle.py`, H = `tests/test_b101_document_homes.py`, B = `tests/test_before_after_report.py`. "Std guard" = passes on base (`red-01-*`); "base RED" = failed on base for the reason the tester notes give. Mutant ids are those of the table in `E4-integration-notes.md`. Δ marks a row this audit changes.

| # | Case | Tests (audited mark) | Coverage | Result | Negative control | Note |
|---|---|---|---|---|---|---|
| 1 | R-BEFORE-AFTER-REPORT-001.1/1 | L `…001_1_1_offer_text_in_a_project` (full); B `test_at_038a…` (partial) | covered | verified (linux, int-01) | pending mutants: M1; base RED | Offer read at the product's `notify` call (a pass-through spy); trigger is the Write file button on the JSON tab |
| 2 | R-BEFORE-AFTER-REPORT-001.36/1 | L `…001_36_1_no_offer_without_a_project` (full) | covered | verified (linux, int-01) | pending mutants: M2; base RED | Prefix sign matched; 0 offers |
| 3 Δ | R-BEFORE-AFTER-REPORT-001.11/1 | B `…_11_2_bkey_no_project_status` (full); B `…_11_1_no_project_reason_exact_text` (full → **partial**) | covered | verified (linux, int-01) | pending mutants: M3 | `_11_2` presses `b` and reads the exact status and no report file anywhere. `_11_1` calls `compose_before_after_report` directly and reads its diagnostics, not the key's status |
| 4 | R-TUI-049.3.1/1 | L `…3_1_control_hidden[load]` (full) | covered | verified (linux, int-01) | pending mutants: **none in table** (M4 leaves it GREEN); std guard | Base already hides on a typed Load |
| 5 | R-TUI-049.3.1/2 | L `…[pick]` (full) | covered | verified (linux, int-01) | pending mutants: M4; base RED | `Select.value` write, which the case header admits ("the dropdown's value") |
| 6 | R-TUI-049.3.1/3 | L `…[guarded]` (full) | covered | verified (linux, int-01) | pending mutants: M4; base RED | The precondition Add is pressed in the hidden Inspector pane (setup only, not the trigger) |
| 7 Δ | R-TUI-049.3.1/4 | L `…[project]` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M10 (may survive); base RED | Trigger is `projects.load_project` → `_handle_load_project` direct: no `p` dialog, no replace question, no Load-result modal |
| 8 | R-TUI-049.3.1/5 | L `…[paste]` (full) | covered | verified (linux, int-01) | pending mutants: **none in table**; std guard | Base already hides on a paste |
| 9 | R-TUI-049.3.1/6 | L `…[undo]` (full) | covered | verified (linux, int-01) | pending mutants: M7; base RED | `ctrl+z`; the precondition Add is in the hidden pane (setup) |
| 10 | R-TUI-049.3.1/7 | L `…[redo]` (full) | covered | verified (linux, int-01) | pending mutants: M8; base RED | `ctrl+y` |
| 11 | R-TUI-049.3.1/8 | L `…[image]` (full) | covered | verified (linux, int-01) | pending mutants: M5; base RED | `ctrl+l` dialog, `y` to the question |
| 12 Δ | R-TUI-049.3.1/9 | L `…3_1_control_kept_on_save_project` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M6; std guard | Save project through `projects.save_project` → `_handle_save_dialog` direct, not `ctrl+s`; the dialog's push/pop and confirm are not exercised for this negative arm |
| 13 | R-TUI-049.3.2/1 | L `…3_2_prompt_hidden[load]` (full) | covered | verified (linux, int-01) | pending mutants: M4; base RED | The "no file written" half cannot fail: no confirm is pressed. The painted absence is the discriminating half |
| 14 | R-TUI-049.3.2/2 | L `…[pick]` (full) | covered | verified (linux, int-01) | pending mutants: M4; base RED | |
| 15 | R-TUI-049.3.2/3 | L `…[guarded]` (full) | covered | verified (linux, int-01) | pending mutants: M4; base RED | |
| 16 Δ | R-TUI-049.3.2/4 | L `…[project]` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M10 (may survive); base RED | As #7. Here the shipped `p` route asks the replace question, because the apply left unsaved bytes (cf. /8, which answers it); the node never meets it |
| 17 | R-TUI-049.3.2/5 | L `…[paste]` (full) | covered | verified (linux, int-01) | pending mutants: M11; base RED | |
| 18 | R-TUI-049.3.2/6 | L `…[undo]` (full) | covered | verified (linux, int-01) | pending mutants: M7; base RED | |
| 19 | R-TUI-049.3.2/7 | L `…[redo]` (full); L `…prompt_redo_with_no_step_keeps_it` (full) | covered | verified (linux, int-01) | pending mutants: M8, M9; base RED at the first read | Sign = the Refresh status line, read from the status log |
| 20 | R-TUI-049.3.2/8 | L `…[image]` (full) | covered | verified (linux, int-01) | pending mutants: M5; base RED | |
| 21 Δ | R-TUI-049.3.2/9 | L `…3_2_prompt_kept_on_save_project` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M6; std guard | As #12 |
| 22 Δ | R-PATCH-DOC-DROPDOWN-001.1/1 | H `…001_1_change_list[open]` (full) | covered | verified (linux, **int-01 → int-07**) | pending mutants: M12, M15; base RED | Key `6`; project open is a precondition (handler) |
| 23 Δ | R-PATCH-DOC-DROPDOWN-001.1/2 | H `…[save]` (full) | covered | verified (linux, int-07) | pending mutants: M12; base RED | Save button |
| 24 Δ | R-PATCH-DOC-DROPDOWN-001.1/3 | H `…[refresh]` (full) | covered | verified (linux, int-07) | pending mutants: M12; base RED | |
| 25 Δ | R-PATCH-DOC-DROPDOWN-001.1/4 | H `…[no-project]` (full); `test_tui_patch_editor_v2.py::test_at030a…` (full → **partial**) | covered | verified (linux, int-07; int-02) | pending mutants: **none in table**; std guard | `test_at030a` checks set equality plus sortedness, not the exact list. It uses generated names, `request_action` setup and fixed pauses |
| 26 Δ | R-PATCH-DOC-DROPDOWN-001.1/5 | H `…[project-load]` (full) | covered | verified (linux, int-07) | pending mutants: M12, M13; base RED | `p` dialog |
| 27 Δ | R-PATCH-DOC-DROPDOWN-001.1/6 | H `…[save-project]` (full) | covered | verified (linux, int-07) | pending mutants: M12, M14; base RED | `ctrl+s` dialog |
| 28 Δ | R-PATCH-DOC-DROPDOWN-001.2/1 | H `…001_2_empty[all-empty]` (full) | covered | verified (linux, int-07) | pending mutants: **none in table**; std guard | Prompt read from the painted dropdown |
| 29 Δ | R-PATCH-DOC-DROPDOWN-001.2/2 | H `…[library-only]` (full) | covered | verified (linux, int-07) | pending mutants: M12, M15; base RED | |
| 30 Δ | R-PATCH-DOC-DROPDOWN-001.3/1 | H `…001_3_pick[project]` (full) | covered | verified (linux, int-07) | pending mutants: M12, M16; base RED | Pick by click and arrow keys; source equality (S-4 itself is decided by /4) |
| 31 Δ | R-PATCH-DOC-DROPDOWN-001.3/2 | `test_tui_patch_editor_v2.py::test_at030a…` (full → **partial**) | covered → **partial** | verified (linux, int-02) | pending mutants: **none in table** | Asserts the loaded entry's address (0x200), never the document source `workarea/patches/<name>` that the case names. Reads after a fixed `pilot.pause()` (rule 7) |
| 32 Δ | R-PATCH-DOC-DROPDOWN-001.3/3 | H `…[library]` (full → **partial**) | covered → **partial** | verified (linux, int-07) | pending mutants: M12, M15; base RED | Ribbon asserted as `"w.json" in ribbon`: a ribbon painting `library/w.json` (the listed value, the M24-type defect) passes. The status and the source are exact |
| 33 Δ | R-PATCH-DOC-DROPDOWN-001.3/4 | H `…001_3_pick_keeps_spelling` (full → **partial**) | covered → **partial** | verified (linux, int-07); **windows: not_run** (junction alias) | pending mutants: M12, M17; base RED | The asserted Save-project lines come from `projects.save_project` → `_handle_save_dialog` direct, not `ctrl+s` |
| 34 Δ | R-PATCH-DOC-DROPDOWN-001.3/5 | H `…001_3_save_after_library_pick` (full) | covered | verified (linux, int-07) | pending mutants: M12, M15, M42; base RED | |
| 35 Δ | R-PATCH-DOC-DROPDOWN-001.4/1 | H `…001_4_refused[link]` (full) | covered | verified (linux, int-07); **windows: not_run** (file link skips without a privilege) | pending mutants: M16, M18; base RED | Posts `ChangeFileSelected`, as the case's Input names |
| 36 Δ | R-PATCH-DOC-DROPDOWN-001.4/2 | H `…[linked-folder]` (full) | covered | verified (linux, int-07); **windows: not_run** (junction) | pending mutants: **none in table** (M18 leaves it GREEN by design; M16 is likely RED but does not list it); base RED (other status) | Defended twice (walk + containment): only a mutant that removes both isolates it |
| 37 Δ | R-PATCH-DOC-DROPDOWN-001.4/3 | H `…[unknown-folder]` (full) | covered | verified (linux, int-07) | pending mutants: M20; base RED | |
| 38 Δ | R-PATCH-DOC-DROPDOWN-001.4/4 | H `…[inside-link]` (full) | covered | verified (linux, int-07); **windows: not_run** (junction) | pending mutants: M16, M18; base RED | |
| 39 Δ | R-PATCH-DOC-DROPDOWN-001.4/5 | H `…[popup-recheck]` (full) | covered | verified (linux, int-07); **windows: not_run** (junction) | pending mutants: M19; base RED | The only refusal arm reached by a real pick and click |
| 40 Δ | R-CHKED-031/1 | H `…031_write_home[project]` (full) | covered | verified (linux, int-07) | pending mutants: M21; base RED | |
| 41 Δ | R-CHKED-031/2 | H `…[no-project]` (full) | covered | verified (linux, int-07) | pending mutants: **none in table**; std guard | |
| 42 Δ | R-CHKED-031/3 | H `…[after-library-pick]` (full) | covered | verified (linux, int-07) | pending mutants: M21, M24, M25; base RED | |
| 43 Δ | R-CHKED-031/4 | H `…[never-overwrites]` (full) | covered | verified (linux, int-07) | pending mutants: M21, M42; base RED | |
| 44 Δ | R-CHKED-034/1 | H `…034_linked_check_home` (full) | covered | verified (linux, int-07); **windows: not_run** (junction) | pending mutants: M22; base RED | |
| 45 Δ | R-CHKED-040/1 | H `…040_spec_list[project]` (full) | covered | verified (linux, int-07) | pending mutants: M23, M25; base RED | Key `=` |
| 46 Δ | R-CHKED-040/2 | H `…[after-write]` (full) | covered | verified (linux, int-07) | pending mutants: M21, M23; base RED | |
| 47 Δ | R-CHKED-040/3 | H `…[save-project]` (full) | covered | verified (linux, int-07) | pending mutants: M14, M23; base RED | `ctrl+s` dialog |
| 48 Δ | R-CHKED-040/4 | H `…[project-load]` (full) | covered | verified (linux, int-07) | pending mutants: M13, M23; base RED | `p` dialog |
| 49 Δ | R-CHKED-042/1 | H `…042_write_as_bare_name` (full) | covered | verified (linux, int-07) | pending mutants: M23, M24, M25; base RED | |
| 50 Δ | R-CHKED-044/1 | H `…044_refused[link]` (full) | covered | verified (linux, int-07); **windows: not_run** (file link) | pending mutants: M18; base RED | Posts `SpecFileSelected`, as the case names |
| 51 Δ | R-CHKED-044/2 | H `…[linked-folder]` (full) | covered | verified (linux, int-07); **windows: not_run** (junction) | pending mutants: **none in table** (M18 leaves it GREEN); base RED | As #36 |
| 52 Δ | R-DIFF-CHK.1/1 | H `…diff_chk_1_list[project]` (full) | covered | verified (linux, int-07) | pending mutants: M23; base RED | Key `7`. The `(no check spec)` anchor is filtered out, not asserted |
| 53 Δ | R-DIFF-CHK.1/2 | `test_tui_check_chain_b94.py::test_tc_b94_15…` (full → **partial**) | covered → **partial** | verified (linux, int-02) | pending mutants: **none in table** | Asserts sorted, filtered labels (drops `broken`, drops non-`.json`), not the option values exactly and in order. Its fixture is three files, not W. Fixed pauses |
| 54 Δ | R-DIFF-CHK.1/3 | H `…[project-load]` (full) | covered | verified (linux, int-07) | pending mutants: M13, M23; base RED | `p` dialog |
| 55 Δ | R-DIFF-CHK.1/4 | H `…[save-project]` (full) | covered | verified (linux, int-07) | pending mutants: M14, M23; base RED | `ctrl+s` dialog |
| 56 Δ | R-DIFF-CHK.3/1 | H `…diff_chk_3_no_row_for_empty_list` (full) | covered | verified (linux, int-07) | pending mutants: **none in table** (the row's E1 control "row composed for an empty list" has no mutant); std guard | |
| 57 Δ | R-DIFF-CHK.5/1 | H `…diff_chk_5_refused[link]` (full) | covered | verified (linux, int-07); **windows: not_run** (file link) | pending mutants: M18; base RED | |
| 58 Δ | R-DIFF-CHK.5/2 | H `…[linked-folder]` (full) | covered | verified (linux, int-07); **windows: not_run** (junction) | pending mutants: **none in table** (M18 GREEN; M26 likely RED, not listed); base RED | As #36 |
| 59 Δ | R-DIFF-CHK.8/1 | H `…diff_chk_8_library_spec_loads` (full) | covered | verified (linux, int-07) | pending mutants: M23, M25, M26; base RED | |
| 60 | R-CHK-PE-008/1 | L `…008_subtitle[two]` (full) | covered | verified (linux, int-01) | pending mutants: **none in table**; std guard | |
| 61 | R-CHK-PE-008/2 | L `…[zero]` (full) | covered | verified (linux, int-01) | pending mutants: M30; base RED | |
| 62 Δ | R-CHK-PE-008/3 | L `…[revert]` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M39; base RED | Add and Remove pressed while the Checks tab is current: both live in the hidden Inspector pane. No operator can press them there, and the tab switch back to Checks (which repaints the subtitle from the pane's stored value) is never driven |
| 63 | R-CHK-PE-009/1 | L `…009_no_run[load]` (full) | covered | verified (linux, int-01) | pending mutants: M31; base RED | Load is outside the tab switcher |
| 64 | R-CHK-PE-009/2 | L `…[image]` (full) | covered | verified (linux, int-01) | pending mutants: M34, M38; base RED | |
| 65 Δ | R-CHK-PE-009/3 | L `…[project]` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M35 (may survive); base RED | Handler direct, as #7; the shipped route also mounts the Load-result modal over the tab it reads |
| 66 Δ | R-CHK-PE-009/4 | L `…[add]` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M39; base RED | As #62 (hidden Add) |
| 67 | R-CHK-PE-009/5 | L `…[apply]` (full) | covered | verified (linux, int-01) | pending mutants: M32, M33; base RED | Apply is outside the tab switcher |
| 68 | R-CHK-PE-009/6 | L `…[mac]` (full) | covered | verified (linux, int-01) | pending mutants: M34, M38; base RED | |
| 69 | R-CHK-PE-010/1 | L `…010_status[load]` (full) | covered | verified (linux, int-01) | pending mutants: M31; base RED | |
| 70 Δ | R-CHK-PE-010/2 | L `…[project]` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M35 (may survive); base RED | As #65 |
| 71 | R-CHK-PE-011/1 | L `…011_strip[load]` (full) | covered | verified (linux, int-01) | pending mutants: M31, M36; base RED | |
| 72 Δ | R-CHK-PE-011/2 | L `…[project]` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M35 (may survive); base RED | As #65 |
| 73 | R-CHK-PE-012/1 | L `…012_rows[load]` (full) | covered | verified (linux, int-01) | pending mutants: M31; base RED | |
| 74 Δ | R-CHK-PE-012/2 | L `…[project]` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M35 (may survive); base RED | As #65 |
| 75 Δ | R-CHK-PE-014/1 | L `…014_glyph_after_save_back` (full → **partial**) | covered → **partial** | verified (linux, int-01) | pending mutants: M31, M32, M33; base RED | Write file (inside `#patch_win_json`) pressed while the Checks tab is current. The ledger half matches the operator route (the ledger is outside the switcher); the subtitle half is not reached by any operator route |
| 76 | R-CHKS-001/1 | L `…chks_001_screen[current]` (full) | covered | verified (linux, int-01) | pending mutants: **none in table**; std guard | Key `9` |
| 77 | R-CHKS-001/2 | L `…[stale]` (full) | covered | verified (linux, int-01) | pending mutants: M37; base RED | |
| 78 | R-CHKS-004/1 | L `…chks_004_note_after_image_load` (full) | covered | verified (linux, int-01) | pending mutants: M37, M38; base RED | |
| 79 | R-CHKS-004/2 | L `…chks_004_note_while_displayed` (full) | covered | verified (linux, int-01) | pending mutants: M28, M29, M37; base RED | "No group header" is asserted for `FAILED` only, not for `PASSED`. Kept full: the grouped list paints either the note or the groups |
| 80 | R-CHKS-009/1 | L `…chks_009_zero_line` (full) | covered | verified (linux, int-01) | pending mutants: M36; base RED | |
| 81 | R-CHKS-009/2 | L `…chks_009_zero_line_while_displayed` (full) | covered | verified (linux, int-01) | pending mutants: M27 (expected survivor, I-D3), M28 (effective); base RED | `p` dialog. Full, as I-D3 rules: the product paints what the case asserts |

## 4. Changes (old → new, why)

**Row coverage `covered` → `partial`, node mark `full` → `partial` (15 rows).**

- **Project load by the private handler (6 rows):** R-TUI-049.3.1/4, R-TUI-049.3.2/4, R-CHK-PE-009/3, -010/2, -011/2, -012/2. The trigger is `tests/support/b100_projects.load_project` → `app._handle_load_project(name)` with `routed=False`. The operator's only route is `p` → `_route_load_project` → `_confirm_then_load`, which asks the replace question over unsaved work, then installs with `routed=True` and pushes `LoadResultScreen`. The node therefore skips a question (3.2/4 has unsaved image bytes when it loads) and a modal over the surface it reads. Four other cases in this catalogue already drive `p` (001.1/5, CHKED-040/4, DIFF-CHK.1/3, CHKS-009/2), so the route is buildable.
- **Save project by the private handler (3 rows):** R-TUI-049.3.1/9, R-TUI-049.3.2/9, R-PATCH-DOC-DROPDOWN-001.3/4. The trigger is `projects.save_project` → `app._handle_save_dialog(payload)`. The shipped route is `ctrl+s` → `SaveProjectScreen` (preview, `_confirm_project_save`) → the same handler. The case header promises black-box through the dialogs, and the catalogue drives `ctrl+s` elsewhere (001.1/6, CHKED-040/3, DIFF-CHK.1/4).
- **A button pressed in a hidden tab pane (3 rows):** R-CHK-PE-008/3 and -009/4 press Add / Remove (Inspector pane) while the Checks tab is current. R-CHK-PE-014/1 presses Write file (JSON pane) while the Checks tab is current. `Button.press()` reaches a button whose pane the `ContentSwitcher` hides, but an operator cannot: none of these three has a key binding. The operator's route goes Checks → other tab → press → Checks. That route repaints the inspector subtitle through `_refresh_inspector_subtitle` from `#patch_win_checks`'s stored subtitle, and no node drives it.
- **Oracle weaker than the expected result (3 rows):**
  - R-PATCH-DOC-DROPDOWN-001.3/3: the ribbon is checked by substring.
  - R-PATCH-DOC-DROPDOWN-001.3/2: `test_at030a` never reads the document source the case names.
  - R-DIFF-CHK.1/2: `test_tc_b94_15` reads sorted, filtered labels, not the exact values in order.

**Secondary node mark `full` → `partial`, row stays `covered` (2 rows).** R-BEFORE-AFTER-REPORT-001.11/1: `…_11_1_no_project_reason_exact_text` calls the service composer, not key `b`. R-PATCH-DOC-DROPDOWN-001.1/4: `test_at030a` uses set plus sorted in place of exact equality.

**Result citation `int-01` → `int-07` (36 rows, every H row).** int-01 ran H before the I-D10 import fix (tree `60737950…`). int-07 ran the final file of this commit (tree `4d71b9b7…`, recomputed in §2). Both passed. Row 25 cites `int-07; int-02`.

**Windows `not_run` named (10 rows).** R-PATCH-DOC-DROPDOWN-001.3/4, 001.4/1, /2, /4, /5, R-CHKED-034/1, -044/1, -044/2, R-DIFF-CHK.5/1, /2. On Windows the folder links are junctions, which the product walks by its own code (`_is_reparse_point`), and the file links skip without a privilege. Nothing ran on Windows (operator rule), so the junction route is unexercised. The other 71 rows are also not run on Windows but have no Windows-only arm.

**No change** on the other 64 rows' marks. The audit agrees that the Patch Editor dropdown, the Check Editor and the A2B Diff picks go through click and arrow keys in H, and through the dropdown's value in L (the header admits both). The refusal arms post the panel's own selection message, as their Inputs name. Painted reads are compositor strips or the widget's own rendered text, and option values are the widget's own options.

## 5. Negative controls (for `E5-mutants.md`)

- **All 81 rows: `pending mutants`.**
- **Rows with no mutant in the E4 table (13):** R-TUI-049.3.1/1, /5; R-PATCH-DOC-DROPDOWN-001.1/4, 001.2/1, 001.3/2, 001.4/2; R-CHKED-031/2, -044/2; R-DIFF-CHK.1/2, .3/1, .5/2; R-CHK-PE-008/1; R-CHKS-001/1.
  - 10 of them are standing guards on base, or existing nodes of unchanged behaviour.
  - The three linked-folder arms (001.4/2, 044/2, DIFF-CHK.5/2) are defended twice, by the link walk and by the containment check. M18 leaves them GREEN by design; isolating them takes a mutant that removes both checks.
  - R-DIFF-CHK.3's E1 control ("the row composed for an empty list") has no mutant at all. Proposal: add one.
- **Expected or allowed survivors (7 rows):** M10 for R-TUI-049.3.1/4 and 3.2/4, and M35 for R-CHK-PE-009/3, -010/2, -011/2 and -012/2: the variant install and the load tail repaint too. M27 for R-CHKS-009/2 (I-D3), whose effective control is M28. If M10 and M35 survive, these 6 rows keep only their base RED as evidence that they can fail.
- **Base evidence:** the lifecycle nodes were 37 RED / 6 standing guards on base (`red-01-tester1-base.txt`); the document-homes nodes 32 RED / 4 standing guards (`red-01-tester2-base.txt`).

## 6. Black-box acceptance tests

The increment owes them (SKILL E5: "black-box, through keys and dialogs"). They are mostly present:

- The before/after offer and refusal (Write file button, key `b`).
- The replaced-document hides (typed Load, dropdown value, popup accept, paste, `ctrl+z`, `ctrl+y`, the `ctrl+l` dialog with its question).
- The lists (keys `6`, `=`, `7`; `p` and `ctrl+s` dialogs for the refill triggers).
- The picks (click and arrow keys).
- The Checks screen (key `9`, `p` while displayed).

**Missing: 12 rows** (§4, first three bullets). The smallest repair re-drives existing nodes, with no new requirement:

1. Replace `projects.load_project` with `ld.open_project_through_dialog` in the six project-load arms. For R-TUI-049.3.2/4, answer the replace question; after the load, close the Load-result panel as `open_project_by_dialog` in H does.
2. Replace `projects.save_project` with `sd.save_through_dialog` in R-TUI-049.3.1/9, 3.2/9 and R-PATCH-DOC-DROPDOWN-001.3/4.
3. In R-CHK-PE-008/3, -009/4 and -014/1: click the owning tab chip before the press, then click the Checks chip back before the read.

The three oracle partials need assertion fixes:

- R-PATCH-DOC-DROPDOWN-001.3/3: compare the ribbon's name segment exactly.
- R-PATCH-DOC-DROPDOWN-001.3/2: add an H node, or a source assert in the existing node.
- R-DIFF-CHK.1/2: add an exact-values node for W.

Each re-driven node must be shown RED on base and GREEN on the tree again.

## 7. Items E4 left for this audit to rule

- **E3A-13** (no re-mount of every result row on every action; render cost): no requirement row states a bound, so the catalogue owes no case. **Ruled `not-testable` as a case here**; backlog unless a row with a measurable bound is added.
- **E3A-17** (a Save project clears a spec picked on a displayed A2B Diff): admitted behaviour (`E1-rulings.md` §1 (h), I-D5), with no row and no case. The E3 architect suggested one case. Agreed that no case is owed while the behaviour is only admitted; if it is promoted to a row, R-DIFF-CHK.1/4's setup is the place for it.
- **R-CHK-PE-013** has no case (unchanged behaviour). Its existing node is outside this increment's catalogue: noted, no mark.

## 8. Not run by this audit

No test was run. Nothing that imports `s19_app` ran on the Windows PC. The only commands were git plumbing in a scratch object directory (the tree recomputation in §2) and file reads. The results above are the E4 integration step's runs on LAN Linux host 2; the transcripts print the base commit, the staged tree and `s19_app.__file__`. The mutant table is running separately (`E5-mutants.md`).

## 9. Totals

| | Before | After |
|---|---|---|
| Coverage `covered` | 81 | 66 |
| Coverage `partial` | 0 | 15 |
| Coverage `gap` / `conflict` / `not-testable` | 0 / 0 / 0 | 0 / 0 / 0 |
| Rows whose marks changed | — | 17 (21 %) |
| Result `verified` (linux) | 81 | 81 (36 re-cited to int-07) |
| Result `failed` | 0 | 0 |
| Result `not_run` (windows) | not stated | 81 (10 with a Windows-only arm) |
| Negative control `pending mutants` | — | 81 (13 with no mutant in the table; 7 with an expected or possible survivor) |
| Black-box AT holes (route) | — | 12 rows |
