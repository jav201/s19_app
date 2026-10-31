# Inc 8b — E4 integration notes

Stage E4 integration of the `design-first-increment` pipeline: G1 (`app.py`), G2 (`project_gather_service.py`, `workspace.py`) and the tester's work brought together, plus the orchestrator's rulings D-3 and D-5. Nothing is committed. Base `ebe6d0c`; worktree `s19_app-b100-inc8b`, branch `b100-inc8b`.

## Rulings applied

| Ruling | What was done | Where |
|---|---|---|
| D-5 | The Loaded panel's A2L slot names the session's A2L (`current_a2l_path`, tag count from `current_a2l_data`) when no `LoadedFile` exists (no data file loaded). One branch in `_slot_state`; no other edit in the file. | `s19_app/tui/screens_directionb.py` `LoadedArtifactsPanel._slot_state` (4th and last source of 8b) |
| D-3 | The A2L "not readable" problem's reason is the bare reason: `link or junction`, `too large to open` or `could not be read`. It holds no second next step. The painted next step is the composer's own step for the `not readable` kind. `variant_execution_service.py` is not edited. | `s19_app/tui/app.py` `_handle_load_project` (the `a2l_problem` construction) |
| G1 D-1, D-2, D-4; G2 D1–D9 | Accepted as recorded in `E4-app-notes.md` / `E4-gather-notes.md`; no code change. | — |

**D-3 wording, recorded.** Load-result problem row for an A2L that sits beside a data file and is a link or over the cap (LLR-171.2g):
- kind: `not readable`
- file: `firmware.a2l`
- reason: `link or junction` | `too large to open` | `could not be read`
- next step: the `not readable` kind's step from `DOCUMENT_NEXT_STEP` / the composer. G1 quotes it as "replace the file, or Save project to drop it".

`01-requirements.md` still names `replace the A2L file, then Load again` as this problem row's next step (the token table row "problem: not readable … (Inc 8b, LLR-171.2g)" and LLR-171.2g's threshold). Those two places need the composer's step instead. This is a requirement-text edit for E5 or the orchestrator; it was not made here. The A2L-only refusal (LLR-171.2f, a status line, not a problem row) keeps `replace the A2L file, then Load again` unchanged.

## Fixes by file

Sources (4 = the cap):

- `s19_app/tui/app.py`: D-3 only (the reason text of the A2L problem). No other change to G1's file.
- `s19_app/tui/screens_directionb.py`: D-5 only.
- `s19_app/tui/services/project_gather_service.py`, `s19_app/tui/workspace.py`: no change to G2's files.

Tests and fixtures (not capped):

- `tests/support/b100_projects.py`: RP-3 (`_is_link` reads the reparse attribute on 3.11).
- `tests/test_b100_reuse.py`: RP-5 (placement census 8 → 9).
- `tests/test_b100_save_image.py`: RP-1 (TC-59 import set), RP-2 (TC-69 SEC-4 junction save-back re-routed through a post-load swap).
- `tests/test_b100_project_homes.py`: RP-4 (AT-B100-10 reads the painted panel cells); the 13 gap nodes below; the tester's `query(projects.LOAD_RESULT_CLOSE)` became `query(LOAD_RESULT_CLOSE)` (a name imported from the support module). `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` allows only literal / name / f-string selectors, and the attribute form was its one `other:Attribute` site (guards-01).
- `E4-tester-notes.md` gains "Re-pins and test fixes at E4 integration" (RP-1 … RP-4, old → new → requirement). `E4-mutants.md`: M22 / M41 / M54 / M75 filled, M76–M85 added.

## Re-pins (summary; full entries in `E4-tester-notes.md`)

- **RP-1** TC-59 import set + `stat`, `unicodedata`, `..`; still 0 change-module imports.
- **RP-2** TC-69 SEC-4: `W/J` loaded as a real folder, then swapped for a junction before the save-back (LLR-171.4e refuses a junction load); same oracle.
- **RP-3** `_is_link`: `DirEntry.is_junction` is not on 3.11, so the fixture followed junctions. That made `free_space[T-1 refused]` fail: its T counted the 10 MiB behind the junction (T = 10 596 352).
- **RP-5** placement census 8 → 9 (the copier's one guarded placement names `workarea_root`).
- **RP-4** AT-B100-10: `render_line` on the `#loaded_panel` container paints only its background (blank lines at both sizes), so the test now reads its `Static` cells. In a headless probe at 118 × 54 with D-5, the A2L slot's detail cell painted `firmware.a2l  3 tags`.
- Watch items `tests/test_tui_app.py:87` and the four `list_projects()` callers: see GREEN below.

## Gaps filled (all in `tests/test_b100_project_homes.py`, section "E4 integration")

| Gap (ruling 5) | Node(s) | Mutant | Sanity run |
|---|---|---|---|
| R2/R11 call order | `test_e4_r2_r11_call_order_of_a_save_as` (spy: `copy:sub:2`, `document`, `copy:top:1`, `gather`, `manifest`) | M76, M78 | killed |
| R2 `changes_1.json` | `test_e4_r2_pasted_document_beside_a_different_p_file_lands_changes_1` | M76 (M77 planned) | killed |
| F-8 `firmware_1.s19` | `test_e4_r11_f8_identical_firmware_1_in_p_is_copied_not_reused` (a first app emits once; its bytes are planted as `P/firmware_1.s19`) | M78 | killed |
| `fw.s19` / `fw_2.s19` mismatch abort | `test_e4_r11_a3r2_5_top_level_copy_reusing_the_image_row_aborts` | M79 | killed |
| R14 | `test_e4_r14_top_level_copy_counted_once_in_the_plan_total` (86 016), `test_e4_r14_top_level_copy_at_the_free_space_boundary_saves` (free = T) | M22 | killed (94 208; T short) |
| LLR-171.5 | `test_e4_llr_171_5_unrecorded_gathered_rows_are_named[1,12]` (painting side, `unrecorded` injected on the real outcome) | M75 | killed |
| LLR-171.2g MAC arm | `test_e4_llr_171_2g_linked_a2l_beside_a_mac_is_never_parsed` (0-parse spy on `_load_a2l_data_with_cache` + `parse_a2l_file`) | M54 | killed (run as "list not cleared") |
| LLR-171.1m rebind | `test_e4_llr_171_1m_document_inside_p_follows_its_copy`; `test_e4_llr_171_1m_rebind_only_to_a_plan_entry[skipped junction, dot-dot]` | M41, M80 | killed |
| LLR-171.1k unlistable folder | `test_e4_llr_171_1k_unlistable_folder_refuses_the_save` (`os.scandir` raises for that one folder) | M81 | killed |
| LLR-171.1k reserved names | `test_e4_llr_171_1k_reserved_device_names_refuse_the_save[CON.txt, lpt1.json, CONOUT$.md]` | M82 | killed |
| A3-13 precedence | `test_e4_a3_13_refusal_precedence_in_the_plan` (passed refusal → depth → unreadable → cap) | M83 | killed after a fixture fix (below) |
| Token row 9 | `test_e4_token_row_9_open_project_swapped_for_a_junction` | M84 | killed |
| AT-B100-10 panel (D-5) | the RP-4 node | M85 | killed |

Each sanity run applied one mutant to a copy of the tree (`scratchpad/int8b/mut`, `s19_app.__file__` printed there) and ran only the named nodes. The runs are in `scratchpad/int8b/mutants-out.txt`. They are not E5's mutation run.

**M83 first survived.** With the trailing-dot entry under `flows/`, the depth stop ended the walk before that entry was classified, so the "unreadable before depth" mutant left the result unchanged. The entry moved to the top level (classified before the walk reaches the deep folder). The node then kills M83. This was a vacuous arm in the first draft, caught by the sanity run.

### Integration finding I-1 (for E5)

LLR-171.5's end-to-end example (a gathered `con.json`) cannot reach the "copied but not recorded" line through the dialog's `batch`. The manifest writer refuses the device-stem `batch` entry first: "Project NOT saved: could not save — project.json was not written. check the folder." (measured). Through a recorded `batch` the name never reaches the gather. So the line is reachable only by a gathered row whose own name is unrecordable while the selection that brought it in is recordable. The node therefore asserts the app's painting of `GatherOutcome.unrecorded` (10-line cap, `and K more`), and the gather's own `unrecorded` population stays unexercised end to end. For E5: confirm a real path (the CRC template?) or re-word LLR-171.5's example.

### Integration finding I-2 (D-5 side effect, for E5)

The D-5 branch shows a present A2L slot whenever no `LoadedFile` exists, which includes a standalone A2L load with no image (its slot painted `(none)` at the base). The present slot carries the `[u]` button, but `_apply_unload("a2l")` with `current_file is None` paints "Nothing to unload." (unchanged `app.py`), so in an A2L-only session that button does nothing. 0 of the 29 snapshots changed (guards-01). Fixing the unload path is an `app.py` change outside D-5's scope: backlog or E5.

## Gaps left (named)

- **LLR-171.4h** (8 named writers, 16 + 8 junction arms; the Save writers' swap arm after the load and between plan and copy): not written (ruling 5: leave unless trivial). RP-2 and token row 9 each cover one swap shape.
- **Q11** (Execute on an A2L-only project, crash check; A3-15 backlog): not written.
- **M77** (the pasted document predicted against the empty home): the node exists, but the mutant was not run.
- **G-5** (R16 walker bound: the yield count and `sorted` sizes are not spied) remains as the tester recorded it. It was not in ruling 5.

## GREEN and guards

All transcripts were run from cwd = the worktree, with `s19_app.__file__` = the worktree's `s19_app/__init__.py` printed in each header.

- **`evidence/inc-8b/green-01-new-and-touched.txt`** (03:50–04:46 UTC; 31 modules: the tester's nodes, the operator's list, and every module that greps the changed functions): **1051 passed, 4 failed, 1 xfailed** (3 362 s). The 4 failures:
  1. `test_b100_save_guards.py::test_tc_b100_05_merge_keeps_a_too_large_document_under_one_second`: 1.094 s against a 1.0 s bound, while the guards and the mutant runs shared the CPU. Re-run alone twice: passed both times (`green-02-repin-and-timing.txt`, `green-03-timing-alone-2.txt`). Timing under load, not a defect.
  2. `test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root`: 9 placement calls found where 8 were pinned. Design-intended: `_copy_project_subfolders` is one more guarded placement, and it names `workarea_root`. Re-pinned as **RP-5** (8 → 9, plus an assertion of exactly 1 placement in the copier); passes in `green-02`.
  3. `test_tui_commandbar.py::test_at_b78_03_the_palette_action_set_matches_the_frozen_artifact` and
  4. `test_tui_report_filter_surface.py::test_at_056e_a2b_diff_report_byte_identical_despite_selection`: **pre-existing**. Both fail with the same assertion at the base `ebe6d0c` (`evidence/inc-8b/base-01-two-failures.txt`, cwd = the base worktree, clean). Neither test touches an 8b file.
- Watch items: `tests/test_tui_app.py:87` and the four `list_projects()` callers passed in green-01. No re-pin was needed.
- The re-pins and gap nodes made while green-01 was running were each run after their edit: the A3-13 fixture fix and the census selector fix in `guards-02-after-selector-fix.txt` (24 passed), RP-5 in `green-02`. green-01 itself collected the earlier text of those two nodes: A3-13 passed there in its first form, and the census guard is not in green-01.
- **`evidence/inc-8b/guards-01.txt`** (03:50–03:52 UTC): **74 passed, 1 failed**; **29 snapshots passed, 0 snapshot cells changed**. The failure was `test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` on the tester's `query(projects.LOAD_RESULT_CLOSE)` (fixed above). `guards-02-after-selector-fix.txt`: the whole `test_address_census.py` and the A3-13 node, **24 passed**.
- Not run (operator ruling): the full suite and the census.
