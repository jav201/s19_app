# Code-Wire baseline notes — Inc 11 slice on main 8947666 (designed post-9b / post-10)

## Numbers

| Item | Value |
|---|---|
| Graph | `baseline-11.md` (this folder) |
| Base | main checkout `C:\Users\jjgh8\Github\s19_app` at `8947666`, clean apart from an untracked `prototypes/load_projects/` that was there before. sha256 prefixes: `app.py` bbf04117fbf0 (byte-identical to the 9a tree that E1's probes ran on), `screens.py` 49d6efdc73e2, `styles.tcss` 781f04ed2cc3, `project_gather_service.py` 524c3409037c. The checkout was only read. The probes ran on a copy in `../work/tree`. One pytest run (census, below) used the checkout read-only, with `-p no:cacheprovider`, `PYTHONDONTWRITEBYTECODE=1` and `--basetemp` in `../work/pt`. |
| Nodes | **42**. `screens.py` 6 (`SaveProjectScreen.__init__`, `._assignment_rows_enabled`, `.compose`, `.on_mount`, `._collect_composition`, `.on_button_pressed`). `app.py` 24: the slice (`action_save_project`, `check_action` post-10, `_handle_save_dialog` post-10, `_decide_project_image`, `_plan_project_save`), the guard and plan helpers (`_save_as_source_for`, `_project_folder_refusal`, `_manifest_carry`, `_manifest_is_link`, `_derived_record`, `_document_home_contained`, `_file_digest`, `_save_manifest_keys`), the commit helpers (`_abort_save`, `_copy_project_subfolders`, `_write_editor_document`, `_write_and_verify_manifest`, `_unrecorded_document_lines`, `_plan_row_mismatch`, `_plan_without_document_key`, `_save_clears_panel_flag`), the Q4 context (`_assignment_candidate_files`, `_variant_display_options`) and `list_projects` (post-9b; E1-scope §5's clash alternative). `project_gather_service.py` 5 (`plan_project_save`, `_plan_copies`, `painted_names`, `classify_active_document`, `inventory_project_tree`). `workspace.py` 4 (`sanitize_project_name`, `is_windows_device_name`, `predict_placement`, `resolve_input_path`). `change_service.py` 2 (`differs_from_last_saved`, `image_differs_from_source`). `screens_directionb.py` 1 (`PatchEditorPanel.is_dirty`, post-10, no code). |
| Nodes Inc 11 changes (per `func:`) | 12: `SaveProjectScreen.__init__`, `.compose`, `.on_mount`, `.on_button_pressed` (rewritten, G-A); `action_save_project`, `check_action`, `_handle_save_dialog`, `_decide_project_image` (call site only), `_plan_project_save`, `_save_as_source_for` (call count only) (G-B); `plan_project_save`, `_plan_copies` (Q10, G-B). Everything else is unchanged context. |
| NEW nodes with no code | `SavePreview`, `SaveProjectScreen.plan` / `BINDINGS` / the timer / the save and cancel actions (G-A); `_prepare_project_save`, `_save_session_inputs`, `_save_dialog_preview`, and the proposed `_commit_project_save` (G-B). A baseline graphs only existing code, so they are seams in `interfaces-11-proposed.md`, not nodes. |
| Post-9b / post-10 nodes | `check_action` (body from proto-9b-app G3 + proto-10-app), `_handle_save_dialog` (one expression from proto-10-app), `list_projects` (proto-9b-app Q7), `PatchEditorPanel.is_dirty` (interfaces-10 S-c; not in code, not marked). |
| Example lines | 60, 1 to 5 per node. Each names a probe step (p11b U1–U8, P11-1 … P11-4, p9b U2, p10b U2), an existing test, or a code read, and describes behaviour that holds on the base. Where Inc 11 turns a line RED, the line says so ("RED side of …"). |
| Caller lines | one `> callers (extractor): …` note per node, generated from `extract-baseline/extract.json` by `../work/callers.py` and converted to base line numbers (the extractor reports lines of the marked copy; each base line = marked line minus the marks above it in the same file). "direct" means the site is inside the caller's own `def`. "Through an unmarked helper" means the extractor lifted the call through a function that is not a node. "Unmarked sites" are call sites with no marked node above them. |
| Extractor | `codewire_extract.py` (Code-Wire v3.1 core), Anaconda Python 3.11 (s19env), on a throwaway marked copy. Final run, exit 0: 41 marks, 41 graph nodes, 47 real calls, 0 findings, 0 ambiguous resolutions, 0 parse failures. The first run reported 2 drifts on `_handle_save_dialog`: blank lines inside its `func:` ended the node before its `module:` line. I removed the blank lines and re-ran. The graph given to the extractor (`../work/graph-extract.md`) is `baseline-11.md` minus the post-10 node `PatchEditorPanel.is_dirty`, which has no code. |
| Marks | 41 marks written by `codewire_marks.py` into `../work/marked`, a copy of `s19_app/` committed into a throwaway `git init` repo (`git diff --stat`: 5 files, 41 insertions); that copy was deleted after the run. The checkout has 0 marks (`grep "# node:"` → 0). |
| Lint | not run (brief: no lint, coherence or STE gates). |
| Report | `extract-baseline/diff-report.md`, `extract-baseline/extract.json` |
| Probe | `probe-p11b.py`, `probe-p11b-u4b.py`, `probe-p11b-u8.py` (this folder); outputs `probe-p11b.out.txt`, `probe-p11b-u4b.out.txt`, `probe-p11b-u8.out.txt`. They ran on `../work/tree` (a copy of `s19_app/`, `tests/support`, and `examples/case_01_basic_valid`, `case_06_large_nested_a2l`) with the s19env interpreter, `python -I`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUTF8=1` and `LOCALAPPDATA` in `../work/localappdata`. The import line prints `…\inc-11-design\work\tree\s19_app\__init__.py`. Split analysis: `split-flow.py` → `split-flow.out.txt` (an AST read of the copy). |

### Probe p11b output (executed, base)

```text
== U1 fresh1 status ['Project saved + manifest verified', "Saved project to …\\workarea\\fresh1 (variant 'firmware')"]
== U1 counts {'_decide_project_image': 1, '_file_digest': 1, '_plan_project_save': 1, '_project_folder_refusal': 1, '_save_as_source_for': 2} handler_ms=26.2
== U1 tree ['firmware.s19', 'project.json']
== U2 open-project save status ['Project saved + manifest verified', "Saved project to …\\workarea\\P (variant 'firmware')"]
== U2 counts {'_decide_project_image': 1, '_file_digest': 3, '_plan_project_save': 1, '_project_folder_refusal': 1, '_save_as_source_for': 2}
== U2 save-as counts {'_decide_project_image': 1, '_file_digest': 3, '_plan_project_save': 1, '_project_folder_refusal': 2, '_save_as_source_for': 2}
== U3 plan rows [('image', 'firmware.s19', 'new'), ('document', 'changes.json', 'new'), ('manifest', 'project.json', 'new')]
== U3 plan copies ['patches/changes_1.json']
== U3 Q tree ['firmware.s19', 'patches/changes_1.json', 'project.json']
== U3 Q active_document patches/changes_1.json
== U4 file_type mac mem_map {'0x80000000': 0} ranges []
== U4 decide emit False refusal None
== U4 save status ['Project saved + manifest verified', 'Saved project to …\\workarea\\macsave']
== U4b dispositions [('0x80000000', 'skipped-outside')]
== U4b rederived_differs False
== U5 status ['Nothing to save: load a data file or A2L first.'] folder False
== U6 ''  / '   ' / '!!!'  -> ['Project NOT saved: name is empty — type a project name.']
== U6 'con.txt' / 'CON'    -> ["Project NOT saved: '<name>' is a device name — choose another name."]
== U6 'Reports'            -> ["Project NOT saved: 'Reports' is a reserved name — choose another name."]
== U6 65 x 'a'             -> ['Project NOT saved: name too long (at most 64 characters) — shorten the name.']
== U6 'a b' / 'AB'         -> ["Project NOT saved: '<typed>' is already a project as 'ab' — choose another name."]
== U6 folders ['ab', 'patches', 'temp']
== U7 __init__ (self, default_parent: 'Path', variants=None, candidate_files=None)
== U7 BINDINGS [] AUTO_FOCUS None ; plan attr False ; id="load_dialog" count in screens.py 8
== U7 payload fields ['parent_folder', 'project_name', 'batch', 'assignments']
== U8 inventory 2000 files: folders=[('flows', 1000), ('reports', 1000)] best_of_5=189.4 ms
```

(Paths are shortened and the U6 lines are grouped; the full lines are in the `.out.txt` files. The `—` shows as `?` there, an artefact of the console code page.)

E1 probes still valid on this base (`app.py` / `screens.py` byte-identical to the 9a tree): P11-1 (A2L digest 26.1 ms), P11-2 (escape, empty Save, no live line, the parent field and Browse, `ctrl+l` / `ctrl+s` stacking a modal over Save), P11-3 (`ctrl+d` changes the density under Save), P11-4 (4 MiB render 1 215 ms).

## The split of `_handle_save_dialog` (line map)

The graph node `S19TuiApp._handle_save_dialog` holds the full map (G0–G18, C1–C5). Summary:

| Part | Lines (base) | Size | Goes to (proposal) |
|---|---|---|---|
| G0 cancel (`payload is None`) | 9448–9450 | 3 | stays in the router |
| G1 nothing loaded | 9451–9454 | 4 | stays in the router (direct calls); the dialog path checks it in `action_save_project` (LLR-175.3j) |
| G2–G3 parent resolve and parent = work area | 9455–9475 | 21 | stays in the router (reads the payload, not the name) |
| G4–G10 name rules: empty, sanitise, device, reserved, 64, path limit, clash loop (with the LED .52(a) rebind of `cleaned`) | 9476–9608 | 133 | `_prepare_project_save` |
| G11 missing source | 9609–9637 | 29 | `_save_session_inputs` (per open) → refusal carried by the session |
| G12–G14 target folder, target check, save-as source | 9638–9697 | 60 | `_prepare_project_save` |
| G15 image step, manifest read, carry, document classifier, emitted record, plan | 9698–9790 | 93 | image step → session; the rest → `_prepare_project_save` |
| G16 unreadable source (`except OSError`) | 9791–9808 | 18 | session (for the session's files) + `_prepare_project_save` (for a target or document read) |
| G17 plan refusal | 9809–9819 | 11 | `_prepare_project_save` |
| G18 free space | 9820–9855 | 36 | `_prepare_project_save` |
| **Guard-and-plan half** | **9447–9855** | **409** | about 380 lines move; G0–G3 (28 lines) stay |
| C1 `mkdir` ownership | 9856–9868 | 13 | commit |
| C2 snapshot, rollback lists, document class, document row | 9869–9909 | 41 | commit |
| C3 the one `try` (copies, rows loop, gather, manifest) | 9910–10349 | 440 | commit |
| C4 four `except` arms → `_abort_save` | 10350–10425 | 76 | commit |
| C5 committed tail (adopt, lines, rebinding, panel flag, labels) | 10426–10605 | 180 | commit |
| **Commit half** | **9856–10605** | **750** | `_commit_project_save` (proposal) or inline |

- **What crosses the cut.** 12 locals: `cleaned`, `project_dir`, `save_as_source`, `source_gone`, `image_step`, `existing`, `target_carry`, `carried_derived`, `carried_active_document`, `carried_document_line`, `emitted_record` and `plan`, plus `payload.batch` / `payload.assignments`.
  - `split-flow.out.txt` also lists `home`, `message`, `part` and `self`. The first three are loop or temp names rebound in the commit half; `self` is the receiver.
- **The first half writes no `self.` attribute.** Two calls inside it have effects outside the function:
  - `_decide_project_image`, which refreshes `document.issues`;
  - the logger.
- **Paint and exit counts.** Returns: 19 before the cut, 10 after. `set_status`: 18 before, 19 after. `notify`: 4 before (`:9629`, `:9800`, `:9811`, `:9843`), 2 after.

## Selectors (`styles.tcss`, not graph nodes)

| Selector (line) | Current rule | Used by | Inc 11 (E1 C1–C4) |
|---|---|---|---|
| marker comment (`:1563`) | `/* --- Calm Dark modal re-skin (batch-02 increment 8, LLR-015.1) ---` | `_modal_css_block()` in `test_tui_directionb.py` finds the modal block by it | keep verbatim (9b A9b-12) |
| `ModalScreen` (`:1576`) | `align: center middle`, dimmed base | every modal | unchanged |
| `.modal-dialog, #load_dialog` (`:1581`–`:1589`) | border, panel background, `padding: 1 2`, `width: 70%`, `height: auto` (no max-height) | `SaveProjectScreen` and 7 other screens carry `id="load_dialog"` (p11b U7: 8 in `screens.py`) | the Save dialog takes `#save_box` (C1) and keeps `.modal-dialog` |
| `.modal-title` (`:1591`) | accent, bold | all modals; TC-033 queries one per modal | keep one `.modal-title` Label |
| `.modal-buttons` (`:1732`), `.modal-buttons Button` (`:1740`), `.modal-confirm` (`:1746`) | horizontal, `dock: bottom`; confirm in the accent | `#saveproject_buttons`; TC-033 reads `.modal-confirm`'s background | unchanged; C4 keeps them visible under a long summary |
| `.modal-dialog Input`, `:focus` (`:1752`, `:1758`) | border, focus border | `#project_name`, `#project_parent_path` | unchanged |
| `.assign-list` (`:1772`) | border, `height: 6`, `margin-bottom: 1` | `#assign_batch`, `#assign_<i>` | unchanged (Q4) |
| `#save_box`, `#save_where`, `#save_summary` | none yet | none | C1–C3, new, tokens only (TC-033) |

## Reverse census

### Direct `_handle_save_dialog` calls kept green (LLR-175.4l)

**Grep result: 56 call lines in 11 files, plus 1 call by reference = 57, not the 58 that E1 states.**
- The 56 call lines match `_handle_save_dialog(`.
- The call by reference is `app.call_next(app._handle_save_dialog, _payload(app, name))` at `test_b100_save_image.py:880`.
- E1's own per-file list (2 + 2 + 2 + 38 + 3 + 1 + 1 + 1 + 4 + 1 + 1) sums to 56.
- One more line assigns a spy to the attribute without calling it (`test_tui_manifest_save.py:712`, `_capture_save_payload`); it is listed under census category H.

Many of these sites are helpers that fan out to more tests. `save_case01_project` alone is used on 25 lines in 5 files, `projects.save_project` on 29 lines in 5 files, and `build_save_as_project` (which saves through `save_case01_project`) on 31 lines in 3 files. The full list is in `../work/direct-calls.txt`. By file and enclosing function:

| File | Sites | Enclosing function (line) |
|---|---|---|
| `tests/support/b100_projects.py` | 2 | `save_case01_project` (:308), `save_project` (:634) |
| `tests/test_b100_active_variant.py` | 2 | `_save_project` (:223), `test_tc_b100_20_writers_on_a_31_folder_manifest_finish_under_one_second` (:689) |
| `tests/test_b100_project_homes.py` | 2 | `_save` (:139), `test_tc_b100_62_folder_check_permission_error_has_its_own_text` (:2407) |
| `tests/test_b100_save_guards.py` | 38 | `_load_and_save` (:222); TC-B100-04 `…reserved_homes_refused_in_every_casing` (:264), `…empty_names_refused` (:307), `…device_names_refused_raw_and_sanitised` (:358); TC-B100-05 `…disguised_clash_refused_naming_both` (:464), `…case_only_clash_refused` (:494), `…exact_name_adds_a_variant` (:519), `…open_project_unsanitised_name_saves_into_it` (:548), `…open_project_case_variant_saves_under_on_disk_name` (:587), `…case_only_match_against_another_project_refused` (:630), `…junction_target_refused_without_writing` (:661); TC-B100-06 `…name_cap_boundary` (:692, :694, :697), `…path_limit_met_and_exceeded` (:739, :741); TC-B100-07 `…forced_oserror_leaves_no_folder` (:991), `…failed_merge_removes_placed_files` (:1054), `…failed_save_removes_every_placed_path` (:1126), `…rollback_keeps_denied_folder_content_r7` (:1188), `…rollback_keeps_concurrent_writer_file_r8` (:1241), `…manifest_mismatch_is_the_newest_status_line` (:1287), `…unreadable_workarea_folder_skipped` (:1325), `…rollback_never_touches_junction_target` (:1415), `…junction_cycle_does_not_block_save` (:1462), `…case_variant_reused_file_survives_failed_save` (:1608), `…failed_verify_leaves_no_folder_fresh` (:1656), `…failed_verify_restores_previous_manifest` (:1697, :1708), `_failed_merge_with_restore_blocked` (:1750, :1762), `…restore_retry_lands_when_the_holder_lets_go` (:1851, :1860), `…save_project_keeps_a_manifest_it_cannot_carry` (:1981), `…save_project_refuses_when_no_previous_copy_can_be_kept` (:2030), `…rollback_keeps_the_previous_copy_unless_restored` (:2100), `…gather_home_created_then_copy_fails_no_folder_left` (:2168), `…empty_preexisting_home_survives_failed_save` (:2215) |
| `tests/test_b100_save_image.py` | 3 (+1 by reference) | `_save` (:223), `test_tc_b100_17_non_os_error_after_the_emit_rolls_back_then_surfaces` (:818), `_save_tolerant_8b` (:2266); by reference `:880` |
| `tests/test_project_gather.py` | 1 | `_save_project` (:147) |
| `tests/test_tui_app.py` | 1 | `test_save_project_writes_under_workarea` (:85) |
| `tests/test_tui_evidence_packs.py` | 1 | `test_save_project_creates_project_folder_on_disk` (:109) |
| `tests/test_tui_manifest_save.py` | 4 | `test_project_save_writes_and_verifies_manifest` (:117), `test_manifest_mismatch_surfaces_loud_notice_naming_drift` (:188), `test_manifest_write_refusal_surfaces_error_notice_no_crash` (:259), `_save_through_handler` (:345) |
| `tests/test_tui_report_seam.py` | 1 | `_save_loaded_project` (:632) |
| `tests/test_tui_variants.py` | 1 | `test_save_second_s19_into_project_appends_variant` (:385) |

All of these pass a `SaveProjectPayload` with `parent_folder=str(app.workarea)` (or a deliberate wrong parent in TC-B100-05/-07 arms) and read the status log; under the S-c router they reach `_prepare_project_save` and then the commit, so their texts must not change except by the scrub (S-a), which removes only Cc / Cf characters none of them type.

### Tests that break when the slice changes (by reading; base run below)

Method: grep for `SaveProjectScreen`, `#project_parent_path`, `#save_browse`, `#save_ok`, `#project_name`, `action_save_project`, `ctrl+s`, `_handle_save_dialog`, `_plan_project_save`, `plan_project_save`, `ast.parse` over `app.py`, then each hit read against the interface proposal. Not executed against a prototype (there is no code). The 24 ids below were run on the base (`../work/census-base-run.txt`) to confirm they pass today; see "Base run".

| Cat. | Why it breaks | Tests (file::test) |
|---|---|---|
| A | The constructor loses `default_parent` (S-b); the parent field is gone | `tests/test_tui_directionb.py::test_tc033_modals_render_with_calm_dark_tokens` (`_MODAL_SPECS` builds `SaveProjectScreen(tmp_path)`; its post-9b form is not in the 9b graph, so the Save entry is re-pinned at Inc 11 whatever 9b does with the other two); `tests/test_tui_directionb.py::test_tc034_modals_behavior_methods_intact` (`SaveProjectScreen(tmp_path)`, `#project_parent_path` at :3090); `tests/test_loadfilescreen_input.py::test_ac2_paste_reaches_project_name_input` (`SaveProjectScreen(default_parent=tmp_path)`) |
| B | `#project_parent_path` is clicked or set (LLR-175.2) | `tests/test_b99_staging.py::test_tc_b99_14_save_project_missing_source`, `::test_tc_b99_14_placement_failure_removes_created_folder`, `::test_tc_b99_14_preexisting_folder_survives_placement_failure`, `::test_at_b99_05_save_project_after_same_name_save_back`, `::test_tc_b99_ux_c10_save_project_filename_renders_literally`, `::test_tc_b99_ux_c10_placement_error_path_renders_literally` (the 6 nodes E1 §C.4 names) |
| C | `#project_name.value = …` then `#save_ok.press()` with no wait: the 150 ms recompute is still pending, so the painted plan is not the plan for the name, and LLR-175.4b keeps the dialog open | `tests/test_tui_manifest_save.py::test_tc304_screen_collects_per_variant_and_batch_assignment`, `::test_tc306_screen_no_selection_yields_empty_composition`; also the two `ux_c10` tests of B |
| D | The name is typed key by key and `#save_ok` is clicked at once (LLR-175.4b, same reason), then the test waits for a status outcome or the dialog to close | `tests/test_b100_active_variant.py::test_at_b100_06_reopen_opens_the_saved_back_variant`; `tests/test_b100_document.py::test_at_b100_08_saved_document_reopens_with_the_project`; `tests/test_b100_project_check.py::test_at_b100_07_load_names_the_changed_file_and_the_hostile_record`; `tests/test_b100_project_homes.py::test_at_b100_09_save_as_copies_the_project_and_q_lists_its_flow`, `::test_at_b100_10_a2l_only_project_saves_and_reopens`, `::test_at_b100_11_junction_project_is_not_listed_and_save_refuses_it`; `tests/test_b100_save_guards.py::test_at_b100_02_name_refusals_through_the_save_dialog`; `tests/test_b100_save_image.py::test_at_b100_05_save_project_saves_the_patched_image`; `tests/test_b100_session_reset.py::test_at_b100_03_project_load_over_unsaved_work_saves_only_p2` |
| E | A refusal is now painted in the dialog with the dialog open (ruling Q5, LLR-175.1k); the test waits for the dialog to close or for a status line | AT-B100-02 (`Reports`, `CON`, 300 × `x`, `a b` arms; re-pin owed by E1), AT-B100-11 (`evil`, the junction arm), `test_tc_b99_14_save_project_missing_source` (missing source) — all already in B / D |
| F | The open project's name is prefilled (LLR-175.3h) and the drive clicks the field then types without clearing it, so the typed text is appended | AT-B100-02's `a b` arm (`prg` open, :2379 → :2387: the field would hold `prga b`); AT-B100-03 (`P2` open, typing `P2` at :930) — both already in D. `_at_save_through_dialog` (`test_b100_project_homes.py`) clears with `ctrl+a`, `delete` first and is safe. |
| G | `ctrl+s` with nothing loaded no longer opens the dialog (LLR-175.3j) | none found: every drive loads first, and the two tests that build the dialog with nothing loaded push it directly (category A) |
| H | Structure censuses over `app.py` | `tests/test_b100_save_guards.py::test_tc_b100_07_ast_census_every_post_creation_return_removes` breaks only if the commit leaves `_handle_save_dialog` (proposal S-c moves it to `_commit_project_save` → re-pin one string). `tests/test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census` breaks only if a new `self.<name> =` is added to `S19TuiApp` (Q-1 option 1 → classify `_save_session`). `tests/test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root` holds while the count of placement calls in `app.py` stays 9. `test_tui_manifest_save._capture_save_payload` (used by tc304 / tc306) replaces `app._handle_save_dialog` with a one-argument lambda: the dismiss callback must call `self._handle_save_dialog(payload)` with one argument (S-c). |
| I | Q10 changes a planned row | `tests/test_b100_project_homes.py::test_e4_r11_a3r2_5_top_level_copy_reusing_the_image_row_aborts` pins today's abort ("the plan named … fw.s19 … fw_2.s19"). It breaks only if Q-5 option 2 (carried rows too) is taken; it becomes a saved `keep` row. `test_tc_b100_31_document_with_an_identical_sibling_follows_its_landing` asserts the landing only and holds. The direct `plan_project_save(...)` calls in `test_b100_project_homes.py` (3 tests) and `test_b100_save_image.py` (4 tests) have no identical siblings and should hold; E4 re-runs them. |

**Count: 20 test functions break by reading.**
- Per category: A 3, B 6, C 2, D 9. Categories E and F overlap these.
- 2 more are conditional on rulings: H (TC-B100-07, TC-B100-09) and I (`test_e4_r11_a3r2_5`).
- Several of the 20 are parametrized over the two reference sizes, so more test ids run.
- Kept green: the 57 direct calls (LLR-175.4l), the 3 `_decide_project_image` / `_plan_project_save` direct calls (`test_b100_save_image.py:286`, `:402`, `:1497`; S-d keeps the positional signature), and every "Nothing written" assertion (9 substring checks; LLR-175.1l only appends the next step).

**No snapshot or label assertion holds the Save dialog.**
- Searched: "Save project folder under", "Project name (new folder", "Browse..." and "Project-wide batch files".
- 0 hits in `tests/` outside `__pycache__`, so no SVG cell needs re-taking.

### Base run

See the section appended at the end of this file.

## Surprises (the E1 against the code)

1. **LLR-175.1n is unreachable; E1's feasibility note is wrong about why.**
   - E1 says "a MAC-only session has an empty image map, so its entries are blocked first (LLR-175.1m)". It does not.
   - A MAC load builds `mem_map = {addr: 0 for each MAC address}` and `ranges = []` (`app.py:14205`–`:14207`). Only `_unload_primary` gives an empty map.
   - With `ranges []`, every change entry's disposition is `skipped-outside`, not `blocked` (p11b U4b). `rederived_differs_from_source` is false, so `render_patched_image` is never called. The save completes as an unchanged copy (p11b U4).
   - `file_type` is only ever `s19`, `hex` or `mac` (`s19+mac` is a log label). S19 and HEX have emitters, so the `cannot be written` arm has no loadable input.
   - Per ruling Q11, withdraw LLR-175.1n and its token row.
   - Side finding (not an Inc 11 requirement; backlog candidate): a MAC-only session with pending change entries saves with no line saying they were skipped.
2. **The direct-call count is 56 (+1 by reference), not 58** (see the census). LLR-175.4l's threshold and E1 §C.4 should say 56 call lines in 11 files, plus `test_b100_save_image.py:880` by reference.
3. **Ruling Q3 / E1 S-e spell the guard as a stack-top test.** 9b S9b-1 and Inc 10 fixed the whole-stack form `any(isinstance(s, (LoadDialog, ConfirmQuestionScreen)) for s in self.screen_stack)`. Inc 11 should add `SaveProjectScreen` to that tuple.
4. **"Five modals share `#load_dialog`" (E1-scope S-f) is eight** in `screens.py` (p11b U7), as the 9b E2 rulings already corrected.
5. **The plan is not executed as the same object.**
   - `:10225` replaces `plan` with `_plan_without_document_key(plan)` when the document is not recorded: the same rows, keys without `active_document`.
   - LLR-175.4a's "dataclass equality with `SaveProjectPayload`'s / the dialog's plan" holds only if the spy reads the plan at the commit's entry, before `:10225`.
6. **Per-name costs E1 did not list (Q-4).** The save-as inventory walks the open project on every plan, 189.4 ms for 2 000 files (p11b U8). The file-backed document digest is also recomputed per plan. LLR-175.5a's 300 ms final-paint threshold is tight for a large save as unless the session holds them.
7. **The F5 remainder is wider than E1's sentence.** p11b U3 confirms the document case: the plan says `new changes.json`, the tree holds `changes_1.json`, and no mismatch is painted, because the file-backed document row is skipped by the rows loop and placed by the gather.
   - The backlog wording also covers the top-level carried case (`fw_2.s19` / `fw.s19`), which today aborts with "the plan named …".
   - Fixing both re-pins `test_e4_r11_a3r2_5…` (Q-5).
8. **Refusal texts embed raw names.** G6 (device) and G10 (clash) put the typed and on-disk names into the status text without `painted_names`. LLR-175.4g requires the scrub in the dialog. The prepared refusal should scrub, so that the status line and the dialog stay equal (LLR-175.6).
9. **Two halves, not "about 440 lines".** The guard-and-plan half is 409 lines (`:9447`–`:9855`). 28 of them (G0–G3) read the payload and stay in the router, so about 380 lines move.
10. **The prefill collides with 2 acceptance drives** (census F): AT-B100-02's `a b` arm and AT-B100-03 click the field and type with a project open. E1 §C.4 lists neither collision.

## Callers outside the slice that matter for Inc 11

- **`_handle_save_dialog`.** There is no product caller other than the dismiss callback at `:7400`; the extractor cannot see it, because the callback is passed as a value. Tests: the census above.
- **`check_action`.** The key bar reads it (`window_help.py:1134`, `:1145`). While the Save dialog is open, the main screen's key bar behind the modal may paint `ctrl+l`, `ctrl+s`, `ctrl+k` and `ctrl+d` dimmed. This is the same note as 9b Surprise 4 and Inc 10.
- **`_variant_display_options`** is also used by the variant picker (`:7539`, unmarked) and, through an unmarked helper, after the save (`:17610`). Q4 keeps it unchanged.
- **`_project_folder_refusal`** is also called by the Load paths (`:11684`, `list_projects` `:12127`). Inc 11 does not change it.
- **`sanitize_project_name`** has 4 other callers (CRC designer, `screens.py:792` for the flow name, flow persistence ×2). Inc 11 does not change it.
- **`list_projects`.** Its callers are the 3 Load paths (`:7441`, `:11714`, `:12871`). If N1 adopts it for the clash, the post-9b content test also decides the clash (E1-scope §5). TC-B100-05's clash arms are the check.
- **Calls the extractor cannot see.**
  - `action_save_project` → `SaveProjectScreen` → `_handle_save_dialog`: the dismiss callback.
  - The palette and the bindings: dispatch by action name.
  - The framework handlers `compose`, `on_mount` and `on_button_pressed`: 0 callers listed.

## Wall time

About 70 minutes by the shell clock. The probe, the split analysis and the graph took most of it; the extractor runs were seconds each; the base run of the 24 census ids ran in the background.

## Base run (appended after the run finished)

The 24 test functions of the census (`../work/census-ids.txt`) were run on the base checkout, read-only: `-p no:cacheprovider`, `PYTHONDONTWRITEBYTECODE=1`, `--basetemp` in `../work/pt`, and `NO_COLOR` unset.
- The 24 are the 20 that break by reading, `test_tc305` (a bystander of category C, kept as a control), and the 3 structure censuses of category H.
- Result: **35 passed in 518.81 s** (parametrized sizes give 35 ids), 0 failed. Output: `../work/census-base-run.txt`.
- So every break in the table would be caused by Inc 11; none is a failure that already exists on main.
- `git status` of the checkout was unchanged after the run.
