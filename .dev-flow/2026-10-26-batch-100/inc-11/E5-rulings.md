# Inc 11 — E5 rulings

Inputs: review-increment-020.md (code-reviewer, FAIL: 1 MAJOR, 1 MINOR, 1 NIT); security-increment-020.md (security-reviewer, FAIL: 1 HIGH, 1 NIT); CI run 41263643715 (9b items routed here); mutation summary (survivors added by the orchestrator when it lands).

| Id | Sev | Tag | Ruling | Done in |
|---|---|---|---|---|
| SE5-11-1 | HIGH | design-gap | **Fix.** Add `image_generation` to `_SaveSession` (the app's `_image_generation` at build time). `_current_save_session` and `_prepare_project_save` discard a session whose generation is out of date and rebuild it (no new refusal text: the dialog repaints with the fresh image decision; a confirm against the stale plan then paints "the summary changed"). The router reuses `confirmed` only while its generation is current. Add TC-B100-65 arms for both layouts of the probes (same address ranges: written image is derived from the NEW file, active_variant and in-memory image consistent; different ranges: no KeyError, app stays up). RED on 051f586. Probes: scratchpad/rev11-security/probe_midload*.py. | corrective |
| CR11-F1 | MAJOR | impl | **Fix.** `_plan_project_save` uses its `inventory` argument only in the walk branch (`walked = inventory if inventory is not None else inventory_project_tree(source_dir)` inside `elif source_dir is not None and refusal is None`; pass `inventory=walked`); also gate `inventory=session.inventory` on `save_as_source is not None`. Regression test through the dialog: P open, type Q (new folder) → P renamed outside → type R → paint shows `source_gone`, no copy rows; alt+s does not crash and copies nothing from P. RED on 051f586. | corrective |
| CR11-F2 | MINOR | impl | **Fix.** Restore the requirement-tagged rationale comments lost when G3–G18 moved into `_prepare_project_save` (SEC-1 "target stays UNRESOLVED", LLR-164.1, LLR-171.1 / S3-6, LLR-171.1e / R7, and the rest of the 18), at their new code locations. No code change. | corrective |
| CR11-F3 | NIT | design-gap | **Keep the sentinel (SR-11-3).** Annotate the `digests` field as `dict` and add a one-line comment at the sentinel write explaining why it cannot collide. | corrective |
| CI9b-1 | — | CI | **Fix.** screens.py LoadDialog.on_mount: replace the IfExp selector with two literal `query_one` calls in an if/else (test_address_census::test_at_b83_08). | corrective |
| CI9b-2 | — | CI | **Fix (re-pin).** test_loadfilescreen_input.py::test_at042b: re-pin to SEC9b-1 ruling B (an over-long paste into #load_path is refused → value ''), docstring cites SEC9b-1 / batch-100 Inc 9b; keep the capped-read path (inject at _STRATEGIES) and add an arm with a blob ≤ 4096 that is inserted whole. | corrective |
| SR-11-name-cap | — | test | **Fix.** name_cap 300 arm waits on a paint it can tell apart from the 65 arm (or asserts the field value). | corrective |
| SE5-11-2 | NIT | design-gap | **Backlog (Inc 12a sweep).** Length checks run before the casefold rebind; base had the same order; the commit rolls back an over-long path. | BACKLOG-CODE |

## Done (E5 corrective pass)

Detail, evidence and source shas: `E5-corrective-notes.md`. Transcripts: `evidence/inc-11/red-03-corrective.txt`, `green-03-corrective.txt`, `green-04-new-and-guards.txt`, `mut-kill-03-corrective.txt`, `green-05-final.txt`, `green-06-full-new-file.txt`.

- **SE5-11-1** — Done. `app.py:1833` (`_SaveSession.image_generation`), `:10799` (set in `_save_session_inputs`), `:10860` (`_current_save_session` rebuilds a stale session), `:10402` (`_prepare_project_save` drops a stale passed session), `:10337` (the router reuses `confirmed` only while the session generation is current). Arm: `SD::test_tc_b100_65_a_load_landing_under_the_dialog_rebuilds_the_session[same_ranges, other_ranges]` — RED on 051f586 (`base 'firmware.s19'`; `KeyError: 2147549184`), GREEN.
- **CR11-F1** — Done. `app.py:12140`, `:12153`, `:12307` (`_plan_project_save` uses `inventory` only in the walk branch, `inventory=walked`); `:10702` (`inventory=session.inventory` gated on `save_as_source is not None`). Arm: `SD::test_tc_b100_65_vanished_source_after_a_save_as_preview_copies_nothing` — RED on 051f586 (`folder reports/ (3 files) — new` painted for `R`), GREEN.
- **CR11-F2** — Done. 19 comments restored, text unchanged (one, the empty-name comment, then widened by MUT11-M-47): the router `app.py:10314` and `_prepare_project_save` `:10426`–`:10734` (list in the notes). No code change; no RED owed.
- **CR11-F3** — Done. `app.py:1831` (`digests: dict[...]`), `:12018` (planner parameter, same annotation), comment at the sentinel write `:12248`.
- **CI9b-1** — Done. `screens.py:406` (two literal `query_one` calls). Arm: `tests/test_address_census.py::test_at_b83_08_tree_holds_no_assembled_selectors` — RED on 051f586 (`screens.py:407 other:IfExp`), GREEN.
- **CI9b-2** — Done (re-pin). `tests/test_loadfilescreen_input.py::test_at042b_ctrl_v_inserts_capped_value_via_real_read[over_field_limit, fits_field_limit]`. Re-pin, no RED owed.
- **SR-11-name-cap** — Done. `SD::test_tc_b100_47_name_cap_64_65_300`: a neutral `bbb — new folder` paint before each over-cap arm, and the field value asserted. The base source is correct, so RED was shown by a mutant (cap refuses 65 but not 300) on a scratch copy.
- **SE5-11-2** — not touched (BACKLOG-CODE).

Mutation survivors routed by the orchestrator (kill proven on the scratch copy `scratchpad/corr11/mutcap`, mutant applied, arm run, source restored and sha-verified; transcript `evidence/inc-11/mut-kill-03-corrective.txt`):

- **MUT11-M-09** — Done. New arm `SD::test_tc_b100_65_a_change_before_the_first_preview_starts_no_recompute`. Mutant: KILLED (`(['early', 'early'], [False, True])`).
- **MUT11-M-14** — Done. New arm `SD::test_tc_b100_65_a_save_queued_before_a_repaint_is_shown_repaints`. Mutant: KILLED (confirm got `('two', SavePlan(...))`).
- **MUT11-M-42** — Done. New arm `SD::test_tc_b100_65_dialog_save_as_leaves_no_session_for_the_next_direct_save`. Mutant: KILLED (`_save_session` survived the dialog save as).
- **MUT11-M-45** — Done. New arm `SD::test_tc_b100_65_confirm_is_not_reused_for_another_typed_name` (B11-14). Mutant: KILLED (`(a_made, b_saved) = (True, False)`).
- **MUT11-M-68** — Done. Strengthened `SD::test_tc_b100_65_session_decided_once_per_open_case06` (emitted image digests counted: `[0, 0]`). Mutant: KILLED (`[1, 1]`).
- **MUT11-M-74** — Done. Strengthened `SD::test_tc_b100_47_target_with_two_mac_files_refused_in_the_dialog` (plan rows ≥ 1, painted rows `[]`). Mutant: KILLED, by an exception (`SavePlanRow` handed to `Text`), before the rows assertion.
- **MUT11-M-96** — Done. New arm `SD::test_tc_b100_65_document_free_name_walk_folds_case` (`patches/Changes.json` sibling). Mutant: KILLED (painted `document patches/changes.json — new`).
- **MUT11-M-47** — Done by removal. The blank-name guard and `if not cleaned:` give the same text for `""` and whitespace (`sanitize_project_name` strips, then returns `None`), so the guard is deleted; `app.py:10430`–`:10433` (the comment widened to say so). Covered by the existing empty-name arms (green-05).
- **Accepted as equivalent by the orchestrator (no work):** M-01, M-02, M-05, M-29, M-31, M-44, M-55, M-87, M-88, M-92. Killed by runtime exception, standing as killed: M-11, M-21, M-52, M-66, M-70.

## Orchestrator rulings on the corrective pass's open items

| Id | Ruling | Done in |
|---|---|---|
| O-1 | **Backlog → Inc 12b.** A source file that vanishes while the dialog is open: the save fails safely (rollback, app up, nothing written) but paints the generic `could not save` instead of base's `source file missing`. Inc 12b's Save worker reads an immutable request; the commit re-checks source presence there. | BACKLOG-CODE (Inc 12b) |
| O-3 | **Accept.** A load landing between confirm and dismiss commits a fresh plan, as the direct path does. Inc 12b's busy refusal (no session-writing entry while a load runs) closes the window. | — |
| SE5-11-3 | **Accept (round-2 security, MINOR = O-3).** Backlog → Inc 12b: the busy refusal must carry a test for the confirm→dismiss window (a load result queued between confirm and the router). The cheaper refusal ("the loaded image changed while the dialog was open — open Save project again") is the fallback if 12b's refusal cannot cover it. Also owed at batch close: the docstring of `test_tc_b100_65_a_load_landing_under_the_dialog_rebuilds_the_session` overstates "installs it into memory" (comment fix only). | BACKLOG-CODE (Inc 12b) |
