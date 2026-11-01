# Inc 12b — E4 implementer notes (app.py, G-A / G-B / G-C)

Base: `71376a3` (12a integrated, pre-corrective). Edited file: `s19_app/tui/app.py` only.
Final `sha256[:16]` of `s19_app/tui/app.py` = `89b2d043c60f3a2f`.

## Scope

Work order followed: G-C1 first, then G-A, then G-B, then G-C2; compiled after each group
(`C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/app.py`). Test suite NOT run.

## Functions / classes / data added

- Module constants `SESSION_ACTION_KEYS`, `_BUSY_LINE`, `_QUIT_TITLE`, `_QUIT_BODY`, `_QUIT_YES`, `_QUIT_NO` — line 429..440.
- `_QuitQuestionScreen(ConfirmQuestionScreen)` — line 442.
- `ProjectLoadRequest` (frozen) — 450; `PreparedProjectLoad` (frozen) — 465; `SaveImageInput` (frozen) — 483; `SaveRequest` (frozen) — 498; `SaveOutcome` (frozen) — 516; `A2LAttachRequest` (frozen) — 540; `A2LAttachResult` (frozen) — 553.
- `_save_failure_outcome(request, lines, toast)` module fn — 563.
- `A2LCacheEntry` type alias — 870; `parse_a2l_cached(path, cached, progress=None)` module fn — 877.
- `S19TuiApp._a2l_cache_entry` — 17959; `S19TuiApp._store_a2l_cache` — 17978.
- `S19TuiApp._project_load_worker` — 13461; `_prepare_project_load` — 13475; `_on_project_loaded` — 13617; `_install_prepared_project` — 13627; `_on_project_load_failed` — 13697; `_parse_data_file` — 13714.
- `S19TuiApp._save_project_worker` — 11516; `_save_project_files` — 11535; `_on_project_saved` — 12154; `_write_manifest_for_save` — 12273.
- `S19TuiApp._a2l_attach_worker` — 15176; `_on_a2l_attached` — 15212; `_install_attached_a2l` — 15217; `_on_a2l_attach_failed` — 15264.
- G-C1 seam: `_running_session_action` — 20316; `_refuse_if_busy` — 20341; `action_quit` — 20365; `_answer_quit` — 20385; `_exit_if_quit_pending` — 20390; `_progress_forwarder` — 20395.
- `__init__` gains `self._quit_pending: bool = False` (the ONE new app attribute, TC-B100-09).

## Functions changed

- `end_busy` — 20200: added the `_exit_if_quit_pending()` tail (A12a-07 / S-c) and the
  `#patch_paste_text.read_only = False` hand-back when a `project_load` run is removed (R2-02 / S12b-04).
- `_confirm_then_load` — 8109: first statement `if self._refuse_if_busy(): return` (S-e, LLR-177.3a).
- `_route_load_project` — 8306: `go` is `lambda: self._handle_load_project(name, routed=True)`; the
  `before`/identity test and the post-call push are deleted (LLR-177.1h).
- `_handle_load_project` — 13264: kickoff only (busy check, cheap refusals unchanged, begin,
  `read_only=True`, request, worker; `except BaseException` kickoff guard). `routed` parameter added.
- `_reopen_active_document` — 13802: now `(state) -> None` (install half); read half inlined in
  `_prepare_project_load` step (6).
- `_parse_loaded_file` — 17293: wrapper; `*, a2l_cache_out=None` out-list (Q-h1 / DF-8), calls
  `parse_a2l_cached` + `_parse_data_file(..., self.current_file)`.
- `_load_mac_file` — 16335: `(path, a2l_path=None, a2l_data=None)`; no session read, no cache write.
- `_merge_primary_with_existing_mac` — 16564 / `_merge_mac_with_existing_primary` — 16615: take `existing`.
- `load_selected_file` — 17238: cache out-list + `_store_a2l_cache` on main.
- `_apply_prepared_load` — 17403: `if prepared.a2l_cache is not None: _store_a2l_cache(...)`.
- `_start_load_worker` — 17823: `a2l_cache_out` out-list; `PreparedLoad.a2l_cache = out[0]`; new
  `sync_project: bool = True`; keeps `exclusive=True` / `group="load"` (R2-04).
- `_handle_load_error` — 17925: `_quit_pending = False` before the end (S12b-R2-4).
- `_commit_project_save` — 11435: kickoff (busy check, begin, `record_save_entries`, `SaveImageInput`,
  document facts, `SaveRequest`, worker; `except BaseException` guard).
- `_write_and_verify_manifest` — 12837: delegates to `_write_manifest_for_save` (signature/behaviour kept, Q-b1).
- `_abort_save` — 10360: `(…, workarea, manifest_restores, kept_copies) -> list[str]`; session-restore half removed (E1 B5).
- `_restore_manifest` — 10487: `(…, workarea, already_kept) -> Optional[str]`; returns the painted note.
- `_keep_previous_manifest` — 10568: `(…, workarea)`.
- `_copy_project_subfolders` — 14150: keyword-only `workarea`, `on_placed`; ticks per placement.
- `load_from_path` — 15001: first statement `if self._refuse_if_busy(): return` (Q-a1); keeps 12a `finally`.
- `load_a2l_from_path` — 15111: kickoff (refusals, recent decision on main, begin, `A2LAttachRequest`, worker).
- `_load_workarea_file` — 15437: A2L arm `load_a2l_from_path(candidate, copy=False)`; data arm begins
  `file_load` + `_start_load_worker(..., sync_project=False)` with `except BaseException` guard.
- The 16 entry points + 4 continuations each gained `if self._refuse_if_busy(): return` as their first
  statement (see the census below).

## Functions retired

- `_install_project_image` (parse half -> `_prepare_project_load` step 8; apply half -> `_install_prepared_project` step 7).
- `_load_a2l_data_with_cache` (-> `parse_a2l_cached`; cache store -> `_store_a2l_cache`).
- `_write_editor_document` (-> inline `write_change_document(request.document_snapshot, …)` in `_save_project_files`).

## Graph node -> code location

G-C1 (first):
- S-a busy check: `_running_session_action` 20316, `_refuse_if_busy` 20341; constants 429/434.
- S-c quit: `action_quit` 20365, `_answer_quit` 20385, `_exit_if_quit_pending` 20390, `_quit_pending` (init),
  `_QuitQuestionScreen` 442, constants 437/438.
- S-f forwarder: `_progress_forwarder` 20395.
- end tail (S-c rule): `end_busy` 20200 (quit check + `read_only` hand-back).

G-A:
- `_handle_load_project` kickoff 13264; `_route_load_project` 8306; `_project_load_worker` 13461;
  `_prepare_project_load` 13475; `_on_project_loaded` 13617; `_install_prepared_project` 13627;
  `_on_project_load_failed` 13697; `_parse_data_file` 13714; `_reopen_active_document` 13802;
  `parse_a2l_cached` 877 / `A2LCacheEntry` 870 / `_a2l_cache_entry` 17959 / `_store_a2l_cache` 17978;
  `_parse_loaded_file` 17293 / `_load_mac_file` 16335 / merge methods 16564+16615 / `PreparedLoad` field /
  `_apply_prepared_load` 17403 / `load_selected_file` 17238.

G-B:
- `_commit_project_save` 11435; `_save_project_worker` 11516; `_save_project_files` 11535;
  `_on_project_saved` 12154; `_write_manifest_for_save` 12273; `_write_and_verify_manifest` 12837;
  `_abort_save` 10360 / `_restore_manifest` 10487 / `_keep_previous_manifest` 10568 /
  `_copy_project_subfolders` 14150; `_save_failure_outcome` 563.

G-C2:
- `load_a2l_from_path` 15111; `_a2l_attach_worker` 15176; `_on_a2l_attached` 15212;
  `_install_attached_a2l` 15217; `_on_a2l_attach_failed` 15264; `_load_workarea_file` 15437;
  `load_from_path` 15001; `_start_load_worker` 17823; `_confirm_then_load` 8109.

Busy-check census (entry points, `if self._refuse_if_busy(): return` first):
`action_load_file`, `action_load_project`, `action_select_variant`, `action_unload_all`,
`on_loaded_artifacts_panel_unload_requested`, `action_save_project`,
`on_patch_editor_panel_action_requested`, `on_patch_editor_panel_save_back_decision`,
`on_patch_editor_panel_undo_requested`, `on_patch_editor_panel_redo_requested`,
`action_patch_undo`, `action_patch_redo`, `on_patch_editor_panel_edit_json_requested`,
`on_patch_editor_panel_entry_edit_json_requested`, `on_patch_editor_panel_change_file_selected`,
`on_patch_editor_panel_dirty_load_requested`. Continuations: `_apply_changeset_json_edit`,
`_apply_entry_json_edit`, and the accept arm of the two `LoadGuardScreen` `_answer` closures.

## Deviations

1. **`read_only` vs `readonly`.** The proto P-2 node text and C12b-55 write `text_area.readonly`;
   binding row R2-02 (= S12b-R2-1) states "Textual's attribute is `read_only`". Verified against
   Textual 8.2.8: `TextArea` exposes `read_only` (no `readonly`). I used `text_area.read_only`
   (set in `_handle_load_project` 13264 area, cleared in `end_busy` 20238 area). This is the only
   deliberate text deviation from the graph, and it follows a binding ruling.

2. **`created_home` tracking inlined.** Retiring `_write_editor_document` dropped its
   `os.lstat(home_dir)` created-home detection. I inlined that detection in `_save_project_files`'s
   document row arm (line ~11640) so the rollback still records a home the pasted-document write
   created (preserves base A3-5 / A3R2-8 rollback behaviour; the graph only names `write_change_document`,
   it does not forbid the home tracking).

3. **No `go_if_idle` removal needed.** E3 A12b-03 reversed P2-6; the Inc-10 `_confirm_then_load` in this
   tree already had no `go_if_idle`, so nothing was removed there beyond adding the busy check.

No other deviations. Seams consumed exactly as fixed in `interfaces-12b.md` (with the orchestrator
rulings and the E3 round-2 addenda).

## Open questions / notes for the tester

- `SaveOutcome` returned facts are composed on the main thread in `_on_project_saved` (S12b-03);
  the success line two-form (R2-01) is kept: `(variant '<id>')` when `saved_variant_id`, else the base
  no-variant form.
- `end_busy` has no `final_line` (R2-03); end sites call `end_busy`/`_busy_fail` directly.
- The failure arms clear `_quit_pending = False` before their end (S12b-01): `_on_project_saved` (failure),
  `_on_project_loaded` (refusal), `_on_project_load_failed`, `_on_a2l_attach_failed` (both arms),
  and 12a's `_handle_load_error` (S12b-R2-4).
- `_start_load_worker` keeps `exclusive=True` / `group="load"` (R2-04); the three 12b workers use
  distinct non-exclusive groups `project_load` / `save_project` / `a2l_load`, `exit_on_error` at Textual default.
- The manifest monkeypatch re-points are the tester's: `_write_and_verify_manifest` -> `_write_manifest_for_save`
  (P1-C6), `save_patched_image` / `verify_written_image` now reached as `app_module.<name>` (P1-C5).
