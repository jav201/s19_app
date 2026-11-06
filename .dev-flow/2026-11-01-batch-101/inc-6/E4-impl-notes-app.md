# Inc 6 — E4 implementation notes (Unit A: app)

Batch 2026-11-01-batch-101, increment 6. Implementer unit A (E4). File touched:
`s19_app/tui/app.py` only. The service/panel/help/doc files are Unit B's
(`E4-impl-notes-svc.md`); the test files are neither unit's (hard rule).

## 1. Functions changed

All 29 slice functions owned by G1 (`app.py`). 8 new, 21 changed.

| File:function | Slice # | Change |
|---|---|---|
| `s19_app/tui/app.py::on_patch_editor_panel_save_back_decision` | #1 | The offer `notify` runs only when `project_dir` (the value the manifest rewrite read) is not `None`; text loses ` (action: before_after_report)`. `show_before_after_prompt()` stays unconditional. |
| `s19_app/tui/app.py::on_patch_editor_panel_action_requested` | #2 | `parse_paste` arm calls `_hide_replaced_document_controls(panel)` in place of the single hide and ends with `_refresh_patch_checks_tab(panel)`; `add_entry`/`edit_entry`/`remove_entry` arms end with `_refresh_patch_checks_tab(panel)` after their service call. No other arm renders the Checks tab. |
| `s19_app/tui/app.py::action_patch_undo` | #3 | Keeps `before = service.document`; after `undo()`, when `service.document is not before`, hides the controls (#9); then `_refresh_patch_history_view()`. |
| `s19_app/tui/app.py::action_patch_redo` | #4 | Same as #3 for `redo()`. |
| `s19_app/tui/app.py::_refresh_patch_history_view` | #5 | The history-site `refresh_check_results(service.check_rows(), "", ...)` becomes `_refresh_patch_checks_tab(panel)` (#8). `update_checks_view()` stays. |
| `s19_app/tui/app.py::_patch_editor_load_tail` | #6 | Ends with `_refresh_patch_checks_tab(panel)`; hides nothing (E3A-01). |
| `s19_app/tui/app.py::_reset_project_session` | #7 | In the panel `else`, after `refresh_bindings()`: `_hide_replaced_document_controls(panel)` and `_refresh_patch_checks_tab(panel)`; after the panel block, `update_checks_view()` (E3A-02). No list refill (project dir still old). |
| `s19_app/tui/app.py::_refresh_patch_checks_tab` | #8 | **New**: `current = check_run_is_current()`; `refresh_check_results(check_rows() if current else [], check_status_line(), check_aggregates())`. |
| `s19_app/tui/app.py::_hide_replaced_document_controls` | #9 | **New**: `hide_before_after_prompt()`; `hide_save_prompt()`. No disk write, no focus move. |
| `s19_app/tui/app.py::_apply_prepared_load` | #10 | In the panel `else`, after site-4 `refresh_entries`/`refresh_bindings`: when `loaded.mem_map is not previous_map` → `_hide_replaced_document_controls(panel)` (S-1); then `_refresh_patch_checks_tab(panel)`; after the panel block `update_checks_view()` (E3A-02). |
| `s19_app/tui/app.py::update_checks_view` | #11 | No-run note and zero strip whenever `not check_run_is_current()` (was: `last_check_result is None`). |
| `s19_app/tui/app.py::_change_homes` | #12 | **New** (I-6): `[("", workarea/patches)]` or `[("checks/", P/checks), ("patches/", P/patches), ("library/", workarea/patches)]`; order = listing order. |
| `s19_app/tui/app.py::_check_home` | #13 | **New**: `scoped_home_target(_active_project_dir(), PROJECT_CHECKS_DIR, workarea/patches)`; nothing created. |
| `s19_app/tui/app.py::_scan_patch_change_files` | #14 | Change list over #12: per home, `prefix + name` for every `list_change_documents(folder)` name, joined in home order (no global sort). |
| `s19_app/tui/app.py::_scan_spec_files` | #15 | **New**: as #14 over `_spec_homes()` (#32). |
| `s19_app/tui/app.py::_resolve_listed_file` | #16 | **New**: one pick guard — home by prefix (empty prefix only when sole home), plain name, reparse walk `stop_at=self.workarea.parent` + `_is_reparse_point(self.workarea.parent)`, resolved-inside-resolved-workarea; returns the **unresolved** `folder / name` (S-4). |
| `s19_app/tui/app.py::on_patch_editor_panel_change_file_selected` | #17 | Guard through #16 over #12; the unsaved-changes popup `_answer` re-runs #16 on accept and on `None` paints the refusal and loads nothing (S-5). |
| `s19_app/tui/app.py::on_check_editor_panel_spec_file_selected` | #18 | Guard through #16 over #32; `load_spec(items, candidate.name)` so Write-as takes the bare name (R-CHKED-042); loaded status keeps the listed value. |
| `s19_app/tui/app.py::on_ab_diff_panel_check_file_selected` | #19 | Guard through #16 over #32; refusal unchanged. |
| `s19_app/tui/app.py::_prefill_check_editor` | #20 | Spec list from `_scan_spec_files()` (was `_scan_patch_change_files()`); A2L picker half unchanged. |
| `s19_app/tui/app.py::_prefill_diff_check_files` | #21 | List from `_scan_spec_files()`. |
| `s19_app/tui/app.py::_compose_screen_diff` | #22 | `AbDiffPanel(check_files=self._scan_spec_files())`. |
| `s19_app/tui/app.py::on_check_editor_panel_action_requested` | #23 | Write passes `dest_dir=self._check_home()`. |
| `s19_app/tui/app.py::_patch_editor_load` | #31 | `_hide_replaced_document_controls(panel)` first (every load replaces the document, also a failed read), then the read and tail as before. |
| `s19_app/tui/app.py::_spec_homes` | #32 | **New** (revised D-3, I-6): `[("", workarea/patches)]` or `[("checks/", _check_home()), ("library/", workarea/patches)]`. |
| `s19_app/tui/app.py::_note_image_bytes_written` | #33 | Three statements prepended: `end_check_run()` (I-7); query the Patch Editor panel and when mounted `_patch_editor_load_tail(panel)`; `update_checks_view()` — then Inc 5's body unchanged. |
| `s19_app/tui/app.py::_refill_document_lists` | #35 | **New** (E3A-04): `_prefill_patch_change_files()`; Check Editor `set_spec_files(_scan_spec_files())` when mounted (Spec half only); `_prefill_diff_check_files()`. |
| `s19_app/tui/app.py::_install_prepared_project` | #36 | `_refill_document_lists()` right after `current_project_dir = request.project_dir`. |
| `s19_app/tui/app.py::_on_project_saved` | #37 | `_refill_document_lists()` right after `current_project_dir = prepared.project_dir` (every committed Save project). |

## 2. Writer / site census (verified)

- `refresh_check_results` call sites in `app.py`: **3** — the run arm (unchanged),
  #8 (`_refresh_patch_checks_tab`), and the Check Editor validate arm. The two
  non-validate sites pass the live `check_aggregates()`.
- `refresh_entries` call sites in `app.py`: **5** — action handler,
  `_refresh_patch_history_view`, `_patch_editor_load_tail`, `_reset_project_session`,
  `_apply_prepared_load`. No new site added (#33 repaints through #6).

## 3. Deviations

- **`_resolve_listed_file` name separators.** The graph says "holds a separator";
  the guard rejects both `/` and `\`, so a listed name can never smuggle a
  Windows directory separator past the `folder / name` join on a Windows
  work area. No case is changed on POSIX (a backslash in a listed name is
  already outside every example and the closed list is re-measured at
  integration).
- **`_resolve_listed_file` resolve failure.** `path.resolve()` /
  `workarea.resolve()` are wrapped in `try/except OSError → return None`, so an
  unresolvable spelling is a refusal (the Write guard's SEC-2 shape) rather
  than a bare `OSError` past the pick handlers. Defensive only; no listed value
  reaches a raise.
- **Offer gate reuses the already-read `project_dir`.** The graph says "read
  once after the save"; the save-back handler already read
  `project_dir = self._active_project_dir()` for the manifest rewrite, so the
  offer gates on that same value instead of a second read.

No other deviation. No UI layout change beyond the admitted hides/refills. The
`app.py` edits stayed local to the named functions and their new private
helpers; no test file, `REQUIREMENTS.md`, `AT-TC-REGISTRY.jsonl` or
`tests/test_id_registry.py` was touched.

## 4. py_compile

`python -m py_compile s19_app/tui/app.py` → OK (no output, exit 0). The
operator rule (no `pytest`, no `import s19_app`) was respected.

## 5. Line endings

`s19_app/tui/app.py` remains pure CRLF (0 bare LF), verified byte-count after
the edits.
