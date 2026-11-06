# Code-Wire graph — Inc 6 (Patch Editor document lifecycle), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `9bb0e3a`, designed against main plus Inc 5 (`b101-inc5`). Requirements `../01-requirements.md`, slice `../E1-slice.md` (node numbers `#n`), rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1, as in `../../inc-2/codewire/graph-inc2.md`.

How to read it: every node's `func:` starts with **unchanged**, **changed** ("was: … / now: …", the baseline first) or **new**. Example sources are case ids (`R-TUI-049.3.2/6`) or `P` = the E1 pilot on `9bb0e3a` (`../evidence-e1/i6e1-pilot-transcript.txt`). Values: `01-requirements.md` Definitions (fixture image, C, C2, K, E, `proj`).

## Groups and pinned interfaces

| Group | File | Owns nodes |
|---|---|---|
| G1 app | `s19_app/tui/app.py` | #1 … #23 |
| G2 service | `s19_app/tui/services/change_service.py` | #24 … #29 |
| G3 panel | `s19_app/tui/screens_directionb.py` | #30 |

| Interface | Pinned form | Producer → consumer |
|---|---|---|
| I-1 current run | `ChangeService.check_run_is_current(self) -> bool`: `last_check_result is not None and _last_check_stamp == (_document_signature(), image_generation)` | G2 → G1 |
| I-2 status line | `ChangeService.check_status_line(self) -> str`: the message `run_checks` returned while I-1, else `""` | G2 → G1 |
| I-3 aggregates | `ChangeService.check_aggregates(self) -> dict[str, int]`: signature unchanged; the last run's counts while I-1, else every key 0 | G2 → G1 |
| I-4 Checks-tab render | `PatchEditorPanel.refresh_check_results(rows, status_line, aggregates=None)`: signature unchanged; an empty `status_line` means "no run shown" (status `CHECKS_NO_RUN_TEXT`, subtitle `no run yet`); otherwise subtitle `<len(rows)> checked` | G3 → G1 |
| I-5 change-list value | without a project the bare file name; with one `patches/<name>` or `checks/<name>`; option label = value (through `safe_text`); `ChangeFileSelected.filename` carries the value | G1 internal, G3 renders |
| I-6 homes | `_change_homes() -> list[tuple[str, Path]]` = `[("", workarea/patches)]` or `[("checks/", P/checks), ("patches/", P/patches)]`; `_check_home() -> Path` = `scoped_home_target(P, PROJECT_CHECKS_DIR, workarea/patches)` (`workarea/patches` without a project) | G1 internal |

Writer census kept: app.py holds exactly three `refresh_check_results` calls — the run arm (unchanged), #8 (replaces the history site), the Check Editor validate arm — each non-validate one passing the live `check_aggregates()` (`test_tc078_3_both_sites`).

Interfaces with other increments:

| With | Shared | Rule |
|---|---|---|
| Inc 5 (merges first) | `on_patch_editor_panel_action_requested` (Inc 5: `if event.action == "apply_doc": self._note_image_bytes_written()` after the `try`), `on_patch_editor_panel_save_back_decision` (Inc 5: `_note_image_bytes_written()` after `save_patched`), `on_check_editor_panel_spec_file_selected` (Inc 5: items `{address, size, expected, symbol}`, its I-3) | Inc 6 edits other lines of each (parse_paste arm + last line; the final `notify`; the guard at the top); keeps Inc 5's calls ungated and its item shape; rebase before E4 |
| Inc 15 (merged) | tests wait on `document.source_path` and on `#patch_saveback_row`'s `hidden` class | not moved: loads still set the source in the same handler; the prompt is hidden only on a replacement (new) and on its buttons (unchanged) |
| Inc 4 (merged) | `read_change_document(…, a2l_context=self.current_a2l_data)` in the three pick handlers | kept verbatim after the new guard |
| Inc 12 (later) | `CheckEditorPanel.on_button_pressed`, unreachable widgets | disjoint |

## Nodes — G1 app

S19TuiApp.on_patch_editor_panel_save_back_decision
req: R-BEFORE-AFTER-REPORT-001.1, R-BEFORE-AFTER-REPORT-001.36
in: PatchEditorPanel.SaveBackDecision
out: None
func: changed. was: on `result.ok`, after `_surface_verify_result()` and `show_before_after_prompt()`, always `notify("Before/after report ready - press b to write it to the project reports directory (action: before_after_report).", title="Before/after report", severity="information")`. / now: the same, but the `notify` runs only when `self._active_project_dir()` is not `None` (read once after the save, the value the manifest rewrite above uses), with the text `Before/after report ready - press b to write it to the project reports directory.`; `show_before_after_prompt()` stays unconditional (R-TUI-049.1, D-2). Inc 5's `_note_image_bytes_written()` after `save_patched` is untouched.
module: s19_app/tui/app.py
calls: ChangeService.save_patched, S19TuiApp._active_project_dir, App.notify, PatchEditorPanel.show_before_after_prompt
examples: (R-BEFORE-AFTER-REPORT-001.1/1) proj open, C applied, Write file → 1 notification, message exactly `Before/after report ready - press b to write it to the project reports directory.` (base P: `… directory (action: before_after_report).`)
examples: (R-BEFORE-AFTER-REPORT-001.36/1) no project → 0 notifications titled `Before/after report`; control shown (base P: 1 offer)

S19TuiApp.on_patch_editor_panel_action_requested
req: R-TUI-049.3.2, R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012
in: PatchEditorPanel.ActionRequested
out: None
func: changed. was: `parse_paste` arm calls `panel.hide_before_after_prompt()` then `load_text`; the handler ends with the enable-guard syncs. / now: the `parse_paste` arm calls `self._hide_replaced_document_controls(panel)` (#9) in place of the single hide (same place, before `load_text`); the handler's last statement is `self._refresh_patch_checks_tab(panel)` (#8), after `set_entry_edit_json_enabled`, so every action (Add, Edit, Remove, Load, paste, Validate, Apply, Save, Refresh, Run checks, Execute) ends with the Checks tab showing the current run or none. The `load_doc` arm keeps its own hide (the tail #6 repeats it; harmless). Inc 5's `apply_doc` hook after the `try` is untouched.
module: s19_app/tui/app.py
calls: S19TuiApp._hide_replaced_document_controls, S19TuiApp._refresh_patch_checks_tab, ChangeService.load_text
examples: (R-TUI-049.3.2/5) C applied (prompt shown), C2 pasted, Parse pasted → `#patch_saveback_row` hidden
examples: (R-CHK-PE-009/4) K run (`2 checked`), Add `0x8007` = `CC` → subtitle `no run yet`, 0 rows

S19TuiApp.action_patch_undo
req: R-TUI-049.3.1, R-TUI-049.3.2
in: —
out: None
func: changed. was: refuse if busy / not allowed; `undo()`; `_refresh_patch_history_view()`. / now: keeps `before = service.document` before `undo()`; after it, when `service.document is not before` (a step moved, R-TUI-057.6), `_hide_replaced_document_controls(panel)` (#9); then `_refresh_patch_history_view()`.
module: s19_app/tui/app.py
calls: ChangeService.undo, S19TuiApp._hide_replaced_document_controls, S19TuiApp._refresh_patch_history_view
examples: (R-TUI-049.3.2/6) C2 pasted, Add, Apply (prompt shown), `ctrl+z` → prompt hidden (base P: shown)
examples: (R-TUI-049.3.2/7 negative arm) empty history, `ctrl+z` → prompt stays shown

S19TuiApp.action_patch_redo
req: R-TUI-049.3.1, R-TUI-049.3.2
in: —
out: None
func: changed. was/now: as `action_patch_undo`, for `redo()`.
module: s19_app/tui/app.py
calls: ChangeService.redo, S19TuiApp._hide_replaced_document_controls, S19TuiApp._refresh_patch_history_view
examples: (R-TUI-049.3.1/7) control shown after a Write file, `ctrl+y` with a redo step → `#patch_before_after_row` hidden

S19TuiApp._refresh_patch_history_view
req: R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012
in: —
out: None
func: changed. was: `panel.refresh_check_results(service.check_rows(), "", service.check_aggregates())`. / now: `self._refresh_patch_checks_tab(panel)` in its place (same render after undo/redo, whose reset leaves no current run; a per-entry JSON edit, which also ends here, now clears too). `update_checks_view()` stays.
module: s19_app/tui/app.py
calls: S19TuiApp._refresh_patch_checks_tab, S19TuiApp.update_checks_view
examples: (AT-078c, unchanged) post-undo strip `✓0 ✗0 ◐0`, `░░░░░░░░`

S19TuiApp._patch_editor_load_tail
req: R-TUI-049.3.1, R-TUI-049.3.2, R-CHK-PE-008, R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012
in: PatchEditorPanel
out: None
func: changed. was: refresh entries, bindings, issues, the three enable guards. / now: first `_hide_replaced_document_controls(panel)`, then the same, then `_refresh_patch_checks_tab(panel)`. Every load path runs this tail (Load, dropdown pick, guarded accept), and every load replaces the document, also a failed read.
module: s19_app/tui/app.py
calls: S19TuiApp._hide_replaced_document_controls, S19TuiApp._refresh_patch_checks_tab
examples: (R-TUI-049.3.1/2) control shown, pick `c2.json` → hidden (base P: shown)
examples: (R-CHK-PE-012/1) K run (2 rows), Load C → 0 rows, status `No check run yet: press Run checks.` (base P: 2 rows, `Checks: 1 passed, 1 failed, 0 uncheckable`)

S19TuiApp._reset_project_session
req: R-TUI-049.3.1, R-TUI-049.3.2, R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012
in: —
out: None
func: changed. was: rebinds `ChangeService()`, repaints entries, clears the paste buffer, `mark_loaded()`, `refresh_bindings()` (inside the `else` of the panel query). / now: in the same `else`, after `refresh_bindings()`: `_hide_replaced_document_controls(panel)` and `_refresh_patch_checks_tab(panel)` (the new service has no run).
module: s19_app/tui/app.py
calls: S19TuiApp._hide_replaced_document_controls, S19TuiApp._refresh_patch_checks_tab
examples: (R-CHK-PE-010/2) K run on image 2, load project `proj` → status `No check run yet: press Run checks.`, subtitle `no run yet` (base P: `Checks: 0 passed, 2 failed, 0 uncheckable`, `2 checked`, while `last_check_result` is None)
examples: (R-TUI-049.3.2/4) prompt shown, load `proj` → hidden

S19TuiApp._refresh_patch_checks_tab
req: R-CHK-PE-008, R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012
in: PatchEditorPanel
out: None
func: new. `current = service.check_run_is_current()` (I-1); `panel.refresh_check_results(service.check_rows() if current else [], service.check_status_line(), service.check_aggregates())` (I-2, I-3, I-4). Pure render: reads the service, writes only the Checks tab. The third positional argument is the live accessor (census).
module: s19_app/tui/app.py
calls: ChangeService.check_run_is_current, ChangeService.check_rows, ChangeService.check_status_line, ChangeService.check_aggregates, PatchEditorPanel.refresh_check_results
examples: (R-CHK-PE-008/3) K run, Add `0x8007` → `[]`, `""`, zeros → `no run yet`; Remove `0x8007` → 2 rows, `Checks: 1 passed, 1 failed, 0 uncheckable`, `✓1 ✗1 ◐0` → `2 checked`
examples: (R-CHK-PE-011/1) after Load C → strip `✓0 ✗0 ◐0` / `░░░░░░░░`

S19TuiApp._hide_replaced_document_controls
req: R-TUI-049.3.1, R-TUI-049.3.2
in: PatchEditorPanel
out: None
func: new. `panel.hide_before_after_prompt()`; `panel.hide_save_prompt()`. Writes nothing to disk and moves no focus.
module: s19_app/tui/app.py
calls: PatchEditorPanel.hide_before_after_prompt, PatchEditorPanel.hide_save_prompt
examples: (R-TUI-049.3.1/1) both rows shown → both carry `hidden`

S19TuiApp._apply_prepared_load
req: R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012
in: PreparedLoad, Path, float
out: None
func: changed. was: bumps `_image_generation`, pushes it, repaints entries (site 4) and bindings. / now: the same, then `_refresh_patch_checks_tab(panel)` in the same `else`. Nothing else in the install changes.
module: s19_app/tui/app.py
calls: ChangeService.set_image_generation, S19TuiApp._refresh_patch_checks_tab
examples: (R-CHK-PE-009/2) K run on the fixture image, load image 2 → `no run yet`, 0 rows (base P: `2 checked`, 2 rows)

S19TuiApp.update_checks_view
req: R-CHKS-001, R-CHKS-004, R-CHKS-009
in: —
out: None
func: changed. was: `if last_check_result is None: render_no_run()` else group `check_display_rows()`; strip from `check_aggregates()`. / now: `if not service.check_run_is_current(): render_no_run()`; else as before; the strip reads I-3 (zeros when not current).
module: s19_app/tui/app.py
calls: ChangeService.check_run_is_current, ChangeService.check_display_rows, ChangeService.check_aggregates, GroupedChecksPanel.render_no_run, GroupedChecksPanel.render_groups
examples: (R-CHKS-001/2) K run, Load C, open the Checks screen → note `No check run yet — run checks from the Patch Editor.`, no group header (base P: `✗ FAILED  (1)` …)
examples: (R-CHKS-001/1) K run → `✗ FAILED  (1)`, `0x8001-0x8001 expected [FF] actual [01] -> fail`, `✓ PASSED  (1)`, `0x8000-0x8000 expected [00] actual [00] -> pass`

S19TuiApp._change_homes
req: R-PATCH-DOC-DROPDOWN-001.1
in: —
out: list[tuple[str, Path]]
func: new. No project → `[("", self.workarea / WORKAREA_PATCHES)]`. Project `P` → `[("checks/", P / PROJECT_CHECKS_DIR), ("patches/", P / PROJECT_PATCHES_DIR)]` (path arithmetic, nothing created).
module: s19_app/tui/app.py
calls: S19TuiApp._active_project_dir
examples: (R-PATCH-DOC-DROPDOWN-001.1/1) proj open → `[("checks/", …/proj/checks), ("patches/", …/proj/patches)]`

S19TuiApp._check_home
req: R-CHKED-031, R-CHKED-040, R-DIFF-CHK.1
in: —
out: Path
func: new. `scoped_home_target(self._active_project_dir(), PROJECT_CHECKS_DIR, self.workarea / WORKAREA_PATCHES)`; creates nothing (Write's placement creates and contains the folder).
module: s19_app/tui/app.py
calls: scoped_home_target, S19TuiApp._active_project_dir
examples: (R-CHKED-031/1) proj open → `…/workarea/proj/checks`; (R-CHKED-031/2) no project → `…/workarea/patches`

S19TuiApp._scan_patch_change_files
req: R-PATCH-DOC-DROPDOWN-001.1
in: —
out: List[str]
func: changed. was: `[name for name, _ in list_change_documents(self._patches_dir())]`. / now: for each `(prefix, folder)` of `_change_homes()`: `prefix + name` for every name of `list_change_documents(folder)`; the joined list sorted. Callers now: `_prefill_patch_change_files` only (#20–#22 move to #15).
module: s19_app/tui/app.py
calls: S19TuiApp._change_homes, list_change_documents
examples: (R-PATCH-DOC-DROPDOWN-001.1/2) proj open, Save → `["patches/changes.json"]` (base P: `[]`)
examples: (R-PATCH-DOC-DROPDOWN-001.1/4) no project, `a.json`, `b.json` → `["a.json", "b.json"]`

S19TuiApp._scan_check_home_files
req: R-CHKED-040, R-DIFF-CHK.1
in: —
out: List[str]
func: new. `[name for name, _ in list_change_documents(self._check_home())]` (sorted, links skipped by the helper).
module: s19_app/tui/app.py
calls: S19TuiApp._check_home, list_change_documents
examples: (R-CHKED-040/1) proj open, `proj/checks/k.chk.json`, `workarea/patches/w.chk.json` → `["k.chk.json"]`

S19TuiApp._resolve_listed_file
req: R-PATCH-DOC-DROPDOWN-001.3, R-PATCH-DOC-DROPDOWN-001.4, R-CHKED-044, R-DIFF-CHK.5
in: value: str, homes: list[tuple[str, Path]]
out: Optional[Path]
func: new. Picks the home whose prefix starts `value` (`""` matches only when it is the sole home); `name = value[len(prefix):]`; `None` when no home matches, `name` is empty or holds a separator or `..`, `folder / name` is a link, its resolved path is not inside `folder.resolve()`, or — with a project open — not inside the resolved project folder (D-6). Otherwise the resolved path.
module: s19_app/tui/app.py
calls: S19TuiApp._active_project_dir, Path.resolve, Path.is_symlink
examples: (R-PATCH-DOC-DROPDOWN-001.3/1) `"checks/k.chk.json"`, proj homes → `…/proj/checks/k.chk.json`
examples: (R-PATCH-DOC-DROPDOWN-001.4/2) `proj/patches` linked to an outside folder, `"patches/x.json"` → `None`
examples: (R-PATCH-DOC-DROPDOWN-001.4/3) proj open, `"w.json"` → `None`; `"patches/../../w.json"` → `None`

S19TuiApp.on_patch_editor_panel_change_file_selected
req: R-PATCH-DOC-DROPDOWN-001.3, R-PATCH-DOC-DROPDOWN-001.4
in: PatchEditorPanel.ChangeFileSelected
out: None
func: changed. was: `candidate = (self._patches_dir() / filename).resolve()`; refuse a link or a path outside `_patches_dir().resolve()`. / now: `candidate = self._resolve_listed_file(filename, self._change_homes())`; `None` → the same status `Patch Editor: change file {filename!r} is outside the patches folder — not loaded.`; the dirty guard and `_patch_editor_load(panel, str(candidate))` unchanged.
module: s19_app/tui/app.py
calls: S19TuiApp._resolve_listed_file, S19TuiApp._change_homes, S19TuiApp._patch_editor_load, LoadGuardScreen
examples: (R-PATCH-DOC-DROPDOWN-001.4/1) `"patches/l.json"` a link → status `Patch Editor: change file 'patches/l.json' is outside the patches folder — not loaded.`, document unchanged

S19TuiApp.on_check_editor_panel_spec_file_selected
req: R-CHKED-044
in: CheckEditorPanel.SpecFileSelected
out: None
func: changed (top lines only). was: guard against `_patches_dir()`. / now: `candidate = self._resolve_listed_file(filename, [("", self._check_home())])`; `None` → the same status `Check Editor: file {filename!r} is outside the patches folder — not loaded.`; the read (with the loaded A2L) and Inc 5's item dicts unchanged.
module: s19_app/tui/app.py
calls: S19TuiApp._resolve_listed_file, S19TuiApp._check_home, read_change_document, CheckEditorPanel.load_spec
examples: (R-CHKED-044/2) `proj/checks` linked, `"x.chk.json"` → status `Check Editor: file 'x.chk.json' is outside the patches folder — not loaded.`

S19TuiApp.on_ab_diff_panel_check_file_selected
req: R-DIFF-CHK.5
in: AbDiffPanel.CheckFileSelected
out: None
func: changed. was: guard against `_patches_dir()`. / now: guard through `_resolve_listed_file(name, [("", self._check_home())])`, same refusal status; the rest unchanged.
module: s19_app/tui/app.py
calls: S19TuiApp._resolve_listed_file, S19TuiApp._check_home
examples: (R-DIFF-CHK.5/1) `"l.chk.json"` a link in `proj/checks` → `#diff_status` `Check spec: 'l.chk.json' is outside the patches folder — not loaded.`

S19TuiApp._prefill_check_editor
req: R-CHKED-040
in: —
out: None
func: changed. was: `panel.set_spec_files(self._scan_patch_change_files())`. / now: `panel.set_spec_files(self._scan_check_home_files())`; the A2L picker half unchanged.
module: s19_app/tui/app.py
calls: S19TuiApp._scan_check_home_files, CheckEditorPanel.set_spec_files
examples: (R-CHKED-040/2) after Write `s1.chk.json` in proj → `["k.chk.json", "s1.chk.json"]`

S19TuiApp._prefill_diff_check_files
req: R-DIFF-CHK.1
in: —
out: None
func: changed. was: `panel.set_check_files(self._scan_patch_change_files())`. / now: `…(self._scan_check_home_files())`.
module: s19_app/tui/app.py
calls: S19TuiApp._scan_check_home_files, AbDiffPanel.set_check_files
examples: (R-DIFF-CHK.1/1) proj open → `["k.chk.json"]` (base P: the common `s1.chk.json`)

S19TuiApp._compose_screen_diff
req: R-DIFF-CHK.1
in: —
out: Container
func: changed. was: `AbDiffPanel(check_files=self._scan_patch_change_files())`. / now: `AbDiffPanel(check_files=self._scan_check_home_files())`.
module: s19_app/tui/app.py
calls: S19TuiApp._scan_check_home_files
examples: (R-DIFF-CHK.1/2) no project at compose → `workarea/patches` names, as on base

S19TuiApp.on_check_editor_panel_action_requested
req: R-CHKED-031, R-CHKED-034
in: CheckEditorPanel.ActionRequested
out: None
func: changed (write arm only). was: `write_change_document(document, self.base_dir, file_name)`. / now: `write_change_document(document, self.base_dir, file_name, dest_dir=self._check_home())`; a placement refusal returns `MF-WRITE-CONTAINMENT` and takes the existing refusal branch (R-CHKED-034, -035). The listings refresh after a write is unchanged.
module: s19_app/tui/app.py
calls: write_change_document, S19TuiApp._check_home, S19TuiApp._prefill_check_editor, S19TuiApp._prefill_patch_change_files, S19TuiApp._prefill_diff_check_files
examples: (R-CHKED-031/1) proj open, Write as `s1.chk.json` → `proj/checks/s1.chk.json`; status `Check Editor: wrote s1.chk.json (0 fields, kind=check).` (base P: `workarea/patches/s1.chk.json`)
examples: (R-CHKED-034/1) `proj/checks` linked → status `Check Editor: spec NOT written.`, Fields `Write refused: MF-WRITE-CONTAINMENT.`, no file through the link

## Nodes — G2 service

ChangeService.__init__
req: R-CHK-PE-010
in: —
out: None
func: changed. adds `self._last_check_message: str = ""` beside `_last_check_stamp`.
module: s19_app/tui/services/change_service.py
calls: —
examples: fresh service → `check_status_line() == ""`

ChangeService.run_checks
req: R-CHK-PE-008
in: mem_map, ranges, mac_records, a2l_tags
out: ChangeActionResult
func: changed. was: stores the result and the stamp; returns the count or blocked line. / now: also `self._last_check_message = <that message>` before returning (both branches).
module: s19_app/tui/services/change_service.py
calls: check_runner, ChangeService._document_signature
examples: (R-CHK-PE-008/1) K on the fixture image → message `Checks: 1 passed, 1 failed, 0 uncheckable`, stored

ChangeService.check_run_is_current
req: R-CHK-PE-008, R-CHK-PE-009, R-CHKS-001
in: —
out: bool
func: new (I-1). `self.last_check_result is not None and self._last_check_stamp == (self._document_signature(), self.image_generation)`.
module: s19_app/tui/services/change_service.py
calls: ChangeService._document_signature
examples: (R-CHK-PE-009/2) after the run `True`; `set_image_generation(n + 1)` → `False`; back to `n` → `True` (as `test_tc077_2_provenance`)

ChangeService.check_status_line
req: R-CHK-PE-010
in: —
out: str
func: new (I-2). `self._last_check_message if self.check_run_is_current() else ""`.
module: s19_app/tui/services/change_service.py
calls: ChangeService.check_run_is_current
examples: (R-CHK-PE-010/1) K run then Load C → `""`

ChangeService.check_aggregates
req: R-CHK-PE-011, R-CHKS-009
in: —
out: dict[str, int]
func: changed (I-3). was: zeros only when `last_check_result is None`. / now: zeros whenever `not self.check_run_is_current()`; else the result's counts as before.
module: s19_app/tui/services/change_service.py
calls: ChangeService.check_run_is_current
examples: (R-CHK-PE-011/1) K run → `{passed: 1, failed: 1, uncheckable: 0}`; Load C → all 0 (base P: `✓1 ✗1`)

ChangeService._check_glyphs
req: R-CHK-PE-013
in: —
out: list[str]
func: changed (no behaviour change). was: its own stamp comparison. / now: `if not self.check_run_is_current(): return []`, then the same mapping.
module: s19_app/tui/services/change_service.py
calls: ChangeService.check_run_is_current
examples: (TC-077.2, unchanged) generation 7 → `✓`; 8 → `·`; 7 → `✓`

## Nodes — G3 panel

PatchEditorPanel.refresh_check_results
req: R-CHK-PE-008, R-CHK-PE-009
in: rows, status_line, aggregates
out: None
func: changed (I-4). was: subtitle `f"{len(rows)} checked" if rows else "no run yet"`. / now: `f"{len(rows)} checked" if status_line else "no run yet"`; the status, strip and rows render as before (the status falls back to `CHECKS_NO_RUN_TEXT` on an empty line, as today). The subtitle text stays author-composed (C-17).
module: s19_app/tui/screens_directionb.py
calls: PatchEditorPanel._set_window_subtitle, PatchEditorPanel._check_strip_text
examples: (R-CHK-PE-008/2) E run → rows `[]`, status `Checks: 0 passed, 0 failed, 0 uncheckable` → subtitle `0 checked` (base P: `no run yet`)
examples: (R-CHK-PE-009/1) `[]`, `""` → `no run yet`, status `No check run yet: press Run checks.`

## Rows → example index

R-BEFORE-AFTER-REPORT-001.1, .36 → save_back_decision; .11 → unchanged (`test_r_before_after_report_001_11_*`). R-TUI-049.3.1, .3.2 → #9 and its five callers. R-PATCH-DOC-DROPDOWN-001.1 → `_scan_patch_change_files`; .3, .4 → `_resolve_listed_file`, change_file_selected. R-CHKED-031, -034 → Check Editor write arm; -040 → `_prefill_check_editor`; -044 → spec_file_selected. R-DIFF-CHK.1, .5 → the A2B nodes. R-CHK-PE-008 … 012 → #8, #30, G2. R-CHKS-001, -004, -009 → `update_checks_view` (R-CHKS-004/1: image 2 loaded after a K run → note `No check run yet — run checks from the Patch Editor.`).
