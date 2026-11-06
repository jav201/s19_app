# Code-Wire graph — Inc 6 (Patch Editor document lifecycle), batch-101

Stage E2 of the design-first flow (`dev-flow-v3-beta`). Graph only: no stub, mark or declaration in any tree. Base `9bb0e3a`, designed against main plus Inc 5 (`b101-inc5`). Requirements `../01-requirements.md`, slice `../E1-slice.md` (node numbers `#n`), rulings `../E1-rulings.md`, cases `../02-test-cases.md`. Notation: Code-Wire v3.1, as in `../../inc-2/codewire/graph-inc2.md`. E3 round-1 corrections (`../E3-rulings.md`) are folded in as targeted edits: nodes #31 … #37 are new, and changed nodes cite the finding (E3A-nn, S-n).

How to read it: every node's `func:` starts with **unchanged**, **changed** ("was: … / now: …", the baseline first) or **new**. Example sources are case ids (`R-TUI-049.3.2/6`) or `P` = the E1 pilot on `9bb0e3a` (`../evidence-e1/i6e1-pilot-transcript.txt`). Values: `01-requirements.md` Definitions (fixture image, C, C2, K, E, `proj`).

## Groups and pinned interfaces

| Group | File | Owns nodes |
|---|---|---|
| G1 app | `s19_app/tui/app.py` | #1 … #23, #31, #32, #33, #35, #36, #37 |
| G2 service | `s19_app/tui/services/change_service.py` | #24 … #29, #34 |
| G3 panel | `s19_app/tui/screens_directionb.py` | #30 |
| G4 help text | `s19_app/tui/window_help.py` | no function node: the `WINDOW_HELP_SECTIONS` lines `:113-116` and `:530` say what the lists hold with a project (E3A-09, text only) |

| Interface | Pinned form | Producer → consumer |
|---|---|---|
| I-1 current run | `ChangeService.check_run_is_current(self) -> bool`: `last_check_result is not None and _last_check_stamp == (_document_signature(), image_generation)` | G2 → G1 |
| I-2 status line | `ChangeService.check_status_line(self) -> str`: the message `run_checks` returned while I-1, else `""` | G2 → G1 |
| I-3 aggregates | `ChangeService.check_aggregates(self) -> dict[str, int]`: signature unchanged; the last run's counts while I-1, else every key 0 | G2 → G1 |
| I-4 Checks-tab render | `PatchEditorPanel.refresh_check_results(rows, status_line, aggregates=None)`: signature unchanged; an empty `status_line` means "no run shown" (status `CHECKS_NO_RUN_TEXT`, subtitle `no run yet`); otherwise subtitle `<len(rows)> checked` | G3 → G1 |
| I-5 list value | without a project the bare file name; with one `checks/<name>`, `patches/<name>` (Patch Editor only) or `library/<name>` (revised D-3); option label = value (through `safe_text`, plus the ` CHECK` / ` PATCH` suffix in the two spec lists); `ChangeFileSelected.filename`, `SpecFileSelected.filename` and the A2B pick carry the value | G1 internal, G3 renders |
| I-6 homes | `_change_homes() -> list[tuple[str, Path]]` = `[("", workarea/patches)]` or `[("checks/", P/checks), ("patches/", P/patches), ("library/", workarea/patches)]`; `_spec_homes() -> list[tuple[str, Path]]` = `[("", workarea/patches)]` or `[("checks/", P/checks), ("library/", workarea/patches)]`; the order of the list is the order of the listing (project entries, then library); `_check_home() -> Path` = `scoped_home_target(P, PROJECT_CHECKS_DIR, workarea/patches)` (`workarea/patches` without a project), the Write destination only | G1 internal |
| I-7 run end | `ChangeService.end_check_run(self) -> None`: `last_check_result = None`, `_last_check_message = ""`; afterwards I-1 is `False` until the next `run_checks` | G2 → G1 (#33) |
| I-8 in-place-write seam | `S19TuiApp._note_image_bytes_written(self) -> None` (Inc 5): every consequence of an in-place write of the loaded image's bytes (apply, save-back, Save project commit) hangs here; Inc 6 prepends I-7 and the two Checks renders | G1 internal (Inc 5 → Inc 6) |

Writer census kept: app.py holds exactly three `refresh_check_results` calls — the run arm (unchanged), #8 (replaces the history site), the Check Editor validate arm — each non-validate one passing the live `check_aggregates()` (`test_tc078_3_both_sites`). The `refresh_entries` sites stay five (`test_tui_patch_card.py` census): #33 repaints through #6, not through a new site.

Interfaces with other increments:

| With | Shared | Rule |
|---|---|---|
| Inc 5 (merges first) | `on_patch_editor_panel_action_requested` (Inc 5: `if event.action == "apply_doc": self._note_image_bytes_written()` after the `try`), `on_patch_editor_panel_save_back_decision` (Inc 5: `_note_image_bytes_written()` after `save_patched`), `on_check_editor_panel_spec_file_selected` (Inc 5: items `{address, size, expected, symbol}`, its I-3), `on_check_editor_panel_action_requested` (Inc 5: docstring), `_on_project_saved` (Inc 5: the hook inside the image `if`), `_note_image_bytes_written` (Inc 5: new) | Inc 6 edits other lines of each (the add / edit / remove / parse_paste arms; the final `notify`; the guard at the top and the `load_spec` argument right after Inc 5's dicts; the Write call; #35 after `current_project_dir`; three statements before the hook's body); keeps Inc 5's calls ungated and its item shape; rebase before E4 and re-check the six ranges (E3A-12) |
| Inc 15 (merged) | tests wait on `document.source_path` and on `#patch_saveback_row`'s `hidden` class | not moved: loads still set the source in the same handler (now the unresolved listed path, S-4 — Inc 15's picks run without a project, where it equals the base spelling); the prompt is hidden only on a replacement or an image load (new) and on its buttons (unchanged); Save project leaves it (E3A-01) |
| Inc 9 (later, D15-18) | `workspace._path_traverses_reparse_point`, `_is_reparse_point` | #16 uses them as they are, with the Write guard's stop point (`self.workarea.parent`); a change Inc 9 makes there applies to picks and Writes alike (S-3) |
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
func: changed. was: `parse_paste` arm calls `panel.hide_before_after_prompt()` then `load_text`; the handler ends with the enable-guard syncs. / now: the `parse_paste` arm calls `self._hide_replaced_document_controls(panel)` (#9) in place of the single hide (same place, before `load_text`) and ends with `self._refresh_patch_checks_tab(panel)` (#8); the `add_entry`, `edit_entry` and `remove_entry` arms end with #8 after their service call (a raise skips it: nothing changed). No other arm renders the Checks tab (E3A-13: a current run is not re-mounted on Validate, Save, Refresh or Execute): `load_doc` renders through #31 → #6, `apply_doc` through Inc 5's hook #33, `run_checks` through its own render. The `load_doc` arm keeps its own hide (#31 repeats it; harmless). Inc 5's `apply_doc` hook after the `try` is untouched.
module: s19_app/tui/app.py
calls: S19TuiApp._hide_replaced_document_controls, S19TuiApp._refresh_patch_checks_tab, ChangeService.load_text, S19TuiApp._note_image_bytes_written
examples: (R-TUI-049.3.2/5) C applied (prompt shown), C2 pasted, Parse pasted → `Save patched image as:` not painted
examples: (R-CHK-PE-009/4) K run (`2 checked`), Add `0x8007` = `CC` → subtitle `no run yet`, 0 rows
examples: (E3A-13) K run (`2 checked`, 2 rows), Validate → the 2 result rows are the same widgets (no re-mount); status from `validate`

S19TuiApp.action_patch_undo
req: R-TUI-049.3.1, R-TUI-049.3.2
in: —
out: None
func: changed. was: refuse if busy / not allowed; `undo()`; `_refresh_patch_history_view()`. / now: keeps `before = service.document` before `undo()`; after it, when `service.document is not before` (a step moved, R-TUI-057.6), `_hide_replaced_document_controls(panel)` (#9); then `_refresh_patch_history_view()`.
module: s19_app/tui/app.py
calls: ChangeService.undo, S19TuiApp._hide_replaced_document_controls, S19TuiApp._refresh_patch_history_view
examples: (R-TUI-049.3.2/6) C2 pasted, Add, Apply (prompt shown), `ctrl+z` → prompt hidden (base P: shown)

S19TuiApp.action_patch_redo
req: R-TUI-049.3.1, R-TUI-049.3.2
in: —
out: None
func: changed. was/now: as `action_patch_undo`, for `redo()`.
module: s19_app/tui/app.py
calls: ChangeService.redo, S19TuiApp._hide_replaced_document_controls, S19TuiApp._refresh_patch_history_view
examples: (R-TUI-049.3.1/7) control shown after a Write file, `ctrl+y` with a redo step → `Before/after report available:` not painted
examples: (R-TUI-049.3.2/7 negative arm, rebuilt E3A-08b) after the redo, a fresh Apply (prompt painted; the redo stack is empty — an apply pushes no step), `ctrl+y` → `service.document is before` → no hide; then Refresh paints `Patch Editor: file list refreshed.` → `Save patched image as:` still painted

S19TuiApp._refresh_patch_history_view
req: R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012
in: —
out: None
func: changed. was: `panel.refresh_check_results(service.check_rows(), "", service.check_aggregates())`. / now: `self._refresh_patch_checks_tab(panel)` in its place (same render after undo/redo, whose reset leaves no current run; a per-entry JSON edit, which also ends here, now clears too). `update_checks_view()` stays.
module: s19_app/tui/app.py
calls: S19TuiApp._refresh_patch_checks_tab, S19TuiApp.update_checks_view
examples: (AT-078c, unchanged) post-undo strip `✓0 ✗0 ◐0`, `░░░░░░░░`

S19TuiApp._patch_editor_load_tail
req: R-CHK-PE-008, R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012, R-CHK-PE-014
in: PatchEditorPanel
out: None
func: changed. was: refresh entries, bindings, issues, the three enable guards. / now: the same, then `_refresh_patch_checks_tab(panel)`. It hides nothing (E3A-01): its callers are `_patch_editor_load` (#31, which hides), `_reopen_active_document` (project install; #7 hid already), `_on_project_saved` (#37, a pasted document placed — the same object, only `source_path` set, so no replacement) and the in-place-write hook #33 (repaints the ledger glyphs and the Checks tab after the run ended).
module: s19_app/tui/app.py
calls: S19TuiApp._refresh_patch_checks_tab
examples: (R-CHK-PE-012/1) K run (2 rows), Load C → 0 rows, status `No check run yet: press Run checks.` (base P: 2 rows, `Checks: 1 passed, 1 failed, 0 uncheckable`)
examples: (R-TUI-049.3.2/9) proj open, C2 pasted, Apply (prompt painted), Save project → the tail runs (pasted placed) → `Save patched image as:` still painted (E1 design: hidden)

S19TuiApp._reset_project_session
req: R-TUI-049.3.1, R-TUI-049.3.2, R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012
in: —
out: None
func: changed. was: rebinds `ChangeService()`, repaints entries, clears the paste buffer, `mark_loaded()`, `refresh_bindings()` (inside the `else` of the panel query). / now: in the same `else`, after `refresh_bindings()`: `_hide_replaced_document_controls(panel)` and `_refresh_patch_checks_tab(panel)` (the new service has no run); after the panel block, `self.update_checks_view()` (E3A-02: a displayed Checks screen repaints; a guarded no-op when it is not mounted). It does not refill the lists: `current_project_dir` is still the old one here (#36 refills after the assignment).
module: s19_app/tui/app.py
calls: S19TuiApp._hide_replaced_document_controls, S19TuiApp._refresh_patch_checks_tab, S19TuiApp.update_checks_view
examples: (R-CHK-PE-010/2) K run on image 2, load project `proj` → status `No check run yet: press Run checks.`, subtitle `no run yet` (base P: `Checks: 0 passed, 2 failed, 0 uncheckable`, `2 checked`, while `last_check_result` is None)
examples: (R-TUI-049.3.2/4) prompt shown, load `proj` → not painted
examples: (R-CHKS-009/2) Checks screen displayed after a K run (`Pass 1 / Fail 1 / Uncheck 0  ████░░░░`), `p`, load `proj` → `Pass 0 / Fail 0 / Uncheck 0  ░░░░░░░░` without reopening

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
examples: (R-TUI-049.3.1/1) both rows shown → both carry `hidden`; `Before/after report available:` and `Save patched image as:` absent from the painted screen

S19TuiApp._apply_prepared_load
req: R-TUI-049.3.1, R-TUI-049.3.2, R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012, R-CHKS-004
in: PreparedLoad, Path, float
out: None
func: changed. was: bumps `_image_generation`, pushes it, repaints entries (site 4) and bindings. / now: the same; then in the same `else`, when `loaded.mem_map is not previous_map` (a new image dict — the test `mark_saved` already uses above; a MAC attach keeps the dict), `_hide_replaced_document_controls(panel)` (S-1); then `_refresh_patch_checks_tab(panel)`; after the panel block, `self.update_checks_view()` (E3A-02). Every install bumps the generation, a MAC load included, so the run ends on both (CTX *current run*, E3A-03b). Nothing else in the install changes.
module: s19_app/tui/app.py
calls: ChangeService.set_image_generation, S19TuiApp._hide_replaced_document_controls, S19TuiApp._refresh_patch_checks_tab, S19TuiApp.update_checks_view
examples: (R-CHK-PE-009/2) K run on the fixture image, load image 2 → `no run yet`, 0 rows (base P: `2 checked`, 2 rows)
examples: (R-TUI-049.3.2/8) C applied (prompt painted, name `img-patched.s19`), `ctrl+l` image 2 → `previous_map` differs → prompt not painted; nothing written (base, S-1: a confirm writes image 2 + C under `img-patched.s19`)
examples: (R-CHK-PE-009/6) K run, `ctrl+l` `m.mac` → generation n+1 → `no run yet`; the MAC attach keeps `mem_map` → no hide
examples: (R-CHKS-004/2) Checks screen displayed with `✗ FAILED  (1)`, `ctrl+l` image 2 → `No check run yet — run checks from the Patch Editor.` painted without reopening (base: groups stay)

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
req: R-PATCH-DOC-DROPDOWN-001.1, R-PATCH-DOC-DROPDOWN-001.2
in: —
out: list[tuple[str, Path]]
func: new. No project → `[("", self.workarea / WORKAREA_PATCHES)]`. Project `P` → `[("checks/", P / PROJECT_CHECKS_DIR), ("patches/", P / PROJECT_PATCHES_DIR), ("library/", self.workarea / WORKAREA_PATCHES)]` (revised D-3; path arithmetic, nothing created; the order is the listing's order).
module: s19_app/tui/app.py
calls: S19TuiApp._active_project_dir
examples: (R-PATCH-DOC-DROPDOWN-001.1/1) proj open → `[("checks/", …/proj/checks), ("patches/", …/proj/patches), ("library/", …/workarea/patches)]`
examples: (R-PATCH-DOC-DROPDOWN-001.1/4) no project → `[("", …/workarea/patches)]`

S19TuiApp._check_home
req: R-CHKED-031, R-CHKED-040, R-DIFF-CHK.1
in: —
out: Path
func: new. `scoped_home_target(self._active_project_dir(), PROJECT_CHECKS_DIR, self.workarea / WORKAREA_PATCHES)`; creates nothing (Write's placement creates and contains the folder).
module: s19_app/tui/app.py
calls: scoped_home_target, S19TuiApp._active_project_dir
examples: (R-CHKED-031/1) proj open → `…/workarea/proj/checks`; (R-CHKED-031/2) no project → `…/workarea/patches`

S19TuiApp._scan_patch_change_files
req: R-PATCH-DOC-DROPDOWN-001.1, R-PATCH-DOC-DROPDOWN-001.2
in: —
out: List[str]
func: changed. was: `[name for name, _ in list_change_documents(self._patches_dir())]`. / now: for each `(prefix, folder)` of `_change_homes()`, in that order: `prefix + name` for every name of `list_change_documents(folder)` (sorted, links skipped by the helper); the lists joined in home order — not one global sort, since `library/` would sort between `checks/` and `patches/`. Callers now: `_prefill_patch_change_files` only (#20–#22 move to #15).
module: s19_app/tui/app.py
calls: S19TuiApp._change_homes, list_change_documents
examples: (R-PATCH-DOC-DROPDOWN-001.1/1) proj open, `proj/patches/a.json`, `proj/checks/k.chk.json`, `workarea/patches/w.json` → `["checks/k.chk.json", "patches/a.json", "library/w.json"]`
examples: (R-PATCH-DOC-DROPDOWN-001.1/2) proj open, all three folders empty, Save → `["patches/changes.json"]` (base P: `[]`)
examples: (R-PATCH-DOC-DROPDOWN-001.1/4) no project, `a.json`, `b.json` → `["a.json", "b.json"]`
examples: (R-PATCH-DOC-DROPDOWN-001.2/1) proj open, all three folders empty → `[]` → prompt `Change files in patches/`, 0 options; (001.2/2) only `workarea/patches/w.json` → `["library/w.json"]`

S19TuiApp._scan_spec_files
req: R-CHKED-040, R-DIFF-CHK.1, R-DIFF-CHK.3
in: —
out: List[str]
func: new (E1 name `_scan_check_home_files`, renamed at E3 because the list now holds the library). As #14, over `_spec_homes()` (#32): `prefix + name` per home, joined in home order.
module: s19_app/tui/app.py
calls: S19TuiApp._spec_homes, list_change_documents
examples: (R-CHKED-040/1) proj open, `proj/checks/k.chk.json`, `workarea/patches/w.chk.json` → `["checks/k.chk.json", "library/w.chk.json"]`
examples: (R-DIFF-CHK.1/2) no project, `workarea/patches/w.chk.json` → `["w.chk.json"]`
examples: (R-DIFF-CHK.3/1) proj open, `proj/checks/` and `workarea/patches/` empty → `[]`

S19TuiApp._resolve_listed_file
req: R-PATCH-DOC-DROPDOWN-001.3, R-PATCH-DOC-DROPDOWN-001.4, R-CHKED-044, R-DIFF-CHK.5
in: value: str, homes: list[tuple[str, Path]]
out: Optional[Path]
func: new. Picks the home whose prefix starts `value` (`""` matches only when it is the sole home); `name = value[len(prefix):]`; `path = folder / name` (unresolved). `None` when no home matches; `name` is empty, holds a separator or is `..`; `_path_traverses_reparse_point(path, stop_at=self.workarea.parent)` or `_is_reparse_point(self.workarea.parent)` — the Write guard's walk and stop point (S-3 = E3A-06: a link anywhere from the work area down to the file, also one that stays inside the project, D-6); or `path.resolve()` is not inside `self.workarea.resolve()` (the Write guard's last check). Otherwise `path` itself, **unresolved** (S-4: the Save project classifier compares unresolved text).
module: s19_app/tui/app.py
calls: workspace._path_traverses_reparse_point, workspace._is_reparse_point, Path.resolve
examples: (R-PATCH-DOC-DROPDOWN-001.3/1) `"checks/k.chk.json"`, proj homes → `<workarea>/proj/checks/k.chk.json` as `self.workarea` spells it
examples: (R-PATCH-DOC-DROPDOWN-001.3/3) `"library/w.json"`, proj homes → `<workarea>/patches/w.json`
examples: (R-PATCH-DOC-DROPDOWN-001.3/4) base folder `alias` → `real`: returns `alias/.s19tool/workarea/proj/patches/a.json` (not `real/…`); the link above `.s19tool` is outside the walk, as for Write
examples: (R-PATCH-DOC-DROPDOWN-001.4/2) `proj/patches` linked to an outside folder, `"patches/x.json"` → `None`
examples: (R-PATCH-DOC-DROPDOWN-001.4/3) proj open, `"w.json"` → `None`; `"patches/../../w.json"` → `None`
examples: (R-PATCH-DOC-DROPDOWN-001.4/4) `proj/checks` a link to `proj/patches`, `"checks/x.json"` → the walk meets `proj/checks` → `None` (E1 design: both containment checks pass → loads)

S19TuiApp.on_patch_editor_panel_change_file_selected
req: R-PATCH-DOC-DROPDOWN-001.3, R-PATCH-DOC-DROPDOWN-001.4
in: PatchEditorPanel.ChangeFileSelected
out: None
func: changed. was: `candidate = (self._patches_dir() / filename).resolve()`; refuse a link or a path outside `_patches_dir().resolve()`. / now: `candidate = self._resolve_listed_file(filename, self._change_homes())`; `None` → the same status `Patch Editor: change file {filename!r} is outside the patches folder — not loaded.`; the dirty guard and `_patch_editor_load(panel, str(candidate))` unchanged, except that the popup's `_answer`, on accept and after its busy check, runs `_resolve_listed_file` again and on `None` paints the same refusal and loads nothing (S-5).
module: s19_app/tui/app.py
calls: S19TuiApp._resolve_listed_file, S19TuiApp._change_homes, S19TuiApp._patch_editor_load, LoadGuardScreen
examples: (R-PATCH-DOC-DROPDOWN-001.4/1) `"patches/l.json"` a link → status `Patch Editor: change file 'patches/l.json' is outside the patches folder — not loaded.`, document unchanged
examples: (R-PATCH-DOC-DROPDOWN-001.4/5) dirty, pick `"patches/a.json"` (passes) → popup; `proj/patches` becomes a link; accept → the second check returns `None` → the refusal status, document unchanged (base: loads the pre-checked path)

S19TuiApp.on_check_editor_panel_spec_file_selected
req: R-CHKED-042, R-CHKED-044
in: CheckEditorPanel.SpecFileSelected
out: None
func: changed (the guard at the top; one argument at the end). was: guard against `_patches_dir()`; `panel.load_spec(items, event.filename)`. / now: `candidate = self._resolve_listed_file(filename, self._spec_homes())`; `None` → the same status `Check Editor: file {filename!r} is outside the patches folder — not loaded.`; the read (with the loaded A2L) and Inc 5's item dicts unchanged; `panel.load_spec(items, candidate.name)` so the Write as input takes the bare file name (R-CHKED-042; the listed value would put `library/` into it); the loaded status still names the listed value.
module: s19_app/tui/app.py
calls: S19TuiApp._resolve_listed_file, S19TuiApp._spec_homes, read_change_document, CheckEditorPanel.load_spec
examples: (R-CHKED-044/2) `proj/checks` linked, `"checks/x.chk.json"` → status `Check Editor: file 'checks/x.chk.json' is outside the patches folder — not loaded.`
examples: (R-CHKED-042/1) proj open, `"library/w.chk.json"` → `<workarea>/patches/w.chk.json`; status `Check Editor: loaded 'library/w.chk.json' (1 fields).`; Write as input `w.chk.json`

S19TuiApp.on_ab_diff_panel_check_file_selected
req: R-DIFF-CHK.5, R-DIFF-CHK.8
in: AbDiffPanel.CheckFileSelected
out: None
func: changed. was: guard against `_patches_dir()`. / now: guard through `_resolve_listed_file(name, self._spec_homes())`, same refusal status; the rest unchanged (`_diff_check_spec_name` keeps the listed value, so the report's `- Check spec:` line names `checks/<n>` or `library/<n>` in a project, revised D-3).
module: s19_app/tui/app.py
calls: S19TuiApp._resolve_listed_file, S19TuiApp._spec_homes
examples: (R-DIFF-CHK.5/1) `"checks/l.chk.json"` a link in `proj/checks` → `#diff_status` `Check spec: 'checks/l.chk.json' is outside the patches folder — not loaded.`
examples: (R-DIFF-CHK.5/2) `proj/checks` a linked folder, `"checks/x.chk.json"` → the same status with `'checks/x.chk.json'`
examples: (R-DIFF-CHK.8/1) proj open, `"library/w.chk.json"` (W) → `#diff_status` `Check spec 'library/w.chk.json' loaded — 1 declared field(s) will ride the report.`

S19TuiApp._prefill_check_editor
req: R-CHKED-040
in: —
out: None
func: changed. was: `panel.set_spec_files(self._scan_patch_change_files())`. / now: `panel.set_spec_files(self._scan_spec_files())`; the A2L picker half unchanged.
module: s19_app/tui/app.py
calls: S19TuiApp._scan_spec_files, CheckEditorPanel.set_spec_files
examples: (R-CHKED-040/2) after Write `s1.chk.json` in proj → `["checks/k.chk.json", "checks/s1.chk.json", "library/w.chk.json"]`

S19TuiApp._prefill_diff_check_files
req: R-DIFF-CHK.1, R-DIFF-CHK.3
in: —
out: None
func: changed. was: `panel.set_check_files(self._scan_patch_change_files())`. / now: `…(self._scan_spec_files())`. An empty list keeps the row out when it was never composed (`set_check_files` no-op); a row composed earlier is not removed (backlog, E3A-11).
module: s19_app/tui/app.py
calls: S19TuiApp._scan_spec_files, AbDiffPanel.set_check_files
examples: (R-DIFF-CHK.1/1) proj open → `["checks/k.chk.json", "library/w.chk.json"]` (base P: the common `s1.chk.json`)
examples: (R-DIFF-CHK.3/1) empty library at start, `proj` with empty `checks/`, key `7` → `[]`, no row composed → `Check spec:` not painted

S19TuiApp._compose_screen_diff
req: R-DIFF-CHK.1
in: —
out: Container
func: changed. was: `AbDiffPanel(check_files=self._scan_patch_change_files())`. / now: `AbDiffPanel(check_files=self._scan_spec_files())`.
module: s19_app/tui/app.py
calls: S19TuiApp._scan_spec_files
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
examples: (R-CHKED-031/3) proj open, `library/w.chk.json` picked (Write as `w.chk.json`), Write → `proj/checks/w.chk.json`; `workarea/patches/` unchanged

S19TuiApp._patch_editor_load
req: R-TUI-049.3.1, R-TUI-049.3.2
in: PatchEditorPanel, str
out: None
func: changed (E3A-01). was: `ChangeService.load`, report, `mark_loaded()` on success, then the tail #6. / now: first `self._hide_replaced_document_controls(panel)` (#9) — every call replaces the document, also a failed read (`ChangeService.load` always assigns) — then the same. Callers: the `load_doc` arm, the dropdown pick (clean, and the popup accept), the typed-Load popup accept (`on_patch_editor_panel_dirty_load_requested._answer`). Save project and the project install do not call it, so they hide nothing here.
module: s19_app/tui/app.py
calls: S19TuiApp._hide_replaced_document_controls, ChangeService.load, S19TuiApp._patch_editor_load_tail
examples: (R-TUI-049.3.1/2) control painted, pick `c2.json` → not painted (base P: painted)
examples: (R-TUI-049.3.2/3) prompt painted, entry added, Load C2 → `Accept loss and load` → not painted

S19TuiApp._spec_homes
req: R-CHKED-040, R-CHKED-042, R-CHKED-044, R-DIFF-CHK.1, R-DIFF-CHK.3, R-DIFF-CHK.5, R-DIFF-CHK.8
in: —
out: list[tuple[str, Path]]
func: new (revised D-3, I-6). No project → `[("", self.workarea / WORKAREA_PATCHES)]`. Project `P` → `[("checks/", self._check_home()), ("library/", self.workarea / WORKAREA_PATCHES)]` (nothing created). The two spec lists and their two pick guards read it; Write keeps `_check_home()` alone.
module: s19_app/tui/app.py
calls: S19TuiApp._active_project_dir, S19TuiApp._check_home
examples: (R-DIFF-CHK.1/1) proj open → `[("checks/", …/proj/checks), ("library/", …/workarea/patches)]`
examples: (R-DIFF-CHK.1/2) no project → `[("", …/workarea/patches)]`

S19TuiApp._note_image_bytes_written
req: R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012, R-CHK-PE-014, R-CHKS-001, R-CHKS-009
in: —
out: None
func: changed (Inc 5's new function; E3A-03). was (Inc 5): tell the CRC Designer, then clear the Check Editor's verdicts (an early `return` when that panel is not mounted). / now: three statements first — `self._change_service.end_check_run()` (I-7); the Patch Editor panel queried, and when mounted `self._patch_editor_load_tail(panel)` (#6: repaints the ledger glyphs to `·`, R-CHK-PE-014, and the Checks tab through #8, with no new `refresh_entries` site); `self.update_checks_view()` — then Inc 5's body unchanged. One seam for every consequence of an in-place write: the apply arm (also when the apply raises after the journal restore, and when 0 applied), the save-back after `save_patched` (whatever `result.ok`), and the Save project commit that wrote the image.
module: s19_app/tui/app.py
calls: ChangeService.end_check_run, S19TuiApp._patch_editor_load_tail, S19TuiApp.update_checks_view, CrcDesignerPanel.note_image_bytes_written, CheckEditorPanel.clear_check_results
examples: (R-CHK-PE-009/5) C applied, K1 loaded, Run (`Checks: 1 passed, 0 failed, 0 uncheckable`, `1 checked`), Apply K1 (`Apply: 0 applied, 0 skipped, 1 blocked`; the journal puts `0x8003` back to `03`) → the hook ends the run → `no run yet`, `No check run yet: press Run checks.` (base, E3 probe: `1 passed` stays current; a fresh run says `1 failed`)
examples: (R-CHK-PE-014/1) C applied, Run (blocked, Kind cell `◐`), Write file → the hook ends the run and repaints → Kind cell `·`, subtitle `no run yet`

S19TuiApp._refill_document_lists
req: R-PATCH-DOC-DROPDOWN-001.1, R-CHKED-040, R-DIFF-CHK.1
in: —
out: None
func: new (E3A-04). `self._prefill_patch_change_files()`; the Check Editor panel queried, and when mounted `panel.set_spec_files(self._scan_spec_files())` (the Spec half only — the A2L picker half stays on screen entry); `self._prefill_diff_check_files()`. Each tolerates an unmounted panel. Called only after `current_project_dir` holds the new project.
module: s19_app/tui/app.py
calls: S19TuiApp._prefill_patch_change_files, S19TuiApp._scan_spec_files, CheckEditorPanel.set_spec_files, S19TuiApp._prefill_diff_check_files
examples: (R-PATCH-DOC-DROPDOWN-001.1/5) Patch Editor displayed with `["w.json"]`, `p` → `proj` → `["patches/a.json", "library/w.json"]` (base: `["w.json"]` kept)

S19TuiApp._install_prepared_project
req: R-PATCH-DOC-DROPDOWN-001.1, R-CHKED-040, R-DIFF-CHK.1
in: PreparedProjectLoad
out: None
func: changed (E3A-04). was: reset (#7), reopen the document, set `current_project` / `current_project_dir`, install the variant and MAC, announce. / now: the same, with `self._refill_document_lists()` (#35) right after `self.current_project_dir = request.project_dir` (`:14090`).
module: s19_app/tui/app.py
calls: S19TuiApp._reset_project_session, S19TuiApp._reopen_active_document, S19TuiApp._refill_document_lists, S19TuiApp._apply_loaded_file
examples: (R-DIFF-CHK.1/3) A2B Diff displayed, no project, `p` → `proj` → values `["checks/k.chk.json", "library/w.chk.json"]` without reopening the screen (base: `["w.chk.json"]`)

S19TuiApp._on_project_saved
req: R-PATCH-DOC-DROPDOWN-001.1, R-CHKED-040, R-DIFF-CHK.1
in: SaveOutcome
out: None
func: changed (Inc 5 function; E3A-04). was: on a committed save, the tail lines, the image adoption (Inc 5's hook inside it), the placed document, then `current_project` / `current_project_dir`, labels, `refresh_files()`. / now: the same, with `self._refill_document_lists()` (#35) right after `self.current_project_dir = prepared.project_dir` (`:12683`) — every committed Save project (plain, create, save-as); an uncommitted one returns early and refills nothing.
module: s19_app/tui/app.py
calls: S19TuiApp._note_image_bytes_written, S19TuiApp._patch_editor_load_tail, S19TuiApp._refill_document_lists
examples: (R-PATCH-DOC-DROPDOWN-001.1/6) no project, `workarea/patches/w.json`, Save project creating `new` → `["library/w.json"]` (base: `["w.json"]`)
examples: (R-CHKED-040/3) Check Editor displayed, `workarea/patches/w.chk.json`, Save project creating `new` → Spec values `["library/w.chk.json"]`

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

ChangeService.end_check_run
req: R-CHK-PE-009, R-CHK-PE-010, R-CHK-PE-011, R-CHK-PE-012, R-CHK-PE-014
in: —
out: None
func: new (I-7, E3A-03). `self.last_check_result = None`; `self._last_check_message = ""` — the reset `undo` / `redo` already make, for an in-place write of the image. Touches no journal, document or stamp.
module: s19_app/tui/services/change_service.py
calls: —
examples: (R-CHK-PE-009/5) after a K1 run `check_run_is_current()` is `True`; `end_check_run()` → `False`, `check_status_line() == ""`, `check_aggregates()` all 0, `_check_glyphs()` → `[]`
examples: no run yet → `end_check_run()` → still no run (idempotent)

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

R-BEFORE-AFTER-REPORT-001.1, .36 → save_back_decision; .11 → unchanged (`test_r_before_after_report_001_11_*`). R-TUI-049.3.1, .3.2 → #9 and its callers: the `parse_paste` arm, undo, redo, `_patch_editor_load` (#31), `_reset_project_session`, `_apply_prepared_load` (new image only); Save project keeps both (/9, `_patch_editor_load_tail`). R-PATCH-DOC-DROPDOWN-001.1 → `_scan_patch_change_files`, `_refill_document_lists` (via `_install_prepared_project`, `_on_project_saved`); .2 → `_change_homes`, `_scan_patch_change_files`; .3, .4 → `_resolve_listed_file`, change_file_selected. R-CHKED-031, -034 → Check Editor write arm; -040 → `_prefill_check_editor`, `_refill_document_lists`; -042, -044 → spec_file_selected. R-DIFF-CHK.1, .3, .5, .8 → `_spec_homes`, `_scan_spec_files` and the A2B nodes. R-CHK-PE-008 … 012 → #8, #30, G2; -009/5, -014 → `_note_image_bytes_written`, `end_check_run`; -009/6 → `_apply_prepared_load`. R-CHKS-001, -004, -009 → `update_checks_view` (R-CHKS-004/1: image 2 loaded after a K run → note `No check run yet — run checks from the Patch Editor.`); -004/2, -009/2 → `_apply_prepared_load`, `_reset_project_session` (displayed screen).
