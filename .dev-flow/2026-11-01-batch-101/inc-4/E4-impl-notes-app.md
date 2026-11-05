# Inc 4 — E4 implementer notes (app unit)

Unit: G3 `s19_app/tui/app.py` — the six session-read sites (R-CHG-SYM.9, R-CHG-SYM.10) and the R-TUI-058.9 plain-language line (R-CHG-SYM.9 alt. 4, R-TUI-058.9).

## Functions changed per file

- `s19_app/tui/app.py`:
  - `S19TuiApp._patch_editor_load`
    - `service.load(path_text, self.base_dir)` →
      `service.load(path_text, self.base_dir, a2l_context=self.current_a2l_data)`
      (site 1: Patch Editor file load — dropdown, typed path, dirty-guard accept).
  - `S19TuiApp.on_patch_editor_panel_action_requested`
    - `parse_paste` arm only: `service.load_text(event.paste_text)` →
      `service.load_text(event.paste_text, a2l_context=self.current_a2l_data)`
      (site 2; also the second half of site 3, reached by the posted `parse_paste`).
  - `S19TuiApp._apply_changeset_json_edit`
    - Pre-check: `parse_change_document(edited)` →
      `parse_change_document(edited, a2l_context=self.current_a2l_data)`
      (site 3: whole-document Edit JSON confirm).
  - `S19TuiApp._apply_entry_json_edit`
    - `edit_entry_json(index, edited)` →
      `edit_entry_json(index, edited, a2l_context=self.current_a2l_data)`
      (site 4: per-entry Edit JSON confirm).
    - After `_report_change_result(result)`, when `not result.ok` and
      `self.current_a2l_data is None` and any issue has
      `code == "CHG-SYMBOL-UNRESOLVED"` with `SYMBOL_NO_A2L_CONTEXT_TEXT in
      issue.message` (interface I-1), one extra `set_status` paints the
      R-TUI-058.9 line exactly as stated:
      `Patch Editor: the entry names an A2L symbol and no A2L is loaded - load the A2L, then edit the entry again.`
      Painted last (after the finding line), before `_refresh_patch_history_view()`.
    - Docstring only: Summary and Data Flow updated to record the declared-A2L
      pass and the R-TUI-058.9 line.
  - `S19TuiApp.on_check_editor_panel_spec_file_selected`
    - `read_change_document(str(candidate), self.base_dir)` →
      `read_change_document(str(candidate), self.base_dir, a2l_context=self.current_a2l_data)`
      (site 5: Check Editor Spec pick; the item-building lines after the read
      are Inc 5's, untouched — interface I-3).
  - `S19TuiApp.on_ab_diff_panel_check_file_selected`
    - `read_change_document(str(candidate), self.base_dir)` →
      `read_change_document(str(candidate), self.base_dir, a2l_context=self.current_a2l_data)`
      (site 6: A2B Diff check-spec pick).

- `s19_app/tui/app.py` module import block:
  - `from .changes.io import (...)` now also imports
    `SYMBOL_NO_A2L_CONTEXT_TEXT` (interface I-1, the G1-produced constant), used
    only by `_apply_entry_json_edit`'s R-TUI-058.9 condition.

## Deviations from the graph

None in behaviour. Every code change is exactly the graph's `func:` for the six
G3 nodes; the R-TUI-058.9 line is painted only when the R-CHG-SYM.2 finding is
present (code + I-1 reason text) AND `current_a2l_data is None`, so the
R-CHG-SYM.1 arm (non-string `symbol`, no A2L) and the E3 A-5 arm (a symbol whose
text is the I-1 text, A2L loaded) each paint zero plain lines, as required.

Two non-behaviour additions, both within this unit's file: (1) the
`SYMBOL_NO_A2L_CONTEXT_TEXT` import line; (2) docstring updates in
`_apply_entry_json_edit` (Summary + Data Flow) to keep the docstring accurate
under the project's fixed section-order convention — no signature, caller, or
test-visible name changed. No test file, REQUIREMENTS.md, AT-TC-REGISTRY.jsonl,
or other source file was touched. No UI layout change: only status lines.

## py_compile result

`python -m py_compile s19_app/tui/app.py` → OK (exit 0). Line endings preserved
as CRLF (`file` reports CRLF before and after; a byte scan shows 0 bare-LF
lines).
