# fast-dev-flow spec — Batch 1: N6 + N7 (user-test polish fixes)

- **Status:** closed 2026-07-23 (both ACs shipped; 2 ATs RED-verified then green; full suite 1851 passed, only the 19 pre-existing batch-58/59 tc016s snapshot cells fail)
- **Date:** 2026-07-23
- **Branch:** `fix/n6-n7-help-toggle-a2l-panel` (base `235923f`)
- **Flow mode:** autonomous + self-merge (operator-approved, per-batch)
- **security_required:** false

## 1. Objective

Fix two TUI usability defects surfaced during operator user-testing:

- **N6** — the `?` Help panel can be opened but never closed with the same key.
- **N7** — after loading an A2L file, its filename does not appear in the top
  "Loaded" panel until the operator switches screens and comes back.

## 2. User stories

- **US-N6:** As an operator, when I press `?` a second time, the Help panel
  closes, so `?` is a true on/off toggle.
- **US-N7:** As an operator, when I load an A2L file, its filename appears
  immediately in the top Loaded-artifacts panel, without navigating away and
  back.

## 3. Scope

**In:**
- Rebind `?` to a toggle action that shows the `HelpPanel` when absent and hides
  it when present (reusing Textual's built-in show/hide actions).
- Call `_refresh_loaded_panel()` at the end of `load_a2l_from_path` so the
  top panel redraws with the A2L slot on load.

**Out:**
- No change to the HelpPanel content or the Legend (N8 is a separate batch).
- No new load paths; C-15.1 sweep already confirmed A2L is the only orphaned
  path (S19/HEX + MAC go through `_apply_loaded_file`, which already refreshes).
- No snapshot-baseline regeneration (no captured-view geometry changes).

## 4. Acceptance criteria (observable)

- **AC-N6-1:** When the operator presses `?` with no Help panel open, the
  system shall mount exactly one `HelpPanel` on the active screen.
- **AC-N6-2:** When the operator presses `?` again while the Help panel is open,
  the system shall remove the `HelpPanel` from the active screen (zero mounted).
- **AC-N7-1:** When `load_a2l_from_path` completes with an A2L file, the system
  shall render that A2L filename in the `#loaded_panel` A2L slot without any
  screen switch.

## 5. Design notes

- **N6:** add `action_toggle_help_panel()` to `S19TuiApp`; repoint the
  `question_mark` binding to it (footer label stays "Help"). Detect the panel
  via `self.screen.query(HelpPanel)`; delegate to the built-in
  `action_show_help_panel` / `action_hide_help_panel` (Textual 8.2.8 — both
  confirmed present). Do not reimplement the panel.
- **N7:** one line — `self._refresh_loaded_panel()` at the end of the A2L load
  path, after `current_file.a2l_path` is set. `_refresh_loaded_panel` reads
  `self.current_file` and calls `panel.render_slots(...)`.

## 6. Security flags

None fired. `security_required: false`.

## 7. Test plan (RED-first)

- `test_help_panel_toggle_hides_on_second_press` — Pilot: `press("?")` →
  1 `HelpPanel`; `press("?")` → 0. RED pre-fix (second press keeps it mounted).
- `test_a2l_load_refreshes_loaded_panel_without_screen_switch` — load S19, then
  `load_a2l_from_path`, assert `#loaded_panel` A2L slot shows the filename with
  no `action_show_screen` call. RED pre-fix (slot empty until screen switch).
