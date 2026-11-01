# E4 — Inc 10 group G-A implementation notes (screens.py + screens_directionb.py)

Scope: the `ConfirmQuestionScreen` modal, the `PatchEditorPanel.is_dirty` reader, and
the `_dirty` attribute comment correction. `styles.tcss` is unchanged (ruling Q-6),
so the slice stays at 3 source files with G-B's `app.py`.

## Functions changed / added / deleted

### s19_app/tui/screens.py

- Added `class ConfirmQuestionScreen(ModalScreen[bool])` — line 1230, placed right after
  `ConfirmDiscardScreen` (ends line 1228) and before `SelectVariantScreen` (line 1314).
  - `AUTO_FOCUS = "#confirm_no"` — line 1255.
  - `BINDINGS` (`y`/`n`/`escape` → `answer(True|False)`, `show=False`) — line 1256.
  - `__init__(self, title, body, yes_label, no_label)` — line 1262; stores
    `_question_title`, `_question_body`, `_yes_label`, `_no_label`, `_dismissed = False`
    (line 1274). Never assigns `self.title` (R-GA10-1).
  - `compose(self)` — line 1276; yields one tree:
    `Container#confirm_box.modal-dialog` → `Label#confirm_title.modal-title` (markup off),
    `Static#confirm_body` (markup off), `Container#confirm_buttons.modal-buttons` →
    `Button(Text(yes_label))#confirm_yes.modal-confirm`, `Button(Text(no_label))#confirm_no`.
  - `on_button_pressed(self, event)` — line 1299; `event.stop()`, then
    `confirm_yes → _close(True)`, `confirm_no → _close(False)`.
  - `action_answer(self, value)` — line 1306; `self._close(value)`.
  - `_close(self, result)` — line 1309; `if self._dismissed: return`, `_dismissed = True`,
    `dismiss(result)`.

No deleted functions. No new imports (uses the existing `Text`, `Label`, `Static`,
`Container`, `Button`, `Binding`, `ComposeResult`, `ModalScreen`).

### s19_app/tui/screens_directionb.py

- Added `PatchEditorPanel.is_dirty` read-only property — line 5866, placed right after
  `mark_pasted` (the last writer) and before `_refresh_dirty_indicator`. Returns
  `self._dirty`; no setter, no side effect, no repaint.
- Changed the `_dirty` attribute comment (comment only, no code) — lines 4808-4817.
  The writer census now reads five sites (w1..w5 `mark_pasted`), the in-module readers
  list the Load guard / ledger subtitle / JSON stamp, and the outside-module reader note
  points at `is_dirty` (LLR-174.1c).

No functions deleted.

## Graph node → code location

| Node | Location |
|---|---|
| Q1 `ConfirmQuestionScreen.__init__` (+ class attrs) | `screens.py:1230-1274` (attrs 1255-1261) |
| Q2 `ConfirmQuestionScreen.compose` | `screens.py:1276-1296` |
| Q3 `ConfirmQuestionScreen.on_button_pressed` | `screens.py:1299-1303` |
| Q4 `ConfirmQuestionScreen.action_answer` | `screens.py:1306-1307` |
| Q5 `ConfirmQuestionScreen._close` | `screens.py:1309-1312` |
| P1 `PatchEditorPanel.is_dirty` | `screens_directionb.py:5866-5873` |
| P2 `_dirty` attribute comment | `screens_directionb.py:4808-4817` |
| C1 `styles.tcss` (unchanged) | no edit; recorded |

## Deviations

None. The graph was followed exactly:

- Button labels wrapped in `rich.text.Text` (P-GA10-1 Option A, ruling Q-1), not `Content`.
- No `textual.content` import (node I1 retired).
- No `styles.tcss` change (C1).
- The class docstring uses the codebase's Summary / Args / Dependencies shape with the
  "Used by: S19TuiApp._confirm_then_load (the load question); Inc 12 builds the quit
  question from it." line, matching the neighbouring `ConfirmDiscardScreen` tone.

## Open questions

None for G-A.

## Verification

- `py_compile` clean under `s19env` for both files.
- Line endings preserved: both files remain CRLF (0 bare LF).
- sha256[:16]:
  - `screens.py` — 58186f0551f9b02e
  - `screens_directionb.py` — c53fd29b14f5c8ed
