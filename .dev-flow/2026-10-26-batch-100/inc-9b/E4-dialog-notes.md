# E4 dialog implementation notes — group G-A (LoadDialog + CSS + re-exports)

Implementer: G-A. Files touched (only the three allowed): `s19_app/tui/screens.py`,
`s19_app/tui/styles.tcss`, `s19_app/tui/__init__.py`. All three keep LF line endings
(unchanged). Verified with `s19env` Python 8.2.8: `py_compile` passes, `screens.py`
loads standalone (all new symbols resolve), and a scratch `run_test` harness confirms
the graph's key behaviours. `import s19_app.tui` still fails until G-B lands its
`app.py` change (it still imports `LoadFileScreen`); that is the expected cross-group
sequence, not a defect in these files.

## Functions / classes changed, added, deleted

### s19_app/tui/screens.py

Added (module level):
- `LoadKind` — line 185.
- `LoadChoice` (frozen dataclass) — lines 189–215.
- `LoadRow`, `PreviewLine` aliases — lines 217–218.
- `LOAD_NOTHING_SELECTED` — line 224.
- `LOAD_MARK` — line 226.
- `LoadDialog` class — lines 229–549; methods:
  - `__init__` 298 · `compose` 317 · `on_mount` 347 · `_initial_index` 369 ·
    `on_key` 392 · `on_input_submitted` 428 · `on_button_pressed` 434 ·
    `action_load` 442 · `action_cancel` 466 · `_row_choice` 470 ·
    `_path_choice` 477 · `_say` 484 · `_close` 488 · `on_descendant_focus` 495 ·
    `on_option_list_option_highlighted` 509 · `_schedule_preview` 516 ·
    `show_preview` 529 · `on_resize` 543 · `_apply_stack` 547.

Changed (imports):
- line 6: `from typing import ...` gained `Callable` and `Literal` (same module, 0 new modules).
- lines 18–30: `from textual.widgets import (...)` gained `OptionList` (same module, 0 new modules).

Deleted:
- `LoadFileScreen` (was lines 184–227).
- `LoadProjectScreen` (was lines 696–735).

Reworded docstrings (retired class names → "the Load dialog"):
- line 603 (was 281), 1097 (was 817), 1233 (was 953), 1966 (was 1686), 2276 (was 1996).

### s19_app/tui/styles.tcss

Changed:
- `.modal-dialog, #load_dialog` → `.modal-dialog` — line 1581 (selector narrowed; body unchanged).
- `#project_list, #variant_list` → `#variant_list` — line 1773 (body unchanged).

Added:
- `#load_box` — line 1596 (C1).
- `#load_panes` 1784 · `#load_panes.stacked` 1789 · `#load_panes.stacked #load_left, #load_panes.stacked #load_preview` 1793–1796 (C3).
- `#load_left` 1798 · `#load_list` 1803 · `#load_list:focus` 1811 · `#load_preview` 1815 · `#load_preview:focus` 1825 · `#load_reason` 1829 (C4).

The C1 marker comment block (lines 1563–1574, literal first line "Calm Dark modal re-skin (batch-02 increment 8") is byte-identical (A9b-12).

### s19_app/tui/__init__.py

Changed:
- line 32: `LoadFileScreen, LoadProjectScreen` → `LoadChoice, LoadDialog` in the `.screens` import.
- lines 61–62: `"LoadFileScreen"`, `"LoadProjectScreen"` → `"LoadChoice"`, `"LoadDialog"` (alphabetical order preserved: LoadChoice < LoadDialog < LoadedFile).

## Graph node → code location

- **S1 LoadChoice / aliases** → `screens.py:185–218`. `LoadKind` (185), `LoadChoice` (189), `LoadRow` (217), `PreviewLine` (218).
- **S2 LoadDialog.__init__ / compose** → `screens.py:229–345` (class + `BINDINGS` + `__init__` + `compose`); constants 224, 226.
- **S3 on_mount** → `screens.py:347–367`; `_initial_index` helper 369–390.
- **S4 on_key** → `screens.py:392–426`.
- **S5 action_load (+ on_input_submitted, on_button_pressed)** → `screens.py:428–464`; helpers `_row_choice` 470, `_path_choice` 477, `_say` 484.
- **S6 action_cancel (+ _close)** → `screens.py:466–468` (`action_cancel`), 488–493 (`_close`).
- **S7 highlight / focus handlers** → `screens.py:495–527` (`on_descendant_focus`, `on_option_list_option_highlighted`, `_schedule_preview`). No `on_input_changed` and no `on_option_list_option_selected` were added, per the graph.
- **S8 show_preview** → `screens.py:529–541`.
- **S9 on_resize / _apply_stack** → `screens.py:543–549`.
- **C1 .modal-dialog + #load_box** → `styles.tcss:1581–1601`.
- **C2 #variant_list** → `styles.tcss:1773–1777`.
- **C3 #load_panes(.stacked)** → `styles.tcss:1784–1796`.
- **C4 #load_left / #load_list / #load_preview / #load_reason / #load_buttons** → `styles.tcss:1798–1835` (`#load_buttons` needs no rule; it carries the shared `modal-buttons` class).
- **R1 LoadFileScreen retired** → class deleted; `#load_path` / `#load_ok` / `#load_cancel` survive inside `LoadDialog`; `#loadfile_buttons` → `#load_buttons`.
- **R2 LoadProjectScreen retired** → class deleted; `#project_list` → `#load_list`, `#project_ok` → `#load_ok`, `#project_cancel` → `#load_cancel`, `#loadproject_buttons` → `#load_buttons`.
- **PSC-1 re-export** → `__init__.py:32,61,62`.

## Deviations

None. Every node was implemented exactly as the graph specifies: widget ids and
painted strings match character-for-character (title `Load`, placeholder
`C:\path\to\file.s19, .hex, .mac, .a2l, or a project folder`, buttons
`Load (alt+l)` / `Cancel (esc)`, reason separator U+2014, `LOAD_MARK` U+25CF U+0020,
`LOAD_NOTHING_SELECTED` pair). `_source` flips to `"path"` synchronously in `on_key`
step 4 (A9b-06), the `_dismissed` guard is the first line of both `action_load` and
`_close`, and the `alt+l` binding is `priority=True` (A9b-01).

Two transcription notes that are not deviations, recorded for the reviewer:
1. `on_key` step 4 uses `self.query_one("#load_path", Input)` (typed query) rather
   than the untyped `query_one("#load_path")` in the graph's prose. `Input` is the
   base class of `OsClipboardInput`, so the query resolves to the same widget; this
   matches the existing `LoadFileScreen` style. Verified at runtime.
2. `_initial_index` is written as three explicit passes (project+value match, first
   project, first loadable) instead of one fused loop. This is the same rule the
   graph states under (a)–(d) and produces identical results; no behaviour change.

## Verification performed (no test suite was run)

- `python -m py_compile s19_app/tui/screens.py s19_app/tui/__init__.py` → OK.
- `screens.py` loaded standalone (package stubs + `importlib`) → all new symbols
  resolve; `LoadChoice` frozen/eq/hash/repr verified; `LOAD_MARK` = U+25CF+U+0020.
- Scratch `run_test` harness (temp dir, not in the repo):
  - S2-1 ids all present; S3-1 highlight = 2 with `highlight="cd"`; S3-8 disabled = {0,3,6}.
  - S4-5: list mode, `down down enter` from `ab` → verdict/dismiss `LoadChoice("workarea","a.s19")`; disabled rows skipped.
  - S5-8 / S5-13 / S6-1: empty path paints `nothing selected — pick a row or type a path` (0 verdict calls); a refusal paints `not found — check the path` and keeps the dialog open with the field untouched; `escape` dismisses.
  - S4-1: printable key on the focused list redirects into `#load_path`, `_source` becomes `"path"`.
  - S2-4 tab order `load_path → load_list → load_preview → load_ok → load_cancel → load_path` (5 of 5).
  - S9/C3: `stacked` at 99 cols, not stacked at 118, live resize 118→99 re-stacks; `#load_box` = 96 %/90 % of the screen (the absolute 111×46 in the scratch host is a harness artifact of its 116×52 modal surface, not a CSS defect — list/preview non-overlap and `#load_reason` height 1 were confirmed).
- Grep guards: `class LoadFileScreen`/`class LoadProjectScreen` = 0; `project_list|project_ok|project_cancel` = 0 in both `screens.py` and `styles.tcss`; `#variant_list` = 1 in `styles.tcss`; `project_list` = 0.

## Open questions / cross-group dependencies

- `import s19_app.tui` (and thus P1-1) fails until G-B removes `LoadFileScreen` /
  `LoadProjectScreen` from `app.py` imports and re-points the callers to
  `LoadChoice` / `LoadDialog` (SA-6). Nothing in this group's files blocks it.
- The exact `#load_box` region coordinates (C1-1, S9-1 … S9-4) were not re-measured
  in this scratch harness because the minimal host screen is 2 rows/cols smaller
  than the graph's K10 probe surface; the rules were transcribed character-for-
  character and parse correctly, so the tester's measurement against `S19TuiApp`
  should match K10.
- `List` and `ListView`/`ListItem` imports remain in use by other classes
  (`SaveProjectScreen` etc.), so no import was pruned.
