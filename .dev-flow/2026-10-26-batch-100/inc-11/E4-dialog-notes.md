# E4 notes — G-A (`screens.py` + `styles.tcss`), Inc 11 Save project dialog

Implementer notes for group G-A. Files edited (only these two, per the task
allow-list): `s19_app/tui/screens.py` and `s19_app/tui/styles.tcss`. No tests,
no other source files, no `.dev-flow/` files except this notes file. The other
implementer's files (`app.py`, `project_gather_service.py`) were never touched;
the only name imported from them is `project_gather_service.SavePlan` (typing
only, see I1).

Verification performed (never the test suite):

- `C:/Users/jjgh8/anaconda3/envs/s19env/python.exe -m py_compile s19_app/tui/screens.py` → OK.
- Runtime import from the working tree + spot checks of the signature,
  `AUTO_FOCUS`, `BINDINGS`, `DEFAULT_CSS`, `SavePreview` frozen-ness,
  `SaveProjectPayload` equality, the `plan` property (no setter), and the old
  positional `SaveProjectScreen(WA)` form raising `TypeError`.
- AST checks for TC-B100-66 (0 decision-id string literals in the
  `SaveProjectScreen` class body, docstrings excluded) and for S2-6 (0
  forbidden calls / `Path` reads in the class body).
- `styles.tcss` modal-block check: `#save_box` / `#save_where` / `#save_summary`
  present between the Calm Dark marker and `/* --- Activity rail`, 0 hex
  colours, marker comment still 1 occurrence.
- Line endings preserved (both files are CRLF; verified 0 bare-LF lines after
  the edits).

---

## Functions added / changed / deleted (`s19_app/tui/screens.py`)

Line numbers are post-edit.

### Added

| Symbol | Line | Kind |
|---|---|---|
| `project_gather_service` TYPE_CHECKING import | 77 | I1 (typing-only import) |
| `WhereKind = Literal["info", "refusal"]` | 190 | type alias (V) |
| `WhereLine = tuple[str, WhereKind]` | 191 | type alias (V) |
| `SavePreview` (frozen dataclass) | 195–222 | new type (V) |
| `SAVE_RECOMPUTE_S = 0.150` | 926 | module constant (S5) |
| `SaveProjectScreen.AUTO_FOCUS` / `BINDINGS` | 985–989 | class attributes (S1) |
| `SaveProjectScreen._first_preview` | 1083 | S4 helper |
| `SaveProjectScreen.on_input_changed` | 1090 | S5 |
| `SaveProjectScreen._recompute` | 1097 | S5 |
| `SaveProjectScreen._stop_trailing` | 1104 | S5 |
| `SaveProjectScreen._paint` | 1110 | S9 (only writer of `_plan`, `#save_where`, summary rows) |
| `SaveProjectScreen._mark_shown` | 1144 | S9 helper |
| `SaveProjectScreen.plan` (read-only property) | 1150 | S8 |
| `SaveProjectScreen.action_save` | 1154 | S6 |
| `SaveProjectScreen.on_input_submitted` | 1180 | S6 trigger |
| `SaveProjectScreen.action_cancel` | 1239 | S7 |
| `SaveProjectScreen._close` | 1243 | S7 helper (only way out) |

### Changed

| Symbol | Line | Change |
|---|---|---|
| `SaveProjectPayload` docstring `parent_folder` | 163 | "as entered or browsed" → "the work area (the dialog sets it; LLR-175.2a)" |
| `SaveProjectPayload` docstring `plan` entry | 171–173 | added (Y) |
| `SaveProjectPayload.plan` field | 187 | added `field(default=None, compare=False)` (Y) |
| `SaveProjectScreen.__init__` | 992–1013 | rewritten keyword-only (S1) |
| `SaveProjectScreen.compose` | 1025–1077 | rewritten (S2) |
| `SaveProjectScreen.on_mount` | 1080–1081 | rewritten to `call_after_refresh(self._first_preview)` (S4) |
| `SaveProjectScreen.on_button_pressed` | 1232–1237 | rewritten (S6/S7 dispatch) |
| `SaveProjectScreen._collect_composition` docstring `Used by` | 1228 | `on_button_pressed (Save dismiss path)` → `action_save` (docstring-only; body unchanged) |

### Deleted / retired (R1)

- `SaveProjectScreen.__init__` parameter and attribute `default_parent` (old positional form).
- `Label("Save project folder under:")`, `OsClipboardInput#project_parent_path`
  (placeholder `C:\path\to\parent\folder`), `Container#save_browse_row`,
  `Button#save_browse` ("Browse..."), `Label("Project name (new folder name):")`.
- The `save_browse` branch of the old `on_button_pressed` (its inline
  `import tkinter` / `from tkinter import filedialog`).
- The strip-and-return rule of the old Save branch (`if not parent or not name`).
- `id="load_dialog"` on this screen (now `id="save_box"`). Other modals keep
  their ids — `tkinter` remains imported elsewhere in `screens.py`
  (`LoadFlowScreen._import_external`, line 1398), so the module census is
  unchanged.

Unchanged: `_assignment_rows_enabled` (1016–1023) and `_collect_composition`
body (1185–1230), exactly as the graph says (their caller moved).

---

## Graph node → code location

| Node | Location |
|---|---|
| V `SavePreview` (+ `WhereKind`, `WhereLine`) | `screens.py:190–222`, right after `SaveProjectPayload` |
| I1 typing import | `screens.py:77` inside `if TYPE_CHECKING:` |
| Y `SaveProjectPayload.plan` | `screens.py:187` (+ docstring 163, 171–173) |
| S1 `__init__` + class attributes | `screens.py:926` (const), 929–1013 (class, attrs, `__init__`) |
| S2 `compose` | `screens.py:1025–1077` |
| S4 `on_mount` / `_first_preview` | `screens.py:1080–1088` |
| S5 `on_input_changed` / `_recompute` / `_stop_trailing` | `screens.py:1090–1109` |
| S9 `_paint` (+ `_mark_shown`) | `screens.py:1110–1148` |
| S8 `plan` | `screens.py:1150–1152` |
| S6 `action_save` + triggers | `screens.py:1154–1183` |
| S7 `action_cancel` / `_close` | `screens.py:1239–1260` |
| R1 retirement | done throughout the above; `grep` of `project_parent_path|save_browse` and `default_parent` → 0 |
| C1 `#save_box` | `styles.tcss:1862–1866` |
| C2 `#save_where` / `#save_where.refusal` | `styles.tcss:1871–1879` |
| C3 `#save_summary` / `:focus` / `Static` | `styles.tcss:1881–1898` |
| C4 (no `#saveproject_buttons` rule) | nothing added; `grep -c "#saveproject_buttons" styles.tcss` → 0 |

The CSS section comment starts `/* --- Save project dialog (batch-100 increment 11, HLR-175)` and the
rules sit after `.assign-list` and before `/* --- Report viewer modal`, as C1 requires.

---

## Deviations

1. **Actual `id="load_dialog"` census count differs from the graph's "base 8 → 7".**
   The working tree already contains Inc 9b + Inc 10, so `screens.py` before my
   edit holds **6** `id="load_dialog"` (not 8): Inc 9b's `LoadDialog` uses
   `#load_box` and the post-9b/10 tree is smaller than the design-time probe
   (p11b U7). My change is still a clean −1: `git show HEAD:s19_app/tui/screens.py
   | grep -c 'id="load_dialog"'` → 6, post-edit → 5. The other modals are
   untouched. The R1-1 target "7" is a census value the tester must re-pin
   against the actual E4 base (5 after my change); I did not and cannot edit
   the test. This is the only place the graph's literal number does not hold in
   this tree, and it is a test re-pin concern, not a code behaviour.

2. **`_collect_composition` docstring `Used by` updated** from
   `SaveProjectScreen.on_button_pressed (Save dismiss path)` to
   `SaveProjectScreen.action_save`. The graph marks the method "unchanged
   code" but its own Callers table records "the one caller moves from the base
   Save branch to `action_save`". I left the body byte-identical and updated
   only that one docstring reference so it is not stale. No behavioural change.

3. **Trivial throwaway-variable names (not behavioural).** In `_paint` the
   `any()` generator uses `_text` where the graph's literal shows `_t`, and the
   `mount_all` list comprehension uses `row` where the graph shows `r`. Both are
   unused throwaways; the produced strings and widget count are identical.

No other deviations. Every widget id, painted string, token pair, action name,
binding, class, and status-line literal follows the graph character-for-character.

---

## Open questions

- None blocking. One environment note for the tester: in this shell, the
  `s19tool` editable install points at `C:\Users\jjgh8\Github\s19_app` (the
  read-only canonical repo), not this working tree, so `python -I -c "import
  s19_app.tui.screens ..."` resolves the stale installed copy. The checks here
  were run against the working tree via cwd import
  (`s19_app/__init__.py` → `C:\Users\jjgh8\Github\s19_app-b100-inc11\s19_app`).
  The I1-2 assertion (`'project_gather_service' in vars(s)` → `False`) holds on
  the working-tree module regardless.

---

## `styles.tcss` new rules (C1–C4)

- `#save_box { width: 80%; max-width: 130; max-height: 90%; }`
- `#save_where { height: auto; padding: 0 1; margin-bottom: 1; }`
- `#save_where.refusal { text-style: bold; }`
- `#save_summary { height: auto; max-height: 50vh; border: round $rule; background: $bg-base; padding: 0 1; }`
- `#save_summary:focus { border: round $accent-calm; }`
- `#save_summary Static { height: 1; text-wrap: nowrap; text-overflow: ellipsis; }`
- No `#saveproject_buttons` rule (C4: the shared `.modal-buttons` dock rule + C1's `max-height` suffice).

All tokens, no hex (TC-033). The marker comment
`/* --- Calm Dark modal re-skin (batch-02 increment 8, LLR-015.1)` is untouched
(1 occurrence).
