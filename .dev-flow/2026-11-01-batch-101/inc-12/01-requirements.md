# Inc 12 — Every dialog, action and widget reachable; Escape closes the Reports dialog: requirements (E1)

Batch 2026-11-01-batch-101, increment 12. Base: `2d1e2b1` (branch `b101-inc12` = main; product tree `e07fb00`, `s19_app/` and `tests/` identical). Stage E1 of the design-first flow (`dev-flow-v3-beta`).
Findings: F-33, F-34, F-35, F-51 (`docs/user-guide/DOSSIER.md` §5, `:742-744`, `:760`), with the requirement-session code changes D7-10, D6-12 (first half), D9-8, D16-6 (`s19w/review/CODE-CHANGES.md`) and, co-located with F-34, D3-7 (decision D-2). Scope, decisions and reasons: `E1-rulings.md`. Slice: `E1-slice.md`. Test cases: `02-test-cases.md`. Graph: `codewire/graph-inc12.md`.

Form column: U = ubiquitous, E = event (`When`). "Base" column: what `e07fb00` does today. C = the E1 census (an AST census of the base tree, `evidence-e1/i12e1-census-transcript.txt`); B = the E1 pilot (the app driven headless; Linux, Python 3.11.18, textual 8.2.8, `evidence-e1/i12e1-pilot-transcript.txt`); R = read in the code, not run.
Row status: **changed** = the canon row's wording is corrected here (`E1-rulings.md` §2); **new** = a new canon row (id checked unused in `REQUIREMENTS.md`, in `docs/requirements/review/S*.md`, in `s19w/review/S*.md` and in every increment folder of the batch).
The rows follow the E1 recommendations (`E1-rulings.md` §3: D-1 A, D-2 A, D-3 A, D-4 A, D-5 A, D-7 A, D-8 A, D-10 A); the orchestrator rules on them.

## User stories

### US-I12-1 — every dialog opens and every action runs from somewhere (F-33, F-34)
As the maintainer, I want every dialog of the app to have a key, a button or a command that opens it, and every action to have a key, a palette command, a button or a caller that runs it, so that the release carries no dialog or action that no operator path reaches and no test keeps one alive.

### US-I12-2 — every widget is shown in some state of its window (F-35)
As the maintainer, I want the Check Editor, the Flow Builder and Flow Execution to hold only widgets that some state of the window shows, so that no hidden copy of the screen is repainted on every change and no test proves a behaviour on a widget the operator never sees.

### US-I12-3 — Escape closes the Reports dialog (F-51)
As the operator, I want Escape to close the Reports dialog as Close does wherever the focus is inside it, an open dropdown list closing first, so that the Reports dialog answers Escape like the other dialogs.

## Definitions (additions and changes to CTX-DIALOG, CTX-KEYS and CTX-SHELL; terms only)

- **Opener** (CTX-DIALOG, new). A key, a button, a palette command, or a control of another dialog or window, whose use opens a dialog.
- **Dropdown list** (CTX-DIALOG, new). The list of choices that a dropdown shows under itself while it is open.
- **Dialogs today** (CTX-DIALOG, changed): the row `Reports (project '<name>'):` reads `yes` in the column "Esc today".
- **Action** (CTX-KEYS, new). A named command of the system: what a key, a palette command, a button or a link runs.
- **Reach** (CTX-KEYS, new). What runs an action: a key binding, a palette command, a button or a link that names it (the system's own, or a binding the terminal toolkit gives the widget the action belongs to, such as `ctrl+x` → cut in a text box), or a call of it from another part of the system.
- **Shown widget** (CTX-SHELL, new). A widget that is displayed, together with every widget that holds it, up to its window.
- **State of a window** (CTX-SHELL, new). An arrangement of a window that the operator reaches through its keys and controls: a tab chosen, a kind chip pressed, a list opened, a notice shown, a lane waiting. A requirement that walks states names them.

## Requirements

### F-33 and F-34 — dialogs and actions (US-I12-1)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-DLG.14 | U | The system shall give every dialog at least one opener. | 1/1 census: every dialog of the system has ≥ 1 opener (a construction of the dialog in another part of the system; a subclass's opener counts for its base); ≥ 21 dialogs censused (21 after the change); 0 dialogs with none | restore `VariantHelpScreen` (the base) → the census names it → RED | US-I12-1 | new (D-1, D-10) | **No** (C: 1 of 22, `VariantHelpScreen`, `screens.py:1091`) |
| R-SHELL-KEYS.3 | U | The system shall give every action at least one reach. | 1/1 census: every action of the system has ≥ 1 reach (a string that is not a docstring naming it as `name`, `name(…)` or `app.name`; a toolkit binding of the class it overrides; a call from another function); ≥ 80 actions censused (80 after the change); 0 with none; the two `action_cut` overrides counted as reached through the toolkit's `ctrl+x` | restore `action_view_mac` (the base) → the census names it → RED | US-I12-1 | new (D-2, D-10) | **No** (C: 2 of 83, `S19TuiApp.action_view_main`, `action_view_mac`; `action_view_alt` reached only from `_jump_to_validation_issue_object`, which no product route calls) |

### F-35 — widgets some state shows (US-I12-2)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-CHKED-058 | U | The system shall show every widget of the Check Editor in at least one state of the Check Editor. | 1/1 walk of the states [opened with the demo A2L; Fields tab; JSON tab; Addendum tab]: every widget of the window that has an id is a shown widget in ≥ 1 state; 0 never shown; ≥ 45 widgets censused (47 after the change); the Addendum tab state shows the addendum preview | restore the hidden `Addendum preview` button (the base) → 1 never shown → RED | US-I12-2 | new (D-3) | **No** (B: 1 of 48 never shown, `#check_preview_toggle_button`) |
| R-TUI-059.25 | U | The system shall show every widget of the Flow Builder in at least one state of the Flow Builder. | 1/1 walk of the states [opened; each of the 7 kind chips pressed; Variables opened; the Add notice shown (Add with an empty image file); 3 LOAD blocks added]: 0 never shown; ≥ 45 widgets censused (48 after the change) | restore any one of the five hidden widgets (the base) → RED | US-I12-2 | new (D-4, D-5) | **No** (B: 5 of 53 never shown: the help sentence, the grid canvas, the numbered list, the kind dropdown, the session line) |
| R-FX-SCR.4 | U | The system shall show every widget of Flow Execution in at least one state of Flow Execution. | 1/1 walk of the states [no lane; `flash_chain` imported; its Run waiting at the external step; the set saved as `s`]: 0 never shown; ≥ 30 widgets censused (34 after the change) | restore the hidden help sentence (the base) → RED | US-I12-2 | new (D-5) | **No** (B: 1 of 35 never shown, `#fx_help`) |

### F-51 — Escape on the Reports dialog (US-I12-3)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-DLG.2 | E | When the operator presses Escape in a dialog while none of its dropdown lists is open, the system shall do what the dialog's Cancel or Close button does. | the Reports dialog, 12/12 (cases R-DLG.2/1 … /12): from each focus place (the report list, the report view, the declared-regions box with typed text, the closed filter dropdown, the filter path box with typed text, the context-bytes box with typed text, Generate, Close, `📂 Open reports/`, `?`) and on the empty dialog, the dialog closes and nothing more changes, as Close (R-DLG.9): 0 new files in `reports/`, the status line as before, the filter selection unchanged; Escape in the help window opened from the dialog closes that window alone | no Escape binding on the dialog (the base) → /1 … /11 RED; Escape bound to Generate's path → /7 writes a report → RED | US-I12-3 | changed (adds "while none of its dropdown lists is open", D-8) | **No** (B: the dialog stays open from 10 of 10 focus places and on the empty dialog; /12 holds) |
| R-DLG.15 | E | When the operator presses Escape while a dropdown list of a dialog is open, the system shall close only that dropdown list. | 1/1: the Reports filter dropdown opened with Enter; after Escape its list is closed and the Reports dialog is still the top screen | the dialog's Escape made a priority binding → the dialog closes with the list open → RED | US-I12-3 | new (D-7, D-8) | **Yes** (B: the list closes and the dialog stays) |

D3-7 (`_jump_to_validation_issue`, `_jump_to_validation_issue_object`, `_format_validation_issue_line`) has no row: the canon has no row for a jump from an issue, and an Issues row selection keeps its one behaviour, the hex peek (S3 R-ISSUES-HEXPANE-001.1, .2, cited and unchanged). The removal is traced through R-SHELL-KEYS.3 (it takes away the only call of `action_view_alt`), as Inc 4 traced D9-7.

### Acceptance

The acceptance cases `AT-I12-1` … `AT-I12-3` of `02-test-cases.md` drive the app through its keys: the Reports dialog closed by Escape from its list, from a filter path typed but not submitted, and after an open dropdown list (R-DLG.2, R-DLG.15); the windows of the removed aliases reached by `1`, `2`, `3` and an Issues row selected (R-SHELL-KEYS.3, with the cited R-TUI-021.3 and R-ISSUES-HEXPANE-001.1); the Addendum tab, a kind chip, Add and the ribbon doing what the removed widgets mirrored (R-CHKED-058, R-TUI-059.25, with the cited R-CHKED-021, R-FB-ADD.1, .3 and R-FB-RIB.2).

## Counts

7 active rows: 6 new (R-DLG.14, R-SHELL-KEYS.3, R-CHKED-058, R-TUI-059.25, R-FX-SCR.4, R-DLG.15), 1 changed (R-DLG.2). Context-note changes: CTX-DIALOG (opener, dropdown list, the Reports row's Esc), CTX-KEYS (action, reach), CTX-SHELL (shown widget, state of a window). D3-7 has no row (above).
