# Inc 12b — Every widget of the Flow Builder and Flow Execution shown in some state: requirements (E1, split from Inc 12 at E3)

Batch 2026-11-01-batch-101, increment 12b. Records written at base `2d1e2b1` (branch `b101-inc12`; product tree `e07fb00`). E4 starts from main once Inc 9 has merged (Inc 9 rewrites the same `flow_screens.py` module docstring and adds the test helper `_add_load_block` that reads `#flow_kind`, E3A-05), in parallel with Inc 10a and 10b; 12b merges before Inc 12, which stays last in the `app.py` chain. Stage E1 of the design-first flow (`dev-flow-v3-beta`), split from Inc 12 by ruling D-5 B (`../inc-12/E1-rulings.md`, orchestrator rulings) and applied at the E3 correction (`../inc-12/E3-rulings.md`).
Findings: F-35, the Flow Builder half (`#flow_kind`; `docs/user-guide/DOSSIER.md:744`), with the requirement-session code change D16-6 (`s19w/review/CODE-CHANGES.md`). Decisions: `E1-rulings.md` (history: `../inc-12/E1-rulings.md`, `../inc-12/E3-rulings.md`). Slice: `E1-slice.md` (one source file, `s19_app/tui/flow_screens.py`). Test cases: `02-test-cases.md`. Graph: `codewire/graph-inc12b.md`. Evidence of the reproduction: `../inc-12/evidence-e1/i12e1-pilot-transcript.txt` (B lines 17-27) and `../inc-12/evidence-e1/i12e1-census-transcript.txt` (C).

Form column: U = ubiquitous. "Base" column: what `e07fb00` does today. B = the E1 pilot (the app driven headless; Linux, Python 3.11.18, textual 8.2.8); C = the E1 census; R = read in the code, not run. Rows moved from Inc 12 keep their ids; their text changes only as E3A-03 rules ("with an id", the population pinned).

## User stories

### US-I12b-1 — every widget of the Flow Builder and Flow Execution is shown in some state (F-35, the `#flow_kind` half; D16-6)
As the maintainer, I want the Flow Builder and Flow Execution to hold only widgets that some state of the window shows, so that no hidden copy of the screen is repainted on every change and no test proves a behaviour on a widget the operator never sees. (Split at E3 from Inc 12's US-I12-2, which keeps the Check Editor.)

## Definitions (additions to CTX-SHELL; terms only; identical text in `../inc-12/01-requirements.md`)

- **Shown widget** (CTX-SHELL, new). A widget that is displayed, together with every widget that holds it, up to its window.
- **State of a window** (CTX-SHELL, new). An arrangement of a window that the operator reaches through its keys and controls: a tab chosen, a kind chip pressed, a list opened, a notice shown, a lane waiting. A requirement that walks states names them.

Whichever of Inc 12 and Inc 12b merges first folds these two terms into the canon; the other cites them.

## Requirements

### F-35 and D16-6 — the Flow windows' widgets some state shows (US-I12b-1)

| Id | Form | Requirement | Threshold | Negative control | US | Status | Base |
|---|---|---|---|---|---|---|---|
| R-TUI-059.25 | U | The system shall show every widget with an id of the Flow Builder in at least one state of the Flow Builder. | 1/1 walk of the states [opened; each of the 7 kind chips pressed; Variables opened; the Add notice shown (Add with an empty image file); 3 LOAD blocks added]: the population is the union of the ids mounted in the window in any of these states; every id of it is a shown widget in ≥ 1 state; 0 never shown; ≥ 45 ids in the population (48 after the change) | restore any one of the five hidden widgets (the base) → RED | US-I12b-1 | new (D-4, D-5; moved from Inc 12 at E3, id unchanged; "with an id" and the population pinned, E3A-03) | **No** (B: 5 of 53 never shown: the help sentence, the grid canvas, the numbered list, the kind dropdown, the session line) |
| R-FX-SCR.4 | U | The system shall show every widget with an id of Flow Execution in at least one state of Flow Execution. | 1/1 walk of the states [no lane; `flash_chain` imported; its Run waiting at the external step; the set saved as `s`]: the population is the union of the ids mounted in the window in any of these states (the lane widgets mount on the import); every id of it is a shown widget in ≥ 1 state; 0 never shown; ≥ 30 ids in the population (34 after the change) | restore the hidden help sentence (the base) → RED | US-I12b-1 | new (D-5; moved from Inc 12 at E3, id unchanged; "with an id" and the population pinned, E3A-03) | **No** (B: 1 of 35 never shown, `#fx_help`) |

### The kind state takes only a block kind (E3 S-1; cited rows)

Removing `#flow_kind` (D-4 A) removes the check its options gave: the hidden select refused any value outside `_KIND_OPTIONS`. The panel's kind is therefore written only with a value of `_KIND_OPTIONS`; a press from a button whose id has the chip prefix `flow_palette_` but names no kind is ignored. The cited canon rows R-FB-ADD.1 (a kind chip shows only its kind's inputs) and R-FB-ADD.3 (Add appends a block of the chosen kind) are unchanged; the robustness case R-FB-ADD.1/2 of `02-test-cases.md` checks the guard (the S16 matrix holds R-FB-ADD.1/1 only, `s19w/test-cases/final/doc/S16-test-cases.md`).

### Docs

Inc 12b marks no DOSSIER row and edits no user-guide passage (E3 ruling E3A-04 + U-1): Inc 12 owns the marks F-33, F-34, F-35, F-51 and the pinned set `_FIXED`, and marks F-35 because it merges after 12b. If the merge order ever flips, the increment that merges second marks F-35.

### Acceptance

The acceptance case `AT-I12b-1` of `02-test-cases.md` (the Flow Builder half of Inc 12's former AT-I12-3) drives the app through its keys: a kind chip, Add and the ribbon doing what the removed hidden kind dropdown and session line mirrored (R-TUI-059.25, with the cited R-FB-ADD.1, .3 and R-FB-RIB.2).

## Counts

2 active rows: 2 new, both moved from Inc 12 with their ids (R-TUI-059.25, R-FX-SCR.4). Cited canon rows that get a case here: R-FB-ADD.1 (the S-1 guard). Context-note changes: CTX-SHELL (shown widget, state of a window; identical in Inc 12).
