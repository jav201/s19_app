# Inc 12b — E1 rulings (split from Inc 12 at E3)

History: Inc 12 was split by the orchestrator's ruling D-5 B (`../inc-12/E1-rulings.md`, orchestrator rulings) and the split was applied at the E3 correction (`../inc-12/E3-rulings.md`; `../inc-12/E1-rulings.md` §7). This file points to the decisions that apply here; it repeats none of their reasoning.

## 1. Scope and what the operator can notice

In: F-35's Flow Builder half (`#flow_kind`) and D16-6 (the hidden help sentences `#flow_help` and `#fx_help`, the grid canvas `#flow_canvas`, the numbered list `#flow_blocks` and the session line `#flow_ext_session`, with their painters), reproduced in Inc 12's E1 (`../inc-12/E1-rulings.md` §1 and §4; B lines 17-27). Moved from Inc 12 with ids unchanged: R-TUI-059.25, R-FX-SCR.4 and their cases R-TUI-059.25/1, R-FX-SCR.4/1; the Flow Builder half of AT-I12-3 becomes AT-I12b-1; Inc 12's US-I12-2 is split, its Flow half becoming US-I12b-1.

What the operator can notice: nothing. Each removed widget was set to `display = False` at compose or mount and never shown again, and each one's work has a visible owner (the kind chips with their kind tag, the pipeline cards, the ribbon, the `?` help body; `../inc-12/E3-ux.md`, Verdict). What changes underneath: no hidden canvas or list is repainted on a chain change (B lines 23-24), and the tests that read hidden widgets read the visible ones.

## 2. Decisions that apply (all in `../inc-12/E1-rulings.md`)

| Decision | Ruling | Applies here as |
|---|---|---|
| D-4 | **A** — `#flow_kind` removed; the kind is `FlowBuilderPanel._kind`, set by the chips | I-2 of `codewire/graph-inc12b.md`; with the E3 S-1 guard (only a value of `_KIND_OPTIONS`) |
| D-5 | **B** — Inc 12b takes `flow_screens.py` alone; E4 starts once Inc 9 merges, in parallel with Inc 10a/10b; Inc 12 stays last in the `app.py` chain | this folder; merge order Inc 9 → 12b → Inc 12 |
| D-10 | **A** — census rows; for 12b the widget walks R-TUI-059.25 and R-FX-SCR.4 | `02-test-cases.md` (State walk, population pinned per E3A-03) |

Not applicable here (Inc 12's): D-1, D-2, D-3, D-6, D-7, D-8, D-9.

## 3. Canon changes (forwarded to the requirements session)

| Row or note | Change | Reason |
|---|---|---|
| R-TUI-059.25, R-FX-SCR.4 | new (moved from Inc 12; ids checked unused at Inc 12's E1); "every widget with an id", the population pinned (E3A-03) | D-4, D-5, D-10 |
| CTX-SHELL (S6) | new terms *shown widget*, *state of a window*, identical to Inc 12's text | the first of Inc 12 and 12b to merge folds them; the other cites them |
| CODE-CHANGES D16-6 | done at 12b's integration | — |

Cited and unchanged: R-FB-ADD.1, .2, .3 (the kind chips and Add, which carry `#flow_kind`'s function; R-FB-ADD.1/2 checks the S-1 guard), R-FB-RIB.2 (the ribbon carries `#flow_ext_session`'s), R-FB-RIB.3 and R-FB-PIPE.1 (the visible pipeline the re-pointed tests move to), R-TUI-059.21 and R-FX-SCR.2 (part order; hidden widgets are not parts).

## 4. Interfaces and pinned notes

- **Inc 9** (merges first): the module docstring of `flow_screens.py` (adjacent hunks); its helper `_add_load_block` in `tests/test_b101_flow_names_ui.py` reads `#flow_kind` and is re-pointed here (E3A-05, 3 nodes).
- **Inc 12** (merges after 12b): no code edge; DOSSIER F-35 and `_FIXED` are Inc 12's; 12b marks no DOSSIER row (E3A-04 + U-1).
- **Pinned for the in-flight testers (Inc 9, 10a, 10b):** after Inc 12b there is no `#flow_help`, `#flow_canvas`, `#flow_blocks`, `#flow_kind`, `#flow_ext_session` or `#fx_help`; tests pick a block kind with its chip `#flow_palette_<kind>`, and read the chain from `#flow_pipeline` and the session from `#flow_name_strip`.

## 5. Backlog

| Id | Item | Source |
|---|---|---|
| BL-I12b-1 | Pre-existing layout defect (same on base `2f54c7d`): at 120x30 the Flow Builder rail's content is 92 wide with no card and 90 from the first card, because `#flow_panel` gains a vertical scrollbar and `FlowBuilderPanel._apply_layout` does not re-run (keyed on the panel's resize/show). Cards stay sized for 92 and paint 92 cells, so the rail scrolls sideways by 2. Fix idea: re-run the layout pass when `#flow_pipeline_scroll` resizes. Not asserted by AT-B94-15 / TC-B94-20, which bound by the pre-card width (92). | E5-corrective-notes E-1, R-1 |
