# Inc 12b — E3 rulings (pointer)

The E3 round-1 reviews and rulings for this increment are Inc 12's, written before the split: `../inc-12/E3-architect.md` (its §3 is the split map), `../inc-12/E3-security.md`, `../inc-12/E3-ux.md` and the orchestrator's `../inc-12/E3-rulings.md` (2026-11-06). The correction pass applied the D-5 B split and these rulings here:

| Finding | Ruling (`../inc-12/E3-rulings.md`) | Applied in |
|---|---|---|
| E3A-03 | "with an id" and the population pinned (the driven states named in the row) | R-TUI-059.25, R-FX-SCR.4 (`01-requirements.md`); the State walk fixture and both cases (`02-test-cases.md`); the compose nodes (`codewire/graph-inc12b.md`) |
| E3A-04 + U-1 | Inc 12 owns the DOSSIER marks and `_FIXED`; 12b marks no DOSSIER row | `01-requirements.md` (Docs); `E1-slice.md` §1, §4 |
| E3A-05 | G-T3's re-point list: 39 nodes in 13 files, Inc 9's `_add_load_block` included, on the tree after Inc 9 merges | `E1-slice.md` §5 |
| S-1 | the kind state accepts only `_KIND_OPTIONS` values (a chip id outside them is ignored); a case added | I-2 and `FlowBuilderPanel.on_button_pressed` (graph); `E1-slice.md` §2; case R-FB-ADD.1/2 |
| S-2 | every re-pointed security node keeps its hostile input and its painted-text assertion; E5 mutants `nul_add_refusal → None` and refs painted with `Text.from_markup` | `E1-slice.md` §5 (Security nodes); `02-test-cases.md` (Counts); graph `pipeline_text`, E2-3 |

Round 2 (per `../inc-12/E3-rulings.md`): the architect re-checks E3A-03, E3A-05 and the split here; the security reviewer re-checks S-1 and S-2 here.
