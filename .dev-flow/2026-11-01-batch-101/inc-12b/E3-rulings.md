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

Round 2 results (`../inc-12/E3-architect.md`, `../inc-12/E3-security.md`, §Round 2): architect **PASS-WITH-NOTES** for 12b (E3A-03, E3A-05 and the split verified; note E3A-R2-4); security **PASS-WITH-NOTES** (S-1, S-2 closed; S2-1, S2-2 LOW). The round-2 correction applied these rulings here:

| Finding | Ruling (`../inc-12/E3-rulings.md` §Round 2) | Applied in |
|---|---|---|
| E3A-R2-4 + S2-1 | each I-3 grep pins `git grep -w` on the bare ids and names, narrows `_layout` to `FlowBuilderPanel`, and lists the expected remaining lines | graph I-3 (two commands; expected output empty; base 145 lines, and 2 + 0); `E1-slice.md` §5 (no re-pointed line spells a removed id; a hidden-is-hidden assertion drops, the walks carry it; the integration step) |
| S2-2 | a re-pointed hostile input stays whole when it fits a card; otherwise it keeps one of each hostile kind (markup tag, C0 / C1 / DEL bytes, sentinel) | `E1-slice.md` §5 (Security nodes); graph I-4, `pipeline_text`, E2-3 |

No count moves: 2 rows, 4 cases, 17 nodes, 3 entities, 7 edges. Per the ruling, E3 closes for 12b after this pass (`../inc-12/E3-rulings.md`).
