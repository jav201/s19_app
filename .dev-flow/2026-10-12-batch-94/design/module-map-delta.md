# Module map delta — s19_app — Batch 2026-10-12-batch-94

> The PDR-promised map-delta: the landed amendments to `docs/architecture.md` that the
> batch's product diff implies. Authored as a plan at ARQ (map §10's header note names it);
> **this copy records the landed delta**, sealed with `DDR-2026-10-12-batch-94`. Each row:
> file · kind · the increment that landed it · the map section it amends · the evidence
> pointer (the increment packet).

| File | Kind | Increment | Map section amended | Evidence (packet id) |
|---|---|---|---|---|
| `s19_app/tui/services/diff_report_service.py` | CHANGED | Inc-001 — the `## Checks` addendum (`_check_addendum_lines` in `generate_diff_report`, the C-42 emitted form) | §10 "Batch-94 declarations — CHANGED `services/flow_*`": the batch-94 CHANGED set named the flow services; this contract-derived touch (LLR-010.2 names `generate_diff_report`) adds the report producer — frozen beyond the addendum hook | `03-increments/increment-001.md` §2 (the SOURCE-file row) + §4 (TC-B94-16's emitted-form paste) |
| `s19_app/tui/flow_screens.py` (+ the moved `FlowBuilderPanel`) | NEW (R8) | Inc-002 — the B2 move: the panel's 759-line vacate of `screens_directionb.py` and its reopening at the R8 address (1 272 lines, fb_a), `app.py`'s import repointed in the same commit | §10 "NEW `s19_app/tui/flow_screens.py`" (declaration header now landed) + the B2 move census note (executed; 13 files post-move, 8 live readers re-pointed in-commit) | `03-increments/increment-002.md` §2/§4 (the B2 vacate row + the reverse-census B1/B2 probes) |
| the allowed edge `flow_screens → services/flow_model` | NEW EDGE (declared) | Inc-002 — the A2B block's type constant/dataclass (`BLOCK_A2B`, `A2BBlock`) landed in `flow_model.py`; the view imports them read-only (`flow_screens.py:71-75`) | §10 "Batch-94 dependency amendments — New edges (allowed, declared)": the declared-edges list gains `flow_screens → services/flow_model` (the view→model posture per `screens_directionb.py`'s historic idiom; the PDR's protection so a future radiografía does not "fix" it) | `03-increments/increment-002.md` §2 (the `flow_model.py` row) + the PDR checklist row 2's declaration |
| `s19_app/tui/issues_view.py` + `s19_app/tui/app.py` | CHANGED | Inc-004 — the US-004 view-level triage seam: `CURATED_STANDARD_A2L_BLOCKS` + the reclassification predicate in the view (+256/−5); the strip/summary/`group_counts` counts fold riding `adjust_counts_for_a2l_triage` in `app.py` (+53/−14) | §10's US-004 seam block (the P1 view-level decision, R12 — landed) + the CHANGED `app.py` declaration (extends to the Inc-004 fold); `issues_view.py` joins the batch-94 CHANGED set; the engine (`rules.py`, `a2l.py`) stays frozen (D-1, the TC-B94-18 byte-check) | `03-increments/increment-004.md` §2 (both SOURCE rows) + §4b (the HLR-012 judgment question answered) |

**Naming flip (carried minor `PDR-2026-10-12-batch-94#ux5`).** The map's batch-94 §10 text
followed the spike shorthand "pe_a/ce_b"; the shipped twins follow the ratified graduation call
**pe_b + ce_a with ce_b folded in** (the contract's HLR-001/003 rationales). The correction
landed in map §10's `screens_directionb.py` declaration (with the ratification parenthetical)
and its two `ce_b` references — discharged here, with this delta's seal.
