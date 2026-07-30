# Requirements Document — s19_app — Batch 2026-07-30-batch-72

> **Status: DRAFT — Phase 1 awaiting-gate.** Authored by the prototyping session
> (2026-07-30) that ran `/tui-design` for the four 2026-07-28 P1 design defects and got
> the operator's variant verdict. The EXECUTING session presents this at the Phase-1
> gate, then proceeds Phase 2 → 6. Nothing here is implemented yet.

## 1. Introduction

### 1.1 Purpose
Implement the operator-decided redesigns for the 2026-07-28 P1 design defects:
**CRC Designer → prototype Variant B** (paired Reflection row + KAT demoted under Check)
and **Legend modal → prototype Variant B** (two-pane, colour key always visible).
Operator verdict 2026-07-30: *"Ok, CRC viewer vamos con (B). Leyenda, dos paneles. (B)"*.

### 1.2 Scope
- IN: `s19_app/tui/crc_designer_view.py` (compose), `s19_app/tui/screens.py`
  (`LegendScreen.compose`), `s19_app/tui/styles.tcss`, tests. REQUIREMENTS.md rows.
- OUT: engine-frozen files (all — no unfreeze needed); `legend.py` data layer (reused
  untouched); any KAT *removal* (operator chose **demote**); Flow Builder; prototype
  teardown (happens at batch close per convention).

### 1.4 References
- `prototypes/p1_design_defects.HANDOFF-PLAN.md` (decision gates + technical map)
- `prototypes/p1_design_defects.NOTES.md` (brief, state inventory, verdict §7)
- PR #164 (prototypes + frames + review page `p1-design-defects-review.html`)
- `.dev-flow/BACKLOG-CODE.md` lines 149-156 (the four defect bullets, mechanisms measured)
- Batch-59 lineage (`.dev-flow/…batch-59`, merged #113): current bench layout + its ATs

## 2. Overall description

### 2.4 Constraints
- `_recompute` (crc_designer_view.py:1115-1142) queries SIX surface ids
  (`#crc_kat_verdict`, `#crc_custom_vector_result`, `#crc_json_preview`,
  `#crc_warnings`, `#crc_coverage_preview`, `#crc_coverage_window`) and aborts on the
  first `NoMatches` — every id MUST stay mounted. Variant B satisfies this by design.
- AT-B59-03/08 (`tests/test_crc_designer_view.py:895-1312`) assert 3 pairwise-distinct
  bench-column ancestors — Variant B keeps 3 columns, so these survive unedited.
- Legend data layer (`legend.py`) and its escaping rules (S-01 / TC-N8-11) are reused
  verbatim; only `LegendScreen.compose` layout changes.
- C-17: every existing `markup=False` sink stays `markup=False`.

### 2.5 Assumptions and dependencies
- PR #164 (prototypes) merges before or with this batch — the prototype files are
  reference-only inputs, not runtime dependencies of the shipped code.
- Parallel batch-65 (addendum lane) may still be in flight — `state.json` is
  last-writer-wins; the executing session re-reads it at kickoff (RC-1) before edit.

### 2.6 Source user stories

**US-072-1 (CRC Designer, Variant B).** As a firmware engineer operating the CRC
Designer bench, I see the two reflection toggles as one labelled pair on a single row
(each toggle individually legible and separable), and the known-answer self-test as an
annotation of the Check field it validates — so no control reads as another control and
the hero row spends its right column on Warnings.
*Acceptance sketch:* pair row renders `Reflection  in <switch>  out <switch>`; toggling
either changes a rendered state; `Self-test` row sits under `Check` inside the Algorithm
group showing ✓/✗/○; the `#crc_live_verify` hero tile no longer exists; Warnings alone
occupies `#crc_top_right`.

**US-072-2 (Legend modal, Variant B).** As an operator opening the Legend from any
view, I see the colour key beside the example card simultaneously (no scrolling past a
~29-line card to reach the key); at the 80-col floor the modal still shows both, stacked
with the key first.
*Acceptance sketch:* at 120x30 both panes visible, key rows readable without scrolling
the card; at 80x24 panes stack, key above card; MAC warning sample + map band-key branch
render unchanged.

#### Refinement log
- Both stories: `READY`. INVEST: independent (different files), negotiable details
  resolved by the operator's variant pick, valuable (operator-flagged P1), estimable
  (prototyped — the compose/CSS shapes exist in PR #164), small (≤5 files each),
  testable (observable through the pilot surface; ATs below).
- Phase-0 already-shipped check (RC-1): `git fetch` done; origin/main tip `6ba0680`;
  no REQUIREMENTS.md row describes a paired reflection row or a two-pane legend — NOT
  shipped externally.

### 2.7 Premise evaluation (C-43) — executed, not cited

| # | Premise | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| P-1 | Switch fusion mechanism = `.crc-field-switch {border:none;height:1}` + no row margin, two `_switch_row`s stacked | premise | ✅ TRUE | `styles.tcss:1952-1955`, `crc_designer_view.py:301-302` read this session; shipped-state frame `crc_p1.shipped.120x30.bench.svg` shows the fusion | fix via pair row (LLR-072-1.1) |
| P-2 | (Backlog line 153) "any change will drift the CRC snapshot cells" | premise | ❌ **FALSE** | `tests/test_tui_snapshot.py:109-110` — `_RESTYLED_SCREENS=[workspace,a2l,mac,issues]`, `_SCAFFOLD_SCREENS=[map,patch,diff]`; `ls tests/__snapshots__ | grep -ic crc` → 0. CRC screen is NOT snapshot-captured | **No snapshot-regen follow-up PR needed for either story.** Backlog premise corrected at reconciliation |
| P-3 | Legend modal not snapshot-captured (cheapest surface) | premise | ✅ TRUE | same probe as P-2 — modal in no screen list, 0 legend snapshots | zero baseline drift |
| P-4 | `_recompute` queries six ids; deleting any breaks all live surfaces | premise | ✅ TRUE | `crc_designer_view.py:1115-1142` read; also demonstrated in prototype (Variant C had to HIDE, not delete) | Variant B keeps all six mounted |
| P-5 | AT-B59-03/08 assert 3 distinct bench-column ancestors and survive Variant B | premise | ✅ TRUE | `tests/test_crc_designer_view.py:895,907,928,1312` read — teeth are a computed 3-column comparison; Variant B keeps `#crc_bench_c1/c2/c3` | file has 32 tests — full blast-radius re-read owed at Phase 2 |
| P-6 | Reverse census (C-26): touched CRC ids pinned ONLY in `test_crc_designer_view.py`; legend nesting pinned in 3 files | premise | ✅ TRUE | `grep -rl` executed this session: CRC symbols → 1 file; `legend_body/legend_dialog/legend_mac_warning_sample` → `test_legend_n8.py`, `test_legend_scope_and_logwidth.py`, `test_tui_legend.py` | those 4 files ARE the test blast radius; re-grep at Phase 3 per increment |
| P-7 | Variant B renders + computes live on the pin (textual 8.2.8) | hypothesis | ✅ TRUE | PR #164 frames: `crc_p1.variant_B.160x44.loaded.svg` shows live `concat 0x9C5BCBBD` etc.; `legend_p1.variant_B.*.svg` show both panes | prototype code is the shape reference; REWRITE properly (throwaway rule) |
| P-8 | Floor (80x24) legend stacking order = key first | hypothesis | ❓ UNDECIDABLE | operator picked "B — dos paneles" without addressing the floor; prototype B squeezes panes side-by-side at 80 cols (no narrow rule was written) | **PROPOSED default: stack, key first** (the review page's stated hybrid). CONFIRM AT THE PHASE-1 GATE |
| P-9 | Switch-row separability guard is encodable as a pilot AT that fails on the old CSS | hypothesis | ❓ UNDECIDABLE | not yet executed — no AT exists | Phase-3 obligation: counterfactual run on a copy with old CSS (C-40 discharge), transcript pasted |

## 3. High-level requirements (HLR)

### HLR-072-1 — Paired reflection row
The CRC Designer Algorithm group **shall** render the `refin`/`refout` controls as ONE
`Reflection` row: the row label, then per-toggle sub-labels `in` and `out`, each
immediately adjacent to its own `Switch` (`#crc_field_refin` / `#crc_field_refout`, ids
unchanged), such that no two Switch widgets are vertically adjacent anywhere on the
screen.
**Acceptance (black-box): AT-213** — pilot at 120x30: both switches' regions share the
same row band (equal `region.y`); an interleaved label sits between them; toggling
`#crc_field_refin` to a NON-default value (C-10) changes the computed CRC surfaces
(observable: `#crc_custom_vector_result` text changes).

### HLR-072-2 — KAT demoted under Check
The known-answer verdict **shall** render as a `Self-test` row directly below the
`Check` field inside `#crc_algorithm_fields`, preserving the id `#crc_kat_verdict` and
the tri-state glyph tokens (`✓ MATCH` / `✗ MISMATCH` / `○ NO-EXPECTED`); the dedicated
hero tile `#crc_live_verify` **shall** no longer be composed, and `#crc_top_right`
**shall** contain the Warnings group only.
**Acceptance: AT-215** — pilot: `#crc_kat_verdict` has ancestor `#crc_algorithm_fields`;
editing `#crc_field_check` through the surface flips the verdict MATCH→MISMATCH (drives
the real Input.Changed path); `query("#crc_live_verify")` is empty.

### HLR-072-3 — Design guards G-1/G-2 as ATs
The batch **shall** encode: **G-1** — for every pair of vertically-adjacent focusable
controls in the CRC form, their regions do not abut without a ≥1-row gap, border, or
interleaved label; **G-2** — toggling a Switch changes at least one rendered glyph/word
on screen (state legible without color/position).
**Acceptance: AT-214 (G-1), folded into AT-213 (G-2).** C-40 discharge for AT-214:
executed counterfactual on a copy carrying the pre-batch CSS (the shipped fusion) must
go RED; transcript pasted in the increment packet. (P-9.)

### HLR-072-4 — Select chrome cap (affordance-density polish)
`#crc_designer_panel Select` widgets **shall** render at height 3 (no multi-row value
wrap at bench column widths).
**Acceptance: TC-level** (white-box CSS + a pilot height assertion inside AT-213's run).
Rationale measured: shipped Selects wrapped to 5-6 rows at 120x30 (PR #164 first-pass
frames).

### HLR-072-5 — Legend two-pane layout
At terminal widths ≥ the app's wide regime, `LegendScreen` **shall** render the example
card and the colour key side-by-side (card left, key right), each independently
scrollable, with the key's first rows visible on open without any scrolling.
**Acceptance: AT-216** — pilot 120x30, mac view: both panes' first rows visible in the
same frame; the key pane shows the `Pale yellow` row without scrolling the card pane.

### HLR-072-6 — Legend floor stacking, key first *(pending P-8 confirmation)*
At the 80-col floor the panes **shall** stack vertically with the colour key ABOVE the
example card.
**Acceptance: AT-217** — pilot 80x24, mac view: key pane region.y < card pane region.y;
both reachable.

### HLR-072-7 — Data-pipeline preservation
The reorganized modal **shall** reuse the shipped data pipeline unmodified
(`LEGEND_EXAMPLES` role mapping, `_render_key` incl. the map band-key branch) and
preserve the ids `#legend_dialog`, `#legend_close`, `#legend_mac_warning_sample` and the
S-01/TC-N8-11 escaping behavior.
**Acceptance: AT-218** — pilot: mac view warning sample present with its inline orange
style; map view renders band-key rows (`band-*` classes, `markup=False`) in the key
pane; existing legend test files stay green (P-6 blast radius: `test_tui_legend.py`,
`test_legend_n8.py`, `test_legend_scope_and_logwidth.py`).

## 4. Low-level requirements (LLR) — sketch for Phase-2 refinement

- **LLR-072-1.1** `crc_designer_view.py::compose` — replace the two `_switch_row` calls
  (currently :301-302) with the pair row; drop `_switch_row` if orphaned.
- **LLR-072-2.1** `compose` — `Self-test` row after the Check row; delete
  `verdict_group`; hero row = window + `Vertical(warnings_group)`.
- **LLR-072-2.2** `styles.tcss` — retire `.crc-hero` / `#crc_live_verify` rules; keep
  `.crc-field-switch` borderless-1-row (now horizontally separated by design); add
  `#crc_designer_panel Select { height: 3; }` (HLR-072-4).
- **LLR-072-5.1** `screens.py::LegendScreen.compose` — two-pane Horizontal
  (card 3fr | key 2fr) + key-pane heading; dialog width per prototype (96%).
- **LLR-072-6.1** `styles.tcss` — width-narrow rule stacking the panes, key first.
- **LLR-072-7.1** — no `legend.py` edit; compose consumes `_render_card`/`_render_key`
  as shipped (grouping helper allowed in `screens.py` if needed).

## 5. Validation strategy

### 5.1 Methods
All ATs: `test (pilot)` — `App.run_test()` driving the shipped surface. TCs: unit/CSS
structure. No `demo`.

### 5.2 Dual-traceability table (to be completed as TCs land)

| Story | AT (black-box) | HLR | LLR | TC (white-box) |
|---|---|---|---|---|
| US-072-1 | AT-213, AT-214, AT-215 | 072-1..4 | 1.1, 2.1, 2.2 | TC-510..TC-514 (reserved) |
| US-072-2 | AT-216, AT-217, AT-218 | 072-5..7 | 5.1, 6.1, 7.1 | TC-515..TC-519 (reserved) |

**ID allocation (executed census this session):** prior max = AT-212 / TC-509b
(batch-71, confirmed by `grep -rhoE` over REQUIREMENTS.md + tests/ + .dev-flow/).
Allocated: **AT-213..AT-218**, block **TC-510..TC-519 reserved** (executing session
assigns within the block; re-run the census at Phase 3 — a parallel batch may consume
ids).

### 5.3 Batch acceptance criteria
1. All six ATs green through the pilot surface, with AT-214's RED counterfactual
   transcript (old CSS on a copy) pasted.
2. Frozen guards BOTH arms green (C-27); `git diff origin/main -- <frozen set>` empty.
3. Test blast radius re-run: the 4 files from P-6 all green.
4. `pytest -q -m "not slow"` green (Phase-4 run owned by the orchestrator, C-25).
5. REQUIREMENTS.md: new/amended rows for the bench layout (batch-59 lineage §6.5
   Before/After — the verdict-tile row changes) and the Legend layout (N8 lineage).
6. NO snapshot regen expected (P-2/P-3) — if any snapshot fails, STOP: a premise was
   wrong; do not regen casually.

## 6. Appendices

### 6.2 Relevant design decisions (operator, 2026-07-30, verbatim)
> "Ok, CRC viewer vamos con (B). Leyenda, dos paneles. (B) Por favor deja el plan hecho,
> llama /dev-flow para ello y deja todo listo para que otra sesión tome desde ahí para
> llevarlo a término."

Gate-2 of the HANDOFF-PLAN (KAT demote-vs-remove) resolves to **demote** (implied by
picking Variant B whose definition is "KAT demoted"; Variant C was the removal option).

### 6.3 Open risks
- P-8 floor-stacking default awaits operator confirmation at the Phase-1 gate.
- `state.json` last-writer-wins vs the in-flight parallel batch-65 — re-read at kickoff.
- Prototype code is THROWAWAY: rewrite the compose properly (docstring conventions,
  PROJECT_RULES.md section order, type hints) — do not copy-paste `VariantB`.
