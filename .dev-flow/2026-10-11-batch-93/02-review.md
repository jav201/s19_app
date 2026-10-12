# Review — s19_app — Batch 2026-10-11-batch-93

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 2 artifact. Reviewers (in parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer` by trigger family C (always in `full`).

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/review-template.md` explains each field below and the rules that read it. It ships with the flow and is not copied into this batch.

## ✅ Verdict (read first)

- **Gate:** `approve` → Phase 3 (P3+ holds for batch-92's merge per the standing authorization)  /  `iterate-to-refine` → Phase 1 (blockers present, or a requirement-defect major)
- **Out-of-scope findings:** 2 named and routed below  /  `none`

- **Findings:** 0 blocker · 0 major · 4 minor
- **shall/should check:** ✓ clean  /  ✗ misuse (blocker)
- **Two-layer (blockers):** ✓ every story has an `AT` · output reqs name deliverable+observation · both trace chains complete · ATs are genuinely black-box  /  ✗ `<which>`
- **Census (change-first):** done — best-effort + gate-confirmed  /  ⚠ incomplete   (NEVER stamp "VERIFIED COMPLETE")
- **Security:** ✓ no findings  /  ⚠ `<N>` findings
- **Evidence checklists (architect / qa / security):** ✓ all complete  /  ✗ `<missing>`

> If gate = `approve` and every line is ✓, the Detail below is reference. Any blocker/⚠ → read the matching part.

---

## Detail (reference)

This is the coordinator-lens P2 self-review of the Phase-1 contract
(`01-requirements.md` + `01-requirements-ledger.md` + the PLAN header). The three reviewer
lenses (architect ∥ qa ∥ security) ran inside it; each checklist is below. Verdict:
**approve** — the contract is internally consistent, every chartered number is re-derived
with its method stated, the two-layer chains close, and the interlock is verified against
the shipped tree rather than assumed.

### Findings
| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status |
|----|----------|----------|------------|------|----------------|--------|
| F1 | coordinator | minor | charter shorthands | The charter named "R-TUI-072/073" as the glance block's row and left the chips' `share%` unstated; the contract corrects both (glance = `R-TUI-061`; share = mapped-BYTE share, the only reading summing to 100 on the capture) | corrections recorded in LED-2026-10-11-batch-93.1; P3 implements the corrected text | fixed (in the ledger) |
| F2 | coordinator | minor | HLR-126 / LLR-126.3 | The variant-C capture does not glyph-render the region-list scrollbar; the contract asserts it behaviorally (scroll reachability + DOM presence) | P3's AT-289 asserts behavior, not a glyph; the capture limitation is declared here so nobody "fixes" the contract against the SVG | open — declared |
| F3 | coordinator | minor | LLR-127.3 / LLR-129.2 / LLR-131.1 | The ~43- and ~84-panel-column thresholds remain charter-measured; P3 re-measures them pilot-style and records the values | the constants in the contract follow the P3 measurement (increment packet) | open — punted to P3 |
| F4 | coordinator | minor | LLR-129.1 | The compact stats form's exact wording below the threshold is unwritten (the contract fixes the seven statistics and the field order only) | P3 finalizes wording within the contract's field list; the full/compact switch itself is contracted | open — punted to P3 |

**Out-of-scope findings (named and routed):**
1. Map variants A/B and legend B — evaluated and not chosen by the operator 2026-08-06;
   routed: nothing registered, nowhere (the charter's own ruling).
2. The entropy sparkline + histogram bars retire from the always-on surface with the
   glance block (charter S-5) — routed: no replacement is chartered or required; if the
   operator wants the profile back, that is a new item for BACKLOG, not this batch.

**A worked example — text to read, never rows of your record.** It sits in a fence so that nothing has to be deleted: a row copied out of it would claim a finding nobody raised. Write your own rows in the table above.

```text
| *(example)* F1 | architect | blocker / major / minor | | | | open / fixed |
```

### shall / should check
> Any modal `should` / `debería` inside an HLR/LLR statement is a writing error → blocker.

✓ clean — every HLR/LLR statement is normative `shall`; the only `should` occurrences sit
in explicitly informative fields (Rationale) and in the refinement-log guidance, which the
template itself authors. LLR-129.3's "consistent with the region list" is a consistency
clause, not a modal.

### Two-layer acceptance review (blockers)
> (a) every story has a black-box `AT`; (b) every output-producing requirement names its observable deliverable + observation method; (c) BOTH traceability chains complete (behavioral US→AT→outcome + functional US→HLR→LLR→TC); (d) each `AT` is genuinely black-box — drives the surface, asserts the outcome, references NO internal symbol.

| Story / Req | (a) AT present | (b) deliverable+method named | (c) both chains | (d) black-box pure | Status |
|-------------|----------------|------------------------------|-----------------|--------------------|--------|
| US-125 (HLR-125/126/128/133) | yes — AT-287/289/295 | yes — the `#screen_map` surface, observed via run_test pilots | yes — US→HLR→LLR-125.1..133.1 closed; US→AT closed | yes — outcomes on the rendered surface; internals appear only in Layer-A TCs | ✓ |
| US-126 (HLR-129) | yes — AT-288/294 | yes — the stats/chips lines, observed in the visible viewport | yes | yes | ✓ |
| US-127 (HLR-127/130/131) | yes — AT-290/291/292 | yes — parsed row offsets, the audit report, the regime render | yes | yes | ✓ |
| US-128 (HLR-132) | yes — AT-293 | yes — the `k`-legend modal, observed rendered + Esc | yes | yes | ✓ |

### Supersession census (change-first)
> Planned new/moved/edited files checked against EVERY guard family (behavioral-placeholder · structural/placement · AST-composition · frozen-module). State reservations; the increment gate is the completeness guarantee, not this census.

This increment is documentation-only (the four artifacts under
`.dev-flow/2026-10-11-batch-93/` — no source/test touched). The planned P3 file set is
censused change-first with reservations: `s19_app/tui/screens_directionb.py`
(`MemoryMapPanel` compose/render + builders — behavioral re-render, no engine touch),
`s19_app/tui/app.py` (`_compose_screen_map` host only — the `CommandBar` mount at
`app.py:1894-1895` is NOT in this batch's diff per HLR-133), `s19_app/tui/screens.py`
(LegendScreen map path), `s19_app/tui/legend.py` (map-authored data), `s19_app/tui/styles.tcss`
(map/legend rules), `tests/test_tui_map_big.py` / `test_map_click_chain.py` /
`test_memmap_entropy_merge.py` / `test_legend_n8.py` (assumption adaptations — behavior
oracles preserved by LLR-127.4/LLR-126.4), the new wrap-audit module, and the registry
rows. **Reservations:** (1) the engine-frozen set (`color_policy.py`, `range_index.py`,
the `_ENGINE_PATHS` list) must not appear in the batch's diff — the symbol-count law
consumes them read-only; (2) `entropy_service.ENTROPY_BANDS` and
`entropy_style.ENTROPY_BAND_LABELS` stay byte-identical (LLR-127.2); (3) snapshot golden
regen is CI-only — no `__snapshots__` edit may ride this batch's diff. The I-gate must
confirm the intersection with batch-92's merged diff is empty before P3 starts.

### Security review summary
✓ no findings. The batch is a presentational re-render of already-sanitized loader facts:
B3 is preserved (no file-derived text in bar/chips/rows/stats; the peek renders bytes
`markup=False`), the only untrusted-text surface today (the inspector's A2L-symbol naming
in `build_detail_text`) is *replaced* on this screen by a byte-only peek — a narrowing,
not an expansion. Legend content: the band rows stay `markup=False` with literal `[lo,hi)`
brackets (TC-N8-11 precedent preserved); the new map-authored legend data must route
through the same escaping discipline the N8 lines established (LLR-132.4's live-source law
removes the drift class, and the role/escape guard suite stays green). No new input
surface, no persistence, no network.

### Evidence checklists (full) — architect · qa-reviewer · security-reviewer
> Attach each reviewer's completed evidence checklist (items in their agent files), ✓/✗ + one-line evidence.

- **architect:** ✓ the IFC has one FLOW block, one owner per node, and Part B answered; ✓
  the batch-77 direction is carried untouched (every LLR says preserved/untouched where it
  applies); ✓ the amendment targets are the correct canon rows (HLR-113, R-TUI-061,
  R-TUI-073) with verbatim Before text; ✓ the interlock is verified against the shipped
  tree (grep evidence P-2), not assumed from the charter's sequencing clause.
- **qa-reviewer:** ✓ every AT names its counterfactual (the shipped render / the injected
  line / the stale width); ✓ the wrap audit's own vacuity is contracted (LLR-130.2 — an
  audit that cannot fail proves nothing); ✓ the negative controls are executable RED on
  today's tree (alignment on single-space rows, one-line stats on `build_stats_text`,
  peek format on `_region_hex_peek`, stats visibility at 120×36); ✓ boundary catalogs
  tick empty/boundary/error classes where they apply; ✓ the chips-sum threshold (100 ±
  0.5) is discriminating, not presence-only.
- **security-reviewer:** ✓ B3 + markup=False preserved and narrowed (see the summary); ✓
  no `_nodes`/`_context` shadowing clause carried; ✓ no new dependency, no network, no
  persistence; ✓ the legend's escaping discipline (N8 roles + TC-N8-11) stays the law for
  the new authored data.
