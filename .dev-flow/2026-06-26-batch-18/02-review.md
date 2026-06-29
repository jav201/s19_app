# Review — s19_app — Batch 2026-06-26-batch-18

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 2 artifact. Reviewers (in parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer`.

## ✅ Verdict (read first)

- **Gate:** PROCEED to Phase 3 **after iterate-light fold** (0 blockers; 1 major + minors folded).
- **Findings:** 0 blocker · 1 major (MAJOR-1) · 4 minor (m1 line-drift, m2 operationalize thresholds, m3 TC-S2 rendered-rows, m4 C-13 fallback-decide) — architect ∥ qa agreed.
- **shall/should check:** ✓ clean — `shall` in all HLR/LLR statements; `should` only in rationale (architect + qa verified).
- **Two-layer (blockers):** ✓ every story has an AT · HLR-022/023 name deliverable+observation · both chains complete (§5.2) · ATs black-box (report file + Pilot buttons); C-10 content asserted; C-12 (AT-022a observes the produced report).
- **Census (change-first):** done — only frozen file in blast radius is `color_policy.py` (READ-only, never edited; diff=0 + the directionb guard); `legend.py` new/outside all guards; report_service/screens/app.py confirmed outside `_ENGINE_PATHS`.
- **Security:** ✓ no findings — **N/A justified inline** (no new external/write/auth/secret surface; legend is static text derived from existing frozen data; report uses the existing contained write path; modal is read-only). No security-reviewer needed.
- **Evidence checklists (architect / qa):** ✓ both complete.

> If gate = PROCEED and every line is ✓, the Detail below is reference. Any blocker/⚠ → read the matching part.

---

## Detail (reference)

### Findings
| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status |
|----|----------|----------|------------|------|----------------|--------|
| MAJOR-1 | architect | major | LLR-022.1 | frozen-guard mis-citation: `color_policy.py` is frozen by `test_tui_directionb.py::_ENGINE_PATHS` (~:3745) + TC-013a / round-trip, NOT `test_engine_unchanged.py`. The `git diff=0` guard is right; the named authority was wrong. | Cite the directionb guard in LLR-022.1; keep it green. | **folded** |
| m1 | both | minor | LLR-023.2 | `on_button_pressed` cited ~:7481; actual `:7433` (48-line drift). | Correct to :7433. | **folded** |
| m4 | architect | minor | LLR-023.3 | C-13 fallback was "or"-ed (keybinding OR shorten label) — bikeshed risk at gate. | Pre-commit: PRIMARY shorten A2L label, LAST RESORT keybinding. | **folded** |
| m2 | qa | minor | AT-022a / LLR-023.3 | operationalize thresholds: "every row" → assert colour→MEANING pairing (a blank-meaning legend must fail); "0 clipped" → button region ≤ container width + label fully present. | Phase-3 test-authoring note (captured in §5 method). | Phase-3 note |
| m3 | both | minor | TC-S2 | anti-drift should compare the RENDERED row set of each surface (report vs modal), not just that both import the same constant (catches formatting/filtering drift). | Phase-3 TC-S2 authoring note. | Phase-3 note |

### shall / should check
> Any modal `should` / `debería` inside an HLR/LLR statement is a writing error → blocker.

`<result>`

### Two-layer acceptance review (blockers)
> (a) every story has a black-box `AT`; (b) every output-producing requirement names its observable deliverable + observation method; (c) BOTH traceability chains complete (behavioral US→AT→outcome + functional US→HLR→LLR→TC); (d) each `AT` is genuinely black-box — drives the surface, asserts the outcome, references NO internal symbol.

| Story / Req | (a) AT present | (b) deliverable+method named | (c) both chains | (d) black-box pure | Status |
|-------------|----------------|------------------------------|-----------------|--------------------|--------|
| US-001 | yes/no | yes/no/n/a | yes/no | yes/no | ✓ / blocker |

### Supersession census (change-first)
> Planned new/moved/edited files checked against EVERY guard family (behavioral-placeholder · structural/placement · AST-composition · engine-frozen). State reservations; the increment gate is the completeness guarantee, not this census.

`<files × families run · reservations · what the I-gate must confirm>`

### Security review summary
`<security-reviewer findings + verdict, or "no attack surface this batch">`

### Evidence checklists (full) — architect · qa-reviewer · security-reviewer
> Attach each reviewer's completed evidence checklist (items in their agent files), ✓/✗ + one-line evidence.
