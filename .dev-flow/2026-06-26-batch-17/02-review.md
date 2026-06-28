# Review — s19_app — Batch 2026-06-26-batch-17

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 2 artifact. Reviewers (in parallel): `architect` ∥ `qa-reviewer` ∥ `security-reviewer`.

## ✅ Verdict (read first)

- **Gate:** PROCEED to Phase 3 **after iterate-light fold** (0 blockers; 1 major + 3 actionable minors to fold into the spec first).
- **Findings:** 0 blocker · 1 major (M1) · 4 minor (m2, F-1, F-2, F-3; m3/m4 cosmetic)
- **shall/should check:** ✓ clean — `should` only in preamble/rationale, none inside any HLR/LLR statement (architect-verified).
- **Two-layer (blockers):** ✓ every story has an AT · output reqs name deliverable+method · both chains complete · ATs genuinely black-box (qa-verified: AT-019b honours C-10+C-12; all numeric thresholds objective).
- **Census (change-first):** done (best-effort + gate-confirmed). Frozen-set: all targets (styles.tcss, screens.py, crc.py, app.py) OUTSIDE the frozen set; LLR-021.1 only READS validation/model.py (frozen-read). io.py NOT edited.
- **Security:** ✓ MANDATORY sign-off **GRANTED** — 0 HIGH/MED; 3 LOW confirmations (US-019 width is record-formatting only, no new write/path surface; US-020a render bounded by MAX_HEX_ROWS; US-020b reads scrubbed/typed fields only). Keep width a closed-enum int, never free-text.
- **Evidence checklists (architect / qa / security):** ✓ all complete.

> If gate = PROCEED and every line is ✓, the Detail below is reference. Any blocker/⚠ → read the matching part.

---

## Detail (reference)

### Findings
| ID | Reviewer | Severity | Area / Req | What | Recommendation | Status |
|----|----------|----------|------------|------|----------------|--------|
| M1 | architect | **major** | LLR-019.1 / §6.4(a) | "Option B (screen state)" is unimplementable as phrased: the width selector lives on `ConfirmWriteScreen` (a `ModalScreen[bool]`) but the consumer `_on_confirm_write` runs on `OperationsScreen` AFTER the modal is dismissed → it cannot read the modal's `_crc_saveback_width`. | Adopt **Option C** (truest US-015 mirror): `ConfirmWriteScreen` carries its own `_crc_saveback_width` + dismisses with a width-bearing result (custom `ConfirmWriteDecision(confirmed, bytes_per_line)` message OR a 2-tuple), consumed by `_on_confirm_write`. Pin ONE screen + ONE carry mechanism in LLR-019.1 + §6.4. | **fold** |
| m2 | architect | minor | LLR-021.1 | contract-touch census misses a 5th `7-tuple` site: `app.py:4957` (`_populate_issues_datatable` docstring) — code is cell-count-agnostic but the docstring goes stale after 7→8. | Add app.py:4957 to LLR-021.1's move-together enumeration (docstring-only update). | **fold** |
| F-2 | qa | minor | LLR-020.2 | edit-site citation conflates the `on_data_table_row_selected` dispatcher (app.py:4433, routing only) with the real render site `_jump_to_validation_issue_object` (app.py:4771, where the 3 hex updates + the missing no-address clear live). | Re-point LLR-020.2 edit site to `_jump_to_validation_issue_object` (app.py:4771); dispatcher untouched. | **fold** |
| F-1 | qa | minor | AT-018 | RED-on-main pre-state asserted as prose, not an executed/recorded measurement (geometry confirms ~54<81 at 120 cols). | Phase 3: run AT-018 on `main`, record measured `#ws_center.region.width`. | Phase-3 note |
| F-3 | qa | minor | AT-021 | index-alignment guard implied, not mandated as a single-run two-row assertion. | Phase 3: assert bare issue Related==`-` AND artifacts issue contains both tokens in the SAME pilot run. | Phase-3 note |
| m3 | architect | cosmetic | §6.4 | use_precomputed citation 4915-4928 → branch body is 4919-4928. | tighten or leave. | noted |
| m4 | architect | cosmetic | — | color_policy.py is in CLAUDE.md frozen list but covered by the 2nd guard, not `_ENGINE_PATHS`; moot (no LLR targets it). | none. | noted |

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
