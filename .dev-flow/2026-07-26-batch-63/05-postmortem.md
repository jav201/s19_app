# batch-63 — post-mortem

> **BLUF: the batch shipped 4 production lines and produced FIVE vacuous acceptance criteria for the
> same defect — three of them written after the batch had already diagnosed vacuity as its own theme,
> and three of those five were mine.** The reusable output is not the fix. It is that *"can this
> predicate go RED on the unfixed tree?"* is a different question from *"is this predicate correct?"*,
> and every gate in this batch that asked only the second one passed something that verified nothing.

**Merged:** PR [#139](https://github.com/jav201/s19_app/pull/139), squash `c473152`. `main` `031ca8d` → `c473152`.
**Shipped:** D3 only (R-TUI-097). **Returned to backlog:** D1, D2.

---

## 1. What worked

- **Fixing the ID ranges before dispatching parallel authors.** It did not work *enough* (see §2), but
  it converted an invisible failure into a visible one: the collision was found by all three Phase-2
  lanes in the first round instead of surfacing at Phase 4.
- **Executing every threshold before promoting it (C-39).** Six numbers in the inherited spec were
  wrong or underivable. The undercount was `N-2`, not the `N-1` **both** REV-5 lanes wrote; the
  golden-neutrality claim flagged `assumed` turned out true but had never been measured; the headline
  `~559.7 GB` could not be re-derived because its input triple was never stated.
- **Briefing reviewers to attack the orchestrator's own rulings.** The instruction *"do not accept this
  because I made it"* produced the batch's single most valuable finding — the refutation of M-7.
- **Auditing the discharge against the SOURCE reviews rather than the amendment table.** This is the
  batch-62 lesson reapplied, and it caught two discharges I had claimed and not performed.
- **Two rounds of post-0-HIGH folds.** Both reviewers said OK-TO-MERGE on the first pass. Holding
  anyway found a census that missed this repo's own `Path.open("w")` idiom — in the one check the
  merge gate can actually run.

## 2. What did not work

**The scope ruling was accepted as a spec.** `01-requirements-rescoped.md` was an operator-approved
*scope decision* with zero HLR/LLR/AT/TC, and the resume checkpoint said "next: Phase 2 re-gate". Had
I re-gated it as written, three reviewers would have blocked on "no acceptance criteria". Phase 1
had to be re-derived, costing an iteration before any work began.

**Fixing ID ranges is not fixing IDs.** I fixed the *ranges* and told the operator the REV-4 collision
was "removed by construction". Both authors then filled the same range with different content: 9–10
of 12 AT ids and ~26 of 40 TC ids bound to different observables. The claim was falsified by all three
lanes independently.

**The consolidation fixed the collision by destroying the coverage.** All three reviews attached the
same condition — *keep the union, drop nothing, add don't substitute*. My revision-3 fold replaced a
40-row TC layer with three id ranges, dropped 8 of ~18 union observables, and substituted away the AST
structural census the architect had explicitly said to **add**. That census is the only D3 check CI can
run.

**Phase 5 and Phase 6 never ran until sync caught it.** I went from Phase 4 to PR to merge. The merge
itself was properly gated, so no defect shipped — but this document and `06-docs/` exist only because
`/dev-flow-sync`'s pre-check refused to sync an incomplete record. The flow's own backstop worked; the
orchestrator's sequencing did not.

## 3. The five vacuous acceptances

The batch's founding thesis is *a document must not assert what it does not honour*. It produced five
predicates that asserted verification they did not perform:

| # | predicate | why it could not fail | author |
|---|---|---|---|
| 1 | `len(join) == _line_bytes - 1` (guarded to N≥1) | function of `_line_bytes` and `join` only — the writer is not in the expression | Phase-1 qa lane |
| 2 | `_line_bytes >= len(join)` | same, and weaker | Phase-1 architect lane |
| 3 | `_line_bytes == len(report_bytes) + 1` | same again — I fixed *bindability*, not *blindness to the writer* | **orchestrator (M-7)** |
| 4 | `AT-165` "every producing class is represented" | tests the concatenation shape, not the evidence: GREEN under all three eviction attacks | **orchestrator (rev-3 fold)** |
| 5 | `AT-193b` offending list | shaped to the DETECTOR, so it certified a completeness the detector lacked | **orchestrator (closeout)** |

The pattern: #1 and #2 disagreed about *which arithmetic form is valid at N=0* and neither asked
whether either could fail. I diagnosed that correctly and then authored #3 with the same blind spot.
#5 is the sharpest: a positive control written to confirm a detector, using cases the detector already
handled.

**Rule extracted:** a positive control must be shaped to the RULE, never to the implementation it
certifies. Deriving its cases from what the detector currently catches makes it a tautology.

## 4. Numbers I carried instead of re-deriving

Three, all mine, all caught by review:

- **`+44 lines`** — correct at `e978d2a`; the closeout added 3 more and I copied. Measured `+47`.
  This violated the very rule (m-3) that the same commit introduced.
- **`three of those TC ids diverge`** — measured: **all ten** of `TC-470..479`, understated 3.3×.
- **`D2 CRASHES the tool`** — `app.py:4034` catches the `ValueError`. It is a report *denial* plus an
  error misclassified into the operator-input-rejection branch. My probe called the service directly,
  bypassing the handler: **C-35 applied to my own measurement.**

## 5. Scope drift

Deliberate and operator-ruled at every step, but large: the batch began as *"cap two unbounded
tables"*, grew to twelve unbounded axes with two competing designs, was split to three shipped-code
defects, and finally shipped one. Each reduction was evidence-driven — but the batch consumed its
Phase-1 and Phase-2 iteration caps before shipping 4 lines.

**The signal to keep:** every reduction was triggered by measurement, not fatigue. D1 was returned
because its two HIGH findings depend on bounding neighbouring tables (batch-64); D2 because it carried
three unfixed predicate defects. Neither was dropped for being hard.

## 6. Metrics

| | |
|---|---|
| Iterations | P1 ×3 · P2 ×3 (both hit the soft cap, both escalated to the operator) |
| Blockers found | 10 at re-gate #1 · 0 HIGH at every merge gate |
| Findings folded post-0-HIGH | 4 (round 1) + 7 (round 2) |
| Production lines | 4 |
| Tests | 2192 → 2201 (+9), 0 regressions |
| Frozen-engine diff | 0 |

## 7. Items for the next batch

1. **`OB-2` — the missing AT/TC registry.** Root cause the operator identified; measured: "next free
   TC id" = **345 / 398 / 479** depending on which subset you grep. 73 % of live AT ids and 52 % of TC
   ids unregistered; **6 phantom TC ids**, including `TC-319` — the node `CLAUDE.md` cites as C-26's
   origin, removed without the registry noticing. Deliberately not pulled into this batch.
2. **D1** and **D2**, with their full attack analyses already recorded in `BACKLOG.md`.
3. **`OB-4`** — the resident-memory axis, operator-confirmed carry with numbers.
4. **`OB-3`** — `diff_report_service`'s two text-mode writers (no budget, so not D3).

## 8. Control candidates raised — NONE encoded (awaiting operator)

Per `feedback_devflow_control_encode_approval`, nothing is encoded without an explicit
AskUserQuestion.

- **P-5 — "can it go RED?" is a distinct gate question from "is it correct?"** Every acceptance must
  state, at authoring time, the mutation that turns it RED, and that mutation must be *executed*.
  Five vacuous predicates in one batch, three written after vacuity was already the batch's theme.
  Placement: agnostic → global `/dev-flow`. **This is the one I would raise again.** C-31 covers a
  vacuous input *set*; C-10 covers a vacuous *assertion* found by mutating code. Neither covers a
  predicate that is correct, non-vacuous in form, and simply does not mention the thing under test.
- **P-6 — a positive control must be shaped to the RULE, not to the implementation.** Narrower than
  P-5 and arguably subsumed by it; raised separately because `AT-193b` shows the failure survives even
  when the author is explicitly hunting vacuity.
- **P-7 — consolidating artifacts must preserve the union.** When N documents merge, every observable
  in the union needs a destination or an explicit retirement line. Placement: agnostic.
- **P-3 (standing, now ~9 occurrences) — assert the emitted encoding.** Unchanged and still unencoded.
