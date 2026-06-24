# Post-mortem — s19_app — Batch 2026-06-24-batch-15 (US-016)

> Phase 5 artifact. Co-authors: `architect` (process/architecture/metrics/carries) + `qa-reviewer` (validation & test-quality retrospective). Scope: ONE story US-016 (A↔B compare false "no diff") — retroactive black-box acceptance closure of a batch-14 escaped bug.

## 🔑 At a glance (read first)

- **Outcome:** **closed clean** — PASS, 0 defects, 1 production file, 0 engine-frozen edits, the cleanest escaped-bug proof in the lineage.
- **Top 3:** ① escaped-bug RED→GREEN proof via `git stash` (AT-016.2) + draft-time disk verification caught two inherited-premise errors ② the headline is upstream — **batch-14 passed its gate with an EMPTY Phase-4 artifact** (this batch is remediation) ③ root cause RC-1: the orchestrator gate checks artifact *presence*, not *filled-ness*.
- **New control this batch:** the automated `dev-flow-sync` template-form reject-check (proposed, still-owed — the prose hard rule already landed post-audit but only *reminds*, it can't *detect*).
- **Open items → next batch:** 9 carries — biggest: **audit #2 (batch-11 manifest) is CONFIRMED LIVE**, + 3 qa test-durability hardenings.
- **Metrics:** iterations 7 (`{0:1,1:2,2:1,3:1,4:1,5:1}`) · findings 20 closed / 0 open · ledger 894→898 (+4).

---

## Detail (reference)

### What worked
- **Draft-time disk verification caught two inherited-premise errors before they cost an increment** (same control as batch-13's "inert shell" stale docstring): (1) Phase 0 found US-015 is net-new feature work, never built — not an escaped bug as the audit assumed — so it was **deferred**, not mis-scoped into a bug-fix batch; (2) Phase 1 D-2 found batch-14's planned fix ("stop swallowing in `_diff_load_maps`") would NOT have fixed the headline — a genuine *raise* already routes to `compare_images`'s refusal branch; the real silent case is the non-raising degenerate/empty map. A wrong fix premise inherited from batch-14's spec, killed before code.
- **Empirical reachability gate (R-2) resolved with a real input, not an argument.** Inc 1 (TDD red-first) armed a halt-and-escalate valve and proved the bug surface-reachable (a non-empty all-malformed file → empty map without raising → `compare_images` non-refused → AT-016.2 RED). Prove, don't assume.
- **The cleanest escaped-bug evidence chain in the lineage:** `git stash` the fix → AT-016.2 RED pre-fix (verbatim) → GREEN post-fix. The gold-standard template for the remaining audit carries.
- **Surgical blast radius:** 1 production file (`app.py` +51/-13), 0 frozen edits, out-of-band `failed_sides` carrier, report path untouched.
- **Security stayed proportional:** ADVISORY (0 new write/exec/network surface) — no ceremony tax.

### What didn't / friction
- **The headline failure is upstream:** batch-14 passed the gate with an unfilled Phase-4 template AND uncommitted code. batch-15 is remediation for a control gap that should never have let batch-14 close.
- **White-box TC-230/231 specified but never created** — reconciled (V-5) as subsumed by the ATs. Defensible (the ATs drive the real mechanism, no mock), but the two-layer model *bent reactively* rather than by design; provisional TC ids now need retiring (C-6).
- **Commits HELD** (operator hard-rule) — the batch sits uncommitted in the worktree, the same precondition that produced the batch-14 escape. Correct per policy; surfaced as a watch-item.

### Scope drift (planned vs actual)
| Planned | Actual | Note |
|---------|--------|------|
| batch-14 closure (US-015 + US-016) | US-016 only | US-015 reclassified net-new feature → **deferred** (disciplined de-scope, not creep) |
| 3 ATs | 4 ATs | AT-016.4 (over-correction guard) added during the Phase-2 fold — in-scope hardening |
| TC-230/231 white-box | subsumed by ATs (V-5) | reconciled, not created |

### Metrics (full)
| Metric | Value |
|--------|-------|
| Iterations per phase | `{0:1, 1:2, 2:1, 3:1, 4:1, 5:1, 6:0}` (sum 7) |
| Findings opened / closed | 20 / 20 |
| Findings by severity (blocker/major/minor) | 0 / 5 / 15 |
| Where caught (Phase 2 / P3 gate / P4) | 20 / 0 / 0 (all at the Phase-2 cross-review) |
| Test ledger (base − D + A = post) | 894 − 0 + 4 = **898** |
| Files touched · increments (cap trips) | 1 production (`app.py`) · 3 increments (0) |
| Full suite | 866 passed / 0 failed / 0 errored (29 skip, 3 xfail) |
| Code review | 2/2 (APPROVE · APPROVE-WITH-NITS) |

### Root causes
- **RC-1 (headline) — the orchestrator gate cannot detect a phase that never ran.** A blank `04-validation.md` (unfilled template, no executed results) satisfies "an artifact exists at the expected path" while satisfying none of the intent; the two-layer model + surface-reachability matrix both *presuppose execution*. Compounded by batch-14's code never being committed. A *gate-completeness* defect, not a discipline defect.
- **RC-2 — wrong fix premise propagated from a spec, not from disk.** batch-14 specified "stop swallowing in `_diff_load_maps`" without tracing the live control flow; only D-2 cross-review (reading the real path) killed it.
- **RC-3 — two-layer model degraded gracefully but undocumented-ly.** TC-230/231 were declared subsumed *after* the ATs proved sufficient; there's no documented criterion for "when may an AT subsume a planned TC?" Acceptable once, latent inconsistency if it recurs.

### Process / workflow findings
- **The process-hole control — done vs still-owed:** the **dev-flow hard rule** ("A phase gate never accepts an artifact still in unfilled-template form" + the gate-evidence-checklist) is ALREADY ENCODED in `~/.claude/commands/dev-flow.md` post-audit — sufficient as a *human* control. STILL-OWED: an **automated `dev-flow-sync` reject-check** that refuses to sync any batch whose required artifacts still contain placeholder tokens (`<P>`/`TC-NNN`/`AT-NNN`/`<...>`), empty required rows, or a `04-validation.md` with no executed-results block. The prose rule *reminds*; only the automated check at the one unskippable gate (sync) *detects*. Reversible, additive (a lint, not a refactor), high leverage. → **C-1**.
- **Formalize "AT-subsumes-TC" (RC-3 / qa §3):** adopt a named rule — *a white-box TC may be subsumed by an AT iff (a) the AT drives the exact mechanism with no mock, AND (b) every named boundary in the LLR's acceptance criteria is exercised by some AT.* This batch satisfies (a) but not fully (b) — the S0-only boundary (F-A-04) is named but unexercised by any AT. → **C-10**.
- **Fixture-precondition self-assertion (qa §6):** any AT whose RED depends on a fixture exhibiting a specific parser/loader state (empty map / raise / refusal) must assert that state inline before exercising the surface — converting "the fixture happens to be degenerate today" into a loud invariant. → **C-8**.

### Product findings
- The fix is a 2-line display-side predicate (`not mem_map and _source_has_content(image)`) + a conditional status branch; it detects the degenerate condition and overrides the unconditional `sev-ok` rather than re-plumbing the diff. Reversible, low-risk.
- **Hex-window deliverable gap (qa §1):** HLR-016 clause 1 says the system "shall render the differing bytes in the hex windows," but no AT observes hex-pane content (AT-016.1 only asserts `"changed" in #diff_range_list`). A defect blanking/mis-rendering the hex panes while producing a correct run list + `sev-ok` would pass all 4 ATs — the *same shape* of escape, narrowed to one un-instrumented widget. → **C-9**.

### Control lineage
- **New control proposed this batch:** automated `dev-flow-sync` template-form reject-check (origin RC-1) — status: **propose** (the prose hard-rule sibling is already adopted).
- **Prior controls exercised:** draft-time disk verification (HELD — caught US-015 mis-scope + the wrong batch-14 fix premise); TDD red-first + escaped-bug RED→GREEN (HELD — the F-Q-03 `result.refused is False` guard was the load-bearing assertion that stopped AT-016.2 passing for the wrong reason); engine-frozen guard (HELD — 0 edits); consumer-input-contract / surface-reachability (HELD). Near-miss: the two-layer model bent on TC-230/231 (RC-3).

### Open / deferred items → next batch
| # | Item | Type | Reason deferred | Trigger / owner |
|---|------|------|-----------------|-----------------|
| C-1 | Automated `dev-flow-sync` template-form reject-check (placeholders / empty rows / no executed-results) | process/tooling | global-config change, distinct from this product batch | High — the backstop for RC-1 |
| C-2 | **Audit #2 — batch-11 manifest composition (CONFIRMED LIVE: `_write_and_verify_manifest` app.py:3591 → `write_project_manifest` with no `batch`/`assignments`)** | product/bug | sequenced after #1 | High — confirmed live |
| C-3 | Audit #3 — batch-07 in-TUI report-trigger seam | product/seam | follow-up batch | Medium |
| C-4 | Audit #4 — batch-01 demo evidence packs | product/evidence | follow-up batch | Medium |
| C-5 | US-015 forward-feature batch (16/32 S19 width + S0; **default-flip blast radius**) | product/feature | net-new, own `/dev-flow` | Medium |
| C-6 | Retire provisional `TC-230`/`TC-231` ids | doc tidy | V-5 reconciliation | Low (Phase 6) |
| C-7 | `app.py` ruff F401/F402 cleanup | hygiene | standing | Low |
| C-8 | ~~Add inline `assert S19File(degenerate).get_memory_map() == {}` to AT-016.2~~ **— DONE at Phase-5 close** (operator-approved pre-close hardening; 4 ATs still green, ruff clean; `S19File` import added) | product/test | qa §5 — fixture degeneracy was implicit | **Closed in-batch** |
| C-9 | Add a hex-window observation to AT-016.1 OR explicitly scope hex-pane rendering out of US-016 acceptance | product/test | qa §1 — HLR-016 cl.1 deliverable un-instrumented | Medium |
| C-10 | Formalize the "AT-subsumes-TC" criterion (a + b) | process | RC-3 / qa §3 | Medium |

**Doc-accuracy correction (qa §5) — DONE at Phase-5 close:** `increment-001.md §3` recorded the R-2 snippet as `S19File("S1ZZ…")` "no raise" — but `S19File` takes a PATH not content (the literal would `OSError`). Corrected in the increment-001 record (the verification was actually run by writing the content to a tmp path, which is what the test does).

**Sequencing (non-binding):** C-2/C-3/C-4 fit one `/fast-dev-flow` batch (audit-backlog cleanup, using this batch's RED→GREEN pattern as the template); C-1 small enough to ride along or land standalone; C-5 wants its own `/dev-flow` (default-flip blast radius); C-8/C-9 are cheap test hardenings (could ride the next batch or apply now); C-6/C-7/C-10 fold into a doc/process pass.

### Evidence checklist — architect + qa-reviewer
Both co-authors returned completed evidence checklists in their Phase-5 outputs:
- **architect:** ✓ constraints stated · ✓ ≥2 alternatives (human rule vs automated sync-check) · ✓ recommendation tied to RC-1 · ✓ risks (HELD-commit staleness, RC-3) · ✓ what-would-change-the-recommendation · two-layer traceability honest (TC-230/231 bent → C-6).
- **qa-reviewer:** ✓ acceptance criteria / explicit expected / edge cases (gap: S0-only named-unexercised) · ✓ regression checklist · ✓ exit criteria · ✓ no PII · ✓ results from a real run (RED verbatim + GREEN reproduced) · ✓ Layer B observed (caveat: hex panes uninstrumented) · ✗ **fixture-durability guard absent (the one unchecked item → C-8)**.
