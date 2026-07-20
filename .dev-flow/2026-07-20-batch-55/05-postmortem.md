# 05 — Post-mortem · batch-55 (P-1b inline-axis length summer)

**BLUF.** batch-55 shipped the CURVE/MAP inline-axis length summer clean: **0 phase iterations, 0 blockers anywhere, +18 tests (1670 total), 0 snapshot drift, 0 engine-frozen diffs outside the sanctioned `a2l.py` unfreeze.** The batch ran smoothly because a *verified design seed* (batch-50 §7) plus *C-35 draft-time execution* reproduced the 25/51/12/None oracles over the real demo **before any code was written** — yet it still needed two substantive in-gate corrections (an `'08'` C-36 phantom the orchestrator itself introduced during the Phase-2 fold, and an ALIGNMENT false-green hole the independent code review caught). Both were caught *at the gate, not in production*, which is the headline result: the review/fail-loud layers did exactly their job. The two catches map cleanly onto **existing** controls (C-36 fold-against-defined-vocabulary; C-10/C-31 completeness + reverse-consumer census). **No new general control is warranted** — minting one per incident would violate general-controls-not-narrow-patches. The single new *product* follow-up is **batch-56: alignment-aware padding sizing** (operator-approved A4 follow-up), plus the mechanical **PR-B re-freeze** of `a2l.py`.

---

## 1. What worked

- **The batch-50 §7 verified seed made Phase 1 near-zero-cost.** The design (`record_layout_full_span` reading `layout["lines"]`, position-index-vs-count trap, full-span-or-None contract, 25/51 oracles) was carried verbatim from batch-50's `01-requirements.md §7` + `02-review.md`. Phase 1 assembled 3 HLR / 11 LLR from a seed that was already reviewed once — the architect and qa reviewers refined rather than discovered. (PLAN.md:33-41; state.json phase-0 note "Verified design seed retained in .dev-flow/2026-07-19-batch-50/…§7".)
- **C-35 draft-time execution reproduced the oracles before any code (0 wasted increments).** The architect ran `parse_a2l_file` over the real `ASAP2_Demo_V161.a2l` at Phase-1 draft time and reproduced `CURVE.STD_AXIS=25 · MAP.STD_AXIS.STD_AXIS=51 · FIX_AXIS.PAR_DIST=12 · COM_AXIS=None`, plus a full-corpus sweep (12 CURVE/MAP tags → 8 derive / 4 stay grey, **0 false-None**, taxonomy complete for the corpus). Because the derivation was proven against ground truth up front, Phase 3 implementation matched on the first pass — the C-35 probe re-ran green at Inc-2 with the identical 25/51/12/None/None (increment-002.md §4; state.json phase-1/phase-3 notes). This is C-35 validating itself, exactly as it did in batch-54.
- **The Phase-2 triple review caught 5 MAJORs pre-implementation.** Three parallel reviewers each executed independent probes against the real demo (not code-reading). All 5 MAJOR + 4 positive/minor findings folded into `01-requirements.md` *before* Phase 3, so implementation never had to unwind a design defect (02-review.md:12-38):
  - **arch-MAJ1** — AT-105 (`==51`) could not discriminate an X/Y axis swap (demo MAP axes are both SBYTE(1), so 4+5 and 4·5 are order-invariant) → folded to a **size-asymmetric MAP oracle** in TC-133 (`[4,3]==25` vs `[3,4]==24`).
  - **qa-M1** — AT-108's colour-flip oracle was unfulfillable as worded (length alone doesn't flip a row when `mem_map is None`; `enrich_tags_and_render` doesn't emit `sev-*`) → rewritten to a covering `mem_map` + `_a2l_tag_row_severity`.
  - **qa-M2** — TC-135's census was hand-listed (the exact C-31 anti-pattern) → derive `observed` from the parse, assert `⊆ ALL_AXIS_KINDS`.
  - **qa-M3** — FIX_AXIS had no black-box VALUE AT → AT-107 retargeted to demo `FIX_AXIS.PAR_DIST==12`.
  - **sec-F2/F3** — base-0 `int(str(mp),0)` widens grammar and raises on `'08'`; guard must be `try/except`, never `isdigit()` → base-10 cast inside `try/except`.
- **The independent code review caught the ALIGNMENT false-green hole.** At Inc-2, the code-reviewer agent flagged F1 (MEDIUM): 2-token `ALIGNMENT_*` directives were silently skipped by the `<3`-token structural filter → an alignment-bearing summable layout would **under-report** its span (a false-green — the precise failure the full-span-or-None contract exists to prevent). This was invisible in the demo (its inline layouts are alignment-free) and only surfaced under adversarial component-census reasoning over *real-world* A2Ls (increment-002.md §5; 01-requirements.md:344, §6.5 A4).
- **The dev's fail-loud caught the orchestrator's own Phase-2 fold error.** During Phase 3, the dev flagged that the orchestrator's Phase-2 disposition of AT-110/TC-139 — `'08' → None` — was a **C-36 phantom**: it is only true under the *rejected* base-0 reading; under the chosen base-10 model `'08'` parses to `8` (valid). The orchestrator corrected §4.9 + §6.5 A3 (increment-002.md §6a; state.json phase-3 note). Fail-loud worked *upward* — the implementer corrected the orchestrator, not the reverse.

## 2. What didn't / friction

- **The orchestrator's own Phase-2 fold introduced a C-36 phantom.** In folding sec-F2/F3 (base-0 → base-10), the orchestrator over-corrected the acceptance value: it wrote `'08' → None` into AT-110/TC-139. That assertion contradicts the model's *defined* base-10 behavior (`'08' → 8`). It was a self-inflicted regression in the spec, caught one phase later by the dev's fail-loud (§6.5 A3). Friction, not defect — it never reached code — but it shows a fold can silently drift the acceptance oracle away from the model it is supposed to encode.
- **Phase-1 requirements initially under-scoped the safety contract.** R4 (taxonomy incompleteness) as first written covered only the *safe* `≥3`-token degradation (an unlisted data component → None). It did **not** register the **span-affecting-directive** class — 2-token `ALIGNMENT_*` lines that induce inter-component padding. The `<3 → skip` structural filter was itself reasonable, but it created a hole in the full-span-or-None contract for exactly that class. The hole was hidden by the alignment-free demo corpus and only closed after the code review (01-requirements.md:344, §6.5 A4 "Root cause").
- **The Phase-4 gate run's first attempt died on process, not product.** The orchestrator-owned C-25 gate suite failed its first invocation on an **unset-`$TMPDIR` redirect** — an environment/shell issue, not a test failure. The re-run was clean (state.json phase-4 note; 04-validation.md:8). A process paper-cut, worth noting only so the gate-run harness gets a defined `$TMPDIR` next time.
- **One commit-hygiene checkpoint surfaced at Phase 4 (non-blocking):** the new white-box file `tests/test_a2l_inline_axis_length.py` was git-**untracked** during the green run — on disk and passing, but it would not ship without a `git add` at commit (04-validation.md:6, :142). Flagged forward to Phase 6, not a gate failure.

## 3. Scope drift

**None. The batch stayed inside its "moderate" cut.**

- The **ALIGNMENT force-None fix was an in-scope safety-contract correction, not drift.** It did not add a feature; it closed a hole in the *already-committed* full-span-or-None invariant (§2.4). The fix strengthens the parent HLR-P1b invariant with **no threshold change** (01-requirements.md §6.5 A4 "Parent-HLR re-read"). Cost was one guard clause + one test (TC-133b) — within the Inc-2 4-file budget.
- **Alignment-*aware* sizing was correctly deferred, not smuggled in.** The operator's AskUserQuestion ruling (2026-07-20) was explicit: "Safe now + alignment-aware follow-up" — ship the force-None guard this batch, model alignment padding in **batch-56**. Deferring the harder, span-affecting-padding arithmetic kept batch-55 at its moderate scope while restoring safety immediately (01-requirements.md §6.5 A4; PLAN.md:64).
- File footprint held: Inc-1 = 2 guard files; Inc-2 = 4 files (`a2l.py` + new test file + `test_a2l_multiline_headers.py` + `REQUIREMENTS.md`), facade untouched because the summer symbols are private (state.json phase-3 note).

## 4. Metrics

| Metric | Value | Source |
|--------|-------|--------|
| **Iterations per phase** | **Phase 0/1/2/3/4 = 0 / 0 / 0 / 0 / 0** | state.json — every gate SELF-APPROVED on first pass; folds were *in-gate*, not iterate-to-refine |
| Phase-2 findings | 5 MAJOR + 4 positive/MINOR, **all folded pre-Phase-3** | 02-review.md:12-38 |
| Code-review findings | 1 MEDIUM (F1 alignment, folded) + 1 LOW (F2 size-encoded-deposit, noted out-of-scope) | increment-002.md §5 |
| Blockers | **0** at every phase | PLAN.md, all gate notes |
| Test delta | **+18** (`test_a2l_inline_axis_length.py`); 1652 base → **1670** total | 04-validation.md:8; reconciled |
| Suite result | 1670 passed / 2 skip / 21 deselected / 3 xfail, **EXIT=0** | state.json phase-4 |
| Snapshot drift | **0** (29 snapshots passed; predicted 8-row A2L drift did NOT materialize → no regen PR) | 04-validation.md:127 |
| Engine-frozen diffs | **`a2l.py` ONLY** (sanctioned unfreeze) + 2 guard files; 0 other frozen module | 04-validation.md:104 |
| §6.5 amendments | A1/A2/A3/A4 all landed + green | 04-validation.md:114-121 |

**Note on "0 iterations with multiple corrections."** No phase looped. The two substantive corrections (the `'08'` phantom, the ALIGNMENT hole) were resolved *within* the gate that surfaced them — a fold and a guard-clause, not a return-to-a-prior-phase-to-refine-or-fix. This is the intended shape of an in-gate correction versus an iteration.

## 5. Root-cause analysis — smooth run, yet two in-gate corrections

**Why the batch ran smoothly (0 iterations):** the *verified seed* + *C-35 execution discipline* removed the two usual sources of iteration — (a) a wrong design (eliminated by carrying batch-50's already-reviewed §7), and (b) an oracle that doesn't match ground truth (eliminated by executing `parse_a2l_file` over the real demo at draft time and reproducing 25/51/12/None *before* writing code). With both removed, implementation matched the spec on the first pass and every gate self-approved.

**Why it still needed two substantive corrections — and why both were catchable at the gate, not in production:**

- **The `'08'` C-36 phantom** arose from a fold, not the design. When the orchestrator translated a security finding (base-0 → base-10) into an updated acceptance value, it changed the *observable oracle* faster than it re-checked the oracle against the *defined model*. The model says base-10; base-10 says `'08'==8`; the fold wrote `None`. It was catchable because the model's vocabulary is *defined and executable* — the dev could run the base-10 cast and see `8`, contradicting the spec's `None`. Defined vocabulary + fail-loud = caught one phase downstream, before code encoded the wrong assertion.

- **The ALIGNMENT false-green hole** arose from a completeness gap in the safety contract, not a wrong number. The `<3`-token skip was a reasonable structural filter that happened to also swallow span-affecting 2-token directives. It was catchable because full-span-or-None is a *stated completeness invariant* — the code review's reverse-consumer / component-census reasoning ("what real-world layout component is NOT in the taxonomy, and does the code degrade to None or under-report?") is precisely the audit that a completeness contract invites. The demo hid it (alignment-free), so *only* an adversarial census over inputs-beyond-the-fixture could surface it — which is what an independent review over the shipped surface is for.

**Common thread:** both catches landed at a gate because the batch had **defined, executable ground truth** (a base-10 model, a full-span-or-None invariant) against which a reviewer or the dev could *falsify* a claim. Where the ground truth is defined and executable, false-greens are catchable pre-merge; where it is vague, they leak. batch-55's discipline was to keep the ground truth defined at every step.

## 6. Proposed for next batch / controls

### 6a. Product follow-ups
- **batch-56 = alignment-aware padding sizing (TOP new backlog item).** The operator-approved A4 follow-up: model the inter-component padding that `ALIGNMENT_BYTE/WORD/LONG/INT64/FLOAT16/FLOAT32/FLOAT64` directives induce, so alignment-bearing real-world CURVE/MAP layouts derive a *correct* span instead of degrading to grey (`length=None`). batch-55 made them **safe** (force-None, no false-green); batch-56 makes them **covered**. Scope: Moderate — extends `_record_layout_full_span` with a running-offset + alignment-rounding pass; the demo corpus is alignment-free so it needs a synthetic alignment-bearing oracle. (01-requirements.md §6.5 A4; PLAN.md:64.)
- **PR-B: re-freeze `a2l.py` (post-merge, mechanical).** Re-insert `"s19_app/tui/a2l.py"` into BOTH `_ENGINE_PATHS` tuples, guard-files-only, `git diff main -- a2l.py` must be empty (AT-112 / TC-142 / LLR-P2b.1). This is the mandatory C-27 corollary tail — a same-PR re-freeze self-trips the vs-main guard, so it MUST be its own post-merge PR. (04-validation.md:144; PLAN.md:69.)
- **Commit hygiene:** `git add tests/test_a2l_inline_axis_length.py` before the PR-A commit or the 18 new tests do not ship (04-validation.md:142).

### 6b. Controls assessment — **recommend NO new control**

Both in-gate corrections map onto **existing** controls that either caught them or would have prevented them. Per general-controls-not-narrow-patches, minting a control per incident is the anti-pattern; the existing set is sufficient.

| In-gate correction | Existing control that applies | Verdict |
|--------------------|-------------------------------|---------|
| **The `'08'` C-36 phantom** (orchestrator's Phase-2 fold wrote an acceptance value — `'08'→None` — that contradicts the model's defined base-10 behavior) | **C-36 (fold-against-defined-vocabulary)** — this is a *textbook* C-36 instance. The phantom is precisely "an acceptance value folded without checking it against the model's defined vocabulary." The dev's fail-loud (a general engineering-rule behavior, CLAUDE.md rule 12) surfaced it. **C-36 already names this failure class** — no new control needed. If anything, batch-55 is a fresh *instance* to cite under C-36, not a reason to add C-37. | Covered by C-36 + fail-loud |
| **The ALIGNMENT false-green hole** (`<3`-token skip silently under-reported a span-affecting directive → false-green) | **C-10 (branch-ATs / false-green anchors)** + **C-31 (input-set-is-an-oracle)** — the completeness gap is exactly what a reverse-consumer / component census is meant to expose: an input class (2-token ALIGNMENT directives) present in real A2Ls but absent from the fixture, against a *stated* full-span-or-None completeness invariant. The independent code review ran that census over the shipped surface and found it. The full-span-or-None *contract itself* is the C-10 discipline made concrete (AT-106 external→None is its declared false-green anchor). **C-10 + C-31 + independent code review already cover this** — no new control needed. | Covered by C-10 / C-31 + independent review |

**Also already-sufficient this batch:** **C-27 dual-guard** (unfreeze REMOVES → same-PR OK; re-freeze ADDS → post-merge PR-B) governed the frozen-file handling with zero incident; **C-35 execution** delivered the 0-iteration result; **C-25 gate run** produced the single authoritative suite pass. None needed extension.

**Recommendation: encode NO new general control.** batch-55's two catches are *instances* of C-36 and C-10/C-31 respectively, both of which fired as designed. The correct lesson is the confirmation that (verified seed + C-35 execution) upstream and (fail-loud + independent census review) downstream form a sufficient net — not that a new rule is missing. Cite this batch as a C-36 instance (the fold phantom) and a C-10/C-31 instance (the alignment census) in the lineage record.

---

## Evidence checklist

- [✓] **Constraints stated** — moderate scope, per-batch autonomy grant, a2l.py unfreeze approved, RC-1 clean @ `a58d4e0` (PLAN.md:8-18).
- [✓] **Alternatives considered** — base-0 vs base-10 cast (chose base-10, sec-F2/F3); private-symbols vs facade re-export (chose private, D2, C-3/C-11 precedent); force-None-now vs alignment-aware-now (chose safe-now + batch-56 follow-up, operator ruling).
- [✓] **Recommendation tied to constraints** — no new control (general-controls-not-narrow-patches); batch-56 deferral (moderate-scope constraint).
- [✓] **Risks listed** — R3 DoS (mitigated, 1 MiB clamp), R4 taxonomy/alignment (mitigated by full-span-or-None + batch-56), R5 snapshot false-regression (0 drift materialized); operational risk = a2l.py guard OPEN until PR-B re-freeze.
- [✓] **Cost/latency** — DoS clamp `MAX_A2L_DECODE_BYTES == 1_048_576` bounds the byte-decode loop; AT-111 proves 10M-axis span clamps to None in <2s.
- [✓] **Diagram** — flow is a single linear pass (post-axis-walk length block at `a2l.py:1273`); no non-trivial control flow warranting a mermaid diagram. Traceability rendered as tables (§4 matrices).
- [✓] **What would change the recommendation** — if batch-56's alignment census surfaces a component class that force-None does NOT catch (i.e. a summable layout that still under-reports), that would reopen the completeness contract and *could* justify a dedicated span-completeness control; nothing in the current corpus indicates it.
- [✓] **Two-layer requirements** — every US carries a first-class Acceptance block + AT-NNN; BOTH chains complete (behavioral US→AT→outcome in 04-validation.md Layer B; functional US→HLR→LLR→TC in Layer A), 0 orphans (02-review.md:6).
