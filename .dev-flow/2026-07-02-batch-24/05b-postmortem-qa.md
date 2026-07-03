# 05b — Post-mortem: validation & metrics deep-dive — 2026-07-02-batch-24

> **BLUF:** Strict caught-P2 = **54.5%** (18 of 33 total findings) — a nominal drop vs batch-22 (75%) and batch-23 (71.4%), but the drop is a *recording artifact*, not a quality regression: 13 of the 15 P3 items are implementation-latitude notes or code born after Phase 2. Excluding execute-to-discover items, caught-P2 = **85.7%** (18/21) — the strongest Phase 2 of the three batches, and the only one whose review caught **two live shipped bugs** and a **masking-class fixture trap** before a single line of product code existed. All 5 increments cap-clean, 1004→1037 tests (+33/−0), full suite 1004/0, verdict PASS with zero Phase-4 findings.
>
> Author: qa-reviewer (Phase 5, dispatched parallel to the architect's 05-postmortem.md — this file owns validation/metrics only).

---

## 1. Shift-left scorecard

### 1.1 Raw counts (verified against the artifacts, not taken from memory)

| Phase | Findings | Composition | Evidence |
|---|---|---|---|
| P2 (cross-review) | **18** | 2 BLOCKER (B-1 no-MAC wipe, B-2 false-provenance) + 4 MAJOR (A-M1, A-M2, Q-M1, Q-M2) + 12 MINOR (S-F2..S-F5, Q-m1..Q-m4, A-m1..A-m5; Q-m4/A-m3 = one merged row) | `02-review.md` §1 — 18 table rows |
| P3 (increments) | **15** | 10 code-review LOWs (I1: 3, I2: 2, I3: 2, I4: 3 — 0 HIGH, 0 MEDIUM) + 5 D-notes/deviations (I1 D-note-1 worker-key routing; I2 D-notes 1–3 citation `:153`→`:80`, sibling test file, consult-order; I4 §2 fifth file beyond the roadmap's 4) | increment packets §10 / gate addenda |
| P4 (validation) | **0** | PASS, zero gaps/blockers; carries only | `04-validation.md` §7 |

### 1.2 Caught-P2 percentage

- **Strict** (every P3 item counted as an escape): 18 / (18 + 15 + 0) = **54.5%**.
- **Excluding execute-to-discover items** — i.e. removing P3 items that did not exist or were not observable at Phase-2 time:
  - Excluded (12): all 5 D-notes (each is either an explicitly-granted LLR latitude exercise — I1 D-note-1's "exact key shape decided at Phase 3", I2 D-note-3's order-invariant placement — or post-P2-born: the `:153` citation was written in the I1 gate addendum; the I4 fifth file was *instructed by* the I3 gate addendum) + 7 code-born LOWs (dead `or []` born in I1, set-then-build, per-render map rebuild, backtick cosmetic, C1-range refinement, orphan-md branch, pre-existing TOC drift).
  - Retained as genuine P2-reachable escapes (3): I4-F2 (HLR-038 "NON-DEFAULT" wording — a spec-artifact sentence P2 re-read four times without flagging), I4-F3 (AT-038d state-level-switch vs LoadProjectScreen — a spec-vs-idiom gap visible in 01b), I2's AT-037b single-shot double-inertness limitation (a spec-scope observation).
  - **18 / (18 + 3) = 85.7%.**

### 1.3 Comparison — and why the strict number must not be read naively

| Batch | Caught-P2 | Note |
|---|---|---|
| batch-22 | 75% | |
| batch-23 | 71.4% | |
| batch-24 strict | **54.5%** | denominator inflated by 5 recorded latitude notes + 7 code-born LOWs |
| batch-24 excl. execute-to-discover | **85.7%** | comparable-severity basis |

Three severity-weighted facts the strict percentage hides:

1. **Every P3 item is LOW or a latitude note.** Zero functional escapes reached Phase 3, Phase 4, or the tree. Batches 22/23 did not have a P2 that found blockers of this class.
2. **Both P2 blockers were real, shipped, reachable-by-user defects** (B-1: every no-MAC session loses its validation report; B-2: cross-project false-provenance report) — caught by reading, before implementation. That is shift-left working at maximum value, and it *costs* percentage points in the strict formula only because the fold generated well-recorded downstream notes.
3. **P4 = 0 for the second consecutive time this metric matters most**: nothing survived to validation. The funnel narrowed monotonically: 18 → 15 (all LOW/notes) → 0.

**Recommendation for the metric itself:** carry both numbers forward. The strict number measures *recording discipline* (more notes = "worse"), which perversely punishes exactly the D-note transparency the flow demands. The execute-to-discover-excluded number is the true shift-left signal; suggest the next batch's 05b computes both and trends the second.

---

## 2. Two-layer performance (AT/TC model)

### 2.1 Two of the three story counterfactuals were LIVE SHIPPED BUGS

AT-036a (red row without a matching issue → `Rendered issue rows: []`, increment-1 §4a) and AT-037a (duplicate-symbol ERROR issue does not recolour its rows, increment-2 §4a) were authored **to the spec** and run on the real pre-fix tree — and both FAILED, verbatim-captured. Only AT-038a's RED was of the "absent deliverable" kind (net-new surface).

What this says:

- **About the reconcile stories' value:** the RED runs are direct, executable proof that the stories' premise — "the A2L colour policy and the issues report disagree in the shipped product" — was fact, not belief. If either AT had passed pre-fix, one of two things would have been true: the divergence didn't exist (story worthless) or the AT couldn't see it (gate worthless). Either way the batch should have stopped. The RED capture is therefore not TDD ceremony here; it is the *acceptance test of the requirement itself*.
- **About RED-first as evidence:** a green AT proves the code satisfies the assert; only a RED→GREEN flip proves the assert is *sensitive to the behavior the story changes*. For live-bug stories, RED-first is strictly stronger than review of the assert text, because it demonstrates sensitivity against the exact tree being fixed — the AT-036a capture even showed observable 1 passing while observable 2 failed, decomposing precisely which half of the divergence was live. This is the two-layer model (batch-14 lineage) at full strength: the black-box layer caught what a decade of green white-box TCs on `_a2l_tag_row_severity` and `validate_a2l_structure` never could, because each side was individually correct — the *disagreement between them* was the bug, and only a test observing both shipped surfaces at once can see a disagreement.

### 2.2 B-1's lesson — the masking class is a REVIEW catch, not a test catch

A MAC-bearing fixture would have made AT-036a/037a green on the broken tree: `update_mac_view` only wiped `_validation_issues` in no-MAC sessions, so adding a MAC record to the fixture sidesteps the wipe while every real no-MAC session keeps the bug. Two implications:

1. **Layer B is only as honest as its fixture minimality.** The C-12-family masking class (batch-16 G-3 lineage) generalizes: any fixture ingredient added "to make the AT work" is a suspect — it may be routing around the defect rather than through it. The B-1a discipline that resulted ("do NOT add a MAC to green it", now stated inside the AT itself) is the right encoding: the constraint travels with the test.
2. **This class is structurally invisible to testing.** No test run reveals that a *different* fixture would have failed — only the architect's Phase-2 probe of `update_mac_view`'s body (one function deeper than P-10 reached) found it. The two-layer model needs the review layer to interrogate *fixture composition*, not just assert content. Phase-2's fixture-plan check earned its place in the flow this batch.

### 2.3 AT-038a's surfaced-path chain (Q-M1) vs a glob reconstruction

| Failure mode | Glob-under-reports-dir catches it? | Surfaced-path chain (snapshot → dir-diff → surfaced == new file → re-read THAT path) catches it? |
|---|---|---|
| No file written at all | ✓ | ✓ |
| File written, wrong content | ✓ | ✓ |
| File written but path never surfaced to the operator (LLR-038.3's surfacing silently dead) | ✗ — glob finds the file anyway | ✓ — surfaced-text assert fails |
| Surfaced path ≠ actual file (stale echo, wrong dir, typo'd join) | ✗ | ✓ — equality against the dir-diff fails |
| Handler announces success, writes into the WRONG tree (the B-2 shape) | ✗ within the globbed dir | ✓ — dir-diff of the expected dir shows 0 new + surfaced path mismatch |
| Content asserts accidentally reading a pre-existing/other file | ✗ — glob picks "a" file | ✓ — re-read is pinned to the surfaced path |
| Typed-name echo (report parrots the suggested name, not the actual dedup-suffixed identity) | ✗ | ✓ — via the Q-M2 companion: pinned literal `img-patched_1.s19`, where the typed name is not a substring |

The glob reconstruction observes only "a deliverable exists"; the chain observes the *contract between the handler and the operator* — that what the app says it did is what it did, where it said. Q-M1 was a MAJOR precisely because the un-amended AT left LLR-038.3's surfacing formally required but never observed. The chain is the reusable pattern: for any handler-writes-then-announces story, the announcement is part of the deliverable and the content read must flow *through* it.

---

## 3. Counterfactual discipline — 3 RED captures, one preserved by an interruption

Captures: AT-036a (deliberate pre-I1 run, live bug), AT-037a (deliberate pre-I2 run, live bug), AT-038a-d + ctl-TC (the I4 interruption checkpoint's `5 failed, 5 passed` state served as the trigger-absent RED).

**Is the accidental RED as strong as a deliberate pre-run? Yes — under four conditions, all of which held here; absent any one of them, it is weaker:**

1. **The failing state matches the SPECCED counterfactual, verbatim.** Increment-4 §0 documents exactly the counterfactual 01b specced: key bound, action absent → `new_files == []` on the dir-diff and no surfaced refusal. An arbitrary 5-fail checkpoint proves nothing; *this* 5-fail state was the named RED.
2. **Capture precedes any completing edit.** Agent B ran the capture before touching the tree. A resume that edits first destroys the evidence irrecoverably.
3. **The failures fail for the specced reason, not for scaffolding/authoring reasons.** The load-bearing asserts (dir-diff empty, positive-diagnostic needles absent) were the failing ones — and the one ambiguous read (the ctl multi-operand display suggesting both formats leaked) was *resolved by instrumentation, not assumed*: a debug script pinpointed the leak as HTML-only before any fix. That verification step is what separates evidence from noise.
4. **The tree state is independently audited coherent.** The interruption protocol's tree-state verification (composer complete — its 5 TCs passing proved it; wiring partially present — 0 refs for the action confirmed it) established exactly the provenance a deliberate capture gets for free by choosing its tree point.

One structural note: the equivalence is *easier* for C-10-family counterfactuals (absent deliverable — ANY pre-completion tree is a valid RED tree) than for live-bug counterfactuals like AT-036a/037a, where the RED must fail *for the divergence reason* on a tree where everything else works. Had the interruption fallen mid-I1 or mid-I2, condition 3 would have carried the full weight, and a deliberate re-capture on a cleaned tree would have been the safer call. The flow got the lucky ordering — worth stating so nobody generalizes "interruptions produce free REDs".

---

## 4. Metrics table

| Metric | Value | Note |
|---|---|---|
| Iterations per phase | P0: 1 · P1: 2 · P2: 1 · P3: 1 · P4: 1 | the single P1 re-iteration was the forced blocker fold |
| Increments | **5/5, cap-clean** | file counts 4 / 5 / 5 / 5 / doc-only — no cap breach, no unapproved 6th file (I4's 5th was gate-addendum-instructed and flagged) |
| Findings raised → closed | P2: 18 → 18 (one-pass fold, orchestrator-verified; C-15 sweep-back found + fixed 1 own residual) · P3: 15 → 4 fixed in-batch (I1-F1→I2, I3 `_strip_ctl` rec→I4, I4-F2→AM-4, I4-F3→traceability note) + 11 recorded/accepted/carried (incl. I4-F1→BACKLOG) · P4: 0 raised | 0 HIGH / 0 MEDIUM anywhere in Phase 3 |
| Tests | **1004 → 1037 (+33 / −0)** | chain 1015/1020/1027/1037 reconciled per increment; net-0 rewrites: 1 in-place update + 3 surviving no-op monkeypatches (B-1a census held) |
| Full suite | **1004 passed / 0 failed** (non-slow) | I4 gate run, current at close (no code since); Phase-4 re-ran the 3 new files (26/26), 2 extended files (45/45), engine guard (1/1) independently |
| Stories | **US 3/3** (US-032/033/034) + 2 blocker-born requirements (LLR-037.4, B-2 provenance) | |
| HLR / LLR coverage | **3 HLR · 12/12 LLR (100%)** | all 12 thresholds read in-assert at Phase 4 — none vacuous |
| AT | **9/9 passing** (036a/b/c, 037a/b, 038a/b/c/d) | 3 GATE + GUARD-class marks honored; 3 RED captures on file |
| QC-3 boundary catalogs | **complete ×3** | every row → node, zero gaps (04-validation §3.2) |
| Amendments / deviations | **AM-1..AM-4 recorded** (§6.5 Before/After) + all 5 D-notes + I4 split-authorship credit recorded | no silent drift found at Phase-4 spot-checks |
| Bidirectional matrix | **1 soft cell, honestly classified** | project.json-untouched = by-construction + adjacent byte-stability TC, justified (no requirement names it; full suite includes batch-20's round-trip ATs) |
| Frozen set | **0-diff at every gate** + Phase-4 direct re-check | |

---

## 5. Process notes

- **The Phase-1-iteration-2 fold — 18 findings in one pass.** Two blockers, four majors, twelve minors folded in a single architect iteration, then orchestrator-verified structurally (18 §6.4 rows; LLR-037.4 ×11 refs; AT-038d ×10 refs; provenance mechanism bound at file:line). The notable data point: **C-15's sweep-back caught its own residual** (one stale R-8 reference found and fixed during the fold's self-check). A control that finds its own leftovers during application is functioning as a check, not a checklist — this is the difference between the fold being verified and being merely asserted. One-pass folding at this volume is viable *because* the P2 findings each shipped with a specified fix; had B-1/B-2 arrived fix-unspecified, one iteration would not have absorbed 18.
- **V-5 friction: zero.** All 24 provisional ids bound 1:1 onto the 33 real nodes at Phase 4 — no orphans, no renames beyond the ×N expansions the spec already carried (036c ×2, 037.4 ×3, 038.3 ×3, 038.4 ×2, 038.1 ×2, stamp ×3). The discipline that produced this: provisional ids declared as provisional from Phase 1, real node names recorded per-increment in REQUIREMENTS §30/§31, and the I5 census enumerating the partition (26 + 7) before Phase 4 bound it. V-5 cost this batch ≈ one collect-only run plus a table — the cheapest it has ever been.
- **The interruption resume: verified-not-redone.** Agent B audited Agent A's half on disk (composer 354 L complete, 10 test nodes, more app.py wiring than the briefing credited) instead of regenerating, corrected the credit upward in the packet, and completed only the 4 genuinely missing pieces. Combined with §3's RED preservation, the interruption cost the batch a session gap and nothing else: no duplicate work, no divergent second implementation, no fabricated continuity. The tree-state briefing in the interruption decision-log entry (DONE/NOT-DONE with ref-counts) is what made this cheap — worth keeping as the interruption-protocol template.

---

## QA evidence checklist (Phase-5 artifact scope)

- [✓] All counts sourced from named artifacts — 02-review.md §1 (18 rows), increment packets §10/addenda (10 LOW + 5 D-notes), 04-validation.md §7 (P4 = 0).
- [✓] Both scorecard formulas stated explicitly with their exclusion lists — no bare percentage without its denominator (§1.2).
- [✓] No fabricated comparisons — batch-22/23 figures quoted as recorded (75% / 71.4%); comparability caveat stated rather than hidden (§1.3).
- [✓] Counterfactual-equivalence conditions named and checked against the actual I4 record, not asserted in general (§3).
- [✓] No test executed for this artifact and none claimed — this is analysis over Phase 1–4 evidence; all run figures cite their original runs.
- [✓] No real PII / secrets — batch fixtures referenced by their synthetic names only.
- [✓] No unfilled template — no placeholders, no empty required rows.
