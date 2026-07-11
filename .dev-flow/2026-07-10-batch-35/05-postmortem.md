# 05 — Post-mortem · batch-35 · Report filter file + patch-editor regroup (B-07, last P1)

> Phase 5 artifact. Co-authored architect + qa-reviewer. Tree: `feat/batch-35-report-filter`
> @ `08507ad`. Written 2026-07-11 against PLAN.md, 01-requirements.md §6.4/§6.5, 02-review.md,
> increment-000..006, 04-validation.md, and `.dev-flow/state.json` (decisions_log).

## BLUF

The batch shipped B-07 complete (filter engine + both filtered reports + selector UX +
patch-editor regroup) in 7 increments with **every review APPROVE, 0 HIGH findings, 0
engine-frozen diffs, and both byte-identity goldens proven live three times**. All 32 in-batch
review findings (25 Phase-2 + 7 increment-review) were closed in-batch. The dominant success
was the **D-9 resolved-matcher unification** — one design change at the Phase-2 gate killed 3
blockers and 1 major simultaneously. The dominant process failure class was **test-run
discipline vs the harness**: 7 recorded backgrounding/stall events culminating in a Phase-4
mandate that was physically unsatisfiable (10-min tool cap < 11.3-min suite) — the mandate,
not the agents, was the bug. One unplanned increment (Inc-6) traces to a re-derivation gap:
the increment cut was fixed at the same gate that amended the AT registry, and was never
re-derived against it. Three controls are **PROPOSED** (never encoded — operator approval
required): C-CAND-D reformulation ("one complete run, own output read"), C-CAND-G
(move-aside, never stash, for net-new-file RED), C-CAND-H (AT-registry re-reconciliation →
increment-cut re-derivation after amending gates), plus C-CAND-I (conditional snapshot-drift
predictions, 2nd occurrence).

**Operator-facing hindsight:** B-07 — the operator's "one of the most important changes" —
was the LAST P1 in the 2026-07-09 baseline backlog. With this batch, **the entire P1 set
(B-01..B-08 as prioritized) is closed pending merge.** What remains is the P2/P3 pool
(B-11..B-19) and the P-1/P-2/P-3 hygiene items.

---

## 1. Metrics

### 1.1 Iterations per phase

| Phase | Iterations | Note |
|---|---|---|
| P0 (stories/RC-1) | 1 | Spec locked by 4-question operator gate; RC-1 PASS @ `79699a5` |
| P1 (requirements) | 1 (+1 fold round at the gate) | Approved after one orchestrator fold round (F-1 extent semantics, F-2 equality short-circuit) — no re-draft |
| P2 (review) | **2** | Triple review → **iterate** (3 blockers / 10 majors / 12 minors) → amendment pass → independent checklist verification **CLEAN 12/12** → APPROVE |
| P3 (implement) | **7 increments** (Inc-0..6), 1 gate pass each | Inc-6 unplanned (§4); plus 2 close-out fold commits (`d9a73c2`, `e15b744`) |
| P4 (validation) | 1 | PASS, all three exit axes |
| P5 (post-mortem) | 1 | this artifact |

### 1.2 Findings opened vs closed

| Source | Opened | Closed in-batch | Carried out (named) |
|---|---|---|---|
| Phase-2 triple review (02-review) | 25 (3 blockers F-01/F-02/Q-1 + 10 majors + 12 minors) | 25 (amendment pass; re-gate CLEAN 12/12) | S-F7 flagged **pre-existing/out-of-scope** → backlog (raw `linkage_symbol` in report_service) |
| Inc-0 review | 0 | — | — (reviewer re-derived goldens byte-identical) |
| Inc-1 review | 2 (D-10a missing-`include` gate call; LLR-053.4 primitive-clause reword) | 2 (fold `d9a73c2`) | — |
| Inc-2 review | 1 (F1: promote duck-typed `source_name` to declared field) | 1 (discharged in Inc-3, surface-asserted by AT-055a) | — |
| Inc-3 review | 1 (TC-F1 cross-module consistency pin) | 1 (realized in Inc-4) | — |
| Inc-4 review | 3 (F1 dock-overlap guard, F2 docstring, F4 conftest regex nit) | 3 (fold `e15b744`) | — |
| Inc-5 review | 0 new (1 deviation ratified: §6.5 #21 drift-set amendment) | 1 ratified | — |
| Inc-6 review | 0 | — | minor redundancy noted (Generate-half TC beside joined AT-053a) → hygiene pool |
| Phase 4 | 0 blockers | — | 8 open items, ALL owed-work carries (04-validation §9), none a defect |
| **Total** | **32** | **32** | S-F7 + 3 hygiene items + post-merge procedure items |

### 1.3 Batch numbers

| Metric | Value |
|---|---|
| Suite (not-slow passed) | 1244 → **1335** (goldens green throughout; 0 unexpected failures at any gate) |
| Collected nodes | 1270 → **1363** (+93; D = 0 — no node deleted all batch) |
| ATs / TCs | 17 ATs (C-18: exactly one on-disk node each) / 14 TCs |
| §6.4 reconciliation rows | 29 (+ 5-row 01b→01 AT-registry sub-table) |
| §6.5 amendments | 21 (18 at Phase-2 re-gate + #19/#20 Inc-0 canonical-form + #21 Inc-5 drift) |
| Increment reviews | 7/7 APPROVE, **0 HIGH across the batch** |
| Engine-frozen diffs | 0 (verified vs base AND `origin/main`, every increment + Phase 4) |
| Golden double-proofs | ×3 (Inc-0 author, Inc-0 reviewer re-derivation, Phase-4 independent re-derivation) |
| Rework collisions (parallel pipeline) | **0** (§2.6) |
| Process incidents recorded | 5 classes (§3), all resolved in-batch |
| Perf (measured, Phase 4) | ceiling filter: parse 3 ms · resolve ≈1.8 s · classify 10k ≈9.3 s (accepted residual, docs note owed) |

---

## 2. What worked

### 2.1 Goldens-first increment ordering (Inc-0) — did the double net pay for itself?

The Inc-0 byte-identity goldens (AT-054b/AT-055b) **never fired against a regression**:
every increment's goldens-gate run was green, because Phase-2's D-9 had already killed the
byte-drift class (F-01) on paper before any code existed. Honest assessment: as a
*regression* net, redundant this batch. **It still paid for itself, three ways:**

1. **It converted "byte-identical" from a claim into an executable gate.** Every wiring
   increment (Inc-2/3/4) ran the goldens as its exit condition; "the b-key wiring did not
   move an unfiltered byte" is a quoted green run, not an assertion of intent. That is what
   made seven fast APPROVE gates possible.
2. **It forced two real environment discoveries at the cheapest possible moment** (test-only
   increment, base revision): the second clock in `changes/apply.py` (no injectable seam —
   would have made the pair non-byte-stable), and the CRLF/run-root canonical-form problem
   (§6.5 #19/#20). Found later, both would have surfaced as cross-platform CI flakes on the
   PR.
3. **It is the standing guard for the carries**: the S-F7 sanitation fix and the three-copy
   canonicalizer consolidation are only safe *because* these goldens exist (golden-regen
   discipline).

Cost: 1 increment, 2 tests, 3 fixtures, ~2 hours. Verdict: **keep goldens-first for any
"unchanged path must stay byte-identical" batch** — the net's value is enforcement and
early environment discovery, not just catch-rate.

### 2.2 D-9 resolved-matcher unification — one design change, 4 findings dead

The single highest-leverage event of the batch. Parse+resolve on the UI thread at trigger
time; ONLY the matcher flows onward. It simultaneously killed F-01 (no record kwargs →
annotation bytes cannot drift), F-02-ii (matcher carries branch (c) to the project report),
F-04 (UI-thread capture kills the stale/torn worker read AND moves refusal before the
expensive variant run), and enabled Q-1's resolution path. Downstream it also **made
predicted test churn evaporate**: census row 9 (TC-038-3 composer pin "EXTEND") survived
unmodified because the composer gained one default-absent kwarg. Lesson worth restating:
when a review yields multiple blockers in one plumbing area, hunt for the single
architecture move that dissolves them jointly before patching them severally.

### 2.3 C-15 probe (textual Select markup) — lineage count

The Inc-4 entry probe proved on textual 8.2.8 that a raw `Select` option label is **parsed
as markup** (brackets consumed, styled render) — `rich.markup.escape` chosen, AT-056b
re-proves through the shipped overlay. Lineage of the underlying class ("Rich/textual
interprets text you assumed inert"): batch-23 (`Select.NULL` vs `Select.BLANK` — C-15
encoded), batch-27 (markup-flip injection caught at Phase 2), batch-29 (related-artifacts
restored markup-safe), batch-33 (FIVE-message injection class, `markup=False` scrub),
batch-35 (this probe). **Fifth occurrence of the class; third time the probe-before-assume
discipline pre-empted a shipped bug.** C-15 is earning its keep; no change proposed.

### 2.4 C-18 registry sweep — caught the unrealized pair post-Inc-5

After all planned increments landed, the C-18 reconciliation (every AT → exactly one
on-disk node) flagged AT-053b + TC-318-report-half as **specced but unrealized** → Inc-6.
This is the detection net working exactly as encoded in batch-30. Note the asymmetry: C-18
caught the omission *after* the fact; the omission's *cause* is a planning gap (§4.1) — the
prevention side is C-CAND-H (§5).

### 2.5 Reviewer counterfactual-mutation practice

Every review mutated live seams rather than reading diffs: Inc-1's reviewer ran an 18k-probe
oracle (0 divergences) and re-derived the RED; Inc-2's reviewer counterfactual-mutated the
matcher seam both directions; Phase 4 independently re-derived all three golden
perturbations and re-ran the C-14 observer sweep. Product: 13/17 ATs live-RED-proven, 2
goldens double-proven thrice, and the 2 honestly-weaker classes (AT-053b NTFS vacuity,
AT-057b regression pin) *declared* with strongest-constructible CFs — nothing silent. This
is the certainty axis being bought with execution, not prose. Keep.

### 2.6 Per-increment review pipeline — zero rework collisions

Review of increment N ran in parallel with implementation of N+1 across the whole batch.
Measured collision count: **0** — no increment had to rebase over a review fold, because
folds landed as dedicated commits (`d9a73c2` docs-only between Inc-1/2; `e15b744` between
Inc-5/6 touching only files outside Inc-6's edit set). Enablers worth naming: strict 5-file
edit sets declared up front, pure-append test policy (0 deletions all batch), and folds
routed through the orchestrator rather than the in-flight implementer. The pattern scales —
keep it, with the §4.2 watch-item on fold-commit growth.

---

## 3. What didn't — process incidents (all recorded at occurrence; none silent)

### 3.1 Agents backgrounding pytest — the mandate was the bug (7 events)

Tally: Inc-0 stalled **3×** on backgrounded runs; Inc-1/2/3 each recorded one harness
auto-background of the single mandated invocation (recovered by reading that run's own
output); Inc-4/5/6 each auto-backgrounded once more; Phase-4's **mandated blocking
foreground call was killed by the harness's hard 10-minute tool cap at ~85%** — the full
suite takes ~11.3 min on this machine, so the "foreground" mandate was *physically
unsatisfiable* as written. The agents' recovery (one complete detached run, exit code +
tail read from that run's own captured log, no stitching, no re-run) was correct and is the
real discipline. **Name it precisely: the invariant is "single complete run, evidence read
from that run's own output" — not "foreground".** A mandate whose satisfaction exceeds a
known harness cap is a spec bug in the mandate. → C-CAND-D reformulation (§5).

### 3.2 The stash-RED trap (1 occurrence + 1 standing hazard)

Inc-1's first RED-evidence attempt ran `git stash push -- <net-new file>` — which stashes
**nothing** for an untracked file — and the follow-up bare `git stash pop` applied the
**parked batch-29 stash**, conflicting `.dev-flow/state.json`. Resolved same-increment
(conflicted path reset to HEAD, batch-29 stash preserved, RED re-captured via move-aside);
every subsequent increment explicitly recorded "NO git stash". Two distinct lessons: (a)
move-aside (rename out of tree) is the correct trigger-absent-RED idiom for net-new
modules; (b) the parked batch-29 stash is a live footgun sitting at `stash@{0}` — any bare
`pop` anywhere resurrects it. → C-CAND-G (§5) + the stash disposition carry (§6).

### 3.3 Orchestrator misrouted a correction to the reviewer (1 occurrence, caught)

A mid-Phase-3 correction message intended for the implementer was sent to the reviewer
agent, which **refused on role-boundary grounds** — the correct behavior, and the reason
the incident cost minutes, not an increment. Below the 2-occurrence bar for a control;
recorded as a watch-item: when fan-out is live, address agents by role+task-id in the
message body so a misroute self-identifies.

### 3.4 Carried standing authorization corrected mid-batch (governance)

Batch-35 started under the multi-batch authorization pattern carried from batches 29/31-34.
The operator's **per-batch correction surfaced mid-batch** (during Phase 3, after Inc-3);
an explicit batch-35 grant was obtained via AskUserQuestion for the remainder, and the
per-batch rule is now on file (`feedback_standing_auth_per_batch`, recorded in
state.json). Phases 0-3-through-Inc-3 therefore ran under an authorization model the
operator had not re-confirmed for this batch. No guardrail was breached (no self-merge, no
regen, propose-not-encode all held), but the governance record was retroactive for half the
batch. **Resolution is already encoded as operator feedback, not a candidate control:
authorization is asked fresh at every batch kickoff.** Nothing further proposed.

### 3.5 LLR-057.4 drift prediction: predicted 2 cells, observed 1

The locked LLR predicted both patch snapshot cells drift; at the canonical textual pin only
120x30 drifted — 80x24 held because the regroup rows render **below the pane fold**, the
exact class already observed in batch-33 ("the longer text renders below the fold there").
Consequence: an xpassed mark until regen + a §6.5 #21 amendment to ratify. Should the
prediction have been conditional? **Yes.** The below-fold mechanism was known one batch
earlier; the prediction should have been derived per-cell from fold position, or phrased as
an upper bound ("up to these 2 cells; a realized subset is a ratifiable deviation"). Cost
was small (the `strict=False` marks made the miss non-gating by design), but this is now
the **second occurrence** of "predicted drift, below-fold cell held". → C-CAND-I (§5).

---

## 4. Scope drift

### 4.1 Inc-6 — unplanned, and the root cause is a re-derivation gap, not creep

Inc-6 was in-spec work (AT-053b + TC-318-report were locked requirements), so this is
**plan drift, not scope drift**. Root cause chain: the architect's increment cut (Inc-0..5)
was drafted against the Phase-1 registry (13 ATs); the Phase-2 amendment pass **at the same
gate** split AT-056a (Q-6 → a/a2/a3) and redefined AT-053b (Q-3, hostile-VALID-filter
semantics needing all product code landed first), growing the registry to 17; the cut was
adopted at the re-gate **without re-deriving increment→AT coverage** against the amended
registry. The C-18 sweep caught it post-Inc-5 at a cost of one cheap test-only increment.
Counterfactual without C-18: the pair ships unrealized and Phase 4 blocks. Prevention
belongs at the gate, not the sweep → C-CAND-H (§5).

### 4.2 Close-out fold commits (`d9a73c2`, `e15b744`) as a pattern

Two dedicated fold commits carried review findings and gate ratifications between
increments. Assessment: **good pattern, keep** — it is what bought the 0-collision pipeline
(§2.6): increment diffs stay closed, folds are individually auditable, and `git log` reads
as gate history. Watch-item: `e15b744` bundled three findings + one requirement amendment;
that is the ceiling. A fold that would touch product logic (not guards/docs/nits) or exceed
~3 items should be promoted to a reviewed increment of its own rather than riding a fold
commit.

---

## 5. Candidate controls — PROPOSED ONLY (encoding requires explicit operator approval, per the standing propose-not-encode rule)

| Id | Proposal (one-liner) | Evidence / occurrences |
|---|---|---|
| **C-CAND-D (reformulated)** | Full-suite gate evidence = **one complete run; exit code + tail read from that run's own captured output**; "foreground vs background" is not the discipline; any mandated-blocking call whose expected duration exceeds the harness tool cap is a **spec bug in the mandate** (fix the mandate, don't fight the harness). | 7 events this batch: 3 Inc-0 stalls, Inc-1..6 auto-backgrounds, Phase-4 cap kill on an ~11.3-min suite vs a 10-min cap (04-validation §6). Supersedes the batch-32 C-CAND-D lint/test-gate wording. |
| **C-CAND-G** | Trigger-absent RED for **net-new files uses move-aside (rename out of tree), never `git stash`** — untracked files stash nothing, and a bare `pop` resurrects whatever stash is parked. | 1 occurrence (Inc-1 batch-29-stash resurrection → state.json conflict) + 1 standing near-miss (the parked stash remains at `stash@{0}`, verified Phase 4). |
| **C-CAND-H** | After **any gate amendment that adds/splits/redefines ATs**, the AT registry is re-reconciled against the increment cut and the cut is **re-derived or explicitly re-affirmed** before Phase 3 opens — C-18 is the detection net; this is its prevention twin. | 1 occurrence (Inc-6: Q-6 split + Q-3 redefinition post-dated the cut; unrealized pair caught only by the post-Inc-5 C-18 sweep). |
| **C-CAND-I** | Snapshot-drift predictions in locked LLRs are **per-cell fold-position-reasoned or stated as an upper bound** ("up to N cells; realized subset = ratifiable deviation"), with `strict=False` marks as the non-gating envelope. | 2 occurrences of the below-fold-holds class: batch-33 (80x24 held under longer help text) + batch-35 (LLR-057.4 predicted 2, observed 1 → §6.5 #21). |

Watch-items below the occurrence bar (recorded, not proposed): orchestrator message-routing
(role+task-id in correction messages, §3.3); fold-commit size ceiling (§4.2).

---

## 6. Carries / next batch

Owed **this batch, before close** (Phase 6): REQUIREMENTS.md rows `R-RPT-FILTER-001` /
`R-TUI-045`; operator format docs (envelope, F-1 extent semantics, F-2 over-match note,
Q-10 bracket note, F-10 annotation divergence, **ceiling-perf note** — "ceiling-size
filters stall the UI for seconds", measured Phase 4 §4-item-4). Then PR.

Post-merge (standing procedure): **canonical snapshot regen** (snapshot-regen.yml @ textual
8.2.8) for the patch cell(s) + retirement of BOTH batch-35 marks (120x30 real drift, 80x24
defensive); **ubuntu CI green run** as the cross-platform proof for the canonical-form
goldens + symlink arms; local `main` ref refresh (stale at `f79834e`).

Backlog (next batches):
1. **S-F7** — sanitize `report_service._modifications_lines` raw `linkage_symbol`
   interpolation (~:703), under golden-regen discipline (the Inc-0 goldens gate it).
2. **Three-copy `canonical_report_bytes` consolidation** onto the conftest helper (two
   per-file twins remain by increment-diff-closure design).
3. **`object.__setattr__` test-helper collapse** to constructor kwargs (the Inc-2
   attachments, superseded by the declared `source_name` field since Inc-3).
4. **Redundant Generate-half TC** beside the joined AT-053a node (declared TC-level;
   hygiene removal or docstring-only keep — reviewer's call next time the file is open).
5. **Parked batch-29 stash** at `stash@{0}` — drop or apply is the **operator's call**;
   until then it is the C-CAND-G standing hazard.
6. **P1 CLOSED** (pending merge): B-07 was the last P1 of the 2026-07-09 baseline backlog.
   Next pool: **B-11..B-19 (P2/P3)** + **P-1/P-2/P-3 hygiene**; plus the standing Bookmarks
   placeholder gap and deferred polish items from memory.

---

## 7. Gate recommendation (exit-axes assessment)

- **Coverage — MET** (inherited from Phase 4, re-checked): 25/25 LLRs on-disk-noded, 17/17
  ATs single-noded through shipped surfaces, census 14/14, bidirectional matrix complete.
- **Certainty — MET**: 13 live-REDs, goldens triple-proven, 2 declared-weaker classes with
  strongest-constructible CFs, last assumed item (perf) measured.
- **Evidence — MET**: every claim in this post-mortem cites a batch artifact
  (02-review verdict table, increment §4 run tails, 04-validation §4/§6/§9, state.json
  iterations/grant record, §6.4/§6.5 counts, `git log` SHAs).
- **Process — accounted**: 5 incident classes, all recorded at occurrence, all resolved
  in-batch; 4 candidate controls proposed with occurrence counts; nothing encoded.

**Recommendation: CLOSE Phase 5 → proceed to Phase 6 (docs), then PR under the batch-35
grant (operator merges).** Do NOT open a new batch inside this one: the batch is complete
pending its owed docs; the post-merge items (canonical regen, ubuntu proof, stash call) are
standing procedure, and the P2/P3 pool is a fresh kickoff **with a fresh per-batch
authorization ask** per the now-on-file rule. Iterate is not warranted — no named gap
remains in any phase artifact (the no-hollow-iterate rule cuts both ways).

## Evidence checklist (architect + qa-reviewer, Phase 5)

- [x] Constraints stated — batch guardrails quoted from state.json `standing_authorization` (§3.4, §5 header).
- [x] ≥2 alternatives considered — §2.1 weighs goldens-first vs review-only net; §5 weighs mandate-fix vs agent-blame framing; §4.2 fold-commit vs promoted-increment.
- [x] Recommendation tied to constraints — §7 close/iterate call tied to the exit axes + per-batch auth rule.
- [x] Risks listed — §3 incident classes, §4.2 fold ceiling, §6 item 5 standing stash hazard.
- [x] Cost/latency where relevant — §1.3 perf row (measured), §2.1 Inc-0 cost, Inc-6 cost (§4.1).
- [x] Diagram — n/a (no new flow; metrics tabular).
- [x] What would change the recommendation — a Phase-6 blocker (docs reveal a spec-docs contradiction) or a red ubuntu CI run on the PR would reopen Phase 4, not Phase 5.
- [x] Two-layer requirements — verified inherited: 17 AT registry (Layer B) + US→HLR→LLR→TC chains re-confirmed in 04-validation §1/§2; no new requirements introduced by this phase.
