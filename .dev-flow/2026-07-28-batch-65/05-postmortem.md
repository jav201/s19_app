# batch-65 — post-mortem

> **BLUF: six independent reviews, two increment code reviews and a validation pass raised 61 findings
> and found ZERO correctness defects in the shipped producer. That is the batch's headline and its
> indictment at the same time. The code was right from the first draft and stayed right; what was
> repeatedly wrong was the document describing it — and "instrument, not product" is only two-thirds
> of an honest name for that, because a third of those defects were the document CLAIMING MORE THAN
> THE DESIGN DELIVERS, which is not an instrument bug. It is the exact sin the last three batches
> exist to stop, committed 46 times in one specification.**

**Shipped:** D1 — `R-TUI-098` / `HLR-103` / `LLR-103.1…6`. `_addendum_lines` bounded.
**Shipped as:** `b691f21` — squash-merge of **PR #149**, parent `73e3fb9`, 2026-07-28. ✅ The commit that carries this batch into `origin/main`.
**Development branch:** `claude/batch-65-addendum-producer-bound`, `082ada9` → `9d21d9a` (5 commits; on the pre-migration backup `claude/batch-64-addendum-producer-bound`).

> ⚠️ **Recorded batch-70:** the 5 development commits are **not reachable from `origin/main` and never will be** — PR #149 was squash-merged into the single commit `b691f21`. `082ada9` (the base) is reachable; `9d21d9a` is not.
**Scope:** D1 only. **Zero drift.** OB-4/F4 and D2 held as carries, as chartered.

> ℹ️ **The old batch number is retained DELIBERATELY in two places — do not "correct" them.** `US-B64-1` / `US-B64-2` and `tests/goldens/batch64/` keep the pre-renumbering `64`: the story ids are baked into passing tests, and the golden directory name is baked into the byte-identity oracle. Renaming either would churn a green suite and a double-proven golden to fix a label. *(Merge-gate corrective item 3, discharged batch-70.)*

---

## 1. The "instrument, not product" frame — verdict

**It is defensible, it is the wrong name, and part of it is a verdict the batch awarded itself.**

The frame collapses two defect classes that behave very differently. Split properly, the 61 findings
sort into three:

| class | what it is | count | is it flattering? |
|---|---|---|---|
| **1 — OVER-CLAIM** | the document asserts a property the system does not have | **~14** | **No.** This is the project's founding defect, not a test bug. |
| **2 — BLIND ORACLE** | the check cannot falsify the thing its own label names | **~38** | Yes, and fairly. Genuine instrument defects. |
| **3 — PRODUCT** | the designed or shipped producer itself | **~9**, of which **0 correctness** | — |

### 1.1 Class 1 is not an instrument defect and calling it one launders a category

Every one of these is the spec stating something false about the shipped system:

- **R-independence.** `R-TUI-098` claimed a single pass "independent of the declared-region count"
  and §10.1 claimed `R×V×E → V×E`. Both **false** under one enclosing region plus `R−1` narrow ones —
  the natural operator declaration. Two lanes, two fixtures, same law: `500 / 4000 / 32000 / 128000`
  region ops at `R = 1/8/64/256` for output that never grows, and `19 200 @ R=64` — *bit-for-bit the
  figure §7 T-2 printed as the defect being removed.*
- **"the affected variants"** (sec S2) — the notice caps at 8, so above 8 "contributed nothing" and
  "evidence dropped" stay indistinguishable. That is the ambiguity US-B64-2 exists to remove.
- **The addendum-scope predicate** (qa NEW-3) — "between the heading and the next `^## `", when the
  addendum is the **last** `##` section. No EOF arm. A literal implementation reads **0 notices on
  every report**, taking `AT-197/198/199/201/202/203` and `TC-499` with it. This lived in shipped
  requirement text and was false about the report's own layout.
- **`HLR-103`'s threshold bullet** naming a criterion the design is expected to fail (arch N-3).
- **§10.4's residual, overstated** — the "evicted" collision still renders via `_declaration_error_lines`
  in all three of §7 T-5's own transcript rows.
- **§10.10's "structurally blind, unconditionally"** — refuted at Inc-3, the guard *was* extendable (A-46).
- **`AT-200`'s stated `emit()` byte-budget hole** — executed-false; the hole does not exist.
- **Inc-3's own draft** asserting six residuals were already carried in `BACKLOG-CODE.md`. One was.

An over-claim is not a mis-measurement. It is a promise. `R-TUI-098` shipped with a **six-part "does
NOT claim" paragraph and ten residual sections** — that is not the profile of a spec whose claims
matched its design and whose tests were buggy. It is the profile of a spec that discovered, over two
gates, that it had promised more than the design delivers, and did the honest thing by writing the
gap down instead of closing it. Honest, but not clean.

### 1.2 The causal link the frame hides

**A claim is over-stated exactly where nothing can falsify it.** Class 1 and class 2 are the same
defect seen from two sides, and every single instance proves it:

| the over-claim | the oracle that could not see it |
|---|---|
| R-independence | `AT-195`/`TC-488` counted **candidate leaves**, which stay flat while work grows ×256 |
| "the affected variants" | `AT-197` asserted `⊇` — **representation**, not identity |
| the addendum-scope rule | never executed against a real report until qa ran it at the re-gate |
| §10.10 permanence | nobody tried to extend the guard until Inc-3 did |
| six residuals "carried" | nobody grepped the backlog |

`FIX-H` is the cleanest demonstration in the batch: an arm that names every **contributing** variant
instead of every **dropped** one passes every stated acceptance in revision 1 while telling the
operator that the attacker's variant lost evidence it did not lose. The batch's flagship AT — the one
the spec argues at length is "not `AT-165` again" — **was `AT-165` again, one axis over.**

### 1.3 Where the frame is made true rather than found true

`B-1`/`S1` was resolved by **narrowing the requirement**, not by fixing the structure. Security put
"(b) keep the claim, fix the structure" on the table as co-equal and never withdrew it; the architect
proposed the same max-segment-tree and then declined it: *"B-1 fold 1 (segment tree) adds real
complexity to a function whose whole point is to get simpler."* Security's diagnosis was explicit —
*"This is inherent to prefix-max attribution, not an implementation slip."*

So `A = R × N` is a real, executed, uncapped cost property of the shipped design. It is filed as a
disclosed residual because the batch chose scope discipline over closure. **That was the right call**
(it is reversible, named, and instrumented by `TC-498` as a disclosure counter that fails loudly).
But it means "no product defect" is partly a **disposition**, not an observation. Say that out loud
rather than banking the clean number.

### 1.4 The counterweight — the product really was clean, and unusually well evidenced

This should not be undersold to make the analysis sound tough:

- **Zero design objections to the shape** across six independent reviews. All three lanes affirmed
  single-pass + one ordered list per region + three admission counters, two of them with executed
  sweeps: 375 064 address checks / 0 mismatches (architect), ~150 000 / 0 (security).
- The Inc-2 reviewer **re-derived correctness rather than trusting the Phase-2 sweeps**: 30 855
  exhaustive geometries + 3 000 randomized + 15 hand-built, **0 mismatches**; plus 4 000 randomized
  below-bound fixtures against a verbatim transcription of the old producer, **exact line equality**.
- Byte identity **6/6 shapes, 0 differing bytes**. **0 goldens re-baselined. 0 frozen diff.**
- Two independent code reviews of a **+565/−33 rewrite of a memory-critical producer** found no
  behavioural bug — only duplication, a stale docstring, and one undocumented precondition.

**Verdict: replace the frame.** Not *"instrument, not product"* but:

> **The design was right and the document kept outrunning it. Every gate defect was either a promise
> the design does not keep, or a check that could not have caught the promise being broken — and
> those are the same defect.**

---

## 2. What worked

- **Starting from batch-63's blocked record instead of re-deriving it.** PLAN.md's ten inherited
  findings were treated as design constraints ("any design that re-opens one of these is wrong by
  construction"). None was re-opened. This is the single highest-leverage thing the batch did.
- **Slug-then-bind at Phase 1.** The qa lane named observables by slug and the architect lane owned
  id allocation. batch-63's failure mode — both lanes allocating, 9–10 of 12 AT ids bound to different
  observables — did not recur. The collision mechanism was removed at its source.
- **Executing every threshold before promoting it (C-39), now proven on the fold direction too.**
  The qa `≤1.30` marginal form was adopted and the architect `≤2.5` 4×-sweep form **retired in
  writing**, resolved by evidence not preference. The recorded reason is the right one: *"widening a
  threshold to fit measurement noise is the batch-63 move."*
- **Refusing to claim DoS closure.** Decision #7: *"If the requirement never asserts closure, F2 has
  nothing to attach to."* Security's re-gate then cleared the batch **unconditionally, 6/6 CLOSED** —
  the first unconditional security pass in several batches. Declining to claim is what bought it.
- **A 27-row disposition table as the discharge artifact.** FOLDED / REJECTED-with-reason /
  CARRIED-with-destination, verified independently of the folding agent by deriving finding keys from
  the review artifacts (27/27, then 19/19). Nothing vanished silently — the P-7 failure did not recur.
- **Retiring ids in place rather than re-pointing them.** `AT-195` and `TC-496` retired, not reused;
  batch-63's contested `AT-164..167` / `TC-440..454` retired at the id-space level. Confirmed at
  Phase 4 to bind nothing.
- **Inc-3 making its control permanent.** The head-of-line guard extension shipped with a positive
  control (`test_head_of_line_guard_detects_a_planted_violation`) rather than a pasted transcript.
  That is the contrast that makes F-4 (below) visible as a defect.

## 3. What did not work

**The fold was applied to the instances the reviewer NAMED, not the class the reviewer DESCRIBED.
Three to four times, in one batch.** `state.json` calls the re-gate occurrence *"third appearance"*
in its own words:

1. Revision 2 applied `B-3`'s GREEN-by-construction analysis to the **2 nodes the architect named**.
   The class was **11 guards / 12 rows**. Result: `≥ 9 of 28` rows in §11.1 asserted RED for nodes
   that are GREEN — *inside the table created to discharge that exact finding.* Found independently
   by two lanes (`ARCH-N-1` == `QA-NEW-1`).
2. The `S3` fold **planted** the vacuous scope predicate: revision 1's report-wide count had the
   defect security named; it did not have this one.
3. `M-4`'s fold **re-created `M-4`'s defect** on the new gate — an exact-equality gate on an unpinned
   counter invites tuning the counter to the number.
4. The **reviewer who found the "GREEN row with no arm" class then supplied an arm that does not
   bite.** `FIX-E`, credited to `TC-487` in revision 3, is executed-**GREEN** on it (A-43).

The counter-example is in the same batch and shows the fix is cheap: security's `S1` discharge
`grep`-ed for every surviving instance of the claim string and reported **6 live sites** —
*"No stale work-axis claim survives anywhere in the document."* Mechanical, and it worked.

**The document acquired its own defect density.** 3453 lines of requirement for a 565-line production
change; **46 amendments**, of which **40 repair the document's own claims from the previous revision**.
That is roughly **one spec defect per 75 spec lines**. Half the review budget went to policing an
artifact the batch itself was producing.

**The orchestrator's own verifier had the batch's defect class in it.** Recorded verbatim in
`state.json`: *"my independent union check verified that every qa slug was BOUND … it did NOT verify
that each observable retained its STRENGTH through the merge. `AT-197` kept its id and lost its
threshold."* That single hole is the direct cause of gate 1's qa blocker. **The failure mode migrated
from deletion (batch-63: 8 of 18 observables dropped) to dilution (batch-65: 16/16 bound, 3 weakened).**

**A gate artifact was invalidated by a post-hoc fold with no re-issue.** Inc-2's packet claimed
`git diff … touches report_service.py only` — false, because the orchestrator applied the L1 docstring
fold **after the packet was written**. Correctly diagnosed at Inc-3: *"The packet went stale rather
than being wrong; the responsibility is the orchestrator's."* No gate was invalidated, but a later
batch greps packets for blast radius and would get the wrong answer.

**Two increment-gate code reviews (11 findings) were never persisted as artifacts.** They exist only
in `state.json` and three commit bodies. Every Phase-2 review has a file; the increment reviews do not.

**Inc-3's packet shipped with unfilled placeholders.** §4.5 and §4.6 both read *"(filled from the run
below)"*, and §4.3's own gate row points at the empty §4.6. The run happened — Phase 4 consumed it —
but the increment artifact does not carry its own declared gate cell. Inc-2 handled the identical
situation correctly and is the model: with the suite at 83 %, its row reads **in flight**, not passed,
because *"stating a partial run as a pass would be the exact failure mode §6.3 forbids."*

## 4. Scope — D1 only, zero drift, and holding it was right

batch-63 began as "cap two unbounded tables," grew to twelve axes and two competing designs, and
shipped 4 lines. batch-65 was chartered D1-only at kickoff, and **nothing was pulled in**: OB-4/F4,
D2, OB-3, OB-2 and the `M-2` marker claim all stayed carries and are all still in Lane A today.
Under sustained pressure to close the DoS, the batch's own requirement says six times that it does not.

**Yes, holding it was right, and the ~14 agents are not an argument against it.** The counterfactual
is measurable: this batch spent two full gates and 46 findings on **one** function. Adding OB-4/F4
would have added a second unbounded producer with a *different* cost law to the same document that
was already generating a defect per 75 lines. batch-63 ran that experiment and shipped 4 lines.

The agent count is not a scope failure. It is an **artifact-size** failure — see §7.

## 5. Root causes where a phase iterated more than once

**Phase 1 (×2).** Two causes, both structural:
- The evaluability problem — the outcome (memory) is not observable in the report file, and the same
  `summary.entries` feed both the addendum and the unbounded tables, so a whole-report measurement is
  dominated by the thing D1 does not touch. Phase 0 sent this down as a **proposal**, correctly; two
  lanes then had to independently validate the marginal-delta isolation.
- Two lanes produced competing threshold forms. Resolving by execution (not preference) cost an
  iteration and was worth it.

**Phase 2, gate 1 (5 blockers).** Root cause: **the R-independence claim was written from the design's
INTENT rather than from a measurement.** Nobody had executed the `huge+tiny` geometry until the
reviewers did — and when they did, two lanes reproduced the same law with non-overlapping fixtures.
Secondary: `AT-197`'s strength loss in consolidation (the Phase-1 verifier hole above), unassigned
increment ownership of `test_report_field_census.py`, and `AT-196` GREEN-by-construction (a byte-identity
test against a golden captured from the code under test).

**Phase 2, re-gate (1 blocker + 4 blocking majors).** Root cause is **one thing**: fix-the-instances-
not-the-class, §3 above. Notably the re-gate found **zero requirement defects** — architect and qa both
say the requirements are sound and what is not runnable is *the plan to run them*. The defect class
moved one level down between gates, which is the shape you want.

**Phase 3 (0 send-backs, but 3 spec claims executed-false).** Root cause: **fixtures sized against the
pre-fix producer are blind against the post-fix one.**
- `AT-194`'s warm-up charged ~124 kB of one-time allocation to whichever window ran first, driving
  `delta(E=2000)` **negative (−71485)** and failing the node's own `delta > 0` precondition. Invisible
  at Inc-1 because the shipped producer's delta was `408661` — the artifact was noise against it.
- `TC-488`'s leaf size was 100 against a cap of 200, so **the early exit the node exists to detect
  cannot fire.** `300/300/300` under `FIX-A2`.
- `FIX-E` GREEN on `TC-487` — three duplicated regions leave `bisect_right - 1` pointing at a still-
  containing region and `sorted()` puts the widest equal-start region last.

All three were **reported, not absorbed.** For `FIX-E`, the implementer changed neither the test nor
the spec, built the arm that does bite (`FIX-E(b)`), drove it RED on three nodes, and demanded an
amendment. That is the correct handling and it should be the standard.

## 6. The self-correction phenomenon

**Eleven explicit self-corrections across four agents.** The load-bearing ones:

| agent | correction | mechanism that produced it |
|---|---|---|
| security | *"my batch-63 framing of the addendum as **the** evidence sink was too narrow … Stated loudly because it **weakens** my own prior finding"* | ran `_declaration_error_lines`; the "evicted" collision still renders |
| security | *"**My finding was over-general and the rejection is right.**"* — severity is available for 2 of 3 hit classes, not 3 | the rejection cited `changes/model.py`; verified |
| security | *"the sentence is mine, carried verbatim from my first-gate table, where it rested on the **docstring**"* — then supplied 206 fixtures / 89 032 addresses / 0 mismatches | its own evidence-checklist row on docstring-vs-census |
| architect | *"my **'infeasible' was conditional** on my probe's local rebinding. The correction is factually correct and I accept it."* | the fold's counter-argument, executed |
| architect | *"**My 'breaks the module's own convention' was an overstatement**"* — stated **twice** | counted the emitters: 2 of 3, not 3 of 3 |
| qa | §6 titled *"A correction to my own M-3, **surfaced rather than buried**"* — the spec claim it was about to call false **was its own sentence, copied verbatim**, and executing it showed the mechanism does not exist | executed `emit()` on `082ada9`; it never drops |
| Inc-3 | corrected its own draft's *"six residuals already carried"* — *"**an over-claim inside the requirement whose whole point is not over-claiming**"* | grepped the backlog |
| orchestrator | *"Same failure class the batch is chasing, **in my own verifier**."* | comparing its check's scope to what gate 1 found |

### What produced it — five mechanisms, four of them reproducible

1. **The re-gate forced a per-finding CLOSED / PARTIAL / NOT-CLOSED ruling.** This is the biggest one
   and it is structural. It puts a reviewer in front of *their own words* with the fold's counter-argument
   attached. That is different from a second opinion — it is an adversarial confrontation with a prior
   self, holding new evidence. **Reproducible: it is a gate shape.**
2. **Execute, don't read.** qa: *"Every fold was executed against, not read."* Every self-correction
   above came from **running something**. Execution is what makes retraction cheap — you do not have to
   argue yourself out of a position, the transcript does it. **Reproducible: it is C-39 generalised
   from thresholds to claims.**
3. **A checklist row that budgets for self-correction.** Security's evidence-checklist row 16 is
   literally *"Claims corrected where the code contradicted a prior review."* If the artifact has a slot
   for it, filling it is **compliance, not confession**. **Cheapest and most transferable mechanism here.**
4. **Overlapping independent lanes.** When two lanes measure the same thing and one is wrong, they find
   out from a peer's transcript rather than from an assertion. `500/4000/32000/128000` was rebuilt
   bit-for-bit by a second lane. **Reproducible.**
5. **The standing brief to attack the orchestrator's rulings** (inherited from batch-63: *"do not accept
   this because I made it"*). Normalising correction of authority lowers the cost of correcting
   yourself. **Reproducible, but softer — it is a cultural setting, not a gate.**

### The part that is NOT reproducible, and one thing I want watched

**Every one of the eleven self-corrections WEAKENED a finding. Not one strengthened one.** They
narrowed, retracted, downgraded, or conceded. Zero went the other way.

I am flagging this as **an observation with an uncertain cause**, not a conclusion. Two readings fit
the evidence and I cannot separate them from this record:

- **Benign:** reviewers over-reach on a first pass by design (that is what a gate is for), so
  calibration is naturally one-directional. Every weakening here was backed by an executed transcript
  — 206 fixtures, 89 032 addresses, `2 of 3` emitters, `emit()` never drops. **They were earned.**
- **Concerning:** the batch ran under **autonomy + self-merge**. A reviewer who weakens their own
  finding removes an obstacle to a merge they also authorise. A process that only ever produces
  *"my finding was too strong"* is producing agreeable retreat wearing the costume of rigour.

**Watch-item for batch-65: if every self-correction again points the same direction, that is a signal,
not a coincidence.** The cheap test is to check whether any reviewer ever *escalates* their own prior
finding after execution. In this batch, none did.

**And the limit of the phenomenon:** self-correction operated on claims *already made*. It did not
generalise. The batch's signature failure — fix-the-instances-not-the-class — recurred three to four
times **while all this self-correction was happening.** Being willing to be wrong about a specific
claim is not the same skill as applying a correction to its whole class.

## 7. Metrics

| | |
|---|---|
| Route · scope | full `/dev-flow`, phases 0–5 · **D1 only, zero drift** |
| Iterations | P0 ×0 · **P1 ×2** · **P2 ×2** (gate + re-gate) · P3 ×0 send-backs · P4 ×0 |
| Independent reviews | **6** at Phase 2 (3 lanes × 2 rounds) + **2** increment code reviews + **1** Phase 4 |
| Findings raised | **61** = 46 at Phase 2 (27 gate + 19 re-gate) · 11 at increment gates · 4 at Phase 4 |
| Findings closed | 46/46 dispositioned, verified independently of the folder (27/27, then 19/19) · 9 of 11 folded in-increment, 2 carried and closed at Inc-3 · Phase 4: 2 folded, 1 carried, 1 undispositioned (corrected at the merge gate) |
| Findings carried out | **F-4** + **F-3** + 3 non-gating gaps (G-1/G-2/G-3) — all now in Lane A. **Corrected at the merge gate:** the metrics row above previously read "3 folded, 1 carried" for Phase 4 and omitted F-3 entirely; the true tally is 2 folded + 1 carried + 1 that vanished *because* of the miscount, and the G-items were claimed to be in Lane A while being in neither backlog file. |
| Blockers | 5 at gate 1 · 1 + 4 blocking majors at re-gate · **0 HIGH at any increment gate** · 0 at Phase 4 |
| Design objections to the shape | **0** (4 to named sub-components, all dispositioned in writing) |
| Spec amendments | **46** — A-1…9 (rev 1) · A-10…27 (rev 2) · A-28…40 (rev 3) · A-41…46 (Phase 3) |
| Spec size | **3453 lines / 318 KB**; batch folder **695 KB** |
| Production diff | **2 files, +565 / −33** (`report_service.py` +565/−33 · `report_addendum.py` +5/−2, docstring) |
| Test diff | 4 files, **+6915 / −22** (incl. a 3583-line golden and a 2863-line module) |
| **Tests** | **2201 → 2233 (+32)** · Inc-1 +29 · Inc-2 +1 · Inc-3 +2 · **0 deleted, 0 regressions** |
| Final suite | `2233 passed · 2 skipped · 21 deselected · 3 xfailed` in **1659.77 s** · 29 snapshots · **exit 0** |
| Traceability | **0 gaps, both directions.** Layer A 19/19 GREEN · Layer B 9/9 GREEN |
| C-18 | **9/9 AT REALIZED**, 0 unrealized, 0 satisfied-in-parts |
| Frozen-engine diff | **0** across all 7 frozen paths (`range_index.py` consumed, never modified) |
| Goldens re-baselined | **0** |
| Ids | `AT-194…203` (9 live, `AT-195` retired) · `TC-480…499` (19 live, `TC-496` retired) |
| Decisions logged | **17** — 6 operator, 11 agent/orchestrator |
| **Correctness defects found in the shipped producer, by anyone, at any stage** | **0** |

**Derived ratios worth carrying:** 6.1 spec lines per production line · ~1 review finding per 12
production lines · **~1 spec defect per 75 spec lines** · 75 % of all defect-finding effort spent on
a document.

## 8. Cost — an honest assessment

**The gates earned their cost. The artifact did not.**

*The gates were the deliverable, not overhead.* The counterfactual is concrete: merging revision 1
ships a requirement claiming R-independence that is false by a factor of `R`, with a gate structurally
unable to notice, plus **seven acceptance tests that read 0 notices on every report** and would have
been permanently, silently vacuous. That is batch-63's failure repeating at larger scale. Five blockers
at gate 1 and five blocking findings at the re-gate is not a bloated process; it is a process finding
what was there.

*The document was disproportionate and much of the cost was self-inflicted.* 3453 spec lines for a
565-line change, 46 amendments, **40 of them repairing the document's own prior claims**. Three of the
re-gate's most expensive findings (`N-1`/`NEW-1`, `NEW-3`, `A-43`) were **created by the previous
fold**. That is a compounding cost with no product on the other end — the batch spent a meaningful
fraction of two gates reviewing damage it had just done to itself.

**So the lever is not fewer reviews. It is a smaller document.** ~14 agents was the right order of
magnitude for the *risk*; it was disproportionate to the *artifact*, and the artifact was ours to size.
A spec that had stated the R-cost honestly at revision 1 — as a measured residual rather than an
intended property — would have removed one blocker, one lane's re-gate, and roughly a dozen amendments.

**Was the batch too expensive for what it delivered?** No, but only because of what it *prevented*, not
what it *shipped*. 565 production lines is a poor return on ~14 agents by itself. What was actually
bought is: a producer whose correctness is established by 33 000+ geometries at 0 mismatches, byte
identity to the previous behaviour, zero regressions, and **a residual set honest enough that the
security lane cleared it unconditionally** — the first such pass in several batches. That is worth the
money. Paying it again on a spec half the size would be worth more.

## 9. Control candidates — NONE encoded (operator AskUserQuestion required)

Per `feedback_devflow_control_encode_approval`, nothing here is encoded. **P-5** ("can it go RED?"
stated AND executed) is being encoded in parallel; **this batch is evidence for it, not a new control** —
`AT-197`, the leaf-counting oracle and the scope predicate are three more occurrences.

- **P-8 (NEW — deserves its own control; the one I would raise first).**
  **A fixture must be sized against the POST-fix system, not the pre-fix one.**
  Evidence: A-42, both halves, in one batch. `AT-194`'s warm-up was noise against the shipped producer
  (`408661`) and decisive against the bounded one (`−71485`, its own precondition unreachable).
  `TC-488`'s leaf size sat **below the cap**, so the early exit it exists to detect *cannot fire*.
  **Why existing controls do not reach it:** P-5 asks "can this predicate go RED?" — and both of these
  **could**, at Inc-1, which is when P-5 is checked. C-10 and C-31 address vacuous assertions and vacuous
  input sets on a *static* system. This is **temporal vacuity**: a check that is falsifiable at authoring
  time and is not at gate time, because the system it measures changed underneath it. No existing control
  re-asks the question after the fix lands. Both instances were invisible to every prior control and were
  caught only by executing against the new producer.

- **P-10 (NEW — deserves its own control; process lane).**
  **A fold must be applied to the CLASS the finding names, not the instances the reviewer listed.**
  Evidence: three to four independent occurrences in one batch — 2 of 11 guards fixed; the `S3` fold
  planting `NEW-3`; `M-4`'s fold re-creating `M-4`; `FIX-E` credited without being executed on its node.
  **Why existing controls do not reach it:** P-7 (consolidation preserves the union) is about not
  *dropping*; this is about not *under-applying*. C-39 (execute every threshold) does not reach a fold.
  The discharge procedure is already demonstrated in-batch by security's `S1` row: `grep` for every
  surviving instance of the claim and report the count. Mechanical, cheap, and it worked.

- **P-9 (NOT a peer — raise as a rider on P-5, not its own control).**
  *"An arm exists" and "an arm bites on THIS node" are different claims.* `FIX-E` was executed and does
  go RED — somewhere. What was never checked is that it bites on the node it is **credited to**. This is
  a per-cell obligation, and it belongs as a clause inside P-5 rather than beside it. Saying so
  explicitly because the temptation is to file it separately and end up with two overlapping controls.

- **P-3 (standing, now ~10 occurrences) — assert the emitted encoding.** Unchanged, still unencoded.
  This batch adds the `19200` vs `19 200` grep brittleness (`TC-497` greps a literal a document renders
  two ways) and the `md_safe`-escaped region-name trap in `AT-203` (`### B\_quiet`).

**Not controls — process/backlog gaps, filed as such deliberately:** the two increment code reviews
having no artifact; F-4's mutant arms living in an uncommitted scratchpad while §6.3 makes their
reproduction a gate condition; and `state.json` never advancing past `current_phase: 3` while Phase 4
was VALIDATED. Each is a fix to the flow's bookkeeping, not a new rule about evidence.

## 10. Items for the next batch, with severities

Lane A (`BACKLOG-CODE.md`) was reconciled in `9d21d9a` and already carries all six `R-TUI-098`
residuals plus F-4 and the new `changes/apply.py` defect. **These are the deltas and the ordering
argument, not a re-listing.**

**Code lane**

1. **HIGH — OB-4/F4, the two unbounded tables.** `_modifications_lines` + `_checklist_lines` at
   **988 B/entry**, ~11× the addendum's 89 B/hit; ~99 MB for one change document at
   `MF_ENTRY_COUNT_CEILING = 100 000`, ~6.3 GB at 8 docs × 8 variants. **This is the actual DoS axis
   and batch-65 explicitly did not touch it.** It is now the top of Lane A on merit, and batch-65 has
   already paid for the hard part: the bounding pattern, the marginal-delta measurement technique, and
   the notice/disclosure shape are all worked examples now. Take it next while they are warm.
2. **MAJOR — `changes/apply.py:465` `_linkage_index` carries its own copy of the one-candidate bisect
   shape.** Live defect in shipped code, executed: `addr=0x5000` → `(False, None)`, ground truth
   `['BIG_ARRAY']`. Linkage IS shown to the operator. Note the trap: **unfreezing `range_index.py`
   would NOT repair it.** The in-repo fix pattern exists twice (`report_filter.py:737` and now
   `_addendum_lines`).
3. **MAJOR — security N3: the `R × N` residual's reversal trigger is a field complaint, not a
   threshold.** *"A residual whose reversal depends on a user complaining is one nobody owns."* Either
   give it an owner and a number, or accept in writing that it is permanent. Currently it is neither.
4. **P2 — `MAX_DECLARED_REGIONS`.** `options.declared_regions` has no cardinality cap anywhere;
   ≈ 11.6–20 kB/region, both lower bounds. Mirror `REPORT_MAX_REGIONS_PER_VARIANT = 128`. Small, and it
   closes non-claim (e) cheaply.
5. **P2 — F-4: make the ten mutant arms re-runnable from the tree.** §6.3 makes their reproduction a
   gate condition and the harness is not committed. Inc-3 already demonstrated the alternative.
6. **P2 — OB-2, the AT/TC registry.** Measured **again** this batch: next-free TC = 345 / 477 / 479
   depending on subset; 1383 raw ids, 134 real. **Third consecutive batch where it forced an executed
   census at Phase 0.** It is now cheaper to build than to keep measuring.
7. **P3 — revisit the `ops_counter` production parameter.** Keyword-only production API whose only
   consumer is `TC-498`. It is defensible today (an instrumented disclosure that fails loudly if a later
   batch swaps in an output-sensitive structure, and strictly better than the module-level global Inc-1
   originally pinned). But it is permanent API surface added for a test, and it exists because a
   test-first increment authored the seam before the producer did. **Closing §10.7's residual should
   delete this parameter** — tie the two together so it does not become furniture.
8. **P3 — unchanged carries:** D2 (schema-legal address `ValueError`) · OB-3 (`diff_report_service`
   text-mode writers) · the `M-2` truncation-marker claim.

**Process lane (`BACKLOG-PROCESS.md`)**

9. **MED — persist increment-gate code reviews as artifacts.** 11 findings from two reviews survive
   only in `state.json` and commit bodies, while every Phase-2 review has a file. Asymmetric and wrong.
10. **MED — a fold applied after a packet is written must re-issue the packet.** Inc-2's packet
    mis-stated its own diff for exactly this reason. Blast-radius questions are answered from packets.
11. **MED — `state.json` phase advancement is not part of any gate.** It reads `current_phase: 3 /
    in-progress` and `obsidian_synced: false` with Phase 4 VALIDATED and Phase 5 written. Same class as
    batch-63's "Phase 5 and 6 never ran until sync caught it" — the backstop keeps catching it, which
    means the sequencing keeps failing.
12. **LOW — an increment packet with unfilled `*(filled from the run below)*` placeholders should not
    pass its own gate.** Inc-3 shipped two.

---

## Evidence provenance and stated uncertainty

Every number and quotation above is drawn from `.dev-flow/2026-07-28-batch-65/` (`PLAN.md`,
`01-requirements.md` rev 3 + §9d, `01b-qa-catalog.md`, three `02-review-*.md`, three `02-regate-*.md`,
`03-increments/increment-00{1,2,3}.md`, `04-validation.md`), `.dev-flow/state.json`,
`.dev-flow/BACKLOG-CODE.md`, and the five commits `0a6595b · c2c63db · 22c5ab7 · 9d21d9a` on
`claude/batch-65-addendum-producer-bound`. The diff shape (`+565/−33` over 2 production files, empty
frozen-path diff) was re-derived here with `git diff --numstat main...HEAD`, not copied from an artifact.

**Flagged as my inference, not as evidence:**
- The **three-class split** of the 61 findings (§1) is my classification. Counts are approximate
  (`~14 / ~38 / ~9`) because several findings are genuinely split across classes — `S5` is one finding
  with an instrument half and two product halves. The *direction* is robust; the exact integers are not.
- **The one-directional self-correction claim (§6)** is an observation over 11 instances with two
  competing explanations I cannot separate from this record. Filed as a watch-item, not a conclusion.
- **"The gates earned their cost, the artifact did not" (§8)** is a judgement about proportionality,
  argued from the amendment ratio (40 of 46 repairing our own prior claims). Reasonable people could
  weigh the same numbers differently.
- **Not verified here:** the full suite was not re-run for this document (1659.77 s, consumed from the
  orchestrator's single run and reconciled arithmetically, `2201 + 29 + 1 + 2 = 2233`), and the ten
  mutant arms were not re-executed — they are not re-runnable from the tree (F-4).
