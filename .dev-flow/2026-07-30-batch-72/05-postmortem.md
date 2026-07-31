# Post-mortem — s19_app — Batch 2026-07-30-batch-72

> Phase 5 artifact. Co-authors: `architect` + `qa-reviewer`. Artifact language: English.
> Subject: the P1 design-defect implementation (CRC Designer Variant B + Legend modal Variant B).
> Branch `claude/batch-72-design-defect-634a67` @ `d13bb1c`. Every number below is read from an
> artifact or a command run in this phase; nothing is recalled.

## 🔑 At a glance (read first)

- **Outcome:** closed with carry-over — **3 iterations total** (Phase 1 ×2, Phase 2 ×1). Phase 3 and
  Phase 4 took zero. Validation verdict **PASS**, 0 blockers.
- **Top 3:**
  ① **Executing the fix instead of adopting it** — the measurement pass (`00-measurements.md`) run
  *before* folding caught a defect *inside the review itself*, killed a requirement that would have
  shipped a control that lies about its value, and turned four prototype numbers into measured ones.
  ② **Revision 1 needed nine blockers' worth of correction** — written by the session that had just
  prototyped these exact screens, and that proximity is *why* it failed, not despite it.
  ③ **The acceptance test for the batch's headline requirement did not test that requirement** (F1) —
  found by executed mutation in an independent code review, not by reading.
- **New control this batch:** **none encoded.** `~/.claude` is clean with 0 unpushed commits — no PUSH
  landed. Five candidates are classified in *Candidate lessons* below; two are portable, two are
  stack-specific, one is a corollary that should be folded into an existing control rather than
  given an id.
- **Open items → next batch:** **11** — headline: **the whole batch is unpushed** (8 commits, no
  remote branch, no PR), and `state.json`'s `decisions_log` stops at Phase 2 while the batch ran
  through Phase 6.
- **Metrics:** iterations `3` · findings `55` opened / `44` closed in-batch / `11` carried · ledger
  `2379 → 2396`.

> **Was the process proportionate to a layout change? Not on its face — and the honest answer is in
> §"Was it worth it".** ~241 lines of product source changed against ~5,000 lines of `.dev-flow`
> prose and a 26m47s gate suite. Four separate gates each found a defect that would have shipped, so
> the *spend* was justified by the *defect density in the spec* — but that density is itself the
> finding, and it is not a fact about layout work.

---

## Detail (reference)

### What worked

**1. The C-39 rider — execute your own thresholds before folding — paid for itself three times.**
Phase 2 returned nine blockers with proposed fixes. Rather than adopt them, the fold dispatched an
executed measurement run first (`decisions_log[8]`, artifact `00-measurements.md`). That caught:

| What the fold refused to adopt | Measured result | Consequence avoided |
|---|---|---|
| qa's G-1 re-scope: *"same widget class → exactly 1 violation"* | **7 pre-batch, 6 post-batch** | Would have relocated the unsatisfiable guard, not closed it |
| The prototype's `Select { height: 3 }` | `CRC-32/ISO-HDLC` renders **`CRC-32/I`** — 8 of 15 chars, no ellipsis; 4 of 6 Selects lose their bottom border | Would have shipped a control that lies about its value (`§6.5 W-1`, HLR-072-4 **withdrawn**) |
| Revision 2's G-3 non-encoding rationale (*"the batch reduces hero tiles 2→1"*) | Both tiles are identical `30x4` boxes — the change is **zero**; the 6:1 law is already FALSE on `main` at **2.54:1** | Would have left a rationalisation on the record as a measurement |

**2. Convergent independent rediscovery upgraded an opinion to a measurement.** The architect and qa
lanes ran different probes in different scratchpads and both counted **16 vertically-abutting
focusable pairs**, both concluding G-1 was unsatisfiable (`02-review.md` §"Convergence"). Neither
lane could have carried that alone at blocker weight.

**3. The re-gate caught a blocker the fold itself created** (`02-regate-architect.md` N-1). LLR-072-5.1
pinned `compose` card-first; HLR-072-6/AT-217 require key-first at the floor; Textual 8.2.8 has no CSS
ordering property. Executed at 80x24 with exactly the specified compose + CSS: `key.y < card.y` →
**False**. The tell was inside the requirement — LLR-072-6.2's threshold *"key h=4, card h=5"* is the
**key-first** measurement, so M-3 had measured a tree the requirement did not specify.

**4. The independent Inc-1/2 code review was the highest-yield single gate in the batch.** It ran 16
falsification mutations in an isolated detached worktree and returned **BLOCK on F1 (HIGH)**: removing
the `#legend_dialog.legend-narrow ` prefix from the three narrow rules collapsed the wide regime into
a vertical stack — *the exact shipped defect this batch exists to remove* — with **all 8 nodes GREEN,
exit 0**.

**5. Counterfactual hygiene held where it had previously failed.** Inc-4 established by probe that
`s19_app` resolves from `sys.path[0] == ''` and is installed nowhere, so `PYTHONPATH` cannot override
the worktree — the reason a sibling increment's counterfactual had **silently run green against the
unmutated tree**. The fix was cwd plus a throwaway `conftest.py` emitting a `pytest_report_header`
with the resolved package dir and the sha256 of the loaded module, so the transcript proves its own
tree. Plus a **control arm** (CF-3b) so a RED run cannot be a broken copy.

**6. Both defects were closed and the frozen set was never touched.** `git diff --name-only origin/main`
shows the frozen engine set absent; `legend.py` byte-identical; `29 snapshots passed, 0 regenerated`
with the snapshot-path diff **empty** — P-2 (*"any change will drift the CRC snapshot cells"*)
confirmed FALSE by a third independent probe.

### What didn't / friction

**1. Revision 1 of the requirements was not fit to gate on** — see §Root causes. Nine blockers, and
four of the six ATs could not go RED on the thing they claimed to certify.

**2. The batch is entirely unlanded.** 8 commits, no upstream, no remote branch, no PR — see §C-44.
The PLAN's own authorization gate says merge is permitted only *after* a clean final PR-level qa pass;
that pass has not run, so this is a correct stopping point, **but it is not a terminal state**.

**3. `state.json` is stale by four phases.** `current_phase: 2`, `phase_status: "approved"`, and
`decisions_log` ends at the Phase-2 approval. Every Phase 3–6 decision — the F1/F2 fold, D-1's
option C, TC-520's out-of-block allocation, the `d13bb1c` spec correction, the Phase-6 CF-count
correction — is recorded only in the increment packets and `04-validation.md`. Against the standing
operator rule *autonomy is never silent*, the canonical machine-readable record under-reports what
the agent decided on its own. This is a real miss, not a formatting nit.

**4. One review finding was neither folded nor carried.** F6 (`on_resize` discards `event` for an
unstated reason; the App-level sibling at `app.py:6212` *does* use `event.size.width`, so a future
"cleanup" would look like a fix) is absent from the on-disk docstring (`screens.py:1287` reads only
*"Re-apply the width regime when the terminal is resized."*) **and** absent from `04-validation.md`
§10's gap table, which carries F5→G-001, F4→G-002, F3→G-003 but not F6. It fell between the fold and
the carry.

**5. The evidence ledger undercounted its own evidence.** `04-validation.md` §3 originally said *"four"*
counterfactuals and omitted CF-5 and CF-6, both of which have pasted transcripts. Caught at Phase 6 by
`docs-writer` cross-reading against `03-increments/`. It understates, so no verdict moved — but a batch
that spent four gates refusing unverified claims from others shipped one of its own.

**6. Prototype teardown is owed and not done.** `PLAN.md` §"Prototype teardown" lists ~10 file globs to
delete *once both stories merge*. `prototypes/` still holds `crc_designer.p1.*`, all 21
`crc_p1.variant_*.svg` / `crc_p1.shipped.*.svg` frames, and the `p1_design_defects.*` set. Correctly
blocked on merge, but it means the batch cannot close without a follow-up action.

### Scope drift (planned vs actual)

| Planned | Actual | Note |
|---|---|---|
| 4 increments (Inc-1 Legend two-pane · Inc-2 floor regime · Inc-3 CRC compose · Inc-4 guard+docs) | 4 increments, **Inc-1 and Inc-2 landed in one commit** (`6854234`) | Packets stayed separate; the split's rationale (regime hook is a behaviour) survived in the TC allocation |
| 6 ATs (AT-213..218), TC-510..519 reserved | **7 ATs** (AT-219 added from security S-1) and **11 TCs** (TC-520 allocated outside the block) | Both additions are documented amendments (§6.5 D-2, `decisions_log[13]`) — growth by review, not by drift |
| HLR-072-1..7 | **HLR-072-4 WITHDRAWN**, **HLR-072-8 added** — 7 in force | Withdrawal on measurement (W-1); net count unchanged by coincidence |
| G-1 + G-2 encoded | **G-1 re-scoped, G-2 retired, G-3 not encoded, G-4 encoded split by regime** | Revision 1 let G-3/G-4 vanish with no disposition; §6.4 now dispositions all four |
| Prototype teardown at close | **not done** — blocked on merge | Carried |

### Metrics (full)

| Metric | Value |
|--------|-------|
| Iterations per phase | `{0:0, 1:2, 2:1, 3:0, 4:0, 5:0, 6:0}` — total **3** |
| Findings opened / closed | **55** / **44** in-batch (11 carried) |
| Findings by severity (blocker/major/minor) | **10 / 22 / 23** (blockers = 9 at the P2 gate + 1 at the re-gate; F1 HIGH counted as a major-tier blocker of the *increment* gate, tallied under increment review below) |
| Where caught (Phase 2 / P3 gate / P4) | **41 / 6 / 8** |
| Test ledger (base − D + A = post) | **2379 − 1 + 18 = 2396** — measured collection **2396**, exactly |
| Gate run of record | `2370 passed / 2 skipped / 21 deselected / 3 xfailed`, `29 snapshots passed`, **exit 0**, 1606.71s (**26m47s**) |
| Files touched · increments (cap trips) | **21** total (6 product/test/docs + 15 `.dev-flow`) · **4** increments (**0** cap trips — max 3 code files per increment vs a cap of 5) |

**Findings raised vs closed, per lane, per gate:**

| Gate | Lane | Raised (B/Maj/Min) | Closed in-batch | Carried | Evidence |
|---|---|---|---|---|---|
| Phase-2 cross-review | `architect` | 13 (4/6/3) | 13 — *"all 13 CLOSED or PARTIALLY CLOSED"* | 0 | `02-regate-architect.md` BLUF |
| Phase-2 cross-review | `qa-reviewer` | 12 (5/5/2) | 12 — *"all five of my Phase-2 blockers CLOSED"*, verdict `approve` | 0 | `02-regate-qa.md` BLUF |
| Phase-2 cross-review | `security-reviewer` | 4 (0/1/3, S-3 shared with A-6) | 4 — S-1 became US-072-3 / HLR-072-8 / AT-219 | 0 | `decisions_log[13]` |
| **P2 subtotal** | | **28 (9/12/7)** | **28** | **0** | `02-review.md` |
| Phase-2 **re-gate** | `architect` | 10 (1/6/3) | 10 — folded into revision 3 | 0 | `decisions_log[18..21]` |
| Phase-2 **re-gate** | `qa-reviewer` | 3 (0/3/0) | 3 | 0 | `02-regate-qa.md` N-1..N-3 |
| **Re-gate subtotal** | | **13 (1/9/3)** | **13** | **0** | |
| Inc-1/2 code review | `code-reviewer` | 6 (1 HIGH / 1 MED / 4 LOW) | **2** (F1, F2 at `0169108`) + F3's spirit via TC-520 | **4** (F3→G-003, F4→G-002, F5→G-001, **F6 uncarried**) | `increment-001-002-review.md` |
| Phase-4 validation | `qa-reviewer` | 8 gaps (0/0/8) | 0 — all declared minor/informational | **8** (G-001..G-008; G-001..G-003 are the same as F5/F4/F3) | `04-validation.md` §10 |
| Phase-6 docs cross-read | `docs-writer` | 1 (0/1/0) | 1 — CF ledger corrected `four`→`six` | 0 | `04-validation.md` §3 note |

> **De-duplicated carry count = 11**: G-001..G-008, F6, the unpushed branch, the stale `state.json`.

### Root causes (only if a phase took ≥2 iterations)

> **Phase 1 took two iterations. The question the operator asked is the right one: why did revision 1
> need nine blockers' worth of correction, when it was written by the session that had just prototyped
> these exact screens?**

**BLUF: prototyping proximity is a liability for a spec, not an asset — because a prototype produces
numbers that are true of the prototype and a spec needs numbers that are true of the shipped tree, and
nothing in the handoff distinguishes the two.** Four distinct mechanisms, each traceable:

**RC-1 — Prototype numbers were transcribed as measurements without a measurement.**
Every numeric geometry commitment in revision 1 (`Select height: 3`, `3fr`/`2fr`, `96%`, the "80-col
floor") came from the prototype pass with **zero** execution on the shipped tree, and none carried the
`assumed — measure` label the project's own convention requires (A-5). One of the four was
outright false in a way that would have shipped a visible defect (W-1). The prototyping session had
*seen* these numbers work — in a `VariantB` throwaway with a different widget tree. **Having built the
thing is what makes its numbers feel measured.**

**RC-2 — The prototype only ever covered one regime, and the spec did not know that.**
Premise P-7 (*"Variant B renders live"*) was recorded ✅ TRUE on the strength of the PR #164 frames.
Phase 2 re-scoped it: TRUE **for the wide case only — the B prototype has no narrow rule at all**. The
one HLR the operator was explicitly asked to confirm (HLR-072-6, floor stacking) was therefore the one
HLR with **no prototype behind it and no implementable mechanism** (A-2: `width-narrow` is applied only
to `#workspace_shell`/`#workspace_body` in the base screen; `LegendScreen` is a pushed `ModalScreen`
and a descendant of neither; Textual 8.2.8 has no media queries). A prototype's *coverage* is not
stated anywhere in a prototype.

**RC-3 — The acceptance layer was written from the design intent, not against an oracle.**
This is the dominant limb: **four of six ATs could not go RED on what they claimed to certify.**
AT-216's `Pale yellow` anchor matched a **card** caption — the pane the assertion is meant to look
*away* from — and its "without scrolling" clause was invisible to the `render().plain` harness every
shipped legend test uses (proven vacuous *on the shipped tree*, Q-4/Q-5). AT-214 was RED after a
perfect implementation under one reading and already GREEN today under the other (A-3/Q-1). AT-218 was
a regression pin mislabelled as a gate. Someone who has just watched a design work knows *what it
should look like*; an AT needs *what would be different if it didn't*, and those are not the same
knowledge.

**RC-4 — The blast-radius re-read was deferred and the debt came due.**
§2.7 P-5 itself flagged *"full blast-radius re-read owed at Phase 2"*. That re-read produced A-1: the
shipped `AT-B59-05` `query_one`s `#crc_live_verify` on five arms — all falsified by Variant B — while
revision 1 simultaneously required that file green. **Revision 1 was internally unsatisfiable**, and
the cheap escape (edit the batch-59 test into passing) is exactly the failure the flow exists to
prevent.

**The second iteration has a different, cleaner root cause.** The re-gate blocker (N-1) was **created
by the fold**, not missed by it: closing A-2 with a `legend-narrow` class introduced an ordering
contradiction against a `compose` that revision 2 pinned card-first. A fold that rewrites LLRs is an
authoring act with its own defect rate. That is not a failure of revision 2 — it is evidence the
re-gate was necessary. See the candidate-lesson assessment below.

**What would have prevented iteration 1, concretely:** running `00-measurements.md` **at Phase 1**
instead of as an iterate remedy. Every one of the nine blockers is a measurement question, and the
measurement pass — when it finally ran — took one dispatch.

### Process / workflow findings

- **The decision record diverged from the decisions.** `state.json.decisions_log` is the machine-readable
  record the standing rule points at, and it stops at Phase 2 while the batch ran to Phase 6. → Make
  `decisions_log` append a row at every phase close, and make the C-44 sweep assert
  `max(decisions_log[].phase) == current_phase`.
- **A re-gate after an LLR-rewriting iterate is currently discretionary and should not be.** It found a
  blocker of the fold's own making. → see the candidate assessment.
- **A conditional gate verdict needs a discharge *record*, not just a discharge.** F1/F2 were genuinely
  fixed (verified below) but F6 was neither fixed nor carried, and nothing structurally caught that. →
  A "BLOCK/conditional" verdict should emit a per-finding disposition table that the next gate re-reads.
- **`ruff format --check` drift is pre-existing and unenforced by CI.** Both touched test files would be
  reformatted — **identically at HEAD with the changes stashed** (G-008). Reported as *found*, not fixed.

### Product findings

- **CRC screen has no floor measurement.** `00-measurements.md` records nothing at 80x24 for the CRC
  screen and no node adds one (G-004). Bounded — the verdict is a `height: auto` `Static` inside a
  `.crc-field-row`, so an overlong string wraps rather than truncating; the M-4 silent-truncation mode
  does not apply. Still an unmeasured regime on a screen this batch rewrote.
- **AT-216 has one row of slack** — key content is 14 rows in a 15-row pane for both mac and map
  (G-006). Mitigated at the cause by clause 3 (`max_scroll_y == 0`), which fails before the symptom.
- **`Escape` does not dismiss `LegendScreen`** — `BINDINGS = ['tab','shift+tab','ctrl+c']`, measured at
  `tabs=0`. **Pre-existing**, reported as found so it is not mistaken for new.
- **G-3: the hero-extent 6:1 law is already violated on `main` at 2.54:1** — a pre-existing, unrelated
  violation this batch neither causes nor worsens.

### Control lineage

- **New control proposed this batch:** **none encoded — 0 of 4 PUSH artifacts landed.** `~/.claude` is
  clean with 0 unpushed commits, verified this phase. Five candidates classified in the next section;
  status **propose**, not adopt.
- **Prior controls exercised:**
  - **C-39 rider (re-measure your own thresholds)** — *held, and stress-tested past its stated scope*.
    It was applied to a **reviewer's** proposed threshold, not only the fold's own, and that is where
    it caught the 7-pre/6-post result.
  - **C-40 (counterfactual must redden on its own assertion)** — *held under stress*: AT-214's
    counterfactual was re-specified twice (N-2: reverting only the pair row raises `NameError`, and an
    error is not an assertion failure) and finally executed with a control arm.
  - **C-43 (premise evaluation at every gate)** — *held, and produced the batch's headline lesson*: it
    is the mechanism that caught D-1 at the validation gate.
  - **C-38 (a narrowed query that empties still passes)** — *held*: it is why P-12 (`#legend_body` may
    be retired) was measured FALSE rather than assumed.
  - **C-18 (one AT per HLR, never realized in parts)** — *held*: revision 1's smuggling of HLR-072-4's
    acceptance into AT-213's run was a named blocker (Q-8).
  - **C-44 (session-close reconciliation)** — **near-miss**: it is the control that surfaced the
    unpushed branch and the stale `state.json`, and F6 slipped past it because F6 was an *increment*
    finding, not a file.
  - **C-13/C-23/C-29 (measure, don't inherit)** — **failed at revision 1** and is the direct cause of
    RC-1. It did not fail at the flow level; it failed because nobody ran it until Phase 2 demanded it.

---

## Candidate lessons — classified before proposing (portability is the test)

> Per the standing control-placement policy: **portable principle → global `~/.claude/commands/`;
> stack-specific → this project's `docs/engineering-rules.md`; neither → batch anecdote.**
> A real global candidate owes all four PUSH artifacts: **(1)** the command change, **(2)** its
> template artifact, **(3)** the `dev-flow-lessons` catalog entry, **(4)** committed + pushed with the
> SHAs recorded. Control-encoding also requires an explicit operator `AskUserQuestion` — **none of the
> below is encoded here.** Next free id if one is granted: **C-46**.

### ① The measured-constant inversion (D-1) — **portable, but it is a RIDER on C-39, not a new control**

**The finding.** HLR-072-3 and M-1 both asserted, as present-tense fact, *"`Switch(` has exactly **one**
construction site (`crc_designer_view.py:467`)"*. Measured on `origin/main`: 1 site. Measured on HEAD:
**2 sites** (`:325`, `:327`) — because LLR-072-1.2 deleted the per-toggle helper (one `Switch(` call
invoked twice) and LLR-072-1.1 inlined both toggles. **The batch falsified its own spec constant by
succeeding at the refactor that constant described.** Option C was taken: assert the *invariant* the
count stood for (single-module confinement), which survived the refactor untouched.

**Is it distinct from C-39?** **No — and saying so is the useful answer.** C-39's rider is *re-measure
the fold's own new thresholds*, i.e. **a carried number is re-derived, not copied** (batch-63). D-1 is
the same proposition with the time arrow reversed: C-39 says *the number you inherited may never have
been true*; D-1 says *the number you correctly measured may stop being true because of what you are
about to do*. Same failure mode — a constant whose truth is tree-relative and whose tree is unstated.
Giving it a new id would fragment one rule into two half-rules.

| Option | Expected result | Consequences |
|---|---|---|
| A — new control `C-46` | A second id for the same proposition | ❌ Fragments C-39; the next author reads one and not the other |
| B — **extend C-39's rider with the inverted case** | One rule covering both time directions | ✅ **Recommended.** Adds: *when the batch is what changes the tree, prefer the invariant the number stands for* |
| C — leave as a batch anecdote | Nothing changes | ❌ Third occurrence of the class (batch-63 ledger, batch-71 baseline, here) |

**PUSH artifacts a real candidate would need under option B:** (1) command edit to the C-39 paragraph
in `dev-flow.md` + `fast-dev-flow.md`; (2) a column or clause in the premise table of
`templates/dev-flow/requirements-template.md` distinguishing *pre-batch measured* from *invariant*;
(3) `dev-flow-lessons` catalog entry citing the `1 → 2 Switch( site` transition; (4) commit + push.
**Verdict: portable, propose as a C-39 amendment, requires operator approval.**

### ② The reviewer's own proposed fix was unmeasured — **portable, and C-39's rider does NOT currently cover it**

**The finding.** qa proposed re-scoping G-1 to *"same widget class → exactly 1 violation"*. Measured
(M-1): **7 pre-batch, 6 post-batch** — still unsatisfiable. The counter-evidence was **inside qa's own
Q-1 transcript**, which listed five same-class abutting pairs; the reviewer, in its own words,
*"hedged instead of counting"*.

**Does C-39's rider already cover it?** **No.** As written, the rider is scoped to *the fold's own new
thresholds*. A number arriving in a **review finding** is neither inherited from a prior batch (C-39's
subject) nor authored by the fold — it enters through the one channel the batch is disposed to trust,
because a reviewer's job is to be right. That gap is real, it is framework-independent, and it cost a
full extra iterate's worth of near-miss: adopting the fix verbatim would have relocated the defect.

**PUSH artifacts:** (1) one sentence widening C-39's rider to *"any threshold entering the fold,
including one proposed by a reviewer"*; (2) a `Basis` column on the review-artifact's findings table so
a proposed number must cite its own measurement; (3) catalog entry; (4) push.
**Verdict: portable, the strongest genuinely-new candidate this batch produced.**

### ③ A re-gate should be mandatory after an iterate that rewrites LLRs — **portable, and this batch is the evidence**

**The finding.** The re-gate found N-1, a **blocker created by revision 2's own fold**, plus six majors
of which three were unfoldable authoring defects in predicates the fold itself wrote (N-2 unprefixed
CSS overriding the wide regime; N-3 AT-216 passing on an off-dialog layout; N-5 the order-fragile
positional unpack). qa's parallel re-gate returned `approve` with three further majors, all *"on
predicates the fold itself wrote"*.

**Does it argue for mandatory?** **Yes, but the trigger must be scoped or it becomes ceremony.** The
distinguishing property is not "an iterate happened" — it is **"the fold authored new normative text"**.
A fold that deletes a requirement, corrects a number, or relabels a pin does not need a re-gate; a fold
that writes new LLRs, new AT clauses, or a new mechanism has produced unreviewed specification, and
unreviewed specification is exactly what Phase 2 exists to catch.

| Trigger | Expected result | Consequences |
|---|---|---|
| Re-gate after **every** iterate | Maximum coverage | ❌ A one-number correction pays a full cross-review; the flow gets ignored |
| Re-gate when the fold **adds or rewrites any LLR / AT clause / mechanism** | Catches authored defects, skips clerical folds | ✅ **Recommended.** Discharge-form re-gate (*did my findings close, and did the fold create new ones?*), not a full re-review |
| Discretionary (status quo) | Depends on the orchestrator's judgment | ⚠️ It happened to be exercised here, and it caught a blocker |

**PUSH artifacts:** (1) command edit to the Phase-2 gate section defining the trigger and the
discharge form; (2) a re-gate section in `templates/dev-flow/review-template.md` with the mandatory
*"Q2 — did the fold introduce new defects?"* heading this batch used; (3) catalog entry; (4) push.
**Verdict: portable, propose. This is the second-strongest candidate.**

### ④ An acceptance test must assert the relation its requirement is *about* (F1) — **portable, and it is the project's own dominant defect class in a new dress**

**The finding.** HLR-072-5 requires the panes **side by side, card left, key right**. AT-216 carried
containment, ordering, scroll and text clauses — and **not one geometric relation between the two
panes**. Executed: unprefixing the three narrow rules collapsed 120x30 into a vertical stack (`card
Region(6,6,107,7)`, `key Region(6,13,107,8)`) and **all 8 nodes stayed GREEN**. Two weaker mutations
(swap `3fr`/`2fr`; wide key `height: 1fr → auto`) confirmed the same axis was unguarded.

**Is there a statable rule?** **Yes, and it generalises past layout.** *Containment, ordering and
presence are true of many arrangements including the defective one; a requirement stated as a
**relation between two things** must be asserted as a relation between those two things.* Note this is
not merely "test the requirement" — AT-216 *did* test HLR-072-5's subject; it tested four true
properties of it, none of which was the **discriminating** one. The rule is about picking the
predicate that separates the required arrangement from its nearest wrong neighbour.

This is the same species as the standing candidate **"assert the emitted encoding"** (now 8+
occurrences, still un-encoded) and as C-40's vacuity limb — the family the `dev-flow-lessons` meta-rule
already names: *the dominant defect class is the vacuous check, and it concentrates in SPECS.*

**PUSH artifacts:** (1) an AT-authoring clause in the command's Phase-1 section: *"for any requirement
stating a relation between two named subjects, name the assertion on that relation, and name the
nearest wrong arrangement it excludes"*; (2) a `Nearest wrong neighbour` column in the AT table of
`templates/dev-flow/requirements-template.md`; (3) catalog entry; (4) push.
**Verdict: portable — but it should be merged with the "assert the emitted encoding" candidate into one
control about discriminating predicates, rather than encoded as a fifth near-duplicate.**

### ⑤ The counterfactual that silently ran against the unmutated tree — **SPLIT: mechanism is stack-specific, obligation is portable**

**The finding.** `PYTHONPATH` cannot override a package resolved from `sys.path[0] == ''`. `s19_app` is
installed nowhere — no editable install, no `.pth` — so running from the worktree meant the worktree
always won, and a sibling increment's private-copy counterfactual **ran GREEN against the unmutated
tree and looked like a pass**.

**Classification — this is two claims and they belong in different places:**

| Claim | Portable? | Where it belongs |
|---|---|---|
| *`PYTHONPATH` does not override `sys.path[0]`; use cwd, and build the copy with `cp -r`, never `git worktree add`* | ❌ **No** — Python import mechanics + this repo's install state | `s19_app/docs/engineering-rules.md`. Pushing it globally would pollute every non-Python project |
| *A counterfactual must prove, **from inside its own run**, which tree it loaded* | ✅ **Yes** — every language has a resolution order and every one of them can surprise you | Global command, as a clause on C-40 |

The portable form is exactly what Inc-4 built: a `pytest_report_header` printing the **resolved package
directory and the sha256 of the loaded module**, so the transcript is self-authenticating — plus the
**control arm** (CF-3b: same copy, same harness, file restored → GREEN), which is the part that proves
a RED run is not just a broken copy. Neither is Python-specific.

**PUSH artifacts for the portable half:** (1) a clause on C-40 in `dev-flow.md` + `fast-dev-flow.md`:
*"a counterfactual transcript must identify the tree it ran against, emitted by the run itself, and
carry a control arm"*; (2) `Tree of record` + `Control arm` rows in the counterfactual block of
`templates/dev-flow/validation-template.md`; (3) catalog entry; (4) push. **The stack-specific half
needs no global artifact — it is a `docs/engineering-rules.md` edit in this repo only.**
**Verdict: portable half → propose as a C-40 clause; mechanism half → project engineering-rules.**

### Summary of classifications

| # | Candidate | Classification | Disposition |
|---|---|---|---|
| ① | Measured-constant inversion (D-1) | Portable — **corollary of C-39** | Amend C-39's rider; do not mint a new id |
| ② | Re-measure a **reviewer's** proposed threshold | **Portable — genuinely new** | Propose (widen C-39's scope). Strongest new candidate |
| ③ | Mandatory re-gate after an LLR-rewriting iterate | **Portable — genuinely new** | Propose, with the trigger scoped to *authored normative text* |
| ④ | Assert the relation the requirement is about (F1) | Portable — **near-duplicate** of the standing "assert the emitted encoding" candidate | Merge both into one *discriminating predicate* control |
| ⑤a | `PYTHONPATH` / cwd / `cp -r` mechanics | **Stack-specific** | `s19_app/docs/engineering-rules.md` |
| ⑤b | Prove the tree from inside the run + control arm | **Portable** | Propose as a C-40 clause |

---

### Open / deferred items → next batch

| Item | Type | Reason deferred | Trigger / owner |
|------|------|-----------------|-----------------|
| **Push the branch, open the PR, run the final PR-level `qa-reviewer` pass over the whole diff vs `main`, merge** | process | Phase 6 not closed; the kickoff grant gates merge on that pass | **Immediate.** Executing session |
| **`state.json` is stale by four phases** — `current_phase: 2`, `decisions_log` ends at the Phase-2 approval; Phases 3–6 autonomous decisions unrecorded there | process | Discovered in this sweep | Batch close; **re-read before writing (concurrency hazard)** |
| **F6 — `on_resize`'s `event`-discard rationale is unstated**, and it is in no gap table | product | Neither folded nor carried at the increment gate | One docstring line, next code-touching batch |
| G-001 — AT-218 clause 4 is a gate-run property the node's docstring does not label as out-of-node | product | Review F5, not folded | One sentence, `tests/test_legend_two_pane.py:420-430` |
| G-002 — `#legend_body { overflow: hidden }` pinned by nothing (executed: revert → 8 green) | product | Review F4, symptom invisible at current content sizes | One line in TC-518's stylesheet scan |
| G-003 — `on_mount`'s width argument unpinned (a `Resize` masks it) | product | Review F3, code is correct | Optional coverage note |
| G-004 — **the CRC screen is unmeasured and unpinned at the 80x24 floor** | product | No measurement exists; out of the increment cut | Backlog a floor measurement |
| G-005 / G-006 / G-007 — G-1 coincides with AT-213 today · AT-216's one row of slack · AT-219 observes the markup flag, not the value, for 4 of 6 sinks | product | Openly stated scope limits, each mitigated at the cause | Informational tripwires |
| G-008 — `ruff format --check` drift, **identical at HEAD with changes stashed** | process | **Pre-existing**, `ruff format` not enforced by CI | Reported as found, not swept |
| **`BACKLOG-CODE.md:153` asserts a premise measured FALSE three times** (*"any change will drift the CRC snapshot cells"*) | process | Backlog correction is a close step | Backlog reconciliation |
| **Backlog entries owed with their measurements attached**: W-1 (`Select` affordance density — the lever is pane *width*), R-1 (retired G-2 state-word guarantee), G-3 (pre-existing **2.54:1** hero-extent ratio vs a 6:1 law) | product | Withdrawn/retired, deliberately not dropped | Already in `R-TUI-100`'s *"deliberately does NOT claim"* block; mirror to `BACKLOG-CODE.md` |
| **Prototype teardown** — `prototypes/crc_designer.p1.*`, 21 `crc_p1.*.svg` frames, `p1_design_defects.*`, `p1_review_build.py`, `p1-design-defects-review.html`, `legend_p1.*` | process | Correctly blocked on merge (absorb-then-delete) | Post-merge |
| **Control candidates ① – ⑤** — 5 classified, **0 encoded** | process | Control-encode requires an explicit operator `AskUserQuestion` | Operator decision; next free id **C-46** |
| Legend variants for `map` / `a2l` / `issues` views were never shot-captured | product | Out of scope, runnable live | Already in backlog lane A |

---

### Working-file reconciliation (C-44) — MANDATORY, every file this batch touched

> **Swept mechanically in this phase, not from memory.** Commands executed:
> `git status --short` · `git log claude/batch-72-design-defect-634a67 --not --remotes --oneline` ·
> `git rev-parse --abbrev-ref @{u}` · `git ls-remote --heads origin | grep batch-72` ·
> `git log --name-status b556e35^..HEAD` · and the same status/unpushed pair inside `~/.claude`.

**🔴 HEADLINE FINDING: the entire batch is unlanded.**

```
$ git rev-parse --abbrev-ref --symbolic-full-name @{u}
fatal: no upstream configured for branch 'claude/batch-72-design-defect-634a67'

$ git ls-remote --heads origin | grep -i batch-72
(no output)

$ git log claude/batch-72-design-defect-634a67 --not --remotes --oneline
d13bb1c  batch-72 docs — correct the spec constant the batch itself falsified (D-1) + TC-520 row (D-2)
37474b5  batch-72 Inc-4 — G-1 guard (AT-214/TC-514), focus pin (TC-520), REQUIREMENTS.md rows
0169108  batch-72 Inc-1/2 review fold — close F1 (HIGH) and F2 (MEDIUM)
a4f2d2e  batch-72 Inc-3 — CRC Designer Variant B compose (AT-213/215/219, TC-510..513)
6854234  batch-72 Inc-1/Inc-2 — Legend two-pane + floor regime (AT-216/217/218, TC-515..519)
54c4b29  batch-72 Phase-2 re-gate discharged, Phase 2 APPROVED — the fold's own blocker caught
0a56ef6  batch-72 Phase-1 iterate — revision 2 folds 9 blockers; two requirements withdrawn
b556e35  batch-72 Phase 1 approved + Phase 2 cross-review — 9 blockers, iterate
```

**8 commits · 0 pushed · no remote branch · no PR · no upstream configured.** This is a *correct* state
for the flow (Phase 6 has not closed and the kickoff grant gates merge on a clean final PR-level qa
pass), but per C-44 it is **not a terminal state**: work that is finished and unlanded is
indistinguishable from work never done.

| Repo | File(s) | Terminal state | Landing / backlog ref |
|------|---------|----------------|-----------------------|
| `s19_app` | `s19_app/tui/crc_designer_view.py` (+98) | ✅ committed — **⚠️ UNPUSHED** | `a4f2d2e` (Inc-3) |
| `s19_app` | `s19_app/tui/screens.py` (+85) | ✅ committed — **⚠️ UNPUSHED** | `6854234` (Inc-1/2) |
| `s19_app` | `s19_app/tui/styles.tcss` (+58) | ✅ committed — **⚠️ UNPUSHED** | `6854234`, `a4f2d2e` |
| `s19_app` | `tests/test_legend_two_pane.py` (new, +817) | ✅ committed — **⚠️ UNPUSHED** | `6854234`, `0169108` (F1/F2), `37474b5` (TC-520) |
| `s19_app` | `tests/test_crc_designer_view.py` (+541) | ✅ committed — **⚠️ UNPUSHED** | `a4f2d2e`, `37474b5` |
| `s19_app` | `REQUIREMENTS.md` (+150 — `R-TUI-100`, `R-LEGEND-MODAL-001`, `R-LEGEND-GEOMETRY-001`) | ✅ committed — **⚠️ UNPUSHED** | `37474b5`, `d13bb1c` |
| `s19_app` | `.dev-flow/state.json` | ✅ committed — **⚠️ UNPUSHED**, and **stale by four phases** | `b556e35`, `0a56ef6`, `54c4b29` → 📋 **backlog: bring to Phase 6 + append Phase 3–6 decisions** |
| `s19_app` | `.dev-flow/…/PLAN.md`, `00-measurements.md`, `01-requirements.md` | ✅ committed — **⚠️ UNPUSHED** | `b556e35`, `0a56ef6`, `54c4b29`, `d13bb1c` |
| `s19_app` | `02-review.md` + `02-review-{architect,qa,security}.md` | ✅ committed — **⚠️ UNPUSHED** | `b556e35` |
| `s19_app` | `02-regate-{architect,qa}.md` | ✅ committed — **⚠️ UNPUSHED** | `54c4b29` |
| `s19_app` | `03-increments/increment-00{1,2,3,4}.md` + `increment-001-002-review.md` | ✅ committed — **⚠️ UNPUSHED** | `6854234`, `a4f2d2e`, `37474b5` |
| `s19_app` | `04-validation.md` | ⚠️ **UNTRACKED** (`?? .dev-flow/2026-07-30-batch-72/04-validation.md`) | 📋 **owed — commit at the Phase-5/6 close** |
| `s19_app` | `06-docs/` (`executive-summary.md`, `functionality.md`, `traceability-matrix.md`, `diagrams/`) | ⚠️ **UNTRACKED** (`?? .dev-flow/2026-07-30-batch-72/06-docs/`) | 📋 **owed — commit at the Phase-6 close** |
| `s19_app` | `05-postmortem.md` (this file) | ⚠️ **UNTRACKED** — created by this phase | 📋 **owed — commit at the Phase-5 close** |
| `s19_app` | `prototypes/crc_designer.p1.*`, `crc_p1.variant_*.svg` (21 frames), `crc_p1.shipped.*.svg`, `p1_design_defects.*`, `p1_review_build.py`, `p1-design-defects-review.html`, `legend_p1.*` | 📋 **in backlog** — teardown owed, correctly blocked on merge (`PLAN.md` §Prototype teardown) | Post-merge follow-up |
| `~/.claude` (flow/config) | — | ✅ **CLEAN** — `git status --short` empty, `git log @{u}..HEAD` empty | HEAD `061bf93`, 0 unpushed. **No control was pushed this batch** |

**Pre-existing dirt found, NOT swept up:** `ruff format --check` reports both touched test files would
be reformatted — **identically at HEAD with the changes stashed** (`04-validation.md` G-008). Not this
batch's, not folded into this batch's commits. `ruff check` → `All checks passed!`.

**Nothing this batch produced was discarded.** Every artifact is either committed-on-an-unpushed-branch,
untracked-and-owed-at-close, or explicitly carried to the backlog. 🗑️ column: **empty**.

**Conditional gate verdicts.** Two gates in this batch closed conditionally; both are discharged below.

| Conditional item | Discharged? | Verified how |
|---|---|---|
| **Inc-1/2 code review closed `BLOCK — F1 (HIGH) must be fixed before the gate`** (`increment-001-002-review.md:338`) — *"add AT-216 clause 2c (two assertions, values already measured) and correct `increment-002.md:154`'s specificity claim"* | ✅ **YES** | **Re-read on disk, not trusted.** `git show 0169108 -- tests/test_legend_two_pane.py` adds `card_pane = legend.query_one("#legend_card_pane")` and two measured keys; the assertions land as **clause 0** (the review proposed the label "2c" — the *predicate* is identical, the numbering is not). Verified **still present at HEAD** by grep of the working tree: `tests/test_legend_two_pane.py:172` `"key_right_of_card": key_pane.region.x >= card_pane.region.right`, `:173` `"panes_share_a_row": key_pane.region.y == card_pane.region.y`, asserted at `:212` and `:217`. The commit body carries a byte-verified C-40 discharge: `styles.tcss` `c65ac445…` → mutated `010c44b2…` → restored `c65ac445…`, RED **on its own assertion line** with `key=Region(6,13,107,8)` / `card=Region(6,6,107,7)` — the exact stack the reviewer measured. `04-validation.md` §3 CF-2 independently re-hashed the worktree `styles.tcss` to `c65ac445…` in Phase 4, confirming the mutation left nothing behind |
| **Same gate, F2 (MEDIUM)** — *"regex instead of a whitespace-exact substring, plus a 120x30 probe"* | ✅ **YES** | Re-read on disk: `tests/test_legend_two_pane.py:667` `height_auto = re.compile(r"height\s*:\s*auto", re.IGNORECASE)` used at `:669`; the live probe loops `:681` `for size in ((80, 24), (120, 30))`. `import re` added at the module head. Both survive at HEAD |
| Same gate, **F3 / F4 / F5** (LOW, *"none blocks"*) | ⚠️ **carried, not fixed — correctly and explicitly** | `04-validation.md` §10 G-003 / G-002 / G-001, each with its measurement attached |
| Same gate, **F6** (LOW) | ❌ **NOT discharged and NOT carried** | Re-read `s19_app/tui/screens.py:1287` — the docstring is still the bare *"Re-apply the width regime when the terminal is resized."* with no note on why `event` is discarded; and F6 appears in **no** row of `04-validation.md` §10. **This is the gap the C-44 sweep found that the flow did not** |
| Same gate, **focus-traversal recommendation** — *"pin the properties, not the literal chain… this belongs in **this** batch"* (`:330`) | ✅ **YES** | `tests/test_legend_two_pane.py:756` `test_tc520_legend_focus_traversal_is_pinned_in_both_regimes`, landed at `37474b5`, reconciled to a collected node in `04-validation.md` §2 with all three recommended clauses: `legend_close` initial focus in both regimes, both pane ids in `focus_chain`, key precedes card at 80x24 |
| **Phase-2 gate self-approved under the kickoff grant** (`decisions_log[22]`) — conditional on Coverage/Certainty/Evidence all MET on revision 3 | ✅ **YES** | `04-validation.md` §11 re-verifies all three axes independently at Phase 4: 7/7 ATs + 11/11 TCs reconciled to distinct **collected** nodes (`--collect-only`, not intent), 13/13 inputs + 21/21 outputs, ledger reconciling exactly, both pins labelled |
| **Merge authority**, conditional on *"a clean final PR-level `qa-reviewer` pass over the whole diff vs `main`; a HIGH finding blocks and returns to the operator"* (`PLAN.md:18-20`) | ⏳ **NOT YET DUE** | The pass has not run and no PR exists. Recorded so it is not mistaken for satisfied |

---

### Was it worth it? — the proportionality question, answered plainly

**BLUF: the ceremony was disproportionate to the change and proportionate to the spec's defect density,
and the second fact is the one worth carrying.**

The arithmetic is unflattering. The product delta is **241 lines across three source files** — a compose
rewrite, a regime hook, and ~58 lines of CSS. Against that: **~5,000 lines of `.dev-flow` prose** (a
~20:1 ratio), 3 iterations, 5 reviewer dispatches across 3 gates, 6 executed counterfactuals, and a
**26m47s** gate suite run once in full. For a layout change, that reads as over-process.

But every gate found something that would have shipped:

| Gate | What it caught | Would it have shipped? |
|---|---|---|
| Phase-2 cross-review | `Select { height: 3 }` truncating `CRC-32/ISO-HDLC` to `CRC-32/I` with no ellipsis | **Yes — a visible defect**, and one the batch was introducing deliberately |
| Phase-2 cross-review | HLR-072-6's mechanism cannot reach a `ModalScreen` | **Yes** — Phase 3 would have improvised a mechanism with no requirement governing it |
| Phase-2 measurement pass | The reviewer's own replacement guard was also unsatisfiable (7→6) | **Yes — as a green, vacuous guard** |
| Phase-2 re-gate | The fold's own key-first/card-first ordering contradiction | **No — it would have failed loudly mid-Phase-3.** Cost: an increment's rework |
| Inc-1/2 code review | AT-216 green on the *exact shipped defect the batch exists to remove* | **Yes — as a green test certifying a broken layout.** The worst kind |
| Phase-4 / Inc-4 | D-1: the batch's own spec constant falsified by its own success | **Yes — as a RED test asserting a falsified premise**, or a re-planted brittle constant |

Five of six would have shipped. So the spend bought real defect removal — but **the reason there were
so many defects to remove is that the spec was authored from a prototype without measurement** (RC-1
through RC-4), and that is a *fixable input condition*, not an intrinsic property of layout work.

**The honest counterfactual: running `00-measurements.md` at Phase 1 instead of as an iterate remedy
would plausibly have collapsed Phase 1 to a single iteration.** Every one of the nine blockers is a
measurement question, and when the measurement pass finally ran it was one dispatch. The 2 iterations
are the price of deferring one cheap step, not the price of the V-model.

**What we would keep and what we would cut, if this batch ran again:**

| Element | Keep / cut | Why |
|---|---|---|
| Measurement pass at **Phase 1** | **Add** | The single highest-leverage change; likely removes iteration 1 entirely |
| 3-lane parallel Phase-2 review | **Keep** | Convergent rediscovery is what made G-1's unsatisfiability a measurement rather than an opinion |
| Re-gate | **Keep** | Found a blocker of the fold's own making |
| Independent increment code review | **Keep — it was the highest-yield gate per unit of effort** | F1 alone justifies it |
| 4-increment split | **Cut to 3** | Inc-1 and Inc-2 shipped in one commit anyway; the packet split added prose without adding a gate |
| ~5,000 lines of artifact prose | **Cut ~30%** | Several sections restate measurements already tabulated elsewhere; the discipline is the *measurement*, not the word count |
| 26m47s full gate run | **Keep** | It is the only run that certifies the ledger, and the ledger reconciled exactly |

---

### Evidence checklist — architect + qa-reviewer

**`architect`**

- [x] **Constraints stated explicitly** — ✓ frozen-source set, Textual 8.2.8 (no media queries, no CSS
      ordering property), zero-snapshot-drift, the 80x24 floor and 120-col breakpoint read from
      `app.py:6202`: `01-requirements.md` §1.2/§2.4, `00-measurements.md`.
- [x] **At least 2 alternatives considered** — ✓ three G-1 scopings measured before adoption (any-focusable
      16→15 ✗ · same-class 7→6 ✗ · `Switch`-only 1→0 ✓), `decisions_log[9]`; D-1's four options tabled at
      `increment-004.md:469-474`.
- [x] **Recommendation has rationale tied to constraints** — ✓ the screen-owned regime hook is *necessary*,
      not preferred: `width-narrow` provably cannot reach a `ModalScreen` (`app.py:6203`), verified twice
      independently (`02-review.md` A-2; `increment-001-002-review.md:109`).
- [x] **Risks listed (operational / security / cost / lock-in)** — ✓ `01-requirements.md` §6.3 (5 risks) +
      `04-validation.md` §10 (G-001..G-008); security lane returned **0 blockers**, its one major became
      HLR-072-8/AT-219 rather than being waved through.
- [x] **Cost / latency estimated where relevant** — ✓ gate suite **1606.71s**; 21 files / 6854 insertions;
      ledger `2379 → 2396`; per-increment file counts vs the 5-file cap (max 3, **0 trips**).
- [x] **Diagram included when flow is non-trivial** — ✓ owned by Phase 6: `06-docs/diagrams/` +
      `06-docs/traceability-matrix.md`. Not duplicated here.
- [x] **What would change the recommendation is stated** — ✓ explicitly: a Textual version exposing a CSS
      ordering property retires the `move_child` hook; one extra legend key row breaches AT-216's
      one-row slack (G-006); a `Switch` constructed outside `crc_designer_view.py` reddens TC-514.
- [x] **Two-layer requirements** — ✓ every story carries a first-class Acceptance block + `AT-NNN`, and
      **both** chains exist: behavioural US→AT→outcome (`04-validation.md` §4.1, 7/7 bijective per C-18)
      and functional US→HLR→LLR→TC (`01-requirements.md` §5.2 + `04-validation.md` §2, 11/11).

**`qa-reviewer`**

- [x] **Acceptance criteria use Given/When/Then (or the house equivalent)** — ✓ every AT states
      *pilot at `<size>`, reached through `<binding>` → drive `<input>` → assert `<observable>`*.
- [x] **Test cases have explicit Expected, not vague "works"** — ✓ literals throughout:
      `0xCBF43926 → 0x1898913F`, `max_scroll_y == 0`, `card_height >= 2`, mac `(17,6)` / map `(20,7)`,
      `Unit.FRACTION`, `key.x >= card.right`.
- [x] **Edge cases include empty / boundary / invalid / error** — ✓ `04-validation.md` §12: empty
      (`query("#crc_live_verify") → 0`), boundary (80x24 floor, 14-in-15 rows), invalid (bogus census id;
      `NO-EXPECTED` and `Invalid parameters` near-misses excluded **by name**), error (`NoMatches` early
      return observed as surface immobility).
- [x] **Regression checklist exists** — ✓ supersession sweep (§7: 0 live deps on any retired marker),
      the two labelled pins (§5), the declared blast radius re-run green at every increment gate
      (**108 passed** at Inc-4).
- [x] **Exit criteria stated** — ✓ Coverage / Certainty / Evidence, per axis with basis, at the Phase-1
      gate, the Phase-2 gate, the re-gate and Phase 4.
- [x] **No real PII / secrets** — ✓ this artifact contains test ids, hashes, geometry, git output and
      file paths only. Host paths appear as `<worktree>` / `<scratchpad>` in the source artifacts.
- [x] **Test results left blank unless actually run** — ✓ every number here is transcribed from an
      artifact or from a command executed in this phase, attributed to its owner (gate run →
      orchestrator per C-25; CF-1/CF-4 → Inc-1/2; CF-2 → the F1 fold; CF-3/3b → Inc-4; the 16-mutation
      table → the independent code review). **This phase ran only `git` reads and greps.**
- [x] **Conditional verdicts discharged by re-reading, not by trusting** — ✓ F1 and F2 re-read at
      `0169108` **and** re-grepped on the HEAD working tree; **F6 found undischarged and unrecorded**,
      and reported rather than smoothed over.
- [x] **No unfilled template** — ✓ no `<...>`, no placeholder id, no empty required row.
