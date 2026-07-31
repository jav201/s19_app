# batch-74 — Post-mortem

**`report_service` producer bounding + the `Address` cell** · `R-TUI-101` · Lane A · 2026-07-31

> **BLUF — one finding is worth more than the feature.**
>
> **An output-shaped predicate cannot bound an allocation, and the gap is not theoretical — it is
> byte-identical.** This batch executed it twice on two different axes:
>
> | Axis | Defective shape | Output | Residency |
> |---|---|---|---|
> | byte-run width (Inc-1) | `format-then-slice` | **identical** — 7 nodes green, incl. the positive control and `test_f17` | 9,490 B → **56,683,416 B (5,973×)** |
> | `Address` (Inc-2) | `format-then-slice` | **identical** — AT-246's *three* conjuncts all green | ratio 1.000 → **9.976** |
>
> A predicate that reads the emitted document is blind to *how much it cost to produce it*. That is the
> whole of OB-4, and it is why every bound this batch ships is gated by a **residency oracle** whose own
> discrimination is executed by a paired falsifier.
>
> **The second finding is about us, not the code.** Across three increments and two review gates in
> this module, **every real defect was in a specification or an acceptance — none was an implementation
> bug.** The shipped code was correct at every site every reviewer attacked. What was missing, every
> time, was a predicate that *could have failed* if it had not been.
>
> ⚠ **This document asserted the completeness of its own remedy, and the assertion was FALSE.** An
> earlier revision of this BLUF read *"every bound this batch ships is gated by a residency oracle
> whose own discrimination is executed by a paired falsifier."* The final PR gate executed it: three
> surfaces were gated and **`_checklist_lines`' cardinality was not**. A full-population-then-slice
> checklist producer is output-identical and survived all 31 nodes at a ratio of **9.087**. Closed by
> `AT-241b`/`TC-546b` before merge — but the lesson is that **the post-mortem repeated the batch's own
> defect while describing it**: a universal claim, written from three confirming instances, never
> enumerated the population it quantified over. See **L-7**.

## 1. What shipped

| | |
|---|---|
| **Requirement** | `R-TUI-101` — two-axis producer bound on `_modifications_lines` / `_checklist_lines`, plus the `Address` cell |
| **Merged as** | see `06-closeout.md` |
| **Production files** | `s19_app/tui/services/report_service.py` (only) |
| **Test ledger** | `tests/test_report_producer_bound.py` **0 → 33**; `test_report_field_census.py::test_f17` amended by **widening** a closed alphabet |
| **Gate suite** | `pytest -q` (full, `slow` included): **2434 passed, 2 skipped, 3 xfailed, 29 snapshots**, 25m08s |
| **Goldens re-baselined** | **0** |
| **Frozen-engine diff** | **0** (both guards) |
| **Iterations** | Phase 1: **3** · Phase 2: **3** (cap reached → escalated) · Phase 3: **1** |

## 2. Premise evaluation (C-43) — the batch's headline number

**Seven inherited or self-authored premises came back FALSE, each with an executed counterexample.**
The full table is `01-requirements.md` §2.7. The distribution is the finding:

| Source of the false premise | Count |
|---|---|
| The inherited plan / the backlog | 3 (`988 B/entry` flat · `_ByteBudget` closes F4 · a cap < 415 re-baselines a golden) |
| **This batch's own specification, written by me** | **4** (`md_safe` on byte cells drifts nothing · "a huge *address* denies the report" · "the Address cell is bounded at 3574 chars" · "traversal shall not terminate" is a requirement) |

**More than half of the falsified premises were mine, and they were falsified by executing my own
document.** The plan warned that it was a hypothesis; nothing warned that the specification would be.

## 3. What the process caught, and where it caught it

| Stage | Caught |
|---|---|
| Phase 0 | `P-14` — the flat `988 B/entry` is not a constant. **This single measurement forced a second axis into the design**; a row-count cap alone bounds the table at ~1.2 GB |
| Phase 2 (3 lanes, blind to each other) | 7 distinct blockers from 12 raw. **All three lanes independently found the same top one** — `AT-227` was unsatisfiable — which is what upgrades it from opinion to measurement |
| Phase 2 re-gate | 3 NEW blockers **created by the fold itself**, with a diagnosable pattern: *the requirement's scope moved and the AT predicate stayed behind* |
| Phase 2 → operator | **Iteration cap reached → escalated rather than looped.** The operator re-scoped |
| Inc-1 review | `F1` HIGH — the width axis had no falsifier |
| **Inc-2 review** | **`F1`+`F2` HIGH — five of the reviewer's 16 mutations survived a 29-node suite** |

**The independent reviewer earned its cost at both increment gates, on the same defect class, after the
implementer had explicitly gone looking for that class.** At Inc-2 I had written TRAP 3's falsifier
*first*, and still shipped four more holes of the same shape one level down.

## 4. Lessons

### L-1 — An output-shaped predicate cannot gate an allocation. Residency is the only honest oracle.

Executed on two axes (table in the BLUF). **A consumption counter is not a substitute on either**: on
the cardinality axis it is invariant (P-25), and on the width axis it goes **RED on correct code**,
because `_format_bytes` deliberately drains an un-sized iterator to count what it elided.

**Transferable rule:** *when a requirement constrains WHERE a bound is applied rather than WHAT is
emitted, no assertion over the emitted artifact can gate it.* Reach for a resource oracle, and pair it
with a falsifier that proves the oracle discriminates.

### L-2 — Fixture SHAPE is part of the acceptance, not an implementation detail. **← the new one**

Every `Address` fixture I wrote was all-`F`. On an all-`F` value:

- rendering the **trailing** `K` digits is **byte-identical** to rendering the leading `K`;
- `bit_length() // 4` is **byte-identical** to `(bit_length() + 3) // 4`, because the `+3` is a no-op
  whenever the top nibble is ≥ 8 — and every `F`-leading value satisfies that.

So `TC-549`, **the node that quotes that exact ceiling formula in its own assertion**, could not
exercise it. A uniform fixture collapses distinctions the requirement depends on, and it does so
*silently* — the suite is green and the count is right.

**Transferable rule:** *for any predicate over a positional or digit-wise property, ask what the fixture
makes indistinguishable.* A fixture whose symmetry matches the operation under test cannot see the
operation. This is a **new** control candidate: the existing catalog covers vacuous *predicates*, not
vacuous *fixtures*.

### L-3 — Bounding a number without changing its FORM is a forgery, not a bound.

A hex address truncated to `0xFFFF…` is still a well-formed numeral: **indistinguishable from a
complete one**, understating by `2**12248` on a 3572-digit value. In an evidentiary document that
converts a memory fix into an integrity defect. The truncated form must **fail** the complete-value
regex *and* state what was elided.

**Corollary that cost a Phase-2 iteration:** the symmetric hole — *a form change with no residency
gate* — was **unregistered** in the vacuity register while its mirror image was registered. Registers
of known-bad shapes need to be closed under symmetry.

### L-4 — A carried number is re-derived, not copied. I broke this on my own figure.

I measured "14 occurrences" on the **Inc-1** file, then appended the Inc-2 block and quoted 14 as
current. It was **26**. The independent reviewer caught it (F5). This is **C-39 applied to my own
work**, and it failed in the one place C-39 does not instinctively point: not at an inherited number,
but at one I had measured myself an hour earlier.

**Refinement:** *a number is stale the moment the artifact it describes changes* — re-derive at the
point of quotation, not at the point of measurement.

### L-5 — Noticing a hole and executing it are different acts.

I self-caught the saturated/zero-kept gap and **recorded it while deferring the fix**. The reviewer
found it independently (F3) **and executed it**, producing the failure message the arm now carries.
The record shows my note and its finding as the same observation — but only one of them was a test.

### L-6 — A presence-grep cannot pin a claim. `TC-497` proved it by staying green.

`TC-497` greps `REQUIREMENTS.md` for residual figures **verbatim**. Inc-3 rewrote non-claim (a) to
declare `988 B/entry` **FALSE** — and `TC-497` stayed **GREEN**. It cannot distinguish an assertion
from its refutation. Registered as a MAJOR with its fix shape (bind the figure to its subject and its
section; a bare token scan can only ever pin a token).

### L-7 — A universal claim needs its population ENUMERATED, not sampled. **← found by this document being wrong**

I wrote *"every bound this batch ships is gated by a residency oracle"* after gating three surfaces. I
never listed the bounds this batch ships and checked them off. The fourth — `_checklist_lines`'
cardinality — was named by the requirement in the same breath as the first, and was ungated. The claim
was assembled from confirming instances, which is exactly how the seven false premises in §2 were
assembled.

**Transferable rule:** *when a summary says "every X", write the list of X and tick it.* The cost is one
list; the failure mode is a document that certifies its own gap. Note the asymmetry that made this
survivable: the omission was found because an independent gate **enumerated the producers** rather than
reading the claim.

## 5. What went well

- **The escalation at the iteration cap.** Phases 1 and 2 each burned their full budget; the standing
  instruction (*"si topas el cap, escala conmigo — no hagas loop"*) was followed, and the operator's
  re-scope removed ~half the requirement surface and produced a shippable batch. **A third autonomous
  iteration would have spent the budget on the requirement that was least defensible** (F4, unclosable
  while five sibling producers stay ungated).
- **The split was made safe by writing the measurements down.** `BACKLOG-CODE.md`'s batch-75 charter
  carries every unspent number. Without Inc-3 the re-scope would have been a deletion with better
  manners.
- **C-12 ordering was enforced by the commit graph**, not by prose: the Inc-0 golden commit touches
  only `tests/goldens/batch74/`, auditable via `git log --diff-filter=A`.
- **0 goldens re-baselined**, on a batch that added two caps and a new column.

## 6. What to carry

| Carry | Where |
|---|---|
| **F4** (the `_ByteBudget` gate) + **D2** + `V`/`F` + `_applied_regions`, with every measurement | `BACKLOG-CODE.md` → batch-75 charter |
| **`TC-497` cannot tell an assertion from its refutation** | `BACKLOG-CODE.md`, MAJOR |
| Four `R-TUI-101` wording carve-outs found by implementing | `BACKLOG-CODE.md`, P3 |
| **L-2 (vacuous FIXTURES, not just vacuous predicates)** as a control candidate | `BACKLOG-PROCESS.md` / `/dev-flow-lessons` |
| **The zero-drift property is EXACTLY spent** at `MAX_REPORT_ROWS_PER_VARIANT = 200` — the largest single `(document, variant)` golden table is exactly 200 | recorded in the constant's docstring |

## 7. Honest residue

- `REPORT_ADDRESS_HEX_DIGITS` has **no in-domain exercise**: every real address is 8 digits, so the
  bound fires only on wire-forged values. Its correctness rests on an executed golden census and on the
  byte-identity control, not on production traffic.
- The `services → changes.io` import is **new coupling**, taken to make `LLR-106.3`'s derivation
  reproducible. Direction is precedented and there is no cycle, but it did not exist before.
- **`R-TUI-101` makes a bounded claim on purpose.** Seven non-claims, each carrying its executed
  number. Anyone reading it as "the report is now memory-safe" is reading it wrong — the document is
  still not byte-bounded, `V` and `F` are still uncapped, and `_applied_regions` is still unbounded.
