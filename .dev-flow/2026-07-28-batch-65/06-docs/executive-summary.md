# batch-64 — executive summary

**One part of the report generator could run a machine out of memory before writing anything. That
part is now bounded, and when it has to leave something out it says so, in the report, by name. The
larger memory problem in the same file is deliberately still open, and this document says so as
plainly as the change itself does.**

---

## Context

s19tool produces evidentiary Markdown reports: documents an engineer relies on as a record of what a
firmware change did. One optional section of that report, the *declared-region addendum*, answers a
specific question — *"for each memory area I named, what changed inside it, and what went wrong?"*

The input to that section comes from a change document supplied by whoever is being reviewed. Its
size is not under the tool's control.

## The problem

Building that section assembled every finished line in memory **before writing a single byte**, and
it re-read the entire input **once for every memory area declared**. Cost grew as the product of three
numbers — areas declared, firmware variants, and entries per variant — at roughly 90 bytes per line.
Doubling any one of the three doubled the memory.

The tool already has a size limit on the finished report. It could not help here: the limit only sees
lines that have been handed to it, and the whole collection was built first. So the failure happens
before anything the limit can measure exists. This is the most likely cause of a host machine running
out of memory during an earlier development session.

Two things made this worth doing carefully rather than quickly. First, the section had **no direct
tests at all** — nothing protected it against a rewrite going quietly wrong. Second, the obvious fix
(just stop after N lines) is unsafe: whoever supplies the change document also controls what appears
first, so a flood of trivial warnings can push a genuine error out of view. A cap that drops evidence
silently turns an evidentiary document into a misleading one.

## What was done

Three changes, together:

1. **One pass instead of one pass per area.** The input is read once. Which area an address belongs to
   is now found by binary search rather than by re-scanning. Measured: the number of items examined
   dropped from 19 200 to 300 on the test case, and no longer changes when more areas are declared.
2. **A hard limit per area and per category, applied while building** — not applied to the finished
   document. That is what makes the memory bounded rather than the output truncated.
3. **A truncation notice.** Whenever the limit removes something, the report itself gains a line, in
   that area's own section, naming the category that was cut, how many items were dropped, and which
   variants lost evidence. The reader can now tell *"there is no error here"* apart from
   *"an error existed and did not fit."* That distinction is the whole point of the third change, and
   it is the reason the batch refused a simpler design that would have been cheaper and faster.

A report that stays below the limit is **byte-for-byte identical to what the tool produced before**.
This was verified against a copy of the old output captured before any code was touched.

## Outcome

| | |
|---|---|
| Production change | 2 files, ~600 lines |
| Tests | 2 201 → 2 233; none deleted, no regressions, full suite green |
| Unchanged output below the limit | 6 of 6 sample reports byte-identical, 0 stored baselines moved |
| Correctness of the new lookup | ~34 000 generated geometries compared against ground truth, **0 mismatches** |
| Defects found in the shipped code, by anyone, at any stage | **0** |
| Independent reviews | 6 formal reviews, 2 code reviews, 1 validation pass — **61 findings**, all dispositioned |
| Security review | cleared **unconditionally** — the first unconditional pass in several batches |

The security result is worth one sentence of explanation, because it is a direct consequence of how
the work was scoped: the review cleared it *because the requirement claims only what the change
actually does*. Prior attempts at this area were blocked for claiming to have closed a memory-
exhaustion risk they had not closed. This one does not claim it, so there was nothing to dispute.

## What this does **not** fix

This is not a caveat section. It is the main finding for anyone deciding what to do next.

- **The memory-exhaustion risk in the report generator is still open.** Two other tables in the same
  file — the modifications table and the checklist — are completely uncapped, at roughly **11 times**
  the per-item cost of the section that was just fixed, and unlike it they still grow with input size.
  At realistic inputs **they dominate**: on the order of 99 MB for one large change document, and
  several gigabytes across eight documents and eight variants. A large report can still exhaust
  memory. **Nothing in this change prevents that.**
- **Declaring more memory areas still costs more.** The work of deciding *which* area an address falls
  into still grows with the number of areas declared — the multiplier was moved, not removed. Measured
  at 256 declared areas, the tool performs 128 000 comparisons to produce a single line of output. It
  is disclosed, instrumented, and reversible by a known technique; it was not done here because doing
  it would have added real complexity to a function whose purpose was to get simpler.
- **The number of memory areas an operator can declare has no limit at all.** Each one costs between
  a measured 11.6 kB and 20 kB, and both figures are lower bounds. That is a self-inflicted rather
  than hostile exposure, but it is uncapped.
- **The truncation notice makes evidence loss visible; it does not prevent it.** Within a category,
  the first items in the supplied document order are still the ones kept. What the change guarantees
  is that the reader is told.
- **Above eight affected variants, the notice reports how many were affected, not which.** The count
  is exact; the naming is capped, because an uncapped list would put the variant count straight back
  into the memory bound this work exists to establish.

Every one of these is recorded in the shipped requirement with the number that was measured for it,
and every one has been entered on the engineering backlog. None is a discovery made after the fact.

## Next steps

1. **Take the two uncapped tables next.** This is now the highest-priority item in the code lane on
   merit — it is the actual memory-exhaustion path. The hard parts are already paid for: the bounding
   pattern, the measurement technique, and the disclosure-notice design are all worked examples now.
2. **Cap the number of declarable memory areas.** Small change; closes two of the residuals above at
   once by mirroring a limit the codebase already has elsewhere.
3. **Fix a related defect found in passing.** The same flawed address-lookup shape was found live in
   another module, where it produces wrong output that *is* shown to the operator. It is filed with a
   reproduction and the in-repo fix pattern.

## Process note

Six reviews raised 61 findings and found **zero** defects in the code. Roughly a quarter of the
findings were the *specification* claiming something the system did not do — the requirement document
outrunning the design it described. That is the honest headline: the engineering was right from the
first draft; the writing about it had to be corrected repeatedly, and the review process is what
caught it.

The cost lands accordingly. The reviews earned their keep — without them, this would have shipped a
requirement asserting a property that is false by a factor of the number of declared areas, plus
seven acceptance tests that would have silently verified nothing on every report. The 3 400-line
specification behind a 600-line change did not earn its keep, and the recommendation carried forward
is a smaller document, not fewer reviews.
