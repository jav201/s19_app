# Executive summary — s19_app — Batch 2026-07-30-batch-72

> Phase-6 artifact. Audience: non-technical stakeholder. Artifact language: English. 1–2 pages.
> No prior knowledge of the codebase is assumed, and no internal shorthand is used.

## 🔑 Bottom line (read first)

- **What we delivered:** we fixed three usability defects the operator found in hands-on testing on
  28 July — two on the checksum-designer screen, one on the colour-legend pop-up. Both screens were
  re-laid-out. Nothing about what the tool *calculates* changed.
- **Business outcome:** the tool's two most-consulted reference surfaces now say what they mean at a
  glance. A pair of controls that looked like a single control is now plainly two; a self-test
  result that was taking premium screen space has moved next to the field it actually reports on;
  and the colour key that explains the whole screen is now visible the moment you open it, instead
  of about eighteen lines further down a scroll.
- **Next step:** the work has **passed formal verification with no blocking issues**. What remains is
  the closing review and merge. Four follow-up items are already written down with their evidence so
  nothing is lost.

---

## Context

The product is an internal engineering tool for working with automotive firmware files. Engineers
use it to inspect firmware images, cross-check them against the sidecar files that name and locate
regions inside them, and design checksum algorithms. It runs as a full-screen terminal application —
no browser, no mouse required.

Two of its screens are the subject of this work:

- the **checksum designer**, a workbench where an engineer defines a checksum algorithm and watches
  the result update live, and
- the **colour legend**, a pop-up that explains what each colour on the current screen means.

Both screens were built to work first and given their visual layout later. The layout pass was
checked for *structure* — does the screen have the right number of columns, does the right panel
exist — but never for *legibility*: whether a control actually reads as one control. That gap is
what produced this batch.

## Problem

**The operator tested the tool by hand on 28 July and reported three things, all of which turned out
to be layout defects with a single common cause.**

1. **Two switches read as one control.** On the checksum designer, two on/off toggles sat directly
   on top of each other with no border, no gap and no separator. Visually they formed a single
   block. An engineer could easily flip the wrong one — and on a checksum bench, flipping the wrong
   parameter produces a plausible-looking but wrong result.
2. **A self-test result had been given the best real estate on the screen.** One panel showed
   whether the algorithm being edited reproduces a published reference value. That is a useful
   sanity check when you are hand-building an algorithm, but it is a bench convenience, not an
   operational result — and it was occupying a prominent tile at the same visual weight as the panel
   that reports actual warnings.
3. **The colour legend hid the thing it exists to show.** The pop-up stacked a worked example on top
   of the colour key, in a single scrolling column. On a standard terminal the visible area is
   fifteen lines and the content is around forty. Opening the legend showed you the example and
   nothing else; the colour key — the reason anyone opens the legend — began roughly eighteen lines
   below the fold. To find out what a colour means, you had to scroll past the example that used it.

## Solution

**Two screens were re-laid-out. No calculation, no data handling and no external behaviour changed.**

- **Checksum designer.** The two toggles were merged into one labelled control — `Reflection`, with
  an `in` toggle and an `out` toggle, each with its own label, and the second label physically
  separating them. The self-test result was moved out of its prominent tile and placed directly
  beneath the field it validates, where it now also names the reference value it tested against.
  The space that tile freed up went to the warnings panel, which now owns that column outright.
- **Colour legend.** The pop-up now shows the worked example and the colour key **side by side**,
  each scrolling independently. On a standard terminal the entire colour key is on screen the
  instant the pop-up opens — no scrolling at all. On a small terminal, where two columns will not
  fit, the two panels stack with the **colour key on top**, which is the arrangement the operator
  chose when asked.

**Two proposed changes were deliberately not shipped, and that is a result rather than a shortfall.**

- A rule to shrink the dropdown selectors on the checksum bench was tested before being written and
  **rejected**: it silently truncated the algorithm name `CRC-32/ISO-HDLC` to `CRC-32/I` — eight of
  fifteen characters, with no "…" or any other sign that text had been cut — and it broke the border
  on four of the six selectors. A control that quietly lies about its own value is a worse defect
  than the crowding it was meant to fix. The crowding finding is real and was written to the backlog
  with its measurement attached; the effective fix is a wider column, which is a larger redesign.
- A proposed rule requiring every toggle to display its state as a word or symbol was **retired**.
  It belonged to a different design option than the one the operator selected, and the check
  originally written to enforce it was found to be testing something else entirely — wiring that was
  already covered elsewhere. It, too, went to the backlog rather than being quietly dropped.

## Outcomes / results

| Outcome | Measure |
|---|---|
| **Formal verification result** | **Pass, with no blocking issues.** Verified independently of the people who wrote the code |
| All three reported defects closed | Each one verified by driving the real screen through the real keyboard shortcut, not by inspecting code |
| No regressions | Full test run: **2,370 tests passed**, 0 failed, plus **29 screen-image comparisons passed** with none needing to be regenerated |
| Test coverage grew | **18 new checks added**, 1 deliberately retired (see below). Total moved from 2,379 to 2,396, and the arithmetic was reconciled two independent ways |
| The checksum designer is now documented for the first time | It shipped in an earlier batch and had **never** been recorded in the project's requirements document. It now has a requirement of its own, including an explicit list of what that requirement deliberately does *not* claim |
| Independent review found — and blocked on — a real gap | An independent reviewer who wrote none of the code proved that the legend's central property (the two panels being side by side) was asserted by **no test at all**: they broke the layout deliberately and every test still passed. The gap was closed before the work advanced |
| Nothing off-limits was touched | The tool's parsing and validation core is locked against modification and guarded automatically. Both guards passed and the comparison against the mainline branch is empty |

**One test was deleted on purpose, and it is worth explaining why.** An earlier batch had written a
check asserting that the self-test result renders as a prominent centred tile. That is precisely the
arrangement the operator asked us to change, so all five of its assertions are now false by design.
It was **deleted outright rather than edited into passing** — editing a check so it agrees with the
new behaviour would have destroyed the record that a decision was reversed. The obligation it
genuinely protected — that the result stays present, correctly placed and reachable — was rewritten
into a new check.

**A note on how the numbers in this batch were produced.** Several figures the plan started from
turned out to be wrong when someone actually measured them, and each was corrected before any code
was written: a claim that changing this screen would disturb the stored screen images was false
(there are none for these screens); a claim about how many rows the colour key occupies was not
reproducible at any width actually used; and a count the specification pinned down was falsified by
this batch's own success, because the very change we made altered the thing being counted. All three
corrections are recorded with their evidence.

## Next steps

| # | Step | Owner | Timing |
|---|---|---|---|
| 1 | Closing review, then merge and publish the batch documentation to the knowledge base. Verification is already complete and passed | Batch coordinator | At close |
| 2 | One small correction to the verification record itself: it lists four of the six deliberate break-it-and-check-the-test-fails exercises that were actually run. The two missing ones are fully documented elsewhere in the batch, so this understates the evidence rather than overstating it | Batch coordinator | At close |
| 3 | File the four carried findings on the backlog with their measurements attached — the selector crowding, a pre-existing screen-proportion issue this batch neither caused nor worsened, the retired toggle-state rule, and one backlog note that was measured false | Batch coordinator | At close |
| 4 | Optional hardening, none of it blocking: three small test and documentation improvements the independent reviewer recommended and explicitly marked as not blocking | Next batch | Next batch |
| 5 | Not scoped, carried: measure the checksum bench at the smallest supported terminal size, and consider the column-width redesign the withdrawn selector change pointed at | Future batch | Unscheduled |

---

### Verification of this summary

Every figure above is copied from an executed test run or measurement recorded in this batch's
working documents; none is an estimate. The test figures come from the formal verification run, and
they were cross-checked against a second, earlier complete run performed during implementation — the
two agree exactly. The one point on which the batch's own documents disagree is the count of
deliberate break-it exercises, and that disagreement is recorded in the detailed traceability record
rather than smoothed over here.
