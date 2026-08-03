# Executive summary — s19_app — Batch `2026-08-01-batch-77`

> **Artifact language:** English (`state.json.language`).
> Phase-6 artifact. **Audience:** non-technical stakeholder. Merged as PR #186 on 2026-08-02; record closed 2026-08-03.

## 🔑 Bottom line (read first)

- **What we delivered:** the Memory Map's region bar now shows regions **at sizes proportional to how much memory they occupy**, instead of drawing every region one column wide regardless of size — plus a keyboard path through the regions and an inspector that fills itself when a file is loaded.
- **Business outcome:** an engineer opening a firmware image can now *see*, at a glance, which parts of memory are large and which are small. Previously the picture was technically present and practically useless. The change covers **15 of the 16** reference files we ship; the remaining one is measurably better but not yet solved, and it is the scheduled subject of the next batch.
- **Next step:** **batch-78**, which inherits a fully-measured charter for the one remaining case. Every measurement it needs has already been taken and paid for.

---

## Context (reference)

### Context

The Memory Map is the screen an engineer opens to understand the shape of a firmware image: which address ranges contain data, how large each is, and where the gaps are. It renders a single horizontal bar in which each mapped region gets a slice, plus an address ruler beneath it and a per-region list beside it.

This batch was the first substantial rework of that screen since batch-47. It began from an operator-approved design prototype ("Variant A") and expanded to cover six adjacent defects found during specification.

### Problem

> **The map's band bar did not fail to show regions — it failed to distinguish them. Every region rendered one column wide regardless of size.**

The underlying cause was that the bar scaled its slices against a **hard-coded constant** rather than against the width it was actually given on screen. At the wider terminal size the real width was **21 columns** against an assumed 60, so the arithmetic overflowed and a safety floor flattened every region to a single column. On our primary reference image, **5 of its 14 regions were rendered invisible entirely.**

Three further problems compounded it:

| | Effect on the engineer |
|---|---|
| The address ruler placed **4 of its 5 labels on addresses that exist in no mapped range.** | The one element meant to orient the reader was pointing at nothing. |
| Coverage was reported as `0.00%` and the largest gap as `67108408 bytes`. | Both true, both unusable. A percentage that reads zero for every sparse image conveys no information. |
| The inspector panel was empty until the engineer clicked a region, and there was **no keyboard route to the regions at all.** | Every inspection required a mouse. |

### Solution

Four changes, all inside the existing screen. No new command, no new option, nothing for an operator to learn.

1. **The bar is measured, not assumed.** Slice widths now derive from the bar's real on-screen width. We also widened the bar itself by laying it out above the summary panel at every terminal size rather than beside it — taking it from **21 to 50 columns** at the wider regime.
2. **The allocation is bounded where it is produced.** Each region is guaranteed one column, and the remaining space is shared out in proportion to how many bytes each region actually holds. Because the limit is enforced at the point the widths are calculated rather than checked afterwards, the bar cannot overflow its container. On the primary reference image everything now fits **exactly**, with no region hidden.
3. **The ruler labels what the bar draws** — one label per region start, plus the last mapped byte. Where there is not enough room for every label, it drops interior ones legibly rather than crushing them all to zero width.
4. **The screen works without a mouse.** A region is selected and inspected the moment a file loads, and `↑` / `↓` / `Enter` move through and inspect regions.

### Outcomes / results

| Measure | Before | After |
|---|---|---|
| Bar width at the wider terminal size | 21 columns | **50** |
| Regions rendered invisible on the primary reference image | **5 of 14** | **0** |
| Ruler labels pointing at unmapped addresses | **4 of 5** | **0** |
| Coverage readout | `0.00%` · `67108408 bytes` | **`0.0008%`** · **`64.0 MiB`** |
| Gestures needed to inspect a region after load | 1 click | **0** |
| Keyboard access to regions | none | **↑ ↓ + Enter** |
| Reference files fully covered | — | **15 of 16** |

**Quality of the work itself:**

- **The automated test suite grew from 2 519 to 2 612 checks** — 94 added, 1 retired — and the **frozen engine was left untouched**. The engine is the part of the product that parses firmware; it is deliberately locked, and an automated dual guard confirmed a zero difference in both its source and its tests **at every one of the ten increments**. Nothing in this batch could have changed how a file is read.
- **All 29 visual baseline images were restored to full oracles** after a controlled regeneration, with no stale exemptions left behind.
- **Zero blocking findings at the merge review.** Two high-severity findings were raised and both were *record* defects — documentation that did not match what shipped — not defects in the product. The evidence for that claim is that the test suite was **unchanged** across the corrective pass, which is only possible if every edit was documentation.
- **Across roughly twenty review passes, exactly one defect was found in shipped product code — and continuous integration found it, not review.** On a machine slower than the development machine, the bar briefly reverted to its old flattened display on first render. It was reproduced, root-caused, fixed at the mechanism rather than by adding a delay, and covered by a new regression check. *(The "roughly twenty" figure is an estimate and is labelled as such in the technical record; no artifact states the exact total.)*

**Stated plainly, because a summary that hides it would be misleading:** one of our sixteen reference files — the heavily-fragmented one, with 801 regions — remains **unreadable on the bar**. Batch-77 makes it better and does not make it good. What it does guarantee for that file is that the screen renders without error and that **all 801 regions stay reachable in the region list.** That limit is written into the requirement itself rather than left implied.

### Next steps

| When | What | Why it is ready |
|---|---|---|
| **Next batch (78)** | Solve the heavily-fragmented case by grouping the smallest adjacent regions, with the fragmented file as the acceptance target **from day one**. | The path was deliberately deferred from this batch after review found seven of eight objections concentrated in it. **Eleven supporting measurements were taken and retained**, so batch-78 inherits a fully-measured charter rather than starting from scratch. It must also add a time budget: the grouping algorithm is quadratic and was measured at 840 ms for 5 000 regions. |
| **Next batch (78)** | Confirm the coverage limit on the new first-render safeguard. | Four related display paths were verified correct but are not yet guarded automatically. Registered in the live work queue. |
| **Reversible on request** | Two small affordances were deliberately dropped — an `o` keyboard shortcut for opening a region in hex, and a size label on gap markers. | Neither is blocked by a defect. The hex view remains reachable by double-click. Each has a written reopening condition. |
| **Housekeeping** | Advance the batch state file past its stale phase marker, resolve one saved work-in-progress stash, and untrack eight stray build files that predate this batch. | Small, known, and listed. |
| **Owed to the operator** | One process decision carried since batch-76, plus four new control proposals arising from this batch, each awaiting an explicit approval before being encoded. | Listed in the process backlog with their supporting evidence. |

---

### One thing worth carrying out of this batch

The most useful finding was not about the map at all.

A helper function in shipped source carried a docstring claiming it neutralised dangerous terminal escape sequences. **It did not.** More consequentially, **nine automated checks across five test files had been written against that claim and were all passing** — every one of them certifying, in effect, that a raw escape byte reaching the screen was safe. The false statement had been absorbed into the tests built to catch it, and they then defended it.

> **A green test suite is not evidence that a guarantee holds. It can be evidence that the guarantee's negation has been ratified.**

All nine checks were repaired rather than deleted — each keeps its original claim, with the new safety clause asserted beside it — and the underlying gap was closed inside this batch rather than deferred.
