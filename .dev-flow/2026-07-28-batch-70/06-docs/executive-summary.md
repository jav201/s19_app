# batch-70 — executive summary

**A saved flow now runs across every image variant in a project and the results fuse into one
report that cannot silently truncate its own evidence.** Shipped as `R-TUI-099`, merged 2026-07-29 as
PR #159 (squash `b457ef8`), CI green, full suite `2350 passed / 0 failed`.

**The engineering value was not in the code — it was in refusing to trust the inherited design.**
Two defects were found by executing the design's premises against disk before writing anything, and
neither could have been caught by a test: the design said the source image is "overridden per
variant" without saying in what *form*, and the obvious form is rejected by the project's own
containment seam by design; and the decision "one report, **and no per-variant files**" had its
second clause assigned to no increment, so a flow with a report block would have written one file
per image while every composer test stayed green.

**What the operator gets:** pick a scope on the Flow Builder — *This image* (unchanged default),
*All variants*, or *Assigned variants* — press Run once, and read a single report whose header states
both the worst outcome across images **and** the counts that invert it, whose per-variant sections
cannot be evicted by a noisy neighbour, and whose every cut names what it dropped.
