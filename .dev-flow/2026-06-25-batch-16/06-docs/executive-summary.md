# Executive Summary — Batch-16 (US-017)

**Per-variant file assignment at project save**
**Outcome: PASS · 0 defects · 0 blocker failures · delivered 2026-06-25**

---

## Context

The tool manages firmware projects that ship in several **variants** — different builds of the same product (for example, regional or hardware-specific versions). When an operator saves a project, the saved project file records which variant is currently active so the work can be reopened and re-run exactly as it was.

## Problem

Saving recorded *which* variant was active, but not the **files an operator wanted applied to it**. A variant often needs extra supporting files (change documents, verification documents), and a project often has files meant to apply across every variant. Before this batch, **there was no way to assign those files at save time**, so the saved project never recorded them — and the engine that executes a batch had nothing to pick up.

This was a known **"surface gap"** carried over from an earlier batch (batch-11). The underlying engine could already store and use these assignments; what was missing was the operator-facing path to set them. The capability existed, but no one could reach it.

## Solution

We added a **file-assignment surface to the Save dialog**. When saving, the operator can now:

- Assign extra files to **each individual variant**.
- Assign files **project-wide** (applied to every variant).

Those choices are written into the saved project file, and the **batch-execution engine now reads and applies them** when the project runs. For safety, assignable files are **restricted to the project folder** — an attempt to assign a file outside that folder is refused and no project file is written.

## Outcomes

| Measure | Result |
|---|---|
| Overall verdict | **PASS** — 0 defects, 0 blocker failures |
| Increments delivered | 2 (payload + engine wiring, then the assignment UI) |
| Automated tests | **922 → 933** (+11), full suite **900 passed / 0 failed** |
| Core / engine code changed | **0 lines** (engine-frozen and substrate modules both untouched) |
| Findings | 0 blocker · 4 major · 9 minor — **all resolved** |
| Independent code review | **2 of 2 approved**, no high or medium issues |

Three points stand out for a stakeholder:

1. **No core or engine code changed.** The verification confirms — by a direct file-by-file comparison against the baseline — that **zero** engine code was modified. The engine already supported this; the work was purely connecting the operator's screen to a capability that was already there. That is the lowest-risk class of change.
2. **Every saved project re-reads identically.** Saving a project and reopening it reproduces the exact same file assignments with **no drift**, verified end-to-end through the real Save dialog (not a shortcut around it).
3. **A test-quality gap was caught and fixed mid-build.** During validation we noticed our own acceptance test was taking a shortcut — it checked the saved file without actually going through the Save dialog. Rather than let it pass quietly, we flagged it and rebuilt it to exercise the **whole chain end-to-end** (save through the real dialog → re-read what was written → confirm the execution engine picks it up exactly). This is the honest, defensible way to close the gap the batch existed to close.

## Next steps

The remaining backlog is small and prioritized:

- **Compare-view coverage** — extend automated acceptance tests to the side-by-side comparison feature (carried item C-9).
- **Minor cleanups** — a pre-existing lint nit in the main app file, handled as its own small change so it doesn't ride along here.
- **Sync the batch record** to the knowledge vault now that the work is closing.

This batch also produced a **reusable testing rule** worth keeping: for any feature where a file is *saved* and later *consumed*, the acceptance test must follow one unbroken chain — drive the real save surface, re-read exactly what it wrote, then confirm the consumer uses it — never a hand-written stand-in. That rule would have caught the shortcut above at the moment it was written, and it now guards future work of the same shape.
