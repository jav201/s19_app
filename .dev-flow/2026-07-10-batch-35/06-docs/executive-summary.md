# Executive summary — s19_app — Batch 35

> **Artifact language:** English. Phase 6 artifact. Audience: non-technical stakeholder.
> 1–2 pages.

## 🔑 Bottom line (read first)

- **What we delivered:** engineers can now hand a customer a *focused* firmware report —
  showing only the parameters and memory regions that customer should see — with a
  built-in audit stamp that says exactly which filter was applied and how much was left
  out; plus a clearer patch-editor layout that separates "apply a patch" controls from
  "run checks" controls.
- **Business outcome:** report sharing without over-disclosure, with zero risk of a
  filtered report masquerading as a complete one — and the tool's existing behavior is
  provably unchanged when no filter is used.
- **Next step:** merge the batch (operator's call), then run the two standing post-merge
  procedures (snapshot refresh in CI, Linux CI proof). This closes the **last
  top-priority item** of the July backlog.

---

## Context

`s19tool` / `s19tui` is the team's firmware inspection and patching tool. Its generated
reports — the "what changed, where, and did the checks pass" documents — are used as
**engineering evidence**: they get attached to deliveries, audits, and customer
hand-offs. Until now, every report was all-or-nothing: it showed everything in the
loaded firmware image.

## Problem

Two frictions, one large and one small:

1. **No way to hand over a focused report.** When a delivery concerns only a handful of
   calibration parameters, the full report over-discloses: it exposes every other
   modified region and check result in the image. Engineers had no supported way to
   scope a report to just the relevant symbols or memory ranges — and any manual
   trimming of a generated report would destroy its value as evidence.
2. **Confusable controls.** In the patch editor, the button that *applies a patch* and
   the button that *runs checks* sat in one mixed row — easy to press the wrong one.

## Solution

- **An operator-authored report filter.** The engineer writes a small, human-readable
  filter file listing the parameter names (with wildcard support) and/or address ranges
  a report should include, drops it in the project's `filters/` folder, and picks it
  from a dropdown before generating. Both report kinds honor it.
- **A report that declares its own incompleteness.** Every filtered report opens with a
  mandatory audit header naming the filter file and stating, per section, how many items
  are shown and how many were hidden. A filter that matches nothing still produces a
  report that loudly says so. A broken filter file **refuses** to generate anything —
  with a plain-language explanation — rather than silently falling back to a full or
  partial report. The A↔B comparison report is deliberately exempt and always complete,
  so unexpected differences can never be filtered out of sight.
- **Unchanged default behavior, proven.** With no filter selected, reports are
  byte-for-byte identical to what the tool produced before this change — verified
  against reference outputs, with the verification itself stress-tested three separate
  times.
- **Clearer patch editor.** The controls now sit in two labeled groups — patch-script
  actions vs check actions — with zero change to what any button does.

## Outcomes / results

- **Scope delivered in full:** filter engine, both filtered report kinds, the selection
  UI, and the patch-editor regroup — 7 planned-plus-one increments, all reviewed and
  approved.
- **93 new automated tests** (project suite grew to 1,363 checks; final run fully
  green), including 17 end-to-end acceptance tests driven through the real UI surfaces.
- **0 high-severity review findings** across the whole batch; all 32 review findings
  (of any severity) closed before batch close.
- **Default behavior provably untouched:** byte-identity of unfiltered reports proven
  by reference-output comparison, triple-verified.
- **Frozen core untouched:** 0 changes to the tool's protected parsing/validation
  engine, confirmed by automated guards.
- **Measured limits (not estimated):** worst-case (deliberately maximal) filters cost a
  few seconds of UI stall; realistic filters are instantaneous. Documented for
  operators.
- **Milestone:** this was the last P1 (top-priority) item of the 2026-07-09 baseline
  backlog — **the entire P1 set is now closed, pending merge**.

## Next steps

1. **Now:** operator reviews and merges the pull request (no self-merge, per standing
   rule).
2. **Immediately post-merge (standing procedure, ~same day):** canonical
   snapshot-baseline refresh in CI for the two patch-screen visuals; confirm the Linux
   CI run is green (the cross-platform proof for the reference-output checks).
3. **Next batch (fresh kickoff, fresh authorization):** the P2/P3 backlog pool
   (items B-11..B-19) plus small hygiene carries — each already named and scoped in the
   batch post-mortem.
