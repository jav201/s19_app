# Executive Summary — Hex Compare Mode (US-006)

**Project:** s19_app (`s19tool`) — firmware/calibration engineering tool
**Batch:** 2026-06-11-batch-09
**Date:** 2026-06-13
**Status:** Complete and validated (PASS-WITH-NOTES; notes are documentation-only, no defects)

---

## Context

`s19tool` is the tool firmware and calibration engineers use to inspect S19/HEX firmware images alongside their A2L/MAC calibration symbol files. Engineers routinely need to answer a deceptively simple question: **given two builds of the same firmware, what exactly changed?** The two images may both belong to the current project, or one (or both) may be an external file handed over from another team or supplier.

## Problem

Until now there was no built-in way to compare two images. Engineers fell back on eyeballing hex dumps or stitching together ad-hoc tooling. That approach has three concrete failure modes:

- **It is error-prone** — a missed byte in a manual hex comparison is a silent defect.
- **It gives no certainty about meaning** — knowing that a byte changed is not the same as knowing *which calibration symbol* that byte belongs to.
- **It produces no auditable artifact** — there is nothing durable to attach to a change record or hand to a reviewer.

The user story (US-006) asked for a comparison mode that works across project and external images, checks them against the shared A2L/MAC artifacts, notes which artifacts each image actually uses, and produces a diff report — extending to N-way comparison if feasible.

## Solution

We delivered a **hex compare mode** built in three reusable layers:

1. **A diff engine** — a self-contained component that takes two firmware images and produces the complete, deterministic list of differences, classifying every change as *changed*, *only in A*, or *only in B*, with summary statistics. It carries no UI dependencies, so other parts of the tool can reuse it.
2. **A dedicated A↔B Diff screen** — the previously-empty "A2B Diff" panel in the tool now shows the real comparison: the list of differing regions and, for any selected region, side-by-side hex views of both images. For each image it notes which shared calibration artifacts it uses — **both, one, or none**.
3. **A complete, auditable diff report in two formats** — a **Markdown** file (with red/green diff cues that render correctly in GitHub, VS Code, and Obsidian, degrading gracefully to plain text elsewhere) and a **safe, self-contained HTML** file (inline styling only, no scripts, no external links). Where a difference touches a calibration symbol, the report annotates *what the change represents*, not just that bytes differ. The reports list in the existing report viewer.

Two deliberate design decisions shape the deliverable:

- **The report file is always complete.** A mid-project review caught an early design that would have truncated large report files. We corrected it: the on-screen view is what gets capped for performance — **the written report is never truncated**, because it is the authoritative artifact.
- **Pairwise (two images) by choice.** N-way comparison was assessed as technically feasible but deferred, because two-image comparison keeps the screen and the report clear and fast. The clause was answered, not dropped.

## Outcomes

| Measure | Result |
|---|---|
| Requirements specified and validated | 5 high-level / 26 low-level — **100% validated** |
| New test cases | **29**, all passing |
| Full test suite | **750 passed / 0 failed** (29 skipped, 3 expected-fail) |
| Delivery increments | **6**, each gated and reviewed |
| New external dependencies | **Zero** |
| Security | One **adversarial** test confirms the HTML export cannot carry an injection payload (all embedded values escaped; no scripts or network references) |
| Reusability | The compare engine is a reusable substrate; its **first downstream consumer arrives next batch** |

The single quality highlight is the truncation catch described above: a design that was internally consistent and passed specification review was still **intent-wrong**, and was caught at a hands-on checkpoint and corrected to a complete-file design *before* delivery — not after.

## Next steps

The compare engine built here is the foundation for the next batch of work:

- **HEX emitter + verify-on-save** — the ability to save an image, immediately re-read it, and diff it against what was intended, **reusing this batch's compare engine** as its first real consumer. This validates the engine as a shared building block.
- **Project manifest writer** — a `project.json` to record project contents.
- **Queued hygiene** — small, already-identified cleanups.
- **First special operation (CRC)** — remains queued, pending the operator's definition of the operation.
