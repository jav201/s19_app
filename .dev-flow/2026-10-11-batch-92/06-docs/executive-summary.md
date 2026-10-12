# Executive summary — s19_app — Batch 2026-10-11-batch-92

> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `presentation-builder`. Audience: non-technical stakeholder. 1-2 pages.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

## 🔑 Bottom line (read first)

- **What we delivered:** A behavior-preserving cleanup of the codebase's module map — the pure renderer, the markup-safety filter, and the micro-bar/style primitives now live in presentation-neutral homes (`s19_app/render/`, `s19_app/utils.py`) instead of inside the TUI layer. 6 of the 7 measured layer inversions are dead; nothing the user sees changed by a single byte.
- **Business outcome:** the codebase is now safe to split into parallel workstreams — the structural blocker for the next refactor (batch-93, the Memory Map pass) is removed. Users and screens see zero difference, proven byte-for-byte.
- **Next step:** batch-93 rebases onto this tree and starts its source increments (already queued per the coordination note); the local test suite's pre-existing flakiness goes to triage as its own backlog item.

---

## Context (reference)

### Context

`s19_app` is being split into parallel batches maintained by separate agent lanes. A 2026-10-11 dependency radiography (an automated census of who imports whom, rendered at `G:/My Drive/dev-flow-radiografia/Refactor_10_11_26/Diagramas/`) found 7 "layer inversions": lower-layer service modules importing TUI presentation modules. Those crossing edges are what make files unsafe to assign to different workstreams, because two lanes end up owning each other's code.

### Problem

Three shared building blocks — the hex renderer, the hostile-text scrubber (`safe_text`, a security filter that stops file contents from being parsed as display markup), and the micro-bar/style constants — were hosted inside TUI modules, so every lane's work touched TUI files. One of the 7 edges could not be fixed this batch: its home file, `tui/color_policy.py`, is under an operator-declared freeze (US-92-5 deferred).

### Solution

Moved the three primitives to neutral addresses and repointed every consumer, in two increments, under a strict no-behavior-change discipline: the moved code is byte-identical (verified by independent hash recomputation), generated reports match a pinned pre-move capture byte-for-byte (AT-288), and new automated "census" tests now fail immediately if anyone re-creates one of the bad import edges — including edges added by future batches. The frozen file was respected by data copies pinned to it, not edits.

### Outcomes / results

- **6 of 7 measured inversions killed**; the 7th (`change_service → color_policy`) is a declared, operator-approved deferral — not hidden debt.
- **2 increments, 0 HIGH-severity issues open at close**; 17 review findings opened and 17 closed.
- **0 user-visible change**: every screen, report, and snapshot byte-identical (AT-288 oracle; 43 repointed regression tests green).
- **5 full-suite executions (~3 hours of gate time)** were spent characterizing a pre-existing flaky-test problem on this machine — the noise pre-dates the batch (it reproduces on untouched base code). This was the batch's real cost center, and it is now a measured, named carry rather than a surprise.
- Merged to main as `a67407c` (PR #210) after a clean independent merge-gate review.

### Next steps

- **Batch-93 (Memory Map cohesion pass)** — contract already written; holds its source work until this merge, then rebases onto the refactored tree (sequencing agreed in `COORDINATION-batch93-memmap.md`).
- **Suite-flakiness sharpening** — triage the 52-node known-unstable corpus (quarantine or fix the harness-level timing races); deliberately **not** absorbed into this behavior-preserving batch — BACKLOG lane A.
- **US-92-5** — unblock the last inversion only with explicit operator words lifting the `color_policy.py` freeze.

### Risk disposition

One carry matters for planning: **the local full-suite gate is not sharp on this machine** (36–40 failures per run on identical code). The batch shipped anyway because its no-functionality-loss claim rests on deterministic evidence (hashes, the pinned capture, cross-tree identity) rather than suite timing — but the sharpening is real follow-up work, budgeted as its own batch and tracked in the backlog. Everything else closed clean.
