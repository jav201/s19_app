# Executive summary — s19_app — Batch 2026-10-12-batch-94

> **Roles:** `presentation-builder` (this artifact). Batch `2026-10-12-batch-94`, repo `s19_app-b94`. Generated in the batch's development language (`state.json` `language` = `en`).
> **Artifact language:** canonical English scaffold. Generate in the batch's development language (`state.json` `language`).
> Phase 6 artifact. Owner: `presentation-builder`. Audience: non-technical stakeholder. 1-2 pages.

> **Owed in.** `core` — · `full` ✓
> **Source:** `/dev-flow-init` step 4's seed-by-level table, which is this fact's one home. A level marked `—` **does not owe this artifact, and its absence is not an omission**; `by trigger` means the station exists only when the `triggers` block fired, and `stations_active` in `state.json` is the authority for *this* batch. Where a SECTION or a gate row is owed more narrowly than the artifact, it says so on the row.

## 🔑 Bottom line (read first)

- **What we delivered:** the seven-change commission (Cambio1–7) for the calibration tool's work screens — two reworked editors, a new checklist file that feeds comparison reports, a rebuilt block-diagram flow builder, a new flow runner, and a cleaned-up issues view.
- **Business outcome:** the tool now separates building, viewing, and executing work; the flow builder is usable; and the issues view no longer drowns real problems in over a thousand false warnings.
- **Next step:** merge the batch's PR, then two operator checks in the next working session — the hands-on verification of the two new shortcut keys and the answers that unblock the one parked change (Cambio6).

---

## Context (reference)

### Context
s19_app is the terminal tool a calibration engineer uses to prepare and review ECU software changes. In October the operator commissioned seven changes (Cambio1–7) after prototyping the new layouts: separate the windows that *build* content from those that *view* or *execute* it; make the flow builder usable as a block diagram; run several change-chains side by side; and stop the issues report from crying wolf. This batch delivered that commission in four increments behind one unchanged entry screen (`PLAN.md` §Header; contract `01-requirements.md` §2.6).

### Problem
Three daily frictions, in the operator's own words and numbers:

- **Mixed surfaces.** One editor window mixed viewing, building, and executing, making the tool hard to learn and risky to operate (Cambio1).
- **An unusable flow builder.** The old builder was "inservible o incompleta" — a list, not a diagram; flows could not be drawn, saved as reusable templates, or run (Cambio5/7).
- **A warning flood.** Loading a standard calibration description file raised 4 489 "unrecognized block" warnings — all standard vocabulary, none a real problem — which trained the operator to ignore the Issues view entirely (Cambio4).

### Solution
What shipped, in plain terms (details: `06-docs/functionality.md`):

- **A split editor pair.** The Patch Editor now does one thing — edit one change-set file — with a bigger text area, a guarded Load that asks before discarding unsaved work, and an honest "Apply loaded changes" button. Its new twin, the Check Editor, builds checklists of parameters to verify; those lists save as `.chk.json` files and appear inside A2B comparison reports automatically.
- **A real flow builder.** Blocks (patch, CRC, compare) are placed on a canvas and wired with cables. Every comparison block records where each input came from, and flows save as named templates — never silently overwritten.
- **A flow runner.** A new Flow Execution window imports templates and shows each chain in its own lane. Chains run one after another by default, or side by side when asked; progress and any failure appear inline; and the whole setup — chains, input files, outputs — saves and reloads for tomorrow's re-run.
- **A quieter, honest issues view.** Standard-block notices now read as informational, with the reason shown; genuinely unknown blocks still warn. Nothing is hidden — reclassified, never deleted.
- **Two new rail shortcuts** (`=` for Check Editor, `]` for Flow Execution) keep all twelve screens one keystroke away.

### Outcomes / results
- **24 acceptance behaviors verified** end-to-end through the shipped screens (AT-B94-01…24, all passing; `04-validation.md` §✅ Verdict), plus 65/65 mutation checks — deliberate fault insertions, every one caught.
- **0 new test failures:** the final full-suite gate run shows 3 040 passing with no failure attributable to this batch (the 5 residual failures pre-date it — documented and owned elsewhere; `04-validation.md` §Gate run).
- **6 coordinated merges with the parallel lane** (batch-95): the other batch's work landed on main while this one ran; every integration point was reconciled and both sides stayed green throughout (`PLAN.md` decision log; `03-increments/increment-002/003` §1).
- **Requirements fully traced:** 21 high-level / 42 low-level requirements, 31 test cases, 24 acceptance tests — no gaps (`06-docs/traceability-matrix.md`).

### Next steps
Phased and concrete (carries recorded in the increment packets §6 and `04-validation.md` §Gaps):

1. **This week — operator hands-on (Cambio6 unblocking + key check).** Answer the two open questions on the CRC test-vector section so the parked US-006 can be specced; and press `=` / `]` on the real terminal once — headless tests cannot prove physical key delivery (the A4 field check; `DDR-2026-10-12-batch-94#F4`).
2. **Before any further screen changes — the snapshot refresh.** The 29 inherited visual-baseline marks await the canonical-CI regeneration (owner: the CI workflow; N-1).
3. **At the close review — three owner rulings.** Two minor labeling items on workspace statistics and filter buttons (Inc-004 F1/F2); and the two out-of-commission items (BlockTags, README refresh) are already filed to the lane-A queue, as is the test-file pair that belongs to batch-95 (TC-707).
