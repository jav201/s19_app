# Post-mortem — s19_app — Batch 2026-06-26-batch-18

> Phase 5. Lenses: `architect` (design/process) + `qa-reviewer` (validation/coverage). Feature #11 — Q1 report legend (US-022) + Q2 in-app legend modal (US-023).

## 🔑 At a glance
- **Outcome:** closed clean (no Phase-1/Phase-3 iterations forced); 2 increments, suite 892→908, 0 fail.
- **Headline:** the C-13 geometry control worked (caught an off-screen A2L button at draft-time measurement before it shipped), but its pre-committed fallback ladder was ordered by escalation cost, not the measured deficit — see lesson below.

## What went well
- **Single-source by construction.** A new non-frozen `legend.py::LEGEND_TABLE` feeds BOTH the report (`_legend_lines`) and the modal (`LegendScreen`); `TC-S2` compares the two *rendered* row-sets (not just a shared import), so Q1/Q2 cannot silently diverge. The frozen-set constraint (the table cannot live in `color_policy.py`) was identified in Phase 0 and held end-to-end (`git diff main -- color_policy.py` = 0).
- **Anti-drift to the engine.** `COLOUR_SEVERITY` couples the legend back to `SEVERITY_CLASS_MAP`; `TC-S1` fails if a future severity has no legend colour — demonstrated live under counterfactual.
- **All four ATs value-discriminating.** Each AT was shown RED under a counterfactual whose post-fix assertion keys on the right payload (meaning text / severity reachability / row-set), not mere call-path wiring (QC-2 satisfied).

## Headline lesson — C-13 worked; the pre-committed fallback was under-specified
Draft-time **measurement** (LLR-023.3) caught that the A2L Legend button renders **off-screen at both 80 and 120 cols** before a dead button shipped — the control working as designed.

**But the pre-committed fallback ladder mis-estimated magnitude.** Phase 1 pre-decided "if A2L overflows → PRIMARY: shorten the label ('Key'); LAST RESORT: key-binding." Measurement showed the overflow is ~67–85 cols — the A2L filter row (`layout: horizontal`, two `1fr` inputs + 7 buttons) already overflows its half-width pane with its *existing* 9 widgets, so a ~3-col label trim was never viable.

**Root cause:** the ladder was ordered by *escalation cost*, not by the *measured deficit*. Phase 1 flagged the row "assumed — measure" but did not estimate the deficit magnitude with the cheap arithmetic already available (Σ sibling natural widths vs container budget). Had it, the "shorten label" rung would have been struck immediately.

**Proposed refinement (C-13.1, additive to C-13):** when a geometry fallback ladder is pre-committed, tag each rung with the **deficit range it recovers** (label-trim ≈3–6 cols; overflow/scroll ≈ a row's worth; key-binding unbounded), estimate the container deficit at the tightest supported regime, and pre-select the *lowest rung whose recovery ≥ the estimated deficit* — not the cheapest rung. Same arithmetic C-13 already mandates; applied to fallback selection, not only go/no-go.

## Minor lessons
- **Editable-install shadows the worktree.** An ad-hoc geometry probe imported the editable-installed *main*-repo package, not the worktree, masking the new code. Loose scripts in worktree work must `sys.path.insert(0, <worktree>)` or run under `pytest` (which roots on the worktree). Cost: one wasted probe run.
- **Textual API drift.** `Label.renderable` is gone in Textual 8.2.5; `str(label.render())` is the text accessor for Pilot content assertions.
- **§6.5 discipline held.** The A2L button→key change was recorded as Before/After amendment A1 with a parent-HLR re-read (HLR-023 unchanged — a keypress is a press affordance), and the acceptance surface updated (AT-023a observes the `k` key; AT-023e + TC-023.2 assert the button's intentional absence). No silent edit.

## Carry / follow-ups
- **G-1 (minor, process):** SVG snapshot baselines for the 3 views + footer (new `k` binding) regenerate in canonical CI at PR — never local (`reference_snapshot_regen_env`).
- **C-13.1** (deficit-matched fallback selection) — candidate to encode into global `dev-flow.md` after batch close, alongside the existing C-13 bullet.
- No requirement defects; no deferred scope (US-022 + US-023 fully shipped). Feature #11 closed.
