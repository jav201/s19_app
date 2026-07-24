# 05 — Postmortem · batch-n8 (comprehensive per-view Legend)

**BLUF:** N8 shipped clean across 3 increments after a fresh-session resume from the
Phase-3 pause checkpoint. Zero functional regressions; the only red is the pre-existing
tc016s snapshot drift (stash-verified). The load-bearing lessons are about (1) *reading
the paint, not the markup string*, and (2) *proving 0-regression by differential, not
assertion*.

## What went well
- **Resume from checkpoint was lossless.** The pause checkpoint (`state.json.pause_checkpoint`)
  named the exact resume point; re-verifying Inc-1 on disk (44 passed, ruff clean) before
  extending it caught nothing broken — the "DO NOT regenerate, extend" discipline held.
- **Isolated change surface.** All behaviour lives in the Legend modal + its section
  mapping; the base rail screens are untouched, so the 19 snapshot failures could be
  proven pre-existing by a single stash-diff instead of a 30-min baseline rerun.
- **Inline code-review avoided the C-33 delegated-review hang** while staying independent
  (main loop reviewed the software-dev author's Inc-1).

## Lessons (candidate carries)
1. **A markup span is not a painted colour — read the right layer.** AT-N8-07 first read
   `widget.render_line(0)` and got the base CSS colour `#e9e9e9`, NOT `orange3`, even though
   the Content span carried `style='orange3'`. The widget's own `render_line` is
   *pre-compositor*: the inline markup colour is applied later in the render pipeline. The
   robust read is `widget.render().spans` (the paint intent). **Pairs with the batch-n8
   qa B-1 lesson** (a "truncation" the eye sees is a compositor clip the widget buffer can't
   observe): both are "probe the correct render layer, not the one that's convenient."
2. **A literal `[` in derived display data re-opens the markup-safety hole.** The band key
   range reads `[lo,hi)`; rendered through a markup-enabled `Static` it would open a tag.
   Fixed with `markup=False` on the band rows. The N8 markup guard (TC-N8-11) covered the
   *card* data but not the *band-key* strings — derived display data is a second markup sink.
3. **"Re-point, don't retire" needs a genuinely-unmapped anchor.** Mapping `workspace→()`
   removed the last rail screen that hit the full-table fallback; the invariant survived
   only because `flow` remains unmapped. If `flow` is ever mapped, 5 tests (`flow`-anchored)
   go RED — an intentional tripwire, recorded so a future batch doesn't "fix" them blindly.
4. **A widget-type swap is an API change for tests.** `Label`→`Static` (LLR-N8-6.1) silently
   broke `#legend_body Label` queries in a sibling test file the PLAN didn't budget. The
   `Label ⊂ Static` relation made the fix a one-word query change, but the increment file
   count went 3→5. **Sweep every query of a widget class when you change that class's type**
   (mirrors the markup-sink SWEEP rule).

## Process notes
- **Authorization CHANGED at resume** (supervised → autonomous + self-merge). The kickoff
  grant was per-batch and NOT carried; re-confirmed at resume per the standing rule. All
  subsequent gates self-approved with a named Coverage/Certainty/Evidence axis check and
  full packets presented in-conversation.
- **Every un-asked decision logged** (PLAN.md decision log + state.json.decisions_log +
  this file): the 4 design-default rulings R-a..R-d (03-increments.md).
- **Phase-2 amendments held.** AMD-5 (Static+height discriminator), AMD-6 (both Hex overlays
  in the map card), AMD-7 (orange3 = real WARNING style, not `#d9a35b`), AMD-8 (live A2L
  column oracle) all implemented as amended; no body/amendment conflict surfaced at build.

## Carries / follow-ups
- **RC-1 chore (repo-wide, not N8-specific):** the 19 tc016s snapshot baselines are stale
  (batch-58/59 drift); needs a canonical-CI snapshot-regen PR. Advisory-red is accepted for
  the N8 merge per the standing authorization.
- **Lesson 1 (render-layer probe)** and **Lesson 4 (widget-type-swap query sweep)** are
  candidate general controls — surface to the operator before encoding (per the
  control-encode approval rule), not encoded autonomously.
