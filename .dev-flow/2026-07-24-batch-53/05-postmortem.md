# 05 — Postmortem · batch-53 (FB-P1 flow.json persistence)

**BLUF:** batch-53 shipped clean across 4 increments + 1 hardening pass after a fresh-session
resume from the Phase-3 pause checkpoint (Inc-1 already committed). Save/Load/Import a Flow
pipeline to `flows/<name>.json` with a hardened, fail-closed untrusted loader. Both final
gates 0-HIGH; 0 functional regressions. The load-bearing lessons are about (1) *querying the
active modal screen, not the app default screen*, and (2) *a sanitiser that strips is a
different containment contract than a sanitiser that rejects*.

## What went well
- **Resume from checkpoint was lossless.** `state.json.pause_checkpoint` named the exact
  resume point (Phase 3, Inc-2) + the authoritative AMD precedence. Re-verifying the Inc-1
  tree on disk (clean, committed `b056036`) before extending held the "extend, don't
  regenerate" discipline.
- **The service seam paid off twice.** `import_flow_file` (a thin wrapper binding the AMD-4
  `FLOW_SIZE_CAP_BYTES` cap over `copy_into_workarea`) gave Inc-2 a testable unit for the
  C-12 output-then-consume AT *and* the exact call Inc-3's app handler reuses — one cap
  binding, no drift between test and handler.
- **Reuse-not-fork held.** Every READ ref re-validates through the existing
  `_resolve_manifest_entry`; the only loader-side path-shape reject (`FLOW-UNSAFE-REF`
  drive-relative) closes a genuine gap the guard's `is_absolute()` arms miss, without
  touching the guard.
- **Inline per-increment review + delegated FINAL gates.** Per-increment gates were
  self-reviewed inline (avoiding the C-33 delegated-review hang); the mandatory final
  qa + security ran as independent subagents over the whole batch diff and both returned
  0-HIGH with liveness intact (~4 min each).

## Lessons (candidate carries)
1. **`App.query_one` searches the DEFAULT screen, not the active modal.** Every modal-widget
   pilot query first failed `NoMatches on Screen(id='_default')` even though the modal was on
   the stack and its widgets existed — because `app.query_one` binds to `screen_stack[0]`,
   not `app.screen` (the top). The fix: query modal widgets via `app.screen.query_one(...)`.
   A general pilot-testing rule for any push_screen modal, not just this batch.
2. **A stripping sanitiser and a rejecting sanitiser are different containment contracts —
   test the one you have.** The first refusal test assumed `sanitize_project_name("../../escape")`
   → `None`; it actually strips `/`+`.` → the contained stem `escape` (only whitespace/
   punctuation-only names → `None`). The real write-side property is "traversal chars are
   removed, the write stays inside `flows/`", not "traversal names are rejected". The test
   was corrected to assert containment (write inside `flows/`, escape target absent) — a
   *stronger* invariant than the original wrong assumption.
3. **Store identity out-of-band, don't parse it back out of a rendered Label.** `LoadFlowScreen`
   first copied `LoadProjectScreen`'s `label_widget.text` idiom to recover the picked stem —
   which yielded the literal `"Label()"` (no `.text` attr in this Textual). The stem now
   travels on `ListItem.name`; the pre-existing `LoadProjectScreen` carries the same latent
   fragility (noted, not fixed here — out of scope).
4. **A `{value!r}` finding message is not a byte-exact echo of the input.** The C-17 quarantine
   test first asserted the raw hostile string (with a real ESC byte) appeared in the finding
   line; `repr` had turned the ESC into the literal `\x1b`. The correct C-17 discriminator is
   the *surviving markup tokens* rendered literally (`[bold red]`, `[link=file:`) **AND**
   `spans == []` — crash-only / exact-byte matching is the wrong assertion.

## Process notes
- **Authorization re-confirmed at resume** (AUTONOMOUS + self-merge; per-batch, not carried).
  All per-increment gates self-approved with a named Coverage/Certainty/Evidence axis check
  and full packets in-conversation; final qa + security 0-HIGH over the whole diff before
  self-merge (untrusted loader).
- **The one design ruling logged:** the `import_flow_file` service seam (recommended, then
  ratified by the operator's "continua") — a new public symbol, swept for C-38.
- **C-38 union sweep:** all three `isinstance`-dispatch sites over the widened `FlowBlock`
  union (`_flow_block_label`, `run_flow`, `flow_to_dict`) handle `ReportBlock` — no silent
  fallthrough.
- **Final-gate MAJORs folded, not deferred blindly.** Both gates were 0-HIGH, but the qa
  MAJOR anti-vacuity items (per-branch output_name, cap boundaries) + the security LOW (V7
  drive-relative symmetry) were cheap and hardened the exact untrusted-loader surface — folded
  into a hardening commit before merge, each RED-verified. qa M-3 (static `from_markup`
  scanner over `render_quarantine`) deferred to FB-P1b (behaviourally covered by AT-006).

## Carries out
- **FB-P1b (report generation)** — the operator-set follow-up: the `ReportBlock` is model +
  persist + no-op only this batch; generating report content is a new batch.
- **qa M-3** — extend the static `from_markup` scanner to `render_quarantine` / the new module.
- **RISK (defense-in-depth):** `LoadProjectScreen`'s `label_widget.text` stem-recovery idiom
  is latently fragile (same bug fixed here for `LoadFlowScreen`) — a separate cleanup.
