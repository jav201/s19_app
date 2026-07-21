# batch-57 — Post-mortem

## What worked
- **Design-first paid off.** The requirements were adversarially refined across the design phase (4
  production observations resolved — bit-ordering, gap-safety, `check` convention, LUT). Phase 0/1 were
  near-instant adoptions; the flow spent its rigor where it mattered (implementation + independent review).
- **LUT as a tabelization of the existing oracle** made E7 provably result-identical rather than a risky
  rewrite — the reviewer both proved it (register-linearity) and confirmed it empirically (0 mismatches
  incl. odd widths). `crc_stream` kept as the oracle turned the differential test into real certainty.
- **Additive, keel-first scoping** kept the batch bounded (3 small increments, 0 frozen diffs, no shipped
  module touched) and de-risked the big TUI view into its own batch (58).
- **Independent review caught a real HIGH** (F1: `parse_job` crash on a non-object `algorithm`) that the
  green 45-test suite had missed — exactly the collect-don't-abort robustness the module claims. Fixed
  at the gate. This is the C-31 lesson in action: a green suite whose input set omits a case is not proof.

## What didn't / friction
- The full suite is ~23 min — over the Bash 10-min cap — so it must run backgrounded (C-25). Handled;
  the post-fix full run is confirmed via CI, not a blocking local wait.
- The keel was built during the *design* phase (before the flow), so Phase-3 "implementation" was partly
  adoption. Recorded transparently (Inc-1 = adopt); not scope creep, but worth noting the ordering.

## Scope drift
None. The view + E6 were explicitly deferred to batch-58 at kickoff (autonomous decision, recorded).

## Metrics
- Iterations per phase: 0/0/0/0/0 (one in-gate review fix, not a phase iteration).
- Findings: 3 (1 HIGH + 1 MEDIUM + 1 LOW) — all closed at the gate (`063bea5`).
- Tests: 34 → 45 (+11). Pre-fix full suite 1730 passed / 0 failed / 0 frozen diff.
- Files: 2 new modules + 2 new test files; docs/prototypes/dev-flow artifacts.

## Root causes (of the one HIGH)
F1 was an eager-default-arg evaluation (`inline.get(...)` in arg position) that bypassed the
object-shape guard the rest of the module applies. Root cause: the inline-algorithm branch was added
without mirroring `_build_target`'s `isinstance` guard. No new control proposed — it is a direct
instance of the existing collect-don't-abort posture + C-31 (input-set completeness); the fix + F1
regression test discharge it.

## Items proposed for the next batch (→ BACKLOG)
- **batch-58: the Variant B TUI view** (CRC Designer screen — form + live KAT verdict + coverage strip
  + Load/Save + the load/check/save flow strip); **E6 legacy `crc_config` up-converter**; **`emit_job`**
  serializer; wiring the width-general kernel into the shipped `crc.py` operation; `check==KAT`
  enforce-on-save in the view. Design + prototypes already done (`prototypes/crc_designer.*`,
  `docs/crc-algorithm-designer/`).
