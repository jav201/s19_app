# 05 — Post-mortem · batch-33 · check-result reasons + per-entry taint

## What worked
- **The three-lens Phase-2 gate produced three non-overlapping pre-code catches:** architect B-1
  (the locked attribution rule would FALSE-TAINT a healthy entry sharing an address with a skipped
  declaration — the exact bug class the operator's decision was meant to remove), security F1
  (`MF-BAD-STRUCTURE` dual-use would have silently re-introduced the collective taint on one junk
  element) and F2 (unbounded reason templates = local-DoS). All were bounded §-level amendments,
  zero renumbering.
- **The QA Phase-1 pass killed an unimplementable AT before code** (the 50-char log cap vs the
  drafted assertion) and surfaced a THIRD markup surface plus a pre-existing five-message injection
  class — closed in-batch by one construction-time `markup=False` funnel scrub.
- **Review-F1 (Inc-2/3) caught an unexecuted census row:** the old apply-gate-mirror test survived
  with a now-false docstring, passing only because its fixture happened to be a collision pair.
  Superseded in place with the same fixtures under new-semantics pins. (Same lesson family as
  batch-29's C-18 origin: dispositions must be REALIZED, not assumed.)
- **Vacuous-assertion self-catch:** TC-051.5's draft `... or True` was caught at authoring and
  replaced with exact aggregates-line pins.
- Parallel-lane requirements drafting (authored during batch-32) again collapsed Phase-0/1 wall
  clock; the draft's one flagged risk (stale-tree citations) was retired by a dedicated
  re-verification pass (36 citations, 0 content changes).

## What didn't
- **The Phase-2 QA fold-verify agent stalled** (600 s watchdog, no output) — recovered by folding
  its checklist into a post-amendment verification agent with a deliberately tight, greps-only
  mandate (which then ran in ~1 min). Lesson: verification agents get checklist-only prompts with
  explicit tool budgets.
- The census execution gap (review-F1) shows increment packets listing "supersessions: 1" can
  under-count when the census table lives only in the spec — the packet should quote the census
  rows it owes, not a tally.

## Scope drift
None. The operator's round-3 decision, the two draft defaults (Q1 collision-taints, Q2 report
column deferred), and the out-of-scope list all held; 0 engine-frozen diffs.

## Metrics
- Iterations: P0 1 · P1 2 (one iterate-to-refine on the B-1 blocker) · P2 1 · P3 4 increments + 2
  fold commits · P4 1.
- Findings: P1 QA 4 prominent (folded) · P2 1 blocker + 2 major + 6 minor (folded) + 1 agent stall ·
  Inc reviews: APPROVE with 2 medium + 2 low (folded). Open: 0.
- Tests: touched files 89 → 108-ish nodes (+4 in-place supersessions); suite 1241 → 1263 collected;
  gate run 1234 passed / 1 anticipated snapshot drift (xfail'd).
- RED evidence: 4 stash captures + 2 declared-negative/regression directions + the review's honesty
  check on the B-1 fixture.

## Root causes (multi-iteration items)
Phase-1's second iteration was the designed response to a named blocker (B-1) — the two-set split
made §1.2 rule 2 literally implementable; root cause was conflating "non-blocking" with
"taint-attributable" in one allowlist, caught exactly where the process wants it caught.

## Proposed for next batches
- P-1 (carried from batch-32): 1-based operator-facing indices as a stated convention.
- P-2 (carried): repo-wide ruff debt (~11 pre-existing hits in untouched files) — one hygiene PR.
- P-3 (new, from architect O-2): filename-markup hygiene on `#status_text` + the verify-mismatch
  `notify` (file-system-derived text on markup-enabled surfaces — same class, different source).
- P-4 (process): increment packets QUOTE their owed census rows (see "what didn't").

## Control-encode proposals
NONE self-encoded. Candidates for operator consideration (propose-only): **C-CAND-E** — verification
subagents get checklist-only prompts with an explicit tool budget (the stall lesson); **C-CAND-F** —
increment packets quote owed census rows verbatim (P-4 as a control).
