# Post-mortem — s19_app — Batch 2026-06-29-batch-19

> Phase 5. Lenses: `architect` + `qa-reviewer`. US-020c (declared-region report addendum + persistence) + US-020d (issue enrichment). Backlog #10 follow-on.

## 🔑 At a glance
- **Outcome:** closed clean — 4 increments, 0 forced iterations, suite 908→926 (+18), PASS at Phase 4. One follow-on feature + one UX nicety deferred to BACKLOG (operator-ratified scope).
- **Headline:** the Phase-0 design spike + the Phase-2 security lens were the two highest-leverage steps — one prevented building the wrong thing, the other caught a real injection vector on a feature that "looks like just text."

## What went well
- **Design spike resolved an unresolved semantic before any HLR.** "Declared memory locations" had no agreed meaning; the Phase-0 spike mapped the surfaces and brought 3 concrete interpretations to the operator (DoR gate). Deriving against the wrong interpretation would have wasted the whole batch.
- **The spike REFRAMED scope.** It found US-020d's "issues in the report" was *partly already built* (a Declaration-errors section that under-rendered the fields), so US-020d became a small, ready, independent Inc1 — and surfaced a divergence from the batch-17 "(d) depends on (c)" premise rather than silently inheriting it.
- **C-13 MEASURED PASS — the control is now routine.** Unlike batch-18 (where the A2L button was off-screen and forced the key-binding fallback + a §6.5 amendment), the report dialog's region input fit both regimes on measurement; no fallback, no amendment. The geometry-budget control caught nothing because nothing was wrong — which is the control working.
- **Every AT shown RED under a value-discriminating counterfactual** (5 across the batch), including the security scrub bypass (Inc2) and the app-threading drop (Inc3) — the tests bite.

## Headline lesson — the security lens earns its seat on "just text" features
The architect and qa lenses both passed US-020c as low-risk. The **security review** caught that the operator-entered region `name` reached the Markdown report *and* `project.json` without the control-char/ANSI/length scrub the codebase already applies to `issue.message` — an inconsistent application of an *existing* protection. Folded by reusing `_scrub_issue_message` at `DeclaredRegion` construction (single source), and the read-path scrub was hardened in Inc4 (a hand-edited `project.json` name is neutralized on read).

**Lesson:** any feature that routes operator free text into a shippable artifact (a report a client receives) or a persisted file is a security-review target, even when it reads as "just a label." The tell is "new operator string → rendered/persisted surface," not "new external/network surface." Keep running the security lens on these; the cost is one parallel agent.

## Minor lessons
- **Investigate-before-derive (spike) repeatedly pays.** Two of the batch's best decisions (US-020d reframe; the `_scrub_issue_message` reuse) came from reading the actual code, not from the backlog's framing.
- **Idempotent-scrub roundtrip.** Persisting a scrubbed value and re-scrubbing on read is safe *because* `_scrub_issue_message` is idempotent — worth asserting (Inc4 read-path scrub test) so a future non-idempotent change to the scrubber breaks loudly.
- **Pre-existing lint debt surfaces when you touch a file.** An unused `import pytest` in `test_manifest_writer.py` (on `main`, CI runs pytest not ruff) showed up only when Inc4 edited that file. Left per surgical discipline; logged for a sweep. (No new control — a reminder that CI not running ruff lets lint debt accumulate silently.)

## Process / environment note (recurring all batch)
The session drove the `claude/batch-19` worktree (`gifted-ramanujan-6d30eb`) via absolute paths while physically rooted elsewhere, so the operator could not open the artifacts in their editor and file-links didn't resolve. Mitigation that worked: **paste the reviewable artifact inline at every gate** (the full spec, each review, each packet). Worth standardizing when a worktree isn't the operator's editor root.

## Carry / follow-ups
- **D-1 (deferred feature):** UI auto-wire — save the report dialog's regions to the manifest on project-save + pre-fill the dialog on load. HLR-026 delivered the serialization layer (operator option-1); this wiring is its natural follow-on. → BACKLOG.
- **D-2 (deferred UX):** surface a count when the region parser skips malformed lines (reviewer Inc3-F1). → BACKLOG.
- **G-1 (lint):** pre-existing unused `import pytest` in `test_manifest_writer.py` — separate sweep.
- No requirement defects; no §6.5 amendment. Feature #10 (issues-report addendum) closed.
