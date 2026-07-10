# Executive Summary — batch-33 · check results that explain themselves

**Audience:** operator / non-technical stakeholders. **Purpose:** one-page account of what batch-33
changed, why, and the evidence behind it.

## The problem

When the tool ran a "check" over a firmware image, any failing result could come back as a bare
**"uncheckable"** — with no explanation. Worse, the old rule was all-or-nothing: if the check
document contained *any* error anywhere (even one bad line, or the wrong document type), **every**
entry was marked uncheckable. Healthy entries were held hostage by a single document flaw, the real
pass/fail picture was hidden, and the tool even reported the run as "OK". Operators had to guess or
re-ask why a check didn't run — the same question kept recurring.

## The decision

The operator reviewed this during the post-batch-29 baseline review (backlog item B-02) and decided:

1. **Judge each entry on its own.** Only entries that themselves carry an error are uncheckable;
   healthy entries are checked normally. (Checking is read-only, so the old conservative
   whole-document block protected nothing.)
2. **Wrong document type still stops the whole run** — but now with one loud, specific message
   instead of silence.
3. **Every "uncheckable" states its reason.**
4. **The screen explains check semantics** so the topic stops coming up.

## What shipped

- A six-reason vocabulary (wrong document kind, document fault, entry fault, range partially or
  fully outside the image, no image loaded) attached to every uncheckable result — visible in the
  result rows, the status line, and machine-readable output.
- Per-entry judgment: one bad declaration no longer hides the pass/fail results of the healthy
  entries next to it.
- A blocked run now says so clearly ("Checks: not run — …") and is reported as not-OK.
- A short always-visible help text on the checks screen explaining what checks do and what the
  results mean.
- A hardening fix discovered along the way: specially crafted file content could previously reach
  screen elements that interpret formatting codes. One small fix closed five such exposure points,
  and hostile-input tests now guard them.

## Quality evidence

- **12 acceptance tests, each realized as exactly one on-disk test** — independently reconciled,
  and exercised through the real user path (the actual Run-checks button), not shortcuts.
- **Independent reviews caught two significant problems before any code was written:** a design bug
  that would have wrongly flagged healthy entries sharing an address with a discarded bad line
  (exactly the false-alarm class the operator's decision was meant to remove), and the
  formatting-injection exposure above. Both were fixed in the specification, then verified by tests.
- **The full 1234-test suite is green** (the single expected visual-snapshot difference from the new
  help text follows the standing regeneration process), with zero changes to the frozen parsing
  engine.
- Behavior changes to two locked requirements were formally amended with before/after records, and
  the write path (applying changes) deliberately keeps its stricter safety gate, guarded by a
  dedicated regression test.

## Next steps

- Optionally surface the reason column in the project report (the data already travels with each
  result; deferred by decision to keep this batch focused).
- Regenerate the one visual snapshot in the canonical CI environment.
- Candidate follow-up: apply the same formatting-safety hygiene to two remaining screen messages
  that display file names (flagged for a future batch).
