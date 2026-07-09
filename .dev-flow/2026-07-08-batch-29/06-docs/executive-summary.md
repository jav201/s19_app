# Executive Summary · batch-29 — clipboard safety + Issues screen cleanup

## Context
The s19tool firmware-inspection tool has two everyday surfaces this batch touched: the **Load
dialog** (where a user pastes a file path) and the **Issues Report screen** (which lists what the
tool found wrong in a firmware image). A recent audit had already hardened how the Load dialog reads
the clipboard, and it left behind two follow-ups — both of which affected how the tool actually
works, not just its appearance. This batch closed them.

## Problem
Two issues, both narrow but real:
- **An oversized clipboard could stall or bloat the paste.** The prior fix put a *time* limit on the
  Ctrl+V paste, but not a *size* limit. A very large clipboard could still spike memory and slow the
  paste before the timer helped.
- **The Issues screen carried a hidden duplicate table.** A modern grouped view had been running
  since a prior batch, but the old table it replaced was never removed — it was just hidden. One
  screen was quietly maintaining two data structures. Worse, a piece of "related artifacts"
  information (which files each issue connects to) had been invisible to users since that changeover.

## Solution
- **A fixed size cap on the clipboard read.** The tool now reads at most 64 KiB from the clipboard —
  roughly twice the longest valid file path — so an oversized clipboard simply cannot overwhelm the
  paste. Real paths are never affected.
- **The hidden table is fully gone.** The modern grouped view is now the single source of truth for
  the Issues screen, and the "related artifacts" information was **restored** onto each issue row, so
  users can see it again.

## Outcomes
- **Shipped as 5 small, reviewed increments** — each one delivered, reviewed, and verified before the
  next began.
- **Full automated test suite passes: 1,158 tests, 0 failures.**
- **Zero changes to the protected parsing/validation engine** — the core that reads and checks
  firmware was untouched, confirmed by an automated guard.
- **Every requirement was verified through the real user-facing surface** — not through internal
  shortcuts, but by driving the actual paste and the actual Issues screen.
- **One security-hardening test was added** to close a gap found during validation: it confirms that
  hostile text inside a firmware file (crafted to corrupt or hijack the display) renders as plain,
  harmless text.

## Next steps
1. Merge the pull request (suite green, engine untouched, independently reviewed).
2. A small **follow-up cleanup batch** to retire now-unused internal formatting code left behind by
   the table removal (already scoped).
3. A routine **visual-baseline refresh** in CI to clear expected-drift markers (a known, deferred
   step done only in the canonical environment).
4. Operator to review **two proposed process improvements** from the post-mortem — both aimed at
   catching, earlier, the one gap this batch surfaced (a required test that was specified but not
   built until late).
