# Requirements review (rationale for `REQUIREMENTS.md`)

These files are the strict-EARS review that produced the requirements canon, `REQUIREMENTS.md` at the root of the repository.

## What is here

- `S0-ears-strict.md` ... `S17-ears-strict.md`: one file per module. For each module they hold the old text, the context notes, the decisions `D<n>-k` that explain why a row says what it says, the strict EARS rows, and a "Code today" column that records what the code did when the module was reviewed.
- `CODE-CHANGES.md`: the backlog of code defects the review found. The review corrected requirement text only; each item enters the code through a later batch. The status column tells which items are open, done, partly done or obsolete.
- `RECONCILE-570b4b5.md`: the row-level log of the reconciliation with s19_app `570b4b5` (batch-100).

## How to read them

- The "Code today" column and the `file:line` cites are a snapshot as of s19_app `e273181`. Most cites refer to `570b4b5` or `093a7c0`, as each file's header says. They are not kept current: use them to find where to look, then read the code.
- References to `cc-S*.md`, `passed-*.md`, `weak-point-check.md` and `review/tools/` are working notes of the review. They are not published.

## Where the canon and the earlier canon are

- The canon is `REQUIREMENTS.md`: per module S0 ... S17, its context notes and its rows `| Id | Form | Requirement |`.
- The canon that `REQUIREMENTS.md` replaced is kept byte for byte in `docs/requirements/history/REQUIREMENTS-legacy-e273181.md`.
