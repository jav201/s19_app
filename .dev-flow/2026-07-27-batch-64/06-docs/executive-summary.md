# batch-64 — Executive summary

## In one line

We wrote down the rule that catches tests which pass without testing anything — and while writing it,
the rule caught nine mistakes in its own authoring and found two broken tests already shipped in the
product's test suite.

## Context

Software teams rely on automated checks to decide whether a change is safe to ship. The failure mode
that matters is not a check that *fails* — a failing check announces itself. It is a check that
**passes without examining what it claims to examine.** It looks like evidence, counts as evidence in
every report, and is worth nothing.

The previous batch produced five such checks for a single defect — three of them written *after* the
team had already named this as the problem they were watching for. They were not sloppy. Each had
correct arithmetic and complete inputs. They simply never referred to the thing being fixed.

## What we did

Encoded that lesson as a permanent rule in the engineering workflow, so it is applied at every future
change rather than remembered:

- **A gate question that did not exist before** — *"can this check go RED?"* is now asked separately
  from *"is this check correct?"*, and it must be answered by **actually breaking the code and watching
  the check fail**, with the transcript recorded.
- **A companion rule** for a related recurring error: checks must be written against what a program
  actually produces, not against how the output looks to a human reading it.
- **A concrete version** of that companion rule for this product's specific technology, and a general
  version added to the reusable design skill.
- **Registry cleanup** — one existing rule had been written but never recorded, and the index claimed a
  rule range that was wrong in both directions.

## Outcome

| | |
|---|---|
| Scope | Documentation and process only — **no application code, no test changes** |
| Change size | ~26 KB across five files |
| Product risk | **None.** The test suite is unchanged at 2 201 passing, verified by a full re-run |
| Independent review | Three reviewers plus a separate audit and a final code review — **zero HIGH findings** |
| Verification | The new rule was tested against a labelled set of known-bad and known-good checks: **it flags 9 of 9 bad, and does not flag the good ones** |

## Why we believe it works

We did not accept "the text is written" as proof. The rule was measured the way a detector is measured
— run against real examples of the problem it is meant to catch, and against examples it must leave
alone. Deleting half the rule drops its detection rate from 9/9 to 4/6, which tells us both halves are
doing work.

The strongest evidence is incidental: **applying the new rule to the previous batch's work found two
checks currently live in the product's test suite that verify nothing** — one of them asserting a
statement that is true of any input, behind a comment claiming it catches a specific bug. Both had
passed three rounds of clean review. The three rules we already had all miss them. These are recorded
for a follow-up; they are test-quality issues, not product defects.

## Cost, stated honestly

The process was heavier than the deliverable warranted — roughly fourteen automated review passes for
four paragraphs of text — and the requirements phase hit its iteration limit before landing. The root
cause was identified and is itself reusable: **the checks were being measured against a document that
kept changing underneath them.** Freezing the text first, then measuring once against the frozen
version, resolved it. That sequencing is the practical lesson for the next batch of this kind.

## Next

Four follow-up items are queued, the two most useful being the broken tests found on the main branch,
and a rule — now with two measured occurrences — about not running experiments in a workspace another
reviewer is reading.
