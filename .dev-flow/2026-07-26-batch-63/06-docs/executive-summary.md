# batch-63 — executive summary

**A correctness defect in the project-report generator has been fixed and merged. The report file
written to disk no longer disagrees with the size budget the tool charged for it.**

## Context

The tool generates evidentiary Markdown reports and enforces a size cap on them. The code that
*counted* the bytes and the code that *wrote* them had drifted apart: the writer let the operating
system expand line endings, so on Windows every report was larger than the number the size check had
been given. In the flow-report generator the same faulty count decides whether an entire section is
included in the document at all — so a wrong number was making inclusion decisions about evidence.

## What changed

All report bytes are now produced by a single function, and both writers use it. The change is four
lines of production code. The counting function was deliberately left untouched, because its current
form is the only one that stays correct when the document is assembled in pieces — a plausible-looking
"cleanup" of it would have made the undercount worse and proportional to the number of variants in
the report.

## Outcome

- Reports are now byte-identical across operating systems.
- 2 201 tests pass, no regressions, no stored baseline moved.
- Two independent reviews (quality and security) plus a follow-up review of the corrections all
  returned zero high-severity findings before merge.
- A side effect worth noting: a report can no longer be left as an empty file bearing a valid report
  name when an unencodable value is encountered.

## What was deliberately not done

Two further defects were found during this work and **returned to the backlog rather than shipped
half-solved**: the declared-region section can exhaust memory on large inputs, and an address that
the file format accepts can cause the tool to decline to produce a report. Both are recorded with
measurements and with the design constraints discovered while analysing them, so the next batch
starts from evidence rather than from scratch.

The report's overall size and memory bounds remain open. The batch states this explicitly in its own
changelog rather than implying more was closed than was — the document's own governing principle is
that it must not assert what it does not honour.

## Cost and process note

The batch consumed its full iteration allowance in the requirements and review phases before shipping
a small change. That is the honest trade: each scope reduction was driven by a measurement that
contradicted an earlier assumption, not by fatigue. The most reusable lesson — that an acceptance
criterion can be *correct* and still verify *nothing* — is recorded with five worked examples from
this batch itself.
