# batch-63 — functional description

## The defect, in one paragraph

`report_service` budgets every project report against a whole-document byte cap. The accounting
function `_line_bytes` charges **one byte per line** for the newline that will separate it from the
next. But both report writers used `Path.write_text`, which opens the file in **text mode** — and on
Windows text mode expands every `\n` into `\r\n`. So the file on disk was **larger than the number
the budget had been charged**, by `N - 2` bytes for an `N`-line document.

This mattered in two places, and one is worse than the other:

- In `report_service`, the budget gates hexdump blocks — an undercount means slightly more hexdump
  is emitted than the cap intends.
- In `flow_report_service`, the **same shared allocator decides whether a whole section is emitted at
  all**. `put()` asks `budget.fits(...)`; a false answer drops a section and records it as truncated.
  An undercounting allocator there is making emission decisions on a wrong number.

## The fix

One function — `report_service.document_bytes(text: str) -> bytes` — is now the only place report
bytes are produced. Both writers obtain their bytes from it and write with `Path.write_bytes`, which
performs no newline translation. The file is therefore identical on Windows and Linux, and equal to
what the encoder produced.

`_line_bytes` was deliberately **left unchanged**. Its `+1`-per-line form is *partition invariant*:
the composer accounts the document in about twelve separate `emit()` batches, and this form charges
the same total no matter how the document is split. The obvious "simplification" — defining
`_line_bytes` as `len("\n".join(batch))` — loses one byte per batch boundary and would undercount
**linearly in the variant count**, which is strictly worse than the defect being fixed. The whole
document is now over-accounted by exactly one byte, which is the safe direction.

The encoder takes a `str` rather than a line sequence. That is what lets one function serve both
writers: `generate_project_report` joins lines, while `flow_report_service.compose_flow_report`
already returns a composed `str` and is covered by 39 tests that pin that public return type.

## Why the test design looks unusual

**CI cannot observe this defect.** Both workflows run `ubuntu-latest`, where `Path.write_text`
already emits LF — so before the fix, the undercount on CI is **zero** and the pre- and post-fix
writers are byte-identical. Any assertion phrased as "the written file contains no `\r`" is therefore
**green before the fix** on the exact platform the merge gate runs on.

The batch handles this by splitting the acceptance into three kinds:

1. **Seam tests** (`AT-172`, `AT-173`) replace the encoder and assert the written file follows. These
   fail before the fix on every platform, because there is no encoder to replace and the writers
   reach `write_text` regardless.
2. **A structural census** (`AT-193`) asserts that no module sharing the byte accounting writes in
   text mode. Its module set is derived by walking the import graph rather than hand-listed, and it is
   the check the merge gate actually relies on. `AT-193b` is its positive control: a census that
   asserts an *absence* passes on a fixed tree whether or not its detector works, so the detector is
   driven over every offending spelling — including `Path.open("w")`, this repository's own idiom.
3. **A platform-conditional test** (`AT-175`) that is explicitly labelled *not verified by the merge
   gate* and skipped on Linux.

`AT-174` is a **pin**, not a gate: it fixes `_line_bytes`'s convention in place so a future change
cannot silently alter it, and it is green both before and after the fix by design. The artifacts say
so, because presenting it as evidence of the fix would misrepresent what was verified.

## Operator-visible effect

Reports written on Windows now use LF line endings instead of CRLF. Nothing in the tool re-reads a
report — readers only glob and stat filenames — and the test suite's canonical comparison already
normalised CRLF, so no stored golden or snapshot moved.

One incidental improvement: because encoding now happens *before* the file is opened, a value that
cannot be encoded no longer leaves a zero-byte file bearing a valid report filename.

## What this batch does not do

It does **not** bound the report document, and it does **not** bound the report's resident memory
cost. The `> TRUNCATED … (report size cap: N bytes)` marker still asserts a bound the document can
violate. Two related defects found during this work — the declared-region addendum's `O(R×V×E)`
memory cost, and a schema-legal address that denies report generation — were returned to the backlog
with their measurements rather than shipped half-solved.
