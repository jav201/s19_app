# Executive summary — s19_app — Batch 2026-07-31-batch-74

## 🔑 Bottom line (read first)

**A wire-legal change file could exhaust process memory while generating a report, and a second defect
let a shortened address pass as a complete one.** Both are closed: the two report row producers now
bound their own resident allocation on two axes, and an oversized `Address` renders in a form that
cannot be mistaken for a whole value.

**The finding worth more than the feature: an output-shaped test cannot bound an allocation, and the
gap is invisible in the output.** Executed on three surfaces — a defective implementation emits
byte-identical text while using up to **5,973×** the memory. Every bound this batch ships is therefore
gated by a memory-residency oracle, each with a falsifier proving the oracle can fail.

**Three independent reviews returned BLOCK, and every one was on a test, never on the code.** No
implementation bug was found at any gate, by any reviewer, at any point in this batch.

## Context

`report_service.py` composes the project report an operator hands to a third party as evidence of what
was written to firmware. Two of its tables — `Modifications` and `Checklists` — emitted **one row per
entry with no cap**, after first flattening the whole population into a list. The cost was therefore
paid in full *before any output existed*, so no output-side budget could reach it.

This was carried as **OB-4** for several batches, with a recommended remedy: charge the tables to the
document's byte budget.

## Problem

**The carried remedy does not work, and the carried number was wrong.** Both were established by
measurement at the batch's first gate:

- `emit()` **accounts, it never gates.** By the time the budget sees a table, the producer has already
  been fully evaluated. Charging the tables to `_ByteBudget` closes the emitted-bytes axis and leaves
  resident memory **completely** untouched.
- The cost is **not** the flat `988 B/entry` the backlog recorded. It is **`≈ 92 + 6·L`**, linear in the
  entry's byte-run length; 988 is merely its value at one unstated run length. Consequence: a row-count
  cap **alone** does not bound memory — one row can cost ~6 MiB, so a 200-row cap bounds the table at
  ~1.2 GB.

Then Phase-2 measurement found a defect **nobody had chartered**: the `Address` cell is unbounded to
**100,000 characters**, because the address pattern carries no digit limit and CPython's decimal-digit
guard does not apply to base-16 parsing.

## Solution

**Bound the producer, not the document** — on two axes, because the axes are mutually invariant:

1. **Cardinality** — at most 200 admitted rows per variant, counted at admission, **summed across all
   of a variant's check files** (the check-file count has no cap anywhere, so a per-table cap would
   leave the product unbounded).
2. **Per-cell width** — byte runs bounded at the **source**, by values consumed, never by slicing an
   already-rendered string.

And for the `Address`: the kept digits are derived **arithmetically**, never by rendering the whole
value and cutting it. **A truncated address deliberately stops looking like a number** — it carries an
ellipsis and states how many digits were removed, so it fails the complete-value pattern. Truncating
without changing the form would have closed a memory hole by opening a **forgery** hole: a shortened
hex address is otherwise indistinguishable from a complete one, understating the true value by a factor
of `2**12248` in a measured case.

Every bound that fires is **disclosed in the document**, with a correct count of what was dropped.

## Outcomes / results

| | |
|---|---|
| Production files changed | **1** (`report_service.py`) |
| Tests added / deleted | **+33 / −0** (2408 → 2441) |
| Gate suite | **2436 passed**, 2 skipped, 3 xfailed, 29 snapshots (full, incl. slow) |
| CI | pass on the PR **and** post-merge on `main` (full suite, ubuntu/py3.11) |
| Goldens re-baselined | **0** |
| Frozen-engine diff | **0** |
| LLR coverage | **100 %** |
| Counterfactual mutations executed | **17** |

**Scope discipline.** The batch hit its iteration cap and was **re-scoped by operator decision** rather
than iterated a third time. Two items were split to a follow-on batch **with every measurement carried
into the backlog** — which is the only thing that makes a split different from a deletion.

`R-TUI-101` carries **seven explicit non-claims**, each with its executed number. Reading it as "the
report is now memory-safe" would be wrong: the document is still not byte-bounded, the variant and
check-file counts are still uncapped, and a third producer is still unbounded.

## Next steps

1. **batch-75** — the emitted-bytes gate, the uncapped variant/check-file counts, and the deferred
   `Length` column. Fully specified and measured in `BACKLOG-CODE.md`.
2. **A test-integrity defect found in passing** — a guard that pins figures in the requirements
   document by literal text **cannot tell an assertion from its refutation**; rewriting a figure to say
   it is *false* left the guard green.
3. **A control candidate**, registered but not encoded pending approval: the lessons catalog covers
   tests that cannot fail, but not **fixtures** that make a correct and an incorrect implementation
   indistinguishable.

### Verification of this summary

Every number above is transcribed from an executed run recorded in `04-validation.md` §1/§3/§5 or
`06-closeout.md` §1. The `≈ 92 + 6·L`, `2**12248`, `5,973×` and `100,000` figures were each produced by
a probe, not estimated. **This summary was written at the sync gate rather than at Phase 6** — see
`04-validation.md` §7 **V-1**.
