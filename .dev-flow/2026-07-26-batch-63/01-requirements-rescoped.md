# batch-63 — RE-SCOPED requirements (operator ruling 2026-07-26)

> **BLUF: batch-63 is now three availability/correctness defects in SHIPPED code. The
> document-bounding redesign moves to batch-64**, with both REV-5 designs as its design input.
>
> Rationale for the split (operator-approved): the bounding work grew to **twelve** unbounded axes
> with two competing designs, one of them conditional on an unbounded axis it does not close. Along
> the way it uncovered three defects **already live on `main`** — two of which hang or crash the
> tool today. Those are smaller, measured, carry no disputed premise, and are worth more than the
> redesign they were found inside.

**Supersedes:** `01-requirements.md` §2.6 (US-B63-1/2), `01-requirements-architect.md` REV 4,
`01b-qa-catalog.md` REV 2. All retained on disk; the reversal stays traceable.
**Design input carried to batch-64:** `01-requirements-architect-rev5.md` (lane A) +
`01-requirements-architect-rev5-lane-b.md` (lane B) + the three Phase-2 lane reviews.

---

## The three defects — each CONFIRMED by execution on this tree

### D1 — `_addendum_lines` is a memory exhaustion, not a large document

`report_service.py:1467`. The function builds `hits: List[str] = []` and **appends one fully
formatted string per (region × variant × entry) match**, for every region, *before emitting
anything*. Cost is O(R×V×E) in **resident memory**, and it is paid at format time.

**Projected in the declared domain: ~559.7 GB, ~1 283 min** (extrapolated by lane A from a 17.5 MB
measurement, not by building the fixture — building it is what crashes).

**Why this is the most important of the three:** no output cap can reach it. The cost is incurred
**before any output exists**, so every byte-budget or row-cap design in REV 4 and REV 5 is
structurally blind to it. It hung a probe in one agent run and is the most likely cause of the
**host RAM exhaustion that crashed the operator's machine during this batch**.

**Fix shape:** admit at the producer — stream/bound hits as they are found, never materialise the
full formatted list. The count reported past the bound is honestly `≥K` when the scan itself is
truncated (bounding output does not bound traversal — lane A's finding).

### D2 — a schema-legal address CRASHES report generation

`ValueError: Exceeds the limit (4300 digits) for integer string conversion`.

**Located precisely by execution — and the obvious suspect is innocent:**

```
$ python -c "big = int('F'*300000, 16); ..."
hex format ok, len = 300000          # f"{big:X}" — hex is EXEMPT from the digit limit
DECIMAL RAISES: Exceeds the limit (4300 digits) for integer string conversion
```

So the address cells (`0x{...:X}`) are fine. The crash site is the **`Length` column**, which
formats `entry.address_end - entry.address_start` in **decimal** (`report_service.py:996`, and the
checklist twin). `_parse_address` (`changes/io.py:952`) accepts `^0x[0-9A-Fa-f]+$` with **no digit
limit**, so an address of 4 301+ decimal digits is schema-legal and reaches that f-string.

This is an **availability** defect — the report does not truncate, it raises — and it is stronger
than the F3 *size* finding the security lane filed against the same parser.

### D3 — `_ByteBudget` undercounts the written file (CRLF)

`_line_bytes` (`report_service.py:394`) charges `len(line.encode("utf-8")) + 1` — one byte for the
newline. The writer (`report_service.py:1682`) is
`target.write_text("\n".join(lines), encoding="utf-8")`, which opens in **text mode**, so on Windows
every `\n` is written as `\r\n` = **2 bytes**.

**Undercount = (number of lines − 1) bytes.** Not academic: during lane A's derivation a
composition the allocator held at **0.978×** measured **1.050× OVER** on disk from this alone.

**Found independently by BOTH REV-5 lanes** → treat as confirmed, not as one agent's claim.

**This means the enforcement already shipped is wrong by that amount** — `_hexdump_section`'s
existing `budget.fits()` check is keyed on the same undercount. So D3 is a live correctness defect
in `main`, not merely a prerequisite for batch-64.

**Fix shape:** pin the writer (explicit `newline=""` / binary write of the encoded bytes) so the
file matches what `_line_bytes` accounts. **Golden-neutral** — `tests/conftest.py::canonical_report_bytes`
already undoes CRLF, so stored goldens do not drift. *(That neutrality claim is `assumed` — it must
be EXECUTED before it is promoted to an acceptance criterion, per C-39. Both lanes asserted it; no
lane measured it.)*

---

## What is NOT in this batch

- The document byte bound (all six-to-twelve unbounded axes) → **batch-64**.
- The row caps, the byte-run cell bound, the truncation-appendix repair → **batch-64** (they are
  parts of the bounding design, not standalone defects).
- The cell-vs-whole-row normative divergence between the two REV-5 lanes → **batch-64's** first
  decision; lane B's §16 names the probe that settles it.

## Carried to `.dev-flow/BACKLOG.md` at close

Every axis and finding surfaced by this batch, including: the twelve unbounded axes · lane A's
RES-1 (`_modified_files_lines`, 64 summaries × 32 000-char paths = 1.955× budget from one section,
**and every number in lane A's §6.2 was measured with that axis idle**) · the addendum *scan* being
O(R×V×E) so bounding output does not bound traversal · first-N truncation being attacker-selectable ·
`format-then-slice` being a 155.91 ms / 3 MB-per-cell DoS **with identical output** · appendix
forgery via a file-derived `variant_id` · the `related_artifacts` field upstream · variant coverage
above ~1 395 · and the standing evidence that **`_hexdump_section` does not carry the bytes 3 of the
4 table cells hold** (`applied.before_bytes` 0/200, `skipped.after_bytes` 0, `check.expected_bytes` 0).

## Process note carried forward

The `> TRUNCATED … (report size cap: N bytes)` marker **still asserts a bound the document
violates** after this re-scoped batch, because none of D1/D2/D3 bounds the document. batch-63 must
therefore **not** claim to have closed M-2. Stating that plainly in the PR is a requirement of this
batch, not a nicety — the batch's own founding thesis is that a document must not assert what it
does not honour, and the same rule binds its changelog.
