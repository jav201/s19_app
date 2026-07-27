# batch-63 — Phase-2 INDEPENDENT qa review of the validation plan

> **Reviewer:** independent `qa-reviewer`. I did not author `01-requirements-architect.md` (REV 4)
> or `01b-qa-catalog.md` (REV 2).
> **Subject:** does the validation plan pass while the product is wrong?
> **Method:** paper mutation-testing of all 24 planned nodes + executed probes against a
> `git archive` export of `031ca8d` in the session scratchpad. **The worktree was not mutated** —
> `git status --porcelain` shows only `.dev-flow/`.
> **Call: CHANGES REQUIRED — 5 blockers, 5 majors.**

---

## BLUF

The catalog's strongest work is real: the multi-run checklist trap (AT-167), the hard-coded-cap
catch (TC-400), and the survival direction on the byte bound (AT-173) are all genuine, and the
pre-existing-marker trap was correctly identified. **The failure is elsewhere: the catalog is REV 2
and the spec is REV 4, and the two diverged on the three things that matter most** — the constant
names, the constant values, and whether the truncation indicator lives inside the cell. As written,
a *correct* implementation of the REV-4 spec fails AT-172 and TC-406.

Independently of that drift, two holes survive on their own merits:

1. **The row cap's `>` vs `>=` boundary has no node at all.** `§4.1` claims AT-171 covers it;
   AT-171's own specification contains no such assertion. The mutation survives all 24 nodes.
2. **The "table is an index, hexdump is the evidence" premise is false for most of the data**
   (executed below), which makes the marker text LLR-091.3 mandates a false statement in the
   document — the exact M-2 class this batch exists to remove.

---

## 1. Blockers

### B-1 — the row cap's at-cap boundary is covered by a PHANTOM. `>=` survives every node.

`§4.1` of the catalog assigns the boundary row **"exactly at (`CAP`) → `CAP` rows; no cap marker
(a marker here is an off-by-one)"** to *"AT-171 (its arm asserts marker absence)"*.

**AT-171 has no such arm.** Its own specification (`01b-qa-catalog.md:274-312`) says only:
*Given* both tables at `CAP` rows with worst-case cells, *Then* "the generated document is **under
`REPORT_MAX_TOTAL_BYTES`**, with the measured size and its multiple of the budget printed". It
asserts a document **size**. It never mentions `> TRUNCATED`, a marker, or the appendix.

Mutation that should turn something red:

```python
-    if len(entries) > CAP:            # truth table M4/K4: "the cap is > , not >="
+    if len(entries) >= CAP:
```

At `M == CAP` this emits `CAP` rows (the slice is a no-op) **plus** a spurious
`> TRUNCATED: 0 of 500 modification rows omitted (cap: 500 rows per variant).` and a spurious
appendix bullet. Row counts are unchanged, so nothing that counts rows fires.

Node-by-node, no node has a fixture at `M == CAP`:

| node | fixture population | fires? |
|---|---|---|
| AT-164 | `3 × CAP`, and arm 2 `CAP + 1` | no — both legitimately over |
| AT-165 | `3 × CAP` | no |
| AT-166 / AT-167 / AT-168 | `3 × CAP` / `4 × 0.75 CAP` | no |
| AT-169 | `CAP − 1` | no — `499 >= 500` is false |
| AT-170 | 0 · filtered-to-0 · filtered-to-`CAP − 1` | no |
| AT-171 | `CAP` — **but asserts size only** | **no** |
| AT-172…175 | byte runs / decl errors / coexistence | no |
| TC-399 | `3 × CAP` | no |
| TC-400 | monkeypatched cap 5, 12 entries | no |
| TC-401 | `RUNS × PER_RUN` | no |
| TC-402…405 | appendix escape · `CAP > 133` · empty · filter→`CAP−1` | no |

This is the same shape as the two vacuous guards batch-62 shipped past three review passes: the
matrix *claims* coverage, and the claim was never checked against the node's own text.

**Required:** add an explicit at-cap arm — `M == CAP` for both tables, assert exactly `CAP` rows
**and** `text.count("> TRUNCATED") == 0` **and** `"## Truncation appendix" not in text` — as a
named assertion on a **non-`slow`** node (see M-5). `§4.1`'s "exactly at" row must point at it.
Note the contrast this makes visible: the *byte* bound's `>`/`>=` boundary **is** properly pinned
(AT-173 arm 2 + TC-406); the *row* cap's is not.

---

### B-2 — the two Phase-1 documents assign the SAME ids to DIFFERENT behaviours

`01-requirements-architect.md` §3 and `01b-qa-catalog.md` §2 are both normative Phase-1 outputs and
they collide:

| id | architect §3 (REV 4) | qa catalog §2 (REV 2) | |
|---|---|---|---|
| AT-166 | US-B63-1 AC-3 — byte-identity at/under cap | **checklist table stops at the cap** | ✗ collide |
| AT-169 | US-B63-2 AC-3 — aggregates unchanged + byte-identity | **the `CAP−1` byte-identity golden** | ✗ partial |
| AT-170 | **one entry at `MF_RUN_LENGTH_CEILING` → doc < budget** | **empty / all-filtered sections untouched** | ✗ collide |
| AT-171 | **in-cell marker inert on the token stream** | **single-variant worst-case size** | ✗ collide |

Requirement ids collide too — architect: `R-TUI-089…092`; catalog: `R-TUI-079/080/081`; the brief
handed to Phase 3: `R-TUI-079/080/081`.

**Executed on disk — the catalog's and the brief's reservation is the wrong one:**

```
$ grep -rohE "R-TUI-[0-9]{3}" --include=*.md --include=*.py . | sort -u | tail -6
R-TUI-087  R-TUI-088  R-TUI-089  R-TUI-090  R-TUI-091  R-TUI-092   (089-092 = this batch only)

$ grep -c "R-TUI-079\|R-TUI-080\|R-TUI-081" REQUIREMENTS.md
0
$ grep -rn "R-TUI-079" --include=*.md . | grep -v batch-63
.dev-flow/2026-07-16-batch-48/01-requirements.md:272:### HLR-079 — Patch Editor: JSON-window colouring + paste-cap gauge (R-TUI-079)
.dev-flow/2026-07-16-batch-48/01b-qa-strategy-and-verification.md:156: R-TUI-079 | HLR-079 | US-P4 | JSON window in-place colouring + paste-cap gauge
```

`R-TUI-079/080/081` are **claimed by batch-48** and simply never landed in `REQUIREMENTS.md`
(neither did `R-TUI-075`). The catalog scanned `REQUIREMENTS.md` only; the architect scanned
repo-wide and got the right answer. Re-using 079/080/081 would put two different meanings on one id
in `.dev-flow/` — and batch-48's own §733 records that exact clash biting a Phase-2 security brief.

**Required:** the architect document is the normative id authority (`R-TUI-089…092`). The catalog
must be re-numbered onto architect §3's AT map in the same pass, and the brief's
`R-TUI-079/080/081` corrected before Phase 3 reads it.

---

### B-3 — the catalog validates a WITHDRAWN design: the in-cell truncation indicator

REV 4 §12.2 **withdrew** the in-cell indicator, and `R-TUI-091(a)` is now unambiguous:

> "…and shall emit **no character outside `"0123456789ABCDEF "`**… **No truncation indicator shall
> be placed inside the cell.**" (`01-requirements-architect.md:368-372`)

The catalog (REV 2) still validates the opposite:

- **AT-172**: "**and** the cell states that it was cut — the row must not silently present a
  truncated run as if it were the whole run" (`:326`). Counterfactual: "Truncate silently (no
  indicator) → the 'states the cut' assertion fails" (`:336`).
- **TC-406**: "`CELL_BYTES + 1` → **bounded + indicator**" (`:438`).
- **TC-409**: exists solely to assert "the chosen indicator's character set" against F-17's
  alphabet (`:441`).

**A correct REV-4 implementation fails AT-172 and TC-406, and TC-409 has no subject.** This is not a
theoretical divergence: an implementer working from the catalog will re-introduce the in-cell
indicator that A-4 withdrew *because it invalidates locked `R-TUI-077`'s premise* — i.e. the catalog
as written steers Phase 3 into re-opening a security pin.

Compounding it, the **architect's own §3 is stale at the same point** and reinforces the error:

- §3 AT-170 (`:458`): "…and **the cell states the exact omitted byte count**."
- §3 AT-171 (`:461`): "The truncation marker **emitted inside a byte-run cell** is inert…"

§12/§13 amended §2 and §5 and left §3 at REV-2 wording. **§2 and §3 of the normative spec now
contradict each other**, and both downstream lanes inherited the §3 version.

**Required:** rewrite AT-172 / TC-406 against the *outside-the-cell* section marker of LLR-091.3;
retire or re-point TC-409 (F-17 now survives untouched — LLR-091.4 says so); and amend architect §3
AT-170/AT-171 with a §6.5 Before/After rather than silently.

---

### B-4 — TC-406's deliberately-pinned drift floor is FALSE against the normative constant

The catalog names exactly two numbers it is allowed to pin, TC-403 (`CAP > 133`) and TC-406. TC-406
pins:

> "Plus the **drift floor**, deliberately pinned: `CELL_BYTES >= 256`, with the docstring stating
> that 256 is the largest run the existing suite renders… and that the value has **zero**
> headroom" (`01b-qa-catalog.md:438`)

The normative value is **`REPORT_CELL_BYTES = 64`** (`01-requirements-architect.md:5, :590`).
`64 >= 256` is false — **TC-406 fails on the shipped constant on day one.** AT-173's drift note
(`:359-362`) and §4.2's "under/at/over = 255/256/257" arms carry the same stale 256.

The underlying analysis is also superseded, and in the reassuring direction. Re-derived by execution
here rather than predicted:

```
$ python p_evid2.py   # every golden .md, max byte-run tokens in any table cell
tests/goldens/batch35/at054b-before-after-report.md  data_rows=2  max_byte_run_in_a_cell=1
tests/goldens/batch35/at055b-project-report.md       data_rows=1  max_byte_run_in_a_cell=1
```

**Document-level golden drift at `REPORT_CELL_BYTES = 64` is ∅** — the largest byte run in any
shipped golden cell is **1 byte**, 64× under the bound. The only drift is the single direct unit
call `_format_bytes(range(256))` at `tests/test_report_field_census.py:835`, and LLR-091.4 rules
that it stays GREEN (the cell alphabet is unchanged, so the `set(rendered) <= set("0123456789ABCDEF ")`
assertion at `:836` holds on a 64-token prefix exactly as on 256).

**Required:** restate the floor as measured against the *document* corpus, not the suite maximum —
`CELL_BYTES >= 16` is the honest floor (§0.7 histogram `{1: 579, 2: 563, 4: 4, 256: 1}`; every real
document cell is 1–4 bytes). Update §4.2's arms to `CELL_BYTES ± 1` computed from the constant, per
the catalog's own [PARAM] rule — the literal `255/256/257` violates it.

---

### B-5 — EVIDENCE DELETION: the design's "index vs evidence" premise is false for most rows, and no node covers it

LLR-091.1 makes the design's legitimacy rest on one claim — *"the table is an index,
`_hexdump_section` is the evidence"* — and LLR-091.3 mandates the implementation put that claim
**into the document**:

> `> TRUNCATED: {k} byte cell(s) rendered as a {REPORT_CELL_BYTES}-byte prefix …;
> **full bytes in the Memory regions section.**` (`01-requirements-architect.md:611-614`)

**I validated the premise empirically instead of accepting it. It is false for 4 of the 5
dispositions and for 100 % of checklist rows.** Probe: one entry, a 100-byte run, byte cell rendered
in the table; then strip every `| 0x…` table row and ask whether the tail bytes survive anywhere
else in the document.

```
                                  tail-in-nontable   hexdump_blocks
MOD disp=applied                       False               0
MOD disp=skipped-partial               False               0
MOD disp=skipped-outside               False               0
MOD disp=skipped-no-image              False               0
MOD disp=blocked                       False               0
CHK result=pass                        False               0
CHK result=fail                        False               0
CHK result=uncheckable                 False               0

--- applied WITH mem_map ---
    ### Memory regions
    0x00001040  40 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F  |@ABCDEFGHIJKLMNO|
```

The mechanism, read from source:

- `_applied_regions` (`report_service.py:1180`, consumed by `_hexdump_section` at `:1315`) collects
  ranges from **`applied` change-summary entries only**.
- `ChangeSummaryEntry.after_bytes` is **`tuple[int, ...]`, not Optional** (`changes/model.py:369`) —
  every `skipped-partial` / `skipped-outside` / `skipped-no-image` / `blocked` entry still renders
  its full declared encoded run into the **After** cell, and contributes nothing to the hexdump.
- `CheckRunEntry.expected_bytes` / `actual_bytes` (`changes/model.py:674-675`) reach
  `_checklist_lines` only. **No checklist byte ever reaches `_applied_regions`.**
- Even for `applied`, the hexdump only materialises when the variant carries a `mem_map` — the
  `applied` row above produced `hexdump_blocks=0` without one.

So for a `blocked` 128-byte patch entry, or a failing 128-byte calibration-map check, a 64-byte cell
bound **deletes bytes that exist nowhere else in the document**, while the document states in
writing that they are in the Memory regions section. That is a document asserting a fact it does not
honour — finding M-2's own class, re-introduced by M-2's fix.

**No node covers this.** AT-172 asserts the cut is *stated*; AT-173 asserts in-bound runs *survive*.
Neither asserts the deleted bytes are *recoverable*, and nothing challenges the marker's own claim.

**Required, one of:**
(a) scope the marker text to what it can honour (drop the "full bytes in the Memory regions
section" clause, or condition it on `applied`), **and** add an AT that asserts the marker's pointer
resolves — for an `applied`+`mem_map` fixture the bytes are found in the hexdump; for a `blocked`
or checklist fixture the marker does **not** make the claim; or
(b) raise `REPORT_CELL_BYTES` above the legitimate check/patch run width and re-derive the cap
against §10.3's joint surface.

Either way this needs a node, and the *decision* is an architect ruling — I am flagging that the
plan currently ships (a)'s text with (b)'s premise and validates neither.

---

## 2. Majors

### M-1 — truth-table rows M8 / K10 (filter set **and** post-filter `K > CAP`) have no node

Both documents make the cap-after-filter ordering normative *and* pin what the marker must say:

> M8: "`F` set, `K > C` → **`C` rows + marker stating `{K-C} of {K}`**. The marker's totals are the
> **post-filter** count `K`" (`01-requirements-architect.md:489`); K10 likewise (`:508`); LLR-089.3
> and LLR-090.4 carry the `shall`.

The **ordering** is covered (AT-170 arm 3, TC-405) — that part of dig-item 4 is genuinely pinned, in
both directions, by both documents. **The marker's totals under a filter are not.** Every node that
sets a filter keeps the kept-count *under* the cap:

- AT-170 arm 2 → `K = 0`; arm 3 → `K = CAP − 1`. No marker in either.
- TC-405 → `K = CAP − 1`. Asserts the notes list is **empty**.
- AT-165 / AT-168 assert the marker's `M` — with **no filter set**.

Mutation `omitted, total = len(entries) - CAP, len(pre_filter_entries)` — emitting the *pre*-filter
total in the marker — is green across all 24 nodes. §4.1's matrix has no row for it either.

**Required:** one arm with a filter set and `K > CAP`, asserting the marker's `N of M` are both
post-filter, and a §4.1 row for it.

### M-2 — LLR-091.3's truncated-cell **count** `k` is never asserted

The marker is `> TRUNCATED: {k} byte cell(s) rendered as a … prefix`. AT-172's fixture is one entry
with **two** oversized cells (`before_bytes` and `after_bytes`), so the correct `k` is 2 — but no
node asserts `k` at all. `k = 1` (counting rows), `k = 2` (counting cells) and `k = 4` (counting
both tables' columns) are all indistinguishable under the current plan, and the marker is the only
place a reader learns how much was cut.

### M-3 — the catalog's [PARAM] import block will not import

```python
from s19_app.tui.services.report_service import (
    MAX_REPORT_TABLE_ROWS_PER_VARIANT as CAP,   # name is the architect's to fix
```
(`01b-qa-catalog.md:137`)

Phase 1 ruled **two** constants (LLR-089.1 `MAX_REPORT_MODIFICATION_ROWS_PER_VARIANT`, LLR-090.1
`MAX_REPORT_CHECK_ROWS_PER_VARIANT`; §1.5 "**TWO constants**", "the coincidence is not a coupling").
A single `CAP` does not exist and never will. This fails loudly (`ImportError`), which is the good
kind of failure — but it means **every node in §2 and §3 is unrunnable as written**, and it invites
the implementer to "fix" it by collapsing the two constants back into one, undoing §1.5.

Every node must bind the constant that governs the table it exercises. AT-171, AT-175 and §4.1's
shared rows need to say which.

### M-4 — unresolved placeholders remain; evidence-checklist item 10 is now false

The catalog's own item 10 claims *"No unfilled template ✓ — no `<...>`… the one deferred item is the
marker's final wording"*. Phase 1 has since closed, and at least three placeholders survive:

| site | placeholder | Phase-1 ruling that resolves it |
|---|---|---|
| §2 [PARAM] `:137` | `# name is the architect's to fix` | LLR-089.1 / LLR-090.1 |
| TC-401 `:433` | "zero data rows **(or is elided — Phase 1 rules which; the TC asserts the ruled shape)**" | **LLR-090.3** — heading + aggregates + table header, zero rows, aggregates unaltered |
| TC-400 `:432` | `"<CAP_CONST>"` | as above |

TC-401 is the node for the checklist cap's most subtle emitted shape; leaving its expected output
unfixed means the implementer picks the oracle.

### M-5 — the only at-cap node is `@pytest.mark.slow`, and the PR lane deselects `slow`

AT-171 is marked `@pytest.mark.slow` (`01b-qa-catalog.md:276`). Executed:

```
$ sed -n '45,52p' .github/workflows/tui-ci.yml
      - name: Run lean test suite (pull requests)
        if: github.event_name == 'pull_request'
        run: pytest -q -m "not slow"
      - name: Run full test suite (pushes)
        if: github.event_name == 'push'
        run: pytest -q
```

**The PR that ships batch-63 never runs AT-171.** The batch's own base measurement is likewise
`-m "not slow"`. Once B-1's at-cap assertion is added it must not land on a `slow` node, or the
boundary is unverified on the merge gate — the gate the operator's autonomy grant is conditioned on.

---

## 3. Minors

| # | finding | evidence |
|---|---|---|
| m-1 | Catalog §5 item 2 states the existing golden carries "**2** modification rows"; measured **1**. | `grep -c "^| 0x" tests/goldens/batch35/at055b-project-report.md` → `1` |
| m-2 | Architect cites `MF_RUN_LENGTH_CEILING` at `changes/io.py:226` in §0.1 and §1.3; it is at **:232** (`:226` is `MF_ENTRY_COUNT_CEILING`). §10.2/§11.3 cite it correctly — self-inconsistent. | `grep -n "MF_RUN_LENGTH_CEILING" s19_app/tui/changes/io.py` → `232` |
| m-3 | The `CAP−1` golden is **74 KiB / 1 074 lines** (measured, below) vs the existing golden's 2.6 KiB — 28×, and unreviewable by a human. Worse, its *unique* catch is narrow: a `>= CAP` off-by-one does **not** fire at 499, so the golden's incremental value over a 199-row one (31 KiB) is only the `>= CAP−1` off-by-two. The realistic off-by-one is B-1's job. Consider 199 + B-1's at-cap node. | see derivation |
| m-4 | AT-169 is the single node for **both** stories' AC-3 (§7 rows 3 and 6). Defensible as one observable, but a failure will not attribute to a story. | `01b-qa-catalog.md:605,608` |
| m-5 | TC-408 (`Length` not derived from the rendered cell) is green before *and* after the change, exactly like AT-173, but §8 item 3's executed-mutation list names AT-173 only. | `01b-qa-catalog.md:633` |

**m-3 derivation, executed through the shipped composer at `031ca8d`:**

```
  CAP-1 =    1 rows/table -> golden document =     2,702 B  (2.6 KiB), lines=78
  CAP-1 =  133 rows/table -> golden document =    22,002 B  (21.5 KiB), lines=342
  CAP-1 =  199 rows/table -> golden document =    31,704 B  (31.0 KiB), lines=474
  CAP-1 =  499 rows/table -> golden document =    75,804 B  (74.0 KiB), lines=1074
```

---

## 4. What the plan gets RIGHT (do not weaken these in the rework)

- **AT-167 / TC-401 — the multi-run checklist trap.** The stated mutation
  (`for entry in check.entries[:CAP]`) genuinely leaves AT-166 green and only AT-167 red. This is a
  correct C-18 split and the measured `10 × 150 → 1500` baseline backs it.
- **TC-400 — the hard-coded-cap catch.** Correctly identified as *the only* node that can catch it,
  since every AT reads the constant. The local `5`/`12` literals are correctly exempted from [PARAM].
- **AT-173 — the survival direction.** Dig-item 2 answered: for the **byte** bound, yes — arm 2
  (exactly `CELL_BYTES` → verbatim) plus TC-406's explicit `>`/`>=` pin would go red on
  `values[:CELL_BYTES]` with a `>=` comparison, and the "expected cell text is built in the test
  from the fixture's own byte tuple" rule kills a reordered or dropped byte. §4.2 additionally
  covers `None` and zero-length. The realistic-short arm is 4 bytes, not 3, which is adequate.
  (The gap is the **row** cap's boundary — B-1 — not this one.)
- **The pre-existing-marker trap** (§2 ⚠ box) and the `skipped-outside` isolation that defeats it.
- **The GFM shape-comparison prohibition** in the row-count helper — the batch-62 lesson applied.
- **Cap × filter ordering** (dig-item 4) is pinned in one direction by both documents (M6/K8 →
  cap after filter, post-filter population) and has a node (AT-170 arm 3, TC-405). Only the marker's
  totals under a filter are missing (M-1).
- **Frozen files** (dig-item 7) — verified from source, not from the brief.

---

## 5. Evidence checklist

| # | item | ✓/✗ | evidence |
|---|---|:--:|---|
| 1 | Acceptance criteria in Given/When/Then | ✓ | catalog §2 uses Given/When/Then throughout |
| 2 | Expected values explicit, never "works" | ✓ | exact marker strings pinned; §4 matrices carry an Expected column |
| 3 | Edge cases: empty · boundary · invalid · error | **✗** | empty ✓ (AT-170 arm 1 / TC-404) · invalid ✓ (AT-170 arm 2) · **boundary INCOMPLETE — `M == CAP` has no node (B-1)**; byte boundary ✓ (AT-173/TC-406) |
| 4 | Regression checklist exists | ✓ | catalog §5 drift set, executed (376 tests, `mod_max=133`, `chk_max=3`) |
| 5 | Exit criteria stated | ✓ | catalog §8 — RED-first, ledger `A=24 D=0`, executed counterfactuals |
| 6 | No real PII / secrets / client data | ✓ | all fixtures synthetic; my probes wrote only into `tempfile.mkdtemp()`; `_assert_no_host_path_residue` at `tests/conftest.py:1039` guards the golden |
| 7 | Results section left blank | ✓ | this review reports no AT/TC as passing — none exists yet |
| 8 | Layer B through the shipped surface, boundary + negative evidence | **✗** | every AT does call `generate_project_report` and re-read from disk ✓; but B-1 (boundary) and B-5 (evidence recoverability) are unobserved |
| 9 | Bidirectional surface-reachability | **✗** | inputs ✓ (entry count, run count, cell width, filter, disposition, byte-run length). **Outputs: the truncated-cell count `k` is a named output with no observation (M-2), and the marker's post-filter totals likewise (M-1)** |
| 10 | No unfilled template | **✗** | `<CAP_CONST>` `:432` · `MAX_REPORT_TABLE_ROWS_PER_VARIANT` "name is the architect's to fix" `:137` · TC-401 "or is elided — Phase 1 rules which" `:433` — Phase 1 has closed (M-4) |
| 11 | Ids verified on disk, not inherited | **✗** | `R-TUI-079/080/081` are claimed by `.dev-flow/2026-07-16-batch-48/`; repo-wide max is `R-TUI-088` (B-2). AT max 163 ✓ correct |
| 12 | Frozen-file list read from source | ✓ | `tests/test_tui_directionb.py:5457-5468` — 9 files, none a report test; `_ENGINE_PATHS` has no `services/` path. **No planned test lands in a frozen file** |
| 13 | Every AT has a constructible killing mutation | **✗** | 20 of 24 yes. **AT-171 cannot kill the `>=` row-cap mutation it is credited with (B-1)**; **AT-172 / TC-406 / TC-409 kill the *correct* implementation (B-3)**; TC-406's floor assert fails on the shipped constant (B-4) |
| 14 | Catalog consistent with the normative spec it validates | **✗** | REV 2 vs REV 4: constant **names** (M-3), constant **values** (B-4), **in-cell indicator** (B-3), **id map** (B-2). Architect §3 is itself stale vs its own §2 (B-3) |
| 15 | Design premises validated, not accepted | **✗** | "the table is an index, `_hexdump_section` is the evidence" is **false** for 4/5 dispositions and all checklist rows — executed (B-5); no node covers it |
| 16 | Golden strategy sound; captured pristine; drift derived not predicted | ✓ *(with m-3)* | `git archive 031ca8d` capture is correctly specified and pre-edit; `canonical_report_bytes(raw, run_root)` (`tests/conftest.py:970`) handles CRLF + run-root tokenisation and the existing golden carries `<RUN-ROOT>` (1 occurrence), so the comparison form is right. **Byte-bound drift on existing goldens = ∅, derived by execution** (max byte run in any golden cell = 1) |
| 17 | C-18 — one AT, one node, one chain | ✓ *(1 phantom)* | every AT is one `def test_at_NNN_*`; no row says "combination of". The one violation is §4.1's "exactly at" row crediting AT-171 with an arm it does not have (B-1) |
| 18 | No worktree mutation by this review | ✓ | probes ran against a `git archive 031ca8d` export in the scratchpad; `git status --porcelain` → `M .dev-flow/state.json`, `?? .dev-flow/2026-07-26-batch-63/` only |

---

## 6. Gate call

**`iterate` — CHANGES REQUIRED.** Named gaps, not a hollow iterate:

| axis | assessment |
|---|---|
| **Coverage** | **NOT MET.** The row cap's at-cap boundary is unobserved (B-1); the byte bound's evidentiary premise is unobserved and false (B-5); two normative outputs have no observation (M-1, M-2). |
| **Certainty** | **NOT MET.** The catalog validates a withdrawn design (B-3) and pins a superseded constant (B-4); a correct implementation fails two of its nodes. |
| **Evidence** | **PARTIAL.** The catalog's own executions are sound and reproduce (I re-derived the golden drift set independently and agree it is ∅). The failures are drift and unchecked premises, not fabrication. |

**Ordered rework, smallest first:**
1. Re-number the catalog onto architect §3's AT map and onto `R-TUI-089…092`; correct the brief. (B-2)
2. Amend architect §3 AT-170/AT-171 to REV-4's outside-the-cell marker, with a §6.5 Before/After. (B-3)
3. Rewrite AT-172 / TC-406 / TC-409 and §4.2 against the outside-the-cell marker and
   `REPORT_CELL_BYTES = 64`, parameterised. (B-3, B-4)
4. Bind each node to its own constant; resolve TC-400/TC-401's placeholders against LLR-090.3. (M-3, M-4)
5. Add the at-cap node, non-`slow`, and re-point §4.1's "exactly at" row. (B-1, M-5)
6. Add the filter+`K > CAP` marker-totals arm and the `k`-count assertion. (M-1, M-2)
7. **Architect ruling required** on the marker's "full bytes in the Memory regions section" clause,
   then a node for whichever way it goes. (B-5)

B-5 is the one that should not be closed by a test alone — it is a design question the plan
currently answers in prose and contradicts in the document it ships.
