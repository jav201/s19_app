# batch-74 — Inc-1 review packet

**LLR-105.1 · 105.3 · 105.5 · 105.6 · 105.7** · ATs **240, 242, 242b, 244, 247, 248** · TCs **540-545**

> **BLUF — the increment's central claim shipped without a falsifier, and the independent review caught
> it by executing the counterexample.** Every width-axis predicate authored at Inc-1 was
> **output-shaped**, so a `format-then-slice` `_format_bytes` emits **byte-identical output**, passes
> **all 79 tests**, and peaks at **56,683,416 B against the correct implementation's 9,490 B — 5,973×**.
> The resident-memory oracle could not see it either: `AT-248`'s fixture uses `_entry`'s default
> **1-byte** run, so it never exercises the width axis at all. **This is the house defect of this exact
> code area** (batch-63 shipped five vacuous criteria for one defect here), and it survived the
> implementer's own C-40 pass because the mutation that reveals it changes *no output at all*.

## 1. What changed

| File | Change |
|---|---|
| `s19_app/tui/services/report_service.py` | `MAX_REPORT_ROWS_PER_VARIANT = 200` · `REPORT_BYTES_PER_CELL = (REPORT_CELL_CHARS + 1) // 3` (**derived**, evaluates to 171) · byte-cell cue + row-notice format constants · `CUE_ALPHABET` · `_format_bytes(values, *, max_bytes)` source-bounded via `islice` · **all four call sites** updated · `_modifications_lines` single-pass rewrite |
| `tests/test_report_producer_bound.py` (new) | AT-240/242/242b/244/247/248 + TC-540…545 |
| `tests/test_report_field_census.py` | `test_f17`'s closed alphabet **widened** to `HEX ∪ {" "} ∪ CUE_ALPHABET`, plus an in-cap arm asserting the *original* narrow alphabet |

**The single-pass claim, verified rather than accepted:** `_modifications_lines` now holds only a `rows`
buffer bounded to the cap by a `continue`, plus two `int` counters. No `list()`, no slice, no
comprehension inside a `sum()`, no intermediate tuple. Corroborated by measurement — peak ratio
**1.0001**, not merely by reading the code.

## 2. Independent review — BLOCK, then discharged

| id | sev | Finding | Disposition |
|---|---|---|---|
| **F1** | **HIGH** | **LLR-105.3's *source-bounding* clause had no falsifier.** Executed: format-then-slice passes all 79 tests with byte-identical output at **5,973×** the peak | **AT-242b added** — the §5.1 residency oracle applied to the width axis. Measured **1.000 shipped vs 9.941 format-then-slice** |
| **F2** | MEDIUM | **The anti-vacuity guard contained its own opt-out** — `... or 256 <= REPORT_BYTES_PER_CELL` auto-disables it if `REPORT_CELL_CHARS` is ever raised past 767, at which point the fixture stops truncating and the alphabet assert becomes trivially true. LLR-105.7 forbids shrinking the fixture; the guard *permitted it automatically* | Fixture scaled to `2 × REPORT_BYTES_PER_CELL`; cue asserted unconditionally; the opt-out arm deleted |
| F3 | LOW | Dual elided-count path (sized fast path + generic drain); only the sized branch is production-reachable | **Kept** — 30 shape×case combinations executed, 0 mismatches. It is the `O(1)` answer to the implementer's own finding (f): a naive drain is `O(L)` *time* per cell, ≈400M iterations at the wire ceiling, inside the very threat model this batch bounds |
| F4 | LOW | Missing type annotation disagreeing with its own docstring | Fixed |
| F6 | LOW | AT-243 landed in Inc-1 while §7 assigns it to Inc-2 | Node renamed + docstring marked "(Inc-1 partial)" so it cannot read as discharged at the Inc-2 gate |
| F5 | LOW | `(+1 more bytes)` pluralisation | Accepted, not changed |

**Two mutations survived the implementer's own suite; one became F1, the other (`_zero_match_notice(kept)`)
was found already covered** by pre-existing `TC-314`/`TC-318` in `test_report_service.py` — the
fused-loop regression risk was real but guarded.

## 3. Evidence

**Counterfactuals executed on a copy of the FIXED tree** (never `main`, never a tree another session
reads), each failing on **its own assertion**, not on an `ImportError`:

| Mutation | Result |
|---|---|
| cap admits one row too many (`>` → `>=`) | `expected exactly … (200) admitted rows at E = cap + 1, got 201` |
| byte-run bound not applied | `Before cell is 2071 chars, over the 3·REPORT_BYTES_PER_CELL − 1 + len(cue) = 532 bound` |
| notice states the POPULATION count | `must state the KEPT overshoot (137) of the KEPT total (337) … Got: '196 of 396'` |
| `CAP = 1` (positive control) | `the under-cap report drifted from the Inc-0 golden` |
| bare `200` re-enters the producer body | `_modifications_lines carries a bare cap literal [200]` |
| cue spelled `...` instead of `…` | `emitted a character outside HEX \| {' '} \| CUE_ALPHABET: ['.']` |
| **format-then-slice (F1)** | **survived** → AT-242b authored |

⚠️ **The implementer flagged its own first RED as weak evidence, correctly.** 15 of 16 nodes initially
died on `AttributeError: … has no attribute 'MAX_REPORT_ROWS_PER_VARIANT'` — an absent-constant RED
proves only that the constant is absent. The evidence that counts is the mutation table above, run
against the *fixed* tree.

**AT-247 provenance verified by execution, not by trust:** swapping in `HEAD:report_service.py` (the
shipped producer) reproduces the Inc-0 golden **byte-for-byte** through `canonical_report_bytes`, and
`c613b6a` adds *only* the golden and predates every `report_service.py` edit. C-12 ordering sound.

**§5.1 oracle re-derived on this tree (C-39 rider — re-measure the fold's OWN numbers):**

| | spec | measured | verdict |
|---|---|---|---|
| SHIPPED | 9.887 | **9.836** | reproduces within 0.5% |
| CAP-ONLY | 1.921 | **2.224** | ❌ **did not reproduce** |
| FUSED (correct) | 1.000 | **1.000** | exact |

**CAP-ONLY's non-reproduction is a spec defect, not a measurement error: §5.1 never DEFINED the
CAP-ONLY shape**, so two reconstructions differ in detail. Verdict unchanged (both defective shapes sit
far above the 1.15 gate), but a number whose counterfactual is undefined is not reproducible and
should not have been quoted as though it were. **The counterfactual now lives in code**
(`_shipped_body` / `_cap_only_body`), so the next run has something to reproduce against. §5.1 amended.
FUSED = 1.000 exactly, so **the threshold was not widened.**

**Flakiness check for CI (ubuntu/py3.11):** FUSED ratio measured **8× consecutively at 1.0001, zero
variance**. Gate 1.15, nearest defective 2.224 — the ratio is structural, not timing-dependent.

## 4. Spec defects found by implementation

| # | Defect | Disposition |
|---|---|---|
| a | **§7's AT column kept the pre-renumber numbers** — the collision renumber replaced `AT-220` but §7 stores **bare** `220, 222, …` with no prefix | Fixed: §7 now reads 240/242/244/247/248 and 241/243/245/246/249 |
| b | **P-18 is TRUE but its margin is ZERO, not comfortable.** The batch-64 golden's largest single `(document, variant)` Modifications table is **exactly 200** = the cap. A census that does not split on document boundaries reads **272** and would wrongly conclude the cap fires | Recorded in the constant's docstring, including that lowering the cap by one trips the batch-64 pin |
| c | §5.1's CAP-ONLY figure not reproducible | §5.1 amended (above) |
| d | **LLR-105.5's "the total" is ambiguous** — kept total or pre-filter population? | Resolved as the **kept** total for consistency with LLR-105.4′; flagged for Inc-3's requirement write-up |
| e | **LLR-105.7's set-inclusion is literally false for `values=None`** — `"-"` is in none of the three sets | The shipped `test_f17` already handled `None` as a separate arm and that survives; the LLR needs a non-`None` carve-out at Inc-3 |
| g | **AT-242's bound is exactly attained, not slack** — `3·171−1 = 512`, `len(cue) = 20`, bound 532, actual cell **532**. A `<` instead of `<=` would be RED on correct code | Recorded so nobody "tightens" it |

## 5. Risks

- **`_checklist_lines` is now bounded on WIDTH but not on CARDINALITY** — Inc-2 owns that. `AT-243`
  asserts the width axis only and says so in its docstring, precisely so it does not read as a
  checklist cardinality gate.
- The batch-64 golden's zero-drift property is **exactly** spent, not comfortably held (defect b).

## 6. Pending

Inc-2 (`_checklist_lines` cap + per-file saturation + the Address bound) · Inc-3 (`REQUIREMENTS.md`
R-TUI-101, the LLR-105.5/105.7 wording carve-outs from defects d/e, and the batch-75 split into
`BACKLOG-CODE.md`).

## 7. Suggested next task

**Inc-2.** The Address axis is the one with no prior art in this batch and the newest requirement —
`REPORT_ADDRESS_CHARS` must be derived **top-down** from `REPORT_ADDRESS_HEX_DIGITS`, never bottom-up
from the golden census, or `AT-246` goes RED after a correct implementation.
