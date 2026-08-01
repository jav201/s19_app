# batch-76 — Inc-1 opening measurements

**Executed against `origin/main` = `291bb76`** (the batch base), on the tree before any producer
edit. Every number here was **run**, not carried across from batch-75's table (C-39).

---

## §1 BLUF

| # | Premise | Verdict | Consequence |
|---|---|---|---|
| **P-16** | the preamble can be refused under the shipped budget | ✅ **TRUE** | **requirement-strength change** — `LLR-108.8` cannot stay "uniform, including the preamble" |
| **P-17** | capping the truncation appendix drifts a shipped golden | ❌ **FALSE** | cap is inert against the current suite; safe to land |
| **P-25** | the reservation floor starves a legitimate single-variant report | ❌ **FALSE** | the floor cannot bind at `V = 1` |
| **P-27** | *(NEW)* the per-variant reservation, alone, preserves the ceiling | ❌ **FALSE** | **the floor breaks the ceiling from the other side** — an admission must fit BOTH gates |

---

## §2 P-16 — TRUE. The preamble is `O(V)`; its header is `O(1)`

Measured by calling the shipped `_header_lines` / `_inventory_lines` / `_overview_lines` /
`_legend_lines` and charging each with the shipped `_line_bytes`.

| `V` | header | inventory | overview | legend | **total** | × cap |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 181 | 105 | 173 | 1562 | **2 021** | 0.001× |
| 10 | 181 | 357 | 425 | 1562 | **2 525** | 0.001× |
| 100 | 181 | 3 057 | 3 035 | 1562 | **7 835** | 0.004× |
| 1 000 | 181 | 31 857 | 30 035 | 1562 | **63 635** | 0.030× |
| 5 000 | 181 | 167 857 | 154 035 | 1562 | **323 635** | 0.154× |
| 20 000 | 181 | 697 857 | 629 035 | 1562 | **1 328 635** | 0.634× |

**Two facts decide the disposition, and they point in opposite directions:**

1. **`inventory` and `overview` are `O(V)`** — one row per variant each. Marginal cost measured at
   **62.0 B/variant** over `100→1000` and **65.0 B/variant** over `1000→5000`. *The slope is not
   constant*, so the growth is strictly `O(V log V)`, not `O(V)`: the variant-id column widens as
   the ordinal gains digits. **I am recording that the two measured slopes disagree rather than
   averaging them** — extrapolating from either alone would misstate the crossover.
   Solving from the `1000→5000` slope: **the preamble alone reaches the 2 097 152 B cap at
   `V ≈ 32 285`.** Non-claim (d) puts no cardinality cap on `V`, so this is reachable by construction.
2. **`header` is `O(1)` — exactly 181 B at every `V` from 1 to 20 000.** Flat, measured, not assumed.

### §2.1 Why this is a requirement-strength change

`LLR-108.8` reads *"Gating shall be uniform across all `emit` call sites including the preamble."*
Implemented literally, at large `V` the **header itself is refused** — and the document loses its
title. That directly contradicts **`AT-255`**, the PIN asserting a budget-exhausted report is still
usable: *"exists, non-empty, **header present**"*. **The spec's own acceptance and its own LLR
cannot both hold.** Surfaced here, not absorbed — as `§2.3` pre-committed.

### §2.2 The disposition, and why not the obvious one

Exempting *the whole preamble* is the reading the spec's `§2.3` sketches ("`LLR-108.8` flips to an
explicit exemption and the allowance grows"). **It is the wrong one, and the measurement is why:**
the preamble is `O(V)`, so exempting it would put an unbounded term inside the allowance and
**`HLR-108`'s `V`-invariance would become false** — at `V = 20 000` the "allowance" would have to
absorb 1.33 MB. The ceiling would still be *stated* and would no longer be *true*.

**Exempt only the `O(1)` header.** It is 181 B, flat in `V`, and it gets exactly the treatment
`LLR-108.5` already gives the per-variant heading — emitted outside the gate so the artefact cannot
vanish — for exactly the same reason. `inventory` and `overview` stay **gated and refusable**, and
their refusal is **disclosed** through the same aggregated block as everything else.

---

## §3 P-17 — FALSE. Capping the appendix drifts nothing

| Probe | Result |
|---|---|
| golden files containing `## Truncation appendix` | **0** — `grep -rln` over `tests/goldens/` returns nothing |
| test files referencing it | **2** (`test_report_service.py`, `test_report_field_census.py`) |
| assertions, and the note count each exercises | `:290` asserts **absent** when no cap fired · `:470` **1** note · `:510` **1** note · `field_census:782` **1** note |

**No byte-identity golden captures an appendix at all**, so the C-24 report-golden census comes back
empty for this change. A derived cap of **4 or more is inert** against every node in the suite today.
The batch-76 Inc-0 golden also carries **no** appendix (nothing is capped under budget), which is
recorded as P-17's starting state.

---

## §4 P-25 — FALSE. The floor cannot bind at `V = 1`

| Probe | Result |
|---|---|
| `reservation(V=1) = CAP // max(V,1)` | **2 097 152 B — the entire cap.** `max(CAP//1, floor)` is `CAP` for any sane floor, so **the floor is structurally unreachable at `V = 1`** |
| a **saturated** single-variant report — rows at `MAX_REPORT_ROWS_PER_VARIANT = 200`, 4 KiB `mem_map` | **26 161 B = 1.2475 % of cap** |
| starved? | **No** |

A single-variant report is refused only if it would exceed the *whole document cap* — which is the
ceiling doing its job, not the floor starving anything.

**Derivation input for the floor.** Minimal report at `V = 1` = **2 358 B**; at `V = 2` = **2 752 B**;
so one variant's **minimal audit record costs 394 B**. The floor is derived from that measured
marginal cost — it must cover at least one variant's heading and section skeleton — never chosen.

---

## §5 P-27 — NEW, and FALSE. The floor breaks the ceiling from the other side

**The spec does not name this, and it is the hazard that matters.** `LLR-108.4` floors the
reservation at `REPORT_VARIANT_RESERVATION_FLOOR_BYTES`. Once the floor binds, the reservations no
longer partition the budget — **they over-subscribe it**:

`Σ reservations = V × max(CAP // V, floor)`

| floor | binds from | `Σ reservations` at that `V` | vs CAP |
|---:|---:|---:|---:|
| 512 B | `V = 4 097` | 2 097 664 B | 1.00× |
| 1 024 B | `V = 2 049` | 2 098 176 B | 1.00× |
| 2 048 B | `V = 1 025` | 2 099 200 B | 1.00× |
| 4 096 B | `V = 513` | 2 101 248 B | 1.00× |

and it keeps growing past the crossover — the table shows the crossover point, not the worst case.
At `floor = 1024`, `V = 100 000`, `Σ reservations = 102 400 000 B ≈ **48.8× CAP**`.

**Consequence.** If a variant's admission were gated **only** by its own reservation, `AT-250`,
`AT-251` and `AT-252` — the three ceiling acceptances — would be **violated at large `V`**, by the
very mechanism added to make the document fair. The reservation must be a **sub-limit inside** the
global budget: an admission is admitted only when it fits **both** its variant's remaining
reservation **and** the document's remaining budget.

This is not a wording preference; without it the batch ships a broken ceiling while its own fairness
test passes.

---

## §6 What these four change in the spec

| Clause | Before | After | Driver |
|---|---|---|---|
| **`LLR-108.8`** | "Gating shall be uniform across all `emit` call sites **including the preamble**." | Uniform across all `emit` call sites **except the `O(1)` header**, which is emitted unconditionally; `inventory`/`overview` stay gated and their refusal is disclosed. | **P-16 TRUE.** Literal uniformity refuses the title at large `V` and contradicts `AT-255`. Exempting the whole preamble instead would put an `O(V)` term in the allowance and falsify `HLR-108`'s `V`-invariance. |
| **`LLR-108.4`** | "each variant's admissions shall be charged against its own reservation" | …**and against the document budget; an admission requires BOTH to fit.** | **P-27 FALSE.** A floored reservation over-subscribes the budget (48.8× CAP at `V=100 000`, floor 1024). |
| **`REPORT_VARIANT_RESERVATION_FLOOR_BYTES`** | undefined | derived from the **measured** 394 B minimal per-variant audit record | C-39 — derived, never chosen. |
| **`REPORT_MAX_TRUNCATION_NOTES`** | "derived from the allowance" | unchanged, and confirmed **inert**: 0 goldens, max 1 note in any existing assertion | **P-17 FALSE.** |

`LLR-108.5` (unconditional per-variant heading) is **unchanged** — P-16's disposition extends its
existing rationale to the header rather than inventing a second mechanism.
