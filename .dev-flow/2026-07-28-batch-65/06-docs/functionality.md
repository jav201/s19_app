# batch-65 — functional description

**Audience:** a technical stakeholder — engineer, reviewer, or maintainer — who did not live this
batch. **Purpose:** understand what changed in the report generator, what it now guarantees, and
precisely what it still does not.

---

## The defect, in plain terms

**Generating a project report over declared memory regions could exhaust the host's RAM before a
single byte of the report was written.**

The s19tool project report can carry an *addendum*: for each memory region the operator declares
(*"the calibration area is `0x1000-0x9000`"*), it lists every modification and every validation issue
whose address falls inside that region, across all variants. The function that builds it,
`report_service._addendum_lines`, was shaped like this:

```
for region in declared_regions:            # R
    for variant in variant_results:        # V
        for entry / issue in that variant: # E
            if region.contains(address):
                hits.append(fully_formatted_markdown_line)   # <- allocation
lines.extend(hits)                         # <- the FIRST output, after ALL the cost
```

Three things about that shape mattered, and only the third one is obvious:

1. **The candidate set was re-read once per declared region.** Ten regions meant ten full passes over
   every entry and every issue of every variant.
2. **Every match was materialised as a finished, escaped Markdown string** — one `md_safe` call each —
   and held in a list.
3. **All of it was paid before any output existed.** The report generator already has a byte budget
   (`_ByteBudget`) that caps the emitted document. It was structurally incapable of reaching this
   cost, because the budget only sees lines that have been handed to it, and the entire list was
   built first.

Measured on the pre-fix producer: **86.5–93.9 bytes resident per hit**, with the product law confirmed
independently on all three axes — roughly `×2` per doubling of `R`, of `V`, and of `E`. Every one of
those axes is document-derived: the change document supplies the entries and the issues, so an
attacker (or simply a very large legitimate change set) chooses `V` and `E`. This is the most likely
cause of the host RAM exhaustion that ended an earlier batch's session.

It was carried as backlog item **D1**. It was specified during batch-63, **blocked at that batch's
Phase-2 re-gate**, and returned. batch-65 started from that blocked record rather than re-deriving it.

---

## The fix

**One pass over the candidates, region identity resolved by binary search, and a hard admission cap
per (region, hit class) whose every firing is announced in the document.**

### 1. The loops are inverted, and the region loop is gone from the hot path

```
build a coalesced, disjoint, half-open cover of the declared regions   # once
for variant in variant_results:            # V — OUTERMOST, deliberately
    for entry / issue in that variant:     # E
        if address is outside the coalesced cover:   continue   # O(log R) sound reject
        for each matching region index:                          # attribution walk
            admit into that region's ordered hit list, or count it as dropped
emit per region: heading, hits, one notice per class whose cap fired
```

`variant_results` stays the **outermost** loop and that is load-bearing, not incidental: it is what
makes each variant's dropped hits contiguous, which in turn lets the `+N more` remainder be counted
with an `O(1)` last-seen sentinel instead of an `O(V)` membership set.

Executed result on the candidate axis: **candidate consumption `19200 → 300`** at `R = 64` over
`N = 300` candidates. The count is now equal to `N` at every `R`, in every geometry tested.

### 2. Region membership: `range_index` as a reject filter, `bisect` for identity

The obvious primitive — `s19_app/range_index.py`, the repo's designated "many addresses against many
ranges" module — turned out to be usable only in part. Two lanes and the orchestrator independently
confirmed the same two facts:

- it is **boolean-only**: it answers *whether* an address falls in any range, never *which*; and
- it is **unsound over overlapping ranges** — it inspects a single `bisect_right` candidate, so an
  address inside an enclosing region but past a nested region's end answers `False`.

Declared regions **do** overlap, and nothing constrains them not to. `range_index.py` is also
engine-frozen. So the shipped design **consumes it, never modifies it**, and only in the one role
where it is sound: as a fast reject pre-filter over a **coalesced** (merged, disjoint, half-open)
cover. Region *identity* is recovered by a caller-local `bisect` plus a **prefix-max array** over the
region ends, which is overlap-safe. The coalescing step reuses `report_filter._merge_ranges`, the
in-repo precedent.

Correctness of that attribution was not argued — it was swept. The increment reviewer re-derived it
independently of the Phase-2 lanes: **30 855 exhaustive geometries + 3 000 randomized + 15 hand-built,
comparing caller-index lists, 0 mismatches.**

### 3. One ordered hit list per region, and three admission counters

The natural implementation — three per-class buckets, concatenated at emit time — was **rejected on
executed evidence**: the shipped emission order interleaves modifications and change-file issues per
summary (`mod, issue, mod, issue`), and bucket concatenation emits `mod, mod, issue, issue`. That
would have broken byte identity below the cap.

What ships instead is **one ordered hit list per region plus three admission counters**. A hit is
admitted while its class's counter is below `MAX_ADDENDUM_HITS_PER_CLASS_PER_REGION = 200`; otherwise
it is counted as dropped and its variant id recorded. Because admission never re-orders and never
evicts, the admitted sequence is a **subsequence of the shipped sequence by construction** — byte
identity below the cap is a structural property, not a test result that happened to hold.

Verified anyway: **6/6 fixture shapes byte-identical to the golden, 0 differing bytes**, with the
golden captured from the *pre-fix* producer at Inc-1 before any production code was touched.

### 4. The truncation notice — the part that is a feature, not an optimisation

A cap that silently drops evidence turns an evidentiary document into a misleading one. batch-63's
own acceptance test for this (`AT-165`, *"every producing hit class is represented"*) was **green
through all three attacks** while the operator-relevant collision was being evicted — it tested the
shape of the concatenation, not the evidence.

So the cap is paired with a notice, emitted **inside the sub-section of the region whose cap fired**:

```
> TRUNCATED: {label} hits in this region were capped at {cap}; {dropped} more not listed (variants affected: {variants}).
```

with `{label}` drawn from `ADDENDUM_CLASS_LABELS`, and `{variants}` naming up to
`ADDENDUM_NOTICE_VARIANTS_MAX = 8` ids followed by `+N more`. The predicate the acceptance tests
assert is deliberately strict in three ways that a weaker one would have passed:

- the variant set is **set equality**, not containment. A mutant that names every variant that
  *contributed* to the cut class rather than every variant whose hits were *dropped* passes a
  containment check while telling the operator that the flooding variant lost evidence it did not
  lose. That mutant (`FIX-H`) is a named RED arm.
- a class that lost nothing is **never named** (`AT-201`), and a variant that lost nothing is
  **never named** (`AT-202`). These are separate nodes because the class-level control does **not**
  cover the variant-level case — executed.
- the notice must sit under the **flooded** region's sub-section (`AT-203`). A mutant that emits
  every notice under the *first* region passes the other notice tests while pointing the operator at
  the wrong region.

The notice text is document-derived, so it is a new Markdown sink: it runs through the same `md_safe`
escaper as the hit lines (`TC-495` asserts *rendering equality*, not merely "no escape artefacts"),
and a forged `> TRUNCATED` in an issue code produces one notice, not two (`AT-199`).

### 5. Counting the notices is addendum-scoped

The report already had **three** pre-existing `> TRUNCATED:` emitters on unrelated axes. Every notice
predicate therefore counts only lines matching the addendum's own format, **between the
`## Addendum: declared regions` heading and the next `## ` heading _or end-of-file, whichever comes
first_** — and the scope helper **fails the test when the scope is empty**. Both clauses are
load-bearing: the addendum is the *last* `## ` section of a report, so a scope rule with no EOF arm
finds no scope at all and reads zero notices on every report, which would have made seven acceptance
tests permanently, silently vacuous. `TC-499` is the positive control: a report where the pre-existing
emitter fires and no addendum cap does must read **0** addendum notices.

---

## What it does **NOT** do

This section is the point of the document. The batch's own post-mortem verdict is *"the design was
right and the document kept outrunning it"* — roughly a quarter of the sixty-one findings raised
across six reviews were the specification asserting a property the system does not have. The
requirement as shipped carries a six-part "does NOT claim" paragraph, and each part below carries the
number that was executed for it.

### It does not close the memory-exhaustion DoS

`_modifications_lines` and `_checklist_lines` — the report's modifications and checklist tables —
remain **completely uncapped**, at a measured **988 bytes per entry**. That is roughly **11×** the
addendum's 86.5–93.9 B/hit, and unlike the addendum they still scale with the candidate count. At
ordinary region and variant counts **they dominate**: ~99 MB for one change document at
`MF_ENTRY_COUNT_CEILING = 100 000`, ~6.3 GB at 8 documents × 8 variants.

The report's whole-document peak with `declared_regions=()` — i.e. with the addendum switched off
entirely — still grows **×1.68 per `E`-doubling and ×1.81 per `V`-doubling** on one lane's fixture,
**×1.94** on a second, **×1.77** on a third. Three fixtures, three figures, deliberately **not
averaged**.

The practical consequence: **any acceptance keyed to `generate_project_report`'s whole-report peak is
unsatisfiable today.** That is why `AT-194` measures the *marginal* delta attributable to the addendum
(regions vs no regions, same fixture) rather than the total. This axis was already a backlog item
before this batch (OB-4 / F4) and **stays one**. It is now the top of the code lane on merit.

### It bounds candidate consumption, never total work — the `R` multiplier is relocated, not removed

The single pass is `R`-independent in *how many candidates it looks at*. It is **not** `R`-independent
in *how much work it does*. Recovering region identity for a candidate that lies inside an enclosing
region costs `O(R)` in the worst case, because the attribution structure is a prefix-max array.

Executed under the `huge+tiny` geometry — one enclosing region plus `R−1` narrow ones, which is
exactly how an operator declares *"the whole calibration area, plus these named sub-blocks"* — with
500 candidates producing **one** hit:

| `R` | 1 | 8 | 64 | 256 |
|---|---|---|---|---|
| candidates consumed | 500 | 500 | 500 | 500 |
| **region ops** | **500** | **4 000** | **32 000** | **128 000** |
| hits produced | 1 | 1 | 1 | 1 |

A second lane reproduced the same law on its own fixture: **19 200 region ops at `R = 64`** — which is
*bit-for-bit the number this batch elsewhere prints as the defect being removed on the candidate
axis*. `TC-498` pins `A == R × N` as a **disclosure counter with a recorded value, not a pass/fail
bound**: no constant `c` exists for a bound of the form `A ≤ c × (N + hits)`, because under this
geometry the output is `R`-independent while `A` grows without limit in `R`, and a gate that cannot
pass is the same defect class as one that cannot fail.

This is a real, uncapped cost property of the shipped design, filed as a disclosed residual because
the batch chose scope discipline over closure. A max-segment-tree over the region ends would remove it
at `O((1+k) log R)`; it was proposed, priced, and declined as *"real complexity added to a function
whose whole point is to get simpler."* The reversal is prepared for in writing.

### `B-3(b)` is reduced from `R×V×E` to `V×E`, not eliminated

The single `V×E` pass survives and is **not removable** while the notice is obliged to state a
dropped count. `summary.entries`, `summary.issues` and `check.issues` are unsorted lists with no
address index — a candidate that has not been looked at cannot be classified, so it cannot be counted
as dropped. A region matching *nothing* no longer pays `R` passes, but it still pays one. Closing it
further requires the change-apply and check engines to emit address-sorted candidate sets, which is a
producer-side change in a different module and a different batch.

### The addendum's resident cost is not independent of `R`

It is `O(R × 3K)` by construction, and **`R` has no cardinality cap anywhere in the codebase**. The
only related constant, `DECLARED_REGION_NAME_MAX = 80`, bounds a region's *name*, not the region
*count*. Measured: **≈ 11.6 kB per region** with no cap firing, rising to **≈ 20 kB per region** with
all three caps firing at the variant limit with worst-case escaped ids. Both are **lower bounds**.
`R` is operator-supplied rather than attacker-supplied, so the exposure is self-inflicted rather than
hostile — but it is real, and it multiplies both the resident term and the work term above. A
`MAX_DECLARED_REGIONS` mirroring the existing `REPORT_MAX_REGIONS_PER_VARIANT = 128` would bound both
in one change; it is carried, not shipped.

### Eviction is disclosed, not prevented

`K` is a **first-`K`-in-document-order** cut inside each class, and all three hit classes are
document-derived — the attacker authors the order. 200 crafted warnings can still push a genuine
error-severity collision out of the addendum. The notice makes that *visible*; it does not make it
*not happen*.

Two things keep this from being worse than it reads, and both are stated because an earlier revision
of the specification **overstated the harm**:

- a hit evicted from the *addendum* is not thereby removed from the *report* — the per-variant issue
  renderer still emits it under its own separate `MAX_REPORT_ISSUES_PER_VARIANT = 200` cap. The
  genuinely-lost case is a flood and a collision in the *same* variant past *both* caps, where two
  notices fire and **neither names a severity**. What is suppressed is the severity *signal*, not the
  evidence's existence.
- prevention was priced and declined in writing. Severity-priority admission would let an
  already-admitted hit be evicted later, which destroys per-variant contiguity and turns the `O(1)`
  remainder sentinel into an `O(V)` membership set — prevention on the severity axis costs the
  `V`-independence claim on the memory axis. Separately, a dropped-severity histogram was rejected
  because the field **does not exist** for one of the three hit classes.

### The notice does not name every affected variant

Above `ADDENDUM_NOTICE_VARIANTS_MAX = 8` it states **how many** further distinct variants were
affected, not **which**: 20 affected variants render as `v1, v2, …, v8, +12 more`. For the unnamed
ones the operator keeps exactly the ambiguity the story exists to remove. The cap is nonetheless
*required* — an uncapped list is `O(V)` resident and puts the variant count straight back into the
bound the change exists to establish. The `+N more` count itself is exact; only the enumeration is
bounded.

### Two more, smaller

- The addendum's notice does **not** reach the report's `## Truncation appendix`; that channel is fed
  by a different emitter and unifying them is a module-wide change.
- `range_index.py`'s unsoundness over overlapping ranges is **worked around, not fixed** — the module
  is frozen and untouched. The same one-candidate-bisect shape was found live in
  `changes/apply.py::_linkage_index`, where it is a genuine defect on shipped, operator-visible
  linkage output; unfreezing `range_index.py` would **not** repair it. Carried as a new Lane-A item.

---

## Operator-visible effect

- A report over declared regions that stays below the cap is **byte-for-byte the document it was
  before** — 6/6 shapes, 0 differing bytes, 0 goldens re-baselined.
- Above the cap, each affected region's sub-section gains one `> TRUNCATED:` line per cut class,
  naming the class, the number dropped, and the variants that lost evidence. It appears in the
  written file **and** in the report viewer.
- Nothing else about the report's content, ordering, or file layout changes.

---

## Verification, in one block

| | |
|---|---|
| production change | **2 files, +570 / −35** (`report_service.py` +565/−33 · `report_addendum.py` +5/−2, docstring only) |
| tests | `2201 → 2233` (+32) · 0 deleted · 0 regressions |
| final suite | `2233 passed · 2 skipped · 21 deselected · 3 xfailed` in `1659.77 s` · 29 snapshots · **exit 0** |
| byte identity | 6/6 shapes, **0 differing bytes**; **0 goldens re-baselined** |
| attribution correctness | 30 855 exhaustive + 3 000 randomized + 15 hand-built geometries, **0 mismatches**; plus 4 000 randomized below-bound fixtures against a verbatim transcription of the old producer, **exact line equality** |
| frozen engine | **0 diff** across all seven frozen paths — `range_index.py` consumed, never modified |
| traceability | **0 gaps**, both directions · Layer A 19/19 · Layer B 9/9 · C-18 9/9 REALIZED |
| reviews | 6 independent Phase-2 reviews + 2 increment code reviews + 1 Phase-4 validation · **61 findings** · **0 correctness defects in the shipped producer** |
| security lane | cleared **unconditionally**, 6/6 findings CLOSED — the first unconditional pass in several batches, and the requirement's refusal to claim DoS closure is what bought it |
