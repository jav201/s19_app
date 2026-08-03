# Phase-2 RE-GATE — ARCHITECT lane — batch `2026-08-01-batch-77`, revision 2

**Under review:** `.dev-flow/2026-08-01-batch-77/01-requirements.md` **revision 2** (548 lines) @ `d33b2ab`
**Prior verdict (rev 1):** BLOCK — 7 blockers, 5 majors, 3 minors (`02-review-architect.md`)
**Method:** R-7 implemented exactly as specified (`LLR-111.9` always-stack · `LLR-111.7` floor-1 + largest-remainder ·
`LLR-111.2` fold=1 · `LLR-111.8` merge-until-fits) and rendered through the shipped surface.
Probes: `scratchpad/arch3_rev2.py`, `arch3_run.py`, `arch3_agg.py`, `arch3_misc.py`. `PYTHONDONTWRITEBYTECODE=1` (C-46).
R1–R9 are **not re-litigated**; findings concern implementation only.

---

## VERDICT: **BLOCK** — 6 blockers, 2 majors, 2 minors.

**Six of my seven rev-1 blockers are genuinely closed, and I verified each by execution, not by reading.**
R-7 works: the container widens 21 → 50, and `prg.s19` fits **exactly** at both regimes with zero aggregation,
as the author reports. I extended the check to **16 shipped fixtures and 9 synthetic classes the author did not
use** — every non-aggregating one passes.

**The corrective pass introduced a new defect cluster, and it is all in the path R-7 added.** `LLR-111.8`
aggregation was designed and validated against a *synthetic* fixture on the stated premise that *"no shipping
fixture reaches the threshold"*. **That premise is false.**
`examples/professional_validation/case_08_heavy_fragmentation/firmware.s19` carries **801 runs** — roughly
**30×** the onset. Executed against it, the aggregation path breaks three of revision 2's own clauses.

---

## 1 · Rev-1 blockers — status, each re-verified by execution

| # | Rev-1 blocker | Status | Executed proof |
|---|---|---|---|
| **B-1** | Design fails `HLR-111` on `prg.s19` | ✅ **CLOSED** for every non-aggregating image | §2.1 — `prg.s19` `Σ=66` into bar 66 and `Σ=50` into bar 50, all visible, monotone, strict, `outside=0`, `agg=0`. **15 of 16 shipped fixtures + 3 synthetic classes pass at both regimes.** Residual failures are confined to the NEW aggregation path → RB-1…RB-4 |
| **B-2** | No normative allocation bound | ✅ **CLOSED** | `LLR-111.7:306` is a `shall not` Statement line. Executed: `Σ widths + Σ markers` equals the bar **exactly** and never exceeds it, on all 25 fixture×size arms. `TC-B77-03:142` now carries an expected result |
| **B-3** | Inc-1a unreachable + regresses 80×24 | ✅ **CLOSED** | §7 Inc-1 is indivisible (basis+bound+fold+settling together). Executed: 80×24 goes `outside 0 → 0`; the rev-1 `[8,8,16,33]` regression cannot occur because no increment lands the basis alone |
| **B-4** | `can_focus` in the wrong increment + duplicate ownership | ✅ **CLOSED** | `LLR-115.1` deleted (`:390`); `LLR-116.1` created under HLR-116 (`:393`); HLR-115's Statement (`:218`) no longer carries a focusability clause — grep confirms exactly **one** normative owner. Inc-7 → Inc-8 (`:517`) |
| **B-5** | C-31 guard FALSE on correct code (runs ≠ ranges) | ⚠️ **HALF-CLOSED — the subject decision is right, the new guard is still FALSE** | §2.2 — subset clause holds everywhere; **coverage clause fails on a shipped fixture** → **RB-1** |
| **B-6** | Header promise FALSE; `[45,15]` is the retired 60-basis | ✅ **CLOSED** (primary) | Sweep of every bracketed integer list in the document (§2.5): 5 hits sum to 60; **4 of 5 are explicitly labelled as the retired/wrong value.** One residue → **Rm-1**. New golden arithmetic → **RM-1** |
| **B-7** | Settle threshold contradicted by its own rationale | ✅ **CLOSED** | §2.4 — the `68 → 68 → 66` trace is retracted and the retraction is correct. 60 fresh rev-2 traces: 13/60 transient first reads, **0 consecutive-equal-at-a-transient**. The pause-counting criterion converges and cannot return a transient |

**Majors:** M-1 (quantifier) ✅ stated normatively at `:125` · M-2 (denominator) ✅ promoted to `LLR-111.1`'s
Statement `:300` · M-3 (census) ✅ 6 → 8, and site 7 (`legend.py:606-614`) is a real find I missed ·
M-4 (backlog) ✅ owned by Inc-5 · M-5 (`AT-B77-02` owner) ✅ Inc-3 owns.
**Minors m-1/m-2** ✅ both ruled on in Amendment C (`:495` reverts the two AC-6 tests to 120×30).

**Author's three self-caught errors — all genuinely repaired, verified independently:**

| Self-caught error | Repaired? | My execution |
|---|---|---|
| F-1(f) glance sweep compared the **title** (11) not the widest **content** row (29) | ✅ | §2.6 — measured rows `11, 29, 17, 1×5`. Title **11**, widest content **29**, exactly as the corrected table says. Under always-stack the box is **50** → no clip, confirming why that candidate alone survives |
| F-1 settle trace mis-stated | ✅ | §2.4 — 0/60 consecutive transients |
| F-1(g) `random.Random(3)` **per byte** made the "random" half constant | ✅ | §2.3 — a single-rng heterogeneous fixture yields **1 range → 3 runs**; P-44 reproduces |

---

## 2 · Executed transcripts

### 2.1 — R-7 verified across 16 shipped fixtures + 9 synthetic classes

CSS widen confirmed: **bar 21 → 50 @120×30; 66 unchanged @80×24** (P-46 ✅).

```
A. SHIPPED examples/ fixtures  (the author used only prg.s19)
 case_00_public/prg.s19 [runs=14]  (80,24)  bar=66 segs=24 cols=66 vis=True monoPAIR=True strict=True bound=True outside=0 cover=True subset=True agg=0  OK
 case_00_public/prg.s19 [runs=14]  (120,30) bar=50 segs=24 cols=50 vis=True monoPAIR=True strict=True bound=True outside=0 cover=True subset=True agg=0  OK
 s19_sample.s19 [runs=2] · case_01 [3] · case_02 [4] · case_03 [2] · case_04 [2] ·
 case_05 [2] · case_06 [3] · case_07 [5] · professional_validation case_01/02/03/04/05/07
   ... all 15 fixtures, both regimes ................................................ OK
 professional_validation/case_08_heavy_fragmentation/firmware.s19 [runs=801]
   (80,24)  bar=66 segs=33 cols=66 vis=True monoPAIR=False strict=True bound=True outside=0 cover=False agg=768 *** FAIL ***
   (120,30) bar=50 segs=25 cols=50 vis=True monoPAIR=False strict=True bound=True outside=0 cover=False agg=776 *** FAIL ***

B. SYNTHETIC
 sparse-5 (batch fixture) [5]  both regimes ......................................... OK
 heterogeneous-1range [3]      both regimes ......................................... OK
 tied-sizes-3 [4]              both regimes ......................................... OK
 many-9 [33] · many-12 [52] @80×24 .................................................. OK
 many-12 [52] @120×30  strict=False agg=13 .......................................... *** FAIL ***
 many-18 [76] both · many-26 [110] both · many-34 [145] both · many-40 [167] both ... *** FAIL ***
```

**`prg.s19` reproduces the author's P-49 byte-for-byte, including `aggregated=0`.** Every failure is in the
aggregation path.

### 2.2 — Why the aggregation path fails (`case_08`, 801 runs, shipped)

```
fixture = examples/professional_validation/case_08_heavy_fragmentation/firmware.s19
  ranges = 801   oracle runs = 801

--- size=(80, 24)  bar=66 ---
  segments: total=33  standalone=0  aggregate=33  (runs inside aggregates=801)
  Q1 monotone using (region_end - region_start) [the only value BandSegment exposes] = False
     monotone using SUM of constituent run bytes                                     = True
     first span-based violation (span,width): ((1988, 2), (2150631108, 1))
  Q2 coverage with rev-2's `if not s.is_aggregate` filter = False  (misses 801 ranges, e.g. ['0x0','0x80300000',...])
     coverage if aggregates are INCLUDED                  = True
  Q4 oracle_runs=801  total_segments=33  standalone=0
     'oracle - TOTAL segments'      = 768
     'oracle - STANDALONE segments' = 801
     runs that lost a dedicated segment = 768

--- size=(120, 30)  bar=50 ---
  segments: total=25  standalone=0  aggregate=25  (runs inside aggregates=801)
  Q1 monotone(span) = False   monotone(sum of run bytes) = True
  Q2 coverage(rev-2 filter) = False (misses 801)      coverage(incl. aggregates) = True
  Q4 'oracle - TOTAL' = 776   'oracle - STANDALONE' = 801   runs that lost a segment = 776
```

### 2.3 — The strictness ceiling

```
1. STRICTNESS CEILING: does 'merge until it fits' kill the strict limb?
  regions=18 runs=76  (80,24)  bar=66 segs=66 distinct widths=[1]    Σ=66 strict=False *** STRICT LIMB DEAD ***
  regions=18 runs=76  (120,30) bar=50 segs=50 distinct widths=[1]    Σ=50 strict=False *** STRICT LIMB DEAD ***
  regions=26 runs=110 (80,24)  bar=66 segs=66 distinct widths=[1]    Σ=66 strict=False *** STRICT LIMB DEAD ***
  regions=26 runs=110 (120,30) bar=50 segs=49 distinct widths=[1,2]  Σ=50 strict=True
```

### 2.4 — Settling under the rev-2 criterion

```
3. SETTLING (LLR-111.6 rev-2): one read per pause, 30 trials/size
  size=(80, 24)   traces={(66,66,66,66,66): 22, (68,66,66,66,66): 8}
      first read != settled: 8/30   consecutive-equal-at-a-TRANSIENT value: 0
  size=(120, 30)  traces={(50,50,50,50,50): 25, (52,50,50,50,50): 5}
      first read != settled: 5/30   consecutive-equal-at-a-TRANSIENT value: 0
```

Note the transient tracks the widen (`52 → 50` where rev 1 saw `23 → 21`) — further confirmation that
`LLR-111.9` is what changed the geometry.

### 2.5 — The 60-basis sweep (every bracketed integer list in the document)

```
   line  list                         sum
     29  [45,15]                      60   <== retired basis — LABELLED as rev-1's error  OK
     29  [50,16]                      66
     88  [21,0]                       21
     95  [1,2,10,...,2]             3968
    320  [3,3,3,3,1]                  13
    328  [30,30]                      60   <== retired basis — NOT labelled            -> Rm-1
    329  [45,15]                      60   <== LABELLED as the wrong value             OK
    331  [50, 16]                     66   \
    332  [38, 12]                     50    >  predicted golden                        -> RM-1
    333  [16,  5]                     21   /
    334  [45, 15]                     60   <== LABELLED "what revision 1 wrongly printed" OK
    514  [8,8,16,33]                  65
    516  [45,15]                      60   <== LABELLED as the rev-1 failure mode      OK
```

### 2.6 — Golden payload, glance rows, `safe_text`, tick elision

```
2. GOLDEN PAYLOAD (LLR-111.4): doc predicts [50,16]@66 and [38,12]@50
  (80, 24)  bar=66   content widths = [49, 17]   sum=66
  (120, 30) bar=50   content widths = [37, 13]   sum=50
  plain proportional round(bar*768/1024), round(bar*256/1024):
      bar=66 -> [50,16]        bar=50 -> [38,12]      <- what the document prints
  LLR-111.7 rationale (floor 1 + largest remainder):
      bar=66 -> [49, 17]       bar=50 -> [37, 13]     <- what LLR-111.7 produces

4. P-47 glance widest CONTENT row      glance box width = 50
      len=11  'At a glance'                          <- the value the broken sweep used
      len=29  '· constant/padding 3 ████ 60%'        <- the widest CONTENT row
      len=17  '▒ medium 2 ██ 40%'
   widest content row = 29 -> clips in a 50-col box: False

5. P-51 safe_text('sensor\x1b[31m_evil[red]')
      ESC survives: True   '[red]' literal: True   spans: []   len(plain)=21 for 16 visible chars
   P-52: N ticks of 1fr in W=50
      N=20 -> 2 cols/tick (8-char label needs 8): elided=True
      N=60 -> 0 cols/tick: elided=True
```

P-51 and P-52 both reproduce exactly. The security-lane findings folded into `LLR-116.6` and `LLR-112.2`
are sound.

### 2.7 — `AT-B77-02`'s prescribed mutation

```
AT-B77-02 mutation check: LLR-111.5 prescribes
  "substitute the fold denominator into the gapless path"
The fixture is GAPLESS -> n_gaps = 0 -> avail = bar_w - 0*fold, for ANY fold.

  FOLD=1    golden payload = [(band-constant, 49), (band-medium, 17)]   identical to FOLD=1: True
  FOLD=2    golden payload = [(band-constant, 49), (band-medium, 17)]   identical to FOLD=1: True
  FOLD=5    golden payload = [(band-constant, 49), (band-medium, 17)]   identical to FOLD=1: True
  FOLD=60   golden payload = [(band-constant, 49), (band-medium, 17)]   identical to FOLD=1: True
```

---

## 3 · BLOCKERS

### RB-1 — The C-31 coverage guard is FALSE on correct code. **Arch B-5, reintroduced in a new form.**

**Where:** `01-requirements.md:133-140`.
```
emitted  = {(s.region_start, s.region_end) for s in query(BandSegment) if not s.is_aggregate}
assert all(any(a <= rs < b for a, b in emitted) for rs, _ in loaded.ranges)   # coverage
```
**Evidence:** §2.2 Q2. On `case_08` every segment is an aggregate, so `emitted` is **empty** and the coverage
clause misses **all 801 ranges** at both regimes. Including aggregates → **True**.

The set is filtered to exclude aggregates, then the universal is quantified over **all** ranges. Those two
choices are incompatible. Line 140 asserts the opposite in the same block: *"Subset (not equality) admits
aggregation; the coverage clause is what stops an implementation silently dropping a region."* The **subset**
clause admits aggregation; the **coverage** clause does not.

This is the same shape as rev-1's B-5 — a guard that is only true of a fixture the author happened to use —
and it landed inside the correction written to close B-5.

**Fix:** evaluate coverage over **all** emitted segments (aggregates included); keep the aggregate exclusion
on the *subset* clause only, where it is correct.

### RB-2 — `HLR-111`'s monotonicity clause has no obtainable subject value for an aggregate segment

**Where:** `:124` (*"visible widths non-decreasing in mapped bytes"*), `:125` (∀ over emitted run segments),
`:53` (aggregate definition), `LLR-111.8:312`.
**Evidence:** §2.2 Q1. On `case_08`, monotonicity computed from `region_end − region_start` — the **only**
size value `BandSegment` carries (`screens_directionb.py:1218-1229`) — is **False** at both regimes. Computed
from the sum of constituent run bytes it is **True**. The violating pair is `(span 1 988, width 2)` versus
`(span 2 150 631 108, width 1)`.

For a **run** segment, address span == mapped bytes. For an **aggregate** they diverge by six orders of
magnitude, because the aggregate spans the unmapped gaps it swallowed. Revision 2 introduced aggregates and
never defined their mapped-byte observable, and `LLR-111.8` adds no attribute to carry it. `AT-B77-01`
therefore has no way to evaluate its own clause on the aggregation path.

**Fix:** `LLR-111.8` must require the aggregate segment to carry its summed mapped bytes as an observable
(the natural companion to the `n_runs` count `AT-B77-17` already needs), and `HLR-111` must name that value
as the monotonicity subject.

### RB-3 — `LLR-111.8`'s stopping rule terminates exactly where `HLR-111`'s strict-∃ clause dies

**Where:** `LLR-111.8:312` (*"merge … until the allocation fits"*) versus `HLR-111:124` (*"shall emit at least
one strictly greater pair whenever two emitted run segments differ in mapped size"*).
**Evidence:** §2.3. Merging stops at the first configuration satisfying `n_segments + n_gaps ≤ bar_width` —
which is the configuration where **every segment is exactly 1 column**. Executed: 18 regions → 76 runs →
`bar=66, segs=66, distinct widths=[1], strict=False`; `bar=50, segs=50, distinct widths=[1], strict=False`.
Same at 26 regions @80×24.

`AT-B77-01` would be **RED on code that conforms to the specification**. Whether the strict limb survives is
decided by whether the merge loop happens to overshoot — `many-26 @120×30` lands at `segs=49 < bar=50` and
survives with widths `[1,2]`; `many-18` lands exactly on the bound and does not. A gate whose verdict depends
on that parity is not a gate.

**Fix:** either give `LLR-111.8` a stopping rule with headroom (merge until the allocation fits **and at least
one strictly greater pair exists**), or scope `HLR-111`'s strict clause to renders where no aggregation
occurred, and say so normatively.

### RB-4 — `AT-B77-17`'s exact-count formula: the label contradicts the arithmetic

**Where:** `:151` — *"stated count **equals** `oracle_runs − non_aggregate_segments_emitted`"*, worked as
`bar=66 → 35 − 33 = 2` · `bar=50 → 35 − 25 = 10`. `LLR-111.8:312` defines the quantity as *"the exact number
of runs that lost their own segment"*; `LLR-111.8:316` repeats the formula.
**Evidence:** §2.2 Q4. On `case_08` @80×24: `oracle = 801`, **non-aggregate (standalone) segments = 0**,
**total segments = 33**.

| Reading | Value @80×24 | Value @120×30 |
|---|---|---|
| literal — `oracle − non_aggregate` | **801** | **801** |
| `oracle − TOTAL segments` | **768** | **776** |
| runs that lost a dedicated segment | **768** | **776** |

The author's own worked numbers (`35 − 33`, `35 − 25`) use **TOTAL** segments, so the intended quantity is
right and the **label is wrong**. R-9 mandates an **exact** count and `AT-B77-17` asserts the integer as its
whole claim — a gate that asserts a differently-defined integer than the LLR it discharges is not exact.
The two readings differ by 33 and 25 on a fixture already in the repo.

**Fix:** state the subtrahend as *total emitted band segments* (or define the count directly as
`Σ(n_runs − 1)` over aggregates) and re-derive the two worked values.

### RB-5 — `AT-B77-02` is a PIN whose only prescribed falsifiability discharge is a provable no-op

**Where:** `LLR-111.5:346` — *"substitute the fold denominator into the gapless path"*, status
*"🔶 PIN; gate via the post-Inc-3 mutation"*. §9 `:544` records it as *"gated by a post-Inc-3 mutation"*.
**Evidence:** §2.7. The fixture is **gapless** by construction (`LLR-111.4:327-328`), so `n_gaps = 0` and
`avail = bar_w − 0·fold` for **any** fold. Executed at fold 1, 2, 5 and 60 — the golden payload is
**byte-identical** in all four.

The mutation cannot redden the node. `AT-B77-02` therefore has **no** discharge, and §9's checklist entry
claiming otherwise is false. Revision 2 correctly flagged this same defect class elsewhere ("a prediction
wearing a discharge mark") and then left it standing here.

**Fix:** name a mutation that can actually fire on a gapless render — e.g. substitute the allocator's
denominator (mapped bytes → address span) or its basis (container → `_BAND_BAR_WIDTH`), both of which move
`[49,17]`.

### RB-6 — The premise that justifies the synthetic `AT-B77-17` fixture is FALSE, and it is why the whole aggregation path went untested

**Where:** `:146-148` — *"(no shipping fixture reaches the threshold; `prg.s19` is 14 runs, and the onset is
26 @bar=50 / 34 @bar=66, so a synthetic fixture is **required**, not a convenience)"*.
**Evidence:** §2.1/§2.2. `examples/professional_validation/case_08_heavy_fragmentation/firmware.s19` has
**801 ranges and 801 runs** — about **30×** the onset, at both regimes.

The claim is truth-apt and false. Its consequence is RB-1, RB-2 and RB-3: aggregation was validated only
against a fixture the author constructed, so every clause that only breaks on a real fragmented image
survived Phase 1 intact. This is the precise failure mode my rev-1 B-1 identified — validation on one
fixture — recurring one revision later on the newly added path.

**Fix:** `AT-B77-17` and the aggregation boundary cases must run against `case_08` as well as the synthetic
fixture, and the parenthetical must be corrected.

---

## 4 · MAJORS

### RM-1 — `LLR-111.4`'s predicted golden is computed with the allocator `LLR-111.7` exists to forbid

**Where:** `:329-336`. Predicted `bar=66 → [50,16]`, `bar=50 → [38,12]`.
**Evidence:** §2.6. Those are plain `round(bar · b / total)`. Under `LLR-111.7`'s own stated allocator (floor
1 per run + largest remainder, `:307`) the executed values are **`[49,17]`** and **`[37,13]`**.

Both sum to the bar, so both satisfy the normative bound — but the document states these numbers exist
*"only so a wrong capture is recognisable"* (`:336`), and as printed they would flag a **correct** capture as
wrong. This is the same defect class as B-6 (a payload computed on superseded arithmetic), in the same LLR,
one revision later. The `predicted` label is honest about *when* it was computed; it is not honest about
*which allocator* computed it.

### RM-2 — `AT-B77-09` is labelled "the GATE" but is structurally a PIN

**Where:** `:223` (*"`AT-B77-09` *(the GATE)*"*), `:431` (*"RED-able only after Inc-7"*), `:544`.
`RegionRow.BINDINGS` is `[]` today and stays `[]` after the change (`LLR-115.4:389` forbids `j`/`k`/`o`), so
the predicate is GREEN before **and** after. Its only falsification is the mutation the document itself
names — *"if someone adds `Binding("k", …)` to `RegionRow.BINDINGS`"*.

That is a legitimate mutation-discharged control, and the focus-ON-row distinction from `AT-B77-16` is a real
and good catch. But "RED-able only after Inc-7" implies it will eventually be demonstrated RED, and it will
not. Label it a PIN with a named mutation, exactly as `AT-B77-02` is labelled, so the §9 checklist reflects
what will actually be produced.

---

## 5 · MINORS

**Rm-1 — one unlabelled 60-basis residue.** `:328`: *"`EQUAL 512/512 → [30,30]` at both regimes"*. `30+30 = 60`,
the retired constant; under R-7 the container is 66 @80×24 and 50 @120×30, so an equal gapless fixture yields
`[33,33]` and `[25,25]` — **not** the same at both regimes. The *vacuity argument* is basis-independent and
survives intact; only the number and the "at both regimes" phrase are stale. Three lines above the block
corrected for exactly this.

**Rm-2 — "non-decreasing in mapped bytes" read as a function fails on ties.** Largest-remainder gives
equal-byte runs unequal widths. Executed: `tied-sizes-3 @120×30` and `many-9 @80×24` both show
`monoPAIR=True, monoFN=False`. The ⭐ note at `:125` (∀ over *ordered* pairs) resolves it correctly, but the
Statement's prose at `:124` reads as a function. Align the two.

---

## 6 · Premise evaluation (C-43) — revision 2

| # | Proposition | Verdict | Basis |
|---|---|---|---|
| P-46 | CSS can widen the bar to 50 @120×30, 66 unchanged @80×24 | ✅ **TRUE** | §2.1 |
| P-47 | Widest glance content row is 29; shrinking starves it | ✅ **TRUE** | §2.6 |
| P-48 | Widening alone is insufficient | ✅ **TRUE** | rev-1 §2.4 + §2.1 |
| P-49 | Bounded allocator satisfies `prg.s19` at both regimes, zero aggregation | ✅ **TRUE, byte-for-byte** | §2.1 |
| P-44 | One range can yield ≥2 runs | ✅ **TRUE** | §2.1 heterogeneous fixture → 1 range, 3 runs |
| P-45 | The `68 → 68 → 66` trace was mis-stated | ✅ **TRUE — retraction correct** | §2.4, 0/60 |
| P-51 | `safe_text`'s ANSI docstring claim is false | ✅ **TRUE** | §2.6 |
| P-52 | rev-1's overlap predicate was vacuous | ✅ **TRUE** | §2.6 |
| P-53 | 8 citation sites, not 6 | ✅ **TRUE** | verified rev-1 §2.6 + `legend.py:606-614` |
| — | *"No shipping fixture reaches the aggregation threshold"* (`:147`) | ❌ **FALSE** | `case_08` = 801 runs → **RB-6** |
| — | Coverage guard is true on correct code | ❌ **FALSE** | §2.2 Q2 → **RB-1** |
| — | `HLR-111` monotonicity is evaluable on aggregates | ❌ **FALSE** | §2.2 Q1 → **RB-2** |
| — | `HLR-111` strict-∃ is satisfiable under `LLR-111.8` | ❌ **FALSE** | §2.3 → **RB-3** |
| — | `AT-B77-17`'s formula computes "runs that lost their own segment" | ❌ **FALSE** | §2.2 Q4 → **RB-4** |
| — | `AT-B77-02` is gated by its post-Inc-3 mutation | ❌ **FALSE** | §2.7 → **RB-5** |
| — | `LLR-111.4`'s predicted payload matches `LLR-111.7`'s allocator | ❌ **FALSE** | §2.6 → **RM-1** |
| — | `HLR-111…117` namespace clean | ✅ **TRUE** | re-verified, 0 hits outside batch-77 |
| — | `should`/`debería` absent from Statements | ✅ **TRUE** | 0 hits |

---

## 7 · What I am NOT flagging

- **R-7 itself.** The two-part structure (widen, then bound) is correct and the evidence for it is strong.
  Widening alone genuinely does not fix `prg.s19`; the bound genuinely does. I reproduced both.
- **The RUNS-vs-RANGES subject decision** (§2.9). Right call, well argued, and the `_merge_band_runs` oracle
  really is independent of `_build_band_widgets`'s allocation. Only the coverage *expression* is wrong.
- **The R-8 / R-9 implementations.** The stats-line cost note is accurate (`bottom=31/30 → 33/30`), and R-9's
  region-list surface is correctly made normative in `LLR-111.8`'s Statement and named in `AT-B77-17`'s
  Given/When/Then. Only the count *formula* is wrong (RB-4), not the surface.
- **`LLR-116.5` liveness, `LLR-116.6` hostile input, `LLR-112.2` elision.** All three are genuine finds from
  the peer lanes, correctly folded, and I reproduced the underlying facts.
- **The withdrawal of rev-1's `test_tc041_9` vacuity claim** (`:202-207`). Correct and well-reasoned; I had
  not checked it and the withdrawal is right.
- **§9's honesty about partial discharge.** Marking the C-40 row ⚠️ *partial, and LABELLED* is the correct
  behaviour. RB-5 is that one of the two labelled exceptions is unachievable, not that labelling was wrong.

---

## 8 · Recommended disposition

**One more bounded revision.** Every blocker is in the aggregation path and none reopens a ruling.

| Blocker | Cost | Change |
|---|---|---|
| RB-1 | trivial | Evaluate coverage over **all** emitted segments; keep the aggregate filter on the subset clause only |
| RB-4 | trivial | Subtrahend = total emitted band segments (or `Σ(n_runs−1)`); re-derive `35−33` / `35−25` |
| RB-5 | trivial | Name a mutation that fires on a gapless render (denominator or basis, not fold) |
| RB-6 | trivial | Correct the parenthetical; add `case_08` to `AT-B77-17` and the aggregation boundary cases |
| RM-1 | trivial | Re-derive the predicted golden with `LLR-111.7`'s allocator: `[49,17]` / `[37,13]` |
| RM-2 | trivial | Relabel `AT-B77-09` a PIN with its named mutation |
| **RB-2** | **small** | `LLR-111.8` must make the aggregate carry its summed mapped bytes; `HLR-111` names it as the monotonicity subject |
| **RB-3** | **small** | Give `LLR-111.8` a stopping rule with headroom, **or** scope `HLR-111`'s strict clause to non-aggregating renders — normatively, either way |

No operator ruling is implicated. RB-2 and RB-3 are the only two requiring a design sentence rather than an
edit, and both are internal to `LLR-111.8`, which revision 2 authored from scratch.

---

## 9 · Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Each rev-1 blocker re-verified **by execution**, not by reading the text | ✓ | §1 table, each row cites a transcript |
| Design re-executed on `prg.s19` | ✓ | §2.1 — fits exactly, both regimes, zero aggregation |
| Design executed on fixtures the author did **not** use | ✓ | §2.1 — 15 further shipped fixtures + 9 synthetic classes |
| Hunted defects the corrective pass introduced | ✓ | RB-1…RB-6, RM-1, all in the R-7 path |
| `TC-B77-03` now carries an expected result | ✓ | `:142`, verified |
| `LLR-111.7` is normative | ✓ | `:306`, a `shall not` Statement line |
| 80×24 does not go GREEN→RED at any increment boundary | ✓ | §1 B-3 row; Inc-1 indivisible |
| `can_focus` ownership single and correctly ordered | ✓ | grep §1 B-4 row |
| Whole-document 60-basis sweep | ✓ | §2.5, 13 lists checked |
| Settling threshold cannot return a transient | ✓ | §2.4, 0/60 |
| The two undischarged acceptances checked for label honesty | ✓ | RB-5 (`AT-B77-02`, dishonest by consequence), RM-2 (`AT-B77-09`, mislabelled) |
| Author's three self-caught errors verified repaired | ✓ | §1 table |
| Nothing manufactured | ✓ | §7 lists what I checked and found sound, including things I had missed in rev 1 |
| No operator ruling re-litigated | ✓ | §7, §8 |
