# batch-77 — Phase-2 QA RE-GATE of requirements revision 2

**Batch:** `2026-08-01-batch-77` · **Branch:** `claude/batch-77-memmap-variant-a` @ `d33b2ab`
**Under re-review:** `.dev-flow/2026-08-01-batch-77/01-requirements.md` **revision 2** (548 lines, was 578)
**Prior gate:** `02-review-qa.md` — 4 blockers · 5 majors · 8 minors → BLOCK
**Method:** every verdict below is **executed**, not read. Inc-1 and Inc-7 were implemented from the LLR text in an isolated copy of `s19_app/` and mutated there under `PYTHONDONTWRITEBYTECODE=1` (C-46). Working tree proven untouched by hash at both ends:
`screens_directionb.py` = `b11fdfcd25c52bf2fdd4d1e40272d9fa` · `styles.tcss` = `b60b1caef924e912dee914872b131f85` — unchanged before and after; `git status` clean of source changes.
**R-7/R-8/R-9 are settled** and reviewed for correct implementation only.

---

## BLUF

**All four of my revision-1 blockers are DISCHARGED BY EXECUTION. One new blocker, 3 majors, 4 minors.**

The corrective pass is genuinely good — B-2 and B-3 are not merely re-worded, they are *provably* fixed: I implemented the LLRs and the gates now pass, and the liveness clause reddens the exact defect it was written for. But the coordinator's warning was correct: **the fix for B-1 reproduced B-1's own defect class one layer along.**

| # | Sev | Finding | Executed evidence |
|---|---|---|---|
| **N-1** | 🔴 | **The re-authored C-31 coverage clause is FALSE on a correctly-*aggregating* implementation** — the same "guard false on correct code" shape as rev-1 B-1, relocated into its fix | 2 ranges → 1 aggregate → `emitted` empty → coverage `False`; on a 26-region fixture, **10** uncovered range starts @bar=66, **15** @bar=50 |
| **M-1** | 🟠 | `AT-B77-17`'s `bar=66 → 35−33 = 2` **contradicts the same callout's** "aggregation is not required at 80×24" | `35+25 = 60 ≤ 66` → aggregation does not fire → disclosure must be **0**. Aggregation ends up exercised at **one arm only** |
| **M-2** | 🟠 | R-9's **exactness** limb has **no executed falsification**, inside a row marked ✅ executed | of the two mutations named, only "remove the bound" is discharged by the pre-change state |
| **M-3** | 🟠 | **`AT-B77-10` has no owning increment** (C-21); M-5 acknowledged in prose but not structurally fixed | §7 gates name **16 of 17** ATs |

**Rev-1 blockers — all four discharged:**

| Rev-1 | Verdict | Proof |
|---|---|---|
| **B-1** runs-vs-ranges | ✅ **DISCHARGED** | rev-2 guard `TRUE`, rev-1 guard `FALSE`, on a fixture I proved genuinely heterogeneous (3 bands, 1 range → 4 runs) |
| **B-2** Inc-1 unsatisfiable | ✅ **DISCHARGED** | Inc-1 implemented as specced → gate GREEN on **3 fixtures × 2 arms**, `prg.s19` included; **no regime regresses** |
| **B-3** focus on a detached widget | ✅ **DISCHARGED, and it is a real gate** | the `sync` variant (rev-1's exact defect) is **RED on all three arms**; `correct` is GREEN on all three |
| **B-4** `AT-B77-09` untestable state | ✅ **DISCHARGED**, label honest | gate arm moved to focus-ON-row; PIN split to `AT-B77-16`. One residual (m-1) |

**Rev-1 majors: M-2, M-3, M-4 and the M-1 discharge-marking are all correctly fixed** (details in §3). The footer ~181-columns figure was adopted into §2.2.

---

## 1 · NEW BLOCKER

### N-1 🔴 The re-authored completeness guard is FALSE on a correctly-aggregating implementation

**What rev-2 says.** HLR-111, replacing rev-1's guard "which was FALSE on correct code":

```python
expected = _merge_band_runs(loaded.entropy_windows)                  # independent oracle
emitted  = {(s.region_start, s.region_end) for s in query(BandSegment) if not s.is_aggregate}
assert emitted <= {(start, start + n) for _band, n, start in expected}
assert all(any(a <= rs < b for a, b in emitted) for rs, _ in loaded.ranges)   # coverage
```

> Subset (not equality) admits aggregation; the coverage clause is what stops an implementation silently dropping a region.

**The subset clause is correct. The coverage clause is not.** `emitted` **excludes aggregate segments** by construction (`if not s.is_aggregate`), and the coverage clause then demands that every `loaded.ranges` start fall inside some *non-aggregate* interval. The moment `LLR-111.8` merges a run that contains a range start — which is the entire point of aggregation — that start is inside an **aggregate** segment and therefore inside no `emitted` interval.

**Minimal executed proof — two ranges, one aggregate:**

```
loaded.ranges        = [('0x1000', '0x1100'), ('0x2000', '0x2100')]
oracle runs          = [('0x1000', 256), ('0x2000', 256)]
kept segments        = 1 aggregate spanning both runs
emitted (non-agg)    = set()   <- empty, aggregates are excluded
subset clause        -> True
coverage clause      -> False   <- FALSE on a CORRECT implementation
GUARD                -> FALSE ❌
```

**At scale**, simulating `LLR-111.8` (merge smallest adjacent runs until the allocation fits) over a 26-region synthetic fixture:

```
  bar=66: kept segments=33  aggregations=18   coverage -> False   uncovered range starts = 10
  bar=50: kept segments=25  aggregations=26   coverage -> False   uncovered range starts = 15
```

**Why this is the same defect, not a new one.** Rev-1's guard equated *run* starts to *range* starts and was false whenever entropy split a range. Rev-2 fixed the subject (runs) but kept a **range-keyed coverage clause** and then subtracted the aggregates from the set it quantifies over. The clause cannot distinguish "this region was dropped" from "this region was aggregated" — and aggregation is precisely what revision 2 introduced.

**It compounds with `AT-B77-17`.** The coverage clause is the *only* predicate that could separate merged from dropped, and `AT-B77-17`'s count formula cannot:

```
  correct: 10 runs MERGED into aggregates    disclosed=10 oracle-non_agg=10  assertion -> GREEN
  defect : 10 runs silently DROPPED          disclosed=10 oracle-non_agg=10  assertion -> GREEN
```

So with the coverage clause broken, **an implementation that silently drops 10 runs passes both the completeness guard's intent and `AT-B77-17`.**

**Fix (cheap).** Split the two clauses by the set each needs:

```python
all_emitted = {(s.region_start, s.region_end) for s in query(BandSegment)}          # incl. aggregates
non_agg     = {(s.region_start, s.region_end) for s in query(BandSegment) if not s.is_aggregate}
assert non_agg <= oracle_pairs                                    # unchanged, correct
assert all(any(a <= rs < b for a, b in all_emitted) for rs, _ in loaded.ranges)   # coverage over ALL
```

Coverage over `all_emitted` is TRUE under correct aggregation (an aggregate spans the runs it absorbed) and FALSE if a region is dropped — which is what the clause claims to do.

---

## 2 · Revision-1 blockers, re-verified by execution

### B-1 ✅ DISCHARGED — runs vs ranges

**First, the trap the coordinator flagged.** I built my own fixture and proved it heterogeneous *before* trusting any verdict from it, and reproduced the author's F-1(g) defect as a control:

```
  loaded.ranges          = [('0x10000', '0x11000')]  (n=1)
  entropy window bands   = {'constant/padding': 8, 'medium': 6, 'high/random': 2}
  DISTINCT bands         = 3   genuinely heterogeneous = True
  oracle _merge_band_runs -> 4 runs from 1 range
  [trap check] random.Random(3) re-seeded per byte -> [121, 121, 121, 121, 121, 121, 121, 121] (all equal = True)
```

**The guard, both regimes, both fixtures:**

```
STEP 2 — rev-2 guard on HETEROGENEOUS 1-range
  size=(80, 24): n_ranges=1 oracle_runs=4 emitted_segs=4
     emitted <= oracle -> True    coverage -> True    GUARD (rev-2) -> TRUE  ✅
     [rev-1 guard, for contrast] -> False
  size=(120, 30): identical.

STEP 2 — rev-2 guard on sparse 5-region
  both sizes: GUARD (rev-2) -> TRUE ✅   [rev-1 guard] -> True
```

The rev-2 guard is TRUE where rev-1's was FALSE, on a fixture the rev-1 guard could not survive. **The subject is now the run** — `visible_cols` has a defined subject when 1 range yields N segments, and `HLR-112` was re-pointed to run starts in the same pass (`ADMISSIBLE = {f"{s:08X}" for run starts} ∪ …`). **Discharged** — with N-1 outstanding on the aggregation path only.

### B-2 ✅ DISCHARGED — Inc-1 is satisfiable and nothing regresses

I implemented Inc-1 exactly as its LLRs prescribe — `LLR-111.9` (CSS: band row always stacks, bar full width), `LLR-111.1` (container basis **and** mapped-bytes denominator), `LLR-111.2` (fold = 1), `LLR-111.7` (floor 1 per run, remainder by largest-remainder on mapped bytes) — and measured its own gate:

```
Inc-1 APPLIED — is its own gate (AT-B77-01 + AT-B77-03, both arms) reachable?

--- sparse5: n_ranges=5 oracle_runs=5 ---
  size=(80, 24) bar=66   Sum(widths)=66 bound->True  gaps all==1  invisible=0 outside=0
     AT-B77-01 visible=True monotone=True strict=True -> GREEN      AT-B77-03 -> GREEN
  size=(120,30) bar=50   Sum(widths)=50 bound->True  gaps all==1  invisible=0 outside=0
     AT-B77-01 -> GREEN                                             AT-B77-03 -> GREEN

--- heterog: n_ranges=1 oracle_runs=4 ---
  bar=66 -> GREEN / GREEN        bar=50 -> GREEN / GREEN

--- prg.s19: n_ranges=11 oracle_runs=14 ---
  size=(80, 24) bar=66   Sum(widths)=66 bound->True  invisible=0 outside=0  -> GREEN / GREEN
  size=(120,30) bar=50   Sum(widths)=50 bound->True  invisible=0 outside=0  -> GREEN / GREEN

  ==> Inc-1 gate reachable on every fixture/arm: True
```

- **`LLR-111.9` works:** the bar measures **50** at 120×30 (was 21) and **66** at 80×24 (unchanged) — P-46 reproduces.
- **No regime regresses:** 80×24 `outside` is `0` pre-change and `0` post-Inc-1. Rev-1's basis-only Inc-1a took it to `2`; making Inc-1 indivisible fixes exactly that, and §7's ordering constraint 1 states my measured numbers (`[8,8,16,33]` = 65 of 66) correctly.
- **`prg.s19` — the architect's blocker fixture — fits at both regimes with zero aggregation**, confirming P-49.

**Discharged.**

### B-3 ✅ DISCHARGED — and the liveness clause is a real gate, not a decoration

`LLR-116.5` now requires `app.focused in set(app.query(RegionRow))` **and** `app.focused.is_attached` **and** `region_start == resolved`, and `LLR-116.2` mandates a post-refresh hook because "`grid.mount()` is deferred". I implemented both, then ran the R-6 pair **plus a fourth variant** — correct resolution applied *synchronously*, i.e. exactly the rev-1 implementation my B-3 caught.

**Per-arm (CC-1), all four variants:**

| Variant | `AT-B77-11` | `AT-B77-13` | `AT-B77-14` |
|---|---|---|---|
| **correct** (post-refresh hook) | **G** | **G** | **G** |
| **mutA** — `selected = ordered[0]` (always reset) | G | **R** | G |
| **mutB** — `selected = _selected_cell_start` (keep stale) | **R** | G | **R** |
| **sync** — correct logic, synchronous (the rev-1 defect) | **R** | **R** | **R** |

```
######## VARIANT = sync ########
   AT-B77-13 preserve: DETAIL=G  FOCUS[in_live=False attached=False start=0x2000000]=R  -> RED
```

That row is the whole finding: the focused widget still reports `region_start == 0x02000000` — rev-1's threshold read **GREEN** on it — while `in_live=False, attached=False`. The liveness clause **reddens it**. 

**And the R-6 collapse I reported in rev-1 M-1 is gone.** `correct` is now `G,G,G`, so `mutB` (`R,G,R`) is distinguishable from it; each mutation reddens exactly one of the 13/14 pair, as tabulated. The document's claim that this table is "**EXECUTED at Phase 2 by the QA lane**" is accurate, and Inc-7's gate correctly requires the two mutations be run **after** liveness lands.

### B-4 ✅ DISCHARGED — the label is honest and correctly scoped

`AT-B77-09` is re-authored to run with focus **ON** a row (the post-R-6 default, the only state where widget-scoped shadowing is reachable), and rev-1's version is split out as `AT-B77-16`, **relabelled a PIN** with the C-40 limb-1 reasoning stated. That is exactly the fix I asked for, and the PIN/gate split is correct.

**Is "cannot be RED until Inc-7" hiding the defect? No — it is a true ordering statement.** Before Inc-7, `can_focus` is False and `row.focus()` is a no-op, so "focus ON a row" is an *unreachable precondition*: the AT cannot run at all, let alone be RED. After Inc-7 it runs and is GREEN on a correct implementation, because nothing is broken today — this is a **regression gate**, not a defect-fixing gate, and such an AT is never "RED pre-change" by construction. Labelling it rather than claiming discharge is the honest call, and §9 marks the checklist row ⚠️ partial rather than ✓.

**One residual — see m-1:** the reddening mutation is *named* (`add Binding("k", …) to RegionRow.BINDINGS`) but no increment gate obliges its **execution**.

---

## 3 · Revision-1 majors — all correctly fixed

| Rev-1 | Status | Evidence in rev 2 |
|---|---|---|
| **M-1** discharge marks over predictions | ✅ **Fixed** | `LLR-111.5` now carries a Status column marking each row ✅ **executed** or 🔶 `predicted — execute at Inc-N`. The R-6 table is attributed "**EXECUTED at Phase 2 by the QA lane**" per row. §9 states the defect by name: *"a prediction wearing a discharge mark"*. One row still slips — **M-2** below |
| **M-2** golden payload on the retired basis | ✅ **Fixed** | `LLR-111.4` prints `bar=66 → [50,16]`, `bar=50 → [38,12]`, `bar=21 → [16,5]`, and shows `[45,15]` explicitly as *"what revision 1 wrongly printed"*. Marked **`predicted` — captured by execution at Inc-3**. My independent arithmetic agrees with all four rows |
| **M-3** `test_tc041_9` vacuity claim | ✅ **Fixed** | Claim **WITHDRAWN**, five assertions acknowledged, and the root cause stated correctly — *"the no-file strip is `''` because `build_stats_text` is never called on that path"*, which is exactly what I measured. The doc adds: *"Do not assert a vacuity you cannot demonstrate"* |
| **M-4** unpinned precision | ✅ **Fixed** | `HLR-113`: *"to exactly four fractional digits"* (was "at least four"), with my `.6f`-reddens-`test_at037` reasoning cited |
| **M-5** `AT-B77-10` two-node claim | ⚠️ **Acknowledged, not structurally fixed** — see **M-3** below |
| footer understatement | ✅ **Adopted** | §2.2: *"**14** `show=True` chips needing ≈ **181** columns in **78**"* |

**Two rev-2 additions I verified sound:**

**`HLR-112`'s legibility clause** replaces rev-1's overlap test. The doc claims the old clause was vacuous because `1fr` children go zero-width rather than overlapping. Executed against the shipped `MapRuler` CSS:

```
N=  5 ticks, 8-char labels, container W=50:
    zero-width=0   overlapping pairs=0   ticks with region.width < len(label)=0
N= 60 ticks, 8-char labels, container W=50:
    zero-width=10  overlapping pairs=0   ticks with region.width < len(label)=60
    rev-1 clause 'no overlapping column ranges'      -> GREEN  <-- VACUOUS
    rev-2 clause '0 ticks narrower than their label' -> RED    <-- discriminating
```

`10 zero-width, 0 overlaps` reproduces the document's figures exactly. **Sound fix.**

**`P-51` / `AT-B77-15`** — the shipped docstring's ANSI guarantee:

```
  input             = 'sensor\x1b[31m_evil[red]'
  safe_text().plain = 'sensor\x1b[31m_evil[red]'
  ESC survives      = True     '[red]' literal = True     spans = []
  docstring lines: ['...raw ANSI bytes carried in the never-scrubbed', '...no MarkupError, no style/ANSI leak,']
```

Confirmed: the markup half is true, the ANSI half is false, and the false claim is in shipped source. The gate is real and correctly routed to a non-frozen file with the scrub itself carried (`C-77-h`).

---

## 4 · MAJORS

### M-1 🟠 `AT-B77-17`'s derived count contradicts the same callout, and aggregation ends up tested at one arm

The `AT-B77-17` callout states both of these:

> `bar=66 → 35 − 33 = 2` · `bar=50 → 35 − 25 = 10`

> at 80×24 the segment **count** fits (`60 ≤ 66`) and only the **bound** is violated, so aggregation is not required there

**Executed, for the AT's own fixture (35 runs, 25 gaps, fold 1):**

```
  bar=66: n_runs+n_gaps*fold = 35+25 = 60  > 66 ? False -> aggregation does NOT fire
  bar=50: n_runs+n_gaps*fold = 35+25 = 60  > 50 ? True  -> aggregation FIRES
```

If aggregation does not fire at `bar=66`, then `non_aggregate_emitted = 35` and the disclosure is **0**, not 2. The two statements cannot both hold.

The AT itself is safe — its assertion is `disclosed == oracle_runs − non_aggregate_emitted`, evaluated at runtime, so it will correctly expect 0. But the figure is presented as the **derived expectation** ("derived, not eyeballed"), so an implementer chasing `2` at 80×24 is chasing a phantom.

**The consequence is the real cost: `LLR-111.8` — all of R-7/2 — is exercised at exactly ONE arm (120×30).** The 80×24 arm tests only the bound. For a mechanism introduced in this revision, that is thin, and "Report per arm (CC-1)" reads as if both arms cover it.

**Also folded in:** `LLR-111.8` gives the threshold as `n_runs + n_gaps·fold > bar_width`, "**i.e.** `2·n_runs − 1 > bar_w`". The second form assumes a gap between *every* adjacent pair. It is right for the onset sweep (executed: `bar=50` 25→26, `bar=66` 33→34, both consistent) and **wrong for the AT's own fixture**, which has 25 gaps for 35 runs. The "i.e." should be "which reduces to … when every run pair is gap-separated".

**Fix.** Correct the `bar=66` expectation to `35 − 35 = 0`; state plainly that aggregation fires only at 120×30 for this fixture; and either add a fixture that crosses the onset at `bar=66` (≥ 34 runs with gaps between all of them) or record that the 80×24 aggregation path is unexercised.

### M-2 🟠 R-9's exactness limb has no executed falsification, in a row marked ✅ executed

`LLR-111.5` row:

| `AT-B77-17` | ✅ the emitted widths and the disclosed count | remove the bound (emit unclamped); **set the disclosure to a constant `1`** | ✅ **GATE — RED, executed** (60 cols into a 50-col bar) |

Two mutations are named. Only the first is discharged: pre-change there *is* no bound, so the shipped tree **is** the unclamped mutant and its RED is genuine evidence. The second — "set the disclosure to a constant `1`" — mutates code that does not exist yet and **cannot have been executed**. The pre-change evidence for limb 2 is `disclosure rows found=[]`, which reddens *"a disclosure exists"*, **not** *"the count is exact"*.

Exactness is the entire content of R-9, and it is the one limb with no falsification. Per the document's own revision-2 evidence promise — *every payload executed or labelled `predicted — execute at Phase N`* — this row should read 🔶 for its second mutation, exactly as `AT-B77-02` does.

Combined with **N-1**, the exactness limb is currently the weakest predicate in the batch: it cannot distinguish merged from dropped, and the clause that could is broken.

**Fix.** Split the row: limb 1 ✅ executed; limb 2 🔶 `predicted — execute at Inc-2`, and add the constant-`1` mutation to Inc-2's gate (which already says "+ its executed mutation", so only the labelling needs correcting).

### M-3 🟠 `AT-B77-10` has no owning increment; M-5 is acknowledged but not structurally fixed

Executed over §7's gate column — the increments name **16 of 17** ATs (01, 02, 03, 04, 05, 06, 07, 08, 09, 11, 12, 13, 14, 15, 16, 17). **`AT-B77-10` appears in no increment gate.** C-21 wants exactly one owning increment per AT.

Separately, rev 2 records my M-5 as a caution rather than a fix:

> **`AT-B77-10`** *(PIN)* N4a mouse split — ⚠️ **QA M-5: this is a two-node claim** mapping to existing `test_ac3_…` + `test_ac4_…`; **reuse those nodes**

"Reuse those nodes" (plural) under one AT id is still "covered by X + Y combined", which C-18 calls UNREALIZED. **Fix:** split into `AT-B77-10a` / `AT-B77-10b` bound to the two existing nodes, and give them an owning increment (Inc-1 is the natural home — it already edits `test_map_click_chain.py` for Amendment C).

---

## 5 · MINORS

| # | Finding | Fix |
|---|---|---|
| **m-1** | `AT-B77-09`'s reddening mutation is named inline but **no gate obliges its execution**. Inc-2 says "+ its executed mutation" and Inc-7 says "the two R-6 mutations executed"; **Inc-8 says only** "`AT-B77-08/09/16`; TC-011 green and unmodified". Without it the AT will simply be GREEN and never mutation-tested — the residual of B-4 | Add "+ the `Binding("k", …)` shadowing mutation, executed" to Inc-8's gate |
| **m-2** | P-51 reports "**16** visible chars, **5** invisible bytes". By `ord < 32` only **1** byte is a control char; the figure counts the whole `\x1b[31m` sequence as invisible. Both readings are defensible and `len(plain)=21` reproduces exactly, but the definition is implicit | State "invisible" = "consumed by the terminal as an escape sequence" |
| **m-3** | The `AT-B77-17` fixture is under-specified — "26 disjoint regions of strictly increasing size, alternating band" does not determine byte content, and my faithful reconstruction produced **51** oracle runs, not 35. The AT derives its expectations at runtime so it still functions, but `35` is not reproducible from the stated recipe | Pin the fixture's construction (sizes and fill) in the AT, or state that only the *derived* relation is normative |
| **m-4** | `LLR-111.9`'s cost note and `C-77-k` both state the stats-line scroll deepens `bottom=31/30 → 33/30`. Accepted under R-8 and correctly recorded as a carry — **no action**, listed only to confirm the R-8 implementation is faithful to the ruling | — |

---

## 6 · Mandated-check disposition

| Check | Result |
|---|---|
| **B-1 runs vs ranges, own heterogeneous fixture** | ✅ Discharged. Fixture proven heterogeneous (3 bands, 1 range → 4 runs) **before** any verdict; F-1(g) trap reproduced as a control. rev-2 guard TRUE / rev-1 guard FALSE at both regimes. ⚠️ **N-1**: the coverage clause fails under aggregation |
| **B-2 Inc-1 + `LLR-111.7` + CSS widen** | ✅ Discharged. LLRs implemented verbatim; gate GREEN on 3 fixtures × 2 arms incl. `prg.s19`; bar 21→**50**; **no regime regresses** (80×24 `outside` 0→0) |
| **B-3 liveness + R-6 re-run, per arm** | ✅ Discharged, and the clause is a **gate**: the `sync` variant is RED on all three arms while `correct` is GREEN on all three. Per-arm table in §2. The rev-1 collapse (`mutB` ≡ `correct`) is resolved |
| **B-4 `AT-B77-09` + the "cannot be RED until Inc-7" label** | ✅ Discharged; the label is **honest and correctly scoped** — the precondition is genuinely unreachable before Inc-7, and this is a regression gate that is never RED pre-change by construction. Residual **m-1**: no gate obliges the mutation |
| **R-7 implementation** | ✅ Correct. Widen-then-bound verified: widening alone leaves runs invisible (reproduced), bound alone is impossible at bar=21; together, GREEN everywhere |
| **R-8 implementation** | ✅ Correct — accepted as carry `C-77-k`, cost stated in both `LLR-111.9` and §6.3, with the "do not narrow the widen to protect it" rationale intact |
| **R-9 — is `AT-B77-17` vacuous?** | ⚠️ **Partly.** The count **is** derived at runtime against an independent oracle, not hand-copied ✅. But: the fixture does **not** cross the onset at `bar=66` (**M-1**), so one arm never exercises aggregation; the exactness limb has **no executed falsification** (**M-2**); and the formula **cannot distinguish merged from dropped** (executed, **N-1**) |
| **§9 discharge marks — any other row?** | Audited all C-40/status rows. `AT-B77-01`/`03` are legitimately discharged (the shipped tree *is* their mutant). `AT-B77-15` legitimately discharged. `AT-B77-02` correctly 🔶. The R-6 table correctly attributed to Phase-2 execution. **One row slips: `AT-B77-17`'s second mutation (M-2).** `AT-B77-09`/`16` carry no mutation row at all (m-1) |
| **`test_tc041_9` census** | ✅ Correct now — claim withdrawn, five assertions acknowledged, root cause (`build_stats_text` never called on the empty path) stated exactly as measured |
| **Footer / no-new-binding** | ✅ Adopted verbatim into §2.2 (14 chips ≈ 181 columns in 78) |
| **New-vacuity sweep on rev-2 additions** | `HLR-112` legibility clause ✅ **sound and discriminating** (executed: rev-1 clause GREEN/vacuous, rev-2 clause RED). `AT-B77-15` ✅ real gate (ESC survives, executed). `LLR-117.2`'s `text-style: reverse` strengthening ✅ sound on inspection. `LLR-111.7` ✅ sound. **The one new vacuity found is N-1** |
| **Id / increment hygiene** | `AT-B77-01…17` all defined, no gaps. `TC-B77-01…31` recount: 6+4+4+2+5+6+4 = **31**, each used exactly once ✅. All increments ≤5 files ✅. **`AT-B77-10` unowned (M-3)** |

---

## 7 · Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Verified by execution, not by reading the diff | ✓ | Inc-1 and Inc-7 implemented from LLR text in an isolated tree; 4 R-6 variants + 3 Inc-1 fixtures × 2 arms executed |
| Own fixtures built and validated before use | ✓ | Heterogeneity proven (3 bands) and the F-1(g) per-byte-reseed trap reproduced as a control |
| Per-arm verdicts (CC-1) | ✓ | §2 B-3 table: 4 variants × 3 arms; §2 B-2: 3 fixtures × 2 arms |
| Hunted for what the fix introduced | ✓ | **N-1** — the fix for B-1 reproduced B-1's defect class on the aggregation path |
| Blockers led | ✓ | §1 |
| Working tree untouched, proven by hash | ✓ | `b11fdfcd25c52bf2fdd4d1e40272d9fa` / `b60b1caef924e912dee914872b131f85` before **and** after; isolated tree deleted |
| Self-caught probe defects recorded | ✓ | My first Inc-1 probe read `bar=0` on every fixture because it held a **pre-re-render** reference to `.map-band-bar` — the exact stale-widget trap of my own B-3, committed inside the probe verifying its fix. Corrected by re-querying after each render; all §2 B-2 figures are from the corrected run |
| No unfilled template | ✓ | No placeholder, no `TC-NNN`, no blank required row |
| Test-results section left blank | ✓ | This review adds none; all figures are Phase-2 probe transcripts with their commands |

---

## 8 · Recommendation

**BLOCK — on one blocker and three majors, all narrow and none requiring a ruling.**

1. **N-1** — evaluate the coverage clause over **all** emitted segments (aggregates included); keep the subset clause over non-aggregates. Two lines.
2. **M-1** — correct `bar=66 → 0`, state that aggregation fires only at 120×30 for this fixture, and either add an onset-crossing fixture at `bar=66` or record the gap.
3. **M-2** — relabel `AT-B77-17`'s second mutation 🔶 `predicted — execute at Inc-2`.
4. **M-3** — split `AT-B77-10` into two ids bound to the two existing nodes and give them an owning increment.

Plus **m-1**: add the shadowing mutation to Inc-8's gate.

**Everything else in revision 2 is sound, and the corrective pass was substantive rather than cosmetic.** B-2 and B-3 are provably fixed — I implemented the requirements and the gates pass, and the liveness clause reddens the precise defect it was written for, which is the strongest form of discharge available at Phase 2. The document also caught two real defects on its own that neither lane had found (the `1fr`-ticks-go-zero-width vacuity and the false ANSI docstring), and it withdrew a vacuity claim it could not demonstrate rather than defending it.
