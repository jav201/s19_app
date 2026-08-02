# Phase-2 RE-GATE 3 — ARCHITECT lane — batch `2026-08-01-batch-77`, revision 3

**Under review:** `01-requirements.md` **revision 3** (644 lines) @ `9b1b744`
**Prior:** rev 1 → 7 blockers · rev 2 → 6 blockers, 2 majors (`02-review-architect.md`, `02b-review-architect-regate.md`)
**Method:** rev-3 producer implemented (`LLR-111.9` stack · `LLR-111.1` basis+denominator · `LLR-111.7`
floor-1 + largest-remainder · `LLR-111.2` fold=1 · **no** `LLR-111.8`) and rendered through the shipped surface.
Probes: `scratchpad/arch3_rev2.py`, `arch4_rev3.py`. `PYTHONDONTWRITEBYTECODE=1` (C-46). R1–R11 not re-litigated.

---

## VERDICT: **BLOCK** — 3 blockers, 2 majors, 2 minors. **All three blockers are the same defect in three places, and it is a propagation miss, not a design error.**

R-10 is the right call and **all five aggregation blockers are genuinely gone, not relocated** — I checked
the acceptance, the guard, the definitions table and every textual reference. The withdrawal record and
`C-77-l` are the best-executed part of this document.

**But the domain restriction R-10 added was applied to `HLR-111`'s Statement and to the AT labels only.
It was not propagated to `LLR-111.7`, to `LLR-111.3`, or to `HLR-112` at all** — three unconditional `shall`
clauses that a shipped fixture falsifies. The unsatisfiable-universal defect did not leave with
`LLR-111.8`; it stayed in its siblings.

**Cost to fix: two edits and one small decision.** No ruling is implicated, nothing needs re-scoping.

---

## 1 · Rev-2 blockers — status, each re-verified by execution

| # | Rev-2 blocker | Status | Proof |
|---|---|---|---|
| **RB-1** | Coverage guard FALSE on correct code | ✅ **CLOSED** | Guard is back to **equality** with the `is_aggregate` filter deleted (`:145-147`). With no aggregation `\|emitted\| = \|oracle\|`; executed `subset=True` + `cover=True` on all 16 in-domain fixtures |
| **RB-2** | Aggregate has no monotonicity subject | ✅ **CLOSED — gone with the path** | No aggregate segments exist. Preserved as `C-77-l` item 7 with the executed violation pair |
| **RB-3** | "Merge until it fits" kills strict-∃ | ✅ **CLOSED** | Preserved as `C-77-l` item 8 |
| **RB-4** | Disclosure count ambiguous | ✅ **CLOSED** | `AT-B77-17` withdrawn (`:398`); preserved as `C-77-l` item 9 with all three readings |
| **RB-5** | `AT-B77-02` mutation is a no-op | ✅ **CLOSED — mutation verified real** | §2.3 |
| **RB-6** | *"No shipping fixture crosses the onset"* was false | ✅ **CLOSED** | `case_08` is now the charter's headline fixture rule (`C-77-l` item 3) |
| **RM-1** | Golden computed by the wrong method | ⚠️ **CLOSED in §4, STALE IN THE BLUF** | §2.4 → **RC-M1** |
| **RM-2** | `AT-B77-09` mislabelled a gate | ✅ **CLOSED** at `:239` — a thorough, honest relabel | stale echo at `:445` → minor |

**Author's self-caught probe defect verified independently.** Its allocator probe assumed a gap between
every pair — wrong for a gapless fixture — giving `[48,17]` (sum 65) before correction to `[49,17]`.
My independent implementation renders **`[49,17]` sum 66** and **`[37,13]` sum 50**. The corrected figure
is right (§2.3).

---

## 2 · Executed transcripts

### 2.1 — The domain statement: both else-clauses HOLD, and no fixture was silently excluded

```
1. AT-B77-18 / HLR-111 ELSE-CLAUSE on case_08 (rev-3 producer, NO aggregation)
  ranges=801  oracle runs=801

  size=(80, 24)  bar=66
    else-clause 1  'shall render without raising'       -> PASS (no exception)
    else-clause 2  'every run reachable in region list' -> region rows=801 vs oracle runs=801  PASS
  size=(120, 30) bar=50
    else-clause 1  'shall render without raising'       -> PASS (no exception)
    else-clause 2  'every run reachable in region list' -> region rows=801 vs oracle runs=801  PASS
```

```
2. IN-DOMAIN CHECK: is every shipped fixture inside the stated domain?
  case_00_public/prg.s19                          runs=14  gaps=10  need=24   @66=True  @50=True
  case_00_public/s19_sample.s19                   runs=2   gaps=1   need=3    @66=True  @50=True
  case_01 … case_07, professional_validation 01/02/03/04/05/07  need 3–9      @66=True  @50=True
  professional_validation/case_08_heavy_fragmentation/firmware.s19
                                                  runs=801 gaps=800 need=1601 @66=False @50=False
```

**The domain statement is honest.** Both else-clauses are true by execution at both regimes. **16 of 17 in
domain, exactly as claimed**, and the restriction excluded nothing quietly — the largest in-domain demand is
**24** against a **50**-column ceiling, so every fixture that used to be covered still is, with 26 columns of
headroom.

### 2.2 — But the domain did not reach the children

```
  size=(80, 24)  bar=66
    -- the child LLRs, which carry NO domain restriction --
    LLR-111.7 conjunct A  Sigma widths <= bar : 1601 <= 66 -> False
    LLR-111.7 conjunct B  every run >= 1 col  : min emitted width=1 -> True
    LLR-111.3             outside == 0        : outside=1535 -> False
    (invisible runs = 768 of 801)
    -- HLR-112, which has NO domain restriction at all --
    ruler ticks emitted today=5  widths=[13, 13, 13, 13, 14]
    LLR-112.1 would require one tick per run start + end = 802 ticks
    HLR-112 clause 4: no tick narrower than its 8-char label
        available ruler columns ~= 66 ; 802 ticks -> 0 cols/tick -> *** UNSATISFIABLE ***

  size=(120, 30) bar=50
    LLR-111.7 conjunct A  Sigma widths <= bar : 1601 <= 50 -> False
    LLR-111.3             outside == 0        : outside=1551 -> False
    (invisible runs = 776 of 801)
        available ruler columns ~= 50 ; 802 ticks -> 0 cols/tick -> *** UNSATISFIABLE ***
```

### 2.3 — `AT-B77-02`'s replacement mutation is real; `[49,17]` independently confirmed

```
AT-B77-02 rev-3 mutation: allocator -> plain round()

  MANDATED  (80, 24)  golden = [49, 17]
  MANDATED  (120, 30) golden = [37, 13]
  MUTATED   (80, 24)  golden = [50, 16]   REDDENS: True
  MUTATED   (120, 30) golden = [38, 12]   REDDENS: True
```

Exactly the reddening the document claims. RB-5 closed.

### 2.4 — The 60-basis sweep, third pass

Every bracketed integer list in the document, checked against the retired `_BAND_BAR_WIDTH = 60`:

```
   line  list        sum   labelled?
     31  [45,15]     60    yes — but the row's CORRECTED value is stale     -> RC-M1
    373  [30,30]     60    yes — "revision 2 printed … one more residue"    OK
    374  [45,15]     60    yes — "Revision 1 printed … the retired constant" OK
    382  [45,15]     60    yes — "retired 60-basis" row of the method table  OK
    578  [30,30]     60    yes — reconciliation log, with [33,33]/[25,25]    OK
    612  [45,15]     60    yes — ordering rationale, rev-1 failure mode      OK
   107/108, 380/381, 399: [49,17] [37,13] [50,16] [38,12] — every one names its METHOD  OK
```

**Every payload in §4 now names its method, and the two mandated values verify.** `should`/`debería`: **0**.

### 2.5 — Inc-2's gate

```
Inc-2 gate reachability: can AT-B77-15a/b see any file-derived text BEFORE Inc-7 auto-select?
  size=(80, 24)  #map_detail_body = 'Click a region to inspect it - double-click to open in hex.'
             contains any file-derived string: False
  size=(120, 30) #map_detail_body = 'Click a region to inspect it - double-click to open in hex.'
             contains any file-derived string: False
```

---

## 3 · BLOCKERS

### RC-1 — The domain was applied to `HLR-111` but not to `LLR-111.7` or `LLR-111.3`

**Where:** `LLR-111.7:351` — *"The sum of all emitted run-segment widths and all emitted gap-marker widths
**shall not** exceed the measured container width, and every emitted run segment **shall** receive at least
one column."* Threshold `:353` — *"for **every suite fixture**"*.
`LLR-111.3:369` — *"Every `.map-band-seg` **shall** satisfy `bar.region.contains_region(seg.region)`."*
Threshold — *"outside `0` at both regimes"*.
**Evidence:** §2.2. On `case_08`: `Σ = 1601` into 66 and into 50 → conjunct A **False** at both regimes;
`outside = 1535 / 1551` → `LLR-111.3` **False** at both regimes.

`HLR-111`'s Statement (`:133`) correctly gates its universals on `n_runs + n_gaps ≤ bar.region.width`, and
`AT-B77-01`/`AT-B77-03` are correctly labelled *in domain* (`:155`). **Neither child LLR carries the
restriction**, and `LLR-111.7`'s two conjuncts are mutually unsatisfiable out of domain — the document says
so itself at `:169` (*"the bound is arithmetically unsatisfiable there: `avail` is −734 / −750"*) and then
leaves the clause unconditional. `LLR-111.7`'s threshold explicitly quantifies over *every suite fixture*,
and `case_08` is in `examples/`.

This is the rev-1 B-2 defect — a normative universal a shipped fixture falsifies — surviving in the children
because the fix was applied one level up.

**Cost: an edit.** Prefix both Statements with the same domain clause `HLR-111` already uses, and scope
`LLR-111.7`'s threshold to in-domain fixtures.

### RC-2 — `HLR-112` has no domain at all, and two of its clauses are jointly unsatisfiable

**Where:** `HLR-112:200` — *"**shall** emit one tick label per emitted **run** start plus one label for the
last mapped byte … and **shall not** emit any tick whose rendered width is smaller than the label it
carries."* `LLR-112.1:414` repeats clause 1; `LLR-112.2:416` carries clause 4.
**Evidence:** §2.2. On `case_08`, clause 1 demands **802** ticks; the ruler has ~66 / ~50 columns → **0
columns per tick** while the label is 8 characters. The two clauses cannot both hold.

Two aggravating facts:

1. **`LLR-112.2`'s rationale still depends on the withdrawn requirement.** `:416` reads: *"the widened bar
   raises the tick budget and **`LLR-111.8`'s aggregation lowers the run count the ruler must label**"*.
   That is the sufficiency argument for the elision predicate, and half of it was withdrawn by R-10.
   **This is the one live dangling reference to `LLR-111.8` in the document** — every other mention is the
   withdrawal record, an explicit `WITHDRAWN` marker, a historical log row, or the `C-77-l` charter.
2. **Nothing covers `HLR-112` out of domain.** `AT-B77-18` (`:155`) covers `HLR-111`'s else-clause only —
   no raise, region list complete. The ruler has no equivalent.

**Cost: a small decision, not an edit.** `LLR-112.2` already contemplates dropping labels (*"shall retain the
first and last labels in preference to any interior label when labels must be dropped"*), so the machinery
exists — but `HLR-112` clause 1 says *one tick per run start*, and someone must state which yields, and
what the out-of-domain ruler promises. Give `HLR-112` the same domain treatment `HLR-111` received.

### RC-3 — Inc-2's gate is unreachable non-vacuously, for the exact reason P-55 catches

**Where:** §7 Inc-2 gate — *"`AT-B77-15a` + `AT-B77-15b`, **per limb per size**"*. `HLR-116`/`LLR-116.6`
scope the clause to *"a render that auto-selects a region"*, and auto-selection lands in **Inc-7**.
**Evidence:** §2.5. Before Inc-7, a zero-click render shows `_DETAIL_HINT` and **no file-derived text** at
either regime.

`AT-B77-15a` asserts the A2L payload renders literal with no spans; `AT-B77-15b` asserts no control byte in
the painted strip. With no file-derived text rendered, **both are green on any implementation** — which is
precisely the vacuity `P-55` (`:104`) just caught in revision 2's `AT-B77-15`. Inc-7's gate concedes the
problem in passing (*"Re-runs `AT-B77-15a/b` **now that auto-select makes the payload actually render**"*)
but Inc-2's gate does not say how it avoids it.

Sequencing the scrub before Inc-7 (R-11, constraint 2 at `:519`) is **correct** and I am not questioning it.
The defect is that Inc-2's *acceptance* was carried over unchanged from a surface that does not exist yet.

**Cost: an edit.** State that the Inc-2 arms drive the payload through the shipped pre-batch route — a click
on a region row — and that the zero-click form is what Inc-7 re-runs.

---

## 4 · MAJORS

### RC-M1 — The BLUF still carries the payload rev-3 corrected

`:31` — *"**Golden payload re-derived on the container basis** — rev-1's `[45,15]` summed to **60**, the
retired constant. **At the measured 66 it is `[50,16]`.**"*

`P-59` (`:108`) and `LLR-111.4` (`:380-382`) both declare `[50,16]` to be **plain `round()`, the wrong
method**, and `[49,17]` to be mandated. The document contradicts itself, and the stale value sits in the
first table a reader sees — the same number, in the same role, that survived a whole revision because it
looked plausible.

### RC-M2 — The out-of-domain measurement block was produced without `LLR-111.7`, and the degradation rule is unspecified

**Where:** `:171-180`, headed *"What the bar ACTUALLY does out of domain — measured"*, row labelled
**`R-7 stack CSS (batch-77)`**: `content=1660`, `INVISIBLE 797/801` @66 and `800/801` @50,
`outside=1594/1600`.
**Evidence:** §2.2. Under the **actual** batch-77 producer (stack CSS **and** the `LLR-111.7` bound) the
figures are `content=1601`, **`768/801`** and **`776/801`** invisible, `outside=1535/1551`.

`content = 1660 > 1601` is the signature of the **unbounded** producer. The row is labelled batch-77 but
omits batch-77's central change. The batch in fact *improves* `case_08` slightly (29 and 24 fewer invisible
runs) — the document understates its own result — and `AT-B77-18` is owned by Inc-1, where it will run
against the real producer and not reproduce these numbers.

**The deeper half:** out of domain `LLR-111.7`'s two conjuncts contradict each other and **nothing states
which yields**. My implementation gives every run its floor of 1 column and lets the sum overflow; an
implementation that instead honoured the sum would drop runs to zero columns and produce different invisible
counts. Until the degradation rule is stated, `AT-B77-18`'s sibling measurements are implementation-defined.
`C-77-l` item 4 inherits the same figures and should inherit the corrected ones.

---

## 5 · MINORS

**Rm-1 — stale label.** `LLR-115.4:445` still reads *"`AT-B77-09` (gate) and `AT-B77-16` (pin) green"*
after the relabel to PIN at `:239`.

**Rm-2 — stale reconciliation row.** `§6.4:552` still records the arch B-1/B-2 body edits as
*"§4 `LLR-111.7`/**.8**/.9; `AT-B77-17`"*. Both are withdrawn. The R-10 row at `:572` supersedes it, so this
is history rather than instruction, but it names artefacts that no longer exist.

---

## 6 · The two things you asked me to attack

**1 · Is `HLR-111`'s domain statement honest and complete?**
**Honest: yes, verified.** Both else-clauses hold by execution at both regimes — no exception raised, and
**801 region-list rows against 801 oracle runs**. The `99.5 % unseen` admission is real and the claim that
the batch does not fix it is true. The domain also excluded nothing quietly: 16 of 17 fixtures in domain at
both regimes, with the largest in-domain demand at **24** against a **50** ceiling.
**Complete: no.** The domain stops at the parent. `LLR-111.7`, `LLR-111.3` (RC-1) and the whole of `HLR-112`
(RC-2) remain unconditional and are falsified by `case_08`. And the out-of-domain *degradation* is
unspecified (RC-M2), so "what the bar actually does" is not yet determined by the requirement.

**2 · Is `LLR-111.8` a withdrawal record rather than a deletion with better manners?**
**It is a genuine withdrawal record, and `C-77-l` is the strongest artefact in this document.**
All six defects are named in the record (`:358`) and each is carried with its executed measurement:

| Re-gate defect | `C-77-l` item | Carried measurement |
|---|---|---|
| RB-2 monotonicity subject | 7 | `((1988,2),(2150631108,1))`; monotone-by-span False, by-sum True |
| RB-3 stopping rule vs strict-∃ | 8 | `regions=18 → 76 runs`, all widths 1, strict False, both regimes |
| RB-4 disclosure count | 9 | all three readings @66 and @50 — `768 / 801 / 768`, `776 / 801 / 776` |
| QA N-1 coverage excludes aggregates | 10 | 10 uncovered @66, 15 @50 on the 26-region fixture |
| QA N-1 merged vs dropped | 11 | `oracle − emitted` green either way |
| RB-6 false fixture premise | 3 | `case_08` named as **the** acceptance fixture, from the start |
| security M-3r O(n²) | 6 | `n=1000 → 31.10 ms`; `n=5000 → 840.34 ms` |
| — onset | 1, 2 | formula + `26 @bar=50`, `34 @bar=66` |
| — out-of-domain baseline | 4 | ⚠️ inherits RC-M2's producer problem |
| — bound unsatisfiable | 5 | `avail = −734 / −750` |

**batch-78 must re-derive exactly one thing: item 4's out-of-domain figures**, because they were measured
without `LLR-111.7` (RC-M2). Everything else is paid for. R-9's region-list decision is preserved verbatim
(`:585`) so batch-78 inherits it rather than re-litigating.

**Aggregation residue sweep:** every reference to `LLR-111.8` / `AT-B77-17` / *aggregate* is accounted for —
withdrawal record, `~~struck~~` rows, historical log, or the charter — **except `LLR-112.2:416`**, which
uses aggregation as a live premise (RC-2). The definitions table strikes *aggregate segment* and states
*"No clause in this document depends on it"* (`:55`); `LLR-112.2` is the counterexample to that sentence.

**Increment plan:** file counts **4 / 3 / 3 / 4 / 5 / 4 / 4 / 4 / 1** — all ≤ 5; Inc-7 came down from 5 to 4
when the hostile test file moved to Inc-2. Ordering constraints 1, 3 and 4 re-verified sound. Constraint 2
(Inc-2 → Inc-7) is correct in principle; only Inc-2's *gate* is wrong (RC-3). No increment regresses a
passing regime: Inc-1 remains indivisible, and Inc-2's scrub touches `safe_text`, whose only map-side inputs
are band glyphs and hatch characters — no control bytes, so no drift into Inc-1's or Inc-3's payloads.

---

## 7 · What I am NOT flagging

- **R-10 itself.** Descoping rather than patching was right: seven of eight re-gate blockers lived in that
  one path, and `LLR-111.7` alone genuinely fixes 16 of 17 fixtures. I verified both halves.
- **The equality guard's restoration** (`:145-149`). Correct, and the reasoning for why equality is right
  again is sound.
- **`AT-B77-18`.** A good replacement — it claims only what the batch can honestly deliver, and both its
  claims are true by execution.
- **`AT-B77-09`'s relabel** (`:239`). Thorough and honest, including the admission that revision 2's
  "RED-able after Inc-7" implied something that would never happen.
- **P-55 and the `AT-B77-15` split.** Catching its own vacuously-green limb is exactly the discipline this
  batch has been converging on. RC-3 is that same insight not yet applied to the increment gate.
- **R-11 sequencing.** Landing the scrub before the clause goes live is right.

---

## 8 · Disposition — edits or design work?

**Two edits and one small decision. This does not need re-scoping.**

| # | Fix | Kind |
|---|---|---|
| RC-1 | Prefix `LLR-111.7` and `LLR-111.3` with `HLR-111`'s existing domain clause; scope `LLR-111.7`'s threshold to in-domain fixtures | **edit** |
| RC-3 | State that Inc-2's `AT-B77-15a/b` arms drive the payload by click; Inc-7 re-runs the zero-click form | **edit** |
| RC-M1 | BLUF row 7 → `[49,17]` | **edit** |
| RC-M2 | Re-measure `:171-180` and `C-77-l` item 4 with the bounded producer; state the out-of-domain degradation rule | **edit + one sentence of design** |
| Rm-1 / Rm-2 | stale labels | **edit** |
| **RC-2** | Give `HLR-112` a domain and say what the ruler promises out of it; drop the withdrawn-`LLR-111.8` premise from `LLR-112.2` | **small design — one decision** |

RC-2 is the only item requiring a judgement rather than a correction, and it is the same judgement already
made once for `HLR-111`. Applying the same pattern to `HLR-112` would close it.

---

## 9 · Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Each rev-2 blocker verified **gone, not relocated** | ✓ | §1 + §6.2 residue sweep — one relocation found (RC-2) |
| Else-clause executed on `case_08`, both regimes | ✓ | §2.1 — no raise, 801/801 rows |
| In-domain universals evaluable for every in-domain fixture | ✓ | §2.1 — 16 of 17, max demand 24 vs 50 ceiling |
| `C-77-l` completeness audited against all six defects | ✓ | §6.2 table — complete; one item needs re-measuring |
| `AT-B77-02` mutation verified real | ✓ | §2.3 |
| `[49,17]` verified independently | ✓ | §2.3 — sum 66; `[37,13]` sum 50 |
| Whole-document 60-sum sweep | ✓ | §2.4 — 6 hits, 5 correctly labelled, 1 stale |
| Every payload names its method | ✓ | §2.4 |
| `AT-B77-09` label accurate | ✓ | `:239` correct; `:445` stale (minor) |
| Increment plan ≤5 files, dependency-sound, no regressed regime | ✓ | §6 — counts verified, one unreachable gate (RC-3) |
| Disposition classified edit vs design | ✓ | §8 |
| Nothing manufactured | ✓ | §7 |
