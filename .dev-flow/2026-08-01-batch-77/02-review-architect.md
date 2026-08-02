# Phase-2 cross-agent review — ARCHITECT lane — batch `2026-08-01-batch-77`

**Under review:** `.dev-flow/2026-08-01-batch-77/01-requirements.md` (578 lines, consolidated Phase-1 artifact)
**Reviewer:** architect (did **not** author the document) · **Branch:** `claude/batch-77-memmap-variant-a` @ `37a83e1`
**Lens:** completeness · ambiguity · contradiction · US→HLR→LLR derivation · *does the design close the measured defect*
**Method:** every verdict below is executed on this tree with `PYTHONDONTWRITEBYTECODE=1` (C-46). Probes:
`scratchpad/arch2_probe.py`, `arch2_design.py`, `arch2_inc.py`, `arch2_golden.py`, `arch2_threshold.py`, `arch2_prg.py`.
The six operator rulings R1–R6 are **not re-litigated**; findings below concern how the document *implements* them.

---

## VERDICT: **BLOCK** — 7 blockers, 5 majors, 3 minors.

The central one is not a wording defect. **The design as specified does not satisfy `HLR-111` on a fixture
that ships in this repository** (`examples/case_00_public/prg.s19`, 11 ranges → 14 runs). It closes the
defect on the batch's own 5-region fixture and on nothing wider. The requirement set has an
output-shaped acceptance over an **unbounded allocation** — the exact defect class batch-74 already paid for.

---

## 1 · What I verified and found SOUND

Stated first so the blockers are read against a fair baseline.

| Mandatory check | Verdict | Executed evidence |
|---|---|---|
| **N-1** — the two regimes redden on DIFFERENT limbs | ✅ **CONFIRMED, exactly as documented** | `arch2_probe.py`, transcript §2.1 |
| **N-2** — geometry unsettled after one `pilot.pause()` | ✅ **CONFIRMED** — 17 of 97 traces read a transient first value (`68`@80×24 11/60 + 6/25; `23`@120×30 3/12) | transcript §2.2 |
| **`should`/`debería` as a modal inside a Statement** | ✅ **CLEAN — zero occurrences anywhere in the document** | `grep -n -i "should\|debería\|debe "` → no match |
| **`shall` outside Statement lines** | ✅ clean — 3 hits, all in the declared exemptions (L7 header, L504 quoted requirement text, L577 checklist) | |
| **ID namespace `HLR-111…117`** | ✅ **NO COLLISION** across `REQUIREMENTS.md` + `tests/` + `.dev-flow/` + `docs/` + `s19_app/`. High-water **110** confirmed: `HLR-108` `tests/test_report_document_bound.py:1`, `HLR-109` `tests/test_report_length_cell.py:1`, `HLR-110` `tests/test_tui_report_attribution.py:1` | §2.5 |
| **`LLR-072.3` 6-site census** | ✅ all six reproduce: `screens_directionb.py:1239,1273,1300,2002`, `tests/test_tui_map_big.py:118`, `tests/test_tui_snapshot.py:670` (see **M-3** for sites the census omits) | §2.6 |
| **Amendment A / B "Before" verbatim** | ✅ both byte-faithful — `REQUIREMENTS.md:4789-4791` and `.dev-flow/2026-07-15-batch-47/01-requirements.md:508` | §2.6 |
| **Amendment C — every asserted observable named** | ✅ the deleted node asserts exactly two things (`test_map_click_chain.py:379` and `:385`); both appear in the retirement table | §2.7 |
| **Increment file counts ≤5** | ✅ 4 / 3 / 3 / 5 / 4 / 4 / 3 / 1 | §7 |
| **Design closes the defect *on the batch's own fixture*** | ✅ **YES** — at both regimes, with the 5-region sparse fixture | §2.3 |
| **Does it merely relocate the problem (all widths 1 at 21 cols)?** | ❌ **not on the 5-region fixture** — `[4,4,4,3,1]`, discriminating. **But yes from 10 runs upward** — see **B-1/B-2** | §2.3, §2.4 |

---

## 2 · Executed transcripts

### 2.1 — N-1 independently reproduced (finding is TRUE)

```
==========================================================================
N-1 CHECK: per-limb verdicts at settled geometry (3 pauses)
==========================================================================

size=(80, 24)  bar.region.width=66
  (run_bytes, visible_cols) = [(256, 1), (256, 1), (256, 1), (200, 1), (62, 1)]
  visible>=1 = True   monotone = True   strict = False
  outside_count = 0
  CONJUNCTION   = False

size=(120, 30)  bar.region.width=21
  (run_bytes, visible_cols) = [(256, 1), (256, 1), (256, 1), (200, 0), (62, 0)]
  visible>=1 = False  monotone = True   strict = True
  outside_count = 2
  CONJUNCTION   = False
```

The document's claim holds byte-for-byte: at 80×24 the conjunction reddens on `strict`; at 120×30 it
reddens on `visible≥1` while `strict` is GREEN because two runs clip to `0` and `1 > 0`.
**`AT-B77-01` must remain a single three-way conjunction — confirmed, not a finding.**
(But see **M-1**: which of two readings of the `strict` clause is meant changes this rationale.)

### 2.2 — N-2 independently reproduced; the mandated helper does NOT match its own rationale

97 traces total, each an independent `App.run_test`, reading `bar.region.width` after each `pilot.pause()`:

```
80x24, 60 trials x 4 reads
  (66, 66, 66, 66)         x49
  (68, 66, 66, 66)         x11
  traces with TWO consecutive 68s (would defeat the specified helper): 0/60
  traces whose first read != settled value: 11/60

80x24, 25 trials x 4 reads
  distinct traces: Counter({(66, 66, 66, 66): 19, (68, 66, 66, 66): 6})

120x30, 12 trials x 6 reads
  trace=[23, 21, 21, 21, 21, 21]  x3       trace=[21, 21, 21, 21, 21, 21]  x9
  runs where the SPECIFIED helper returns a non-settled value: 0/12
```

The *phenomenon* is real (17/97). The *helper as specified* converged in **97/97**. See **B-7** for why
that is still a blocker: the LLR's own rationale asserts a trace that would defeat it, and I cannot
reproduce that trace.

### 2.3 — The specified design, implemented and rendered (does it close the defect?)

`arch2_design.py` patches `MemoryMapPanel._build_band_widgets` to exactly what `LLR-111.1` + `LLR-111.2`
specify — widths scaled to the **measured** `.map-band-bar` container, gaps folded to a fixed **1** column,
run widths proportional to mapped bytes over `avail = bar_w − n_gaps` — then renders through the shipped
surface and measures **painted** geometry.

```
A. SPECIFIED DESIGN, 5-region sparse fixture (the charter fixture)
size=(80, 24)  bar.width=66
  (run_bytes, visible_cols) = [(256, 15), (256, 15), (256, 15), (200, 12), (62, 4)]
  gap marker widths         = [1, 1, 1, 1]
  visible>=1=True  monotone=True  strict=True  outside=0
  AT-B77-01 conjunction = True    AT-B77-03 (outside==0) = True

size=(120, 30)  bar.width=21
  (run_bytes, visible_cols) = [(256, 4), (256, 4), (256, 4), (200, 3), (62, 1)]
  gap marker widths         = [1, 1, 1, 1]
  visible>=1=True  monotone=True  strict=True  outside=0
  AT-B77-01 conjunction = True    AT-B77-03 (outside==0) = True
```

**On the batch's own fixture the design works and does not relocate the problem.** `P-38` is TRUE and
R-5's `fold=1` choice is vindicated. That is the good news, and it is the end of it.

### 2.4 — The same design against a SHIPPED example fixture — **it fails at both regimes**

```
fixture=examples/case_00_public/prg.s19  ranges=11  mapped=3968

--- SPECIFIED design (container basis + 1-col fold) ---
  batch-77  size=(80, 24)  bar=66  runs=14 gaps=10
      (bytes,visible) = [(1,1),(2,1),(10,1),(2,1),(3,1),(768,11),(512,7),(2560,36),
                         (38,1),(60,0),(8,0),(1,0),(1,0),(2,0)]
      visible>=1=False monotone=False strict(EXISTS)=True strict(FORALL)=False outside=9
      AT-B77-01 (exists-reading)=False  AT-B77-03=False
  batch-77  size=(120, 30) bar=21  runs=14 gaps=10
      (bytes,visible) = [(1,1),(2,1),(10,1),(2,1),(3,1),(768,2),(512,1),(2560,7),
                         (38,1),(60,0),(8,0),(1,0),(1,0),(2,0)]
      visible>=1=False monotone=False strict(EXISTS)=True strict(FORALL)=False outside=10
      AT-B77-01 (exists-reading)=False  AT-B77-03=False
```

Five runs invisible at 80×24 and five at 120×30; **9 and 10 segments painted outside the container.**
Sweep of the failure onset at 120×30 (bar = 21):

```
  regions=4   visible=[5,5,4,4]                     outside=0   OK
  regions=5   visible=[4,3,3,3,3]                   outside=0   OK
  regions=6   visible=[3,3,3,3,3,1]                 outside=1   *** VIOLATED ***
  regions=7   visible=[2,2,2,2,2,2,2]               outside=0   OK
  regions=8   visible=[2,2,2,2,2,2,2,0]             outside=1   *** VIOLATED ***
  regions=10  visible=[1,1,1,1,1,1,1,1,1,1]         outside=0   (all widths 1 -> strict limb DEAD)
  regions=12  visible=[1,1,1,1,1,1,1,1,1,1,1,0]     outside=2   *** VIOLATED ***
```

### 2.5 — ID namespace (clean)

```
$ grep -rnoE "HLR-11[1-7]" REQUIREMENTS.md tests/ docs/ s19_app/ .dev-flow/ | grep -v 2026-08-01-batch-77
.dev-flow/state.json:137:HLR-116          <- batch-77's own decision log
$ grep -rnoE "LLR-11[1-7]" ... | grep -v 2026-08-01-batch-77
.dev-flow/state.json:136:LLR-111  :137:LLR-116  :141:LLR-111   <- batch-77's own
```

### 2.6 — Citation census (six sites verified, plus omissions → M-3)

```
s19_app/tui/screens_directionb.py:1239 :1273 :1300 :2002      (LLR-072.3)
s19_app/tui/screens_directionb.py:1274 _TICK_COUNT = 5   :1312 :1313 usages
tests/test_tui_map_big.py:118 (LLR-072.3)   :140 assert len(ticks) == 5
tests/test_tui_snapshot.py:670 (LLR-072.3)
REQUIREMENTS.md:4790 (R-TUI-072)   :4191 (R-TUI-060 duplicate clause)
--- NOT in the document's census ---
.dev-flow/2026-07-15-batch-47/01-requirements.md:580   (C-29 geometry list)
.dev-flow/2026-07-15-batch-47/01-requirements.md:651   (LLR-072.3 validation row)
.dev-flow/2026-07-15-batch-47/03-increments/increment-06.md:23
.dev-flow/2026-07-15-batch-47/06-docs/traceability-matrix.md:54
    -> "5 ticks @ 0/25/50/75/100 %"  — restates the RETIRED clause verbatim
.dev-flow/BACKLOG-CODE.md:53  -> still asserts LLR-072.3 has "ZERO definitions"
```

### 2.7 — Increment ordering / focus precondition

```
2. FOCUS: does HLR-116 (Inc-5) need LLR-115.1 can_focus (Inc-6)?
  app.focused before                                 = RailItem
  RegionRow.can_focus / .focusable                   = (False, False)
  app.focused after row.focus() with can_focus=False = RailItem     <- no-op
  app.focused after row.focus() with can_focus=True  = RegionRow
```

```
1. Inc-1a IN ISOLATION (LLR-111.1 only, NO gap fold) -- can its gate go GREEN?
size=(80, 24) bar.width=66
  (run_bytes, visible_cols) = [(256,1),(256,1),(256,1),(200,1),(62,0)]
  gap widths = [8, 8, 16, 33]   sum(gaps)=65
  visible>=1=False monotone=True strict=True outside=2
  AT-B77-01 = False   AT-B77-03 = False
size=(120, 30) bar.width=21
  (run_bytes, visible_cols) = [(256,1),(256,1),(256,1),(200,1),(62,0)]
  gap widths = [3, 3, 5, 10]   sum(gaps)=21
  visible>=1=False monotone=True strict=True outside=2
  AT-B77-01 = False   AT-B77-03 = False
```

### 2.8 — The golden payload's basis

```
A. LLR-111.4 golden payload, SHIPPED producer (pre-change tree)
  size=(80, 24)  bar.region.width=66  content=[45, 15] visible=[45, 15]  sum(content)=60
  size=(120, 30) bar.region.width=21  content=[45, 15] visible=[21, 0]   sum(content)=60

  _BAND_BAR_WIDTH = 60
  round(60*768/1024)=45  round(60*256/1024)=15  -> [45,15]      <- MATCHES the document
  round(66*768/1024)=50  round(66*256/1024)=16  -> [50,16]      <- the CONTAINER basis
```

### 2.9 — The C-31 completeness guard

```
C-31 guard: {seg.region_start} == {start for start,_ in loaded.ranges}
  len(run starts)   = 14
  len(range starts) = 11
  EQUAL?            = False
  renderer starts that are NOT range starts: ['0xee08', '0xf008', '0xfa08']
```

---

## 3 · BLOCKERS

### B-1 — The specified design does not satisfy `HLR-111` on a fixture that ships in this repo

**Where:** `01-requirements.md:135` (HLR-111 Statement), `:139` (numeric pass threshold), `:293` (LLR-111.1), `:299` (LLR-111.2).
**Evidence:** §2.4. `examples/case_00_public/prg.s19` — 11 ranges, 14 merged runs, 10 gaps.
Under the design exactly as specified: **5 runs invisible at 80×24, 5 at 120×30, 9 and 10 segments
painted outside the container**, and monotonicity fails (a 60-byte run paints 0 columns while a 2-byte
run paints 1).

`HLR-111`'s Statement is an unconditional universal — *"shall paint at least one visible column for
**every** mapped region … and **shall not** paint **any** segment outside its container"*. The document's
sole feasibility evidence (`P-38`, `:105`) is computed for **one** fixture with **five** runs. The
generalisation from that fixture to the universal was never executed, and it does not hold.

This is not a Phase-3 implementation detail. It is the requirement being unsatisfiable by the design the
requirement itself sketches, on data already in the repository.

**What would close it:** either bound `HLR-111`'s universals with a stated feasibility precondition
(`n_runs + n_gaps ≤ container_width`) plus a stated degradation policy for the excess, **or** carry a
normative allocation LLR that guarantees `Σ widths + Σ gap markers ≤ bar.region.width` (see B-2).

### B-2 — Clauses 2 and 5 of `HLR-111` are jointly unsatisfiable, and no LLR bounds the allocation

**Where:** `01-requirements.md:135`, boundary catalog `:146` ("more runs than container columns, `TC-B77-03`").
**Evidence:** §2.4. At `bar = 21` the design already violates at **6 regions**; above **11 runs**
(`n_runs + n_gaps = 2n−1 > 21`) satisfaction is arithmetically impossible for *any* implementation.

Two distinct defects sit on the same line:

| | Defect | Executed |
|---|---|---|
| (i) | **Unbounded allocation.** `max(1, round(avail · run/mapped))` is summed with no budget check. At 8 regions in a 21-column bar a feasible allocation *exists* (`[2,2,2,2,2,2,1,1]` + 7 gaps = 20 ≤ 21) yet the design emits 23 columns and clips. No LLR states a normalization/budget rule. | §2.4, `regions=8` |
| (ii) | **Genuine infeasibility.** Above 11 runs the two clauses cannot both hold. | §2.4, `regions=12` |

`TC-B77-03` **names this boundary and assigns it no expected result.** A boundary case with no oracle is
a catalog entry, not a test — and it is the one case where the requirement contradicts itself.

This is batch-74's asset restated against this batch: *an output-shaped predicate cannot bound an
allocation.* `AT-B77-03` is output-shaped. `LLR-111.1`/`.2` carry the basis and the marker width; neither
carries the bound.

### B-3 — Inc-1a's stated gate is unreachable, and Inc-1a alone **regresses** the 80×24 regime

**Where:** `01-requirements.md:535` — *"**Inc-1a** … `LLR-111.1` + `LLR-111.6` … `AT-B77-01`, `AT-B77-03`"*
and `:546` — *"**Inc-1a precedes Inc-1b precedes Inc-2**"*.
**Evidence:** §2.7 block 1. With `LLR-111.1` alone (container basis, gaps still proportional — the fold is
`LLR-111.2`, allocated to **Inc-2**):

- `AT-B77-01` = **False** at both regimes; `AT-B77-03` = **False** at both.
- Worse: at **80×24**, which is fully correct today (`outside = 0`, all five visible), Inc-1a alone
  produces `outside = 2` and one invisible run. **Gap widths become `[8,8,16,33]` = 65 of 66 columns.**

Inc-1a as cut cannot pass its own gate and would land a regression if it merged alone. The gate discipline
in §5.3 (*"0 blocker findings at the merge gate"*, *"every gate AT demonstrated RED pre-change"*) is
unsatisfiable for this increment.

**What would close it:** merge Inc-1a and Inc-2 into one increment (4 files: `screens_directionb.py`,
`styles.tcss`, `tests/test_tui_map_big.py`, `tests/test_map_click_chain.py` — still ≤5), or move
`AT-B77-01`/`AT-B77-03` to Inc-2's gate and give Inc-1a a gate it can actually reach.

### B-4 — `LLR-115.1` (`can_focus`) is allocated to Inc-6 but is a precondition of Inc-5's own gate; and one clause is owned by two HLRs

**Where:** `01-requirements.md:383` (`LLR-115.1`, under HLR-115 → **Inc-6**), `:238` (`HLR-116` Statement:
*"the panel **shall** make the region rows focusable"*), `:241` (HLR-116 threshold: *"`app.focused.region_start` equals it"*),
`:402` (`LLR-116.5`), `:540-541` (increments), `:545` (ordering rationale).
**Evidence:** §2.7 block 2 — `RegionRow.can_focus` is `False`, `.focusable` is `False`, and `row.focus()`
is a **no-op** until `can_focus` is flipped.

1. **The ordering claim itself is CORRECT in direction** — `HLR-116` does own the entry path and
   `AT-B77-08` is unreachable without it. That part of §7 stands.
2. **But the LLR allocation contradicts it.** Inc-5 (HLR-116 + HLR-117) must satisfy
   `app.focused.region_start == resolved_selection` (`LLR-116.5`) — impossible without `can_focus = True`,
   which the plan assigns to Inc-6. Inc-5's gate cannot go green as cut.
3. **Duplicate ownership.** "rows become focusable" is stated normatively **twice** — in `HLR-116`'s
   Statement and in `LLR-115.1`. The functional chain (§5.2, `:450`) therefore cannot say which LLR
   discharges it. `HLR-115 → LLR-115.1` and `HLR-116 → (its own clause 1)` both claim it.

**What would close it:** move `LLR-115.1` under HLR-116 (it is the entry mechanism, not the keyboard
behaviour) and into Inc-5, and delete the focusability clause from whichever of the two statements does
not keep it.

### B-5 — The C-31 completeness guard in `HLR-111`'s Acceptance is FALSE on a shipped fixture

**Where:** `01-requirements.md:144` — *"assert `{s.region_start for s in query(BandSegment)} == {start for start,_ in loaded.ranges}` … The set comes from the fixture's ranges, never from what the renderer emitted."*
**Evidence:** §2.9 — on `prg.s19` the renderer emits **14** run starts against **11** range starts;
`0xee08`, `0xf008`, `0xfa08` are band-change boundaries **inside** a range.

`_merge_band_runs` splits on band change *as well as* address discontinuity — the document says so itself
at `:400` (*"a re-merge can change how many runs precede the selected one … splits on band change **or**
address discontinuity"*) and then specifies a guard that assumes runs ≡ ranges. The guard would red-flag
**correct** behaviour on any image whose region spans two entropy bands.

It happens to hold on the batch's synthetic fixture because every region there is single-band. That is
exactly the shape of vacuity this project catalogs: a predicate that is only true of the fixture.

**What would close it:** derive the expected set from the *runs* oracle (`_merge_band_runs` over the
fixture's own windows), or weaken to a coverage assertion — every range start is *covered by* some
segment's `[region_start, region_end)`.

### B-6 — The document's global evidence promise is FALSE; `LLR-111.4`'s payload is the retired 60-basis

**Where:** `01-requirements.md:9-10` — *"**All transcripts in this document were RE-EXECUTED after the
rulings.** Nothing measured under the old `_BAND_BAR_WIDTH` basis is carried forward."*
Falsified at `:322-327` — *"Measured payload **@80×24, container 66**: … `len= 45` … `len= 15`"* — and at
`:104` (`P-37`).
**Evidence:** §2.8. `45 + 15 = 60 = _BAND_BAR_WIDTH`, the **retired** constant. Under the container basis
the same fixture at 66 columns yields `[50,16]`.

Three consequences:

1. The header claim is a truth-apt proposition and it is **FALSE**. Per the document's own gate rule
   (`:112`, *"❌ blocks"*) and C-43, that blocks.
2. `LLR-111.4` (`:320`) requires the golden to be captured **after** the width basis settles (Inc-1b,
   after Inc-1a). The bytes Inc-1b will actually capture are therefore **not** `[45,15]`. A figure
   printed in the requirement, under a heading naming container 66, that the implementer will
   reasonably paste into the test, is wrong by 5 and 1 columns respectively.
3. `P-37`'s **conclusion** ("the second run is invisible today even with no gaps") is nonetheless
   **TRUE** — I reproduce `visible=[21,0]` @120×30. Only the label on the number is wrong. Fix the label,
   keep the finding.

### B-7 — `LLR-111.6`'s normative threshold is contradicted by its own rationale, and that rationale is unreproduced

**Where:** `01-requirements.md:344-348`.
- Threshold (`:347`): *"the helper returns only when **two consecutive reads** of `bar.region.width` agree"*.
- Rationale (`:346`): *"traced live as `68 → 68 → 66`"*.

If the traced sequence is real, the specified stopping rule **returns 68** — a non-settled value — and the
mandated helper is unsound at precisely the moment it is needed. The two halves of one LLR cannot both hold.

**Evidence:** §2.2. In **97 independent traces** I observed the transient 17 times and **never twice in
succession** (`traces with TWO consecutive 68s: 0/60`). Every trace has the form
`(transient, settled, settled, …)`. So:

- the *phenomenon* (N-2) is **TRUE** and the settling requirement is justified;
- the *specific trace* `68 → 68 → 66` is **UNDECIDABLE** — asserted as executed evidence, not reproducible
  on this tree, and load-bearing for whether the mandated helper works.

Per C-43 as the document itself applies it (`:112`), UNDECIDABLE blocks. Either produce the transcript for
`68 → 68 → 66` — in which case the threshold must change to a stronger criterion (e.g. *N consecutive
agreeing reads*, or *discard the first read then require two*) — or retract the trace and keep the
two-read rule, which my 97 traces support.

Note the LLR's acceptance line (`:348`, *"no geometry AT calls `pilot.pause()` exactly once"*) is a
**different and weaker** rule than its threshold. Two normative criteria for one helper is itself an
ambiguity; pick one.

---

## 4 · MAJORS

### M-1 — The `strict` limb is quantifier-ambiguous, and the ambiguity is load-bearing for N-1

**Where:** `01-requirements.md:135` — *"shall emit visible widths that are non-decreasing in mapped bytes
**with at least one strictly greater pair whenever two runs differ in mapped size**"*.

Two readings:

| Reading | Formalisation | `strict` @120×30 today |
|---|---|---|
| **R∃** | if ∃ two runs of differing size, then ∃ ≥1 strictly-ordered pair | **True** (`1 > 0`) |
| **R∀** | every pair of differing size is strictly ordered | **False** (200 B → 0 cols, 62 B → 0 cols) |

The document's own transcript (`:150-151`) and `P-32` use **R∃**. Under **R∀**, N-1's headline —
*"the two regimes redden on different limbs"* — **collapses**: both regimes would redden on `strict`, and
120×30 would additionally redden on `visible`. The conclusion (keep one conjunction) survives; the stated
rationale does not.

The reading also changes what the design must deliver: §2.4 shows `strict(FORALL) = False` on `prg.s19`
under the specified design at both regimes.

**Fix:** state the quantifier in the Statement, not in the transcript.

### M-2 — No normative statement of the allocation rule

`LLR-111.1` (`:293`) fixes the **basis** (measured container) and forbids `_BAND_BAR_WIDTH`. It does not
state the **denominator** or the **allocation function**. The rule the batch actually depends on —
run widths proportional to *mapped bytes* over `avail = bar_width − n_gaps × fold`, replacing today's
*address-span* denominator — appears **only** in `LLR-111.2`'s **informative** rationale (`:302-308`).

The naive discharge of `LLR-111.1` as written (swap `60` → `bar_w`, keep `total_span`) is exactly what
§2.7 block 1 measures, and it is a regression. `AT-B77-01` does catch it, so this is not itself a hole —
but a requirement whose only correct reading lives in a rationale block is one refactor away from being
lost. Promote the denominator change into a normative Statement.

### M-3 — `LLR-112.3` says "every surviving citation" and then enumerates a census that omits four

**Where:** `:364` (Statement: *"shall update **every** surviving citation of the retired clause"*),
`:365` (census: six sites), `:366` (threshold: *"6 sites reconciled"*).
**Evidence:** §2.6. Not in the census:

- `.dev-flow/2026-07-15-batch-47/06-docs/traceability-matrix.md:54` — **restates the retired clause
  verbatim** (`5 ticks @ 0/25/50/75/100 %`). Since Amendment B edits `01-requirements.md:508` **in place**,
  batch-47's own artifact set will self-contradict after Inc-3.
- `.dev-flow/2026-07-15-batch-47/01-requirements.md:651` (the LLR-072.3 validation row) and `:580`.
- `.dev-flow/2026-07-15-batch-47/03-increments/increment-06.md:23`.

Either scope the Statement to shipped source + `REQUIREMENTS.md` (defensible — historical batch artifacts
are a record, not a contract) or extend the census. As written, Statement and census disagree, and the
threshold "6" is asserted rather than derived.

### M-4 — The retracted `LLR-072.3` "dangling" claim is still live on disk and no increment owns it

`:367` says *"The Phase-0 'dangling citation' carry is **void**."* But:

- `.dev-flow/BACKLOG-CODE.md:53` still asserts *"`LLR-072.3` — an id with **ZERO definitions**"* and
  *"a **dangling reference**"* — a false statement in the **live** Lane-A queue.
- `PLAN.md:171-173` still lists it under **§9 Out-of-scope carries**.

No increment in §7 lists `.dev-flow/BACKLOG-CODE.md` or `PLAN.md`. Per the standing backlog-carryover
rule, reconciliation is a mandatory close step — name the file in an increment or in §5.3.

### M-5 — `AT-B77-02` is owned by two increments

`:536` Inc-1b *captures* the golden; `:537` Inc-2's gate is *"`AT-B77-02` proven RED under mutation"*.
C-18/C-21 want one AT owned by exactly one increment. Every other AT maps cleanly. State which increment
owns the node and which merely re-runs it.

---

## 5 · MINORS

### m-1 — Amendment C leaves the `160×48` magic size unexplained
`:526` instructs dropping the limitation note from the two AC-6 pointer tests. That note
(`tests/test_map_click_chain.py:220-227`) is the **only** justification for those tests running at
`160×48` instead of the module's `120×30`. After R1 the justification is false. Dropping the note without
ruling on the size leaves an unexplained constant — and the batch loses its only coverage of
band-segment clickability at `120×30`, which is precisely the regime R1 repairs. Consider reverting those
two tests to `120×30` in Inc-1a and saying so in the amendment.

### m-2 — "the same measurement, opposite expected value" is loose
`:525`. The deleted node measures `outside_count` on `_two_band_loaded` **@120×30**; `AT-B77-03` measures
it on the batch's 5-region sparse fixture. Same predicate, different fixture. Name the fixture in the
retirement table so the inversion claim is checkable.

### m-3 — Seven of fourteen ATs are only implicitly assigned to an increment
`AT-B77-04/05/06/08/10/11/12` are not named in any §7 gate cell. They are inferable from the HLR→Inc
mapping, but the gate column is what an implementer reads.

---

## 6 · Premise evaluation (C-43) — this review's own table

| # | Proposition extracted from the document | Verdict | Basis |
|---|---|---|---|
| A-1 | N-1: the two regimes redden on different limbs | ✅ **TRUE** | §2.1, reproduced exactly |
| A-2 | N-2: geometry unsettled after one `pilot.pause()` | ✅ **TRUE** | §2.2, 17/97 |
| A-3 | LLR-111.6's trace `68 → 68 → 66` | ❌ **UNDECIDABLE** | §2.2, 0/60 double-68 → **B-7** |
| A-4 | P-31: container is 66 @80×24 / 21 @120×30 settled | ✅ **TRUE** | §2.1, §2.3 |
| A-5 | P-37: unequal dense fixture's 2nd run invisible @120×30 | ✅ **TRUE** | §2.8, `visible=[21,0]` |
| A-6 | P-38: R1 achievable inside the real container **at both regimes** | ⚠️ **TRUE only for the 5-run fixture**; **FALSE** as a general claim | §2.3 vs §2.4 → **B-1** |
| A-7 | L9-10: nothing measured under the old basis is carried forward | ❌ **FALSE** | §2.8, `45+15=60` → **B-6** |
| A-8 | `HLR-111` is satisfiable as stated | ❌ **FALSE** above 11 runs at 21 cols | §2.4 → **B-2** |
| A-9 | The C-31 guard `{run starts} == {range starts}` | ❌ **FALSE** on `prg.s19` | §2.9 → **B-5** |
| A-10 | §7 is dependency-ordered | ❌ **FALSE** — Inc-1a, and Inc-5/Inc-6 | §2.7 → **B-3**, **B-4** |
| A-11 | "Inc-5 must precede Inc-6" | ✅ **TRUE** (the *claim*; the *allocation* is not) | §2.7 |
| A-12 | HLR high-water is 110; 111–117 free | ✅ **TRUE** | §2.5 |
| A-13 | P-39: the PIN test's docstring sanctions its own deletion | ✅ **TRUE** | `test_map_click_chain.py:379-389` |
| A-14 | Six `LLR-072.3` citation sites | ⚠️ **TRUE for source+tests, incomplete for `.dev-flow/`** | §2.6 → **M-3** |
| A-15 | Amendment A/B "Before" texts are verbatim | ✅ **TRUE** | §2.6 |

---

## 7 · What I am NOT flagging

- **The six rulings.** R1–R6 are settled and, apart from the items above, are implemented consistently.
  R-5's `fold=1` is genuinely the right call for the 5-run fixture and the evidence for it holds.
- **`AT-B77-01` as a single conjunction.** Correct, and N-1's reasoning survives review (subject to M-1).
- **`AT-B77-04`'s `⊇` lower bound** (`:175`). `set() <= admissible` really is `True`; the pairing is right.
- **`AT-B77-13`/`14` as two nodes** (`:249-254`). The per-arm mutation table is the strongest single piece
  of derivation in the document — each mutation reddens exactly one arm. Keep it as the template.
- **C-40 discipline generally.** Absence-with-presence pairing is applied consistently at `:190`, `:210`,
  `:244`, `:373`, `:398`. No vacuous absence clause found.
- **B3 / colour-channel / engine-frozen invariants.** Nothing in the design touches them.
- **Normative keyword discipline.** Clean — nothing to report.

---

## 8 · Recommended disposition

**Return to Phase 1 for a bounded revision.** Five of the seven blockers are cheap:

| Blocker | Cost | Change |
|---|---|---|
| B-6 | trivial | Relabel `[45,15]` as the pre-change 60-basis; state the expected post-Inc-1a payload is re-derived at capture, not printed here |
| B-7 | trivial | Retract the `68 → 68 → 66` trace **or** strengthen the threshold; collapse the two competing helper criteria into one |
| B-5 | small | Re-derive the completeness set from the runs oracle, or weaken to coverage |
| B-3 | small | Merge Inc-1a+Inc-2, or move `AT-B77-01`/`AT-B77-03` to Inc-2's gate |
| B-4 | small | Move `LLR-115.1` under HLR-116/Inc-5; delete the duplicate focusability clause |
| **B-2** | **design** | Add a normative allocation bound (`Σ widths + Σ markers ≤ bar.region.width`) as `LLR-111.7`, and give `TC-B77-03` an expected result |
| **B-1** | **design + operator** | `HLR-111`'s universals need a feasibility precondition and a stated degradation policy. **This is an operator call** — what should the bar show when the image has more runs than the container has columns? Candidate answers: (a) merge the smallest runs into an aggregate segment; (b) cap the run count and mark the remainder with an overflow glyph; (c) accept the container width as a hard budget and declare `visible≥1` conditional on `n_runs + n_gaps ≤ width`. |

B-1 is the only one that reopens a decision. It is also the one that determines whether this batch ships a
map that is correct on the shipped `examples/` corpus or only on its own fixture.

---

## 9 · Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Every finding classified blocker/major/minor | ✓ | §3 (7) · §4 (5) · §5 (3) |
| Every blocker carries an executed transcript | ✓ | §2.1–2.9, each blocker cites its block |
| Premises ruled TRUE / FALSE / UNDECIDABLE | ✓ | §6, 15 propositions |
| `should` / `debería` grep executed | ✓ | §1, zero hits |
| ID-namespace union check executed | ✓ | §2.5 |
| Deleted test read in full, not summarised | ✓ | `tests/test_map_click_chain.py:342-389` |
| Design verified by EXECUTION, not argument | ✓ | §2.3, §2.4 — the design implemented and rendered through the shipped surface |
| Counter-fixture is one that ships in the repo | ✓ | `examples/case_00_public/prg.s19` |
| Nothing manufactured | ✓ | §7 lists what I checked and found sound |
| No operator ruling re-litigated | ✓ | §7 first bullet |
