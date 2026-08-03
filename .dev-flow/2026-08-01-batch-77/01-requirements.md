# Requirements Document — s19_app — batch `2026-08-01-batch-77` — **REVISION 7**

> ⚠️ **Header hygiene, recorded not silently fixed.** This header read **REVISION 5** while the body
> carried revision-6 content (Amendment D, the gap-count correction, the `LLR-112.3` estimate). The
> body was edited and the header was not — the same *"applied where it was noticed, not carried to
> everything depending on it"* failure §6.4a exists to catch, committed on the document's own first line.
> **Revision 7** adds §6.5 **Amendment E** (`TC-519`), closes the `LLR-112.3` census with executed
> figures, discharges carry **C-77-i** and registers **C-77-m**.

**Objective:** Memory Map redesign — Variant A (gap-fold band bar) + cross-cutting fixes S-1…S-7
**Branch:** `claude/batch-77-memmap-variant-a` · **Base:** `origin/main` @ `f8747b8`
**Revision 5** supersedes revision 4 after the **final architect re-gate** (*"this batch does not need re-scoping. It needs an edit pass"* — 1 blocker, 1 major, 1 minor, all edits). **Revision 4** superseded revision 3 after **gate 3** (security CLEAN · QA 0 blockers · architect 3, all one defect in three places). **Revision 3** superseded revision 2 after the **Phase-2 re-gate** (architect 6 · QA 1 · security 1 new blockers) and **operator rulings R-10 (descope aggregation to batch-78) and R-11 (pull the ANSI scrub in)**.
**All three lanes discharged every revision-1 blocker by execution.** R-7 is verified sound: the bar widens 21→50, `prg.s19` fits **exactly** at both regimes, 15 further shipped fixtures + 3 synthetic classes pass, and **no regime regresses**. That is not reopened here.
**7 of the 8 re-gate blockers were in the AGGREGATION path**, which R-10 removes from this batch.
**Consolidates:** `00-measurements.md` · `01-requirements-architect.md` · `01b-qa-validation.md` · `02-review-architect.md` · `02-review-qa.md` · `02-review-security.md`
**Rulings applied:** R1–R11 (authoritative, not re-litigated)
**Revision 4's theme is PROPAGATION.** Gate 3 found the same failure that produced defects in all three rounds: *a change applied where it was noticed and not carried to everything depending on it.* R-10's domain reached `HLR-111`'s Statement but not its LLR children and not `HLR-112`. §6.4 now carries an **evidenced propagation sweep** over R-1…R-11, not a claim that one was done · **Normative keyword:** `shall`, only inside HLR/LLR **Statement** lines.

> **Evidence promise, scoped this time.** Revision 1 claimed *"all transcripts re-executed; nothing measured
> under the old basis is carried forward"* and **that claim was FALSE** (architect B-6). Revision 2 makes a
> narrower, checkable claim: **every numeric payload below is either (a) executed against this tree at
> revision 2 with its transcript inline, or (b) explicitly labelled `predicted — execute at Phase N`.**
> No third category. Probes ran read-only with `PYTHONDONTWRITEBYTECODE=1` (C-46).

---

## BLUF — what revision 2 changes

**The design wall is closed by R-7, and closing it took two normative parts, not one.**

| # | Change | Blocker(s) closed |
|---|---|---|
| **1** | 🆕 **The subject of every width clause is the RUN, not the range.** `_merge_band_runs` splits on band change *or* address discontinuity, so one range can yield many segments. Executed: **1 range → 2 `BandSegment`s**. Every clause, guard and oracle re-pointed. | arch **B-5**, QA **B-1** |
| **2** | 🆕 **The bar is widened by CSS before anything is aggregated** (R-7/1). Measured: `.map-band-bar` goes **21 → 50** columns @120×30. **80×24 is unaffected (66).** | arch **B-1** |
| **3** | 🆕 **A normative allocation bound** (`LLR-111.7`) — `Σ run widths + Σ gap markers ≤ bar.region.width`, enforced in the producer. **Widening alone does NOT fix `prg.s19`** — executed, it still leaves 5 runs invisible at bar=50. | arch **B-2** |
| **4** | ❌ **Aggregation DESCOPED to batch-78 (R-10).** `LLR-111.8`, `AT-B77-17` and the `+N more` disclosure are **withdrawn with a record**, not deleted. **7 of the 8 re-gate blockers lived in that path**, and exactly **one** shipped fixture crosses the onset while `LLR-111.7` alone fixes the other **15 of 16**. `HLR-111` now states an explicit **domain** and describes the out-of-domain case truthfully; `C-77-l` charters batch-78 with every measurement paid for. | arch **RB-1/2/3/4/6**, QA **N-1**, sec **M-3r** |
| **5** | **Increments re-cut.** Old Inc-1a was unsatisfiable *and* regressed 80×24 (`outside 0 → 2`). Container basis, bound and fold now land in **one** increment. | arch **B-3**, QA **B-2** |
| **6** | `LLR-115.1` (`can_focus`) **moved under HLR-116** and into the earlier increment; the duplicate focusability clause deleted. | arch **B-4** |
| **7** | **Golden payload re-derived — twice.** rev-1's `[45,15]` summed to **60**, the retired constant; rev-2's `[50,16]` was the right basis but **the wrong method** (plain `round()`). Through the mandated `LLR-111.7` allocator it is **`[49,17]` @bar=66 and `[37,13]` @bar=50**. Every payload now names its method. | arch **B-6**, **RM-1**, **RC-M1**, QA **M-2** |
| **8** | 🆕 **My settle trace was mis-stated and is retracted.** `68 → 68 → 66` was **two reads inside one frame** plus one after a pause — not two pauses. Executed: same-frame triples `{(66,66,66):9, (68,68,68):3}`; per-pause sequences `{(66,66,66):9, (68,66,66):3}`. **Threshold now counts pauses, not reads.** | arch **B-7** |
| **9** | **Focus predicates assert liveness**, not identity — a detached row satisfies `region_start == X`. | QA **B-3** |
| **10** | `AT-B77-09` re-authored: the gate arm now runs with focus **ON** a row (the post-R-6 default), the only state where shadowing can occur. | QA **B-4** |
| **11** | **Hostile-input acceptance REPAIRED, and the fix pulled IN (R-11).** `AT-B77-15` is split into **`AT-B77-15a`** (GATE, discharged) and **`AT-B77-15b`** (GATE from Inc-2); revision 2 recorded its control-byte limb as RED when it was **GREEN vacuously**, and its mutation was **inert** on that limb. **`LLR-116.7` now lands the C0/C1 scrub in this batch** so the normative clause is satisfiable at close. The false layout-perturbation rationale is **withdrawn explicitly**. | **security B-1r, X-1** |
| **12** | `LLR-112.2` re-authored against **zero-width/elision**, not overlap — `1fr` children cannot overlap. Executed: N=60 in W=50 → **10 zero-width ticks, 0 overlaps, rev-1 predicate GREEN**. | **security M-1** |
| **13** | Citation census **6 → 8 sites** (`legend.py:613` prose; batch-47 `traceability-matrix.md:54`). | **security M-2**, arch **M-3** |

**Nothing is left unresolved at the requirement level.** OQ-1…OQ-6 are all closed by rulings R-5, R-6, R-8, R-9 and R-10; §8's two remaining entries are Phase-3 implementation choices. **The one thing a reader must not miss:** `HLR-111` is now *smaller in scope and truer* — it holds inside a stated domain, and it says plainly that on `case_08` the bar is unreadable and batch-77 does not fix that.

---

## 1. Introduction

### 1.3 Definitions — **the one that caused three blockers**

| Term | Definition |
|---|---|
| **range** | An entry of `loaded.ranges` — a contiguous address interval the loader parsed from the image. |
| **run** ⭐ | A merged same-band region from `_merge_band_runs`, which starts a new run on **band change OR address discontinuity**. **A run is NOT a range.** One range spanning two entropy bands yields ≥2 runs. Each run is emitted as one `BandSegment` (`screens_directionb.py:1172`). |
| **gap** | Unmapped interval between consecutive runs → an inert `Static` classed `map-band-seg map-band-gap`. |
| **container** | `.map-band-bar` (`:2098`). Its `region.width` is **measured at render time**, never assumed. |
| **`visible_cols(seg)`** | `max(0, min(seg.region.right, bar.region.right) − max(seg.region.x, bar.region.x))` — the painted, clipped width. Never `len(str(seg.render()))` (pre-layout proxy, C-32). |
| **settled geometry** | A read taken after the container width is unchanged across **two successive `pilot.pause()` boundaries** — *not* two successive reads (P-45). |
| ~~aggregate segment~~ | **Withdrawn to batch-78 (R-10).** Retained here only so the withdrawal is legible: it would have been one `BandSegment` standing for ≥2 merged adjacent runs with an exact `+N more` disclosure. ~~No clause in this document depends on it.~~ **That claim was FALSE and is corrected at revision 4:** `LLR-112.2`'s sufficiency argument depended on it (arch RC-2). The reference is now removed and the argument re-derived without it. **Nothing depends on it as of revision 4** — verified by the §6.4 propagation sweep, not asserted. |

> ⭐ **This is the defect two lanes found independently.** Revision 1's §3 assumed runs ≡ ranges while its own
> `LLR-116.4` reasoned correctly that they differ. **Decision (§2.9): every width, visibility, monotonicity and
> ruler clause quantifies over RUNS.** Ranges appear only in the *coverage* guard.

---

## 2. Overall description

### 2.2 Constraints — measured at revision 2

| Constraint | Value | Evidence |
|---|---|---|
| Regimes | 80×24, 120×30 | `tests/test_tui_map_big.py:32` |
| `.map-band-bar` **before** R-7 | **66 @80×24 · 21 @120×30** | executed P-31; reproduced by two lanes |
| `.map-band-bar` **after** R-7 CSS | **66 @80×24 · 50 @120×30** | executed **P-46** |
| `#map_grid` | 66 @80×24 · 50 @120×30 | executed |
| Glance widest content row | **29 columns**, in a **28**-column box → **clips today** | executed **P-47** |
| `_BAND_BAR_WIDTH` | `60` — **retired as a width basis** (R1) | `screens_directionb.py:230` |
| Textual | 8.2.8 | executed |
| Footer | **14** `show=True` chips needing ≈ **181** columns in **78** | QA-executed |
| Engine-frozen set | off-limits, source **and** `_ENGINE_TEST_FILES` (C-27) | 0 intersections, security-verified |
| B3 | no file-derived text in bar/rows | security-verified for all four **new label surfaces**; the sink that is *not* a new label is `LLR-116.6` |

### 2.6 Source user stories
Unchanged from revision 1 except **US-77-6**, which now also owns the focus-entry path (`can_focus`) — arch B-4.

### 2.7 Premise evaluation (C-43) — revision-2 additions and corrections

Revision 1's P-16…P-43 stand except where corrected below.

| # | Premise | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|
| **P-31** *(corrected)* | Bar is 66/21 settled | ✅ **TRUE for the pre-R-7 CSS only** | reproduced by two lanes | superseded by P-46 |
| **P-37** *(label corrected)* | Dense fixture's 2nd run invisible @120×30 | ✅ **TRUE** — only rev-1's *label* was wrong | `visible=[21,0]`, reproduced by architect | finding kept, label fixed |
| **P-38** *(corrected — over-generalised)* | R1 achievable in the real container | ❌ **FALSE as a general claim** | `prg.s19` at bar=**66** *and* bar=**50**: unbounded allocation still yields `visible≥1=False`, `monotone=False`, `outside≠0` | **drove R-7/2 + `LLR-111.7`** |
| **P-44** 🆕 | One range yields one run | ❌ **FALSE** | range `0x10000..0x10800`, first half `0xFF`, second half seeded-random → **2 `BandSegment`s** (`0x10000..0x10400`, `0x10400..0x10800`). rev-1 equality guard → **False**; coverage form → **True** | **§2.9; re-points every clause** |
| **P-45** 🆕 | rev-1's `68 → 68 → 66` shows two settled-looking reads then a change | ❌ **FALSE — retracted, it was mis-stated** | 12 trials: **same-frame** triples `{(66,66,66):9, (68,68,68):3}`; **one-read-per-pause** sequences `{(66,66,66):9, (68,66,66):3}`. The repeated `68` came from three reads **inside one frame**. Architect's 97 traces (0/60 double-68 across pauses) agree. | **`LLR-111.6` counts PAUSES** |
| **P-46** 🆕 | The bar can be widened by CSS at 120×30 | ✅ **TRUE** | settled sweep: `glance 28 (baseline) → bar 21` · `glance 20 → 29` · `glance 16 → 33` · `bar 3fr/glance 1fr → 36` · **`always stack → 50`**. **80×24 is 66 in every candidate** (already stacks via `width-narrow`). | **R-7/1 → `LLR-111.9`** |
| **P-47** 🆕 | Shrinking the glance is a viable way to widen the bar | ❌ **FALSE** | the glance's widest painted row is **29 columns** (`'· constant/padding 3 ████ 60%'`). `glance 20/16/1fr` all clip it. **The baseline box is 28 and clips it today by 1.** Only *always-stack* both widens the bar and stops the clip. | selects the stack variant; pre-existing clip → carry **C-77-j** |
| **P-48** 🆕 | With the widened bar, `prg.s19` satisfies HLR-111 | ❌ **FALSE without a bound** | unbounded @bar=50: `(bytes,visible)=[(1,1),(2,1),(10,1),(2,1),(3,1),(768,8),(512,5),(2560,26),(38,1),(60,0),(8,0),(1,0),(1,0),(2,0)]` → **5 runs invisible**, `outside≠0`; content sums to **60 > 50** because `max(1,·)` floors nine tiny runs while one takes 26 | **`LLR-111.7` is mandatory** |
| **P-49** 🆕 | A bounded allocator satisfies `prg.s19` at both regimes with **no** aggregation | ✅ **TRUE** | runs `[1,2,10,2,3,768,512,2560,38,60,8,1,1,2]`: `bar=66 → 14 segs + **10** gaps, Σ widths 56, total 66, FITS, allvis, mono, strict, aggregated=0`; `bar=50 → Σ widths 40 + 10, total 50, FITS, allvis, mono, strict, aggregated=0`. *(**Gap count corrected at rev 6** — every revision wrote "13 gaps", i.e. `n_runs − 1`; the traversal emits **10**. The `total` figures are unaffected because the allocator fills whatever the gaps leave: `53+13` and `56+10` both equal 66. See the §3 domain callout.)* At the **un-widened** `bar=21` the same allocator needs **4** aggregations — which is why R-7/1 precedes R-7/2. | **`LLR-111.7`** |
| **P-50** 🆕 | Aggregation onset | ✅ **TRUE, exact** | `bar=50`: 25 runs → 0 aggregated; **26 → 1**. `bar=66`: 33 → 0; **34 → 1**. Matches `n_runs + n_gaps·fold > bar_w`, i.e. `2·n_runs − 1 > bar_w`. | **Preserved in `C-77-l` item 1–2 for batch-78.** *(Revision 3 left this disposition pointing at `LLR-111.8`, which R-10 withdrew — caught by the revision-4 propagation sweep, and the only genuine residue it found.)* |
| **P-51** 🆕 | `safe_text` neutralises ANSI, as its shipped docstring claims (`:694-697`) | ❌ **FALSE — a false claim in shipped source** | `safe_text('sensor\x1b[31m_evil[red]')` → **unchanged**. `ESC survives: True` · `'[red]' literal: True` · `spans: []` · `len(plain)=21` for **16** visible chars — **5 invisible bytes billed as width**. The *markup* half is TRUE; the *ANSI* half is FALSE. | **`LLR-116.6` + `AT-B77-15a/b`**; **the docstring and the scrub are now `LLR-116.7`, in-batch (R-11) — carry `C-77-h` DISCHARGED** |
| **P-52** 🆕 | rev-1's `LLR-112.2` overlap predicate can detect a non-collapsing ruler | ❌ **FALSE — vacuous** | `width:1fr` children **cannot overlap**. N ticks in W=50: `N=20 → max width 3` (8-char label elided); `N=60 → 10 zero-width, OVERLAPS=0`. rev-1's conjunction **GREEN at 10 invisible labels**. | **`LLR-112.2` re-authored** |
| **P-53** 🆕 | The retired 5-tick clause has 6 citation sites | ❌ **FALSE — 8** | + `s19_app/tui/legend.py:606-614` — prose *"address ruler — 5 ticks at 0/25/50/75/100 % of span"* **plus a 5-address sample line**, in a file absent from revision 1 entirely; + `.dev-flow/2026-07-15-batch-47/06-docs/traceability-matrix.md:54` | **`LLR-112.3` → 8**; `legend.py` enters §7 |

| **P-54** 🆕 | Only ONE shipped fixture crosses the **`HLR-111`** onset | ✅ **TRUE, and now DERIVED** | executed over `examples/**/*.s19` (**16** fixtures): the only exclusion is `case_08` (801 runs + 800 gaps = **1601** vs bar 66/50). **15 of 16 in domain at both regimes.** *(Earlier revisions wrote "16 of 17"; the corpus is 16.)* ⚠️ **This premise is about `HLR-111` ONLY — `HLR-112`'s membership is a different and larger exclusion set, see P-60.** | **basis for R-10** |
| **P-55** 🆕 | Revision 2's `AT-B77-15` control-byte limb is RED today | ❌ **FALSE — it is GREEN, vacuously** | zero clicks → body still shows `_DETAIL_HINT` → no file-derived text at all → `limb3 no-ESC = True` at both sizes. The node aggregated RED off limb 1 and hid it. | **`AT-B77-15a/b` split, per-arm reporting** |
| **P-56** 🆕 | Revision 2's recorded mutation discharges the control-byte limb | ❌ **FALSE — inert** | `remove safe_text → Text.from_markup`: `limb1 True→False`, `limb2 True→False`, **`limb3 False→False`**. `safe_text` is a no-op on ESC to begin with (P-51), so removing it cannot move limb 3. | **R-11: land the scrub, then the mutation is "revert the filter"** |
| **P-57** 🆕 | A hostile symbol name can perturb the bar's layout arithmetic *(rev 1–2 rationale)* | ❌ **FALSE — WITHDRAWN** | body plain length **277 → 708** with ESC present, while `.map-band-bar`, `#map_grid`, `#map_detail` were **byte-identical at both regimes**. `#map_detail` is `width: 36` **fixed**; `#map_grid` takes `1fr` of the remainder. No file-derived string is an input to `LLR-111.7`. | **rationale deleted explicitly**; finding stands on the load-path reachability alone |
| **P-58** 🆕 | Revision 2's `AT-B77-02` mutation is discharging | ❌ **FALSE — a provable no-op** | the fixture is gapless → `n_gaps = 0` → `avail = bar_w − 0·fold`; executed at fold 1/2/5/60 the payload is `[49,17]` every time. | **real mutation: allocator → plain `round()`, `[49,17]→[50,16]`** |
| **P-59** 🆕 | Revision 2's predicted golden was computed by the mandated allocator | ❌ **FALSE — wrong method** | `[50,16]`/`[38,12]` are plain `round()`. `LLR-111.7`'s allocator gives **`[49,17]`/`[37,13]`**. Both sum to the bar, which is why it survived a revision. | **every payload now names its method** |

**Gate rule:** ❌ blocks. Every ❌ above is dispositioned in the body.

### 2.9 🆕 Subject decision — the acceptance quantifies over RUNS (arch B-5 / QA B-1)

| Option | Consequence |
|---|---|
| Quantify over **RANGES** | ❌ Would require one segment per range, **deleting the entropy-band split** that R-TUI-060 exists for. Rejected. |
| Quantify over **RUNS** ✅ | ✅ Matches what the producer emits and the operator sees. ✅ `visible_cols` is per-segment and a run is exactly one segment, so monotonicity **has a well-defined subject**. ⚠️ The oracle can no longer be `loaded.ranges`. |

**Chosen: RUNS.** Consequences, all normative below:

1. **The completeness guard becomes a two-part guard.** The equality form is **FALSE on correct code** (P-44). Replaced by (a) an **independent runs oracle** — `_merge_band_runs(loaded.entropy_windows)` computed in the test — and (b) a **coverage** assertion: every `loaded.ranges` start falls inside some emitted run's `[region_start, region_end)`. Executed: (b) holds on the heterogeneous fixture where (the old) equality fails.
2. **The runs oracle is not the producer under test.** `_merge_band_runs` is a pure function over `entropy_windows`; the code under test is `_build_band_widgets`'s **allocation**. Using the former to check the latter is **a differential check on the emission layer** — it detects a segment population that disagrees with the merged runs, which is the defect the guard exists to catch. *(Stated because it is the obvious objection.)*
   ⚠️ **It is NOT an independent oracle, and rev 5 called it one.** The guard calls the same `_merge_band_runs` the producer calls, so **it cannot detect a defect inside that function** — a wrong merge produces a wrong `expected` and a wrong `emitted` that agree. The claim is narrowed rather than the check changed: `_merge_band_runs` is **unchanged by this batch** (no increment lists it), so its correctness is inherited from batch-47 and is not what Inc-1 is gating. A true independent oracle would re-derive the runs from `entropy_windows` in the test; that is worth doing when a batch actually modifies the merge, and is **not** worth doing here.
3. **R-4's "labels at region starts" resolves to RUN starts** — the ruler must label what the bar draws.

---

## 3. High-level requirements

> Next free ID **`HLR-111`** (high-water 110; `HLR-108/109/110` live in shipped tests, absent from `REQUIREMENTS.md`). Namespace re-verified clean by the architect lane.

### HLR-111 — every mapped run is visible, ordered by size, inside a bounded container
- **Traceability:** US-77-1 · **Rulings:** R1, R2, R5, **R-7**
- **Statement:** When the Memory Map renders an image at any supported terminal size, the band strip **shall** derive all segment widths from the rendered width of their container measured at render time, and **shall** render each unmapped gap at exactly one column. **While the image satisfies `n_runs + n_gaps ≤ bar.region.width`**, the strip **shall** emit a total column count, over all run segments and gap markers together, not exceeding that container width; **shall** paint at least one visible column for every emitted run segment; **shall** emit visible widths non-decreasing in mapped bytes over ordered **pairs** of run segments (a pairwise order, not a function of byte count — largest-remainder legitimately gives equal-byte runs unequal widths); and **shall**, **while the image additionally satisfies `(bar.region.width − n_runs − n_gaps) × (max_bytes − min_bytes) > total_bytes`**, emit at least one strictly greater pair whenever two emitted run segments differ in mapped size. If the image does not satisfy the containment condition, then the panel **shall** render without raising and **shall** leave every run reachable in the region list.
- **⭐ THE STRICTNESS PRECONDITION (Amendment D, rev 6).** The strictness clause — and **only** that clause — carries a second condition, because on the containment domain alone it is **FALSE on in-domain inputs and unsatisfiable by any allocator**. `surplus = bar.region.width − n_runs − n_gaps` is the columns left after one per run and one per gap; `max_bytes − min_bytes` is the mapped-byte spread; `total_bytes` is the sum. **Two runs of different but similar byte counts legitimately round to the same integer column count** — a size difference smaller than one column's worth of bytes cannot be represented in integer columns, so no implementation can discriminate them. `visible ≥ 1`, `Σ ≤ width` and monotone-∀ are **NOT** narrowed: they hold at the containment boundary and stay on the `≤` domain. See §6.5 **Amendment D** for the executed counterexample, the 859 276-case sweep and the shipped-corpus confirmation.
- **⭐ Quantifier, stated normatively (arch M-1):** monotonicity is **∀** over ordered pairs of emitted run segments; strictness is **∃** — *at least one* strictly greater pair. Revision 1 left this to a transcript. Under a **∀** reading of strictness, N-1's "different limbs" rationale collapses; under **∃** it holds. **∃ is the requirement.**
- **Rationale (informative):** shipped code scales to `_BAND_BAR_WIDTH = 60` against a `1fr` container measured at 66/21. R-7 widens the container first (50 @120×30) and bounds the allocation second. **Both parts are load-bearing:** executed, widening alone still leaves 5 of 14 runs invisible on `prg.s19`, because `max(1,·)` floors nine tiny runs while one claims 26 columns (P-48). With the bound, `prg.s19` fits exactly at both regimes with **zero** aggregation (P-49).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k "b77_width or b77_bound or b77_contain or b77_domain" -v` + **full** `tests/test_tui_directionb.py` + **full** `tests/test_map_click_chain.py` (C-34 + census)
- **Numeric pass threshold, per size arm, EVALUATED INSIDE THE DOMAIN:** `invisible_runs == 0` · `Σ widths ≤ bar.region.width` · `outside == 0` · gap markers all `== 1` · monotone ∀ holds; **strict ∃ holds while `surplus × spread > total_bytes` (Amendment D) — all 15 in-domain shipped fixtures satisfy it at both regimes**. Out of domain the only thresholds are *no exception raised* and *region-list row count == oracle run count*. Pre-change, executed: `invisible` **0 @80×24 / 2 @120×30**; `strict` **False / True**; `outside` **0 / 4**.
- **Priority:** high
- **Acceptance (black-box):**
  - **Shipped surface:** `App.run_test(size=…)` → `action_show_screen("map")` → `update_memory_map()` → `app.query(".map-band-seg")`, geometry clipped against `app.query_one(".map-band-bar").region`, read at **settled** geometry (`LLR-111.6`).
  - **Completeness guard (C-31), re-authored per §2.9 — replaces rev-1's guard, which was FALSE on correct code:**
    ```
    expected = _merge_band_runs(loaded.entropy_windows)                  # independent oracle
    emitted  = {(s.region_start, s.region_end) for s in query(BandSegment)}
    assert emitted == {(start, start + n) for _band, n, start in expected}
    assert all(any(a <= rs < b for a, b in emitted) for rs, _ in loaded.ranges)   # coverage
    ```
    ⚠️ **This is EQUALITY again, and that is correct now.** Revision 2 weakened it to a subset with an
    `if not s.is_aggregate` filter, purely to admit aggregation — and QA proved that filter makes the guard
    **FALSE on a correctly-aggregating implementation** (2 ranges → 1 aggregate → `emitted` empty → coverage
    `False`; 10 uncovered range starts @bar=66, 15 @bar=50 on a 26-region fixture). **With aggregation
    descoped there are no aggregate segments, so equality holds and the filter is deleted.** The weakening
    existed only to serve the path R-10 removes.
  - **Acceptance test(s):** **`AT-B77-01`** three-way conjunction (visible ∧ monotone∀ ∧ strict∃), both sizes, **in domain** — its two fixtures satisfy Amendment D's strictness precondition at both regimes (executed: margins ≥ 10×), so the `strict` limb has a live subject there · **`AT-B77-02`** gapless no-op at fixed container width · **`AT-B77-03`** every segment contained in the container, **in domain** · **`AT-B77-18`** 🆕 *(replaces the withdrawn `AT-B77-17`)* **out of domain** — on `case_08` the panel renders without raising and the region list carries one row per oracle run
  - **Boundary catalog (QC-3):** ☑ **empty** — no ranges → zero segments, no raise, `TC-B77-01` · ☑ **boundary** — one run: strict **skipped explicitly** at `n<2`, never passed silently, `TC-B77-02` · ☑ **boundary** ⭐ — **`n_runs + n_gaps > bar_width`** — the domain edge. Expected result: **no raise, region list complete, bar not claimed correct**. Executed onset **26 runs @bar=50, 34 @bar=66**; the one shipped fixture past it is `case_08` at 1601. `TC-B77-03` — ⚠️ **which must carry a DIFFERING-SIZE arm (Amendment D):** its `[256] * n_runs` fixture makes `differing` False, so the strict limb has no subject anywhere in the sweep, which is precisely why the onset sweep never evaluated the clause Amendment D had to fix · ☑ **boundary** 🆕 — **the strictness precondition edge** — in the containment domain but `surplus × spread ≤ total_bytes`: widths legitimately tie and `strict` is False. Expected result: **no raise, bound still exact, strictness NOT claimed**. `TC-B77-03` differing arm · ☑ **invalid** — zero-byte run, `TC-B77-04` · ☑ **error** — `total_span ≤ 0`, guarded `:1900`, `TC-B77-05` · ☑ **boundary** 🆕 — entropy-heterogeneous single range (1 range → 2 runs), `TC-B77-30`

> ⭐ **THE DOMAIN, STATED (R-10). This requirement is deliberately SMALLER IN SCOPE than revision 2's and truer.**
> Revision 2 promised universals over *every* image and discharged the excess with an aggregation path that
> the re-gate found broken in six independent ways. R-10 removes aggregation to **batch-78**. What remains is
> a requirement with an **explicit domain** and an **honestly described** out-of-domain case.
>
> **In domain — `n_runs + n_gaps ≤ bar.region.width`.** Executed: **15 of the 16 shipped image fixtures** satisfy this, and the allocation bound alone (`LLR-111.7`) makes them all pass with **zero aggregation**. *(Derived at revision 5 by executing the membership test over `examples/**/*.s19`; earlier revisions said "16 of 17" — the corpus is **16** and the split is **15 / 1**.)*
> `prg.s19` (14 runs, **10** gaps) fits **exactly**: `bar=66 → total 66` (`Σ widths 56 + 10`), `bar=50 → total 50` (`Σ widths 40 + 10`).
> ⚠️ **Rev 6 correction — the gap count was `n_runs − 1`, not the traversal's.** Every prior revision wrote *"13 gaps"*, which is `14 − 1`. The emitted count from the one traversal that decides gap placement (`_build_band_widgets:2236-2239`) is **10**: a gap is emitted only where a run starts above the cursor, and `prg.s19` has four adjacent runs. **This is the exact inference the production comment at `:2230-2235` warns against** — *"inferring `n_runs - 1` lets the count the bound spends diverge from the count the bar draws"* — reproduced in the document describing that code. The conclusion is unaffected (the bar still fits exactly at both regimes, executed above); only the parenthetical was wrong. Found while deriving Amendment D's corpus row.
>
> **Out of domain — exactly ONE shipped fixture**, `examples/professional_validation/case_08_heavy_fragmentation/firmware.s19`,
> at **801 ranges → 801 runs + 800 gaps = 1601 segments**, roughly **30×** the ceiling. The bound is
> arithmetically unsatisfiable there: `avail = bar_w − n_gaps` is **−734** @bar=66 and **−750** @bar=50.
>
> **What the bar ACTUALLY does out of domain — measured, EACH FIGURE ATTRIBUTED TO ITS PRODUCER, and NOT described as correct:**
> ```
> case_08: ranges=801  oracle runs=801  gaps=800  n_runs+n_gaps=1601
>
> (a) PRISTINE producer + R-7 CSS only  -- what revisions 1-3 printed, MISATTRIBUTED
>     (80,24)  bar=66  content=1660  INVISIBLE 797/801 (99.5%)  outside=1594  gap_w max=60
>     (120,30) bar=50  content=1660  INVISIBLE 800/801 (99.9%)  outside=1600  gap_w max=60
>
> (b) BATCH-77 producer (LLR-111.1 basis+denominator, .2 fold=1, .7 bound; no aggregation)
>     (80,24)  bar=66  content=1601  INVISIBLE 768/801 (95.9%)  outside=1535  gap_w max=1
>     (120,30) bar=50  content=1601  INVISIBLE 776/801 (96.9%)  outside=1551  gap_w max=1
>
> region-list rows = 801 in every case;  no crash in any case
> ```
> ⚠️ **Revisions 1–3 labelled row (a) as batch-77's and it is not.** The tell is `gap_w max = 60`: gaps are
> **unfolded**, so `LLR-111.2` had not been applied. **Two consequences, both correcting this document's own
> claims about its own work:**
> 1. The shipping numbers are **95.9 % @80×24 and 96.9 % @120×30** — not 99.5 %/99.9 %. **Both regimes must be
>    quoted wherever either is**, or the wide regime is understated: `768/801` @66 and `776/801` @50. The bar is
>    still unreadable on `case_08` at both — and **batch-77 does not fix that**.
> 2. Revision 3's *"it is not made worse either: the invisible-run count is identical with and without the R-7
>    widen"* compared **two rows of the same pre-fold producer**. Against batch-77's actual producer it is
>    **797 → 768 and 800 → 776: measurably BETTER, not identical.** The document was understating its own work.
>
> **⚠️ The out-of-domain DEGRADATION RULE is deliberately UNSPECIFIED, and that is stated rather than implied.**
> `HLR-111`'s out-of-domain clause requires only *no raise* and *every run reachable in the region list*. It does
> **not** prescribe how widths are apportioned once the bound is unsatisfiable. **Therefore the figures in row (b)
> are OBSERVATIONS of one conforming implementation, not a contract** — a different conforming degradation
> (all-1 widths, proportional-then-clip, first-N-only) would give different counts and still satisfy this
> requirement. `AT-B77-18` asserts only the two contracted properties, never these numbers. Specifying the
> degradation rule is **batch-78's job** and is carried in `C-77-l`.

> **Owner: batch-78, chartered in `§6.3` carry `C-77-l` with every measurement already paid for.**

> ⚠️ **N-1 stands, rationale tightened (arch M-1).** Executed at settled geometry, pre-change:
> ```
> 80×24 : visible>=1 = True    monotone = True   strict(∃) = False   -> conjunction RED
> 120×30: visible>=1 = False   monotone = True   strict(∃) = True    -> conjunction RED
> ```
> Both lanes reproduced this byte-for-byte. Keep **one** conjunction. The precise hazard is **not**
> "an untested limb" but a **spuriously-GREEN `strict` arm at 120×30** — it reads True only because two
> runs clip to `0` and `1 > 0`. Splitting the node would let that spurious GREEN stand alone.

### HLR-112 — every ruler label names a mapped address and is legible
- **Traceability:** US-77-2 · **Rulings:** R4, security M-1
- **Statement:** When the Memory Map renders, the address ruler **shall not** emit a label naming an address outside every mapped range, and **shall** emit strictly ascending, non-duplicate labels. **While the image satisfies `n_ticks ≤ ruler.region.width ÷ label_width`**, the ruler **shall** emit one tick label per emitted **run** start plus one label for the last mapped byte, and **shall not** emit any tick whose rendered width is smaller than the label it carries. If the image does not satisfy that condition, the ruler **shall** retain the first and last labels, **shall** drop interior labels rather than emit an illegible one, and **shall** render without raising.
- **⭐ DOMAIN — added at revision 4, MEASURED at revision 5 (arch RC-2 / QA M-4 / arch RC4-2).** Revision 3 gave `HLR-111` a domain and left `HLR-112` with none, so its cardinality and legibility clauses were **jointly unsatisfiable on shipped fixtures**. The domain resolves that by the same pattern already applied to `HLR-111`: the *invariants* stay universal because they cost nothing; the *cardinality* and *legibility* clauses take the domain; out-of-domain behaviour is stated rather than left silent.

  **The ceiling, DERIVED (not copied):** ruler width measured at **66 @80×24 and 50 @120×30**; tick labels measured at **8 characters** (8 hex digits, the `0x` prefix already dropped as a spent C-13.1 fallback). **A one-column separator is required** — two adjacent 8-hex labels with no gap render as an unreadable 16-digit run — so the pitch is **9** and the ceiling is `⌊(width + 1) ÷ 9⌋` = **7 ticks @80×24 and 5 @120×30**.
  ⚠️ **The separator convention is load-bearing and therefore normative, not cosmetic.** At pitch 8 (no separator) the ceiling would be 8/6 and `case_07_stress_smoke` (6 ticks) would read as *in domain* at the wide regime. It is not. **A membership answer that changes with an unstated convention is not a membership answer** — the convention is stated in `LLR-112.2`.

  **Membership across the WHOLE shipped corpus — executed over `examples/**/*.s19`, both regimes:**

  | Fixture | runs | ticks | cols needed | in @80×24 (≤7) | in @120×30 (≤5) |
  |---|---:|---:|---:|:--:|:--:|
  | **`case_00_public/prg.s19`** ⭐ | 14 | 15 | 134 | ❌ | ❌ |
  | `case_00_public/s19_sample.s19` | 2 | 3 | 26 | ✅ | ✅ |
  | `case_01_basic_valid` | 3 | 4 | 35 | ✅ | ✅ |
  | `case_02_gaps_and_patch_targets` | 4 | 5 | 44 | ✅ | ✅ |
  | `case_03_overlapping_records` | 2 | 3 | 26 | ✅ | ✅ |
  | `case_04_bad_checksums` | 2 | 3 | 26 | ✅ | ✅ |
  | `case_05_dense_mixed_content` | 2 | 3 | 26 | ✅ | ✅ |
  | `case_06_large_nested_a2l` | 3 | 4 | 35 | ✅ | ✅ |
  | **`case_07_stress_smoke`** | 5 | 6 | 53 | ✅ | ❌ |
  | `professional_validation/case_01_baseline_valid` | 3 | 4 | 35 | ✅ | ✅ |
  | `professional_validation/case_02_patch_targets_and_gaps` | 4 | 5 | 44 | ✅ | ✅ |
  | `professional_validation/case_03_overlapping_records` | 3 | 4 | 35 | ✅ | ✅ |
  | `professional_validation/case_04_bad_checksums` | 2 | 3 | 26 | ✅ | ✅ |
  | `professional_validation/case_05_out_of_order_and_mixed` | 4 | 5 | 44 | ✅ | ✅ |
  | `professional_validation/case_07_cross_reference_inconsistencies` | 3 | 4 | 35 | ✅ | ✅ |
  | **`professional_validation/case_08_heavy_fragmentation`** | 801 | 802 | 7217 | ❌ | ❌ |

  **EXCLUDED — three fixtures, not one:**
  - **`case_00_public/prg.s19` — OUT at BOTH regimes** (15 ticks vs 7/5). ⚠️ **This is the batch's showcase fixture** — the one `LLR-111.7`'s threshold names, the one every `HLR-111` demonstration uses, the one R-7 was validated against. **`HLR-111` covers it; `HLR-112` does not.** Revision 4's callout named only `case_08`, from which a reader would reasonably conclude `case_08` was the sole exclusion.
  - **`case_07_stress_smoke` — OUT at 120×30 only** (6 ticks vs a ceiling of 5). A single-regime exclusion, invisible to any check that tests one regime.
  - **`professional_validation/case_08_heavy_fragmentation` — OUT at BOTH** (802 ticks vs 7/5).

  **`HLR-112`'s domain is materially smaller than `HLR-111`'s: 13 of 16 at both regimes versus 15 of 16.** Stating this is the point — US-77-2's delivered outcome on `prg.s19` is that every emitted label names a mapped address (the invariant holds) but the operator sees at most 7 of 15 run starts. **That is weaker than the story implies, and it is now on the page.**

- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py::test_at072b_ruler -v` (re-derived) + `-k b77_ruler`
- **Numeric pass threshold:** *(universal)* 0 labels outside every mapped range (today **4**); `len(ticks) == len(set(ticks))`; strictly ascending. *(in domain)* one tick per run start plus the end label; **0 ticks with `region.width < len(label)`**. *(out of domain)* first and last labels retained, no raise.
- **Acceptance (black-box):**
  - **Deliverable + observation:** tick labels **and each tick's `region.width`**. Membership via the frozen `address_in_sorted_ranges(addr, index)` — note the argument order (`s19_app/range_index.py:39`); revision 1's first probe had it inverted and was caught by a `TypeError`.
  - ⚠️ **FIXTURE PIN — normative, and the reason is a latent false failure (arch RC4-2c).** `AT-072b` carries the **in-domain** clause *"no elided tick"*. **Its fixture must be one that is in `HLR-112`'s domain at BOTH regimes** — i.e. **≤ 5 ticks**, which the current `_load_case_02()` (4 runs → 5 ticks) satisfies. **`prg.s19` MUST NOT be used**: at 15 ticks it is out of domain at both regimes and the node would go **RED on correct code**. The trap is latent rather than live only because Inc-4 has not re-derived the node yet, and `prg.s19` is the obvious fixture for an editor to reach for.
  - **Acceptance test(s):** **`AT-072b`** *(re-derived, keeps its global id; **fixture pinned in domain at both regimes**)* — `{ticks} ⊆ ADMISSIBLE` ∧ ascending ∧ no duplicates ∧ **no elided tick**, where `ADMISSIBLE = {f"{s:08X}" for run starts} ∪ {f"{span_end-1:08X}"}` · **`AT-B77-04`** — the `⊇` lower bound
  - **⚠️ Why `AT-B77-04` is not optional:** executed, `set() <= admissible` is **`True`**. A subset-only predicate is GREEN on a ruler that rendered zero ticks.
  - **Boundary catalog:** ☑ empty `TC-B77-06` · ☑ one run `TC-B77-07` · ☑ **more runs than ruler columns → elision, the case rev-1 could not detect** `TC-B77-08` · ☑ two run starts rendering to one column `TC-B77-09` · ☐ error **N/A** — ticks derive from validated `ranges`/runs (LLR-041.7)

### HLR-113 — the stats strip states mapped-vs-span with a discriminating percentage
- **Statement:** When the Memory Map renders a loaded image, `#map_stats_body` **shall** present the mapped total and the image span as humanized sizes in one dual readout, **shall** render the coverage percentage to exactly four fractional digits, and **shall** present the largest gap as a humanized size.
- **Change (QA M-4):** revision 1 said *"at least four"*, pinning nothing — a `.6f` implementation would satisfy it while reddening `test_at037`'s absence clause. **Now exactly four.**
- **Threshold:** `0.0008%` not `0.00%`; `64.0 MiB` not `67108408 bytes`; contains `1.0 KiB` and `128.0 MiB` — all executed.
- **Acceptance:** **`AT-B77-05`**; expected strings **computed** in the test via `human_bytes(...)`, never hand-typed (C-42). Absence clauses each paired with their presence clause in the same node (C-40).
- **Boundary:** `TC-B77-10` (no file) · `TC-B77-11` (100 %, assert `human_bytes(0)`) · `TC-B77-12` (1-byte image) · `TC-B77-13` (`image_span == 0`)

> ⚠️ **`test_tc041_9` — revision 1's vacuity claim is WITHDRAWN, not repeated (QA M-3).** It has **five**
> assertions, not one, and its vacuity is **UNDECIDABLE**: the no-file strip is `''` because
> `build_stats_text` is **never called** on that path, so `"Coverage:" not in strip` was never the
> load-bearing part. `TC-B77-10` re-derives the empty-state guarantee positively. **Do not assert a
> vacuity you cannot demonstrate** — that is the same error class this batch keeps finding, committed
> by the document that was cataloguing it.

### HLR-114 — the legend block is not resident in the map body
- **Statement:** When the Memory Map renders, `#map_grid` **shall not** contain any `.map-legend-row` or `.map-band-legend` widget, and the application's legend screen **shall** remain reachable and render the same band-label set as before this batch.
- **Threshold:** both queries 0 (today **4** and **1**) **while** `.map-band-seg` ≥ 1
- **Acceptance:** **`AT-B77-06`** (absence + presence co-assertion) · **`AT-B77-07`** *(PIN)* legend screen intact, label completeness derived from **`ENTROPY_BAND_LABELS`**, never hand-listed (C-31)
- **Boundary catalog (QC-3):** ☑ **empty** — no file → still zero legend rows, and the AT must **not** count that as a pass (the `.map-band-seg ≥ 1` co-assertion guards it), `TC-B77-14` · ☑ **boundary** — legend screen opened from the map and dismissed back to it; the map still renders, `TC-B77-15` · ☐ **invalid** / ☐ **error** — **N/A:** removing a static widget set admits no new input class.
- **Blast radius:** `test_at075_e_key_opens_no_modal_map_has_legend` (`tests/test_tui_directionb.py:4574`) goes RED by design; **port its `e`-key clause, never delete the node.**

### HLR-115 — region rows are actionable with arrows and Enter
- **Traceability:** US-77-5 · **Ruling:** R3
- **Statement:** While the Memory Map is active with an image loaded and a region row has focus, `↑` and `↓` **shall** move focus to the previous and next region row in ascending address order, `Enter` **shall** populate the inspector for the focused region, and the application **shall** continue to route `j`, `k` and `o` to their pre-existing application actions unchanged.
- **Change (arch B-4):** the focusability clause is **removed from this HLR and from `LLR-115.1`** — it belongs solely to HLR-116, which owns the entry path. One normative owner.
- **⚠️ Scope reduction:** `o` = open-hex **descoped** (R3) — carry **C-77-f**. Hex stays reachable by the unchanged N4a mouse double-click.
- **⚠️ C-16:** no spatial arrow-focus by default; `assumed — verify at Phase 3`. **Real `pilot.press` only; never `.focus()`.**
- **Acceptance (black-box) — `AT-B77-09` re-authored per QA B-4:**
  - **`AT-B77-09`** *(a PIN with a named mutation — **relabelled at revision 3**, arch RM-2)* — with focus **ON** a region row, which after R-6 is the **default** state: `k` pushes the legend screen, `j` invokes `dump_a2l_json`, `o` invokes `open_workarea`, and none moves the map selection. **This is the only state in which widget-scoped shadowing can occur**, so it is the only arm that can redden if someone adds `Binding("k", …)` to `RegionRow.BINDINGS` — **and that named mutation is its whole falsifiability.** `RegionRow.BINDINGS` is `[]` today and `LLR-115.4` keeps it `[]`, so the predicate is GREEN before and after. Revision 2 called it "the GATE" and §5.2 said "RED-able only after Inc-7", implying it would eventually be demonstrated RED. **It will not be.** It is a PIN, labelled like `AT-B77-02`, so §9 reflects what will actually be produced.
  - **`AT-B77-16`** 🆕 *(the PIN)* — with focus **off** the region list, the same three keys behave as today. This is revision 1's `AT-B77-09` verbatim, correctly **relabelled a PIN**: with no row focused there is no widget binding in the resolution chain, so the predicate is invariant under the change it gates (C-40 limb 1).
  - **`AT-B77-08`** real keys move focus and `Enter` inspects · **`AT-B77-10`** *(PIN)* N4a mouse split — ⚠️ **QA M-5: this is a two-node claim** mapping to existing `test_ac3_…` + `test_ac4_…`; **reuse those nodes** rather than minting one that covers half the claim.
  - **Why revision 1 got this wrong, recorded:** the wording was inherited verbatim from the pre-R-6 QA lane, and §6.4's reconciliation log recorded R-6 as touching HLR-116 and **not** HLR-115. R-6 changed the default focus state; the acceptance that depended on it was never re-read.
  - **Boundary:** `TC-B77-16` (first/last row, focus unchanged) · `TC-B77-17` (no file, keys inert) · `TC-B77-18` (single region) · `TC-B77-19` (`Enter` on an invalidated row) · `TC-B77-20` (`Enter` with no focus)
  - **⚠️ C-28:** **add no App-level `Binding(..., show=True)`.** QA measured the 14 existing chips need ≈ **181** columns of footer in the **78** available — already ~2.3× oversubscribed and truncating. A 15th chip does not merely *risk* truncation; it **guarantees** displacing an existing one, and drifts all 29 snapshot cells instead of 2. Discoverability is served by the existing `?` help panel.

### HLR-116 — a region is focused and inspected without operator input, safely
- **Traceability:** US-77-6 · **Rulings:** R-6, **security B-1** · **absorbs `can_focus` (arch B-4)**
- **Statement:** When the Memory Map completes a render for a loaded image with at least one run, the panel **shall** make the region rows focusable; **shall** resolve the selected region to the previously selected region when a region with that start address is present among the newly rendered rows, and to the first region otherwise; **shall** populate `#map_detail_body` with the resolved region's detail; **shall** place focus on a region row that is attached to the running application and present among the currently mounted region rows and whose start address equals the resolved selection; **shall not** post `MemoryMapPanel.OpenInHexRequested` as a consequence; and **shall** render every file-derived string in `#map_detail_body` as literal content emitting no control byte into the painted strip.
- **Rationale (informative):** measured, `#map_detail_body` shows `_DETAIL_HINT` with a file loaded; `down`×3 and `tab` never leave `RailItem`; `can_focus` is `False` on all rows. Focus must follow selection or the operator's arrow keys resume elsewhere and HLR-115 silently regresses.
- **⚠️ Liveness, not identity (QA B-3).** `app.focused.region_start == X` reads **`True` on a fully detached widget** — QA executed `is_attached=False`, `parent=None`, focused row absent from the five live `RegionRow`s. **Root cause is this document's own §2.2 remount constraint:** `grid.remove_children()` defers removal (`screens_directionb.py:2094-2097`), so during the resolution window both stale and fresh row sets are queryable.
- **⚠️ `grid.mount()` is deferred too** — "after the rows are mounted" is **not** a synchronous point inside `render_ranges`. The resolution must run on a post-refresh hook. Unstated in revision 1; it is the mechanism that produced the detached-focus defect.
- **Validation:** `test`
- **Numeric pass threshold:** fresh render — detail names run 1, **0** `OpenInHexRequested`; re-render with the region present — detail names the **previously selected** run and `app.focused` is **live and attached** with that start; re-render with it absent — detail names the **new first** run, focus likewise; hostile fixture — `render().spans == []`, payloads verbatim, **no `\x1b` in the painted strip**
- **Acceptance (black-box) — four nodes (C-18: one claim per node):**
  - **`AT-B77-11`** *(fresh render)* — zero clicks, zero keys: inspector names run 1 and **0** `OpenInHexRequested`.
  - **`AT-B77-13`** *(re-render, region PRESENT → preserved)* and **`AT-B77-14`** *(re-render, region ABSENT → fallback)* — each conjoined with the **liveness** clause.
  - **`AT-B77-15a`** *(markup literal ∧ no spans — GATE)* and **`AT-B77-15b`** *(no C0/C1 byte in the painted strip — GATE from Inc-2)*, both **reported per limb per size**, below.
  - **Per-arm mutation table (R-6) — `predicted` at Phase 1, **EXECUTED at Phase 2 by the QA lane**:**

    | Arm | Mutation (substituted VALUE) | `AT-B77-13` | `AT-B77-14` | Executed? |
    |---|---|---|---|---|
    | preserve | `selected = ordered[0]` (always reset) | **RED** | GREEN | ✅ QA-executed |
    | fallback | `selected = self._selected_cell_start` unconditionally | GREEN | **RED** | ✅ QA-executed |

    **QA's verdict: the split is sound on the selection-resolution clause** — each mutation reddens exactly one arm. **But conjoined with revision 1's identity-only focus clause, the fallback mutation produced `R,G,R` — byte-identical to correct**, collapsing the discrimination. That is a *consequence* of the liveness defect. **The liveness fix must land before these arms are trusted**; §7 orders it accordingly.
  - **Boundary:** `TC-B77-21` (no file → hint retained, no selection fabricated) · `TC-B77-22` (single run) · `TC-B77-23` (disjoint file switch) · `TC-B77-24` (zero-byte region) · `TC-B77-29` (preserved run no longer first after a re-merge — match by **address**, never index) · `TC-B77-31` 🆕 (resolution runs on the post-refresh hook, not inline)

> 🔒 **`AT-B77-15a` / `AT-B77-15b` — the hostile-input gates (security B-1, repaired at rev 3 per **R-11**).**
> `HLR-116` converts `#map_detail_body` from **click-gated** to **populated as a consequence of loading a
> file**. That body is the map's only sink for A2L symbol names (`:2397-2400`) and
> `ValidationIssue.code`/`.message`/`.symbol` (`:2410-2417`).
>
> **Why it lands on this batch — the TRUE reason, and only that one.** `HLR-116` makes this sink fire on
> the untrusted-firmware **load path** with zero operator input. That is sufficient on its own.
>
> ❌ **WITHDRAWN RATIONALE, removed explicitly rather than silently.** Revisions 1–2 also claimed the payload
> was *"distorting the very layout arithmetic R-7 exists to reconcile."* **The security lane has now executed
> its own claim and it is FALSE.** A hostile payload inflated the body's plain text **277 → 708 chars with the
> ESC present**, while `.map-band-bar`, `#map_grid` and `#map_detail` were **byte-identical at both regimes**:
> `#map_detail` is `width: 36` **fixed** (`styles.tcss:861`), its body `width: 100%` of that fixed parent, and
> `#map_grid` takes `1fr` of the remainder. **An attacker cannot perturb the bar through a symbol name**, and
> no file-derived string is an input to `LLR-111.7` — the allocator consumes run byte-counts from
> `_merge_band_runs`, pure address arithmetic. *(Recorded loudly because I repeated this claim to the operator
> twice; it must not survive into batch-78 as a premise. Same failure mode as P-38/P-44/P-45 — a plausible
> sentence that nobody had executed.)*
>
> **⚠️ The node was also MIS-VERDICTED, and the mis-verdict is CC-1 inside the acceptance written to close a
> security finding.** Executed through the shipped surface with zero clicks:
> ```
> size=(80,24) and (120,30)   detail_body = 'Click a region to inspect it - double-click to open in hex'
>    limb1 non-control-verbatim : False -> RED
>    limb2 spans == []      : True  -> GREEN
>    limb3 no ESC in strip  : True  -> GREEN   <== revisions 1-2 recorded this as RED
> ```
> **Limb 3 is green because NOTHING RENDERED** — with zero clicks the inspector still shows `_DETAIL_HINT`,
> which contains no file-derived text at all. The node aggregated to RED off limb 1, and that hid the green
> arm. This is the document's own standing rule 3 (absence needs a presence co-assertion) violated by the
> document.
>
> **Three repairs, all mandatory:**
> 1. **BOTH ARMS ASSERT THEIR PRECONDITION AND FAIL LOUDLY IF THE GESTURE MISSED (rev 5, arch RC4-1).**
>    Before any safety limb is evaluated, at **each** size arm, the test **asserts that `#map_detail_body`
>    actually contains the hostile payload**. If it does not, the node **FAILS with a message naming the
>    missed gesture** — it never proceeds to the safety limbs and never passes silently.
>    ⚠️ **Revision 4 fixed 120×30 and left 80×24 vacuous.** Reproduced on the unpatched tree: the click point
>    inside the row's *own reported region* resolves to a `Container` at 80×24 and a `RegionRow` at 120×30 —
>    so the detail body stayed `_DETAIL_HINT` at the narrow arm and the safety limbs asserted over a strip
>    with **no file-derived text at all**. That is P-55's vacuity again, at one of the two arms the gate names.
>    **The batch already holds this lesson as §6.3 F-1(e)** — *"a setup gesture that silently misses turns a
>    gate into a tautology"* — and applied it to `AT-B77-13`/`14`; it was not carried to the new Inc-2 arms.
>    **The fix is detection, not a better click.** Changing the gesture only moves the failure; asserting the
>    precondition catches it whatever the gesture does. Limb 3 remains evaluable **only** in a run where the
>    precondition has established the payload is present.
> 1a. ⚠️ **WORDING, corrected at revision 4 (QA M-2).** Revision 3 said *"payload verbatim"* in two places
>    while `LLR-116.7` correctly says *preserve every **non-control** character verbatim*. **Post-scrub the ESC
>    payload is deliberately NOT verbatim** — that is the fix working. As written, `AT-B77-15a` would have gone
>    **RED on a correct implementation**. Every occurrence now reads *non-control characters verbatim*. Stated in the AT body, not merely
>    inherited from a standing rule.
> 2. **Per-arm reporting (CC-1).** Three limbs × two sizes = six verdicts, reported individually. An
>    aggregate verdict is what hid this.
> 3. **Split by dischargeability, so neither node lies about its own status:**
>    - **`AT-B77-15a` — GATE.** Limbs 1–2 (**every non-control character** of the payload verbatim ∧ `spans == []`). Mutation: remove `safe_text`
>      → `Text.from_markup`. Executed: `limb1 True→False`, `limb2 True→False`. **Discharged.**
>    - **`AT-B77-15b` — GATE from Inc-2 onward.** Limb 3 (no C0/C1 byte in the painted strip), which
>      **R-11 makes satisfiable by landing the scrub in this batch**. Mutation: **revert the filter**
>      (substituted VALUE: scrubbed → raw). Before Inc-2 this limb is *vacuously green*; after Inc-2 it is a
>      real gate. **It is never listed as a gate in a state where it cannot pass** — which is what revision 2
>      would have shipped.

### HLR-117 — the selected region row is visually distinguishable
- **Statement:** While a region is selected, the corresponding region row **shall** render a resolved style differing from that of every unselected region row, exactly one region row **shall** carry the selection marker, and the row's entropy band styling **shall** remain unchanged by selection.
- **Which layer holds the fact (P-42, executed):** `widget.styles.(background, color, text_style)`. `render().spans` is **`[]`** on these rows, so **C-37's span route is inapplicable**; `render_line` returns the base theme colour.
- **Acceptance:** **`AT-B77-12`** — triple differs ∧ exactly one marker ∧ band token unchanged; plus an `inspection` arm on the `styles.tcss` rule.
- **⚠️ security m-1:** revision 1's inspection arm ("sets no `color:` property") is satisfiable by `text-style: reverse`, which **does** repaint the band colour. **Strengthened** in `LLR-117.2`.
- **Boundary:** `TC-B77-25` (**fixture must have ≥2 runs and the body must assert it** — with one run the clause is vacuously true) · ~~`TC-B77-26`~~ · ~~`TC-B77-27`~~ · ~~`TC-B77-28`~~ **WITHDRAWN at Inc-8 — allocated without content, never specified; numbers NOT reused.** Replaced by **`TC-B77-32`** (band channel survives a selection MOVE) and **`TC-B77-33`** (the stylesheet inspection arm). Withdrawal record in §4 under `HLR-117 → LLR-117.x`.

---

## 4. Low-level requirements

### HLR-111 → LLR-111.x

**LLR-111.9 🆕 — the container is widened before anything is aggregated (R-7/1)**
- **Statement:** The band row **shall** lay the band bar and the "At a glance" panel vertically at every supported terminal size, and the band bar **shall** occupy the full width of `#map_grid`.
- **Symbols:** `.map-band-row` `styles.tcss:779`, `.map-band-bar` `:791`, `.at-a-glance` `:809`, `width-narrow` overrides `:786`/`:799`/`:815`.
- **Geometry (C-23/C-29, BOTH axes, WHOLE pane re-measured):**
  | Candidate | bar @80×24 | bar @120×30 | glance | widest glance row | clips? |
  |---|---|---|---|---|---|
  | baseline (glance 28) | 66 | **21** | 28 | 29 | ⚠️ **yes, today** |
  | glance 20 | 66 | 29 | 20 | 29 | ❌ worse |
  | glance 16 | 66 | 33 | 16 | 29 | ❌ worse |
  | bar 3fr / glance 1fr | 66 | 36 | 13 | 29 | ❌ worse |
  | **always stack** ✅ | 66 | **50** | 50 | 29 | ✅ **no** |
- **Rationale (informative):** 80×24 already stacks via `width-narrow`, so this makes 120×30 behave like the regime that already works — a *removal* of a special case, not a new one. Every glance-shrinking candidate starves the histogram row.
  ⚠️ **Self-caught (F-1f):** my first sweep compared the glance box against its **title** (11 cols) instead of its widest **content** row (29) and reported "STARVED: none" for every candidate — the exact C-13 starvation the probe existed to detect, committed inside the detector. The table above is the corrected run.
- **Cost, stated and ACCEPTED (R-8):** the band row grows 4 → 6 rows at 120×30, pushing `#map_stats_body` from `bottom=31/30` to `bottom=33/30`. It is **already** below the fold in the baseline at both regimes (`bottom=31/30` @120×30, `bottom=35/24` @80×24) — reachable-under-scroll is the established policy for this pane — so this deepens an existing scroll and newly hides nothing. **The widen must not be narrowed to protect it**: every column surrendered lowers the ceiling on visible regions. Registered as carry **C-77-k**.
- **Validation:** `test (integration)` · **Threshold:** `bar.region.width == #map_grid.region.width` at both regimes; glance widest row ≤ glance width

**LLR-111.1 — the width basis AND the denominator are both normative (R1, arch M-2)**
- **Statement:** `_build_band_widgets` **shall** derive segment widths from the rendered width of the `.map-band-bar` container obtained at render time; **shall** apportion run widths in proportion to each run's share of the **total mapped bytes** of the emitted runs; and **shall not** derive any segment width from `_BAND_BAR_WIDTH` or from the image address span.
- **Change (arch M-2):** revision 1 fixed only the *basis*; the **denominator** change (address-span → mapped-bytes) lived in an informative rationale. A naive discharge of rev-1's wording — swap `60 → bar_w`, keep `total_span` — is exactly the regression architect measured. **Promoted to normative.**
- **Symbols:** `_build_band_widgets:1988`; expressions to replace `:2058` (gap) and `:2066` (run); `_BAND_BAR_WIDTH:230`.
- **Acceptance:** ⚠️ the container width is unavailable before first layout — widths must be computed where the region is known (post-mount refresh / `on_resize`), **not** in `compose`. `assumed — verify the recompute hook at Phase 3.` Pre-layout fallback is **OQ-3**.

**LLR-111.7 🆕 — the allocation is bounded in the producer (arch B-2, R-7)**
- **Statement:** While the image satisfies `n_runs + n_gaps ≤ bar.region.width`, the sum of all emitted run-segment widths and all emitted gap-marker widths **shall not** exceed the measured container width, and every emitted run segment **shall** receive at least one column. **While the image additionally satisfies `(bar.region.width − n_runs − n_gaps) × (max_bytes − min_bytes) > total_bytes`, the allocator shall assign strictly more columns to some run than to some other run of smaller mapped size.** If the image does not satisfy the containment condition, the allocator **shall** return a width for every run without raising.
- **⚠️ Strictness precondition added at revision 6 (Amendment D).** Revisions 1–5 let `HLR-111` promise discrimination on the containment domain alone. That is **false on in-domain inputs** — executed, `runs=[1,2,4,8,16,32,64,128,256,512]`, `n_gaps=9`, `bar=19` is in domain and yields all-`1` widths. **Narrowing the containment domain from `≤` to `<` does not fix it** (576 → 85 failures over 20 000 in-domain cases): the cause is integer **quantization**, not surplus exhaustion, and it is unsatisfiable by any allocator at those geometries. **The `> total_bytes` threshold is TIGHT** — the highest ratio observed on a non-strict in-domain case is exactly `1.000000000`, so `≥` admits failures (executed: `runs=[1,4,4]`, `n_gaps=0`, `bar=6` → `[2,2,2]`). **Only the strictness conjunct takes this precondition**; the bound and the floor stay on the `≤` domain.
- **⚠️ Scope added at revision 4 (arch RC-1).** Revision 3 stated both conjuncts unconditionally while §3 openly admitted the bound is arithmetically unsatisfiable out of domain (`avail = −734 / −750`). Executed on `case_08`: `1601 ≤ 66` **False**, `1601 ≤ 50` **False**. A requirement that its own document proves false is worse than one with a stated limit.
- **Rationale (informative):** **an output-shaped predicate cannot bound an allocation** — batch-74's asset restated. `AT-B77-03` is output-shaped; it detects the overflow but cannot prevent it. Executed: with the container basis and a 1-column fold but **no** bound, `prg.s19` emits **60 columns into a 50-column bar** while leaving 5 runs invisible (P-48). With the bound — floor 1 per run, remainder by largest-remainder on mapped bytes — `prg.s19` fits **exactly** at both regimes, all runs visible, monotone and strict, with **zero** aggregation (P-49).
- **Validation:** `test (integration)` + `analysis` · **Threshold:** `Σ widths + Σ markers ≤ bar.region.width` for **every IN-DOMAIN suite fixture** (**15 of the 16** shipped image fixtures — derived, rev 5) **and** for `examples/case_00_public/prg.s19` specifically. For the one out-of-domain fixture the threshold is *returns without raising*, verified by `AT-B77-18`. *(Revision 3 said "every suite fixture", which `case_08` falsifies.)*
- **Acceptance:** the bound is asserted on the **emitted widths**, and separately the allocator is unit-tested over a swept run count, so the bound holds **by construction** rather than by luck on one fixture.

**LLR-111.8 — WITHDRAWN to batch-78 (R-10). Recorded, not deleted.**
- **Was:** *"When the number of emitted run segments plus gap markers would exceed the container width, the panel shall merge the smallest adjacent runs into aggregate segments … and shall render in the region list a disclosure stating the exact number of runs that lost their own segment."*
- **Why withdrawn:** the Phase-2 re-gate found **six** independent defects in this one path — an aggregate's monotonicity subject does not exist on `BandSegment` (RB-2), the stopping rule terminates exactly where the strict-∃ clause dies (RB-3), the disclosure count is ambiguous three ways on the real fixture (RB-4), the coverage guard goes false on correctly-aggregating code (QA N-1), the justifying premise for its synthetic fixture was false (RB-6), and the merge loop is O(n²) on the UI thread (security M-3r). **Exactly one shipped fixture crosses the onset**, and `LLR-111.7` alone fixes the other sixteen.
- **Where it went:** carry **`C-77-l`** in §6.3 charters batch-78 with every measurement already paid for.
- **What replaced its acceptance:** `AT-B77-17` is withdrawn with it; **`AT-B77-18`** now covers the out-of-domain case with the only two claims batch-77 can honestly make — no raise, region list complete.
- ⚠️ **This is a scope reduction, not a silent deletion.** `HLR-111` now states its domain explicitly and describes the out-of-domain behaviour truthfully rather than leaving a hole where a universal used to be.

**LLR-111.2 — gaps fold to ONE column (R-5)**
- **Statement:** Each unmapped gap **shall** render at exactly one column, independent of its byte size and of the container width, and **shall** remain a plain `Static` classed `map-band-seg map-band-gap` — never a `RegionRow`, never a `BandSegment`.
- **Value rationale (measured):** at 21 columns `fold=2` yields `[3,3,3,3,1]`, collapsing three runs to equal width and gutting the strict limb; `fold=1` preserves discrimination at every container size.
- **⚠️ Scope reduction:** the charter's 2-column marker + humanized size label is **descoped** — carry **C-77-g**.
- **Acceptance:** existing `test_ac6_gap_hatch_segments_are_not_clickable` and `test_ac6_band_segments_do_not_widen_region_row_queries` stay green **unmodified** — **PIN, not gate**.

**LLR-111.3 — no segment paints outside its container (scoped to the domain, rev 4 / arch RC-1)** · **Statement:** While the image satisfies `n_runs + n_gaps ≤ bar.region.width`, every `.map-band-seg` **shall** satisfy `bar.region.contains_region(seg.region)`. **⚠️ Why the scope was added:** revision 3 left this an unconditional universal that a **shipped fixture falsifies** — executed on `case_08` under batch-77's own producer, `outside = 1535` @bar=66 and `1551` @bar=50. `HLR-111`'s Statement was scoped by R-10 and this child was not; the unsatisfiable-universal defect did not leave with `LLR-111.8`, it stayed in its siblings. **Threshold:** outside `0` at both regimes (today **0 @80×24 / 4 @120×30**). **Acceptance:** this is what retires the PIN test — §6.5 Amendment C.

**LLR-111.4 — the gapless no-op control (R2), payload RE-DERIVED (arch B-6)**
- **Statement:** For a gapless image rendered at a fixed container width, the concatenated `.map-band-seg` classes and content **shall** equal a golden captured from the shipped producer after the width basis is settled.
- **Fixture — MUST be unequal.** Under the R-7 container basis, through the mandated allocator, `EQUAL 512/512` gives **`[33,33]` @bar=66 and `[25,25]` @bar=50** — equal widths at each regime, invariant under any monotone re-weighting → **vacuous**. *(Revision 2 printed `[30,30]` "at both regimes": `30+30 = 60`, one more retired-60-basis residue, and the "both regimes" phrase was false under R-7. The vacuity argument is basis-independent and survives; only the numbers were stale.)* Use **`UNEQUAL 768/256`**.
- **⚠️ Corrected payload.** Revision 1 printed `[45,15]` labelled *"@80×24, container 66"*. **`45+15 = 60 = _BAND_BAR_WIDTH`, the retired constant.** Executed on the container basis:
  ⚠️ **Corrected AGAIN at revision 3 (arch RM-1) — and the defect was the METHOD, not the arithmetic.**
  Revision 2's `[50,16]`/`[38,12]` are plain `round(bar·b/total)`. That is **not the allocator `LLR-111.7`
  mandates**. Through the mandated allocator (floor-1 per run + largest remainder, gapless so `n_gaps = 0`):
  ```
  method                       bar=66        bar=50
  LLR-111.7 allocator          [49, 17]      [37, 13]     <- MANDATED; this is the expected payload
  plain round()                [50, 16]      [38, 12]     <- what revision 2 printed
  retired 60-basis             [45, 15]      —            <- what revision 1 printed
  ```
  Both sum to the bar, so both satisfy the bound — which is exactly why this survived a revision: the
  numbers looked plausible and the `predicted` label was honest about *when* they were computed but silent
  about *which method* computed them. **As printed in revision 2 they would have flagged a CORRECT capture
  as wrong.** Every payload in this document now names its method.
  ✅ **EXECUTED AT Inc-3 — the label is DISCHARGED, not left standing.** The golden was captured from the shipped producer through the acceptance's own fixture and drive helpers, **never pasted from here**. Captured payload: **`[49,17]` @bar=66 and `[37,13]` @bar=50** — matching the mandated allocator and **two independent executions** of `_allocate_band_widths`. Stored at `tests/goldens/batch77/at-b77-02-gapless-band-strip.txt` (404 B · sha256 `b2805bf0…` · **0 CR bytes in the STORED BLOB**, verified via `git show :<path>`, not via the worktree file · `-text` in `.gitattributes`). *(A `predicted` label left on an executed result is the same defect as a discharge mark on a prediction — the document is false either way. Cleared at the increment that discharged it, not deferred to close.)*
- **⚠️ C-42 encoding:** compare against the widget's runtime `render()` text — never snapshot-export bytes (`&#160;`), never a raw console `print` (my probe died on `UnicodeEncodeError` under cp1252). `-text` in `.gitattributes` if stored.
- **⚠️ COUPLING TO THE CONTAINER CSS — stated so a future failure is read correctly (merge-gate L-3).** Each golden record is keyed by the **settled bar width** (`80x24|66|…`, `120x30|50|…`). **Any CSS change that moves `.map-band-bar`'s width therefore reddens `AT-B77-02` BY DESIGN.** That is the contract working, not drift: `LLR-111.1` makes the measured container the basis, so a silent width change *is* a silent change to every emitted segment width, and this coupling is the only thing that surfaces it. **An editor who widens or narrows the bar must re-capture the golden deliberately and record the new settled widths** — never `-k`-skip the node. Conversely, this node reddening with **no CSS change in the diff** is the real alarm: the allocator or the settle path moved. Recorded in the node docstring too (`tests/test_tui_map_big.py`, `test_b77_gapless_golden`), because the person who hits the failure is reading the test, not this document.

**LLR-111.5 — C-40 register for HLR-111** — *(each row carries its true status; see §9)*

| Predicate | Subject in the expression? | Mutation (substituted VALUE) | Status |
|---|---|---|---|
| `AT-B77-01` | ✅ `visible_cols` = `BandSegment.region` clipped to `bar.region`; `run_bytes` present | denominator → `total_span`; basis → `_BAND_BAR_WIDTH` | ✅ **GATE — RED both arms, executed** |
| `AT-B77-03` | ✅ `seg.region`, `bar.region` | restore the `_BAND_BAR_WIDTH` basis | ✅ **GATE — 4 outside @120×30, executed** |
| `AT-B77-18` 🆕 | ✅ the raise-or-not and the region-list row count | make the allocator raise on `avail < n_runs` instead of degrading | ✅ **GATE (out of domain) — evaluable today**: `case_08` renders, 801 rows, no raise |
| ~~`AT-B77-17`~~ | — | — | ❌ **WITHDRAWN with `LLR-111.8` (R-10)** — see the withdrawal record |
| `AT-B77-02` | ✅ classes + text per segment | **substitute the allocator with plain `round(bar·b/total)`** — executed: `[49,17] → [50,16]` @66 and `[37,13] → [38,12]` @50, so the golden reddens | ✅ **GATE — the mutation is real** *(revision 2 prescribed "substitute the fold denominator", a **provable no-op**: the fixture is gapless, `n_gaps = 0`, so `avail = bar_w − 0·fold` is identical at fold 1/2/5/60 — executed, payload `[49,17]` at every value. arch RB-5.)* |
| `AT-B77-15a` | ✅ the rendered payload and its spans | remove `safe_text` from the A2L path → `Text.from_markup` | ✅ **GATE — executed**: `limb1_literal True→False`, `limb2_nospans True→False` |
| `AT-B77-15b` | ✅ the painted strip's control bytes | **revert the C0/C1 filter (substituted VALUE: scrubbed → raw)** — available only because **R-11 lands the scrub in this batch** | ✅ **GATE after Inc-2** *(the revision-2 mutation "remove `safe_text`" is **INERT** on this limb — `safe_text` is a no-op on ESC to begin with, executed `limb3 noESC False→False`. security B-1r(c).)* |
| ~~`Σ content ≤ _BAND_BAR_WIDTH`~~ | ❌ certifies a constant, not the operator's view | — | ❌ **REJECTED by R1 — recorded so it is not reintroduced** |
| ~~`monotone` alone~~ | ❌ GREEN at both regimes today | none exists | ❌ **VACUOUS LIMB — never the gate alone** |
| ~~`strict ∃` on the containment domain alone~~ | ❌ **the subject need not exist** — at `surplus × spread ≤ total` no allocator can produce it | none exists; it is unsatisfiable, not untested | ❌ **UNSATISFIABLE CLAUSE — replaced by Amendment D's precondition.** Recorded so it is not reintroduced: this shipped in revisions 1–5 and no test caught it, because `TC-B77-03`'s all-equal fixture gave the limb no subject |
| ~~rev-1 C-31 equality guard~~ | ❌ FALSE on correct code (P-44) | — | ❌ **REPLACED by the runs-oracle + coverage pair** |

**LLR-111.6 — geometry is read from settled layout, corrected (arch B-7)**
- **Statement:** Every test that reads a rendered region **shall** re-read the container width after successive `pilot.pause()` boundaries until two successive **post-pause** reads agree, and **shall not** treat repeated reads taken within a single frame as evidence of settling.
- **⚠️ Revision 1's rationale trace is RETRACTED.** It cited `68 → 68 → 66` as a live trace that would defeat a two-read rule. Executed at revision 2, 12 trials: **same-frame triples** `{(66,66,66):9, (68,68,68):3}` — the repeated `68` came from reading three times **inside one frame**; **one-read-per-pause sequences** `{(66,66,66):9, (68,66,66):3}` — never two consecutive transients. Architect's independent 97 traces (`0/60` double-68 across pauses) agree. **The phenomenon (N-2) is TRUE; my description of it was wrong, and the wrong description would have justified a stricter helper than the evidence supports.**
- **One criterion, not two.** Revision 1 also carried a weaker acceptance line ("no geometry AT calls `pilot.pause()` exactly once"). **Deleted** — the post-pause fixed-point rule is the single criterion.
- **Threshold:** ≥15 consecutive runs report the same settled width per regime.

### HLR-112 → LLR-112.x

**LLR-112.1 — ticks derive from RUN starts plus the last mapped byte (R4, §2.9)** · **Statement:** `MapRuler` **shall** accept the ordered emitted-run start addresses and the last mapped byte, and **shall** emit one `.map-ruler-tick` per retained address, replacing the fixed `_TICK_COUNT = 5` percentile derivation. **Symbols:** `MapRuler:1234`, `_TICK_COUNT:1274`, `compose:1293`, construction `:2102` (signature changes). **Threshold:** 0 labels outside every mapped range (today 4 of 5); `END_LABEL == f"{span_end-1:08X}"` — executed `0x07FFFF3D` mapped **True** vs `span_end 0x07FFFF3E` mapped **False**.

**LLR-112.2 — legibility, not overlap (security M-1)** · **Statement:** The ruler **shall not** emit a tick whose rendered width is less than the length of the label it carries, and **shall** retain the first and last labels in preference to any interior label when labels must be dropped. **Rationale (informative):** revision 1 asserted "0 overlapping column ranges", which **cannot fail** — `width:1fr` children partition the row and never overlap; they degrade to zero width. Executed in a synthetic `1fr` row: `N=20, W=50 → max tick width 3` (an 8-char label elided); `N=60, W=50 → 10 zero-width ticks, 0 overlaps`, and revision 1's conjunction was **GREEN**. **Sufficiency argument, re-derived at revision 4 (arch RC-2).** Revision 3 justified this predicate by saying *"`LLR-111.8`'s aggregation lowers the run count the ruler must label"* — **the one live dangling reference to the withdrawn LLR**, and, worse, the predicate's whole *sufficiency* argument. With aggregation descoped that support is gone and the predicate needs a new one, which is this: **elision is not a fallback, it is the out-of-domain behaviour itself.** `HLR-112`'s domain admits at most `ruler_width ÷ label_width` ticks — measured, **8 @66 and 6 @50** for 8-hex-digit labels. Past that the ruler *must* drop labels, and the only question is whether it drops them **legibly or silently**. This predicate is what forces the former: it fails on a ruler that renders 802 ticks at 0 columns each, which is precisely what `1fr` does by default. It needs no aggregation to be sufficient — it is the clause that makes the domain edge observable. **Separator convention (normative, rev 5):** adjacent tick labels **shall** be separated by at least one blank column, so the per-tick pitch is `len(label) + 1 = 9`. **This is not cosmetic: it decides domain membership** — at pitch 8 the ceiling is 8/6 and `case_07_stress_smoke` reads as in-domain at 120×30 when it is not. **Geometry:** ruler measured at **66 / 50**, ceiling **7 / 5**, derived at rev 5; the `0x`-prefix-drop fallback is **already spent** (`:1245-1247`).

**LLR-112.3 — the retired clause is amended at EIGHT sites (arch M-3, security M-2)**
- **Statement:** The batch **shall** record Before/After amendments for `R-TUI-072` and `LLR-072.3` and **shall** update every surviving statement of the retired 5-tick contract in shipped source, tests, `REQUIREMENTS.md`, and the batch-47 artifact set.
- **Census — CLOSED at Inc-5. Executed total: 35 statement sites in 13 files** — **7 sites / 4 files** discharged at Inc-4, **28 sites / 9 files** at Inc-5. Against this document's own estimate of *"9 known, roughly 14 more"* (**≈23**), the executed figure is **52 % higher**, and it is the fourth consecutive revision whose quoted integer was low.
  ⚠️ **Inc-5's own first draft of this line said "33 sites in 11 files" and both numbers were wrong** — 11 was the count of files *edited* (which includes `BACKLOG-CODE.md` and this document, neither a census site, and excludes Inc-4's four). Caught by re-adding the per-file column instead of trusting the summary. **A total that is not re-derived from its own table is the same defect as a threshold that is not re-derived from its claim**, committed inside the item that exists to catch it.

  **Discharged before Inc-5 (Inc-4, code + tests):**
  | # | Site | Form | State |
  |---|---|---|---|
  | 1–4 | `screens_directionb.py:1239, :1273, :1300, :2002` | `LLR-072.3` citations | ✅ Inc-4 |
  | 5 | `tests/test_tui_map_big.py:118` (+ `:140` `len(ticks)==5`) | citation + assertion | ✅ Inc-4 |
  | 6 | `tests/test_tui_snapshot.py:670` | citation | ✅ Inc-4 |
  | 7 | **`s19_app/tui/legend.py:606-614`** | **PROSE** — matches no `LLR-072` grep; **what the operator reads** | ✅ Inc-4 |

  **Discharged at Inc-5 (documents) — 28 sites: 3 in `REQUIREMENTS.md`, 25 across 8 batch-47 files:**
  | File | Sites | Treatment |
  |---|---:|---|
  | `REQUIREMENTS.md` | **3** — `R-TUI-072` Statement `:4790`; the duplicate in `R-TUI-060`'s §6.5 Amendment B `:4191`; 🆕 **`R-TUI-072`'s own `Validation:` line `:4798`** | Statement amended in place + full Before/After block (**Amendment A**) |
  | batch-47 `01-requirements.md` | **7** — `HLR-072` Statement `:245`; observation `:254`; AT list `:255`; **`LLR-072.3` Statement `:510`**; acceptance criteria `:514`; AT table `:607`; §6.5 Amendment B "After" `:727` | normative → amended in place + Before/After (**Amendment B**) |
  | batch-47 `01b-qa-strategy…md` | **7** — `:29`, 🆕 `:65` (`**5-tick address ruler**`), `:132`, `:203`, `:277`, `:292-293`, `:301` | historical → banner + per-site marker |
  | batch-47 `02-review.md` | **1** — `:76` | historical → per-site marker |
  | batch-47 `03-increments/increment-05.md` | 🆕 **1** — `:131` (`5-tick ruler`) | historical → per-site marker |
  | batch-47 `03-increments/increment-06.md` | **3** — `:24`, `:106`, `:143` | historical → per-site marker |
  | batch-47 `04-validation.md` | **3** — `:53`, `:106`, `:144` | historical → per-site marker |
  | batch-47 `06-docs/functionality.md` | **1** — `:173` | living doc → corrected in place |
  | batch-47 `06-docs/traceability-matrix.md` | **2** — `:54`, 🆕 `:92` | living doc → corrected in place |

- **⚠️ FOUR sites were missed by every prior census, and the misses are informative, not incidental.**
  1. **`REQUIREMENTS.md:4798`** — `R-TUI-072`'s own `Validation:` line, quoting *"**exactly 5** ticks"* as `AT-072b`'s predicate. **It sits eight lines below the Statement the census DID name.** The census read the Statement and stopped; the requirement restates its own contract in its verification row.
  2. **`01b:65`** and **`increment-05.md:131`** — both write **`5-tick`**, hyphenated. Every prior sweep searched `5 tick` / `exactly 5 tick`. **A hyphen defeated the census twice.**
  3. **`traceability-matrix.md:92`** — a *second* row in a file the census already named at `:54`. Naming a file by one line number invites checking that line and closing the file.
- **The controlling lesson, restated with its fourth and fifth pieces of evidence:** site 7 proved an **id-keyed** grep cannot find a prose restatement. Sites 1–3 above prove a **phrase-keyed** grep cannot find a hyphenation variant, and a **line-keyed** census cannot find a sibling line. **The only sweep that closed this census was: derive a superset predicate from the CLAIM (`ruler|tick` across the whole scope, 327 hits), read every hit, and classify.** That is what the Threshold mandates and it is why it is worded that way.
- **Deliberately EXCLUDED, recorded so the exclusion is a decision rather than an oversight:**
  - `prototypes/legend_n8.INVENTORY.md:76`, `legend_n8.kimi.NOTES.md:132`, `legend_n8.kimi.prototype.py:166`, `screen_upgrades.HANDOFF-PLAN.md:112` — **KEPT-by-operator-decision prototypes**, outside the Threshold's four roots. **Left untouched, verified untouched.**
  - `.claude/worktrees/c3-d2-triage/` — a **detached git worktree** at `f8747b8` living under the repo root, carrying a full second copy of `s19_app/`, `tests/`, `REQUIREMENTS.md` and `.dev-flow/`, all still pre-Inc-4. Its paths are not under the Threshold's roots. ⚠️ **Recorded because a naive `grep -rn` from the repo root returns it and doubles every count** — a future census that does not exclude it will report ~66 sites and be wrong in both directions.
  - batch-47 `05-postmortem.md`, `PLAN.md`, `executive-summary.md`, `architecture-dataflow.md` — read; each mentions *the ruler* but **states no tick count or percentile**. Not restatements. **Read and cleared, not skipped.**
- **⚠️ Why site 7 matters most:** it is what the **operator reads**. `AT-B77-07` (legend screen unaffected) would pass **green** while the legend screen describes pre-batch behaviour. A census keyed on an id cannot find a prose restatement — **C-42 in its purest form**, and the reason the census is now derived from the *claim* rather than from the *id*.
- **Threshold, DERIVED not counted:** **0** surviving statements of the retired 5-tick contract under `s19_app/`, `tests/`, `REQUIREMENTS.md` and `.dev-flow/2026-07-15-batch-47/`, verified by **reading each file the sweep returns** rather than grepping for the id.
- ⚠️ **The integer was a LOWER BOUND in FOUR consecutive revisions — 6 → 8 → 9 → "9 + ~14" (≈23) → the executed 35.** Every revision that quoted a number quoted one it had not derived from the claim, and every one was low. **The Statement's *"and the batch-47 artifact set"* wording governs; the tables above are a RECORD of what the sweep returned, not a budget the sweep must reconcile to.** Had Inc-5 reconciled to "≈23" it would have stopped four sites short and reported a green census.

### HLR-113 → LLR-113.x
**LLR-113.1 — dual readout, precision pinned** · **Statement:** `build_stats_text` **shall** compose the mapped total and image span through `insight_style.human_bytes` and **shall** render the coverage percentage with exactly four fractional digits. **Symbols:** `build_stats_text:2275`, the `Coverage` f-string `:2304`, `human_bytes insight_style.py:124`, `CoverageStats:966`. **Acceptance:** no new arithmetic over `ranges` (LLR-041.7 preserved).
**LLR-113.2 — humanized largest gap** · **Statement:** The largest-gap statistic **shall** render through `human_bytes`. **Acceptance:** ⚠️ C-40 — the absence half is green on an empty strip; pair it with presence.

### HLR-114 → LLR-114.x
**LLR-114.1** · **Statement:** `_build_band_widgets` **shall not** construct or return a `.map-band-legend` container. **Acceptance:** ⚠️ C-38 — scope the query to `#map_grid`, or it falsely reddens when the legend screen is open.
**LLR-114.2** · **Statement:** The `k` binding and `action_show_legend` **shall** remain unmodified. **Threshold:** 0 diff lines in `app.py:1345-1375`.

### HLR-115 → LLR-115.x
**LLR-115.2 — arrow movement with stated edges** · **Statement:** While a region row has focus, `↑` **shall** move focus to the previous row and `↓` to the next in ascending address order; at the first row `↑` **shall** leave focus unchanged and at the last row `↓` **shall** leave focus unchanged. **⚠️ C-16** `assumed — verify at Phase 3`. **Acceptance: `pilot.press` only.**
**LLR-115.3 — `Enter` inspects via the single click-policy site** · **Statement:** `Enter` **shall** cause the focused row to post `RegionRow.Activated` with `chain = 1`. **Symbols:** `Activated:1123`, `chain:1141-1147`, `on_region_row_activated:2422`, gate `:2461-2471`.
**LLR-115.4 — no application binding is shadowed** · **Statement:** `RegionRow.BINDINGS` **shall not** bind `j`, `k` or `o`. **Symbols:** `app.py:1352/1356/1359`; `_PRE_BATCH_BINDINGS tests/test_tui_directionb.py:5460-5478`; `test_tc011_…:5578`. **Threshold:** those literals appear **0** times in `RegionRow.BINDINGS`; `AT-B77-09` (gate) and `AT-B77-16` (pin) green; **TC-011 green and unmodified.**

> ⭐ **`AT-B77-16`'s WORKING mutation — the substituted VALUE, recorded here because it existed only in a commit message (merge-gate M-2).** §9 asserts the PINs are *"falsified only by their named mutation"*, and the mutation this document named — adding `Binding("k", …)` to `RegionRow.BINDINGS` — is **INERT** for this PIN: Inc-8 executed it and both PINs stayed GREEN. The mutation that actually reddens both PINs at both arms, on the behavioural assertion, is in the **application** binding table, not the row's:
> ```
> s19_app/tui/app.py:1359      Binding("k", "show_legend", "Legend", show=True)
>                    key "k"  ->  key "f9"
> ```
> **Record the substituted VALUE, not the deleted operator** (project control): "break the `k` binding" names at least two distinct edits — removing the row-level shadow and re-keying the application action — and only the second has a tooth here. Confirmed by the independent merge-gate reviewer to redden **both** PINs at **both** arms. ⚠️ **A PIN whose named mutation is inert is a PIN with no demonstrated subject**; §9's claim was true of the id and false of the mutation beside it.
> *(`LLR-115.1` deleted — moved to `LLR-116.1` per arch B-4.)*

### HLR-116 → LLR-116.x
**LLR-116.1 🆕 — rows are focusable and reachable (moved from `LLR-115.1`, arch B-4)** · **Statement:** `RegionRow` **shall** be declared focusable, and the panel **shall** establish a focus path to the region rows without operator input. **Symbols:** `RegionRow:1088`; `can_focus` **NEW — created in Phase 3** (0 hits today). **⚠️ Textual internal-name shadowing:** every new member **shall** be checked against `dir(Widget)` — a `_nodes`/`_context` collision is a silent mount crash with no traceback. **⚠️** Do not widen the global `tab` chain without checking the rail — it changes focus on every screen. `assumed — verify at Phase 3`. **Why it moved:** `row.focus()` is a **no-op** while `can_focus` is False (architect-executed), so this is a precondition of `LLR-116.5`, not of the keyboard behaviour.
**LLR-116.2 — auto-select after reset, on a post-refresh hook** · **Statement:** The panel **shall** resolve and apply the selection after `_reset_detail()` has run and after the mounted rows are queryable. **Symbols:** `render_ranges:1808`; `_reset_detail()` call `:1896`, body `:2313-2330`; `_ordered_ranges:1923`; `grid.mount():1927-1929`. **⚠️ `grid.mount()` is deferred** — "after the rows are mounted" is not a synchronous point; a post-refresh hook is required (QA B-3 root cause).
**LLR-116.3 — auto-selection never navigates** · **Statement:** Auto-selection **shall not** post `MemoryMapPanel.OpenInHexRequested`. **Acceptance:** ⚠️ C-40 — co-assert the inspector was populated in the same run.
**LLR-116.4 — re-render resolution (R-6)** · **Statement:** On each render the panel **shall** resolve the selected region to the previously selected region when a region with that start address is present among the newly rendered rows, and to the first region otherwise. **Rationale (informative):** matching is by **address**, never index — a re-merge changes how many runs precede the selected one.
**LLR-116.5 — focus follows the resolved selection, and the focused row is LIVE (QA B-3)** · **Statement:** After the selection is resolved, focus **shall** be on a region row that is attached to the running application and present among the panel's currently mounted region rows, and whose start address equals the resolved selection. **Threshold:** `app.focused in set(app.query(RegionRow))` **and** `app.focused.is_attached` **and** `app.focused.region_start == resolved`. **Rationale (informative):** identity alone is satisfied by a **detached** row — QA executed `is_attached=False`, `parent=None`, focused row absent from the 5 live rows, threshold `True`. Deferred child removal (`:2094-2097`) is the mechanism.
**LLR-116.6 — the auto-populated inspector is markup- and control-char-safe (security B-1)** · **Statement:** On a render that auto-selects a region, `#map_detail_body` **shall** render every file-derived string as literal content with no style span and no hyperlink, and **shall not** emit any C0 or C1 control byte into the painted strip. **Symbols:** `build_detail_text:2338`; A2L path `:2397-2400`; `ValidationIssue` path `:2410-2417`; `safe_text:688`. **Threshold, per limb per size (CC-1):** every **non-control** character of the payload verbatim in `render().plain` — **RED today (`False`)**; `render().spans == []` — GREEN today; **no C0/C1 byte in any painted strip row — GREEN today VACUOUSLY (nothing rendered: the body still shows `_DETAIL_HINT`), genuinely RED once Inc-7 lands auto-select, GREEN again once Inc-2's scrub lands**; no raise. **Validation:** `test (e2e)`, routed to a **non-frozen** test file. **⚠️** Read the **painted strip** for the control-byte limb, not `.plain` — `.plain` is where the byte lives, the strip is where it escapes. **⚠️ The control-byte limb is evaluated only after its precondition (payload present) holds** — see the `AT-B77-15a/b` block.

**LLR-116.7 🆕 — `safe_text` strips C0/C1 control bytes (R-11)** · **Statement:** `safe_text` **shall** remove from its input every codepoint in the C0 range `U+0000`–`U+001F` except the retained whitespace it already emits, the delete character `U+007F`, and every codepoint in the C1 range `U+0080`–`U+009F` — **selecting them as a byte CLASS, not by matching an escape-sequence pattern** — before composing the returned `Text`, and **shall** preserve every non-control character of the input verbatim, including square-bracket markup and URL-like substrings.
- **⚠️ The byte-class form is NORMATIVE, so Phase 3 cannot regress it to a regex (security forward flag).** `U+009B` is **single-byte CSI** and `U+009D` **single-byte OSC** — functional equivalents of `ESC [` and `ESC ]` that carry **no `\x1b` at all**. A filter written as *"strip `\x1b`-introduced sequences"* passes both and silently reopens the hole. Security executed the class filter against them: `U+009B` → `'a31mb'`, `U+009D` → `'a8;;ub'`, **residual control = False** in both. **Identity damage 0/14** legitimate symbol names; an AST census over **85 call sites in 4 modules** found **0** literal-argument control characters, so no call site depends on the current pass-through. **Symbols:** `safe_text` `screens_directionb.py:688`; its docstring claim `:694-697`. **⚠️ NOT frozen** — `safe_text` lives outside `_ENGINE_PATHS`, verified; in-scope for batch-77 under **R-11**. **Rationale (informative):** the shipped docstring asserts `safe_text` neutralises *"raw ANSI bytes carried in the never-scrubbed `ValidationIssue.symbol` — no style/ANSI leak"*. **Executed, the markup half is TRUE and the ANSI half is FALSE**: `safe_text('sensor\x1b[31m_evil[red]')` returns the string **unchanged**. Revision 2 carried the fix out of the batch as `C-77-h`, which would have left `LLR-116.6`'s normative `shall not` with **no verifier able to pass at close** — a red gate the batch could not satisfy. **Threshold, executed against a candidate C0/C1 filter:** `'sensor\x1b[31m_evil[red]'` → `'sensor[31m_evil[red]'` (ESC gone, `[red]` literal intact); `'a\x07b\x00c'` → `'abc'`; `'x[link=file:///C:/W]click[/link]'` and `'plain_ok'` **unchanged**. **Acceptance:** the docstring at `:694-697` is corrected in the same edit so the source no longer asserts a guarantee ahead of the code. Snapshot drift expected; absorbed by Inc-9's regen.

### HLR-117 → LLR-117.x
**LLR-117.1 — marker applied by address** · **Statement:** The panel **shall** apply a selection marker to the region row whose `region_start` equals the resolved selection, and to no other row. **Threshold:** exactly 1 (today 0), matched by address not index.
**LLR-117.2 — the band channel survives selection (strengthened, security m-1)** · **Statement:** Applying or removing the selection marker **shall not** add, remove or override any `band-*` class on the row, and the selection style **shall not** set a foreground colour nor a text style that inverts foreground and background. **Change:** revision 1 said only "no `color:` property", which `text-style: reverse` satisfies while repainting the band colour.

**`TC-B77-26` / `TC-B77-27` / `TC-B77-28` — WITHDRAWN at Inc-8. Recorded, not deleted.**
- **Was:** nothing. That is the whole finding. The three ids appear in exactly two places — §3 `HLR-117`'s boundary list and §5.2's functional chain — **as bare ids, with no content stated for them anywhere in the batch artifacts**, at any revision. Unlike `TC-B77-25`, which carries its own fixture constraint inline, these three were allocated and never specified.
- **Why withdrawn:** Inc-7 emitted two HLR-117 nodes beyond `AT-B77-12`/`TC-B77-25` and correctly **refused to label them `TC-B77-26/27/28`**. Retro-fitting content into an id whose intent nobody recorded is **minting under an existing number** — it makes the id mean whatever the later increment happened to write, which is precisely what a spent-id rule exists to prevent.
- **The rule this follows is already this batch's:** `AT-B77-17` established that **a spent id is never reused, so allocation stays monotonic and an id can never mean two things** (§5.4). Withdrawing without reuse is the same rule applied to ids spent by *allocation* rather than by *specification*.
- **What replaced them:** Inc-7's two unlabelled nodes take the next free ids — **`TC-B77-32`** (`test_tc_b77_32_b77_style_band_token_survives_selection`, LLR-117.2 behavioural arm) and **`TC-B77-33`** (`test_tc_b77_33_b77_style_selection_rule_sets_no_foreground_no_inversion`, LLR-117.2 inspection arm). **`26`/`27`/`28` are not reused.**
- ⚠️ **This is a coverage question the withdrawal does NOT answer.** Withdrawing the ids does not establish that HLR-117's boundary catalog is complete at two entries; it establishes only that three of its entries were never real. Whether HLR-117 needs further boundaries is a separate judgement, and none is claimed here.

---

## 5. Validation strategy

### 5.1 Standing rules
1. **Read the layer that holds the fact.** Geometry → `widget.region` clipped to the container, at **settled** layout. Selection/band style → `widget.styles.*` (**not** `render().spans`, measured `[]`). Control bytes → the **painted strip**. Text → `#map_stats_body`/`#map_detail_body` (**not** the containers, which render `Blank`). Footer → `app.active_bindings` filtered `.show and .enabled`.
2. **Settle before measuring geometry** (`LLR-111.6`) — post-pause fixed point, never a same-frame repeat.
3. **Every absence assertion carries a presence co-assertion** (C-40).
4. **Per-arm verdicts (CC-1)** — every AT parametrized over both sizes; report RED/GREEN **per resolved node id per arm**. `AT-B77-01`'s arms redden on different limbs; an aggregate verdict destroys that.
5. **C-34** — every increment touches a render module: full `tests/test_tui_directionb.py` + full `tests/test_tui_map_big.py` + full `tests/test_map_click_chain.py` at every gate.
6. **Mutation discharge is executed, not described** — substituted VALUE recorded, isolated tree, `PYTHONDONTWRITEBYTECODE=1`, restore proven by a **green run**.
7. **No test deleted in the increment that changes the behaviour it guards.**

### 5.2 Dual traceability — behavioural chain

| US | Outcome | AT | Pre-change verdict |
|---|---|---|---|
| US-77-1 | runs visible, ordered, bounded, folded | `AT-B77-01` | **RED both arms** (different limbs) — executed |
| US-77-1 | gapless no-op | `AT-B77-02` | ✅ **GATE — DISCHARGED at Inc-3, executed.** allocator → plain `round()` reddens it at **both** size arms (`[49,17]→[50,16]` @66 · `[37,13]→[38,12]` @50), reddening exactly the 3 payload-asserting nodes while correctly leaving the fixture-shape and stored-encoding nodes GREEN (per-arm, CC-1). Tree restored, hash-proven `ecdca06b…`→`ecdca06b…` |
| US-77-1 | nothing outside the bar | `AT-B77-03` | **RED @120×30** (4 outside) — executed |
| US-77-1 | out of domain: no raise, region list complete | `AT-B77-18` 🆕 | **evaluable today** — `case_08` (801 runs) renders, 801 region rows, no raise, at both regimes |
| US-77-2 | every label admissible + legible | `AT-072b` | **RED** — 4 of 5 unmapped — executed |
| US-77-2 | lower bound | `AT-B77-04` | **RED**; `set() ⊆ admissible` is True — executed |
| US-77-3 | dual readout | `AT-B77-05` | **RED** — executed |
| US-77-4 | legend gone from body | `AT-B77-06` | **RED** — 4 rows, 1 container — executed |
| US-77-4 | legend screen intact | `AT-B77-07` | **PIN** |
| US-77-5 | arrows + Enter | `AT-B77-08` | **RED** — `can_focus=[False]×5` — executed |
| US-77-5 | no binding shadowed, focus ON row | `AT-B77-09` 🔄 | **PIN** — GREEN before and after; falsified only by its named mutation (add `Binding("k",…)`). Relabelled at rev 3 (arch RM-2) |
| US-77-5 | same, focus off row | `AT-B77-16` 🆕 | **PIN** |
| US-77-5 | N4a mouse split | `AT-B77-10` | **PIN** — reuse `test_ac3_…`/`test_ac4_…` (QA M-5) |
| US-77-6 | focused + inspected, zero input | `AT-B77-11` | **RED** — executed |
| US-77-6 | re-render preserved + focus LIVE | `AT-B77-13` | **RED** — executed |
| US-77-6 | re-render fallback + focus LIVE | `AT-B77-14` | **RED** — executed |
| US-77-6 | hostile input: payload literal, no spans | `AT-B77-15a` 🔄 | **RED** — executed: `limb1 payload-verbatim = False` at both sizes |
| US-77-6 | hostile input: no control byte painted | `AT-B77-15b` 🔄 | **GREEN today, VACUOUSLY** (nothing rendered — body shows `_DETAIL_HINT`); genuinely RED after Inc-7; GREEN by Inc-2's scrub. **Not listed as a gate before Inc-2.** |
| US-77-7 | selection visible | `AT-B77-12` | **RED** — 0 markers — executed |

**Functional chain:** HLR-111 → LLR-111.1…**.9** → `TC-B77-01…05`, `TC-B77-30` · HLR-112 → LLR-112.1…3 → `TC-B77-06…09` · HLR-113 → LLR-113.1…2 → `TC-B77-10…13` · HLR-114 → LLR-114.1…2 → `TC-B77-14…15` · HLR-115 → LLR-115.2…4 → `TC-B77-16…20` · HLR-116 → LLR-116.1…**.6** → `TC-B77-21…24`, `TC-B77-29`, `TC-B77-31` · HLR-117 → LLR-117.1…2 → `TC-B77-25`, **`TC-B77-32`, `TC-B77-33`** *(🆕 Inc-8 — `TC-B77-26/27/28` are **WITHDRAWN, allocated without content, never specified**, and their numbers are **not reused**; see the withdrawal record in §4 under `HLR-117 → LLR-117.x`)*.

### 5.3 Batch acceptance criteria — **RESTORED at revision 4 (QA M-3)**

> ⚠️ **This section was DELETED between revisions 2 and 3** — the numbering jumped 5.2 → 5.4 and nothing in
> §6.4 recorded a decision, so it read as collateral from the R-10 removal. It took the frozen-engine gate,
> the full-suite baseline and the 0-blockers-at-merge rule with it. **A batch that loses its own acceptance
> criteria during a split has no merge gate.** Restored below, adjusted for the descope; **no part of it was
> deliberately dropped** — the deletion was accidental, and that is recorded in §6.4.

- 100 % of LLRs covered by ≥1 TC with a pass result; every US has ≥1 passing AT observing its outcome through the shipped surface, with boundary + negative evidence.
- **Every gate AT demonstrated RED pre-change, per size arm** — with the four labelled exceptions in §9 (`AT-B77-02` discharged by mutation; `AT-B77-09`/`AT-B77-16` PINs; `AT-B77-15b` vacuous until Inc-2). No unlabelled exception is permitted.
- Every PIN labelled PIN, with its falsifiability discharged by a named mutation whose transcript is pasted.
- **Frozen-engine diff = 0** — source **and** `_ENGINE_TEST_FILES` (C-27 dual guard). Security re-verified **0 intersections across all 9 increments**.
- **TC-011 green and unmodified.**
- Full suite green — baseline **2514 passed / 2 skipped / 3 xfailed** (FULL form, batch-76 close). `tui-ci` runs `-m "not slow"` on PRs and the FULL suite on pushes; **the FULL form runs before merge** and every ledger figure states which form produced it.
- **0 blocker findings at the merge gate**, across all three review lanes.
- **Descope-specific (R-10):** the batch does **not** claim `HLR-111`/`HLR-112` hold out of domain. `AT-B77-18` is the only out-of-domain gate and asserts only *no raise* + *region list complete*. `C-77-l` is present and complete at close.

### 5.4 IDs
**Batch-scoped `AT-B77-01…16`, `AT-B77-18`, `TC-B77-01…33`.** *(🆕 Inc-8: high-water `TC-B77-31` → **`TC-B77-33`**; `TC-B77-26/27/28` **WITHDRAWN — allocated without content, never specified** — and like `AT-B77-17` their numbers are **not reused**, so the range is not contiguous and that is deliberate.)* `AT-B77-15` is **split** into `AT-B77-15a` (GATE, discharged) and `AT-B77-15b` (GATE from Inc-2). **`AT-B77-17` is WITHDRAWN with `LLR-111.8` and its id is NOT reused** — allocation stays monotonic so a spent id can never mean two things. Letter-initial bodies are outside `AT-TC-REGISTRY.jsonl` authority (`_meta.governed`, spec §2.3); **no reservation PR**. **Exception:** `AT-072b` keeps its global id as a re-derivation. New at revision 2: `AT-B77-15` (hostile input), `AT-B77-16` (shadow PIN), `AT-B77-17` (allocation bound), `TC-B77-30` (heterogeneous range), `TC-B77-31` (post-refresh hook).

---

## 6. Appendices

### 6.3 Risks and carries

| # | Item | Disposition |
|---|---|---|
| **C-77-h** | **✅ DISCHARGED at revision 3 — pulled INTO batch-77 by R-11, not dropped.** `safe_text`'s ANSI guarantee was asserted in shipped source and is FALSE (`screens_directionb.py:694-697`). Deferring it would have left `LLR-116.6`'s normative `shall not` with no verifier able to pass at close. **Now `LLR-116.7`, owned by Inc-2.** The carry is closed by implementation, not by re-filing. | **DISCHARGED — no longer a carry** |
| **C-77-l** 🆕 | **BATCH-78 CHARTER — the aggregation path, with every measurement already paid for.** See the block below. | **Lane-A carry, chartered** |
| **C-77-i** | ✅ **DISCHARGED at Inc-5.** `.dev-flow/BACKLOG-CODE.md:53` asserted `LLR-072.3` has *"ZERO definitions"* / is *"a dangling reference"*. **FALSE** — defined at `.dev-flow/2026-07-15-batch-47/01-requirements.md:508`, cited from 4 shipped-source sites. Corrected **with its reasoning**: the claim came from grepping `REQUIREMENTS.md`, which defines **zero** LLR bodies, so absence there is evidence of nothing. ⚠️ **The carry's own pointer did not reproduce:** it names `PLAN.md:171-173` as repeating the claim; those lines are the **process-count retraction**, an unrelated passage. The claim is at **`PLAN.md:82-85` and `:503`** — left as-is, both being a Phase-0 record of what was believed at the time, now corrected in the live queue a reader acts on. **A carry that mis-cites its own evidence is the defect class the carry exists to fix.** | **DISCHARGED** |
| **C-77-m** 🆕 | **`R-TUI-112` is cited in shipped source and tests but has NO row in `REQUIREMENTS.md`** (high-water `R-TUI-102`). Sites: `screens_directionb.py:612`, `:1454`; `tests/test_legend_two_pane.py:705`; `tests/test_tui_snapshot.py:671`, `:919`, `:957`. Minted by Inc-4 in comments without a register row. Under **Amendment A** the governing id is `R-TUI-072` **as amended**, so those citations are dangling. **Two clean resolutions — operator picks:** (a) add an `R-TUI-112` row and restate Amendment A as a supersession, or (b) re-point the six citations at `R-TUI-072`. **Not resolved at Inc-5** — both touch production source, which this docs-only increment is not scoped to. ⚠️ **This is `C-77-i`'s exact defect shape, committed by this batch two increments after cataloguing it.** | Lane-A carry, **open** |
| **C-77-j** 🆕 | **Pre-existing 1-column glance-box clip** — the box is 28, its widest content row is 29 (`'· constant/padding 3 ████ 60%'`). Found by the corrected R-7 sweep. `LLR-111.9` incidentally fixes it at 120×30 by giving the glance full width; the 80×24 path is unchanged. **Distinct from C-77-k** — different defect, same screen. | Lane-A carry |
| **C-77-k** 🆕 | **The stats line's scroll deepens** (R-8, accepted). `LLR-111.9` moves `#map_stats_body` from `bottom=31/30` to `bottom=33/30` at 120×30. It is **already below the fold at both regimes today** (`bottom=31/30` @120×30, `bottom=35/24` @80×24), so this deepens an existing scroll and **newly hides nothing**; the line stays reachable by scrolling exactly as today. **The widen is deliberately NOT narrowed to protect it** — every column surrendered lowers the ceiling on visible regions, which is the batch's whole purpose. **Distinct from C-77-j.** | Lane-A carry |
| **C-77-f** | `o` = open-hex descoped (R3) | Lane-A carry |
| **C-77-g** | 2-column marker + size label descoped (R-5) | Lane-A carry |
| **C-77-a/c/d/e** | dense `round()` drift (superseded by R1/R-7) · `REQUIREMENTS.md` not an HLR index · US-77-8 · Variant B | carried |
| **R-7** *(risk)* | Geometry unsettled after one pause (17/97, two lanes) | `LLR-111.6` |
| **R-8** 🆕 | `#map_stats_body` pushed 2 rows deeper below an already-below-the-fold position by `LLR-111.9` | **OQ-5** |
| **F-1** | Self-caught probe defects: (a) cp1252 `UnicodeEncodeError`; (b) temp-cleanup `PermissionError`; (c) an unsettled 23/50 read reported as fact; (d) `address_in_sorted_ranges` arg order inverted; (e) a `pilot.click` that did not land, making the R-6 arms RED for the wrong reason; **(f) 🆕 my R-7 candidate sweep compared the glance box against its TITLE (11 cols) instead of its widest CONTENT row (29) and reported "STARVED: none" for every candidate — the exact C-13 starvation the probe existed to detect**; **(g) 🆕 my first runs-vs-ranges fixture constructed `random.Random(3)` per byte, making the "random" half constant, so 1 range yielded 1 run and appeared to REFUTE the finding — corrected to one rng, 1 range → 2 runs** | recorded, not hidden |


#### `C-77-l` — BATCH-78 CHARTER: the aggregation path (R-10)

**Every measurement below is already paid for. batch-78 re-derives none of them; it re-verifies them and
builds on them.** The single most important line is the fixture rule.

| # | Measurement / finding | Value, executed |
|---|---|---|
| 1 | **Onset formula** | aggregation is required when `n_runs + n_gaps·fold > bar_width`, i.e. `2·n_runs − 1 > bar_w` |
| 2 | **Measured onset** | **26 runs @bar=50** (25 clean, 26 aggregates 1) · **34 runs @bar=66** (33 clean, 34 aggregates 1) |
| 3 | ⭐ **THE ACCEPTANCE FIXTURE, FROM THE START** | `examples/professional_validation/case_08_heavy_fragmentation/firmware.s19` — **801 ranges → 801 runs + 800 gaps = 1601 segments**, ~30× the ceiling. **It is the ONLY shipped fixture past the onset**; every other is ≤ 11 runs. **The aggregation path has now been designed TWICE against fixtures that did not represent the real one** — revision 2's synthetic 35-run fixture was chosen because no shipped fixture was believed to cross, and that premise was false. **This is the batch's signature failure recurring, and it is why R-10 descoped rather than patched.** |
| 4 | **Out-of-domain behaviour, BOTH producers** | **pristine + CSS only:** @66 `797/801 (99.5 %)`, outside 1594; @50 `800/801 (99.9 %)`, outside 1600; `gap_w max=60`. **batch-77's producer:** @66 `768/801 (95.9 %)`, outside 1535; @50 `776/801 (96.9 %)`, outside 1551; `gap_w max=1`. **Improvement: −29 runs @66 and −24 @50.** Region list **801** rows, **no crash**, in every case. **batch-77 improves it at both regimes and fixes it at neither. Quote both figures or neither — a lone "95.9 %" understates the wide regime.** ⚠️ **The degradation rule is UNSPECIFIED — these are observations of one conforming implementation, not a contract. batch-78 must specify it.** |
| 5 | **The bound is arithmetically unsatisfiable out of domain** | `avail = bar_w − n_gaps` = **−734** @66, **−750** @50 |
| 6 | **O(n²) cost — and time is NOT currently a stated cost axis** | merge-smallest-adjacent on the UI thread: **n=1000 → 975 merges, 31.10 ms**; **n=5000 → 4975 merges, 840.34 ms**, uncapped. `case_08` is n=801. **batch-78 must add a time budget to its constraints** (security M-3r) |
| 7 | **An aggregate has no usable monotonicity subject** | `region_end − region_start` **includes swallowed gaps**, so it is not the aggregate's mapped size. Executed on `case_08`: monotone-by-span **False**, monotone-by-**sum of constituent run bytes** **True**; first span violation `((1988,2),(2150631108,1))`. **The subject must be the summed run bytes, and `BandSegment` does not currently expose it** (arch RB-2) |
| 8 | **"Merge until it fits" dies exactly where strict-∃ dies** | executed: `regions=18 → 76 runs`, both regimes, **all widths 1, strict False — the strict limb is DEAD**. The stopping rule and the discrimination requirement are in direct tension; batch-78 must resolve which yields (arch RB-3) |
| 9 | **The disclosure count is ambiguous three ways on the real fixture** | `case_08` @66: `oracle − TOTAL segments = 768` · `oracle − STANDALONE = 801` · `runs that lost a dedicated segment = 768`. @50: `776` / `801` / `776`. **Pick the definition before writing the AT, not after** (arch RB-4) |
| 10 | **A coverage clause that excludes aggregates is FALSE on correctly-aggregating code** | QA: 2 ranges → 1 aggregate → filtered `emitted` empty → coverage `False`; 26-region fixture leaves **10** uncovered range starts @66, **15** @50. **Coverage must include aggregate spans** (QA N-1) |
| 11 | **The count formula cannot distinguish merged from DROPPED** | `oracle − emitted` is GREEN identically whether runs were merged into an aggregate or **silently discarded**. batch-78 needs a separate clause that every run is *represented*, not merely *counted* (QA N-1) |

**Scope note.** `LLR-111.7` (floor-1 + largest-remainder bound) stays in batch-77 — it is verified sound and
is what makes **15 of the 16** shipped fixtures work with zero aggregation. batch-78 inherits a working
bound and owns only the excess.

### 6.4a 🆕 PROPAGATION SWEEP (revision 4) — the root-cause fix, EVIDENCED

**Why this section exists.** Across three gate rounds the same failure recurred: *a change was applied where
it was noticed and not carried to everything that depends on it.* R-10's domain reached `HLR-111`'s Statement
and the AT labels but not `LLR-111.3`, not `LLR-111.7`, and not `HLR-112` at all — three unconditional `shall`
clauses a shipped fixture falsifies. Earlier rounds show the same shape: a design validated on one fixture
rather than the fixture set; a payload corrected in §4 and left stale in the BLUF. **This is C-15's sweep-back
and C-26's reverse-grep applied to the document itself.**

**A claim that a sweep was run is not the artefact.** The sweep below is a **executed string-presence check**
over this document, one row per dependent surface, run to a fixed point. It is reproducible: each row's probe
is the quoted anchor text.

| Ruling | Dependent surface | Verdict |
|---|---|---|
| **R-10** | `HLR-111` Statement carries the domain | ✅ |
| **R-10** | `LLR-111.3` scoped *(was unconditional — **fixed at rev 4**)* | ✅ |
| **R-10** | `LLR-111.7` Statement scoped *(was unconditional — **fixed at rev 4**)* | ✅ |
| **R-10** | `LLR-111.7` threshold no longer says "every suite fixture" *(**fixed at rev 4**)* | ✅ |
| **R-10** | `HLR-112` Statement carries a domain *(had **none** — **fixed at rev 4**)* | ✅ |
| **R-10** | `HLR-112` threshold split universal / in-domain / out-of-domain *(**fixed at rev 4**)* | ✅ |
| **R-10** | `LLR-111.8` withdrawal record present | ✅ |
| **R-10** | `AT-B77-17` withdrawn, id not reused | ✅ |
| **R-10** | `AT-B77-18` replaces it in §3, §5.2, §7 | ✅ |
| **R-10** | `C-77-l` charter present and complete (11 items) | ✅ |
| **R-10** | definitions-table entry struck **and its "nothing depends on it" claim corrected** *(**fixed at rev 4** — it was false: `LLR-112.2` depended on it)* | ✅ |
| **R-10** | **no live dangling `LLR-111.8` reference** — executed: **0** *(rev 3 had **1** live dependency in `LLR-112.2` and **1** stale disposition on `P-50`; both **fixed at rev 4**)* | ✅ |
| **R-10** | BLUF row 4 rewritten to the descope | ✅ |
| **R-10** | equality guard restored (aggregate filter deleted) | ✅ |
| **R-11** | `LLR-116.7` exists | ✅ |
| **R-11** | byte-class filter is **normative**, C1 codepoints named *(**added at rev 4**)* | ✅ |
| **R-11** | `C-77-h` marked DISCHARGED, not re-filed | ✅ |
| **R-11** | Inc-2 owns the scrub and precedes Inc-7 | ✅ |
| **R-11** | `AT-B77-15` split a/b in §3, §5.2, §4 register, §7 | ✅ |
| **R-11** | false layout-perturbation rationale withdrawn explicitly | ✅ |
| **R-11** | *"payload verbatim"* → *"non-control characters verbatim"* in **both** places *(**fixed at rev 4** — it would have gone RED on a correct implementation)* | ✅ |
| **R-8** | `C-77-k` carry present, kept distinct from `C-77-j` | ✅ |
| **R-9** | region-list decision preserved into `C-77-l` after R-10 mooted it | ✅ |
| **R-5** | fold=1 value + `C-77-g` descope carry | ✅ |
| **R-6** | two arms + liveness clause in `HLR-116`, `LLR-116.5`, §5.2 | ✅ |
| **R-1…R-4, R-7** | `LLR-111.9` widen; container basis; ruler end label | ✅ |
| **cross** | §5.3 batch acceptance criteria present *(**deleted between rev 2 and rev 3 — restored at rev 4**)* | ✅ |
| **cross** | every out-of-domain figure names its producer *(**fixed at rev 4**)* | ✅ |
| **cross** | degradation rule declared unspecified, figures declared observations | ✅ |
| **cross** | BLUF row 7 golden = `[49,17]` *(**fixed at rev 4** — had survived one revision as `[50,16]`)* | ✅ |
| **cross** | Inc-2 gate driven by a real click, and marked `full ×3` *(**fixed at rev 4**)* | ✅ |

**🆕 DERIVED-EXCLUSION ROWS (rev 5, arch RC4-2d) — the sweep no longer only confirms what it was told to look for.**

Revision 4's sweep had a **hand-listed row set**: rows verified that each domain *was added*, and **no row asked
what any domain EXCLUDES**. That is the C-31 vacuous-input-set defect wearing a control's clothing — **the fourth
occurrence of that shape in this batch**, this time inside the control built to stop it. The rows below **compute**
the excluded set from the fixture corpus instead of asserting a domain exists.

| Declared domain | Excluded set — **COMPUTED over `examples/**/*.s19`** | Named in the document? |
|---|---|---|
| `HLR-111` — `n_runs + n_gaps ≤ bar_width` | **1 of 16**: `case_08` (1601 vs 66/50) | ✅ named |
| `HLR-112` — `n_ticks ≤ ⌊(ruler_width+1)/9⌋` | **3 of 16**: `prg.s19` (15 ticks, both regimes) · `case_07_stress_smoke` (6 ticks, **@120×30 only**) · `case_08` (802 ticks, both) | ✅ **all three named at rev 5** *(rev 4 named only `case_08`)* |
| `LLR-111.7` bound | same set as `HLR-111` — 1 of 16 | ✅ |
| `LLR-112.2` legibility | same set as `HLR-112` — 3 of 16 | ✅ |
| 🆕 **`HLR-111` strictness — `surplus × spread > total_bytes`** (Amendment D, rev 6) | **0 of the 15 in-domain fixtures**, at **both** regimes — computed, `strict=True` in all 30 fixture/regime pairs; tightest margin **`case_07_stress_smoke` @120×30 at 9.95×** *(⚠️ corrected at merge-gate close-out L-1 — this row read `case_02_gaps_and_patch_targets` @120×30 at 10.6×, which is the SECOND tightest; re-derived over all 32 pairs, see §6.5 Amendment D)*. The excluded set is **empty on the corpus and non-empty in general** (executed: `runs=[1,2,4,…,512]`, `n_gaps=9`, `bar=19`) | ✅ named in §3 ⭐ callout + §6.5 Amendment D |

**Two findings the derived rows produced that no hand-listed row could have:**
1. **`prg.s19` — the showcase fixture — is outside `HLR-112` at both regimes.** Every `HLR-111` demonstration uses it; a reader would not expect it to be excluded anywhere.
2. **`case_07_stress_smoke` is a SINGLE-REGIME exclusion** (@120×30 only), and its membership **flips with the separator convention** — invisible to any check that tests one regime or leaves the pitch unstated. That is why `LLR-112.2` now states the convention normatively.

**Standing obligation for Phase 3 and batch-78: every domain this document declares carries a derived-exclusion
row. A domain whose excluded set has not been computed has not been measured.**

**Executed result at revision 5: 42 of 42 PASS**, after correcting **three genuine residues** (`P-50`'s disposition pointing at a withdrawn LLR; the `LLR-111.8` dependency inside `LLR-112.2`'s sufficiency argument; the corpus count repeated across four revisions) and **three probe-string defects of my own** (a bold-marker mismatch on the `LLR-111.7` anchor, and an exclusion filter that did not whitelist the sweep's own self-describing rows). **Recorded because the probe defects matter as much as the document ones:** a sweep whose probes are wrong reports failures that are not there — and would, on the next run, teach a reader to ignore it. The first run reported **2** failures. One was a bad probe
string on my side (the `HLR-111` anchor). **The other was a genuine residue the sweep existed to find:** `P-50`'s
disposition column still pointed at `LLR-111.8`, a withdrawn requirement. **That is one more propagation miss,
caught by the mechanism rather than by a fourth review round** — which is the point of building the mechanism.)*

**At revision 5 the sweep caught a third:** the corpus size itself. Every prior revision wrote *"16 of 17 shipped
fixtures"*; the derived count is **16 fixtures, 15 in domain**. A figure repeated across four revisions was never
derived — the same defect class as the golden payload and the out-of-domain figures, in the sentence describing
how well the design works.

**Standing rule for Phase 3 and for batch-78:** any change to a domain, a scope, a withdrawal or a wording
re-runs this sweep and records the result. The cost is a minute; the alternative has cost three gate rounds.

**🆕 REVISION 6 RUN — Amendment D (a domain change, so the rule above fires). Result: 44 of 44 PASS.**

Rows cover the amendment's own surfaces (Statement, threshold, `LLR-111.7`, §6.4 log, §6.5 Before→After ×2, the derived-exclusion row, the `AT-B77-01` acceptance, the boundary catalog, the `LLR-111.5` register, the `TC-B77-03` arm) **and** the five co-landed review findings (F2…F8). It includes **negative** probes — that monotone-∀ was *not* narrowed, that no unconditional strictness promise survives in the normative body, and that `prg.s19`'s corrected gap count leaves no `13 gaps` anywhere.

**The first run reported 3 failures and ALL THREE WERE MY OWN PROBES, not document residues** — recorded because the rev-5 run made exactly this point and it recurred anyway:
1. A negative probe for the superseded strictness wording matched **§6.5's own `Before (verbatim)` block**. An amendment is *required* to quote the text it replaces, so the probe must run over the **normative body only**. Now split at the §6.5 heading, and paired with a **positive** probe asserting the Before-block *is* present — the two directions together are what make the amendment form checkable.
2. A **bold-marker mismatch** on the Inc-1 anchor (`⚠️ **Inc-1…` vs the actual `**⚠️ Inc-1…`). **This is the identical defect rev 5 recorded on the `LLR-111.7` anchor.** A probe string is a definition; pasting it by eye reintroduces the error the sweep exists to catch.
3. A probe that grepped the module for the bare word `strict` to assert *"the allocator was not modified to chase the clause"*. It failed on the word appearing in **unrelated docstrings three functions away** — and it could never have succeeded, because a word-grep cannot decide whether an algorithm changed. **Replaced with a BEHAVIOURAL probe**: the allocator must still return the mandated `LLR-111.4` goldens `[49,17]` @66 / `[37,13]` @50, the two degenerate cases, **and it must still return all-`1` widths on Amendment D's counterexample** — i.e. the sweep now asserts the counterexample was *left degrading*, not repaired. A textual probe would have passed on a silently patched allocator.

**The generalisable point:** probe defect 3 was a check whose LABEL ("allocator unchanged") and SUBJECT (the substring `strict`) were unrelated — the batch's own recurring finding, committed inside the control built to detect it. **A negative probe over a document that legitimately quotes its own history must state which region it governs.**

### 6.4 Reconciliation log

| Blocker | What changed | Parent re-read? | Body edit landed? |
|---|---|---|---|
| arch **B-1**, **B-2** | container widened (R-7/1) + normative bound *(aggregation added here, **later WITHDRAWN by R-10** — `LLR-111.8` and `AT-B77-17` are **not** landed edits)* | **HLR-111 Statement rewritten**, threshold extended | §3 HLR-111; §4 **LLR-111.7**, **LLR-111.9** *(not `.8` — withdrawn)*; ~~`AT-B77-17`~~ → `AT-B77-18` |7/.9** |
| arch **B-3**, QA **B-2** | increments re-cut; basis+bound+fold land together | no threshold change | §7 |
| arch **B-4** | `LLR-115.1` → `LLR-116.1`; duplicate clause deleted | **HLR-115 Statement** lost the focusability clause; **HLR-116** keeps it | §3 HLR-115, HLR-116; §4 |
| arch **B-5**, QA **B-1** | subject = RUNS; C-31 guard replaced | **HLR-111 + HLR-112** both re-pointed | **§2.9**; §3 both HLRs; §4 LLR-112.1 |
| arch **B-6**, QA **M-2** | golden payload re-derived; header promise narrowed | `LLR-111.4` threshold unchanged, payload corrected | header; §4 LLR-111.4 |
| arch **B-7** | settle trace retracted; one criterion | `LLR-111.6` Statement rewritten | §2.7 **P-45**; §4 LLR-111.6 |
| QA **B-3** | focus predicates assert liveness | **HLR-116 Statement + threshold** | §3 HLR-116; §4 LLR-116.5, LLR-116.2 |
| QA **B-4** | `AT-B77-09` re-authored; PIN split to `AT-B77-16` | **HLR-115 acceptance** | §3 HLR-115 |
| sec **B-1** | hostile-input LLR + AT | **HLR-116 Statement** gained the safety clause | §3 HLR-116; §4 **LLR-116.6**; carry C-77-h |
| sec **M-1** | zero-width/elision replaces overlap | **HLR-112 Statement** | §3 HLR-112; §4 LLR-112.2 |
| sec **M-2**, arch **M-3** | census 6 → 8 | `LLR-112.3` threshold 6 → 8 | §4 LLR-112.3; §7 Inc-4/Inc-5 |
| arch **M-1** | quantifier stated (∀ monotone, ∃ strict) | **HLR-111 Statement** | §3 HLR-111 |
| arch **M-2** | denominator promoted to normative | `LLR-111.1` Statement | §4 LLR-111.1 |
| arch **M-4** | backlog correction assigned an owner | — | carry **C-77-i**, Inc-5 |
| arch **M-5** | `AT-B77-02` single owner | — | §7 Inc-3 owns; Inc-2 re-runs |
| arch **m-1/m-2** | `160×48` ruled on; retirement fixture named | Amendment C | §6.5 |
| QA **M-3** | `test_tc041_9` vacuity claim **withdrawn** | HLR-113 note | §3 HLR-113 |
| QA **M-4** | precision pinned to exactly four digits | **HLR-113 Statement** | §3 HLR-113; §4 LLR-113.1 |
| QA **M-5** | `AT-B77-10` reuses two existing nodes | — | §3 HLR-115 |
| sec **m-1** | inverting text style excluded | `LLR-117.2` Statement | §4 LLR-117.2 |
| **R-10** | aggregation descoped to batch-78 | **HLR-111 Statement rewritten with an explicit DOMAIN** + a truthful out-of-domain clause; threshold scoped to the domain | §3 HLR-111 + the ⭐ domain callout; §4 **LLR-111.8 withdrawal record**; `AT-B77-18` replaces `AT-B77-17`; §6.3 **C-77-l** charter |
| **R-11** | ANSI scrub pulled INTO batch-77 | **HLR-116** unchanged in substance; `LLR-116.6`'s per-limb verdicts corrected | §4 **LLR-116.7** (new); §6.3 **C-77-h DISCHARGED**; §7 **Inc-2** |
| arch **RB-1**, QA **N-1** | coverage guard back to EQUALITY, aggregate filter deleted | HLR-111 acceptance | §3 completeness guard |
| arch **RB-5** | `AT-B77-02` given a real discharging mutation | — | §4 LLR-111.5 register |
| arch **RM-1** | golden payload re-derived THROUGH THE ALLOCATOR; method named | `LLR-111.4` | §4 LLR-111.4 |
| arch **RM-2** | `AT-B77-09` relabelled PIN | HLR-115 acceptance | §3 HLR-115; §5.2 |
| arch **Rm-1** | equal-fixture `[30,30]` → `[33,33]`/`[25,25]` | `LLR-111.4` | §4 LLR-111.4 |
| arch **Rm-2** | monotonicity prose aligned to pairwise | **HLR-111 Statement** | §3 HLR-111 |
| sec **B-1r** | `AT-B77-15` split, per-arm, precondition, non-inert mutation; **false rationale withdrawn** | **HLR-116 acceptance** | §3 `AT-B77-15a/b` block; §4 LLR-116.6; §4 LLR-111.5 register |
| sec **X-1** | width-perturbation rationale deleted **explicitly** | — | §3 `AT-B77-15a/b` block |
| sec **m-2r**, arch **Rm-3** | census threshold made DERIVED, not a fixed integer | `LLR-112.3` | §4 LLR-112.3 |
| QA **M-3** *(gate 2)* | `AT-B77-10` given an owning increment | — | §7 Inc-8 |
| arch **RC-1** | domain propagated to `LLR-111.3` + `LLR-111.7` (Statement **and** threshold) | **HLR-111 re-read** — its Statement already carried the domain; the children did not | §4 LLR-111.3, LLR-111.7 |
| arch **RC-2**, QA **M-4** | `HLR-112` given a domain by the **same pattern as HLR-111**; `LLR-112.2`'s dangling `LLR-111.8` reference removed and its **sufficiency argument re-derived**; definitions-table "nothing depends on it" claim **corrected — it was false** | **HLR-112 Statement + threshold rewritten** | §3 HLR-112; §4 LLR-112.2; §1.3 |
| arch **RC-3**, QA **M-2** | Inc-2's gate now **drives the sink with a real click** (was vacuous pre-auto-select) **and** the "payload verbatim" wording corrected to **non-control characters verbatim** in both places (was RED-on-correct) | `LLR-116.6` threshold; `AT-B77-15a` block | §3 AT block; §4 LLR-116.6; §7 Inc-2 + ordering note 2a |
| QA **M-3** *(gate 3)* | **§5.3 RESTORED.** It was **deleted between revisions 2 and 3 with no decision recorded** — numbering jumped 5.2 → 5.4, taking the frozen-engine gate, the full-suite baseline and 0-blockers-at-merge. **Nothing was deliberately dropped; the deletion was accidental collateral from the R-10 removal.** Restored and adjusted for the descope. | — | §5.3 |
| QA **M-1**, arch **RC-M2** | every out-of-domain figure **attributed to its producer**; 99.5 % → **95.9 %** for batch-77's producer; "not made worse" → **measurably better (797→768, 800→776)**; **degradation rule declared UNSPECIFIED** and the figures declared observations, not a contract | **HLR-111 out-of-domain clause re-read** — it contracts only *no raise* + *region list complete*, which is why the figures are not a contract | §3 domain callout; §6.3 C-77-l item 4 |
| arch **RC-M1** | BLUF row 7 golden `[50,16]` → **`[49,17]`/`[37,13]`** (had survived a revision) | — | §BLUF row 7 |
| sec forward flag | byte-class filter made **normative** with `U+009B`/`U+009D` named, so Phase 3 cannot substitute a regex | `LLR-116.7` Statement | §4 LLR-116.7 |
| sec minors | Inc-2 gate marked `full ×3`; Inc-5 census cell made **derived** (9 known, lower bound) | — | §7 Inc-2, Inc-5 |
| **Amendment D** *(Inc-1, code review)* | **strictness clause given a QUANTIZATION precondition** — it was unsatisfiable by any allocator on in-domain inputs. Reviewer's proposed `≤`→`<` narrowing executed and **rejected** (576→85, not 0). Derived `surplus × spread > total`, **859 276-case sweep, 0 counterexamples**, threshold tight at ratio 1.0. **Allocator NOT changed.** Also corrected `prg.s19`'s gap count `13 → 10` in **two** places (it was `n_runs − 1`, the inference the producer's own comment forbids) | **`HLR-111` Statement re-read** — only the strictness conjunct takes the precondition; `visible ≥ 1`, `Σ ≤ width` and monotone-∀ stay on the `≤` domain | §3 HLR-111 Statement + threshold + ⭐ callout + boundary catalog; §4 **LLR-111.7**, LLR-111.5 register; §2.7 **P-49** gap count; §6.5 **Amendment D**; `TC-B77-03` differing arm |
| **root cause** | **§6.4a propagation sweep added and EXECUTED** — 32/32 after two corrections, one of which was a genuine residue (`P-50`'s disposition pointing at a withdrawn LLR) | — | §6.4a |
| **R-8** | stats-line fold accepted, not designed around | `LLR-111.9` cost note — **no threshold change**; HLR-111 untouched | §4 LLR-111.9; §6.3 **C-77-k**; §8 OQ-5 closed |
| **R-9** | *(superseded by R-10)* disclosure surface fixed to the region list | — | **Moot: `LLR-111.8` withdrawn.** R-9's reasoning is preserved verbatim in the `C-77-l` charter so batch-78 inherits the decision rather than re-litigating it |

### 6.5 Requirement amendments
**Amendment A (`R-TUI-072`)** and **Amendment B (`LLR-072.3`)** — ✅ **LANDED at Inc-5.** Before texts verbatim-verified by the architect lane and reproduced unchanged. **After** texts: *"one tick label per emitted **run** start plus one for the last mapped byte"* (§2.9), extended with the legibility clause (security M-1).
- **Amendment A** is written into `REQUIREMENTS.md` at `R-TUI-072` — Statement amended in place, full Before/After block appended to Status. **Its parent re-read names the duplicate at `REQUIREMENTS.md:4190-4191` and that duplicate is amended in the same edit.** ⚠️ **It also found a THIRD site the census table did not name** — `R-TUI-072`'s own `Validation:` line, quoting *"exactly 5 ticks"* as `AT-072b`'s predicate, eight lines below the Statement. **A requirement restates its own contract in its verification row; a census that reads only Statements will miss it every time.**
- **Amendment B** is written into `.dev-flow/2026-07-15-batch-47/01-requirements.md` at `LLR-072.3:508` — the definition whose existence carry `C-77-i` denied. Its retired *"labels fit without overlap"* acceptance criterion is recorded as **vacuous** in the same block: `width: 1fr` children partition the row and cannot overlap, so the predicate was GREEN at 10 invisible labels (P-52).
**Amendment C** — retirement of `test_ac6_clipped_segments_are_a_known_layout_limitation`, verified by the architect lane to drop no observable. **Two additions:**
- **Name the fixtures** in the retirement table (arch m-2): the deleted node measures `outside_count` on `_two_band_loaded` **@120×30**; `AT-B77-03` measures the same predicate on the 5-region sparse fixture **and** on `prg.s19`. Same predicate, **different fixture** — the inversion claim is now checkable rather than loose.
- **Rule on the `160×48` size** (arch m-1): the limitation note at `tests/test_map_click_chain.py:220-227` is the **only** justification for the two AC-6 pointer tests running at `160×48` instead of `120×30`. After R1/R-7 that justification is false, and leaving it would lose the batch's only band-segment-clickability coverage at the regime R-7 repairs. **Both tests revert to `120×30` in Inc-1**, in the same edit that drops the note.

**Amendment D 🆕 (`HLR-111` Statement + `LLR-111.7`) — the strictness clause was UNSATISFIABLE in domain. Surfaced during Inc-1 by an independent code review; the fix the review proposed does not work.**

**This is a REQUIREMENT defect, not a code defect. The allocator is unchanged by this amendment.**

**Before (verbatim, `HLR-111` Statement, rev 5):**
> …and **shall** emit at least one strictly greater pair whenever two emitted run segments differ in mapped size. If the image does not satisfy that condition, then the panel **shall** render without raising and **shall** leave every run reachable in the region list.

**After (verbatim, rev 6):**
> …and **shall**, **while the image additionally satisfies `(bar.region.width − n_runs − n_gaps) × (max_bytes − min_bytes) > total_bytes`**, emit at least one strictly greater pair whenever two emitted run segments differ in mapped size. If the image does not satisfy the containment condition, then the panel **shall** render without raising and **shall** leave every run reachable in the region list.

**Before (verbatim, `LLR-111.7` Statement, rev 5):**
> While the image satisfies `n_runs + n_gaps ≤ bar.region.width`, the sum of all emitted run-segment widths and all emitted gap-marker widths **shall not** exceed the measured container width, and every emitted run segment **shall** receive at least one column. If the image does not satisfy that condition, the allocator **shall** return a width for every run without raising.

**After (verbatim, rev 6):**
> While the image satisfies `n_runs + n_gaps ≤ bar.region.width`, the sum of all emitted run-segment widths and all emitted gap-marker widths **shall not** exceed the measured container width, and every emitted run segment **shall** receive at least one column. **While the image additionally satisfies `(bar.region.width − n_runs − n_gaps) × (max_bytes − min_bytes) > total_bytes`, the allocator shall assign strictly more columns to some run than to some other run of smaller mapped size.** If the image does not satisfy the containment condition, the allocator **shall** return a width for every run without raising.

**The executed counterexample that falsifies the Before text (in domain, `n_runs + n_gaps = 19 ≤ bar = 19`):**
```
runs=[1, 2, 4, 8, 16, 32, 64, 128, 256, 512]  n_gaps=9  bar=19
  -> widths=[1,1,1,1,1,1,1,1,1,1]   differing=True   strict=False
     surplus=0   spread=511   total=1023
```

**Why the reviewer's proposed fix does NOT work.** The review proposed narrowing the containment domain from `≤` to `<` (i.e. requiring `surplus ≥ 1`). Over 20 000 random in-domain cases that drops failures only **576 → 85**. Survivors, executed:
```
runs=[2994, 4924]              n_gaps=0  bar=6   surplus=4   widths=[3, 3]
runs=[3256, 2639, 1615, 2601]  n_gaps=1  bar=9   surplus=4   widths=[2, 2, 2, 2]
runs=[4849, 4642]              n_gaps=2  bar=38  surplus=34  widths=[18, 18]
```
**The cause is integer QUANTIZATION, not surplus exhaustion.** A mapped-size difference smaller than one column's worth of bytes cannot be represented in integer columns, so **no allocator can discriminate those runs**. Surplus alone never expresses that; the spread relative to the total is what does.

**Derivation (executed, not reasoned).** The candidate the operator sketched was `surplus × spread ≥ total`. Executed, it is **wrong at the boundary**: over an exhaustive enumeration it admits **285** non-strict cases at ratio exactly `1.000000` —
```
runs=[1, 4, 4]  n_gaps=0  bar=6  -> widths=[2, 2, 2]  strict=False  ratio=1.000000
```
— a case the 140 808-case random sweep never hit, because exact equality is measure-zero under random bytes. **The threshold must be STRICT.** With `>`:

| Population | In-domain cases | Counterexamples |
|---|---|---|
| Exhaustive A (`n_runs` 2–4, bytes 0..7, gaps 0..4, bar ≤ 16) | 260 160 | **0** |
| Exhaustive B (`n_runs` 5, bytes 0..5, gaps 0..3, bar ≤ 14) | 264 384 | **0** |
| Adversarial grid (powers of two, near-equal, one-huge-many-tiny, all-zero-but-one) | — | **0** |
| Random (4 families: small-byte, wide-byte, tight-bar, tiny-bar) | 80 000 | **0** |
| Ratio-targeted + exact-equality constructions (ratio 1 ± ε) | — | **0** |
| **CONSOLIDATED** | **859 276** | **0** |

**Tightness:** the highest `surplus × spread / total` observed on **any** non-strict in-domain case is exactly `1.000000000`. The threshold therefore cannot be loosened to `≥`, and every value above 1 is safe. This is a *sufficient* precondition, deliberately — the exact condition is not closed-form, and a sufficient one that admits the corpus is what a requirement needs.

**Not vacuously narrow — the shipped corpus, all 16 fixtures, both regimes (executed):** 15 of 16 are in the containment domain at **both** `bar=66` (80×24) and `bar=50` (120×30) — unchanged by this amendment — and **every one of those 15 satisfies the amended strictness clause at both regimes**, with `strict=True` observed in all 30 fixture/regime pairs. `case_08_heavy_fragmentation` remains the single out-of-domain fixture (801 runs + 800 gaps = 1601). **No shipped fixture is pushed out of the strictness promise by this amendment.**

⚠️ **The tightest-margin fixture was WRONG, and is corrected here by re-derivation (merge-gate L-1).** This paragraph named `case_02_gaps_and_patch_targets` @120×30 at **10.6×**. Re-derived at close-out over **all 16 fixtures × both regimes** — the full 32-pair sweep, not a subset — the tightest is a different fixture:

| Rank | Fixture | Regime | `surplus` | `spread` | `total` | `s×spread / total` |
|---|---|---|---|---|---|---|
| **1** | **`case_07_stress_smoke`** | **@120×30 (`bar=50`)** | **41** | **250** | **1 030** | **9.95×** |
| 2 | `case_02_gaps_and_patch_targets` | @120×30 (`bar=50`) | 43 | 23 | 93 | 10.63× |
| 3 | `professional_validation/case_03_overlapping_records` | @120×30 | 45 | 18 | 70 | 11.57× |
| 4 | `case_03_overlapping_records` | @120×30 | 47 | 10 | 38 | 12.37× |
| 5 | `professional_validation/case_05_out_of_order_and_mixed` | @120×30 | 43 | 36 | 112 | 13.82× |

**The arithmetic that was printed was right; the SEARCH was not.** `43 × 23 = 989` against `total = 93` does give 10.63× on `case_02` — that row is real, it is simply the **second** tightest. The defect is provenance: a figure was reported as the minimum over a corpus without the minimum having been taken over that corpus. **The conclusion is unaffected** — 30 of 30 in-domain pairs satisfy the precondition, **0 violations**, and both candidates are an order of magnitude clear of the threshold — which is precisely why it survived every gate. **This is the fifth quoted integer in this batch to be off**, and like the other four it was off in a direction that changed nothing, which is the property that lets this defect class accumulate.

**What did NOT change:** `visible ≥ 1`, `Σ widths + Σ markers ≤ bar.region.width`, and monotone-**∀** stay on the existing `≤` containment domain. They hold at the boundary and narrowing them would be a scope loss with no evidence behind it. **`_allocate_band_widths` is not modified** — chasing the clause in the allocator would be chasing an unsatisfiable target.

**Test consequence:** `TC-B77-03` is labelled "the domain edge" but its fixture is `[256] * n_runs` — all runs equal — so `differing` is `False` and the strict limb has **no subject** anywhere in its sweep. **That is why a sweep across the onset never evaluated the clause that fails.** A differing-size arm at the last in-domain point is added in Inc-1, pinning the truthful degenerate behaviour. This is the batch's registered **vacuous-fixture** defect class (batch-74), now on its own boundary test.

**Amendment E 🆕 (`LLR-072-7.1`, node `TC-519`) — the guard was watching the wrong file for four batches. Executed at Inc-4 under operator ruling; recorded here because a guard amendment is a REQUIREMENT-level fact, not a test edit.**

**Before (verbatim, the node's asserted predicate):**
> `git diff origin/main -- s19_app/tui/legend.py` is empty — **file identity**.

**After (verbatim, the node's asserted predicate):**
> A two-arm **behavioural** predicate. **Arm A — the CONSUMER re-parents:** `LegendScreen.compose` splats each helper's return value directly into its pane (AST: `_render_card` and `_render_key` both appear as starred `Call`s). **Arm B — the PRODUCERS return widgets, not text:** each helper's return value is a sequence of `Widget`s.

**Why — and the two directions are not symmetric.**

| Direction | Claim | Verdict | Executed evidence |
|---|---|---|---|
| **Too strict** | batch-72's *"the data module has no reason to change"* is a standing property of `legend.py` | ❌ **FALSE** | That was a true statement about **batch-72's own scope**, encoded as though it were a standing invariant. `LLR-112.3` falsifies it: `legend.py` states the retired 5-tick contract **in prose the operator reads**, and amending it is a legitimate data change with no bearing on re-parenting. Executed now: `git diff --stat origin/main -- s19_app/tui/legend.py` → **5 insertions, 3 deletions** — the old node would be RED on a correct change. |
| **Too weak — and this matters more** | a path-filtered diff on `legend.py` can fail on the regression the node names | ❌ **FALSE, structurally** | `_render_card` is at **`s19_app/tui/screens.py:1093`** and `_render_key` at **`:1141`**; `grep -c '_render_card\|_render_key' s19_app/tui/legend.py` → **0**. **Not one symbol the node's rationale names lives in the file the node watched.** Rewriting `compose` to rebuild every row from text would have left it GREEN. It stayed green from batch-72 to batch-77 and could not have done otherwise. |

> ⚠️ **This is the strongest instance in the batch of a predicate that does not test what its LABEL claims.** The other twelve were caught by execution at a gate; this one was caught only because an unrelated requirement (`LLR-112.3`) forced an edit to the file the guard was pinning. **Nothing in four batches of green runs carried any information about the invariant.**

**A hash of the two helpers was considered and REJECTED:** it reddens on any edit to the producers while staying GREEN on the consumer defect, which is where the regression actually lives — i.e. it inverts the discrimination.

**The node NAME is deliberately retained despite now being inaccurate.** `AT-TC-REGISTRY` binds `TC-519` to that exact node path (and to the `_repo_root` helper, kept for the same reason), so renaming is a **registry change, not a test change**. **Carried for the registry lane** — do not rename it opportunistically in this batch.

---

## 7. Increment plan — re-cut (arch B-3, QA B-2)

| Inc | Content | Files | Gate |
|---|---|---|---|
| **Inc-1** | **CSS widen + container basis + bound + fold + settling, TOGETHER** — `LLR-111.9`, `.1`, `.7`, `.2`, `.6`, `.3`. Owns `AT-B77-18` (out-of-domain, `case_08`). Amendment C deletion + the two AC-6 pointer tests reverted to 120×30. **+ Amendment D's `TC-B77-03` differing-size arm.** | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_map_big.py`, `tests/test_map_click_chain.py`, **`tests/test_tui_directionb.py`** (**5**) | `AT-B77-01`, `AT-B77-03` **both arms, in domain**; `AT-B77-18` on `case_08`; full ×3 |
| **Inc-2** 🔄 | **`LLR-116.7` — the C0/C1 **byte-class** scrub in `safe_text` + its docstring correction (R-11)**. Sequenced **early** so `LLR-116.6`'s normative clause is satisfiable before Inc-7 makes it live. Owns `AT-B77-15a/b`. | `screens_directionb.py`, `tests/test_tui_hostile_map.py` (NEW, non-frozen), `REQUIREMENTS.md` (3) | **`AT-B77-15a/b` driven by a REAL CLICK on a region row** — *not* by auto-select, which does not exist until Inc-7 — **per limb per size**; scrub-revert mutation executed; **full ×3** (this is the widest blast radius in the batch: `safe_text` has ~85 call sites across 4 modules) |
| **Inc-3** | **`LLR-111.4` golden capture**, own commit, after the basis settles · **owns `AT-B77-02`** (arch M-5) | `tests/test_tui_map_big.py`, golden artifact, `.gitattributes` (3) | golden committed; stored blob's bytes verified |
| **Inc-4** | **HLR-112 ruler** — code + tests + **`legend.py` site 7** | `screens_directionb.py`, `legend.py`, `tests/test_tui_map_big.py`, `tests/test_tui_snapshot.py` (4) | `AT-072b`, `AT-B77-04`; 0 "5 ticks" in source/tests. ⚠️ **`AT-072b`'s fixture must stay in `HLR-112`'s domain at both regimes (≤5 ticks) — `case_02` qualifies, `prg.s19` does NOT** |
| **Inc-5** | **Amendments A + B + doc census** + **carry C-77-i** | `REQUIREMENTS.md`, batch-47 `01-requirements.md`, batch-47 `traceability-matrix.md`, `.dev-flow/BACKLOG-CODE.md`, `PLAN.md` (5) | **0 surviving statements** of the retired contract under `s19_app/`, `tests/`, `REQUIREMENTS.md` and `.dev-flow/2026-07-15-batch-47/`, verified by **reading each file the sweep returns** (the count is a lower bound — 9 known, ~14 more likely; `LLR-112.3`'s "artifact set" wording governs, not the integer); backlog claim corrected |
| **Inc-6** | **HLR-113 + HLR-114** stats + legend removal; `test_at075` `e`-clause **ported** | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_directionb.py`, `REQUIREMENTS.md` (4) | `AT-B77-05/06/07` |
| **Inc-7** | **HLR-116 + HLR-117** — `LLR-116.1` focusability (moved here), post-refresh hook, resolution, **liveness**, selection style. Re-runs `AT-B77-15a/b` now that auto-select makes the payload actually render. | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_map_big.py`, `REQUIREMENTS.md` (4) | `AT-B77-11/12/13/14`; `AT-B77-15a/b` re-run per limb; the two R-6 mutations executed **after** liveness lands |
| **Inc-8** | **HLR-115** arrows + Enter. **No `show=True` binding.** | `screens_directionb.py`, `tests/test_tui_map_big.py`, `tests/test_map_click_chain.py`, `REQUIREMENTS.md` (4) | `AT-B77-08`; `AT-B77-09`/`AT-B77-16` **as PINs with their named mutations**; **`AT-B77-10` owned here** (QA M-3 — reuses `test_ac3_…`/`test_ac4_…`); **TC-011 green and unmodified** |
| **Inc-9** | Snapshot regen — **canonical CI only** | snapshot baselines | full suite; per-cell C-22 |

**⚠️ Inc-1 is FIVE files, not four (rev 6).** Revisions 1–5 declared four and the increment touches five: `tests/test_tui_directionb.py` carries `test_at073b_glance_geometry_fits_and_reflows`, which is where **`LLR-111.9`'s own Threshold** (`#map_grid.region.width == .map-band-bar.region.width`) is asserted at both regimes. **Blast-radius note:** that file is the batch's widest *test-side* surface — the initial allocation apportions against `grid.region.width` while `LLR-111.7`'s bound is stated over `bar.region.width`, and the two are equal **only** because the bar is `width: 100%` of `#map_grid` and `#map_grid` carries no padding or border. A future CSS edit that adds either silently breaks the equality, and every segment then overflows the container by the difference — with no other test in the batch positioned to see it. The file is also Inc-6's, so a change here is re-read there.

**Ordering constraints — four, all forced by execution:**
1. **Inc-1 is indivisible.** Container basis alone leaves both its ATs RED and **regresses 80×24** from `outside=0` to `outside=2` (gap widths `[8,8,16,33]` = 65 of 66 columns). Basis, bound and fold must land together or the increment cannot pass its own gate.
2a. ⚠️ **Inc-2's gate must DRIVE THE SINK, not wait for it (arch RC-3 / QA M-2).** Before Inc-7 there is no auto-select, so `#map_detail_body` shows `_DETAIL_HINT` — **no file-derived text at either regime**. An `AT-B77-15a/b` that renders and reads would therefore be **green on ANY implementation**, including one with no scrub at all: a gate that cannot fail, sitting one increment away from a gate that could not pass. **Inc-2's gate drives the inspector with a real `pilot.click` on a region row**, which is the shipped pre-auto-select path and exists today. Inc-7 then re-runs the same nodes through the auto-select path. *(Two lanes found opposite defects in this one gate — vacuous on one limb, red-on-correct on another — and both were true.)*
2. **Inc-2 precedes Inc-7 (R-11).** `LLR-116.6` forbids a control byte in the painted strip; Inc-7 is what makes that clause *live* by rendering file-derived text on load. Landing the scrub first means Inc-7 never introduces a gate the batch cannot pass — which is exactly what revision 2 would have shipped.
3. **Inc-3 after Inc-1.** A golden captured before the basis settles pins the retired arithmetic — precisely how `[45,15]` got into revision 1.
4. **Inc-7 → Inc-8.** `LLR-116.1` (focusability) is a precondition of `AT-B77-08`; `row.focus()` is a **no-op** until `can_focus` is True. And `AT-B77-09`'s gate arm requires focus-on-row, which Inc-7 establishes.

---

## 8. Open questions

| # | Question | Blocks | Owner |
|---|---|---|---|
| ~~OQ-5~~ | ✅ **CLOSED — ruling R-8.** Accept the deepened scroll; do not narrow the widen. Registered as carry **C-77-k**, kept distinct from **C-77-j**. | landed: `LLR-111.9` cost note, §6.3 | — |
| ~~OQ-6~~ | ✅ **CLOSED — R-9, then SUPERSEDED by R-10.** The region-list decision stands and is carried into `C-77-l` for batch-78; nothing in batch-77 now depends on it. | landed: `C-77-l` | — |
| **OQ-3** | `_BAND_BAR_WIDTH` deleted outright, or retained as a pre-layout fallback? | Inc-1 | Phase 3 |
| **OQ-4** | The focus-entry mechanism — screen-scoped binding, auto-focus, or extending the rail tab chain (⚠️ shared). | Inc-7 | Phase 3 |

---

## 9. Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Constraints stated | ✓ | §2.2, each with a measurement or `file:line` |
| ≥2 alternatives considered | ✓ | §2.9 subject decision; `LLR-111.9`'s five-candidate sweep with the whole-pane cost of each |
| Recommendation tied to constraints | ✓ | the stack variant is chosen because every alternative starves a 29-column content row |
| Risks listed | ✓ | §6.3 — 2 risks, 9 carries, **7** self-caught probe defects |
| Cost/latency estimated | ✓ | column budgets are the cost axis; `LLR-111.9` states the row cost, OQ-5 states who pays it |
| Diagram when flow is non-trivial | ✗ | **deliberate** — one linear producer, stated in three lines |
| What would change the recommendation | ✓ | OQ-5, OQ-6; `C-77-g`'s reopening condition |
| Two-layer requirements, both chains | ✓ | §5.2 behavioural and functional |
| **Every gate AT RED by execution** | ⚠️ **partial, and LABELLED** | **13 executed RED** (§5.2). **`AT-B77-02` is now a real GATE** — its revision-2 mutation was a provable no-op (P-58); the discharging mutation is allocator → plain `round()`. **`AT-B77-09` and `AT-B77-16` are PINs**, GREEN before and after, falsified only by their named mutation — revision 2 called `AT-B77-09` "the GATE" and implied it would be demonstrated RED; **it will not be** (arch RM-2). ⚠️ **CORRECTED at merge-gate close-out (M-2): the mutation `LLR-115.4` NAMED was inert.** Adding `Binding("k", …)` to `RegionRow.BINDINGS` left both PINs GREEN when Inc-8 executed it. The mutation that actually reddens **both PINs at both arms** on the behavioural assertion is the **application** table — `s19_app/tui/app.py:1359`, `Binding("k", "show_legend", …)` with key `"k"` → `"f9"` — confirmed by the independent merge-gate reviewer and now recorded as the substituted VALUE beside `LLR-115.4`. **This row's claim was true of the ids and false of the mutation the document offered next to them**, which is the same defect one layer down: a PIN whose named mutation is inert has no demonstrated subject. **`AT-B77-15b` is vacuously green until Inc-2** and is not listed as a gate before then. **`AT-B77-18` is evaluable today** on `case_08`. |
| **C-40 both limbs per predicate** | ⚠️ **partial, and LABELLED** | `LLR-111.5` marks each row ✅ **executed** or 🔶 `predicted — execute at Inc-N`, **and now also names which METHOD produced each payload** (P-59 — a payload computed by a different allocator than the requirement mandates survived a whole revision behind an honest-looking `predicted` label). **Revision 1 marked this row ✓ while its mutations were written against code that does not exist — a prediction wearing a discharge mark**, the exact defect class this batch keeps finding. The R-6 table is now labelled *executed at Phase 2 by the QA lane*, with its collapse-under-B-3 caveat recorded. |
| No transcript carried from a retired basis | ✓ | header states the narrow, checkable form; `LLR-111.4`'s payload re-derived and the old value shown as the counterexample |
| Normative keyword discipline | ✓ | `shall` only in Statements, quoted requirement text, and §2.7's quoted premises |
| No id minted outside authority | ✓ | `AT-B77-*`/`TC-B77-*` batch-scoped; `AT-072b` re-derived |
