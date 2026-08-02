# Requirements Document — s19_app — batch `2026-08-01-batch-77` — **REVISION 2**

**Objective:** Memory Map redesign — Variant A (gap-fold band bar) + cross-cutting fixes S-1…S-7
**Branch:** `claude/batch-77-memmap-variant-a` · **Base:** `origin/main` @ `f8747b8`
**Revision 2** supersedes revision 1 (578 lines) after **Phase-2 BLOCK from all three lanes** (architect 7 · QA 4 · security 1) and **operator ruling R-7**.
**Consolidates:** `00-measurements.md` · `01-requirements-architect.md` · `01b-qa-validation.md` · `02-review-architect.md` · `02-review-qa.md` · `02-review-security.md`
**Rulings applied:** R1–R7 (authoritative, not re-litigated) · **Normative keyword:** `shall`, only inside HLR/LLR **Statement** lines.

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
| **4** | 🆕 **Aggregation past the bound** (`LLR-111.8`) — merge smallest adjacent runs, disclose an **exact** `+N more`, per the `R-TUI-098` precedent. Measured onset: **26 runs @bar=50, 34 @bar=66**. | arch **B-1/B-2** |
| **5** | **Increments re-cut.** Old Inc-1a was unsatisfiable *and* regressed 80×24 (`outside 0 → 2`). Container basis, bound and fold now land in **one** increment. | arch **B-3**, QA **B-2** |
| **6** | `LLR-115.1` (`can_focus`) **moved under HLR-116** and into the earlier increment; the duplicate focusability clause deleted. | arch **B-4** |
| **7** | **Golden payload re-derived on the container basis** — rev-1's `[45,15]` summed to **60**, the *retired* constant. At the measured 66 it is **`[50,16]`**. | arch **B-6**, QA **M-2** |
| **8** | 🆕 **My settle trace was mis-stated and is retracted.** `68 → 68 → 66` was **two reads inside one frame** plus one after a pause — not two pauses. Executed: same-frame triples `{(66,66,66):9, (68,68,68):3}`; per-pause sequences `{(66,66,66):9, (68,66,66):3}`. **Threshold now counts pauses, not reads.** | arch **B-7** |
| **9** | **Focus predicates assert liveness**, not identity — a detached row satisfies `region_start == X`. | QA **B-3** |
| **10** | `AT-B77-09` re-authored: the gate arm now runs with focus **ON** a row (the post-R-6 default), the only state where shadowing can occur. | QA **B-4** |
| **11** | 🆕 **Hostile-input acceptance for the auto-populated inspector** (`LLR-116.6` / `AT-B77-15`). **The shipped docstring's ANSI claim is FALSE** — executed. | **security B-1** |
| **12** | `LLR-112.2` re-authored against **zero-width/elision**, not overlap — `1fr` children cannot overlap. Executed: N=60 in W=50 → **10 zero-width ticks, 0 overlaps, rev-1 predicate GREEN**. | **security M-1** |
| **13** | Citation census **6 → 8 sites** (`legend.py:613` prose; batch-47 `traceability-matrix.md:54`). | **security M-2**, arch **M-3** |

**Still unresolved and flagged:** OQ-5 (the widened bar pushes `#map_stats_body` 2 rows deeper below an *already* below-the-fold position) and OQ-6 (whether the aggregate disclosure belongs in the bar or the region list). Neither blocks Phase-2 re-review; both need a decision before their increment.

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
| **aggregate segment** | One `BandSegment` standing for ≥2 merged adjacent runs, carrying an exact `+N more` disclosure. |

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
| **P-49** 🆕 | A bounded allocator satisfies `prg.s19` at both regimes with **no** aggregation | ✅ **TRUE** | runs `[1,2,10,2,3,768,512,2560,38,60,8,1,1,2]`: `bar=66 → 14 segs + 13 gaps, total 66, FITS, allvis, mono, strict, aggregated=0`; `bar=50 → total 50, FITS, allvis, mono, strict, aggregated=0`. At the **un-widened** `bar=21` the same allocator needs **4** aggregations — which is why R-7/1 precedes R-7/2. | **`LLR-111.7`** |
| **P-50** 🆕 | Aggregation onset | ✅ **TRUE, exact** | `bar=50`: 25 runs → 0 aggregated; **26 → 1**. `bar=66`: 33 → 0; **34 → 1**. Matches `n_runs + n_gaps·fold > bar_w`, i.e. `2·n_runs − 1 > bar_w`. | **`LLR-111.8` threshold, derived** |
| **P-51** 🆕 | `safe_text` neutralises ANSI, as its shipped docstring claims (`:694-697`) | ❌ **FALSE — a false claim in shipped source** | `safe_text('sensor\x1b[31m_evil[red]')` → **unchanged**. `ESC survives: True` · `'[red]' literal: True` · `spans: []` · `len(plain)=21` for **16** visible chars — **5 invisible bytes billed as width**. The *markup* half is TRUE; the *ANSI* half is FALSE. | **`LLR-116.6` + `AT-B77-15`**; docstring → carry **C-77-h** |
| **P-52** 🆕 | rev-1's `LLR-112.2` overlap predicate can detect a non-collapsing ruler | ❌ **FALSE — vacuous** | `width:1fr` children **cannot overlap**. N ticks in W=50: `N=20 → max width 3` (8-char label elided); `N=60 → 10 zero-width, OVERLAPS=0`. rev-1's conjunction **GREEN at 10 invisible labels**. | **`LLR-112.2` re-authored** |
| **P-53** 🆕 | The retired 5-tick clause has 6 citation sites | ❌ **FALSE — 8** | + `s19_app/tui/legend.py:606-614` — prose *"address ruler — 5 ticks at 0/25/50/75/100 % of span"* **plus a 5-address sample line**, in a file absent from revision 1 entirely; + `.dev-flow/2026-07-15-batch-47/06-docs/traceability-matrix.md:54` | **`LLR-112.3` → 8**; `legend.py` enters §7 |

**Gate rule:** ❌ blocks. Every ❌ above is dispositioned in the body.

### 2.9 🆕 Subject decision — the acceptance quantifies over RUNS (arch B-5 / QA B-1)

| Option | Consequence |
|---|---|
| Quantify over **RANGES** | ❌ Would require one segment per range, **deleting the entropy-band split** that R-TUI-060 exists for. Rejected. |
| Quantify over **RUNS** ✅ | ✅ Matches what the producer emits and the operator sees. ✅ `visible_cols` is per-segment and a run is exactly one segment, so monotonicity **has a well-defined subject**. ⚠️ The oracle can no longer be `loaded.ranges`. |

**Chosen: RUNS.** Consequences, all normative below:

1. **The completeness guard becomes a two-part guard.** The equality form is **FALSE on correct code** (P-44). Replaced by (a) an **independent runs oracle** — `_merge_band_runs(loaded.entropy_windows)` computed in the test — and (b) a **coverage** assertion: every `loaded.ranges` start falls inside some emitted run's `[region_start, region_end)`. Executed: (b) holds on the heterogeneous fixture where (the old) equality fails.
2. **The runs oracle is not the producer under test.** `_merge_band_runs` is a pure function over `entropy_windows`; the code under test is `_build_band_widgets`'s **allocation**. Using the former to check the latter is a genuine independent oracle. *(Stated because it is the obvious objection.)*
3. **R-4's "labels at region starts" resolves to RUN starts** — the ruler must label what the bar draws.

---

## 3. High-level requirements

> Next free ID **`HLR-111`** (high-water 110; `HLR-108/109/110` live in shipped tests, absent from `REQUIREMENTS.md`). Namespace re-verified clean by the architect lane.

### HLR-111 — every mapped run is visible, ordered by size, inside a bounded container
- **Traceability:** US-77-1 · **Rulings:** R1, R2, R5, **R-7**
- **Statement:** When the Memory Map renders an image at any supported terminal size, the band strip **shall** derive all segment widths from the rendered width of their container measured at render time; **shall** emit a total column count, over all run segments and gap markers together, not exceeding that container width; **shall** paint at least one visible column for every emitted run segment; **shall** emit visible widths non-decreasing in mapped bytes; **shall** emit at least one strictly greater pair whenever two emitted run segments differ in mapped size; **shall** render each unmapped gap at exactly one column; and, when the number of runs and gaps would exceed the container width, **shall** merge the smallest adjacent runs into aggregate segments and disclose the exact number of runs so merged.
- **⭐ Quantifier, stated normatively (arch M-1):** monotonicity is **∀** over ordered pairs of emitted run segments; strictness is **∃** — *at least one* strictly greater pair. Revision 1 left this to a transcript. Under a **∀** reading of strictness, N-1's "different limbs" rationale collapses; under **∃** it holds. **∃ is the requirement.**
- **Rationale (informative):** shipped code scales to `_BAND_BAR_WIDTH = 60` against a `1fr` container measured at 66/21. R-7 widens the container first (50 @120×30) and bounds the allocation second. **Both parts are load-bearing:** executed, widening alone still leaves 5 of 14 runs invisible on `prg.s19`, because `max(1,·)` floors nine tiny runs while one claims 26 columns (P-48). With the bound, `prg.s19` fits exactly at both regimes with **zero** aggregation (P-49).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k "b77_width or b77_bound or b77_contain or b77_aggregate" -v` + **full** `tests/test_tui_directionb.py` + **full** `tests/test_map_click_chain.py` (C-34 + census)
- **Numeric pass threshold, per size arm:** `invisible_runs == 0` · `Σ widths ≤ bar.region.width` · `outside == 0` · gap markers all `== 1` · monotone ∀ and strict ∃ hold. Pre-change, executed: `invisible` **0 @80×24 / 2 @120×30**; `strict` **False / True**; `outside` **0 / 4**.
- **Priority:** high
- **Acceptance (black-box):**
  - **Shipped surface:** `App.run_test(size=…)` → `action_show_screen("map")` → `update_memory_map()` → `app.query(".map-band-seg")`, geometry clipped against `app.query_one(".map-band-bar").region`, read at **settled** geometry (`LLR-111.6`).
  - **Completeness guard (C-31), re-authored per §2.9 — replaces rev-1's guard, which was FALSE on correct code:**
    ```
    expected = _merge_band_runs(loaded.entropy_windows)                  # independent oracle
    emitted  = {(s.region_start, s.region_end) for s in query(BandSegment) if not s.is_aggregate}
    assert emitted <= {(start, start + n) for _band, n, start in expected}
    assert all(any(a <= rs < b for a, b in emitted) for rs, _ in loaded.ranges)   # coverage
    ```
    Subset (not equality) admits aggregation; the coverage clause is what stops an implementation silently dropping a region.
  - **Acceptance test(s):** **`AT-B77-01`** three-way conjunction (visible ∧ monotone∀ ∧ strict∃), both sizes · **`AT-B77-02`** gapless no-op at fixed container width · **`AT-B77-03`** every segment contained in the container · **`AT-B77-17`** 🆕 allocation bound holds and the aggregate disclosure count is exact
  - **Boundary catalog (QC-3):** ☑ **empty** — no ranges → zero segments, no raise, `TC-B77-01` · ☑ **boundary** — one run: strict **skipped explicitly** at `n<2`, never passed silently, `TC-B77-02` · ☑ **boundary** ⭐ — **`n_runs + n_gaps > bar_width`**: expected result now **defined** (aggregate + exact disclosure), not blank as in rev-1. Executed onset **26 runs @bar=50, 34 @bar=66**, `TC-B77-03` · ☑ **invalid** — zero-byte run, `TC-B77-04` · ☑ **error** — `total_span ≤ 0`, guarded `:1900`, `TC-B77-05` · ☑ **boundary** 🆕 — entropy-heterogeneous single range (1 range → 2 runs), `TC-B77-30`

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
- **Statement:** When the Memory Map renders, the address ruler **shall** emit one tick label per emitted **run** start plus one label for the last mapped byte; **shall not** emit a label naming an address outside every mapped range; **shall** emit strictly ascending, non-duplicate labels; and **shall not** emit any tick whose rendered width is smaller than the label it carries.
- **Rationale (informative):** measured **4 of 5** ticks name unmapped addresses. `span_end = 0x07FFFF3E` is exclusive and unmapped; `0x07FFFF3D` is mapped (frozen-oracle verified). Per §2.9 the tick subject is the **run** start. The final clause replaces revision 1's overlap test, which was vacuous: `1fr` children **cannot overlap**; they go **zero-width**. Executed, N=60 ticks in W=50 → **10 zero-width, 0 overlaps**, and rev-1's predicate was **GREEN**.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py::test_at072b_ruler -v` (re-derived) + `-k b77_ruler`
- **Numeric pass threshold:** 0 labels outside every mapped range (today **4**); `len(ticks) == len(set(ticks))`; strictly ascending; **0 ticks with `region.width < len(label)`**
- **Acceptance (black-box):**
  - **Deliverable + observation:** tick labels **and each tick's `region.width`**. Membership via the frozen `address_in_sorted_ranges(addr, index)` — note the argument order (`s19_app/range_index.py:39`); revision 1's first probe had it inverted and was caught by a `TypeError`.
  - **Acceptance test(s):** **`AT-072b`** *(re-derived, keeps its global id)* — `{ticks} ⊆ ADMISSIBLE` ∧ ascending ∧ no duplicates ∧ **no elided tick**, where `ADMISSIBLE = {f"{s:08X}" for run starts} ∪ {f"{span_end-1:08X}"}` · **`AT-B77-04`** — the `⊇` lower bound
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
  - **`AT-B77-09`** *(the GATE)* — with focus **ON** a region row, which after R-6 is the **default** state: `k` pushes the legend screen, `j` invokes `dump_a2l_json`, `o` invokes `open_workarea`, and none moves the map selection. **This is the only state in which widget-scoped shadowing can occur**, so it is the only arm that can redden if someone adds `Binding("k", …)` to `RegionRow.BINDINGS`.
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
  - **`AT-B77-15`** 🆕 *(hostile input — security B-1)*, below.
  - **Per-arm mutation table (R-6) — `predicted` at Phase 1, **EXECUTED at Phase 2 by the QA lane**:**

    | Arm | Mutation (substituted VALUE) | `AT-B77-13` | `AT-B77-14` | Executed? |
    |---|---|---|---|---|
    | preserve | `selected = ordered[0]` (always reset) | **RED** | GREEN | ✅ QA-executed |
    | fallback | `selected = self._selected_cell_start` unconditionally | GREEN | **RED** | ✅ QA-executed |

    **QA's verdict: the split is sound on the selection-resolution clause** — each mutation reddens exactly one arm. **But conjoined with revision 1's identity-only focus clause, the fallback mutation produced `R,G,R` — byte-identical to correct**, collapsing the discrimination. That is a *consequence* of the liveness defect. **The liveness fix must land before these arms are trusted**; §7 orders it accordingly.
  - **Boundary:** `TC-B77-21` (no file → hint retained, no selection fabricated) · `TC-B77-22` (single run) · `TC-B77-23` (disjoint file switch) · `TC-B77-24` (zero-byte region) · `TC-B77-29` (preserved run no longer first after a re-merge — match by **address**, never index) · `TC-B77-31` 🆕 (resolution runs on the post-refresh hook, not inline)

> 🔒 **`AT-B77-15` — the hostile-input gate (security B-1).** `HLR-116` converts `#map_detail_body` from
> **click-gated** to **populated as a consequence of loading a file**. That body is the map's only sink for
> A2L symbol names (`:2397-2400`) and `ValidationIssue.code`/`.message`/`.symbol` (`:2410-2417`).
> Revision 1 disposed of this in one line (*"N/A: reuses `build_detail_text`, already C-17-hardened"*).
> **Executed, that line is half true.** `safe_text('sensor\x1b[31m_evil[red]')` returns the string
> **unchanged**: markup is inert (`spans: []`, `'[red]'` literal) but **the ESC byte survives**, and
> `len(plain)=21` for **16** visible characters — five invisible bytes billed as width.
> **The docstring at `screens_directionb.py:694-697` asserts the ANSI guarantee and is FALSE.**
> A false claim in shipped source became revision 1's premise.
> **Why it lands on *this* batch:** a hostile A2L symbol inflates rendered width by invisible bytes,
> distorting the very layout arithmetic R-7 exists to reconcile.
> `AT-B77-15` loads a fixture whose A2L carries `sensor[red]`, `x[link=file:///…]click[/link]` and a raw
> `\x1b[31m`; renders with **zero clicks and zero keys**; asserts at the **painted** layer: payloads
> verbatim, `spans == []`, **no `\x1b` in any painted strip row**, no raise. The control-byte limb is
> **RED today** — that is what makes it a gate. Routed to a **non-frozen** test file.
> **The scrub itself is NOT fixed here** — carry **C-77-h**; the fix site `safe_text:688` is outside
> `_ENGINE_PATHS`, but a control-char filter drifts snapshot baselines and belongs in its own batch.

### HLR-117 — the selected region row is visually distinguishable
- **Statement:** While a region is selected, the corresponding region row **shall** render a resolved style differing from that of every unselected region row, exactly one region row **shall** carry the selection marker, and the row's entropy band styling **shall** remain unchanged by selection.
- **Which layer holds the fact (P-42, executed):** `widget.styles.(background, color, text_style)`. `render().spans` is **`[]`** on these rows, so **C-37's span route is inapplicable**; `render_line` returns the base theme colour.
- **Acceptance:** **`AT-B77-12`** — triple differs ∧ exactly one marker ∧ band token unchanged; plus an `inspection` arm on the `styles.tcss` rule.
- **⚠️ security m-1:** revision 1's inspection arm ("sets no `color:` property") is satisfiable by `text-style: reverse`, which **does** repaint the band colour. **Strengthened** in `LLR-117.2`.
- **Boundary:** `TC-B77-25` (**fixture must have ≥2 runs and the body must assert it** — with one run the clause is vacuously true) · `TC-B77-26` · `TC-B77-27` · `TC-B77-28`

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
- **Cost, stated:** the band row grows 4 → 6 rows at 120×30, pushing `#map_stats_body` from `bottom=31/30` to `bottom=33/30`. It is **already** below the fold in the baseline at both regimes (reachable-under-scroll is the established policy for this pane). **OQ-5.**
- **Validation:** `test (integration)` · **Threshold:** `bar.region.width == #map_grid.region.width` at both regimes; glance widest row ≤ glance width

**LLR-111.1 — the width basis AND the denominator are both normative (R1, arch M-2)**
- **Statement:** `_build_band_widgets` **shall** derive segment widths from the rendered width of the `.map-band-bar` container obtained at render time; **shall** apportion run widths in proportion to each run's share of the **total mapped bytes** of the emitted runs; and **shall not** derive any segment width from `_BAND_BAR_WIDTH` or from the image address span.
- **Change (arch M-2):** revision 1 fixed only the *basis*; the **denominator** change (address-span → mapped-bytes) lived in an informative rationale. A naive discharge of rev-1's wording — swap `60 → bar_w`, keep `total_span` — is exactly the regression architect measured. **Promoted to normative.**
- **Symbols:** `_build_band_widgets:1988`; expressions to replace `:2058` (gap) and `:2066` (run); `_BAND_BAR_WIDTH:230`.
- **Acceptance:** ⚠️ the container width is unavailable before first layout — widths must be computed where the region is known (post-mount refresh / `on_resize`), **not** in `compose`. `assumed — verify the recompute hook at Phase 3.` Pre-layout fallback is **OQ-3**.

**LLR-111.7 🆕 — the allocation is bounded in the producer (arch B-2, R-7)**
- **Statement:** The sum of all emitted run-segment widths and all emitted gap-marker widths **shall not** exceed the measured container width, and every emitted run segment **shall** receive at least one column.
- **Rationale (informative):** **an output-shaped predicate cannot bound an allocation** — batch-74's asset restated. `AT-B77-03` is output-shaped; it detects the overflow but cannot prevent it. Executed: with the container basis and a 1-column fold but **no** bound, `prg.s19` emits **60 columns into a 50-column bar** while leaving 5 runs invisible (P-48). With the bound — floor 1 per run, remainder by largest-remainder on mapped bytes — `prg.s19` fits **exactly** at both regimes, all runs visible, monotone and strict, with **zero** aggregation (P-49).
- **Validation:** `test (integration)` + `analysis` · **Threshold:** `Σ widths + Σ markers ≤ bar.region.width` for every suite fixture **and** for `examples/case_00_public/prg.s19` specifically
- **Acceptance:** the bound is asserted on the **emitted widths**, and separately the allocator is unit-tested over a swept run count, so the bound holds **by construction** rather than by luck on one fixture.

**LLR-111.8 🆕 — aggregation past the bound, with an exact disclosure (R-7/2)**
- **Statement:** When the number of emitted run segments plus gap markers would exceed the container width, the panel **shall** merge the smallest adjacent runs into aggregate segments until the allocation fits, and **shall** disclose the exact number of runs that lost their own segment.
- **Precedent (`R-TUI-098`, `REQUIREMENTS.md:4988`):** that requirement discloses *"the cut hit class, the dropped count, and up to `…_MAX` of the variants whose hits were dropped, **with an explicit count of the remainder**"*. Two properties carry over: the disclosure names only items that **actually lost content** — never mere contributors — and **the count is exact even when the enumeration is bounded**.
- **Threshold, derived not guessed:** fires when `n_runs + n_gaps·fold > bar_width`. Executed onset: **`bar=50` → 25 runs clean, 26 aggregates 1**; **`bar=66` → 33 clean, 34 aggregates 1**. Consistent with `2·n_runs − 1 > bar_w`.
- **Acceptance:** the disclosed `N` must equal `(runs from the independent oracle) − (non-aggregate segments emitted)`, asserted against `_merge_band_runs`, **not** against the producer's own counter. ⚠️ **OQ-6:** bar or region list is undecided; both are count-only so B3 holds either way.

**LLR-111.2 — gaps fold to ONE column (R-5)**
- **Statement:** Each unmapped gap **shall** render at exactly one column, independent of its byte size and of the container width, and **shall** remain a plain `Static` classed `map-band-seg map-band-gap` — never a `RegionRow`, never a `BandSegment`.
- **Value rationale (measured):** at 21 columns `fold=2` yields `[3,3,3,3,1]`, collapsing three runs to equal width and gutting the strict limb; `fold=1` preserves discrimination at every container size.
- **⚠️ Scope reduction:** the charter's 2-column marker + humanized size label is **descoped** — carry **C-77-g**.
- **Acceptance:** existing `test_ac6_gap_hatch_segments_are_not_clickable` and `test_ac6_band_segments_do_not_widen_region_row_queries` stay green **unmodified** — **PIN, not gate**.

**LLR-111.3 — no segment paints outside its container** · **Statement:** Every `.map-band-seg` **shall** satisfy `bar.region.contains_region(seg.region)`. **Threshold:** outside `0` at both regimes (today **0 @80×24 / 4 @120×30**). **Acceptance:** this is what retires the PIN test — §6.5 Amendment C.

**LLR-111.4 — the gapless no-op control (R2), payload RE-DERIVED (arch B-6)**
- **Statement:** For a gapless image rendered at a fixed container width, the concatenated `.map-band-seg` classes and content **shall** equal a golden captured from the shipped producer after the width basis is settled.
- **Fixture — MUST be unequal:** `EQUAL 512/512 → [30,30]` at both regimes, invariant under any monotone re-weighting → vacuous. **`UNEQUAL 768/256`.**
- **⚠️ Corrected payload.** Revision 1 printed `[45,15]` labelled *"@80×24, container 66"*. **`45+15 = 60 = _BAND_BAR_WIDTH`, the retired constant.** Executed on the container basis:
  ```
  bar= 66 -> [50, 16]  sum=66      <- the post-Inc-1 payload at 80x24
  bar= 50 -> [38, 12]  sum=50      <- at 120x30 under R-7 CSS
  bar= 21 -> [16,  5]  sum=21      <- baseline CSS, reference only
  retired 60-basis -> [45, 15]     <- what revision 1 wrongly printed
  ```
  **These are `predicted` — the golden is captured by execution at Inc-3, never pasted from here.** They are printed only so a wrong capture is recognisable.
- **⚠️ C-42 encoding:** compare against the widget's runtime `render()` text — never snapshot-export bytes (`&#160;`), never a raw console `print` (my probe died on `UnicodeEncodeError` under cp1252). `-text` in `.gitattributes` if stored.

**LLR-111.5 — C-40 register for HLR-111** — *(each row carries its true status; see §9)*

| Predicate | Subject in the expression? | Mutation (substituted VALUE) | Status |
|---|---|---|---|
| `AT-B77-01` | ✅ `visible_cols` = `BandSegment.region` clipped to `bar.region`; `run_bytes` present | denominator → `total_span`; basis → `_BAND_BAR_WIDTH` | ✅ **GATE — RED both arms, executed** |
| `AT-B77-03` | ✅ `seg.region`, `bar.region` | restore the `_BAND_BAR_WIDTH` basis | ✅ **GATE — 4 outside @120×30, executed** |
| `AT-B77-17` | ✅ the emitted widths and the disclosed count | remove the bound (emit unclamped); set the disclosure to a constant `1` | ✅ **GATE — RED, executed** (60 cols into a 50-col bar) |
| `AT-B77-02` | ✅ classes + text per segment | substitute the fold denominator into the gapless path | 🔶 **PIN; gate via the post-Inc-3 mutation** — `predicted — execute at Inc-3` |
| `AT-B77-15` | ✅ the painted strip's bytes | remove `safe_text` from the A2L path | ✅ **GATE — RED, executed** (ESC survives) |
| ~~`Σ content ≤ _BAND_BAR_WIDTH`~~ | ❌ certifies a constant, not the operator's view | — | ❌ **REJECTED by R1 — recorded so it is not reintroduced** |
| ~~`monotone` alone~~ | ❌ GREEN at both regimes today | none exists | ❌ **VACUOUS LIMB — never the gate alone** |
| ~~rev-1 C-31 equality guard~~ | ❌ FALSE on correct code (P-44) | — | ❌ **REPLACED by the runs-oracle + coverage pair** |

**LLR-111.6 — geometry is read from settled layout, corrected (arch B-7)**
- **Statement:** Every test that reads a rendered region **shall** re-read the container width after successive `pilot.pause()` boundaries until two successive **post-pause** reads agree, and **shall not** treat repeated reads taken within a single frame as evidence of settling.
- **⚠️ Revision 1's rationale trace is RETRACTED.** It cited `68 → 68 → 66` as a live trace that would defeat a two-read rule. Executed at revision 2, 12 trials: **same-frame triples** `{(66,66,66):9, (68,68,68):3}` — the repeated `68` came from reading three times **inside one frame**; **one-read-per-pause sequences** `{(66,66,66):9, (68,66,66):3}` — never two consecutive transients. Architect's independent 97 traces (`0/60` double-68 across pauses) agree. **The phenomenon (N-2) is TRUE; my description of it was wrong, and the wrong description would have justified a stricter helper than the evidence supports.**
- **One criterion, not two.** Revision 1 also carried a weaker acceptance line ("no geometry AT calls `pilot.pause()` exactly once"). **Deleted** — the post-pause fixed-point rule is the single criterion.
- **Threshold:** ≥15 consecutive runs report the same settled width per regime.

### HLR-112 → LLR-112.x

**LLR-112.1 — ticks derive from RUN starts plus the last mapped byte (R4, §2.9)** · **Statement:** `MapRuler` **shall** accept the ordered emitted-run start addresses and the last mapped byte, and **shall** emit one `.map-ruler-tick` per retained address, replacing the fixed `_TICK_COUNT = 5` percentile derivation. **Symbols:** `MapRuler:1234`, `_TICK_COUNT:1274`, `compose:1293`, construction `:2102` (signature changes). **Threshold:** 0 labels outside every mapped range (today 4 of 5); `END_LABEL == f"{span_end-1:08X}"` — executed `0x07FFFF3D` mapped **True** vs `span_end 0x07FFFF3E` mapped **False**.

**LLR-112.2 — legibility, not overlap (security M-1)** · **Statement:** The ruler **shall not** emit a tick whose rendered width is less than the length of the label it carries, and **shall** retain the first and last labels in preference to any interior label when labels must be dropped. **Rationale (informative):** revision 1 asserted "0 overlapping column ranges", which **cannot fail** — `width:1fr` children partition the row and never overlap; they degrade to zero width. Executed in a synthetic `1fr` row: `N=20, W=50 → max tick width 3` (an 8-char label elided); `N=60, W=50 → 10 zero-width ticks, 0 overlaps`, and revision 1's conjunction was **GREEN**. **Interaction with R-7:** the widened bar raises the tick budget and `LLR-111.8`'s aggregation lowers the run count the ruler must label — but the elision predicate is what makes any residual loss **visible rather than silent**. **Geometry:** `assumed — measure at Phase 3` at the widened 50-column regime; the `0x`-prefix-drop fallback is **already spent** (`:1245-1247`).

**LLR-112.3 — the retired clause is amended at EIGHT sites (arch M-3, security M-2)**
- **Statement:** The batch **shall** record Before/After amendments for `R-TUI-072` and `LLR-072.3` and **shall** update every surviving statement of the retired 5-tick contract in shipped source, tests, `REQUIREMENTS.md`, and the batch-47 artifact set.
- **Census, executed — 8 sites, was 6:**
  | # | Site | Form |
  |---|---|---|
  | 1–4 | `screens_directionb.py:1239, :1273, :1300, :2002` | `LLR-072.3` citations |
  | 5 | `tests/test_tui_map_big.py:118` (+ `:140` `len(ticks)==5`) | citation + assertion |
  | 6 | `tests/test_tui_snapshot.py:670` | citation |
  | 7 | 🆕 **`s19_app/tui/legend.py:606-614`** | **PROSE** — *"address ruler — 5 ticks at 0/25/50/75/100 % of span"* **plus a 5-address sample line**. **Matches no `LLR-072` grep.** The file appears **0 times** in revision 1. |
  | 8 | 🆕 `.dev-flow/2026-07-15-batch-47/06-docs/traceability-matrix.md:54` | verbatim restatement |
  | — | `REQUIREMENTS.md:4790` + the duplicate at `:4191` | the requirement text itself |
- **⚠️ Why site 7 matters most:** it is what the **operator reads**. `AT-B77-07` (legend screen unaffected) would pass **green** while the legend screen describes pre-batch behaviour. A census keyed on an id cannot find a prose restatement — **C-42 in its purest form**, and the reason the census is now derived from the *claim* rather than from the *id*.
- **Threshold:** 0 surviving assertions of "exactly 5 ticks" in shipped source, tests or `REQUIREMENTS.md`; 8 sites reconciled.

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
> *(`LLR-115.1` deleted — moved to `LLR-116.1` per arch B-4.)*

### HLR-116 → LLR-116.x
**LLR-116.1 🆕 — rows are focusable and reachable (moved from `LLR-115.1`, arch B-4)** · **Statement:** `RegionRow` **shall** be declared focusable, and the panel **shall** establish a focus path to the region rows without operator input. **Symbols:** `RegionRow:1088`; `can_focus` **NEW — created in Phase 3** (0 hits today). **⚠️ Textual internal-name shadowing:** every new member **shall** be checked against `dir(Widget)` — a `_nodes`/`_context` collision is a silent mount crash with no traceback. **⚠️** Do not widen the global `tab` chain without checking the rail — it changes focus on every screen. `assumed — verify at Phase 3`. **Why it moved:** `row.focus()` is a **no-op** while `can_focus` is False (architect-executed), so this is a precondition of `LLR-116.5`, not of the keyboard behaviour.
**LLR-116.2 — auto-select after reset, on a post-refresh hook** · **Statement:** The panel **shall** resolve and apply the selection after `_reset_detail()` has run and after the mounted rows are queryable. **Symbols:** `render_ranges:1808`; `_reset_detail()` call `:1896`, body `:2313-2330`; `_ordered_ranges:1923`; `grid.mount():1927-1929`. **⚠️ `grid.mount()` is deferred** — "after the rows are mounted" is not a synchronous point; a post-refresh hook is required (QA B-3 root cause).
**LLR-116.3 — auto-selection never navigates** · **Statement:** Auto-selection **shall not** post `MemoryMapPanel.OpenInHexRequested`. **Acceptance:** ⚠️ C-40 — co-assert the inspector was populated in the same run.
**LLR-116.4 — re-render resolution (R-6)** · **Statement:** On each render the panel **shall** resolve the selected region to the previously selected region when a region with that start address is present among the newly rendered rows, and to the first region otherwise. **Rationale (informative):** matching is by **address**, never index — a re-merge changes how many runs precede the selected one.
**LLR-116.5 — focus follows the resolved selection, and the focused row is LIVE (QA B-3)** · **Statement:** After the selection is resolved, focus **shall** be on a region row that is attached to the running application and present among the panel's currently mounted region rows, and whose start address equals the resolved selection. **Threshold:** `app.focused in set(app.query(RegionRow))` **and** `app.focused.is_attached` **and** `app.focused.region_start == resolved`. **Rationale (informative):** identity alone is satisfied by a **detached** row — QA executed `is_attached=False`, `parent=None`, focused row absent from the 5 live rows, threshold `True`. Deferred child removal (`:2094-2097`) is the mechanism.
**LLR-116.6 🆕 — the auto-populated inspector is markup- and control-char-safe (security B-1)** · **Statement:** On a render that auto-selects a region, `#map_detail_body` **shall** render every file-derived string as literal content with no style span and no hyperlink, and **shall not** emit any C0 or C1 control byte into the painted strip. **Symbols:** `build_detail_text:2338`; A2L path `:2397-2400`; `ValidationIssue` path `:2410-2417`; `safe_text:688`. **Threshold:** payloads verbatim in `render().plain`; `render().spans == []`; `"\x1b" not in` any painted strip row — **RED today**; no raise. **Validation:** `test (e2e)`, routed to a **non-frozen** test file. **⚠️** Read the **painted strip** for the control-byte limb, not `.plain` — `.plain` is where the byte lives, the strip is where it escapes.

### HLR-117 → LLR-117.x
**LLR-117.1 — marker applied by address** · **Statement:** The panel **shall** apply a selection marker to the region row whose `region_start` equals the resolved selection, and to no other row. **Threshold:** exactly 1 (today 0), matched by address not index.
**LLR-117.2 — the band channel survives selection (strengthened, security m-1)** · **Statement:** Applying or removing the selection marker **shall not** add, remove or override any `band-*` class on the row, and the selection style **shall not** set a foreground colour nor a text style that inverts foreground and background. **Change:** revision 1 said only "no `color:` property", which `text-style: reverse` satisfies while repainting the band colour.

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
| US-77-1 | gapless no-op | `AT-B77-02` | **PIN**, gate via post-Inc-3 mutation — `predicted` |
| US-77-1 | nothing outside the bar | `AT-B77-03` | **RED @120×30** (4 outside) — executed |
| US-77-1 | allocation bounded + exact disclosure | `AT-B77-17` 🆕 | **RED** — executed: 60 cols into a 50-col bar on `prg.s19` |
| US-77-2 | every label admissible + legible | `AT-072b` | **RED** — 4 of 5 unmapped — executed |
| US-77-2 | lower bound | `AT-B77-04` | **RED**; `set() ⊆ admissible` is True — executed |
| US-77-3 | dual readout | `AT-B77-05` | **RED** — executed |
| US-77-4 | legend gone from body | `AT-B77-06` | **RED** — 4 rows, 1 container — executed |
| US-77-4 | legend screen intact | `AT-B77-07` | **PIN** |
| US-77-5 | arrows + Enter | `AT-B77-08` | **RED** — `can_focus=[False]×5` — executed |
| US-77-5 | no binding shadowed, focus ON row | `AT-B77-09` 🔄 | **RED-able only after Inc-7** (needs focus-on-row) — stated |
| US-77-5 | same, focus off row | `AT-B77-16` 🆕 | **PIN** |
| US-77-5 | N4a mouse split | `AT-B77-10` | **PIN** — reuse `test_ac3_…`/`test_ac4_…` (QA M-5) |
| US-77-6 | focused + inspected, zero input | `AT-B77-11` | **RED** — executed |
| US-77-6 | re-render preserved + focus LIVE | `AT-B77-13` | **RED** — executed |
| US-77-6 | re-render fallback + focus LIVE | `AT-B77-14` | **RED** — executed |
| US-77-6 | hostile input, zero clicks | `AT-B77-15` 🆕 | **RED** — ESC survives `safe_text` — executed |
| US-77-7 | selection visible | `AT-B77-12` | **RED** — 0 markers — executed |

**Functional chain:** HLR-111 → LLR-111.1…**.9** → `TC-B77-01…05`, `TC-B77-30` · HLR-112 → LLR-112.1…3 → `TC-B77-06…09` · HLR-113 → LLR-113.1…2 → `TC-B77-10…13` · HLR-114 → LLR-114.1…2 → `TC-B77-14…15` · HLR-115 → LLR-115.2…4 → `TC-B77-16…20` · HLR-116 → LLR-116.1…**.6** → `TC-B77-21…24`, `TC-B77-29`, `TC-B77-31` · HLR-117 → LLR-117.1…2 → `TC-B77-25…28`.

### 5.4 IDs
**Batch-scoped `AT-B77-01…17`, `TC-B77-01…31`.** Letter-initial bodies are outside `AT-TC-REGISTRY.jsonl` authority (`_meta.governed`, spec §2.3); **no reservation PR**. **Exception:** `AT-072b` keeps its global id as a re-derivation. New at revision 2: `AT-B77-15` (hostile input), `AT-B77-16` (shadow PIN), `AT-B77-17` (allocation bound), `TC-B77-30` (heterogeneous range), `TC-B77-31` (post-refresh hook).

---

## 6. Appendices

### 6.3 Risks and carries

| # | Item | Disposition |
|---|---|---|
| **C-77-h** 🆕 | **`safe_text`'s ANSI guarantee is asserted in shipped source and is FALSE** (`screens_directionb.py:694-697`). Executed: ESC survives, 5 invisible bytes billed as width. Fix site is **not frozen**, but a control-char filter drifts snapshot baselines. | **Lane-A carry.** `AT-B77-15` pins the behaviour meanwhile |
| **C-77-i** 🆕 | `.dev-flow/BACKLOG-CODE.md:53` still asserts `LLR-072.3` has "ZERO definitions" / is "a dangling reference" — **false**, and live in the Lane-A queue; `PLAN.md:171-173` repeats it. | **Owned by Inc-5** (arch M-4) |
| **C-77-j** 🆕 | The glance box (28) is **1 column narrower than its widest content row (29) today** — a pre-existing clip found while measuring R-7. `LLR-111.9` incidentally fixes it at 120×30. | Lane-A carry for the 80×24 path |
| **C-77-f** | `o` = open-hex descoped (R3) | Lane-A carry |
| **C-77-g** | 2-column marker + size label descoped (R-5) | Lane-A carry |
| **C-77-a/c/d/e** | dense `round()` drift (superseded by R1/R-7) · `REQUIREMENTS.md` not an HLR index · US-77-8 · Variant B | carried |
| **R-7** *(risk)* | Geometry unsettled after one pause (17/97, two lanes) | `LLR-111.6` |
| **R-8** 🆕 | `#map_stats_body` pushed 2 rows deeper below an already-below-the-fold position by `LLR-111.9` | **OQ-5** |
| **F-1** | Self-caught probe defects: (a) cp1252 `UnicodeEncodeError`; (b) temp-cleanup `PermissionError`; (c) an unsettled 23/50 read reported as fact; (d) `address_in_sorted_ranges` arg order inverted; (e) a `pilot.click` that did not land, making the R-6 arms RED for the wrong reason; **(f) 🆕 my R-7 candidate sweep compared the glance box against its TITLE (11 cols) instead of its widest CONTENT row (29) and reported "STARVED: none" for every candidate — the exact C-13 starvation the probe existed to detect**; **(g) 🆕 my first runs-vs-ranges fixture constructed `random.Random(3)` per byte, making the "random" half constant, so 1 range yielded 1 run and appeared to REFUTE the finding — corrected to one rng, 1 range → 2 runs** | recorded, not hidden |

### 6.4 Reconciliation log — revision 2

| Blocker | What changed | Parent re-read? | Body edit landed? |
|---|---|---|---|
| arch **B-1**, **B-2** | container widened (R-7/1) + normative bound + aggregation | **HLR-111 Statement rewritten**, threshold extended | §3 HLR-111; §4 **LLR-111.7/.8/.9**; `AT-B77-17` |
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

### 6.5 Requirement amendments
**Amendment A (`R-TUI-072`)** and **Amendment B (`LLR-072.3`)** — Before texts verbatim-verified by the architect lane. **After** texts updated to *"one tick label per emitted **run** start plus one for the last mapped byte"* (§2.9) and extended with the legibility clause (security M-1). Amendment A's parent re-read still names the duplicate at `REQUIREMENTS.md:4190-4191`.
**Amendment C** — retirement of `test_ac6_clipped_segments_are_a_known_layout_limitation`, verified by the architect lane to drop no observable. **Two additions:**
- **Name the fixtures** in the retirement table (arch m-2): the deleted node measures `outside_count` on `_two_band_loaded` **@120×30**; `AT-B77-03` measures the same predicate on the 5-region sparse fixture **and** on `prg.s19`. Same predicate, **different fixture** — the inversion claim is now checkable rather than loose.
- **Rule on the `160×48` size** (arch m-1): the limitation note at `tests/test_map_click_chain.py:220-227` is the **only** justification for the two AC-6 pointer tests running at `160×48` instead of `120×30`. After R1/R-7 that justification is false, and leaving it would lose the batch's only band-segment-clickability coverage at the regime R-7 repairs. **Both tests revert to `120×30` in Inc-1**, in the same edit that drops the note.

---

## 7. Increment plan — re-cut (arch B-3, QA B-2)

| Inc | Content | Files | Gate |
|---|---|---|---|
| **Inc-1** | **CSS widen + container basis + bound + fold + settling, TOGETHER** — `LLR-111.9`, `.1`, `.7`, `.2`, `.6`, `.3`. Amendment C deletion + the two AC-6 pointer tests reverted to 120×30. | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_map_big.py`, `tests/test_map_click_chain.py` (4) | `AT-B77-01`, `AT-B77-03` **both arms**; full ×3 |
| **Inc-2** | **`LLR-111.8` aggregation + exact disclosure** · owns `AT-B77-17` | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_map_big.py` (3) | `AT-B77-17` + its executed mutation |
| **Inc-3** | **`LLR-111.4` golden capture**, own commit, after the basis settles · **owns `AT-B77-02`** (arch M-5) | `tests/test_tui_map_big.py`, golden artifact, `.gitattributes` (3) | golden committed; stored blob's bytes verified |
| **Inc-4** | **HLR-112 ruler** — code + tests + **`legend.py` site 7** | `screens_directionb.py`, `legend.py`, `tests/test_tui_map_big.py`, `tests/test_tui_snapshot.py` (4) | `AT-072b`, `AT-B77-04`; 0 "5 ticks" in source/tests |
| **Inc-5** | **Amendments A + B + doc census** + **carry C-77-i** | `REQUIREMENTS.md`, batch-47 `01-requirements.md`, batch-47 `traceability-matrix.md`, `.dev-flow/BACKLOG-CODE.md`, `PLAN.md` (5) | 8 sites reconciled; backlog claim corrected |
| **Inc-6** | **HLR-113 + HLR-114** stats + legend removal; `test_at075` `e`-clause **ported** | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_directionb.py`, `REQUIREMENTS.md` (4) | `AT-B77-05/06/07` |
| **Inc-7** | **HLR-116 + HLR-117** — `LLR-116.1` focusability (moved here), post-refresh hook, resolution, **liveness**, selection style, **`AT-B77-15` hostile input** | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_map_big.py`, `tests/test_tui_hostile_map.py` (NEW, non-frozen), `REQUIREMENTS.md` (5) | `AT-B77-11/12/13/14/15`; the two R-6 mutations executed **after** liveness lands |
| **Inc-8** | **HLR-115** arrows + Enter. **No `show=True` binding.** | `screens_directionb.py`, `tests/test_tui_map_big.py`, `REQUIREMENTS.md` (3) | `AT-B77-08/09/16`; **TC-011 green and unmodified** |
| **Inc-9** | Snapshot regen — **canonical CI only** | snapshot baselines | full suite; per-cell C-22 |

**Ordering constraints — four, all forced by execution:**
1. **Inc-1 is indivisible.** Container basis alone leaves both its ATs RED and **regresses 80×24** from `outside=0` to `outside=2` (gap widths `[8,8,16,33]` = 65 of 66 columns). Basis, bound and fold must land together or the increment cannot pass its own gate.
2. **Inc-1 → Inc-2.** Aggregation is defined relative to the bound; without the bound there is nothing to overflow.
3. **Inc-3 after Inc-1.** A golden captured before the basis settles pins the retired arithmetic — precisely how `[45,15]` got into revision 1.
4. **Inc-7 → Inc-8.** `LLR-116.1` (focusability) is a precondition of `AT-B77-08`; `row.focus()` is a **no-op** until `can_focus` is True. And `AT-B77-09`'s gate arm requires focus-on-row, which Inc-7 establishes.

---

## 8. Open questions

| # | Question | Blocks | Owner |
|---|---|---|---|
| **OQ-5** 🆕 | `LLR-111.9` pushes `#map_stats_body` from `bottom=31/30` to `bottom=33/30` at 120×30. It is **already** below the fold at both regimes in the baseline (reachable-under-scroll is the established policy for this pane), so this deepens an existing scroll rather than newly hiding it. Accept, or reclaim rows elsewhere? | Inc-1 | **OPERATOR** |
| **OQ-6** 🆕 | Does the `+N more` aggregate disclosure render **in the bar** or **in the region list**? Both are count-only so B3 holds either way; it changes which surface `AT-B77-17` observes. | Inc-2 | **OPERATOR** |
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
| **Every gate AT RED by execution** | ⚠️ **partial, and LABELLED** | **14 executed RED** (§5.2), including the three new ones. **`AT-B77-02` is a PIN** — `predicted`, gated by a post-Inc-3 mutation. **`AT-B77-09` cannot be RED until Inc-7** (it needs focus-on-row). Both stated, neither hidden. |
| **C-40 both limbs per predicate** | ⚠️ **partial, and LABELLED (QA M-1)** | `LLR-111.5` marks each row ✅ **executed** or 🔶 `predicted — execute at Inc-N`. **Revision 1 marked this row ✓ while its mutations were written against code that does not exist — a prediction wearing a discharge mark**, the exact defect class this batch keeps finding. The R-6 table is now labelled *executed at Phase 2 by the QA lane*, with its collapse-under-B-3 caveat recorded. |
| No transcript carried from a retired basis | ✓ | header states the narrow, checkable form; `LLR-111.4`'s payload re-derived and the old value shown as the counterexample |
| Normative keyword discipline | ✓ | `shall` only in Statements, quoted requirement text, and §2.7's quoted premises |
| No id minted outside authority | ✓ | `AT-B77-*`/`TC-B77-*` batch-scoped; `AT-072b` re-derived |
