# Requirements Document — s19_app — batch `2026-08-01-batch-77`

**Objective:** Memory Map redesign — Variant A (gap-fold band bar) + cross-cutting fixes S-1…S-7
**Branch:** `claude/batch-77-memmap-variant-a` · **Base:** `origin/main` @ `f8747b8` (HEAD `065bb95`, docs-only)
**Consolidates:** `00-measurements.md` (Phase 0) · `01-requirements-architect.md` (architect lane) · `01b-qa-validation.md` (QA lane)
**Operator rulings R1–R4 + four binding decisions, 2026-08-01** — authoritative, superseding both lanes where they differ.
**Language:** English · **Lane:** A (`.dev-flow/BACKLOG-CODE.md`) · **Normative keyword:** `shall`, only inside HLR/LLR **Statement** lines.

> **All transcripts in this document were RE-EXECUTED after the rulings.** Nothing measured under the old
> `_BAND_BAR_WIDTH` basis is carried forward. Probes ran read-only with `PYTHONDONTWRITEBYTECODE=1` (C-46).

---

## BLUF

**All prior blockers are closed by the rulings. Re-execution closed them and opened two new findings, one of which changes an acceptance.**

| # | Finding | Status |
|---|---|---|
| **N-1** | 🆕 **The two regimes redden on DIFFERENT limbs, so neither limb alone is a gate.** Measured at the painted layer: at **80×24** `visible≥1`=GREEN, `strict`=**RED**; at **120×30** `visible≥1`=**RED**, `strict`=**GREEN**. Dropping either limb ships one regime green. **This corrects the QA lane**, which stated the strict clause is "RED at both" — true on *content* widths, false on *painted* widths, because at 120×30 two runs clip to 0 and 1>0 satisfies strictness. | ✅ folded into `AT-B77-01` as a **three-way conjunction** |
| **N-2** | 🆕 **Map geometry is not settled after one `pilot.pause()`.** At 80×24 the bar transiently reads **68** before settling to **66** — reproduced 1-in-5 over 15 runs. My own first consolidated probe read **23/52** at 120×30 where the settled value is **21/50**. Not caused by reading `active_bindings` (executed: 21→21→21). | ✅ new risk **R-7**; every geometry AT must settle to a fixed point — `LLR-111.6` |
| **B-3 (arch)** | `LLR-072.3` **exists**; `REQUIREMENTS.md` defines 0 LLR bodies | ✅ **ACCEPTED by operator** — two amendments, §6.5 A + B |
| **N-1 (arch)** | HLR/LLR high-water is **110**, not 106 | ✅ **ACCEPTED** — `HLR-111…117` |
| **B-1 / B-2 (arch)**, **B-1…B-6 (QA)** | all six QA blockers + both architect blockers | ✅ **CLOSED by R1–R4** |

**Nothing is left unresolved at the requirement level.** The two questions this document raised were answered by **R-5** (one-column fold marker, always) and **R-6** (preserve the selection if the region is present, else fall back to first; focus follows selection); both are folded in below, each with a new carry or new acceptance arms. §8's two remaining entries (**OQ-3** `_BAND_BAR_WIDTH` as a pre-layout fallback, **OQ-4** the focus-entry mechanism) are **Phase-3 implementation choices**, not requirement gaps. **This document is final for Phase 2 review.**

---

## 1. Introduction

### 1.1 Purpose
Derive the HLR/LLR set for batch-77 under IEEE 830 + EARS from the seven READY stories, with every code claim verified against disk and every acceptance demonstrated RED by execution.

### 1.2 Scope
**In:** US-77-1 … US-77-7 (charter S-1…S-7).
**Out:** US-77-8 (Variant C ports); Variant B; the CC-1 encoding decision; **`o` = open-hex from the keyboard** (descoped by R3 — §6.3 carry C-77-f); **the dense-image `round()` drift** (carry C-77-a).

### 1.3 Definitions

| Term | Definition |
|---|---|
| **run** | A merged same-band region from `_merge_band_runs` → a `BandSegment` (`screens_directionb.py:1172`). |
| **gap** | Unmapped interval between runs → an inert `Static` classed `map-band-seg map-band-gap` (`:2060-2064`). |
| **container** | `.map-band-bar`, the `Horizontal` the segments are mounted into (`:2098`). Its `region.width` is **measured at render time**, never assumed. |
| **`visible_cols(seg)`** | `max(0, min(seg.region.right, bar.region.right) − max(seg.region.x, bar.region.x))` — the **painted, clipped** width. **Not** `len(str(seg.render()))`, which is a pre-layout proxy blind to clipping (C-32). |
| **settled geometry** | A read taken after the container width reaches a fixed point (two consecutive equal reads, or ≥2 `pilot.pause()`). See N-2. |
| **fold** | Replacing a gap's proportional width with a fixed, size-independent marker width. |

### 1.4 References
`REQUIREMENTS.md` R-TUI-041/060/061/072/073/074 · `.dev-flow/2026-07-15-batch-47/01-requirements.md` (LLR-072.x bodies) · `docs/engineering-rules.md` · `01b-qa-validation.md` (validation design, folded in) · `AT-TC-REGISTRY.jsonl`.

---

## 2. Overall description

### 2.1 Product perspective
`MemoryMapPanel` (`screens_directionb.py:1660`) → `render_ranges` (`:1808`) → `_build_band_widgets` (`:1988`) mounts four children into `#map_grid`: band row (bar + glance), `MapRuler` (`:1234`), region list of `RegionRow` (`:1088`), 4-row legend (`:2084-2104`). Batch-77 changes the width **basis**, the ruler **tick derivation**, the stats **composer** (`build_stats_text:2275`), removes the legend, and adds a focus/selection layer that does not exist today.

### 2.2 Constraints (all verified or measured)

| Constraint | Value | Evidence |
|---|---|---|
| Regimes | 80×24 and 120×30 | `tests/test_tui_map_big.py:32` |
| **`.map-band-bar` measured width** | **66 @80×24 · 21 @120×30** (settled) | executed §2.7 P-31; the wide regime is *narrower* — the glance panel docks beside it |
| `_BAND_BAR_WIDTH` | `60` — **retired as a width basis by R1** | `screens_directionb.py:230` |
| Textual | 8.2.8 | executed |
| Footer capacity | **14** `show=True` chips in a **78**-col Footer @80×24 | executed §2.7 P-35 |
| Engine-frozen set | off-limits, source **and** `_ENGINE_TEST_FILES` (C-27) | `PLAN.md:118` |
| B3 | no file-derived text in bar/rows | `REQUIREMENTS.md:4158`, `:4817` |
| Colour | only via `band-*`; glyphs `· ░ ▒ ▓` are the colour-blind cue (C-10) | `styles.tcss:665/669/673/677` |
| LLR-041.7 | panel is presentational — no re-derivation | `REQUIREMENTS.md:667` |
| Remount discipline | classes, never ids (`DuplicateIds`) | `screens_directionb.py:2094-2097` |

### 2.6 Source user stories

| ID | Story | DoR |
|---|---|---|
| **US-77-1** | As a firmware engineer, I want every mapped region visible with a width that orders by mapped size and gaps folded, so that I can tell regions apart on a sparse image **at every supported terminal size**. | 🟢 READY (R1, R2) |
| **US-77-2** | …every ruler label to name a mapped address, so that the ruler tells me where my data is. | 🟢 READY (R4) + §6.5 A+B |
| **US-77-3** | …a dual mapped/span readout with a real percentage and humanized sizes. | 🟢 READY |
| **US-77-4** | …the always-on 4-row legend block **removed from the map body**, so that the map uses its rows for the map. | 🟢 READY (re-authored per B-4) |
| **US-77-5** | …to reach and act on regions with **arrows and Enter**, so that I am not forced onto the mouse. | 🟢 READY (R3) |
| **US-77-6** | …the inspector populated and a region focused with zero clicks. | 🟢 READY (absorbs the focus-entry path) |
| **US-77-7** | …the selected region row visually distinct. | 🟢 READY |
| **US-77-8** | Variant C ports | 🔴 OUT — carry C-77-d |

**US-77-4 re-authored (QA B-4).** Executed: `k → Legend` is **already** a `show=True` footer chip on the map screen. "A footer hint points to `k`" is **GREEN pre-change** — vacuous. The falsifiable content is the **removal of the 4-row in-body block**, which is RED today (4 rows present). The story no longer claims to add a hint.

**US-77-6 widened (QA B-6).** Executed: `down`×3 and `tab` never leave `RailItem`; `can_focus == False` on all 5 rows; `RegionRow.BINDINGS == []`. `can_focus = True` alone is not an entry path, so **US-77-6 owns the focus-entry mechanism** and US-77-5's keyboard AT is unreachable without it. This is a hard increment ordering constraint (§7).

### 2.7 Premise evaluation (C-43)

Phase-0 P-1…P-15 and the architect lane's P-16…P-30 are not restated. This table carries what the **rulings** and the **re-execution** newly establish or correct.

| # | Premise | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| **P-31** | The bar container is **66 @80×24 / 21 @120×30**, settled | premise | ✅ **TRUE** | 15 runs: `120×30 → 21` in 15/15; `80×24 → 66` at ≥2 pauses in 15/15. Confirms QA; **refutes `REQUIREMENTS.md:4800`'s "52 @120×30"**, which is `#map_grid` (50 measured), not the bar. | drives R1 |
| **P-32** | 🆕 **The two regimes redden on different limbs** | hypothesis | ✅ **TRUE — corrects the QA lane** | `80×24`: `visible≥1=True`, `monotone=True`, `strict=False`. `120×30`: `visible≥1=False`, `monotone=True`, `strict=True`. QA §3.1 states strict is "RED at both"; that holds on *content* widths (all `1`), not on *painted* widths — at 120×30 two runs clip to `0` and `1 > 0` satisfies strictness. | `AT-B77-01` is a **3-way conjunction**; per-arm verdicts mandatory (CC-1) |
| **P-33** | 🆕 **Map geometry is settled after one `pilot.pause()`** | premise | ❌ **FALSE** | `80×24` over 5 runs @1 pause: `[66,66,68,66,66]` → **not stable**; @2 pauses: `[66,66,66,66,66]`. Traced live: `(68 → 68 → 66)` across an extra pause. My own first probe read `23/52` @120×30 vs the settled `21/50`. **Not** caused by `active_bindings` (executed: `21→21→21`, `66→66→66`). | **new risk R-7**; `LLR-111.6` mandates settling |
| **P-34** | R4: `span_end` is exclusive and unmapped; the last mapped byte is mapped | premise | ✅ **TRUE** | `span_end = 0x07FFFF3E  mapped? False`; `last mapped byte = 0x07FFFF3D  mapped? True` (oracle = frozen `address_in_sorted_ranges`) | R4's label is well-formed |
| **P-35** | Ruler ticks naming unmapped addresses = **4 of 5**, not 3 | premise | ✅ **TRUE — corrects Phase-0 P-7** | `[('00000000',True),('01FFFFCF',False),('03FFFF9F',False),('05FFFF6E',False),('07FFFF3E',False)]` → **4 of 5** | R4 is right |
| **P-36** | An equal-run dense fixture is a vacuous golden (QA B-5) | hypothesis | ✅ **TRUE** | `EQUAL 512/512 → content [30,30]` at **both** regimes — invariant under any monotone re-weighting. `UNEQUAL 768/256 → [45,15]`. | golden fixture **must** be unequal |
| **P-37** | 🆕 The dense fixture is fully visible at both regimes | premise | ❌ **FALSE** | `UNEQUAL 768/256 @120×30: content=[45,15] visible=[21,0]` — the **second run is invisible today even with no gaps**. | the golden is captured **at a fixed container width** (R2), and the dense control is a *content* comparison, not a visibility one |
| **P-38** | R1 is achievable inside the real container at both regimes | hypothesis | ✅ **TRUE** | scaling to the measured container: `bar=66,fold=1 → [15,15,15,12,4] total 65 fits mono strict allvisible`; `bar=21,fold=1 → [4,4,4,3,1] total 20 fits mono strict allvisible`; `bar=21,fold=2 → [3,3,3,3,1] total 21 fits`. | acceptance is **not** physically impossible (C-29) |
| **P-39** | The PIN test's docstring sanctions its own deletion | premise | ✅ **TRUE** | `tests/test_map_click_chain.py:342-389`: *"If the constant and the container were reconciled, DELETE this test — it exists only to pin the disagreement"* and *"delete it and drop the limitation note from the two AC-6 pointer tests"*. | R1's deletion is docstring-sanctioned; §6.5 Amendment C records it |
| **P-40** | `o` and `j` are frozen in `_PRE_BATCH_BINDINGS` under live TC-011 | premise | ✅ **TRUE** | `tests/test_tui_directionb.py:5460-5478` — `("o","open_workarea")`, `("j","dump_a2l_json")`; consumed at `:5578` by `test_tc011_every_pre_batch_action_keeps_a_keyboard_path` | **R3 touches neither** → TC-011 stays green, no supersession owed |
| **P-41** | `k → Legend` is already a footer chip on the map screen | premise | ✅ **TRUE** | footer `show=True` keys = `['comma','ctrl+d','ctrl+k','ctrl+l','ctrl+s','g','k','minus','period','plus','q','question_mark','slash','x']` — **14 chips**, `'k' in set → True` | US-77-4's hint clause is vacuous → re-authored |
| **P-42** | `RegionRow.render().spans` carries the selection fact | premise | ❌ **FALSE** | `row render().spans lengths = [0,0,0,0,0]` — plain `Text`, no inline markup. **C-37's span route is inapplicable.** The fact lives in `widget.styles`: measured triples `('Color(0,0,0,a=0)','Color(107,114,128)','none')` vs `('Color(0,0,0,a=0)','Color(217,163,91)','none')` — `color` differs per band, `background` transparent on every row. | `AT-B77-12` reads the resolved-CSS **triple** |
| **P-43** | No focus entry path to the region list exists | premise | ✅ **TRUE** | `can_focus = [False]*5`; `RegionRow.BINDINGS = []`; `app.focused` after render = `RailItem` | US-77-6 owns the entry path |

**Gate rule:** ❌ blocks. P-33, P-37, P-42 are ❌ and each is dispositioned in the body above. P-32 is a ✅ that **corrects a peer lane** and reshapes an acceptance.

### 2.8 The four operator rulings, as applied

| Ruling | Applied as | Supersedes |
|---|---|---|
| **R1** — reconcile to the real container | `HLR-111` scales to `bar.region.width` measured at render time; `LLR-111.1`; the `_BAND_BAR_WIDTH` basis is retired; the PIN test is deleted with a §6.5 retirement record | architect B-1 option ①; QA §3.3 option C-1 |
| **R2** — re-base the golden after the width fix | `LLR-111.4` — settle width first, capture in its own commit, then assert **gap-folding is a strict no-op on gapless images at fixed container width**; fixture **unequal** 768/256 | the "byte-identical to today" clause |
| **R3** — arrows + Enter only | `HLR-115`; `j`/`k`/`o` unbound on the row; `o` = open-hex **descoped** (carry C-77-f); mouse N4a unchanged | architect B-2 option ①; QA B-3 |
| **R4** — label the last mapped byte | `HLR-112`; `END_LABEL = f"{span_end-1:08X}"`; 4 of 5 (not 3) | QA B-2; Phase-0 P-7 |

**Binding decisions:** batch-scoped ids `AT-B77-nn` / `TC-B77-nn` (outside registry authority per `_meta.governed`; **no reservation PR**), except `AT-072b` which keeps its global number as a re-derivation.

---

## 3. High-level requirements (HLR)

> **ID basis:** high-water over `REQUIREMENTS.md` + `.dev-flow/` + `tests/` + `docs/` is **`HLR-110`/`LLR-110`** (`HLR-108/109/110` live in shipped tests, absent from `REQUIREMENTS.md`). Next free = **`HLR-111`**. `HLR-*`/`LLR-*` are a separate counter from `R-TUI-*` (high-water `R-TUI-102`).

---

### HLR-111 — every mapped region is visible, ordered by size, inside its real container
- **Traceability:** US-77-1 · **Ruling:** R1, R2
- **Statement:** When the Memory Map renders an image at any supported terminal size, the band strip **shall** scale segment widths to the rendered width of their container measured at render time; **shall** paint at least one visible column for every mapped region; **shall** emit visible widths that are non-decreasing in mapped bytes with at least one strictly greater pair whenever two runs differ in mapped size; **shall** fold each unmapped gap to a fixed marker width independent of that gap's byte size; and **shall not** paint any segment outside its container.
- **Rationale (informative):** The shipped code scales to the module constant `_BAND_BAR_WIDTH = 60` while the container is `width: 1fr`. Measured settled: **66 @80×24** and **21 @120×30** — a 39-column disagreement at the wide regime, where **2 of 5 mapped regions are painted entirely off the bar today**. R1 retires the constant as a width basis. Feasibility is measured, not assumed (P-38): at 21 columns the target widths are `[4,4,4,3,1]`, which fit, order, and are all visible.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k "b77_width or b77_visible or b77_contain or b77_dense" -v` **plus the full** `tests/test_tui_directionb.py` and `tests/test_map_click_chain.py` (C-34 + census)
- **Numeric pass threshold:** per size arm — `invisible_regions == 0` (today **0** @80×24, **2** @120×30); `strict` inequality exists (today **False** @80×24, **True** @120×30); every segment `bar.region.contains_region(seg.region)` (today **0** outside @80×24, **4** outside @120×30); gap marker widths all equal (today `[7,7,15,30]`)
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** at both terminal sizes the operator sees all five regions, wider for bigger, with gaps reduced to fixed marks.
  - **Shipped surface:** `App.run_test(size=…)` → `action_show_screen("map")` → `update_memory_map()` → `app.query(".map-band-seg")`, geometry read against `app.query_one(".map-band-bar").region`
  - **Deliverable + observation:** `visible_cols(seg)` per segment, clipped to the container. **Completeness guard (C-31):** before evaluating any universal, assert `{s.region_start for s in query(BandSegment)} == {start for start,_ in loaded.ranges}` — otherwise a fold that *drops* a region shrinks the quantified set and monotonicity passes over the survivors. The set comes from the fixture's ranges, never from what the renderer emitted.
  - **Acceptance test(s):** **`AT-B77-01`** — the three-way conjunction (`visible≥1` ∧ `monotone` ∧ `strict`), parametrized over both sizes · **`AT-B77-02`** — gap-folding is a strict no-op on a gapless image at fixed container width (R2) · **`AT-B77-03`** — every segment is contained in the container
  - **Boundary catalog (QC-3):** ☑ **empty** — no ranges → zero segments, no raise (`:1900-1914`), `TC-B77-01` · ☑ **boundary** — the **21-column** regime, which is where the batch breaks, covered by every arm · ☑ **boundary** — single run (no orderable pair; the AT **skips the strict limb explicitly at `n<2`** rather than passing it silently), `TC-B77-02` · ☑ **boundary** — more runs than container columns, `TC-B77-03` · ☑ **invalid** — a zero-byte run, `TC-B77-04` · ☑ **error** — `total_span <= 0`, already guarded at `:1900`, `TC-B77-05`

> ⚠️ **N-1, the reason this is one conjunction and not three tests.** Executed per arm:
> ```
> 80×24 : visible>=1 = True    monotone = True   strict = False   -> conjunction RED
> 120×30: visible>=1 = False   monotone = True   strict = True    -> conjunction RED
> ```
> **The two regimes redden on different limbs.** Splitting the conjunction across nodes, or dropping
> either limb, ships one regime GREEN. The `monotone` limb is GREEN at both sizes today and is
> **vacuous on its own** — it carries no falsifying power and must never be the gate alone.
> This corrects `01b-qa-validation.md` §3.1, which records strict as "RED at both": that is true on
> *content* widths (all `1`) and false on *painted* widths, because at 120×30 two runs clip to `0`
> and `1 > 0` satisfies strictness.

---

### HLR-112 — every ruler label names a mapped address
- **Traceability:** US-77-2 · **Ruling:** R4
- **Statement:** When the Memory Map renders, the address ruler **shall** emit one tick label per mapped region start plus one label for the **last mapped byte**; **shall not** emit a label naming an address outside every mapped range; **shall** emit strictly ascending, non-duplicate labels; and **shall** collapse labels that would occupy overlapping columns, retaining the first and last labels in preference to any interior label.
- **Rationale (informative):** Measured: **4 of 5** ticks name unmapped addresses. `span_end = 0x07FFFF3E` is **exclusive** and unmapped; `0x07FFFF3D` is the last mapped byte and is mapped (frozen-oracle verified). R4 resolves the charter's contradiction — "every label mapped" ∧ "a span-end label" is unsatisfiable while `span_end` is exclusive. Amends `R-TUI-072` **and** `LLR-072.3` (§6.5 A + B).
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py::test_at072b_ruler -v` (re-derived) + `-k b77_ruler`
- **Numeric pass threshold:** **0** labels outside every mapped range (today **4**); `len(ticks) == len(set(ticks))`; labels strictly ascending as integers; `≥2` labels always retained
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** every address printed under the strip is one the operator can actually go to.
  - **Shipped surface:** as HLR-111, reading `app.query(".map-ruler-tick")`
  - **Deliverable + observation:** tick label set. Membership tested via the **frozen** `range_index` oracle — `address_in_sorted_ranges(addr, index)` (note the argument order; `s19_app/range_index.py:39`), already imported at `tests/test_tui_map_big.py:22-25`. An oracle outside the code under test.
  - **Acceptance test(s):** **`AT-072b` (re-derived, keeps its global id)** — `{ticks} ⊆ ADMISSIBLE` ∧ strictly ascending ∧ no duplicates, where `ADMISSIBLE = {f"{s:08X}" for s,_ in loaded.ranges} ∪ {f"{span_end-1:08X}"}` · **`AT-B77-04`** — the `⊇` lower bound: `{ticks} ⊇ {first region start, last mapped byte}`
  - **⚠️ Why `AT-B77-04` is not optional:** executed — `set() <= admissible` is **`True`**. A subset-only predicate is GREEN on a ruler that rendered **zero** ticks. The lower bound is what makes the pair a gate.
  - **Boundary catalog (QC-3):** ☑ **empty** — no ranges → no ruler, `TC-B77-06` · ☑ **boundary** — one region (first start and last mapped byte are its own bounds), `TC-B77-07` · ☑ **boundary** — more regions than ruler columns → collapse, `TC-B77-08` · ☑ **invalid** — two starts rendering to the same column, `TC-B77-09` · ☐ **error** — **N/A:** ticks derive from already-validated `ranges`; no new input class (LLR-041.7).

---

### HLR-113 — the stats strip states mapped-vs-span with a discriminating percentage
- **Traceability:** US-77-3
- **Statement:** When the Memory Map renders a loaded image, `#map_stats_body` **shall** present the mapped total and the image span as humanized sizes in one dual readout, **shall** render the coverage percentage at a precision yielding a non-zero value for a ratio of 1 in 130 000, and **shall** present the largest gap as a humanized size.
- **Rationale (informative):** Executed today: `'Coverage: 0.00%  Bytes covered: 1030\nValid ranges: 5  Invalid ranges: 0\nGaps: 4  Largest gap: 67108408 bytes\nTotal issues: 0'`. True coverage `0.000767 %`, flattened by `f"{…:.2f}%"` (`:2304`). Pure re-formatting of an existing `CoverageStats` (`:966-986`) — **LLR-041.7 preserved by construction**.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_directionb.py -k "map_stats or b77_stats" -v`
- **Numeric pass threshold:** rendered percentage `0.0008%` not `0.00%`; largest gap `64.0 MiB` not `67108408 bytes`; readout contains both `1.0 KiB` and `128.0 MiB`
- **Priority:** medium
- **Acceptance (black-box):**
  - **Shipped surface:** `app.query_one("#map_stats_body").render()` — ⚠️ the **`_body`**, never `#map_stats` (a container; renders `Blank`).
  - **Expected strings are COMPUTED, not guessed (C-42):** the test writes `human_bytes(1030)` and `human_bytes(span_end - span_start)` from the fixture and asserts those exact substrings — never a hand-typed `"1.0 KiB"`.
  - **Acceptance test(s):** **`AT-B77-05`** — dual readout present ∧ percentage ≠ `0.00%` ∧ humanized gap present ∧ **`"Largest gap: 67108408 bytes"` absent** ∧ **`"Coverage: 0.00%"` absent**
  - **⚠️ C-40:** both absence clauses are GREEN on an empty strip. Each is paired with its presence clause in the same node; absence alone is a pin.
  - **Boundary catalog (QC-3):** ☑ **empty** — no file → neutral strip, no divide-by-zero, **`TC-B77-10`** (this **re-derives `test_tc041_9`**, see below) · ☑ **boundary** — 100 % coverage single range, assert `human_bytes(0)` for the gap, not the literal `"0 B"`, `TC-B77-11` · ☑ **boundary** — 1-byte image, no `ZeroDivisionError`, `TC-B77-12` · ☑ **invalid** — `image_span == 0`, the single div-by-zero guard (`:980-981`), `TC-B77-13` · ☐ **error** — **N/A:** every field is a pre-computed `CoverageStats` scalar.

> ⚠️ **`test_tc041_9_empty_state_stats_neutral_no_exception` (`tests/test_tui_directionb.py:3674`) goes VACUOUS.**
> Its runtime clause is `assert "Coverage:" not in strip`. Once `build_stats_text` stops emitting the word
> "Coverage:" anywhere, that assertion can never fail — it passes on correct code, broken code, and no code.
> **`TC-B77-10` re-derives it** to assert the new neutral form **positively** and the new mapped/span tokens
> absent. Leaving it is how a vacuous check lands on `main`.

---

### HLR-114 — the legend block is not resident in the map body
- **Traceability:** US-77-4
- **Statement:** When the Memory Map renders, `#map_grid` **shall not** contain any `.map-legend-row` or `.map-band-legend` widget, and the application's legend screen **shall** remain reachable and render the same band-label set as before this batch.
- **Rationale (informative):** Measured: **4** `.map-legend-row` in **1** `.map-band-legend` container, always on, inside a pane 14 rows tall. **The story deliberately claims nothing about a footer hint:** executed, `k → Legend` is **already** one of the map screen's **14** `show=True` footer chips, so a "a hint points to `k`" clause would be GREEN pre-change — vacuous, C-40 limb 1 (QA B-4). The falsifiable content is the **removal**.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_directionb.py -k "legend or b77_legend" -v` + the full file (C-34)
- **Numeric pass threshold:** `len(query(".map-legend-row")) == 0` **and** `len(query(".map-band-legend")) == 0` (today **4** and **1**); the legend screen's own body still lists every label in `ENTROPY_BAND_LABELS`
- **Priority:** medium
- **Acceptance (black-box):**
  - **Acceptance test(s):** **`AT-B77-06`** — both queries empty **while `len(query(".map-band-seg")) >= 5`** · **`AT-B77-07`** *(PIN)* — `pilot.press("k")` still pushes the legend screen and its body lists every band label
  - **⚠️ C-40:** the absence is trivially green on a screen that rendered nothing; the non-empty segment co-assertion is what makes `AT-B77-06` a gate.
  - **⚠️ C-31:** the legend screen's label completeness is derived from **`ENTROPY_BAND_LABELS`**, not hand-listed as `("constant/padding","low","medium","high/random")` — which is what the live `test_at075` does today and is a hand-listed domain.
  - **Boundary catalog (QC-3):** ☑ **empty** — no file → still zero legend rows, and the AT must not count that as a pass (the co-assertion guards it), `TC-B77-14` · ☑ **boundary** — legend opened from the map and dismissed; the map still renders, `TC-B77-15` · ☐ **invalid** / ☐ **error** — **N/A:** removing a static widget set admits no new input.

> **Blast radius:** `test_at075_e_key_opens_no_modal_map_has_legend` (`tests/test_tui_directionb.py:4574`) asserts all four band names appear in `query(".map-legend-row")` → **RED by design**. Its *first* purpose — "pressing `e` opens no modal" — is unrelated: **port that clause, never delete the node wholesale.**

---

### HLR-115 — region rows are reachable and actionable with arrows and Enter
- **Traceability:** US-77-5 · **Ruling:** R3
- **Statement:** While the Memory Map is active with an image loaded and a region row has focus, `↑` and `↓` **shall** move focus to the previous and next region row in ascending address order, `Enter` **shall** populate the inspector for the focused region, and the application **shall** continue to route `j`, `k` and `o` to their pre-existing application actions unchanged.
- **Rationale (informative):** Measured: **0 of 5** rows focusable; `RegionRow.BINDINGS == []`; `screens_directionb.py` defines no `BINDINGS` at all. R3 binds **only** arrows and `Enter` on the row, so `j`/`k`/`o` are never shadowed: `k` keeps opening the legend (which HLR-114 relies on), and `o`/`j` stay in `_PRE_BATCH_BINDINGS` (`tests/test_tui_directionb.py:5460-5478`) under live `TC-011` — **verified: R3 touches neither, so TC-011 stays green and no supersession is owed.**
- **⚠️ Scope reduction, stated not hidden:** the charter's **`o` = open-hex keyboard affordance is DESCOPED** (R3). Reason: `o` is a frozen pre-batch binding and a row-scoped `o` would shadow it whenever a row is focused, which is the default state once rows are focusable. **Hex remains reachable by the unchanged N4a mouse double-click.** Registered as carry **C-77-f**.
- **⚠️ C-16:** Textual performs no spatial arrow-focus by default. `assumed — verify in target framework at Phase 3`. **Every arm presses real keys via `pilot.press`; none may call `.focus()`** — batch-27 shipped exactly that gap green.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_map_big.py -k b77_keyboard -v` + full `tests/test_tui_directionb.py` (C-34, hosts TC-011) + full `tests/test_map_click_chain.py`
- **Numeric pass threshold:** `sum(r.can_focus for r in query(RegionRow)) == 5` (today **0**); after `press("down")` the focused row's `region_start` is the next in address order; after `press("enter")` `#map_detail_body` contains that region's `0x%08X` start; with focus off the region list, `k` pushes the legend screen, `j` invokes `dump_a2l_json`, `o` invokes `open_workarea`
- **Priority:** high
- **Acceptance (black-box):**
  - **Acceptance test(s):** **`AT-B77-08`** — real keys: entry → `↑`/`↓` move in address order → `Enter` populates the inspector for the **focused** row (assert the address, not merely "changed") · **`AT-B77-09`** *(the discriminating negative)* — with focus **not** on a region row, `k`/`j`/`o` still perform their App actions and none moves the map selection · **`AT-B77-10`** *(PIN)* — N4a preserved: single click ⇒ inspector populated **and zero** `OpenInHexRequested`; double ⇒ **exactly one**
  - **⚠️ Check before minting `AT-B77-10`:** `tests/test_map_click_chain.py` already covers the N4a split. **Reuse the existing node if it suffices** — C-18 asks for one node per AT, not a new file.
  - **Boundary catalog (QC-3):** ☑ **boundary** — `↑` on the first row and `↓` on the last: focus **unchanged**, no wrap, no crash (stated in `LLR-115.2`), `TC-B77-16` · ☑ **empty** — no file → no focusable rows and every key inert rather than raising, `TC-B77-17` · ☑ **boundary** — exactly one region (`↑`/`↓` are no-ops), `TC-B77-18` · ☑ **invalid** — `Enter` on a row whose region was invalidated by a re-render, `TC-B77-19` · ☑ **error** — `Enter` with no focused row posts nothing and raises nothing, `TC-B77-20`
  - **⚠️ C-28 / snapshot:** **add no App-level `Binding(..., show=True)`.** The map footer already renders **14** chips in **78** columns @80×24; a 15th risks *silently truncating* an existing chip, and any `show=True` addition drifts **all 29** snapshot cells instead of 2. Discoverability is served by the existing `?` help panel, which lists every active binding.

---

### HLR-116 — a region is focused and inspected without operator input
- **Traceability:** US-77-6 · **absorbs the focus-entry mechanism (QA B-6)**
- **Statement:** When the Memory Map completes a render for a loaded image with at least one region, the panel **shall** make the region rows focusable, **shall** populate `#map_detail_body` with the selected region's detail, and **shall not** post `MemoryMapPanel.OpenInHexRequested` as a consequence; the selected region **shall** be the previously selected region when that region is still present in the newly rendered set, and the first region otherwise; and focus **shall** follow the selected region.
- **Rationale (informative):** Measured with a file loaded: `#map_detail_body = 'Click a region to inspect it - double-click to open in hex.'` (`_DETAIL_HINT`, `:1723`), written unconditionally by `_reset_detail()` at `:1896`. Executed: `down`×3 and `tab` never leave `RailItem` — **`can_focus = True` alone gives the operator no way in**, so this story owns the entry path and **HLR-115's keyboard acceptance is unreachable without it** (§7 ordering). "Never navigate" is the hazard clause: auto-selection must inspect only. **Focus follows selection (R-6):** if selection were preserved across a re-render while focus reset to the rail, the operator's arrow keys would resume from somewhere else and the keyboard story would silently regress — so the two must move together and the coupling must be observable.
- **Validation:** `test` · **Executed verification:** `pytest tests/test_tui_map_big.py -k b77_autoselect -v` + full `tests/test_tui_directionb.py`
- **Numeric pass threshold:** fresh render — `#map_detail_body != _DETAIL_HINT` and contains the first region's `0x%08X` start; **exactly 0** `OpenInHexRequested` across the render; re-render with the region present — `#map_detail_body` still contains the **previously selected** region's start and `app.focused.region_start` equals it; re-render with the region absent — `#map_detail_body` contains the **new first** region's start and `app.focused.region_start` equals it
- **Priority:** high
- **Acceptance (black-box) — three nodes, because one claim per node (C-18):**
  - **`AT-B77-11`** *(fresh render)* — with no click, no key press and no test-posted message, the inspector names region 1 **and** exactly zero `OpenInHexRequested` are observed.
  - **`AT-B77-13`** *(re-render, region PRESENT → preserved)* — select a **non-first** region through the shipped surface, re-render the same image; the inspector still names **that** region and `app.focused` is the row whose `region_start` equals it.
  - **`AT-B77-14`** *(re-render, region ABSENT → fallback)* — select a region, then render an image whose ranges do **not** contain that address; the inspector names the **new first** region and `app.focused` is that row.
  - **⚠️ Why this is two nodes and not one (R-6).** Each covers a distinct failure mode and **neither alone can distinguish the specced behaviour**:

    | Arm | Reddening mutation (substituted VALUE) | Effect on `AT-B77-13` | Effect on `AT-B77-14` |
    |---|---|---|---|
    | preserve | re-render resolution → `selected = ordered[0]` (always reset) | **RED** | GREEN |
    | fallback | re-render resolution → `selected = self._selected_cell_start` unconditionally (never re-resolve, keep the stale address) | GREEN | **RED** |

    **Each mutation reddens exactly one arm and leaves the other green** — which is precisely why a single arm is not a gate. A preserve-only node is green on an implementation that never re-selects; a fallback-only node is green on one that always resets.
  - **⚠️ C-40:** on `AT-B77-11`, "zero messages" is green on a render that never happened; the inspector-populated clause is co-asserted in the same node. On `AT-B77-13`/`14`, the **precondition must be verified before the re-render** — assert the selection actually took (`#map_detail_body` names the target) rather than assuming the setup gesture landed. *(This is not hypothetical: my first probe's `pilot.click` did not land and reported `_selected_cell_start = None`; the arms still measured RED, but for the wrong reason. Re-run with `scroll_visible` + click, verified precondition, in §6.3 F-1(e).)*
  - **Executed pre-change verdicts — both new arms RED, with a verified precondition:**
    ```
    target (non-first) region        = 0x02000000
    after selection: detail names it = True      _selected_cell_start = 0x2000000
    ARM A (region PRESENT after re-render): _selected_cell_start = None
        detail still names target = False   detail reverted to hint = True
        focus = ScrollableContainer (region_start None)      -> AT-B77-13 RED
    ARM B (region ABSENT after re-render):  _selected_cell_start = None
        detail names new first 0x10000000 = False   detail reverted to hint = True
                                                             -> AT-B77-14 RED
    ```
    Both are RED for the same structural reason: `_reset_detail()` runs unconditionally at `:1896` on **every** render and clears `_selected_cell_start` at `:2329`. **No preservation exists today in either direction.**
  - **Boundary catalog (QC-3):** ☑ **empty** — **no file → the hint is retained and no region is selected** (auto-select must not fabricate one); `test_tc025` guards the `EmptyStatePanel`, `TC-B77-21` · ☑ **boundary** — exactly one region, `TC-B77-22` · ☑ **boundary** — **file switch to a disjoint image** is the `AT-B77-14` fallback path; ⚠️ `_selected_cell_start` (`:1768`) survives across renders and `_reset_detail` (`:2329`) clears it, so the resolution must run **after** the reset, `TC-B77-23` · ☑ **invalid** — a zero-byte region, `TC-B77-24` · ☑ **boundary** — the previously selected region is present but is **no longer first** after a re-merge (runs can merge differently), so preservation must match by **address**, not index, `TC-B77-29` · ☐ **error** — **N/A:** reuses `build_detail_text`, already C-17-hardened (`REQUIREMENTS.md:4840-4846`).

---

### HLR-117 — the selected region row is visually distinguishable
- **Traceability:** US-77-7
- **Statement:** While a region is selected, the corresponding region row **shall** render a resolved style differing from that of every unselected region row, exactly one region row **shall** carry the selection marker, and the row's entropy band styling **shall** remain unchanged by selection.
- **Rationale (informative):** Measured: `row_classes` carry the base class plus the band token and nothing else; the panel already tracks `_selected_cell_start` (`:1768`/`:2463`/`:2329`) and simply never renders it. Style-only motion. The band's colour and glyph are the entropy channel and the colour-blind cue (C-10) — a selection style that repaints them destroys the information the row exists to carry.
- **Validation:** `test` + `inspection`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k b77_selection -v`; plus `grep` of the selection rule in `styles.tcss`
- **Numeric pass threshold:** exactly **1** row carries the marker (today **0**); the selected row's resolved triple differs from every unselected row's; `set(classes) - {marker}` identical before and after selection
- **Priority:** medium
- **Acceptance (black-box):**
  - **Deliverable + observation — which layer holds the fact (P-42, executed):** `widget.styles.(background, color, text_style)` — the **resolved CSS**. `RegionRow.render().spans` is **`[]`** on these rows (measured), so **C-37's span route is inapplicable here**, and `render_line` returns the base theme colour. Measured baseline: `background` is `Color(0,0,0,a=0)` on **every** row and `color` **already differs per band** — so the predicate must compare the **triple**, **selected vs unselected**, and never against a hex literal.
  - **Acceptance test(s):** **`AT-B77-12`** — the selected row's triple differs from every unselected row's ∧ exactly one marker ∧ the band token is unchanged by selection · a companion **`inspection`** arm that the `styles.tcss` rule exists and sets no `color:` property
  - **Written mechanism-agnostically on purpose:** asserting only `"…-selected" in row.classes` certifies a *class*, not *distinguishability*. The triple certifies the outcome whichever property the implementer reaches for.
  - **Boundary catalog (QC-3):** ☑ **boundary** — **the fixture must have ≥2 regions and the test body must assert `len(rows) >= 2`**: with one region, "differs from every unselected row" is **vacuously true**, `TC-B77-25` · ☑ **empty** — no rows → no marker anywhere, `TC-B77-26` · ☑ **boundary** — re-render while selected: the marker lands on the row for the same **address**, not the same index, `TC-B77-27` · ☑ **invalid** — the selected address no longer exists after a file switch → **no** row carries it (not row 0 by accident), `TC-B77-28` · ☐ **error** — **N/A:** style-only.

---

## 4. Low-level requirements (LLR)

### HLR-111 → LLR-111.x

**LLR-111.1 — the width basis is the measured container (R1)**
- **Traceability:** HLR-111 · **Statement:** `_build_band_widgets` **shall** derive segment widths from the rendered width of the `.map-band-bar` container obtained at render time, and **shall not** derive any segment width from `_BAND_BAR_WIDTH`.
- **Symbols:** `_build_band_widgets` `screens_directionb.py:1988`; the expressions to replace `:2058` (gap) and `:2066` (run); `_BAND_BAR_WIDTH = 60` `:230` (**retired as a width basis**; the constant itself may remain as a fallback for the pre-layout case — see OQ-3).
- **Geometry:** container width **measured**, 66 @80×24 / 21 @120×30 (P-31) — but the implementation must not hard-code either — it reads the live value (the normative form is in `LLR-111.1`'s Statement).
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_map_big.py -k b77_width -v` · **Numeric pass threshold:** `AT-B77-01` GREEN on both arms
- **Acceptance criteria:** ⚠️ **the container width is not available before first layout.** The widths must be computed where the container's region is known (a post-mount refresh or an `on_resize`/`on_mount` recompute), **not** in `compose`. `assumed — verify the recompute hook in Phase 3.`

**LLR-111.2 — gaps fold to a ONE-COLUMN marker (R-5)**
- **Traceability:** HLR-111 · **Statement:** Each unmapped gap **shall** render at exactly one column, independent of its byte size and of the container width, and **shall** remain a plain `Static` classed `map-band-seg map-band-gap` — never a `RegionRow`, never a `BandSegment`.
- **Symbols:** `:2056-2065`; `_MAP_GAP_HATCH = "╱"` `:253`; `RegionRow` `:1088`; `BandSegment` `:1172`. Fold-width constant **NEW — created in Phase 3**, value **1**.
- **Rationale for the value (informative, measured — R-5):** executed feasibility over the real containers:
  ```
  bar= 66 fold=1 avail= 62 -> run widths=[15,15,15,12,4] total=65 fits mono strict allvisible
  bar= 66 fold=2 avail= 58 -> run widths=[14,14,14,11,3] total=64 fits mono strict allvisible
  bar= 21 fold=1 avail= 17 -> run widths=[ 4, 4, 4, 3,1] total=20 fits mono strict allvisible
  bar= 21 fold=2 avail= 13 -> run widths=[ 3, 3, 3, 3,1] total=21 fits mono strict allvisible
  ```
  At the 21-column regime `fold=2` collapses **three runs to equal width** (`[3,3,3,3,1]`), leaving the 62 B run as the sole discriminating pair. That guts the **strict** limb — the load-bearing half of `AT-B77-01` at 80×24 per N-1. **`fold=1` preserves width discrimination at every container size**, which is why it is uniform rather than threshold-driven.
- **⚠️ Scope reduction, stated not hidden (R-5):** the charter's **"2-column marker + humanized size label at/above a fold threshold"** (`prototypes/memmap_variant_a.HANDOFF.md` §2, S-1) is **DESCOPED**. A uniform 1-column marker carries no size label. Registered as carry **C-77-g** — same treatment as C-77-f.
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_map_click_chain.py -k "blast_radius or gap_hatch" -v` · **Numeric pass threshold:** every gap marker is exactly **1** column despite spans of `16776960/16776960/33554176/67108408 B` (today `[7,7,15,30]`)
- **Acceptance criteria:** the existing `test_ac6_gap_hatch_segments_are_not_clickable` and `test_ac6_band_segments_do_not_widen_region_row_queries` stay green **unmodified** — they are the standing guards for the fold marker's inertness and its non-`RegionRow`-ness. **Labelled PIN, not gate** (invariant by design).

**LLR-111.3 — no segment paints outside its container**
- **Traceability:** HLR-111 · **Statement:** Every `.map-band-seg` **shall** satisfy `bar.region.contains_region(seg.region)`.
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_map_big.py -k b77_contain -v` · **Numeric pass threshold:** outside count **0** at both regimes (today **0** @80×24, **4** @120×30)
- **Acceptance criteria:** ⚠️ **this predicate is what retires the PIN test** — see §6.5 Amendment C.

**LLR-111.4 — the gapless no-op control (R2)**
- **Traceability:** HLR-111 · **Statement:** For a gapless image rendered at a fixed container width, the concatenated `.map-band-seg` classes and content **shall** equal a golden captured from the shipped producer after the width basis is settled.
- **Symbols:** golden fixture **NEW — created in Phase 3**, captured in **Inc-1b, its own commit, after Inc-1a settles the width basis and before any gap-fold edit**.
- **Fixture — MUST be unequal (QA B-5, executed):** `EQUAL 512/512 → content [30,30]` at both regimes, **invariant under any monotone re-weighting** → vacuous. **`UNEQUAL 768/256 → [45,15]`**, which moves. Measured payload @80×24, container 66:
  ```
  ('band-constant','map-band-seg')  len= 45  '·············································'
  ('band-medium',  'map-band-seg')  len= 15  '▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒'
  ```
  ⚠️ Golden payload is `(sorted(classes), text)` per segment — **classes included** so a band-token regression (`band-medium`→`band-low`) reddens it.
- **⚠️ Capture at a FIXED container width.** Executed: the same unequal fixture at 120×30 renders `content=[45,15] visible=[21,0]` — the second run is **invisible today even with no gaps** (P-37). The control is a **content** comparison at a pinned width, not a visibility one.
- **Validation:** `test (integration)` · **Numeric pass threshold:** exact equality
- **Acceptance criteria:** **`AT-B77-02` is a PIN, and its falsifiability is discharged the other way:** after Inc-2 lands, substitute the fold denominator into the gapless path (a one-token change, record the **substituted VALUE**) and confirm it goes RED. **A golden never mutation-tested is a file, not a control** — that mutation must be executed and its transcript pasted at the Inc-2 gate.
- **⚠️ C-42 encoding:** the payload contains `·`, `▒`, `╱`. Compare against the widget's runtime `render()` text — **never** snapshot-export bytes (`&#160;`) and never via a raw console `print` (my own probe died on `UnicodeEncodeError` under cp1252, §6.3 F-1). If stored on disk it needs `-text` in `.gitattributes`.

**LLR-111.5 — C-40 register for HLR-111**
- **Traceability:** HLR-111 · **Statement:** Every acceptance-bearing predicate of HLR-111 **shall** carry a recorded mutation naming the **substituted value**.

| Predicate | Declared subject in the expression? | Mutation (substituted VALUE) | Verdict |
|---|---|---|---|
| `AT-B77-01` conjunction | ✅ `visible_cols` is `BandSegment.region` clipped to `bar.region`; `run_bytes` also appears | restore the divisor: container width → `total_span`, and the numerator → `_BAND_BAR_WIDTH` | ✅ **GATE** — RED at both arms today, on *different* limbs |
| `AT-B77-02` gapless golden | ✅ classes + text of every segment | substitute the fold denominator into the gapless path | ⚠️ **PIN pre-fix; gate via the post-Inc-2 mutation** |
| `AT-B77-03` containment | ✅ `seg.region`, `bar.region` | restore `_BAND_BAR_WIDTH` as the basis | ✅ **GATE** — 4 outside @120×30 today |
| ~~`Σ content ≤ _BAND_BAR_WIDTH`~~ | ❌ certifies a **constant**, not the operator's view; satisfiable at 60 while 2 of 5 regions stay invisible | — | ❌ **REJECTED by R1** — recorded so it is not reintroduced as a "simplification" |
| ~~`monotone` alone~~ | ❌ GREEN at both regimes today | none exists | ❌ **VACUOUS LIMB — never the gate alone** |

**LLR-111.6 — geometry is read from a settled layout (N-2)**
- **Traceability:** HLR-111 · **Statement:** Every test that reads a rendered region **shall** settle the layout to a fixed point before measuring.
- **Rationale (informative):** Executed — at 80×24 the bar reads **68** on roughly 1 run in 5 at a single `pilot.pause()` and **66** thereafter; traced live as `68 → 68 → 66`. My own first consolidated probe read `23/50` at 120×30 where the settled value is `21`. Ruled out as a cause: reading `app.active_bindings` (`21→21→21`, `66→66→66`).
- **Validation:** `test (integration)` + `inspection` · **Numeric pass threshold:** the helper returns only when two consecutive reads of `bar.region.width` agree; ≥15 consecutive runs report the same width per regime
- **Acceptance criteria:** a shared `_settled_bar(app, pilot)` helper; **no geometry AT calls `pilot.pause()` exactly once**. Without this every HLR-111 arm is intermittently flaky, and a flaky gate is indistinguishable from a broken one.

### HLR-112 → LLR-112.x

**LLR-112.1 — ticks derive from run starts plus the last mapped byte (R4)**
- **Traceability:** HLR-112 · **Statement:** `MapRuler` **shall** accept the ordered run start addresses and the last mapped byte, and **shall** emit one `.map-ruler-tick` per retained address, replacing the fixed `_TICK_COUNT = 5` percentile derivation.
- **Symbols:** `MapRuler` `:1234`; `_TICK_COUNT = 5` `:1274`; `compose` `:1293`; construction site `:2102` — `MapRuler(span_start, span_end)`, **signature changes**.
- **Validation:** `test (integration)` · **Numeric pass threshold:** 0 labels outside every mapped range (today 4 of 5); `END_LABEL == f"{span_end-1:08X}"` — executed: `0x07FFFF3D`, mapped **True**, vs `span_end 0x07FFFF3E`, mapped **False**

**LLR-112.2 — overlapping labels collapse; ordering is the surviving invariant**
- **Traceability:** HLR-112 · **Statement:** When two retained labels would occupy overlapping columns, the ruler **shall** drop one, **shall** retain the first and last labels in preference to any interior label, and **shall** emit labels that are strictly ascending as integers with no duplicates.
- **Rationale (informative):** Strict ascent is what "5 evenly-spaced ticks" was really protecting; it survives collapse and is falsifiable, whereas `len(ticks) == 5` would go **red on the correct new behaviour** and **green on a broken collapse that happened to emit 5**.
- **Geometry:** `assumed — measure in Phase 3` at the **21-column** bar / **50-column** grid regime. ⚠️ The `0x`-prefix-drop fallback is **already spent** (`:1245-1247`, C-13.1) and cannot be spent again.
- **Validation:** `test (integration)` + `analysis` · **Numeric pass threshold:** 0 overlapping column ranges at both regimes; ≥2 labels retained

**LLR-112.3 — the 5-tick contract is amended at all six citation sites**
- **Traceability:** HLR-112 · **Statement:** The batch **shall** record Before/After amendments for `R-TUI-072` and `LLR-072.3` and **shall** update every surviving citation of the retired clause.
- **Symbols — executed census, six sites:** `screens_directionb.py:1239`, `:1273`, `:1300`, `:2002`; `tests/test_tui_map_big.py:118`; `tests/test_tui_snapshot.py:670`. Plus `REQUIREMENTS.md:4787-4793` and the duplicate clause at `:4190-4191`.
- **Validation:** `inspection` · **Executed verification:** `grep -rn 'LLR-072\.3\|exactly 5 tick\|_TICK_COUNT' s19_app tests REQUIREMENTS.md` · **Numeric pass threshold:** 0 surviving assertions of "exactly 5 ticks"; 6 sites reconciled
- **Acceptance criteria:** ⚠️ **the `LLR-072.3` citation is NOT dangling** — the id is defined at `.dev-flow/2026-07-15-batch-47/01-requirements.md:508`. The edit corrects the *clause*, not a broken reference. The Phase-0 "dangling citation" carry is **void**.

### HLR-113 → LLR-113.x

**LLR-113.1 — dual readout** · **Traceability:** HLR-113 · **Statement:** `build_stats_text` **shall** compose the mapped total and image span through `insight_style.human_bytes` and **shall** render the coverage percentage with at least four fractional digits. **Symbols:** `build_stats_text:2275`; the `Coverage` f-string `:2304`; `human_bytes` `insight_style.py:124`; `CoverageStats` `:966`. **Validation:** `test (unit)` · **Threshold:** contains `1.0 KiB`, `128.0 MiB`, `0.0008%` — all three executed. **Acceptance:** no new arithmetic over `ranges`; every input is an existing `CoverageStats` field (LLR-041.7 preserved).

**LLR-113.2 — humanized largest gap** · **Traceability:** HLR-113 · **Statement:** The largest-gap statistic **shall** render through `human_bytes`. **Symbols:** `:2309`. **Threshold:** renders `64.0 MiB`; `67108408` absent. **Acceptance:** ⚠️ **C-40** — the absence half is green on an empty strip and must be paired with the presence half in the same node.

### HLR-114 → LLR-114.x

**LLR-114.1 — the legend leaves the builder** · **Statement:** `_build_band_widgets` **shall not** construct or return a `.map-band-legend` container. **Symbols:** legend loop `:2084-2092`; return list `:2100-2105`; CSS `styles.tcss:849`, `:856`. **Threshold:** both queries 0 (today 4 and 1) while `.map-band-seg` ≥5. **Acceptance:** ⚠️ **C-38** — `.map-legend-row` may also class the legend screen's rows; **scope the query to `#map_grid`** or the assertion falsely reddens when that screen is open. `assumed — verify the legend screen's row classes in Phase 3.`

**LLR-114.2 — the legend screen is untouched** · **Statement:** The `k` binding and `action_show_legend` **shall** remain unmodified. **Symbols:** `app.py:1359`, `action_show_legend` `app.py:5867`. **Validation:** `inspection` + `test` · **Threshold:** 0 diff lines in `app.py:1345-1375`; `AT-B77-07` green.

### HLR-115 → LLR-115.x

**LLR-115.1 — rows become focusable** · **Statement:** `RegionRow` **shall** be declared focusable. **Symbols:** `RegionRow` `:1088`; `can_focus` **NEW — created in Phase 3** (executed: 0 hits for `can_focus` in the module). **⚠️ Textual internal-name shadowing:** every new member **shall** be checked against `dir(Widget)` — a `_nodes`/`_context` collision is a silent mount crash with no traceback; `MapRuler` documents the discipline at `:1249-1250`. **Threshold:** `sum(r.can_focus …) == 5` (today 0).

**LLR-115.2 — arrow movement with stated edges** · **Statement:** While a region row has focus, `↑` **shall** move focus to the previous row and `↓` to the next in ascending address order; at the first row `↑` **shall** leave focus unchanged and at the last row `↓` **shall** leave focus unchanged. **⚠️ C-16:** `assumed — verify in target framework at Phase 3`; if the default traversal does not match address order an explicit handler is required. **Acceptance:** **`pilot.press` only — a test that calls `.focus()` does not discharge this LLR.**

**LLR-115.3 — `Enter` inspects via the single click-policy site** · **Statement:** `Enter` **shall** cause the focused row to post `RegionRow.Activated` with `chain = 1`. **Symbols:** `Activated` `:1123`, `chain` `:1141-1147` (defaults to 1 = inspect); `on_region_row_activated` `:2422`, chain gate `:2461-2471`. **Rationale (informative):** routing through the existing message keeps the single/double policy in exactly one place (`:1164-1165`) so the keyboard cannot drift from the mouse. **Threshold:** `Enter` → 0 `OpenInHexRequested`, inspector populated.

**LLR-115.4 — no application binding is shadowed (R3)** · **Statement:** `RegionRow.BINDINGS` **shall not** bind `j`, `k` or `o`. **Symbols:** `app.py:1352/1356/1359`; `_PRE_BATCH_BINDINGS` `tests/test_tui_directionb.py:5460-5478`; `test_tc011_…` `:5578`. **Validation:** `test (e2e)` + `inspection` · **Threshold:** the literals `"j"`, `"k"`, `"o"` appear **0 times** in `RegionRow.BINDINGS`; `AT-B77-09` green; **TC-011 green and unmodified**. **Acceptance:** this LLR is the discharge of R3 — and the reason no supersession record is owed for TC-011.

### HLR-116 → LLR-116.x

**LLR-116.1 — focus entry** · **Statement:** On completing a render with ≥1 region, the panel **shall** establish a focus path to the region rows without operator input. **Rationale (informative):** executed — `down`×3 and `tab` never leave `RailItem`; `can_focus` alone is not an entry path. **Threshold:** `isinstance(app.focused, RegionRow)` after render, **or** a documented single keystroke reaches one; the chosen mechanism is named at Phase 3.
- ⚠️ **Do not make the rows part of the global `tab` chain without checking the rail.** Widening the tab order changes focus behaviour on every screen that shares the chain. `assumed — verify in Phase 3.`

**LLR-116.2 — auto-select after reset** · **Statement:** `render_ranges` **shall** select the first ordered region **after** `_reset_detail()` and after the rows are mounted. **Symbols:** `render_ranges:1808`; `_reset_detail()` call `:1896`, body `:2313-2330` (clears `_selected_cell_start` at `:2329`); `_ordered_ranges` `:1923`; mount `:1927-1929`. **Rationale (informative):** ordering matters — selecting before the reset would be erased; this is also the file-switch correctness point.

**LLR-116.3 — auto-selection never navigates** · **Statement:** Auto-selection **shall not** post `MemoryMapPanel.OpenInHexRequested`. **Threshold:** exactly 0 across a full render. **Acceptance:** ⚠️ **C-40** — "zero messages" is green on a render that never happened; co-assert the inspector was populated in the same run.

**LLR-116.4 — re-render selection resolution (R-6)** · **Traceability:** HLR-116 · **Statement:** On each render the panel **shall** resolve the selected region to the previously selected region when an address equal to it is present among the newly rendered runs, and to the first ordered region otherwise. **Symbols:** `_selected_cell_start` `:1768`/`:2463`/`:2329`; `_reset_detail()` call site `:1896`; `_ordered_ranges` `:1923`; `_run_bands` `:1926`. **Rationale (informative):** matching is by **address**, never by index — a re-merge can change how many runs precede the selected one (`_merge_band_runs` splits on band change *or* address discontinuity), so an index match would silently select a different region. **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_map_big.py -k "b77_rerender" -v` · **Threshold:** `AT-B77-13` and `AT-B77-14` both green, each RED under its own mutation per the HLR-116 table. **Acceptance:** the resolution **shall** run after `_reset_detail()`, which clears the stored address — capturing it **before** the reset is the ordering the implementation must get right.

**LLR-116.5 — focus follows the resolved selection (R-6)** · **Traceability:** HLR-116 · **Statement:** After the selection is resolved, focus **shall** be on the region row whose `region_start` equals the resolved selection. **Rationale (informative):** without this, preserved selection plus reset focus would leave the operator's arrow keys resuming from the rail — a silent regression of HLR-115 caused by a change in HLR-116. **Validation:** `test (e2e)` · **Threshold:** `app.focused.region_start == resolved_selection` in both the preserved and the fallback case (today: `app.focused` is `RailItem`/`ScrollableContainer` with **no** `region_start`, executed). **Acceptance:** observable through `app.focused`, so the coupling is asserted rather than assumed; ⚠️ moving focus during a render must not itself re-enter `render_ranges` — `assumed — verify no re-entrancy in Phase 3`.

### HLR-117 → LLR-117.x

**LLR-117.1 — marker applied by address** · **Statement:** The panel **shall** apply a selection marker to the row whose `region_start` equals `_selected_cell_start`, and to no other row. **Symbols:** `_selected_cell_start` `:1768`/`:2463`/`:2329`; `RegionRow.region_start` `:1157`; `_build_region_row:2107`. Marker token **NEW — created in Phase 3**. **Threshold:** exactly 1 (today 0); matched by **address**, not index.

**LLR-117.2 — the band channel survives selection** · **Statement:** Applying or removing the selection marker **shall not** add, remove or override any `band-*` class on the row. **Symbols:** `styles.tcss:665/669/673/677`. **Validation:** `test` + `inspection` · **Threshold:** `set(classes) - {marker}` identical before and after; the CSS rule sets no `color:` property. **Acceptance:** asserted at the **resolved-CSS** layer (`widget.styles`), because `render().spans` is `[]` on these rows (P-42) and `render_line` returns the base theme colour (C-37).

---

## 5. Validation strategy

### 5.1 Methods
**Layer A (white-box, `TC-B77-nn`)** — `test (unit|integration|e2e)` / `inspection` / `analysis` over the mechanism.
**Layer B (black-box, `AT-B77-nn`)** — Textual Pilot e2e through the shipped surface, both regimes. **`demo` is never used for acceptance.**

**Standing rules:**
1. **Read the layer that holds the fact.** Geometry → `widget.region` clipped to the container (never `len(str(render()))`). Selection/band style → `widget.styles.(background,color,text_style)` (**not** `render().spans`, measured `[]`). Text → `#map_stats_body`/`#map_detail_body` (**not** the `#map_stats`/`#map_detail` containers, which render `Blank`). Footer → `app.active_bindings` filtered on `.show and .enabled` (never a Footer substring grep).
2. **Settle before measuring geometry** (LLR-111.6, N-2).
3. **Every absence assertion carries a presence co-assertion** (C-40): `AT-B77-05` ×2, `AT-B77-06`, `AT-B77-11`, and `AT-072b`'s `⊆` paired with `AT-B77-04`'s `⊇`.
4. **Per-arm verdicts (CC-1).** Every AT is parametrized over `[(80,24),(120,30)]`. **Report RED/GREEN per resolved node id per size arm** — `AT-B77-01`'s arms redden on *different limbs*, and an aggregate verdict destroys exactly that information. An exit code over parametrized tests hid 4 surviving arms in batch-76.
5. **C-34:** every increment touches a TUI render module, so every gate runs the **full** `tests/test_tui_directionb.py` (host of `test_tc_042_10`, the rail census, TC-030, **TC-011**), plus full `tests/test_tui_map_big.py` and `tests/test_map_click_chain.py`.
6. **Mutation discharge is executed, not described** — substituted VALUE recorded, run in an isolated tree with `PYTHONDONTWRITEBYTECODE=1` (C-46), restore proven by a **green run**, not a hash.
7. **Gate form stated with every ledger figure.** `tui-ci` runs `-m "not slow"` on PRs, FULL on pushes; 21 slow tests; **FULL runs before merge**.
8. **No test is deleted in the increment that changes the behaviour it guards.** `test_at072b_ruler`, `test_at075_…` and `test_tc041_9` are **re-derived in place**; `test_ac6_clipped_segments_…` is deleted only under §6.5 Amendment C.

### 5.2 Dual traceability

**Behavioral (black-box) — every AT demonstrated RED by execution:**

| US | Outcome | AT | Executed pre-change verdict |
|---|---|---|---|
| US-77-1 | regions visible, ordered, folded, contained | `AT-B77-01` | **RED both arms** — 80×24 `strict=False`; 120×30 `visible≥1=False` |
| US-77-1 | gapless no-op | `AT-B77-02` | **PIN** (green by construction; gated by post-Inc-2 mutation) |
| US-77-1 | nothing painted outside the bar | `AT-B77-03` | **RED @120×30** (4 outside); GREEN @80×24 |
| US-77-2 | every label admissible | `AT-072b` (re-derived) | **RED** — 4 of 5 unmapped; `{ticks} ⊆ ADMISSIBLE` = False |
| US-77-2 | lower bound | `AT-B77-04` | **RED** — and `set() ⊆ ADMISSIBLE` is True, proving why it is needed |
| US-77-3 | dual readout | `AT-B77-05` | **RED** — `Coverage: 0.00%` + `67108408 bytes` |
| US-77-4 | legend gone from the body | `AT-B77-06` | **RED** — 4 rows, 1 container |
| US-77-4 | legend screen intact | `AT-B77-07` | **PIN** |
| US-77-5 | arrows + Enter | `AT-B77-08` | **RED** — `can_focus=[False]×5`, `BINDINGS=[]` |
| US-77-5 | no binding shadowed | `AT-B77-09` | **PIN** — must stay green after Inc-4 |
| US-77-5 | N4a mouse split | `AT-B77-10` | **PIN** — reuse an existing node if it suffices |
| US-77-6 | focused + inspected, zero input | `AT-B77-11` | **RED** — `focused=RailItem`, detail = `_DETAIL_HINT` |
| US-77-6 | re-render, region present → **preserved** + focus follows | `AT-B77-13` | **RED** — `_selected_cell_start` → `None`, detail reverts to hint, focus has no `region_start` |
| US-77-6 | re-render, region absent → **falls back to first** | `AT-B77-14` | **RED** — detail reverts to hint; new first `0x10000000` not named |
| US-77-7 | selection visible | `AT-B77-12` | **RED** — 0 markers; all triples equal but for the band colour |

**Functional (white-box):** HLR-111 → LLR-111.1…6 → `TC-B77-01…05` · HLR-112 → LLR-112.1…3 → `TC-B77-06…09` · HLR-113 → LLR-113.1…2 → `TC-B77-10…13` · HLR-114 → LLR-114.1…2 → `TC-B77-14…15` · HLR-115 → LLR-115.1…4 → `TC-B77-16…20` · HLR-116 → LLR-116.1…**5** → `TC-B77-21…24` + `TC-B77-29` · HLR-117 → LLR-117.1…2 → `TC-B77-25…28`. Both chains exist for all seven stories.

### 5.3 Batch acceptance criteria
- 100 % of LLRs covered by ≥1 TC with a pass result; every US has ≥1 passing AT with boundary + negative evidence.
- **Every gate AT demonstrated RED pre-change, per size arm** (§5.2, executed).
- Every PIN labelled PIN, with its falsifiability discharged by a post-fix mutation whose transcript is pasted.
- 0 blocker findings at the merge gate; frozen-engine diff **= 0** (source **and** `_ENGINE_TEST_FILES`).
- **TC-011 green and unmodified.** Full suite green — baseline **2514 passed / 2 skipped / 3 xfailed** (FULL form).

### 5.4 IDs
**Batch-scoped: `AT-B77-01…14`, `TC-B77-01…29`.** (`AT-B77-13`/`14` and `TC-B77-29` added by R-6; the claim was split, so the id was split — C-18.) Letter-initial bodies are outside `AT-TC-REGISTRY.jsonl`'s authority (`_meta.governed`, spec §2.3) and preferred by `docs/engineering-rules.md:48` — **no reservation PR, collision impossible by construction.** **Exception:** `AT-072b` is an existing global id being re-derived and keeps its number. Registry `next_free` re-derived for the record: **`AT-282` / `TC-613`**.

---

## 6. Appendices

### 6.3 Risks and carries

| # | Item | Disposition |
|---|---|---|
| **R-7** | 🆕 **Geometry unsettled after one `pilot.pause()`** — 80×24 reads 68 then 66 (~1 in 5); my own probe read 23 vs the settled 21. **Not** caused by `active_bindings`. | **LLR-111.6** — settle to a fixed point; no geometry AT pauses exactly once |
| R-1 | Blast radius: **3 files, 7 live assertions**, 4 RED by design + 1 going vacuous | C-26 census §6 of `01b-qa-validation.md`, folded into §7 gates |
| R-2 | Fold markers becoming `RegionRow`s | **Downgraded** — gaps are already inert `Static`s and `test_map_click_chain.py:309-337` already guards it |
| R-3 | No spatial arrow-focus in Textual (C-16) | `assumed — verify Phase 3`; real keys only |
| R-4 | Snapshot drift | **2 map cells** (`comfortable × {80×24,120×30}`) per C-22; regen **canonical CI only** (textual 8.2.8) |
| R-5 | Markup injection | **B3 holds by construction** — every new label is a count, an address or a constant |
| **R-6** | 🆕 **A `show=True` binding would drift all 29 cells and may truncate a footer chip** (14 chips / 78 cols measured) | **Add none.** `?` help panel serves discoverability |
| **C-77-a** | Dense `round()` drift — off-budget on 37.3 % of gapless images | **superseded by R1** — the container basis replaces the constant; re-measure at Phase 4 |
| **C-77-c** | `REQUIREMENTS.md` is not an index of the HLR namespace (`HLR-108/109/110` live in tests, absent there) | **Lane-B (process) carry** |
| **C-77-d** | US-77-8 Variant C ports | Lane-A carry |
| **C-77-e** | Variant B two-lane map | Lane-A carry |
| **C-77-f** | 🆕 **`o` = open-hex from the keyboard, DESCOPED by R3** | **Lane-A carry.** Hex stays reachable by N4a double-click |
| **C-77-g** | 🆕 **The charter's "2-column gap marker + humanized size label at/above a fold threshold" (`memmap_variant_a.HANDOFF.md` §2, S-1) — DESCOPED by R-5.** Measured reason: at the 21-column container `fold=2` yields `[3,3,3,3,1]`, collapsing three runs to equal width and gutting the strict limb of `AT-B77-01`. A uniform 1-column marker carries no size label. | **Lane-A carry.** Revisit only if the bar gains columns (e.g. if the glance panel stops docking beside it at 120×30) |
| **F-1** | Self-caught probe defects: (a) `UnicodeEncodeError` (cp1252) printing the strip — same family as C-42 mechanic 4; (b) `PermissionError` on temp cleanup holding `s19tui.log`; (c) **an unsettled 23/52 geometry read reported as fact in my own first pass**, corrected by re-execution and promoted to R-7; (d) `address_in_sorted_ranges(index, addr)` argument order inverted — caught by a `TypeError`, not by a wrong answer; (e) 🆕 **the R-6 probe's `pilot.click` did not land** — `_selected_cell_start` read `None` immediately after the setup gesture, so the first `AT-B77-13`/`14` transcript was RED for the wrong reason. Re-run with `scroll_visible` + click and a **verified precondition** (`detail names target = True`, `_selected_cell_start = 0x2000000`); both arms still RED, now for the right one. *This is why `AT-B77-13`/`14` must assert their own precondition — a setup gesture that silently misses turns a gate into a tautology.* | recorded, not hidden |

### 6.4 Reconciliation log

| Decision | What changed | Parent HLR re-read? | Body edit landed? |
|---|---|---|---|
| **R1** | width basis → measured container; `_BAND_BAR_WIDTH` retired as a basis; PIN test deleted | HLR-111 restated with 5 clauses | §3 HLR-111; §4 LLR-111.1/.3; §6.5 Amendment C |
| **R2** | golden re-based; unequal fixture; fixed container width | HLR-111 clause 1 now "no-op on gapless" not "identical to today" | §4 LLR-111.4 |
| **R3** | `j`/`k`/`o` dropped; `o` descoped | HLR-115 restated; HLR-114 no longer depends on a hint | §3 HLR-115; §4 LLR-115.4; carry C-77-f |
| **R4** | end label = last mapped byte; 4 of 5 | HLR-112 restated | §3 HLR-112; §4 LLR-112.1; §6.5 A+B |
| **QA B-4** | US-77-4 re-authored around removal | HLR-114 statement + rationale | §2.6; §3 HLR-114 |
| **QA B-6** | focus entry absorbed into US-77-6 | HLR-116 gained clause 1 | §3 HLR-116; §4 LLR-116.1; §7 ordering |
| **N-1** | conjunction, not separate limbs | HLR-111 clauses 2+3 joined | §3 HLR-111 + its callout; §4 LLR-111.5 |
| **N-2** | settling requirement added | HLR-111 unchanged in threshold; new child | §4 **LLR-111.6**; §6.3 R-7 |
| **R-5** | fold marker fixed at **1 column**, uniform; 2-col + size-label descoped | HLR-111 clause 4 already said "fixed marker width"; **no threshold change** — the value is set in the child, and the parent's `AT-B77-01` strict limb is what motivated it | §4 **LLR-111.2** (value, measured rationale, scope-reduction note); §6.3 **C-77-g**; §8 OQ-2 closed |
| **R-6** | preserve-if-present else first; focus follows selection | HLR-116 **Statement rewritten** (two new clauses) and its **threshold extended** to the two re-render cases | §3 HLR-116 Statement + threshold + `AT-B77-13`/`14` + mutation table; §4 **LLR-116.4**, **LLR-116.5**; §5.2 two rows; §8 OQ-1 closed |

### 6.5 Requirement amendments

#### Amendment A — `R-TUI-072` (`REQUIREMENTS.md:4787-4793`), ruler clause
- **Before** (verbatim `:4789-4791`): *"…and render a NEW **address ruler** beneath the strip with **exactly 5 tick labels** at 0/25/50/75/100 % of the address span — tick 0 % == span start and tick 100 % == span end."*
- **After:** *"…and render a NEW **address ruler** beneath the strip with **one tick label per mapped region start plus one for the last mapped byte**, strictly ascending and without duplicates, collapsed where labels would overlap at the rendered width, retaining the first and last labels in preference to any interior label. **No tick label shall name an address outside every mapped range.**"*
- **Deleted:** "exactly 5 tick labels", "0/25/50/75/100 %", "tick 100 % == span end", `_TICK_COUNT = 5` as a contract.
- **New:** per-region-start ticks, the last-mapped-byte end label, strict ascent, no duplicates, overlap collapse.
- **Preserved:** the `╱` hatch clause; humanized sizes; entropy colour/texture flowing solely from `entropy_style`; the `band-*`/`sev-*` separation; the "extends R-TUI-060/041, nothing superseded" relation; the spent `0x`-prefix-drop fallback.
- **Parent re-read:** `R-TUI-060`'s §6.5 Amendment B block at `REQUIREMENTS.md:4190-4191` **restates the same retired clause** and must be amended in the same edit — a second copy.
- **Re-derived verifier:** `test_at072b_ruler` — `assert len(ticks) == 5` retired; endpoints re-pointed; strict ascent + `⊆ ADMISSIBLE` added; `AT-B77-04` adds the `⊇` bound. ⚠️ The node is **currently passing** — this is a live acceptance being deliberately invalidated, which is why this block exists.

#### Amendment B — `LLR-072.3` (`.dev-flow/2026-07-15-batch-47/01-requirements.md:508`)
- **Before** (verbatim): *"**Statement:** A NEW ruler widget beneath the strip shall render 5 tick labels at 0/25/50/75/100 % of the address span, tick 0 % == span start and tick 100 % == span end."*
- **After:** *"**Statement:** The ruler widget beneath the strip shall render one tick label per mapped region start plus one for the last mapped byte, shall emit strictly ascending non-duplicate labels, shall collapse labels that would overlap at the rendered width, and shall render no label naming an address outside every mapped range. **Superseded in batch-77 by `LLR-112.1`/`LLR-112.2` (HLR-112 / US-77-2).**"*
- **Parent re-read:** batch-47 `HLR-072` — its siblings `LLR-072.1` (hatch), `.2` (humanized sizes), `.4` (band-bands amendment) are **untouched**.
- ⚠️ **Convention (OQ-3, ruled):** LLR bodies exist **only** in the owning batch's Phase-1 artifact — `REQUIREMENTS.md` defines zero. The operator accepted amending that artifact in place, with the supersession pointer above so the edit is traceable from either end.

#### Amendment C — retirement of `test_ac6_clipped_segments_are_a_known_layout_limitation` (R1)
- **Node:** `tests/test_map_click_chain.py:342-389`. **Live and passing today.**
- **What it asserts (the observable being dropped):** (a) `bar_width < _BAND_BAR_WIDTH` at 120×30 — i.e. *the constant and the container disagree*; (b) `outside_count > 0` — i.e. *at least one band segment is painted outside the bar*.
- **Why it goes:** R1 reconciles the constant with the container. The test asserts the **disagreement exists**; fixing it correctly must fail here. Its own docstring sanctions this verbatim: *"If the constant and the container were reconciled, DELETE this test — it exists only to pin the disagreement"* and *"delete it and drop the limitation note from the two AC-6 pointer tests."*
- **What replaces each dropped observable (C-40 limb 2 (ii) — a consolidation must not silently drop observables):**
  | Dropped observable | Replacement | Direction |
  |---|---|---|
  | `bar_width < _BAND_BAR_WIDTH` (disagreement exists) | **no replacement, deliberately** — the premise is being made false. `LLR-111.1` forbids deriving any width from `_BAND_BAR_WIDTH`, verified by inspection | inverted by design |
  | `outside_count > 0` (segments painted outside) | **`AT-B77-03`** — `outside_count == 0` at both regimes | **inverted**: the same measurement, opposite expected value |
- **Also required:** drop the limitation note from the two AC-6 pointer tests (`tests/test_map_click_chain.py:227` and the sibling double-click test), as the docstring instructs.
- **Recorded as:** a deliberate, docstring-sanctioned retirement — **not** a test deleted to make a change pass. The distinguishing evidence is that its measurement survives inverted in `AT-B77-03`.

---

## 7. Increment plan (dependency-ordered, ≤5 files each)

| Inc | Content | Files | Gate |
|---|---|---|---|
| **Inc-1a** | **`LLR-111.1` + `LLR-111.6`** — width basis → measured container; the settling helper. `AT-B77-01`, `AT-B77-03`. **Deletes the PIN test per Amendment C** and drops the two limitation notes. | `screens_directionb.py`, `tests/test_tui_map_big.py`, `tests/test_map_click_chain.py`, `REQUIREMENTS.md` (4) | full ×3 census files; per-arm verdicts |
| **Inc-1b** | **`LLR-111.4` golden capture** — unequal 768/256 fixture, at fixed container width, **its own commit, after the width basis settles, before any fold edit** (R2) | `tests/test_tui_map_big.py`, golden artifact, `.gitattributes` (3) | golden committed; stored blob's bytes verified |
| **Inc-2** | **`LLR-111.2`** gap fold + `LLR-111.5` mutation discharge, incl. **the `AT-B77-02` reddening mutation with its transcript** | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_map_big.py` (3) | full ×3; `AT-B77-02` proven RED under mutation |
| **Inc-3** | **HLR-112** ruler + **Amendments A + B** + `AT-072b` re-derivation + the 6-site sweep | `screens_directionb.py`, `REQUIREMENTS.md`, `.dev-flow/2026-07-15-batch-47/01-requirements.md`, `tests/test_tui_map_big.py`, `tests/test_tui_snapshot.py` (5) | grep census = 0 surviving "exactly 5 ticks" |
| **Inc-4** | **HLR-113 + HLR-114** — stats re-format, legend removal, **`TC-B77-10` re-derives `test_tc041_9`**, `test_at075`'s `e`-key clause **ported not deleted** | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_directionb.py`, `REQUIREMENTS.md` (4) | full `test_tui_directionb.py`; `AT-B77-07` green |
| **Inc-5** | **HLR-116 + HLR-117** — focus entry, auto-select, **re-render resolution + focus-follows-selection (`LLR-116.4`/`.5`, R-6)**, selection style | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_map_big.py`, `REQUIREMENTS.md` (4) | full ×3; **`AT-B77-13` and `AT-B77-14` each proven RED under its OWN mutation** (HLR-116 table) |
| **Inc-6** | **HLR-115** — arrows + Enter. **No `show=True` binding.** | `screens_directionb.py`, `tests/test_tui_map_big.py`, `REQUIREMENTS.md` (3) | full ×3; **TC-011 green and unmodified**; `AT-B77-09` green |
| **Inc-7** | Snapshot regen — **canonical CI only**, collapsed into one PR | snapshot baselines | full suite; per-cell C-22 |

**Ordering rationale — three hard constraints, not preferences.**
1. **Inc-5 precedes Inc-6.** `HLR-116` owns the focus-entry path (QA B-6: `tab` and `down` never reach the map, `can_focus=False`, `BINDINGS=[]`). **Without it `AT-B77-08` has no first `Given` and is unreachable.**
2. **Inc-1a precedes Inc-1b precedes Inc-2** (R2). A golden captured before the width basis settles pins the wrong thing; one captured after the fold lands cannot detect the fold.
3. **Inc-7 last** (C-30). Each functional increment then drifts and marks only its own 2 map cells, leaving the other 27 live as regression guards; the regen collapses into one canonical-CI PR.

---

## 8. Open questions

| # | Question | Blocks | Owner |
|---|---|---|---|
| ~~OQ-1~~ | ✅ **CLOSED — ruling R-6.** Preserve the selection when the region is still present; fall back to the first region otherwise; focus follows selection. | landed: HLR-116, LLR-116.4/.5, `AT-B77-13`/`AT-B77-14` | — |
| ~~OQ-2~~ | ✅ **CLOSED — ruling R-5.** One-column fold marker, always; the charter's 2-column + size-label variant is descoped to carry **C-77-g**. | landed: LLR-111.2, C-77-g | — |
| **OQ-3** | Whether `_BAND_BAR_WIDTH` is deleted outright or retained as a pre-layout fallback. R1 retires it as a *basis*; it may still be needed before first layout (`LLR-111.1` acceptance note). | `LLR-111.1` | Phase 3 |
| **OQ-4** | The focus-entry mechanism itself — screen-scoped binding, auto-focus on render, or extending the rail's tab chain. ⚠️ Extending the shared chain changes focus on every screen. | `LLR-116.1` | Phase 3 |

---

## 9. Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Constraints stated explicitly | ✓ | §2.2 — each with a `file:line` or an executed measurement |
| ≥2 alternatives considered | ✓ | §2.8 maps R1–R4 onto the option tables they resolve; `LLR-111.5` records the two **rejected** predicates so they are not reintroduced |
| Recommendation tied to constraints | ✓ | The `fold=1` recommendation (accepted as **R-5**) is tied to the measured 21-column container and the strict limb's margin — `LLR-111.2` carries the executed four-row comparison |
| Risks listed | ✓ | §6.3 — 7 risks + 6 carries + 4 self-caught probe defects |
| Cost/latency estimated where relevant | ✓ | Column budget and pane geometry are the cost axis (§2.2, P-38); no new I/O or compute — pure re-formatting and re-scaling |
| Diagram included when flow is non-trivial | ✗ | **Deliberate** — the flow is one linear producer stated in three lines in §2.1 |
| What would change the recommendation is stated | ✓ | **C-77-g** states the condition that would reopen the 2-column marker (the bar gaining columns); OQ-3 (fallback need); OQ-4 (entry mechanism) |
| Two-layer requirements, both chains | ✓ | Every HLR has a first-class Acceptance block + QC-3 catalog; §5.2 carries both chains for all 7 stories |
| **Every gate AT demonstrated RED by execution, per arm** | ✓ | §5.2 — **11** gates RED with transcripts (incl. `AT-B77-13`/`14`, re-run after a self-caught bad precondition, §6.3 F-1(e)); 4 PINs labelled PIN with their post-fix mutation named |
| **C-40 both limbs per predicate** | ✓ | `LLR-111.5` table; the HLR-116 **per-arm mutation table** (each mutation reddens exactly one of `AT-B77-13`/`14`); per-AT notes on `AT-B77-05/06/11`, `AT-072b`+`AT-B77-04`; Amendment C discharges limb 2 (ii) |
| No transcript carried from the old width basis or a fold=2 assumption | ✓ | Every figure re-executed post-ruling. `LLR-111.2` keeps the fold=1 **and** fold=2 rows deliberately — they are the *evidence for* R-5, not an assumption behind it. The 23/52 unsettled read is **retracted in §6.3 F-1(c)**, not carried |
| Normative keyword discipline | ✓ | `shall` only in HLR/LLR **Statement** lines, in quoted requirement text (§6.5), and in §2.7's quoted premise |
| No id minted outside authority | ✓ | `AT-B77-*`/`TC-B77-*` are batch-scoped (outside registry authority); `AT-072b` is an existing id re-derived |
