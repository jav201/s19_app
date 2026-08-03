# Requirements Document — s19_app — batch `2026-08-01-batch-77` (ARCHITECT lane)

**Objective:** Memory Map redesign — Variant A (gap-fold band bar) + cross-cutting fixes S-1…S-7
**Charter INPUT:** `prototypes/memmap_variant_a.HANDOFF.md` · **Phase-0:** `00-measurements.md`
**Branch:** `claude/batch-77-memmap-variant-a` · **Base:** `origin/main` @ `f8747b8` (HEAD `065bb95`)
**Language:** English · **Lane:** A (`.dev-flow/BACKLOG-CODE.md`)
**Normative keyword:** `shall`, and it appears ONLY inside HLR/LLR **Statement** lines.

---

## BLUF — three blockers, one namespace correction, before anything else

| # | Finding | Verdict | Who decides |
|---|---|---|---|
| **B-1** | **US-77-1 is self-contradictory as chartered.** Its two clauses — *"a dense no-gap image renders byte-identical to today"* **and** *"the bar within its column budget"* — are **jointly unsatisfiable on 20.6 % of dense inputs**, and specifically on the measured dense fixture, which renders **61 columns against a 60 budget with zero gaps and zero flooring**. | ❌ **BLOCKS US-77-1** | **OPERATOR** — option table in §2.8 |
| **B-2** | **US-77-4 and US-77-5 collide on the key `k`.** US-77-4 demotes the legend and points the operator at app-wide `k` (`app.py:1359`). US-77-5 makes `k` mean "move up" on a focused region row. **Executed:** a focused widget's binding **shadows** the App binding — the hint would be false exactly where it is displayed. `j` and `o` collide too. | ❌ **BLOCKS US-77-5 as worded** | **OPERATOR** — option table in §2.8 |
| **B-3** | **Phase-0's P-5 is wrong: `LLR-072.3` EXISTS.** It is defined at `.dev-flow/2026-07-15-batch-47/01-requirements.md:508`. `REQUIREMENTS.md` defines **zero** LLR bodies (`grep -cE '^\*\*LLR-[0-9]' → 0`), so the corpus that produced "dangling" makes *every* LLR in the project dangling — a reductio. **US-77-2 therefore needs TWO amendments, not one, and the "dangling citation" carry is VOID.** | ⚠️ **Scope doubles** | architect — resolved in §6.5 |
| **N-1** | **ID namespace: next free is `HLR-111` / `LLR-111`, not `107`.** Deriving from `REQUIREMENTS.md` alone returns `HLR-106`→next `107`, which **collides with three live HLRs** (`HLR-108/109/110`) cited in shipped test files. `REQUIREMENTS.md` is **not** an index of the HLR namespace. | ✅ resolved | derived in §2.7 P-20 |

**Nothing in this document may be implemented until B-1 and B-2 carry an operator ruling.** Every other story (US-77-2, -3, -6, -7) is derivable and derived below.

---

## 1. Introduction

### 1.1 Purpose
Derive the HLR/LLR set for batch-77 from the seven READY user stories in `PLAN.md §3`, under IEEE 830 + EARS, with every code claim verified against disk at draft time.

### 1.2 Scope

**In:** US-77-1 … US-77-7 (charter S-1…S-7). The Memory Map screen's band bar, address ruler, stats strip, legend placement, keyboard path, auto-selection and selection rendering.

**Out:** US-77-8 (log-scale microbar + column-aligned rows — Variant C ports, no measured defect); Variant B (two-lane map); the CC-1 encoding decision; **the dense-image rounding drift** (new carry C-77-a, §6.3) unless the operator picks Option B-1/②.

### 1.3 Definitions

| Term | Definition |
|---|---|
| **run** | A merged same-band region from `_merge_band_runs` — `(band_label, summed_bytes, start_addr)`. Emitted as a `BandSegment` (`screens_directionb.py:1172`). |
| **gap** | An unmapped address interval between two consecutive runs. Emitted as an inert `Static` with classes `map-band-seg map-band-gap` (`:2060-2064`). |
| **column budget** | `_BAND_BAR_WIDTH = 60` (`screens_directionb.py:230`) — the intended total character width of the band strip. |
| **fold** | Replacing a gap's span-proportional width with a **fixed, size-independent** marker width. |
| **emitted column total** | `Σ len(str(seg.render()))` over `app.query(".map-band-seg")` — the observable this batch bounds. |
| **width monotonicity** | For runs `a`,`b`: `bytes(a) > bytes(b) ⇒ cols(a) ≥ cols(b)`, **plus** ≥1 strict inequality over the fixture. |

### 1.4 References
`REQUIREMENTS.md` R-TUI-041 / R-TUI-060 / R-TUI-061 / R-TUI-072 / R-TUI-073 / R-TUI-074 · `.dev-flow/2026-07-15-batch-47/01-requirements.md` (LLR-072.x bodies) · `docs/engineering-rules.md` (C-13, C-22…C-42) · `AT-TC-REGISTRY.jsonl` · `~/.claude/templates/dev-flow/req-template.md`.

### 1.5 Document overview
§2 description + the mandatory **§2.7 premise table** and the **§2.8 blocker option tables** · §3 HLR · §4 LLR · §5 validation + dual traceability · §6 appendices incl. the **§6.5 Before/After amendments** · §7 increment plan.

---

## 2. Overall description

### 2.1 Product perspective
`MemoryMapPanel` (`screens_directionb.py:1660`) renders the Memory Map screen. `render_ranges` (`:1808`) tears down `#map_grid` and re-mounts four children built by `_build_band_widgets` (`:1988`): a band row (bar + glance), a `MapRuler` (`:1234`), a region list of `RegionRow`s (`:1088`), and a 4-row legend (`:2084-2104`). Batch-77 changes the **width arithmetic** (`:2058`, `:2066`), the **ruler tick derivation**, the **stats composer** (`build_stats_text:2275`), the **legend placement**, and adds a **keyboard/selection layer** that does not exist today.

### 2.2 Product functions
(a) size-discriminating band widths within a bounded column total; (b) an address ruler whose labels name mapped addresses; (c) a dual mapped/span stats readout with humanized sizes; (d) legend demoted out of the map body; (e) a keyboard path over region rows; (f) auto-selection of the first region; (g) a visible selection state.

### 2.3 User characteristics
A firmware/calibration engineer inspecting a sparse S-record image in a terminal at 80×24 or 120×30. Single operator, no permissions model.

### 2.4 Constraints

| Constraint | Value | Evidence |
|---|---|---|
| Terminal regimes | 80×24 (floor) and 120×30 | `tests/test_tui_map_big.py:32` `_SIZES` |
| Real `#map_grid` budget | **66×14 @80×24, 52×12 @120×30** — the *wide* regime is narrower | `REQUIREMENTS.md:4799-4802` (C-29, both axes measured, batch-47) |
| Column budget | `_BAND_BAR_WIDTH = 60` | `screens_directionb.py:230` |
| Textual version | **8.2.8** | executed: `probe77c.py` printed `textual version: 8.2.8` |
| Engine-frozen set | off-limits, source **and** `_ENGINE_TEST_FILES` (C-27 dual guard) | `PLAN.md:118` |
| B3 | no file-derived text in bar/rows — counts, addresses, constant band labels only | `REQUIREMENTS.md:4158`, `:4817` |
| Colour | **only** via `band-*` classes; glyphs `· ░ ▒ ▓` are the colour-blind cue (C-10) | `styles.tcss:665-679` (verified — `.band-constant/.band-low/.band-medium/.band-high` at `:665/:669/:673/:677`) |
| LLR-041.7 | the panel is presentational — no entropy/coverage re-derivation | `REQUIREMENTS.md:667`, `screens_directionb.py:973` |
| Remount discipline | re-mounted children carry **classes, never ids** (`DuplicateIds`) | `screens_directionb.py:2094-2097` |
| Fold markers | **must not be `RegionRow`** — `BandSegment` is the sibling precedent | `:1088` vs `:1172`; `:1185-1190` states the rationale |

### 2.5 Assumptions and dependencies
Every load-bearing assumption is evaluated in §2.7. Unevaluated prose here would be a Phase-2 blocker.

### 2.6 Source user stories
Verbatim from `PLAN.md §3`; DoR status inherited from Phase 0, **amended** where this lane's execution changed it.

| ID | User story (Connextra) | Source | DoR status (this lane) |
|---|---|---|---|
| **US-77-1** | As a firmware engineer, I want each region's bar width to order with its mapped size and gaps folded to fixed markers, so that I can tell regions apart on a sparse image. | charter S-1 + D-2 | 🔴 **BLOCKED — B-1** (was 🟢) |
| **US-77-2** | As a firmware engineer, I want every ruler label to name a mapped address, so that the ruler tells me where my data is instead of where it is not. | charter S-2 | 🟡 **READY-WITH-AMENDMENT ×2** (B-3) |
| **US-77-3** | As a firmware engineer, I want a dual mapped/span stats readout with a real percentage and humanized sizes, so that "0.00 %" stops hiding the number. | charter S-3 | 🟢 **READY** |
| **US-77-4** | As a firmware engineer, I want the always-on legend out of the map body, so that the map uses its rows for the map. | charter S-4 | 🟡 **READY — coupled to B-2** |
| **US-77-5** | As a firmware engineer, I want to reach and act on regions with the keyboard only, so that I am not forced onto the mouse. | charter S-5 | 🔴 **BLOCKED — B-2** (was 🟡) |
| **US-77-6** | As a firmware engineer, I want the inspector populated with zero clicks when a file is loaded, so that the pane is never dead space. | charter S-6 | 🟢 **READY** |
| **US-77-7** | As a firmware engineer, I want the selected region row to be visually distinct, so that I can see what I am looking at. | charter S-7 | 🟢 **READY** |
| **US-77-8** | *(charter "optional")* | — | 🔴 **OUT** — carry, §6.3 |

#### Refinement deltas this lane introduced (Phase 0 owns the rest)

**US-77-1 — downgraded 🟢 → 🔴.** Its **T** (testable) fails: the two acceptance clauses cannot both hold. See B-1 / §2.8.
**US-77-5 — downgraded 🟡 → 🔴.** Its **N** (negotiable) and **I** (independent) fail: as worded it silently removes a binding another story in the same batch depends on. See B-2 / §2.8.

### 2.7 Premise evaluation (C-43) — one row per premise

Tier: **axiom** (validated+verified) · **hypothesis** (this batch/charter introduces) · **premise** (claim about the world). Phase-0's P-1…P-15 are **not restated**; this table carries only what THIS lane newly relies on or newly corrects.

| # | Premise as a truth-apt proposition | Tier | Verdict | Executed evidence | Disposition |
|---|---|---|---|---|---|
| **P-16** | The proposed **width-monotonicity** predicate goes **RED** on the sparse fixture (i.e. it is not vacuous, C-40 limb 1) | hypothesis | ✅ **TRUE** | `probe77.py`, both regimes: `run bytes=[256,256,256,200,62]` `run widths=[1,1,1,1,1]` → `[PRED-A monotonic ordering]=True`, **`[PRED-A >=1 STRICT inequality]=False`**, combined `False`. Contrast the vacuous charter draft: `[charter#1 every run >=1 col]=True`. | — |
| **P-17** | The same predicate is **GREEN** on an already-discriminating render (positive control — it is not merely always-false) | hypothesis | ✅ **TRUE** | same probe, DENSE fixture: `run bytes=[512,256,256,512,512]` `run widths=[15,8,8,15,15]` → strict `True`, combined **`True`**. Both arms exercised. | — |
| **P-18** | 🆕 **The column-budget overflow is caused by the `max(1,…)` floor** (Phase-0's stated attribution for P-15) | premise | ⚠️ **PARTIALLY FALSE** | `probe77b.py` CASE 2 (sparse): floor contributes **+5**, `round()` contributes **−1**, net **+4** — attribution holds here. CASE 1 (dense, no gap): `parts=[512,256,256,512,512]`, exact shares `[15.0,7.5,7.5,15.0,15.0]`, shipped `[15,8,8,15,15]` **sum 61**, unfloored **also 61** → **floor contributed 0**. The budget is simply **never enforced anywhere**. | **Corrects P-15.** Feeds B-1. |
| **P-19** | 🆕 **The dense no-gap render is on-budget today**, so "byte-identical dense" and "within budget" can both hold | hypothesis | ❌ **FALSE** | `probe77b.py` CASE 3 — 20 000 random no-gap images, 2–9 segments, floor never firing: **on budget 62.7 %**, **over 20.6 % (worst +3)**, **under 16.7 % (worst −2)**. The measured DENSE fixture is one of the over cases (**61**). | **BLOCKS B-1** → §2.8 |
| **P-20** | 🆕 **The HLR/LLR high-water is derivable from `REQUIREMENTS.md`** | premise | ❌ **FALSE** | `grep -rhoE 'HLR-[0-9]{2,4}' REQUIREMENTS.md` → max **106**. Over `REQUIREMENTS.md + .dev-flow + tests + docs` → max **110**. `HLR-108/109/110` are **live in shipped tests** (`tests/test_report_document_bound.py`, `test_report_length_cell.py`, `test_tui_report_attribution.py`) and appear **0 times** in `REQUIREMENTS.md`. | **Next free = `HLR-111`/`LLR-111`.** Namespace gap → carry C-77-c. |
| **P-21** | 🆕 **`LLR-072.3` does not exist** (Phase-0 P-5) | premise | ❌ **FALSE** | Defined at `.dev-flow/2026-07-15-batch-47/01-requirements.md:508` — *"A NEW ruler widget beneath the strip shall render 5 tick labels at 0/25/50/75/100 % of the address span…"*. And `grep -cE '^\*\*LLR-[0-9]' REQUIREMENTS.md` → **0**: `REQUIREMENTS.md` defines **no** LLR bodies at all. | **Corrects P-5.** Amendment scope doubles (§6.5). "Dangling citation" carry **VOID**. |
| **P-22** | 🆕 **`LLR-072.3` is cited in shipped source, not only in tests** | premise | ✅ **TRUE** | `screens_directionb.py:1239`, `:1273`, `:1300`, `:2002`; `tests/test_tui_map_big.py:118`; `tests/test_tui_snapshot.py:670`. Six citation sites, not one. | Amendment must sweep all six. |
| **P-23** | 🆕 **A focused widget's `BINDINGS` shadow the App-level binding for the same key** (the mechanism US-77-5 depends on, and the hazard it creates) | hypothesis | ✅ **TRUE** | `probe77c.py`, textual **8.2.8**: row focused → `press k → ['ROW.k']` (App's `k` **never fires**), `press o → ['ROW.o']`, `press j → ['APP.j']` (unbound on row, falls through). Also: the row is auto-focused at mount, so shadowing applies from the **first** keystroke. | **BLOCKS B-2** → §2.8 |
| **P-24** | 🆕 **`j` / `k` / `o` are already bound app-wide** | premise | ✅ **TRUE** | `app.py:1356` `Binding("j","dump_a2l_json",…,show=False)`; `app.py:1359` `Binding("k","show_legend","Legend",show=True)`; `app.py:1352` `Binding("o","open_workarea",…,show=False)`. | Feeds B-2 |
| **P-25** | `RegionRow` is **not** focusable today, and `screens_directionb.py` defines **no** `BINDINGS` at all | premise | ✅ **TRUE** | `grep -n 'can_focus\|BINDINGS' s19_app/tui/screens_directionb.py` → **0 hits**. Executed render: `focusable=0` of 5 `RegionRow`s. | US-77-5 is all-new infrastructure |
| **P-26** | The `query(RegionRow)` blast radius is the 2 sites Phase-0 named | premise | ❌ **FALSE — understated** | `grep -rn 'query(RegionRow)\|isinstance(.*RegionRow' tests/` → **13 sites across 3 files**: `test_map_click_chain.py:115,187,326,328`; `test_tui_directionb.py:3461,3906,3927,4241`; `test_tui_map_big.py:177,226`. **`test_map_click_chain.py:309-337` is an explicit AC-6 blast-radius guard** that asserts segments must NOT match `query(RegionRow)`. | C-26 census widened; risk R-2 is **already guarded** |
| **P-27** | `human_bytes` renders the measured figures as the story assumes | premise | ✅ **TRUE** | **Executed** (C-35): `human_bytes(1030)='1.0 KiB'`, `(134217534)='128.0 MiB'`, `(67108408)='64.0 MiB'`, `(62)='62 B'`. Signature `def human_bytes(n: int) -> str` at `insight_style.py:124`. | — |
| **P-28** | A 4-decimal percentage discriminates the sparse case from the shipped `0.00%` | hypothesis | ✅ **TRUE** | **Executed**: `f"{100*1030/134217534:.4f}%"` → **`0.0008%`** vs shipped `f"{…:.2f}%"` (`screens_directionb.py:2304`) → **`0.00%`**. | — |
| **P-29** | `CoverageStats` already carries every field the new stats line needs — no new derivation (LLR-041.7 safe) | premise | ✅ **TRUE** | `screens_directionb.py:966-986`: `image_span`, `covered_bytes`, `coverage_pct`, `valid_count`, `invalid_count`, `gap_count`, `largest_gap`. US-77-3 is **pure re-formatting**. | — |
| **P-30** | Gap segments are already inert `Static`s, so "fold markers are not `RegionRow`s" is preserved by construction | premise | ✅ **TRUE** | `screens_directionb.py:2060-2064` builds `Static(..., classes="map-band-seg map-band-gap")`; executed render `segments=9, BandSegment=5` → the 4 gaps are plain `Static`. | Risk R-2 **downgraded** |

**Gate rule:** ❌ and ❓ block. **P-19 and P-23 block and are dispositioned in §2.8.** P-18/P-20/P-21/P-26 are ❌ but self-dispositioning — each corrects a prior claim and the correction has landed in this document's body.

### 2.8 Blocker option tables — OPERATOR DECISION REQUIRED

#### B-1 · US-77-1: "byte-identical dense" ∧ "within column budget" are jointly unsatisfiable

**The measurement.** The dense no-gap fixture renders **61 columns against a 60 budget**, with the `max(1,…)` floor contributing **exactly 0**. `round()` alone does it: exact shares `[15.0, 7.5, 7.5, 15.0, 15.0]` sum to 60; two half-values round up; total 61. Across 20 000 random no-gap images the shipped expression is **off-budget 37.3 % of the time** (20.6 % over, 16.7 % under). Enforcing the budget therefore **must** change some dense renders; preserving byte-identity therefore **must** leave the budget unenforced on them.

| Option | What the HLR would say | Expected result | Consequences |
|---|---|---|---|
| **①** *(recommended)* **Split the clause by input class.** Budget bound applies **when the image contains ≥1 gap**; byte-identity applies **when it contains none**. | "…shall emit ≤ `_BAND_BAR_WIDTH` columns **for any image containing at least one unmapped gap**" + "…**for a gapless image** shall emit a strip byte-identical to the pre-change render" | ✅ Both clauses independently RED-able and GREEN-able; no overlap, so no contradiction. The strongest control in the drafted set (the byte-golden) survives intact. | ⚠️ "Within budget" is **not** universal — the pre-existing ±1…3 dense rounding drift ships unchanged. Registered as carry **C-77-a** with its measured distribution. Honest, but the operator must accept a known-and-named residual. |
| **②** **Enforce the budget universally; drop byte-identity.** | "…shall emit exactly `_BAND_BAR_WIDTH` columns for every non-empty image" | ✅ A single, strong, universal invariant. Fixes the dense drift too. | ❌ **Destroys the batch's best control.** The dense no-op golden is the only thing proving the rewrite did not perturb the shipped render. Losing it trades a measured 1-column cosmetic defect for the loss of the regression net over a 6300-line render module. ❌ Also drifts an unknown number of snapshot cells on *dense* fixtures, widening the regen. |
| **③** **Enforce universally, redefine "byte-identical" as "identical modulo the budget correction".** | — | ❌ The control becomes self-referential: the counterfactual can no longer fail, because the correction is defined as whatever the new code emits. This is the project's dominant defect class (**vacuous check in a spec**) authored deliberately. | ❌ Reject. |
| **④** **Raise `_BAND_BAR_WIDTH` to a measured maximum.** | — | ❌ Does not fix it. The overflow is unbounded above in segment count (`probe77b.py` CASE 4: 100 equal segments → 100 columns, +40 over **any** fixed budget). | ❌ Reject. |

**Recommendation: ①.** Rationale tied to the constraints: the batch's stated invariant list (`PLAN.md:118`) puts regression-safety over the shipped render contract ahead of cosmetic completeness, and C-12/the byte-golden is the control that enforces it. A ±1-column drift on a *dense* image is not the defect the operator chartered — the chartered defect is a *sparse* image whose 5 regions are indistinguishable. Option ① fixes exactly that and names what it does not fix.
**What would change this recommendation:** if a dense-image snapshot cell is found to already be visibly clipped by the 61st column, the drift is no longer cosmetic and ② becomes correct. **Not measured — `assumed; measure at Phase 3` if ① is chosen.**

#### B-2 · US-77-4 ∧ US-77-5 collide on `k` (and `j`, and `o`)

**The measurement.** `probe77c.py` on textual 8.2.8: with the row focused, `press k` fires **`ROW.k`** and the App's `k` **never fires**. US-77-4's entire deliverable is a footer hint telling the operator to press `k` for the legend. US-77-5 would make `k` mean "move up" whenever a region row has focus — and Textual auto-focuses the first focusable widget, so that is the default state on the map screen.

| Option | Keymap on a focused region row | Expected result | Consequences |
|---|---|---|---|
| **①** *(recommended)* **Drop the vim aliases. `↑`/`↓` + `Enter` + `o` only.** | `↑`/`↓` move · `Enter` inspects · `o` opens hex | ✅ `k` keeps meaning Legend everywhere, so US-77-4's hint is true where it is shown. ✅ `j` keeps meaning dump-A2L-JSON. ✅ US-77-4 and US-77-5 become independent again (restores **I** in INVEST). | ⚠️ `o` still shadows app-wide `open_workarea` (`app.py:1352`) while a row is focused. **Declared, not hidden** — and pinned by a regression AT asserting `o` still opens the workarea when no region row is focused. |
| **②** **Keep `j`/`k`; move the legend to another key on the map screen.** | `↑↓jk` move · `Enter` · `o` | ⚠️ Works mechanically. | ❌ Breaks app-wide key consistency (`k`=Legend on 10 other screens), for a convenience alias. ❌ Forces an unbudgeted edit to `app.py`'s shared chrome → C-28 shared-chrome snapshot census across **every** screen's cells. |
| **③** **Keep `j`/`k`; accept that `k` stops opening the legend on the map.** | `↑↓jk` move · `Enter` · `o` | ❌ US-77-4 ships a footer hint that is **false on the screen that displays it**. | ❌ Reject — this is shipping a known-wrong affordance. |
| **④** **Keep `j`/`k`; drop US-77-4.** | — | ⚠️ Removes the contradiction by removing a story. | ❌ Trades a measured defect (4 rows of always-on legend eating a 14-row pane) for a convenience alias. Wrong side of the trade. |

**Recommendation: ①.** Rationale tied to the constraints: the `#map_grid` budget is **14 rows @80×24** (`REQUIREMENTS.md:4800`) — reclaiming 4 of them is the point of US-77-4, and it must not be paid for with a false hint.
**What would change this recommendation:** an operator preference for vim navigation strong enough to justify a global `k` remap — in which case ② is the correct form, and it pulls `app.py` and a full C-28 census into the batch.

---

## 3. High-level requirements (HLR)

> **ID basis (P-20, executed):** high-water across `REQUIREMENTS.md` + `.dev-flow/` + `tests/` + `docs/` is **`HLR-110` / `LLR-110`**. **Next free = `HLR-111`.** `HLR-*` / `LLR-*` are a **separate counter from `R-TUI-*`** (high-water `R-TUI-102`) and are **not** governed by `AT-TC-REGISTRY.jsonl` (`docs/engineering-rules.md:58`).
>
> **No `AT-NNN` / `TC-NNN` id is minted in this document.** `AT-TC-REGISTRY.jsonl` is the sole authority (`_meta.next_free` = `AT-282` / `TC-613`, read 2026-08-01) and reservation happens on its own PR before the batch's work. Placeholders `<AT-a>`… / `<TC-a>`… below state **what each must observe**; §5.4 sizes the reservation.

---

### HLR-111 — the band strip discriminates region size and is column-bounded
- **Traceability:** US-77-1
- **Statement:** When the Memory Map renders an image whose merged runs differ in mapped size, the band strip **shall** emit segment widths that are non-decreasing in mapped bytes, with at least one strictly greater pair whenever two runs differ in size by a factor of at least two; **and** when that image contains at least one unmapped gap, the strip **shall** emit a total of no more than `_BAND_BAR_WIDTH` columns; **and** when that image contains no unmapped gap, the strip **shall** emit content byte-identical to the pre-change render.
- **Rationale (informative):** The shipped expression scales by **address span**, not mapped bytes, so on a sparse image every run collapses to the `max(1,…)` floor — measured `[1,1,1,1,1]` for runs of `256/256/256/200/62 B`. The bar does not fail to *show* regions; it fails to *discriminate* them. The budget clause is scoped to gapped images per operator decision **B-1/①** — the residual dense rounding drift is carry C-77-a, not silence.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k "memmap_width or memmap_budget or memmap_dense_golden" -v` **plus** the full `tests/test_tui_directionb.py` (C-34 render-increment guard host)
- **Numeric pass threshold:** monotonic ordering holds over **all** run pairs; **≥1** strict inequality on the sparse fixture; emitted column total **≤ 60** on the sparse fixture (today **64**); dense strip string **== the committed golden**, exact equality
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome:**
  - **Observable outcome:** on the sparse 5-region image the operator sees five band segments of visibly different widths ordered by region size, gaps reduced to fixed markers, and the whole strip fitting its 60-column budget.
  - **Shipped surface:** `App.run_test(size=…)` → `action_show_screen("map")` → `update_memory_map()` → `app.query(".map-band-seg")`
  - **Deliverable + observation:** the rendered `.map-band-seg` widget set; observed as `[len(str(s.render())) for s in segs]` paired with each `BandSegment`'s `(region_start, region_end)`. **FAILS if the strip is absent** — `assert len(segs) >= 5` precedes every width assertion (a zero-segment render must not pass vacuously).
  - **Acceptance test(s):** `<AT-a>` width monotonicity + ≥1 strict, sparse fixture, both regimes · `<AT-b>` emitted column total ≤ `_BAND_BAR_WIDTH`, sparse fixture, both regimes · `<AT-c>` dense gapless strip == committed byte-golden (the C-12 control)
  - **Boundary catalog (QC-3):** ☑ **empty** — no ranges → `_EMPTY_TEXT`, zero segments, no raise (`screens_directionb.py:1900-1914`), `<TC-a>` · ☑ **boundary** — a single run (no pair to order; monotonicity must be *vacuously true but not asserted*, so the AT skips the strict clause at `n<2` **explicitly** rather than passing it), `<TC-b>` · ☑ **boundary** — >60 runs, where the floor alone forces overflow (`probe77b.py` CASE 4: 61 equal segments → 61 columns), `<TC-c>` · ☑ **invalid** — a zero-byte run, `<TC-d>` · ☑ **error** — `total_span <= 0` already guarded at `:1900`, `<TC-e>`

---

### HLR-112 — every ruler label names a mapped address
- **Traceability:** US-77-2
- **Statement:** When the Memory Map renders, the address ruler **shall** emit one tick label per mapped region start plus one for the image span end, **shall not** emit any label whose address falls in an unmapped gap, and **shall** collapse labels that would occupy overlapping columns at the rendered ruler width.
- **Rationale (informative):** Measured today: ticks `['00000000','01FFFFCF','03FFFF9F','05FFFF6E','07FFFF3E']` — **3 of 5 name addresses that hold no data** (Phase-0 P-7). A ruler that labels the middle of a 64 MiB hole is worse than no ruler. This **amends** `R-TUI-072` and `LLR-072.3`, both of which mandate *exactly 5 ticks at 0/25/50/75/100 %* — see **§6.5 Amendment A and Amendment B**.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py::test_at072b_ruler -v` (**re-derived**, see §6.5) + the new ruler ATs
- **Numeric pass threshold:** **0** tick labels fall outside `[start, end)` of every mapped range (today **3**); tick count `== len(runs) + 1` before collapse; **0** column overlaps between adjacent labels at both 66 cols @80×24 and 52 cols @120×30
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** every address printed under the strip is an address the operator can actually go to.
  - **Shipped surface:** as HLR-111, reading `app.query(".map-ruler-tick")`
  - **Deliverable + observation:** the rendered `.map-ruler-tick` label set; each label parsed as `int(label, 16)` and tested for membership in the loaded `ranges` via the **frozen, read-only** `range_index` primitives (`address_in_sorted_ranges` — already imported by `tests/test_tui_map_big.py:22-25`). **FAILS if the ruler is absent** — `assert len(ticks) >= 2`.
  - **Acceptance test(s):** `<AT-d>` **0** labels in unmapped space, sparse fixture, both regimes (**RED today at 3**) · `<AT-e>` first label == span start **and** last label == span end (the surviving half of AT-072b) · `<AT-f>` no two adjacent labels overlap at the measured 52-col regime
  - **Boundary catalog (QC-3):** ☑ **empty** — no ranges → no ruler mounted, `<TC-f>` · ☑ **boundary** — one region (2 ticks: start and end, which coincide with the region's own bounds), `<TC-g>` · ☑ **boundary** — more regions than the ruler has columns, forcing collapse, `<TC-h>` · ☑ **invalid** — two regions whose starts render to the same column, `<TC-i>` · ☐ **error** — **N/A:** the ruler derives from already-validated `ranges`; there is no new input class that can be malformed (LLR-041.7 — the panel derives nothing).

---

### HLR-113 — the stats strip states mapped-vs-span with a discriminating percentage and humanized sizes
- **Traceability:** US-77-3
- **Statement:** When the Memory Map renders a loaded image, `#map_stats_body` **shall** present the mapped byte total and the image span as humanized sizes in a single dual readout, **shall** render the coverage percentage at a precision that yields a non-zero value for a coverage ratio of 1 in 130 000, and **shall** present the largest gap as a humanized size rather than a raw byte count.
- **Rationale (informative):** Executed today: `Coverage: 0.00%  Bytes covered: 1030 … Largest gap: 67108408 bytes`. The true coverage is `0.000767 %`, flattened to `0.00%` by `f"{…:.2f}%"` at `screens_directionb.py:2304`. `human_bytes` (`insight_style.py:124`) already ships and is already imported by this module. This is **pure re-formatting of an existing `CoverageStats`** (P-29) — no new derivation, so **LLR-041.7 is preserved by construction**.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_directionb.py -k "map_stats" -v` + the new stats ATs
- **Numeric pass threshold:** the rendered percentage for the measured fixture is **`0.0008%`**, not `0.00%` (executed, P-28); the rendered largest gap is **`64.0 MiB`**, not `67108408 bytes` (executed, P-27); the rendered dual readout contains both **`1.0 KiB`** and **`128.0 MiB`**
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the operator reads "how much of this image is real" without doing arithmetic.
  - **Shipped surface:** as HLR-111, reading `app.query_one("#map_stats_body").render()`
  - **Deliverable + observation:** the `#map_stats_body` **`_body`** widget's rendered text. ⚠️ **Read `#map_stats_body`, never `#map_stats`** — the latter is a container and renders `Blank` (C-32/C-37; this exact confusion produced a false Phase-0 finding, `00-measurements.md §4`). **FAILS if the body is empty** — `assert text.strip()`.
  - **Acceptance test(s):** `<AT-g>` the sparse fixture's stats text contains `1.0 KiB`, `128.0 MiB`, a non-`0.00` percentage, and `64.0 MiB`; and **does not** contain the substring `67108408`
  - **Boundary catalog (QC-3):** ☑ **empty** — no file → the existing blanked strip (`_render_stats(..., empty=True)`, `:1905`), `<TC-j>` · ☑ **boundary** — coverage exactly 100 % (contiguous image, span == mapped) renders `100.0000%` not `100.00%`-rounded-from-99.99, `<TC-k>` · ☑ **boundary** — `gap_count == 0` → largest gap `0 B`, `<TC-l>` · ☑ **invalid** — `image_span == 0`, already the single div-by-zero guard (`:980-981`), `<TC-m>` · ☐ **error** — **N/A:** every field is a pre-computed `CoverageStats` int/float (P-29).

---

### HLR-114 — the legend is not resident in the map body
- **Traceability:** US-77-4
- **Statement:** When the Memory Map renders, `#map_grid` **shall not** contain any `.map-legend-row` widget, and the application's existing legend screen **shall** remain reachable and unchanged.
- **Rationale (informative):** Measured today: **4** `.map-legend-row` widgets built at `screens_directionb.py:2084-2092`, always on, inside a pane whose measured height is **14 rows @80×24** (`REQUIREMENTS.md:4800`). 4 of 14 rows is 29 % of the pane spent on a static key. The app already binds `k` → `action_show_legend` (`app.py:1359`, `show=True`, so the Footer already advertises it) — the affordance exists and needs no new key. **This story's correctness depends on B-2/① being chosen**; under B-2/③ the hint it displays would be false.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_directionb.py -k "legend" -v` + the full `tests/test_tui_directionb.py` (C-34)
- **Numeric pass threshold:** `len(app.query(".map-legend-row")) == 0` on the map screen (today **4**); the legend screen still opens on `k` and still renders **the same number of rows as before this batch**
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the map body gives its rows to the map; the legend is one keystroke away and unchanged.
  - **Shipped surface:** as HLR-111 for the absence; `pilot.press("k")` for the legend screen
  - **Deliverable + observation:** absence — `app.query(".map-legend-row")` is empty **while `app.query(".map-band-seg")` is non-empty** (⚠️ **C-40:** an absence assertion is trivially green on a screen that rendered nothing; the non-empty co-assertion is what makes it a gate and not a pin). Presence — the legend screen's own row count after `press("k")`.
  - **Acceptance test(s):** `<AT-h>` zero `.map-legend-row` in `#map_grid` **and** ≥5 `.map-band-seg` present · `<AT-i>` **regression:** `press("k")` from the map screen opens the legend screen with its pre-batch row count (this is the AT that catches B-2 if US-77-5 lands wrong)
  - **Boundary catalog (QC-3):** ☑ **empty** — no file loaded → still zero legend rows, and the AT must **not** count that as a pass (guarded by the co-assertion above), `<TC-n>` · ☑ **boundary** — legend screen opened from the map and dismissed back to the map, map still renders, `<TC-o>` · ☐ **invalid** / ☐ **error** — **N/A:** removal of a static widget set admits no new input.

---

### HLR-115 — region rows are reachable and actionable from the keyboard
- **Traceability:** US-77-5 · 🔴 **BLOCKED on B-2; the statement below assumes B-2/① and is void under any other option**
- **Statement:** While the Memory Map is the active screen and an image is loaded, each region row **shall** be focusable; when a region row has focus, `↑` and `↓` **shall** move focus to the previous and next region row respectively, `Enter` **shall** populate the inspector for the focused region, and `o` **shall** post `MemoryMapPanel.OpenInHexRequested` for it; and the application **shall** continue to route `k` to the legend screen and `j` to its existing action while a region row has focus.
- **Rationale (informative):** Measured today: **0 of 5** `RegionRow`s are focusable, and `screens_directionb.py` defines **no** `BINDINGS` at all (P-25) — this is entirely new infrastructure. The final clause is the **anti-regression** half, and it is the reason `j`/`k` are absent from the keymap: executed on textual 8.2.8, a focused widget's binding **shadows** the App's (P-23), so binding `k` here would silently disable the legend key that HLR-114 depends on.
- **⚠️ C-16 flag:** Textual performs **no** spatial arrow-focus by default. `↑`/`↓` moving between sibling rows is `assumed — verify in target framework at Phase 3`. **Its AT must press real keys via `pilot.press`, never call `.focus()`** — batch-27 shipped exactly that gap green.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k "keyboard" -v` + full `tests/test_tui_directionb.py` (C-34) + a C-28 shared-chrome snapshot census if any `show=True` binding is added
- **Numeric pass threshold:** `sum(r.can_focus for r in app.query(RegionRow)) == 5` on the 5-region fixture (today **0**); after `press("down")` the focused widget is the **next** `RegionRow` by address order; after `press("enter")` `#map_detail_body` differs from `_DETAIL_HINT`; `press("o")` yields **exactly 1** `OpenInHexRequested`; `press("k")` with a row focused opens the legend screen
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator drives the map with the keyboard alone, and loses no key they had before.
  - **Shipped surface:** `pilot.press(...)` against the live map screen — **real key events only**
  - **Deliverable + observation:** `app.focused` identity across presses; `#map_detail_body` text; captured `OpenInHexRequested` messages; the legend screen's presence in `app.screen_stack`.
  - **Acceptance test(s):** `<AT-j>` focus reaches a row and `↑`/`↓` move it, by **real keypress** (C-16) · `<AT-k>` `Enter` populates the inspector for the **focused** row (assert the *address* rendered, not merely "changed") · `<AT-l>` `o` posts exactly one `OpenInHexRequested` with the focused region's start · `<AT-m>` **anti-regression:** with a row focused, `k` still opens the legend · `<AT-n>` **anti-regression:** with **no** row focused, `o` still triggers `open_workarea`
  - **Boundary catalog (QC-3):** ☑ **boundary** — `↑` on the first row and `↓` on the last (must not wrap silently or crash; behaviour is stated in LLR-115.2), `<TC-p>` · ☑ **empty** — no file loaded → no focusable rows, and every key is inert rather than raising, `<TC-q>` · ☑ **boundary** — exactly one region (`↑`/`↓` are no-ops), `<TC-r>` · ☑ **invalid** — `Enter` on a row whose region was invalidated by a re-render, `<TC-s>` · ☑ **error** — `o` with no focused row posts **zero** `OpenInHexRequested`, `<TC-t>`
  - **⚠️ Mouse preservation (N4a, not negotiable):** single click = inspect, double click = hex (`on_region_row_activated:2422`, gated on `event.chain >= 2` at `:2461-2471`). The keyboard path adds a second entry point to the **same** handler; it does not re-decide the click policy. Pinned by the existing `tests/test_map_click_chain.py`, run in full at this increment's gate.

---

### HLR-116 — the inspector is populated without operator input
- **Traceability:** US-77-6
- **Statement:** When the Memory Map completes a render for a loaded image with at least one region, the panel **shall** populate `#map_detail_body` with the first region's detail, and **shall not** post `MemoryMapPanel.OpenInHexRequested` as a consequence of doing so.
- **Rationale (informative):** Measured today with a file fully loaded: `#map_detail_body` = `"Click a region to inspect it - double-click to open in hex."` (`_DETAIL_HINT`, `screens_directionb.py:1723`), written unconditionally by `_reset_detail()` at `:1896` on every render. The pane is dead space until a click. The second clause is the **hazard** clause: auto-selection must inspect, never navigate — otherwise loading a file would teleport the operator to the hex screen.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k "autoselect" -v` + full `tests/test_tui_directionb.py` (C-34)
- **Numeric pass threshold:** `#map_detail_body` text `!= _DETAIL_HINT` and contains the first region's start address in `0x%08X` form; **exactly 0** `OpenInHexRequested` messages observed across the render
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** with a file loaded, the inspector already shows the first region — no click needed, and the screen does not change under the operator.
  - **Shipped surface:** as HLR-111, reading `#map_detail_body` **immediately after** `update_memory_map()`, with no click and no keypress
  - **Deliverable + observation:** `#map_detail_body` rendered text; and a message-capture arm over `OpenInHexRequested`.
  - **Acceptance test(s):** `<AT-o>` inspector non-hint and names region 1's start, zero clicks · `<AT-p>` **zero** `OpenInHexRequested` posted during auto-selection
  - **Boundary catalog (QC-3):** ☑ **empty** — no ranges → the hint is **retained** (auto-select must not fabricate a region), `<TC-u>` · ☑ **boundary** — exactly one region, `<TC-v>` · ☑ **boundary** — re-render after a **file switch**: the inspector shows the **new** file's first region, not the old file's (⚠️ the state-lifetime rule — `_selected_cell_start` at `:1768` survives across renders and `_reset_detail` at `:2329` is what clears it; auto-select must run **after** that reset, not before), `<TC-w>` · ☑ **invalid** — a region with zero bytes, `<TC-x>` · ☐ **error** — **N/A:** the path reuses `build_detail_text`, already hardened (C-17 / MN-4, `REQUIREMENTS.md:4840-4846`).

---

### HLR-117 — the selected region row is visually distinguishable
- **Traceability:** US-77-7
- **Statement:** While a region is selected, the corresponding region row **shall** carry a selection CSS class that no unselected region row carries, and at most one region row **shall** carry it at any time.
- **Rationale (informative):** Measured today: `row_classes = [['map-region-row','band-constant'], ['map-region-row','band-medium'], …]` — the base class plus the band token, and nothing else. The panel already tracks the selection in `self._selected_cell_start` (`:1768`, set at `:2463`, cleared at `:2329`); the state exists and is simply not rendered. Style-only motion. **Colour discipline holds:** the selection cue must not be a colour override of the `band-*` token — the band's colour and glyph are the entropy channel (C-10) and must survive selection.
- **Validation:** `test`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k "selection" -v` + full `tests/test_tui_directionb.py` (C-34)
- **Numeric pass threshold:** exactly **1** row carries the selection class after a selection (today **0**); the selected row still carries its original `band-*` token (set equality on the non-selection classes, before vs after)
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the operator can see which region they are looking at.
  - **Shipped surface:** as HLR-111, reading `list(r.classes)` per `RegionRow` after a selection
  - **Deliverable + observation:** the class set on each `RegionRow`. ⚠️ **C-32/C-37:** a class is a *style intent*, not a painted result. Because the cue is CSS-only and its painted colour is not observable at `render_line` (C-37), the AT asserts the **class**, and a **separate** arm asserts the **CSS rule exists** in `styles.tcss` by inspection — neither alone is sufficient, and this split is stated rather than assumed.
  - **Acceptance test(s):** `<AT-q>` exactly one row carries the selection class after selecting region 3; the other four do not · `<AT-r>` the selected row's `band-*` token is unchanged by selection · `<AT-s>` selecting a different row moves the class (asserts the **old** row lost it — the arm that catches an append-only implementation)
  - **Boundary catalog (QC-3):** ☑ **empty** — no rows → no selection class anywhere, `<TC-y>` · ☑ **boundary** — first and last row, `<TC-z>` · ☑ **boundary** — re-render while selected: the class lands on the row for the **same address**, not the same index, `<TC-aa>` · ☑ **invalid** — the selected address no longer exists after a file switch → **no** row carries the class (not row 0 by accident), `<TC-ab>` · ☐ **error** — **N/A:** style-only.

---

## 4. Low-level requirements (LLR)

> ID format `LLR-<HLR>.<M>`. Every LLR traces to a parent HLR. Every named symbol carries a grep-verified `file:line` or a `NEW — created in Phase 3` flag; every geometry constant carries a measurement or an `assumed` flag.

### HLR-111 → LLR-111.x

**LLR-111.1 — widths scale by mapped bytes, not by address span**
- **Traceability:** HLR-111
- **Statement:** `MemoryMapPanel._build_band_widgets` **shall** compute each run's segment width from that run's share of the **mapped byte total** (`Σ run_bytes`), not from its share of `total_span`.
- **Symbols:** `_build_band_widgets` `screens_directionb.py:1988`; the expression to replace `screens_directionb.py:2066` (`seg_width = max(1, round(_BAND_BAR_WIDTH * run_bytes / total_span))`); `total_span` bound at `:2043`.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k memmap_width -v`
- **Numeric pass threshold:** monotonic over all run pairs **and** ≥1 strict inequality on the sparse fixture (today: strict = **False**, executed `probe77.py`)
- **Acceptance criteria:** runs of `256/256/256/200/62 B` no longer render `[1,1,1,1,1]`; the 62 B run is **not** wider than any 256 B run.

**LLR-111.2 — gaps fold to a size-independent marker**
- **Traceability:** HLR-111
- **Statement:** Each unmapped gap **shall** render as a marker whose column width is a fixed constant independent of the gap's byte size, and **shall** remain a plain `Static` carrying `map-band-seg map-band-gap` — **never** a `RegionRow` and **never** a `BandSegment`.
- **Symbols:** gap construction `screens_directionb.py:2056-2065`; `_MAP_GAP_HATCH = "╱"` `:253`; `RegionRow` `:1088`; `BandSegment` `:1172`. Fold-width constant **NEW — created in Phase 3**.
- **Geometry:** the fold-width value is `assumed — measure in Phase 3` against the 66-col @80×24 / **52-col @120×30** `#map_grid` (`REQUIREMENTS.md:4800`, the tighter regime).
- **Validation:** `test (integration)` + `inspection`
- **Executed verification:** `pytest tests/test_map_click_chain.py -k blast_radius -v` (the existing AC-6 guard, `tests/test_map_click_chain.py:309-337`)
- **Numeric pass threshold:** gap marker widths are **equal across all four gaps** despite spans of `16776960 / 16776960 / 33554176 / 67108408 B` (today: `[7,7,15,30]`, executed); `len([w for w in app.query(".map-band-seg") if isinstance(w, RegionRow)]) == 0`
- **Acceptance criteria:** the four measured gaps render at one common width; the existing blast-radius guard stays green **unmodified**.

**LLR-111.3 — the emitted column total is bounded for gapped images**
- **Traceability:** HLR-111
- **Statement:** For an image containing at least one unmapped gap, the sum of emitted segment widths **shall not** exceed `_BAND_BAR_WIDTH`.
- **Symbols:** `_BAND_BAR_WIDTH = 60` `screens_directionb.py:230`.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k memmap_budget -v`
- **Numeric pass threshold:** emitted total **≤ 60**; today **64** (executed, both regimes) — the predicate is RED pre-change
- **Acceptance criteria:** the predicate **quotes `_BAND_BAR_WIDTH`, never the literal `60`** (C-39: an AT quotes the constant, not its value); holds at ≥61 runs, where the floor alone would otherwise force overflow (`probe77b.py` CASE 4).

**LLR-111.4 — the gapless render is byte-identical (the C-12 control)**
- **Traceability:** HLR-111
- **Statement:** For an image containing no unmapped gap, the concatenated `.map-band-seg` content **shall** equal, character for character, a golden captured from the **pre-change** producer.
- **Symbols:** golden fixture file **NEW — created in Phase 3**, captured in **Inc-0, its own commit, before any production edit**.
- **Validation:** `test (integration)`
- **Executed verification:** `pytest tests/test_tui_map_big.py -k memmap_dense_golden -v`
- **Numeric pass threshold:** exact string equality
- **Acceptance criteria:** the golden is captured **from the shipped surface**, not from `_build_band_widgets` called directly (C-35). **Measured pre-change value for the reference dense fixture** (executed `probe77.py`, both regimes byte-identical):
  `'···············▒▒▒▒▒▒▒▒········▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓'` (**61** chars). ⚠️ This is **1 over budget** — the contradiction B-1 exists to resolve; under B-1/① that is expected and correct.
- **⚠️ C-42 encoding note:** the golden contains `·`, `░`, `▒`, `▓`, `╱`. It must be compared against the widget's runtime `render()` text, **never** against snapshot-export bytes (which spell spaces `&#160;`, C-42 mechanic 4) and **never** via a console `print` (the draft-time probe hit `UnicodeEncodeError` under cp1252 — recorded in §6.3 as a self-caught probe defect). If stored as a file it needs `-text` in `.gitattributes` (the `core.autocrlf` hazard).

**LLR-111.5 — C-40 mutation register for HLR-111's predicates**
- **Traceability:** HLR-111
- **Statement:** Each acceptance-bearing predicate of HLR-111 **shall** be accompanied by a recorded mutation that reddens it, and the mutation **shall** name the substituted VALUE, not the deleted operator.
- **Validation:** `inspection`
- **Acceptance criteria — the register (authored here, discharged at Phase 3):**

| Predicate | Declared subject appears in the expression? | Mutation that reddens it (substituted VALUE) | Verdict |
|---|---|---|---|
| `<AT-a>` monotonicity + strict | ✅ `run_bytes` **and** `seg_width` both appear | revert the divisor: `Σ run_bytes` → `total_span` | ✅ **gate** — measured RED today |
| `<AT-b>` column total ≤ budget | ✅ `_BAND_BAR_WIDTH` and the emitted widths both appear | substitute the fold width constant → the pre-change `max(1, round(W*gap/span))` | ✅ **gate** — measured 64 today |
| `<AT-c>` dense byte-golden | ✅ | substitute any width expression; also substitute `round` → `math.ceil` | ✅ **gate** |
| ~~charter draft #1~~ "every run ≥1 col" | ❌ — invariant under every candidate change, because `max(1, …)` guarantees it unconditionally | none exists | ❌ **REGRESSION PIN, not a gate — labelled as such and NOT used as an acceptance** |

### HLR-112 → LLR-112.x

**LLR-112.1 — ticks derive from run starts**
- **Traceability:** HLR-112 · **Statement:** `MapRuler` **shall** accept the ordered run start addresses plus the span end and **shall** emit one `.map-ruler-tick` per retained address, replacing the fixed `_TICK_COUNT = 5` percentile derivation.
- **Symbols:** `MapRuler` `screens_directionb.py:1234`; `_TICK_COUNT = 5` `:1274`; `MapRuler.compose` `:1293`; construction site `:2102` (`MapRuler(span_start, span_end)` — **signature changes**).
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_map_big.py::test_at072b_ruler -v` (re-derived) · **Numeric pass threshold:** **0** labels outside mapped ranges (today **3** of 5)
- **Acceptance criteria:** membership tested via the **frozen, read-only** `address_in_sorted_ranges` (`tests/test_tui_map_big.py:22-25` already imports it) — an independent oracle, not the producer's own arithmetic.

**LLR-112.2 — overlapping labels collapse**
- **Traceability:** HLR-112 · **Statement:** When two retained tick labels would occupy overlapping columns at the rendered ruler width, the ruler **shall** drop one and **shall** retain the span-start and span-end labels in preference to any interior label.
- **Geometry:** `assumed — measure in Phase 3` at **52 cols @120×30** (the tighter regime, `REQUIREMENTS.md:4800`). Each label is 8 hex digits with the `0x` prefix already dropped as a C-13.1 fallback (`:1245-1247`) — **that fallback is already spent and cannot be spent again.**
- **Validation:** `test (integration)` + `analysis` · **Executed verification:** `pytest tests/test_tui_map_big.py -k ruler_collapse -v` · **Numeric pass threshold:** **0** overlapping column ranges at both 66 and 52 cols; ≥2 labels always retained
- **Acceptance criteria:** `<AT-f>` drives a fixture with more runs than the ruler has columns.

**LLR-112.3 — the `_TICK_COUNT == 5` contract is amended, not silently broken, at all six citation sites**
- **Traceability:** HLR-112 · **Statement:** The batch **shall** record a Before/After amendment for `R-TUI-072` and for `LLR-072.3`, and **shall** update every surviving citation of the retired 5-tick clause.
- **Symbols — the executed census (P-22), all six sites:** `screens_directionb.py:1239`, `:1273`, `:1300`, `:2002`; `tests/test_tui_map_big.py:118`; `tests/test_tui_snapshot.py:670`. Plus the requirement text at `REQUIREMENTS.md:4787-4793` and `:4190-4191`.
- **Validation:** `inspection` · **Executed verification:** `grep -rn 'LLR-072\.3\|exactly 5 tick\|_TICK_COUNT' s19_app tests REQUIREMENTS.md` · **Numeric pass threshold:** **0** surviving assertions of "exactly 5 ticks"; **6** citation sites reconciled
- **Acceptance criteria:** §6.5 Amendment A and Amendment B both present with Before/After text.

### HLR-113 → LLR-113.x

**LLR-113.1 — dual readout composition**
- **Traceability:** HLR-113 · **Statement:** `build_stats_text` **shall** compose the mapped total and image span through `insight_style.human_bytes` and **shall** render the coverage percentage with at least four fractional digits.
- **Symbols:** `build_stats_text` `screens_directionb.py:2275`; the `Coverage` f-string `:2304`; `human_bytes` `insight_style.py:124`; `CoverageStats` `:966`.
- **Validation:** `test (unit)` · **Executed verification:** `pytest tests/test_tui_directionb.py -k map_stats -v` · **Numeric pass threshold:** the composed text contains `1.0 KiB`, `128.0 MiB`, `0.0008%` for the measured fixture (**all three executed at draft time**, P-27/P-28)
- **Acceptance criteria:** no new arithmetic over `ranges` — every input is an existing `CoverageStats` field (LLR-041.7 preserved, P-29).

**LLR-113.2 — humanized largest gap**
- **Traceability:** HLR-113 · **Statement:** The largest-gap statistic **shall** render through `human_bytes`.
- **Symbols:** `screens_directionb.py:2309` (`f"Largest gap: {stats.largest_gap} bytes\n"`).
- **Validation:** `test (unit)` · **Executed verification:** as LLR-113.1 · **Numeric pass threshold:** renders `64.0 MiB`; the substring `67108408` is **absent** (executed: `human_bytes(67108408) == '64.0 MiB'`)
- **Acceptance criteria:** ⚠️ **C-40:** the absence half (`"67108408" not in text`) is **green on an empty strip**. It must be paired with the presence half (`"64.0 MiB" in text`). Absence alone is a pin, not a gate.

### HLR-114 → LLR-114.x

**LLR-114.1 — legend rows leave `_build_band_widgets`**
- **Traceability:** HLR-114 · **Statement:** `_build_band_widgets` **shall not** construct or return a `.map-band-legend` container.
- **Symbols:** legend loop `screens_directionb.py:2084-2092`; return list `:2100-2105`; CSS `.map-band-legend` `styles.tcss:849`, `.map-legend-row` `styles.tcss:856`.
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_directionb.py -k legend -v` **and the whole file** (C-34) · **Numeric pass threshold:** `len(app.query(".map-legend-row")) == 0` (today **4**) **while** `len(app.query(".map-band-seg")) >= 5`
- **Acceptance criteria:** ⚠️ **C-38:** `.map-legend-row` is also the class used by the app-wide legend screen's rows — the query must be scoped to `#map_grid`, or the assertion will falsely redden when the legend screen is open. `assumed — verify the legend screen's row classes in Phase 3`.

**LLR-114.2 — the legend screen is untouched**
- **Traceability:** HLR-114 · **Statement:** The `k` binding and `action_show_legend` **shall** remain unmodified.
- **Symbols:** `Binding("k", "show_legend", "Legend", show=True)` `app.py:1359`; `action_show_legend` `app.py:5867`; the per-screen legend scoping map `app.py:5706`.
- **Validation:** `inspection` + `test (integration)` · **Executed verification:** `git diff main -- s19_app/tui/app.py` over the binding block · **Numeric pass threshold:** **0** diff lines in `app.py:1345-1375`; `<AT-i>` green
- **Acceptance criteria:** if `app.py`'s binding block is touched at all, **C-28 shared-chrome snapshot census across every screen's cells** is mandatory.

### HLR-115 → LLR-115.x — 🔴 void unless B-2/① is ruled

**LLR-115.1 — rows become focusable**
- **Traceability:** HLR-115 · **Statement:** `RegionRow` **shall** be declared focusable.
- **Symbols:** `class RegionRow(Static)` `screens_directionb.py:1088`. `can_focus` **NEW — created in Phase 3** (`grep 'can_focus' screens_directionb.py` → **0 hits**, P-25).
- **⚠️ Textual internal-name shadowing:** any new member added to `RegionRow` must be checked against `dir(Widget)` — a `_nodes`/`_context` collision produces a silent mount crash **with no traceback**. `MapRuler` already documents this discipline at `:1249-1250`.
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_map_big.py -k keyboard_focus -v` · **Numeric pass threshold:** `sum(r.can_focus for r in app.query(RegionRow)) == 5` (today **0**, executed)

**LLR-115.2 — arrow movement, with stated edge behaviour**
- **Traceability:** HLR-115 · **Statement:** While a region row has focus, `↑` **shall** move focus to the previous row and `↓` to the next row in ascending address order; at the first row `↑` **shall** leave focus unchanged and at the last row `↓` **shall** leave focus unchanged.
- **⚠️ C-16:** Textual gives **no** spatial arrow-focus for free. `assumed — verify in target framework at Phase 3`. If the framework's default `focus_next`/`focus_previous` traversal does not match address order, an explicit handler is required.
- **Validation:** `test (e2e)` · **Executed verification:** `pytest tests/test_tui_map_big.py -k keyboard_move -v` · **Numeric pass threshold:** after `press("down")` from row *i*, `app.focused.region_start` equals row *i+1*'s start; at the last row it is unchanged
- **Acceptance criteria:** **`pilot.press` only. A test that calls `.focus()` does not discharge this LLR** — that is verbatim the batch-27 C-16 origin.

**LLR-115.3 — `Enter` inspects, `o` navigates, reusing the single click-policy site**
- **Traceability:** HLR-115 · **Statement:** `Enter` **shall** cause the focused row to post `RegionRow.Activated` with `chain = 1`, and `o` **shall** cause it to post `RegionRow.Activated` with `chain = 2`.
- **Symbols:** `RegionRow.Activated` `:1123`, its `chain` parameter `:1141-1147` (defaults to `1` = inspect); `on_region_row_activated` `:2422`, the chain gate `:2461-2471`.
- **Rationale (informative):** routing both keys through the existing message keeps the single/double policy in **exactly one place** (`:1164-1165`), so the keyboard cannot drift from the mouse.
- **Validation:** `test (e2e)` · **Executed verification:** `pytest tests/test_tui_map_big.py -k keyboard_action -v` + **full** `tests/test_map_click_chain.py` · **Numeric pass threshold:** `Enter` → **0** `OpenInHexRequested`, inspector populated; `o` → **exactly 1** `OpenInHexRequested` with the focused start

**LLR-115.4 — no app-wide binding is shadowed except `o`, and that one is declared**
- **Traceability:** HLR-115 · **Statement:** `RegionRow.BINDINGS` **shall not** bind `j` or `k`, and the batch **shall** carry a regression test that `o` still triggers `open_workarea` when no region row has focus.
- **Symbols:** `Binding("j","dump_a2l_json",…)` `app.py:1356`; `Binding("k","show_legend",…)` `app.py:1359`; `Binding("o","open_workarea",…)` `app.py:1352`.
- **Validation:** `test (e2e)` + `inspection` · **Executed verification:** `pytest tests/test_tui_map_big.py -k "keyboard_no_shadow" -v`; `grep -n 'BINDINGS' -A8 s19_app/tui/screens_directionb.py` · **Numeric pass threshold:** the literal keys `"j"` and `"k"` appear **0 times** in `RegionRow.BINDINGS`; `<AT-m>` and `<AT-n>` green
- **Acceptance criteria:** this LLR **is** the discharge of B-2. Executed basis: `probe77c.py` on textual 8.2.8 showed `press k` with the row focused fires `ROW.k` and **never** `APP.k`.

### HLR-116 → LLR-116.x

**LLR-116.1 — auto-select after reset**
- **Traceability:** HLR-116 · **Statement:** `render_ranges` **shall** select the first ordered region **after** `_reset_detail()` has run and after the region rows are mounted.
- **Symbols:** `render_ranges` `:1808`; `_reset_detail()` call site `:1896`; `_reset_detail` body `:2313-2330` (it sets `self._selected_cell_start = None` at `:2329`); `_ordered_ranges` assigned `:1923`; mount `:1927-1929`.
- **Rationale (informative):** ordering matters — `_reset_detail` is the clear step, so selecting before it would be erased. This is also the file-switch correctness point (`<TC-w>`).
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_map_big.py -k autoselect -v` · **Numeric pass threshold:** `#map_detail_body != _DETAIL_HINT` and contains the first region's `0x%08X` start

**LLR-116.2 — auto-selection never navigates**
- **Traceability:** HLR-116 · **Statement:** Auto-selection **shall not** post `MemoryMapPanel.OpenInHexRequested`.
- **Symbols:** `OpenInHexRequested` post site `screens_directionb.py:2422`-block.
- **Validation:** `test (e2e)` · **Executed verification:** as LLR-116.1 · **Numeric pass threshold:** **exactly 0** `OpenInHexRequested` observed across a full render
- **Acceptance criteria:** ⚠️ **C-40:** "zero messages" is green on a render that never happened. The arm must co-assert that `#map_detail_body` was populated in the same run.

### HLR-117 → LLR-117.x

**LLR-117.1 — selection class applied by address**
- **Traceability:** HLR-117 · **Statement:** The panel **shall** apply a selection CSS class to the region row whose `region_start` equals `self._selected_cell_start`, and to no other row.
- **Symbols:** `self._selected_cell_start` `:1768` (init), `:2463` (set), `:2329` (cleared); `RegionRow.region_start` `:1157`; row construction `_build_region_row` `:2107`. Selection class token **NEW — created in Phase 3**.
- **Validation:** `test (integration)` · **Executed verification:** `pytest tests/test_tui_map_big.py -k selection -v` · **Numeric pass threshold:** exactly **1** row carries it (today **0**, executed); matching is by **address**, not index

**LLR-117.2 — the band channel survives selection**
- **Traceability:** HLR-117 · **Statement:** Applying or removing the selection class **shall not** add, remove or override any `band-*` class on the row.
- **Symbols:** `.band-constant/.band-low/.band-medium/.band-high` `styles.tcss:665/669/673/677`; `entropy_style.band_style`.
- **Rationale (informative):** colour and glyph are the entropy channel and the colour-blind cue (C-10). A selection style that repaints the row destroys the information the row exists to carry.
- **Validation:** `test (integration)` + `inspection` · **Executed verification:** as LLR-117.1; plus `grep -n '<selection-class>' s19_app/tui/styles.tcss` · **Numeric pass threshold:** `set(classes) - {selection}` is **identical** before and after selection; the CSS rule sets no `color:` property
- **Acceptance criteria:** the CSS rule is asserted by **inspection of `styles.tcss`** in addition to the class assertion — per C-37 the painted colour of a CSS-driven style is **not** observable at the widget's `render_line`, so a runtime colour assertion would be reading the wrong layer.

---

## 5. Validation strategy

### 5.1 Methods
**Layer A (white-box, `TC-NNN`):** `test (unit)` / `test (integration)` / `test (e2e)` / `inspection` over the HLR/LLR mechanism.
**Layer B (black-box, `AT-NNN`):** Textual Pilot e2e — `App.run_test(size=…)` → `action_show_screen("map")` → `update_memory_map()` → query the shipped widget tree. **Never** `_build_band_widgets` called directly (C-35). Both regimes `(80,24)` and `(120,30)`, per `tests/test_tui_map_big.py:32`.

**Standing observation rules for this batch:**
1. **Read the layer that holds the fact** (C-32/C-37): text → `#map_stats_body` / `#map_detail_body`, **never** `#map_stats` / `#map_detail` (containers; they render `Blank`). Geometry → `region`. Colour intent → `render().spans`, not `render_line`.
2. **Every absence assertion carries a presence co-assertion** (C-40). Listed per-AT above; there are four: `<AT-h>`, `<AT-p>`, and the negative halves of `<AT-g>` and `<AT-l>`.
3. **Every threshold quotes its constant, not its value** (C-39): `_BAND_BAR_WIDTH`, `_TICK_COUNT`, `_DETAIL_HINT`, `_MAP_GAP_HATCH`.
4. **C-34:** every increment touching `screens_directionb.py` or `styles.tcss` runs the **full** `tests/test_tui_directionb.py` at its gate, not a `-k` subset.
5. **`tui-ci` form:** PRs run `-m "not slow"`; the **full** suite runs before merge. Every ledger figure states which form produced it (21 tests are marked slow).

### 5.2 Dual-traceability

**Behavioral chain (black-box):**

| US | Observable outcome | Shipped surface | AT | RED today? |
|---|---|---|---|---|
| US-77-1 | bar widths order with region size; strip within budget; dense render unchanged | `.map-band-seg` after `update_memory_map` | `<AT-a>`,`<AT-b>`,`<AT-c>` | ✅ strict=`False`; total=`64`; golden n/a |
| US-77-2 | every ruler label names a mapped address | `.map-ruler-tick` | `<AT-d>`,`<AT-e>`,`<AT-f>` | ✅ 3 of 5 unmapped |
| US-77-3 | dual mapped/span readout, real %, humanized gap | `#map_stats_body` | `<AT-g>` | ✅ `0.00%` + raw bytes |
| US-77-4 | no legend in the map body; `k` still opens it | `#map_grid` query + `press("k")` | `<AT-h>`,`<AT-i>` | ✅ 4 legend rows |
| US-77-5 | keyboard-only reach and act; no key lost | `pilot.press` | `<AT-j>`…`<AT-n>` | ✅ 0 focusable |
| US-77-6 | inspector populated with zero clicks | `#map_detail_body` | `<AT-o>`,`<AT-p>` | ✅ shows `_DETAIL_HINT` |
| US-77-7 | selected row visually distinct | `RegionRow.classes` | `<AT-q>`,`<AT-r>`,`<AT-s>` | ✅ 0 rows classed |

**Functional chain (white-box):** HLR-111 → LLR-111.1…5 → `<TC-a>`…`<TC-e>` · HLR-112 → LLR-112.1…3 → `<TC-f>`…`<TC-i>` · HLR-113 → LLR-113.1…2 → `<TC-j>`…`<TC-m>` · HLR-114 → LLR-114.1…2 → `<TC-n>`,`<TC-o>` · HLR-115 → LLR-115.1…4 → `<TC-p>`…`<TC-t>` · HLR-116 → LLR-116.1…2 → `<TC-u>`…`<TC-x>` · HLR-117 → LLR-117.1…2 → `<TC-y>`…`<TC-ab>`.

Both chains exist for all seven stories. ✅

### 5.3 Batch acceptance criteria
- 100 % of LLRs covered by ≥1 TC with a pass result.
- Every US has ≥1 passing AT observing its outcome through the shipped surface, with boundary + negative evidence.
- **Every AT demonstrated RED on the pre-change tree** (the RED-today column above is executed for all seven).
- 0 blocker findings at the merge gate; frozen-engine diff **= 0** (source **and** `_ENGINE_TEST_FILES`, C-27).
- Full suite green (**baseline 2514 passed / 2 skipped / 3 xfailed**, `PLAN.md:126`, FULL form).

### 5.4 AT/TC reservation sizing (for the registry PR — **no ids minted here**)
**19 `AT` + 28 `TC` = 47 ids.** Registry `_meta.next_free` read 2026-08-01: `AT-282` / `TC-613`. Reservation is a **separate PR merged to `main` before the batch's work** (`docs/engineering-rules.md:46`) — a reservation on an unmerged branch prevents nothing.
⚠️ **Consider batch-scoped ids** (`AT-B77-01`, `TC-B77-01`): `docs/engineering-rules.md:48` prefers them, they cannot collide by construction, and 47 is a large draw on the global pool. **Recommend batch-scoped** — flagged for the operator.

---

## 6. Appendices

### 6.1 Extended glossary — see §1.3.

### 6.2 Relevant design decisions
- **D-2 (Phase 0, autonomous):** fold P-15 into US-77-1. **Upheld, but its premise is corrected** — P-18 shows the overflow is not solely a flooring defect, and that correction is what surfaced B-1.
- **D-3 (Phase 0, autonomous):** replace charter draft #1 with width monotonicity. **Upheld and now executed on both arms** (P-16 negative, P-17 positive).
- **NEW D-7 (architect, autonomous):** HLR/LLR ids allocated from **111**, derived over the union corpus, not from `REQUIREMENTS.md` alone (P-20).
- **NEW D-8 (architect, autonomous):** `LLR-072.3`'s "dangling citation" carry is **withdrawn** — the id is defined (P-21). The amendment scope doubles instead.

### 6.3 Open risks and carries

| # | Risk / carry | Disposition |
|---|---|---|
| **C-77-a** | 🆕 **Dense-image column drift.** The shipped width expression is off-budget on **37.3 %** of gapless images (20.6 % over, worst +3; 16.7 % under, worst −2) purely from `round()` accumulation — executed, `probe77b.py` CASE 3. | **Lane-A carry** under B-1/①. Becomes in-scope under B-1/②. |
| **C-77-b** | 🆕 **`_BAND_BAR_WIDTH` is unbounded above in segment count.** At >60 segments the `max(1,…)` floor alone guarantees overflow (61 segments → 61 cols; 100 → 100). LLR-111.3 must hold here too — `<TC-c>` is that arm. | In scope, HLR-111 |
| **C-77-c** | 🆕 **`REQUIREMENTS.md` is not an index of the HLR namespace.** `HLR-108/109/110` are live in shipped tests and absent from it. A future batch deriving high-water from that file alone **will** collide. | **Lane-B (process) carry** |
| **C-77-d** | **US-77-8** — log-scale microbar + column-aligned rows | Lane-A carry (Phase-0 D-4) |
| **C-77-e** | **Variant B** — two-lane map | Lane-A carry |
| R-1 | `tests/test_tui_map_big.py` blast radius | **Widened by P-26 to 13 sites / 3 files.** C-26 reverse-grep over all three before any increment. |
| R-2 | Fold markers becoming `RegionRow`s | **Downgraded.** Gaps are already inert `Static`s (P-30) **and** `tests/test_map_click_chain.py:309-337` is an existing guard that would catch it. |
| R-3 | Textual gives no spatial arrow-focus (C-16) | `assumed — verify Phase 3`; AT presses real keys (LLR-115.2) |
| R-4 | Snapshot drift | C-22 per-cell; **regen only in canonical CI** (textual **8.2.8**, verified by execution); C-28 if any `show=True` binding is added |
| R-5 | Markup injection via new label paths | **B3 holds by construction** — every new label is a count, an address or a constant band label. C-17 re-check at Phase 2. |
| **F-1** | 🆕 **Self-caught probe defect (recorded, not hidden).** The draft-time probe raised `UnicodeEncodeError: 'charmap' codec` printing the strip under Windows cp1252, and separately a `PermissionError` on temp cleanup holding `s19tui.log`. Neither corrupted a measurement — both aborted loudly. Recorded because the **encoding** failure is the same family as the un-encoded control candidate *"assert the emitted encoding"* (8+ occurrences project-wide) and it landed on my own probe. Fixed with `PYTHONIOENCODING=utf-8`; the golden in LLR-111.4 carries the resulting C-42 note. | recorded |

### 6.4 Phase-1 reconciliation log

| Decision | What changed | Parent HLR re-read? | Body edit landed? |
|---|---|---|---|
| **D-7** | HLR ids 111–117 instead of 107–113 | n/a — allocation, no threshold | §3 preamble + every HLR heading |
| **D-8** | `LLR-072.3` exists → 2 amendments not 1 | HLR-112 re-read: its Rationale now names **both** `R-TUI-072` and `LLR-072.3` | §3 HLR-112 Rationale; §4 LLR-112.3 Symbols; §6.5 Amendments A **and** B |
| **B-1** | HLR-111's budget clause scoped to gapped images | HLR-111 statement re-written with three explicitly scoped clauses | §3 HLR-111 Statement; §4 LLR-111.3 (gapped) and LLR-111.4 (gapless) |
| **B-2** | `j`/`k` struck from US-77-5's keymap | HLR-115 statement gained the final anti-regression clause; HLR-114's Rationale now names the dependency | §3 HLR-115 Statement (final clause); §4 **LLR-115.4** (new); §3 HLR-114 `<AT-i>` |
| **P-26** | blast radius 2 → 13 sites | no HLR threshold changed | §2.7 P-26; §6.3 R-1 |

*(Body-first ordering observed: every §3/§4 line above was written before this table pointed at it.)*

### 6.5 Requirement amendments (Before / After)

#### Amendment A — `R-TUI-072` (`REQUIREMENTS.md:4787-4793`), ruler clause only

- **Before** (verbatim, `REQUIREMENTS.md:4789-4791`):
  > "…and render a NEW **address ruler** beneath the strip with **exactly 5 tick labels** at 0/25/50/75/100 % of the address span — tick 0 % == span start and tick 100 % == span end."
- **After:**
  > "…and render a NEW **address ruler** beneath the strip with **one tick label per mapped region start plus one for the span end**, collapsed where labels would overlap at the rendered width, and **retaining the span-start and span-end labels in preference to any interior label**. No tick label shall name an address that falls in an unmapped gap."
- **Deleted tokens:** "exactly 5 tick labels", "0/25/50/75/100 %", `_TICK_COUNT = 5` as a fixed contract.
- **New tokens:** per-region-start ticks, overlap collapse, the no-unmapped-address invariant.
- **Preserved (unchanged):** the `╱` hatch clause; humanized sizes via `human_bytes`; entropy colour + texture flowing solely from `entropy_style`; the `band-*`/`sev-*` separation; the "extends R-TUI-060 / R-TUI-041, nothing superseded" relation; the C-13.1 `0x`-prefix-dropped label form (already spent, `screens_directionb.py:1245-1247`).
- **Parent re-read:** `R-TUI-060`'s §6.5 Amendment B block (`REQUIREMENTS.md:4190-4191`) restates "**exactly 5 ticks at 0/25/50/75/100 % of the span**" and **must be amended in the same edit** — it is a second copy of the retired clause.
- **Re-derived verifier:** `tests/test_tui_map_big.py::test_at072b_ruler`. **Its `assert len(ticks) == 5` is retired**; the surviving half (first == span start, last == span end) is re-derived as `<AT-e>`, and the new invariant as `<AT-d>`. ⚠️ The node **is currently passing** — it is not a broken test being fixed, it is a **live acceptance being deliberately invalidated**, which is why this block exists.

#### Amendment B — `LLR-072.3` (`.dev-flow/2026-07-15-batch-47/01-requirements.md:508`)

- **Before** (verbatim):
  > "**Statement:** A NEW ruler widget beneath the strip shall render 5 tick labels at 0/25/50/75/100 % of the address span, tick 0 % == span start and tick 100 % == span end."
- **After:**
  > "**Statement:** The ruler widget beneath the strip shall render one tick label per mapped region start plus one for the span end, shall collapse labels that would overlap at the rendered width, and shall render no label naming an address in an unmapped gap; the span-start and span-end labels shall be retained in preference to any interior label. **Superseded in batch-77 by `LLR-112.1` / `LLR-112.2` (HLR-112 / US-77-2).**"
- **Deleted tokens:** "5 tick labels", "0/25/50/75/100 %".
- **New tokens:** per-region-start derivation, overlap collapse, the no-unmapped-address invariant, the supersession pointer.
- **Parent re-read:** `HLR-072` (batch-47 artifact) — its other children `LLR-072.1` (hatch), `LLR-072.2` (humanized sizes), `LLR-072.4` (the band-bands amendment) are **untouched**. Only the ruler child changes.
- **⚠️ Convention note (P-21):** amending an LLR body means editing a **prior batch's Phase-1 artifact**. That is the only place LLR bodies exist in this project (`REQUIREMENTS.md` defines zero). If the operator prefers those artifacts be immutable, the alternative is a supersession note in `REQUIREMENTS.md` plus this document's §6.5 as the authority. **Open question OQ-3.**

---

## 7. Increment plan (dependency-ordered, ≤5 files each)

| Inc | Content | Files | Gate |
|---|---|---|---|
| **Inc-R** | **AT/TC id reservation** — `RESERVED` rows, **its own PR, merged to `main` first** | `AT-TC-REGISTRY.jsonl` (1) | `tests/test_id_registry.py` G1–G7 green |
| **Inc-0** | **Byte-golden capture of the dense gapless strip** from the **pre-change** producer, in its own commit before any production edit (the C-12 control for LLR-111.4) | `tests/test_tui_map_big.py`, golden fixture, `.gitattributes` (3) | golden committed; `git show` confirms the stored blob's bytes (not the file handed to git) |
| **Inc-1** | **HLR-111** — width basis, gap fold, column bound. *Gated on B-1.* | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_map_big.py`, `REQUIREMENTS.md` (4) | full `test_tui_directionb.py` (C-34) + full `test_map_click_chain.py` (blast radius) |
| **Inc-2** | **HLR-112** — ruler + **Amendment A** + **Amendment B** + `AT-072b` re-derivation + the 6-site citation sweep | `screens_directionb.py`, `REQUIREMENTS.md`, `.dev-flow/2026-07-15-batch-47/01-requirements.md`, `tests/test_tui_map_big.py`, `tests/test_tui_snapshot.py` (5) | C-34 full run; `grep` census = 0 surviving "exactly 5 ticks" |
| **Inc-3** | **HLR-113** + **HLR-114** — stats re-format and legend demotion (both are `_build_band_widgets`/`build_stats_text` edits, no new widget class) | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_directionb.py`, `REQUIREMENTS.md` (4) | C-34 full run; `<AT-i>` legend-screen regression green |
| **Inc-4** | **HLR-115** — keyboard layer. *Gated on B-2.* Sequenced **after** Inc-3 so `<AT-i>` already pins the legend key before anything can shadow it. | `screens_directionb.py`, `tests/test_tui_map_big.py`, `REQUIREMENTS.md` (3) | C-34 full run + full `test_map_click_chain.py`; **C-28 census if any `show=True` binding is added** |
| **Inc-5** | **HLR-116** + **HLR-117** — auto-select and selection style | `screens_directionb.py`, `styles.tcss`, `tests/test_tui_map_big.py`, `REQUIREMENTS.md` (4) | C-34 full run |
| **Inc-6** | Snapshot regen — **canonical CI only** (textual 8.2.8 pin), collapsed into one PR | snapshot baselines | full suite; per-cell C-22 reasoning |

**Sequencing rationale (C-30):** the visual changes are per-screen, not app-wide, so no blanket `xfail` is needed — but the **snapshot regen is deliberately last** so every earlier increment marks only its own cells and the untouched cells stay live as regression guards. Inc-0 precedes Inc-1 because a golden captured after the change proves nothing. Inc-4 follows Inc-3 because the anti-shadow regression AT must exist before the shadowing code does.

---

## 8. Open questions

| # | Question | Blocks | Owner |
|---|---|---|---|
| **OQ-1** | **B-1** — which option for the budget-vs-byte-identity contradiction? (§2.8; architect recommends **①**) | Inc-1, HLR-111 | **OPERATOR** |
| **OQ-2** | **B-2** — which option for the `k` collision? (§2.8; architect recommends **①**) | Inc-4, HLR-115 | **OPERATOR** |
| **OQ-3** | May a prior batch's Phase-1 artifact be edited to record Amendment B, or should supersession live only in `REQUIREMENTS.md` + this §6.5? | Inc-2 file list | **OPERATOR** |
| **OQ-4** | Global AT/TC ids (47 from the pool) or **batch-scoped** `AT-B77-*` / `TC-B77-*`? (`docs/engineering-rules.md:48` prefers scoped; architect recommends **scoped**) | Inc-R | **OPERATOR** |
| **OQ-5** | Under B-1/①, is the residual dense drift ever *visible* — i.e. does the 61st column clip in a real snapshot cell? **Not measured.** If yes, B-1/② becomes correct. | HLR-111 wording | measure at Phase 3 |
| **OQ-6** | Does `.map-legend-row` also class the app-wide legend screen's rows? If so LLR-114.1's query must be scoped to `#map_grid` (C-38). `assumed — verify Phase 3`. | LLR-114.1 | Phase 3 |

---

## 9. Evidence checklist

| Item | ✓/✗ | Evidence |
|---|---|---|
| Constraints stated explicitly | ✓ | §2.4 — 10 constraints, each with a `file:line` or an executed value |
| ≥2 alternatives considered | ✓ | §2.8 — 4 options for B-1, 4 for B-2, each with expected result + consequences |
| Recommendation tied to constraints | ✓ | B-1/① tied to `PLAN.md:118` invariant priority; B-2/① tied to the measured 14-row `#map_grid` budget (`REQUIREMENTS.md:4800`) |
| Risks listed (operational, security, cost, lock-in) | ✓ | §6.3 — 5 carries + 5 risks + 1 self-caught probe defect; security = B3/C-17 under R-5 |
| Cost/latency estimated where relevant | ✓ | Column budgets and pane geometry are this design's cost axis: §2.4, LLR-111.3, LLR-112.2. No new I/O, no new compute (P-29 — pure re-formatting) |
| Diagram included when flow is non-trivial | ✗ | **Deliberate.** The flow is a single linear producer (`render_ranges` → `_build_band_widgets` → 4 mounted children); §2.1 states it in three lines. A diagram would restate, not clarify. |
| What would change the recommendation is stated | ✓ | §2.8 under both option tables; OQ-5 |
| Two-layer requirements: Acceptance block + AT, both chains | ✓ | Every HLR has a first-class **Acceptance (black-box)** block with observable outcome + shipped surface + deliverable/observation + AT placeholders + a QC-3 boundary catalog; §5.2 carries both chains for all 7 stories |
| Every AT demonstrated RED pre-change | ✓ | §5.2 "RED today?" column — 7 of 7, each from an executed transcript |
| No `AT-NNN`/`TC-NNN` minted | ✓ | placeholders only; §5.4 sizes the reservation |
| Normative keyword discipline | ✓ | **Executed self-check:** `shall` appears only in HLR/LLR **Statement** lines, in **quoted** requirement text (§2.7 P-21, §6.5 Before/After) and in the **proposed** statement texts inside the §2.8 option tables — nowhere in rationale, acceptance-criteria or flag prose. `grep -cE '^\s*-?\s*\*\*Statement:\*\*.*should'` → **0**. |
