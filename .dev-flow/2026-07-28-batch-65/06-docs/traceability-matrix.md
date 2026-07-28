# batch-65 — traceability matrix

**Audience:** engineers and reviewers auditing coverage of `R-TUI-098`.
**Purpose:** show that both traceability chains close with zero gaps, and name what is *not* covered.

**Scope:** backlog item **D1** only — bounding the declared-region report addendum producer
(`s19_app/tui/services/report_service.py::_addendum_lines`). OB-4 / F4 (the two unbounded report
tables), D2, OB-3 and OB-2 were held as carries and are **not** part of this batch's coverage.

**Branch** `claude/batch-65-addendum-producer-bound` · **base** `082ada9` · **HEAD** `ba5f09a`.
**Source of this mapping:** `REQUIREMENTS.md` §`R-TUI-098` (the shipped entry) and
`.dev-flow/2026-07-28-batch-65/04-validation.md` §1–§3. Nothing below is re-derived from memory.

---

## 1. Chain A — behavioural (black-box): `US → AT → observed outcome → node`

Every `AT` drives `generate_project_report(...)` and reads the **written report file**
(`_write_report()`, `tests/test_report_addendum_bound.py:723-774`); `AT-200` additionally reads the
`ReportViewerScreen` seam. **9/9 GREEN, 9/9 C-18 REALIZED.**

| US | AT | binds | observed outcome | collected node |
|---|---|---|---|---|
| US-B64-1 | **AT-194** | HLR-103 | marginal resident delta attributable to the addendum, ratio at `E: 2000 → 4000` **≤ 1.30**; observed `1.00` (`delta(2000)=52296`, `delta(4000)=52247`) | `test_report_addendum_bound.py::test_at194_addendum_marginal_resident_cost_flat_in_candidate_count` |
| US-B64-1 | **AT-196** | LLR-103.4 | byte identity vs the Inc-1 golden — **6/6 shapes, 0 differing bytes** | `…::test_at196_below_bound_report_is_byte_identical_to_the_inc1_golden` |
| US-B64-2 | **AT-197** | LLR-103.5 | notice names cut class `change-file issue`, dropped `2`, variant set **== `{v2, v3}`** (set equality, not containment) | `…::test_at197_notice_names_cut_class_dropped_count_and_exact_variant_set` |
| US-B64-2 | **AT-198** | LLR-103.3 | class total `≤ K` → **0** addendum notices; `K+1` → **exactly 1** (3 parametrised arms: `le_K` / `interior` / `K_plus_1`) | `…::test_at198_notice_presence_keys_on_the_class_total[le_K \| interior \| K_plus_1]` |
| US-B64-2 | **AT-199** | LLR-103.5 | document-derived text cannot forge a notice — 1 notice not 2; injected `>` escaped; `\r\n\t` collapsed | `…::test_at199_document_derived_text_cannot_forge_a_notice` |
| US-B64-2 | **AT-200** | LLR-103.5 | the notice is **delivered**: present in the written file **and** in the rendered viewer (`in_viewer == in_file`) | `tests/test_tui_report_seam.py::test_at200_truncation_notice_reaches_the_file_and_the_viewer` |
| US-B64-2 | **AT-201** | LLR-103.5 | a class that lost nothing is never named — named classes **==** cut classes | `…::test_at201_a_class_that_lost_nothing_is_never_named` |
| US-B64-2 | **AT-202** | LLR-103.5 | a variant that lost nothing is never named — named variants **==** variants with ≥ 1 dropped hit | `…::test_at202_a_variant_that_lost_nothing_is_never_named` |
| US-B64-2 | **AT-203** | LLR-103.5 | the notice sits under the **flooded** region's `### ` sub-section and is absent from the quiet one | `…::test_at203_notice_sits_under_the_flooded_regions_subsection` |

**Both stories have ≥ 1 file-observed AT.** US-B64-1 → `AT-194`, `AT-196`. US-B64-2 → `AT-197` … `AT-203`.

---

## 2. Chain B — functional (white-box): `US → HLR → LLR → TC → node`

Both user stories trace to the single high-level requirement; all six LLRs parent to it.
**19/19 live `TC` ids GREEN** (`python -m pytest tests/test_report_addendum_bound.py -q` → `29 passed`;
29 collected = 26 single-node ids + `AT-198`'s three parametrised arms).

```
US-B64-1 ┐
         ├─► R-TUI-098 ─► HLR-103 ─┬─► LLR-103.1 … LLR-103.6 ─► TC-480 … TC-499
US-B64-2 ┘                         └─► TC-480 (end-to-end shape)
```

| Requirement | statement, in short | TC | collected node | observed |
|---|---|---|---|---|
| **R-TUI-098** | the shipped requirement carries its residuals with their numbers | TC-497 | `test_tc497_shipped_requirement_carries_the_residuals_with_their_numbers` | 7-string grep passes + a flagged inspection half, two named signatures |
| **HLR-103** | bounded, order-preserving, self-disclosing production | TC-480 | `test_tc480_addendum_end_to_end_shape_at_the_boundary` | heading + sub-headings + `≤ K` hits + ≥ 1 notice, via `_write_report` |
| **LLR-103.1** | single **candidate consumption**, independent of `R` | TC-488 | `test_tc488_candidate_consumption_is_r_independent_overlapping` | `consumed == N` = `900/900` at `R = 1/8/64` |
| | | TC-489 | `test_tc489_candidate_consumption_is_r_independent_disjoint` | `consumed == N` = `300/300` at `R = 1/8/64` |
| | | TC-498 | `test_tc498_region_ops_equal_r_times_n_under_huge_tiny_geometry` | `A == R × N` = `300/2400/19200/76800` at `R = 1/8/64/256`, `N = 300` — a **disclosure counter**, not a bound |
| **LLR-103.2** | sound membership over **overlapping**, inclusive regions | TC-486 | `test_tc486_membership_is_sound_over_nested_overlapping_regions` | `0x5000` inside outer beyond inner end → 1 hit; `0x2000` emitted twice |
| | | TC-487 | `test_tc487_duplicate_and_equal_start_nested_regions_each_emit` | duplicate ×3 → 3 hits; equal-start-nested → 2 |
| **LLR-103.3** | per-(region, hit-class) admission cap; resident bound independent of `V` and `E` | TC-481 | `test_tc481_below_the_bound_renders_every_hit_and_no_notice` | `K-1`: 199 hits, 0 notices |
| | | TC-482 | `test_tc482_exactly_at_the_bound_renders_k_hits_and_no_notice` | `K`: 200 hits, 0 notices |
| | | TC-483 | `test_tc483_above_the_bound_is_capped_and_line_count_is_bounded` | `K+1` and 3000 both `≤ K`; addendum 208 lines ≤ bound 607 |
| | | TC-484 | `test_tc484_empty_and_negative_domain_renders_none_without_notice` | `None.` on 3 empty sub-cases; 1-byte region → 1 hit; `issue.address is None` skipped |
| | | TC-485 | `test_tc485_addendum_is_guarded_by_a_non_empty_declared_region_set` | the `R = 0` guard, asserted on `inspect.getsource(generate_project_report)` |
| | | TC-493 | `test_tc493_addendum_producer_peak_is_flat_in_the_candidate_count` | `peak(E=1000)=19801`, `peak(E=2000)=19802`, ratio `1.0001 ≤ 1.25` |
| **LLR-103.4** | byte identity **and emission order** below the bound | TC-491 | `test_tc491_golden_capture_harness_is_deterministic` | two run roots identical, and equal to the committed golden |
| | | TC-494 | `test_tc494_emission_order_is_result_summary_interleaved` | `['modification','issue','modification','issue','issue']`, fixture precondition `S ≥ 2` |
| **LLR-103.5** | the notice names the cut class, the count and the variants | TC-490 | `test_tc490_notice_caps_the_variant_list_with_a_plus_n_more_remainder` | 8 named + `+32 more` over 40 affected variants, read from the written file |
| | | TC-495 | `test_tc495_notice_renders_a_variant_id_exactly_as_a_hit_line_does` | notice rendering **==** hit-line rendering over 5 ids incl. a hostile string |
| | | TC-499 | `test_tc499_report_wide_truncation_is_not_an_addendum_notice` | a report-wide `> TRUNCATED:` fires; **0** addendum notices counted |
| **LLR-103.6** | the cap, the class labels and the notice format are module constants | TC-492 | `test_tc492_cap_labels_and_notice_format_are_module_constants` | four constants present; no bare `200` in the body; `K → 37` green over the `K`-derived nodes |

**LLR coverage: 6/6 = 100 %. Orphan nodes: 0. Phantom ids: 0.**

`LLR-103.1`, `LLR-103.2` and `LLR-103.6` carry **no direct `AT`** and that is by design, not a gap:
candidate consumption, region ops and constant-definition are readable only through an injected
instrument, and `01-requirements.md` §1.3 defines any such observable as a `TC`, never an `AT`. The
user-story coverage obligation is discharged by the file-observed `AT`s in Chain A.

---

## 3. Retired ids — allocated, then withdrawn, and **not reused**

| id | why retired | where the observable lives now |
|---|---|---|
| **AT-195** | bound to *"candidate consumption via an injected re-iterable counting sequence"* — not readable from the written report file, so it failed the batch's own `AT` definition, and it asserted the identical predicate on the identical instrument as `TC-488` | `TC-488` / `TC-489` / `TC-498` |
| **TC-496** | file-observed under a white-box id — promoted rather than kept | **`AT-200`** |

Confirmed at Phase 4 to bind nothing: `grep -rn "AT-195" tests/ s19_app/ --include=*.py` and the same
for `TC-496` both return **no matches**. Neither appears as a row in the shipped mapping table; the
only mention is the retirement sentence itself, which is the intended grep landing site.

Also retired at the **id-space** level, carried from batch-63's blocked D1 spec: `AT-164..167`,
`TC-440..454`, `R-TUI-095`, `HLR-100`, `LLR-100.1..4`. Their *content* was carried into this batch;
only the numbers were dropped, because reusing them would bind two different observables to one id.

---

## 4. Falsifiability — eleven nodes were GREEN before the fix

A passing run proves nothing about a node that already passed on `082ada9`. Eleven live ids
(twelve `§11.1` rows — `AT-198` occupies two) are **regression guards**, and each names a mutant arm
driven RED against the **implemented** producer. This is part of the coverage claim, not a footnote.

| Inc-1 GREEN guard | Inc-2 arm(s) driven RED |
|---|---|
| `AT-196` | `FIX-B`, `FIX-E`, `FIX-E(b)`, `FIX-G` |
| `AT-198[le_K]`, `AT-198[interior]` | `FIX-G` |
| `TC-481` | `FIX-C`, `FIX-G` |
| `TC-482` | `FIX-G` |
| `TC-484` | `FIX-NONE` |
| `TC-485` | **none — declared pure guard, in writing** (it guards unchanged code) |
| `TC-486` | `FIX-E`, `FIX-E(b)` |
| `TC-487` | `FIX-E(b)` |
| `TC-491` | `FIX-B`, `FIX-E`, `FIX-G` |
| `TC-494` | `FIX-B` |
| `TC-499` | `FIX-SCOPE` |

Three further arms — `FIX-H`, `FIX-I`, `FIX-A2` — were executed but belong to `AT-202`, `AT-203` and
`AT-197`/`TC-488`, which were **genuinely RED at Inc-1** and therefore outside the guard class.
Ten arms in total.

**Known limit, disclosed rather than absorbed:** the mutant harness lived in a scratch export and is
**not committed**, so this roster is a *record*, not something a later batch can re-execute — while
`01-requirements.md` §6.3 makes reproduction a gate condition. Phase 4 finding **F-4**; carried to
`.dev-flow/BACKLOG-CODE.md`.

---

## 5. What this batch does **not** cover

The requirement's own coverage claim is narrow on purpose. Each line below is a residual with an
executed number, carried in `.dev-flow/BACKLOG-CODE.md`, not a gap this matrix is papering over.

| not covered | number | where it lives |
|---|---|---|
| the report's **memory-exhaustion axis** — `_modifications_lines` / `_checklist_lines` are still uncapped | **988 B/entry**, ~11× the addendum's 86.5–93.9 B/hit | OB-4 / F4, pre-existing Lane-A item |
| the **`R` multiplier on the work axis** — relocated, not removed | region ops `500 / 4000 / 32000 / 128000` at `R = 1/8/64/256` for 500 candidates producing **one** hit | `TC-498` records it; residual §10.7 |
| **B-3(b)** — reduced `R×V×E → V×E`, not eliminated | the single `V×E` pass survives | residual §10.1 |
| **intra-class and cross-variant eviction** — disclosed by the notice, not prevented | first-`K` in attacker-controlled document order still decides what is shown | residual §10.4 |
| **region cardinality `R`** — no cap exists anywhere | `≈ 11.6 kB/region` with no cap firing, `≈ 20 kB/region` with all three firing; both lower bounds | residual §10.3 |
| **naming every affected variant** | above `ADDENDUM_NOTICE_VARIANTS_MAX = 8` the notice states how many, not which | residual §10.9 |
| duplicate / equal-start-nested region geometry, and the addendum line-count bound | white-box only (`TC-487`, `TC-483`) | Phase-4 gaps G-1, G-2 — non-gating; both consequences are pinned byte-for-byte by `AT-196` |
| three disclosed figures outside `TC-497`'s grep list | `≈ 11.6 kB/region`, `≈ 20 kB/region`, `86.5–93.9 B/hit` | Phase-4 gap G-3 — can decay silently |

---

## 6. Verification state at `ba5f09a`

| check | result |
|---|---|
| Layer A — `TC` | **19/19 GREEN** |
| Layer B — `AT` | **9/9 GREEN**, 9/9 C-18 REALIZED, 0 satisfied-in-parts |
| traceability gaps | **0**, both directions |
| full non-slow suite | `2233 passed · 2 skipped · 21 deselected · 3 xfailed` in `1659.77 s` · 29 snapshots · **exit 0** |
| suite delta | `2201 → 2233 (+32)`, reconciled exactly to the three touched test files (+29 / +1 / +2) |
| goldens re-baselined | **0** |
| frozen-engine diff | **0** across all seven frozen paths — `range_index.py` is **consumed, never modified** |
| production blast radius | **2 files, +570 / −35** (`report_service.py` +565/−33 · `report_addendum.py` +5/−2, docstring only) |
| Phase-4 verdict | **VALIDATED** — neither `iterate-to-refine` nor `iterate-to-fix` triggered |
