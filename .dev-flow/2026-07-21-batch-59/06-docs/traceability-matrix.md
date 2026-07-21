# Traceability Matrix — batch-59 (CRC Designer view-fidelity rebuild)

> Audience: reviewer / engineering. Purpose: prove full V-model coverage — every user story → HLR → LLR(s) → acceptance node — with no gaps.
> Source: `01-requirements.md` (5 US / 5 HLR / 12 LLR / 11 AT) reconciled against the Phase-4 realization table (`04-validation.md`).
> Status legend: **GREEN** = realized by a non-vacuous, through-surface on-disk node passing in the gate run (1772 passed). All nodes live in `tests/test_crc_designer_view.py` and drive the real `#screen_crc_designer` via `S19TuiApp.run_test()` + `press("0")`.

---

## 1. Full chain — US → HLR → LLR → AT/node → status

| US | HLR | LLR | AT | On-disk node (`tests/test_crc_designer_view.py`) | Status |
|----|-----|-----|----|---------------------------------------------------|--------|
| **US-L1** coverage-window hero | HLR-L1 | LLR-L1.1 (builder), LLR-L1.2 (widget + recompute wiring), LLR-L1.3 (color policy ≥2 colors) | AT-B59-01 | `test_coverage_window_renders_colored_glyphs_with_live_oracles` (:1079) | GREEN |
| US-L1 | HLR-L1 | LLR-L1.1, LLR-L1.2 | AT-B59-02 | `test_coverage_window_deltas_and_repins_on_range_edit` (:1108) | GREEN |
| US-L1 | HLR-L1 | LLR-L1.4 (boundary — empty image) | AT-B59-10 | `test_coverage_window_empty_state_no_image` (:1147) | GREEN |
| US-L1 | HLR-L1 | LLR-L1.4 (boundary — malformed range, mem_map intact) | AT-B59-11 | `test_coverage_window_malformed_range_markup_safe` (:1163) | GREEN |
| **US-L2** 3-column bench | HLR-L2 | LLR-L2.1 (bench composition), LLR-L2.3 (hero-row containers) | AT-B59-03 | `test_bench_columns_pairwise_distinct_ancestors` (:919) | GREEN |
| US-L2 | HLR-L2 | LLR-L2.2 (bench CSS + reflow), LLR-L2.4 (hero-row CSS + reflow) | AT-B59-04 | `test_bench_reflows_to_vertical_stack_when_narrow` (:957) | GREEN |
| **US-L3** verdict hero | HLR-L3 | LLR-L3.1 (verdict-hero styling), LLR-L2.3 (hero-row placement) | AT-B59-05 | `test_verdict_hero_center_aligned_in_hero_row` (:993) | GREEN |
| **US-L4** functional preservation | HLR-L4 | LLR-L4.1 (ids + handlers unchanged) | AT-B59-06 | `test_recompute_handler_fires_through_relayout` (:1264) | GREEN |
| US-L4 | HLR-L4 | LLR-L4.2 (existing suite green) | AT-B59-07 | the full 20 batch-58 CRC nodes (:61–:882), green unchanged | GREEN |
| **US-L5** fidelity gate with teeth | HLR-L5 | LLR-L5.1 (assertions derive from the tree) | AT-B59-08 | `test_bench_column_ancestry_teeth_computed` (:1299) | GREEN |
| US-L5 | HLR-L5 | LLR-L1.4 (hostile markup on the new sink), LLR-L5.1 | AT-B59-09 | `test_coverage_window_hostile_markup_renders_literally` (:1336) | GREEN |

**Security-realization node (not a numbered AT, locks the F2 window abort-contract):**

| Contract | LLR anchor | On-disk node | Status |
|----------|-----------|--------------|--------|
| Window honors `on_gap_conflict="abort"` — refuses the store word, agreeing with the sibling preview | HLR-L1 / LLR-L1.1 (reuses `evaluate_target`) | `test_coverage_window_dirty_gap_abort_refuses_store` (:1229) | GREEN |

---

## 2. LLR → node coverage (Layer A — every LLR realized)

| LLR | Statement (abbrev.) | Realizing node(s) | Status |
|-----|---------------------|-------------------|--------|
| LLR-L1.1 | `_render_coverage_window` builder — live glyphs + pinned oracle hexes, graceful empty note, no new math | AT-B59-01, AT-B59-02 | GREEN |
| LLR-L1.2 | window widget + `_recompute` wiring (inside the `NoMatches` guard) | AT-B59-02 (delta proves re-render on edit) | GREEN |
| LLR-L1.3 | color policy binds `$accent-calm` + `.sev-warning`, ≥2 distinct colors | AT-B59-01 (`len({span.style})>=2`) | GREEN |
| LLR-L1.4 | new-sink boundary + hostile input (markup-safe, no crash, mem_map intact) | AT-B59-09, AT-B59-10, AT-B59-11 | GREEN |
| LLR-L2.1 | bench composition — 3 columns, existing group ids preserved | AT-B59-03 | GREEN |
| LLR-L2.2 | bench + reflow CSS (`layout:horizontal` / `width-narrow` → vertical) | AT-B59-04 | GREEN |
| LLR-L2.3 | hero row `#crc_hero_row` = window + `#crc_top_right` (verdict + warnings), NOT in bench | AT-B59-05 | GREEN |
| LLR-L2.4 | hero-row reflow driven through a REAL narrow size (no hand-added class) | AT-B59-04 | GREEN |
| LLR-L3.1 | verdict-hero styling — `content-align: center middle`, `crc-hero` | AT-B59-05 | GREEN |
| LLR-L4.1 | ids + handlers unchanged (surgical; only `compose` / `_recompute`+1 / new render method) | git-diff inspection + AT-B59-06 + AT-B59-07 | GREEN |
| LLR-L4.2 | full pre-existing suite green | AT-B59-07 (20 batch-58 nodes green in the 1772) | GREEN |
| LLR-L5.1 | fidelity assertions derive from the tree; pairwise-distinct-ancestor teeth | AT-B59-08 | GREEN |

---

## 3. Gap check

- **US:** 5/5 covered (US-L1..L5). No orphan.
- **HLR:** 5/5 covered (HLR-L1..L5). Each traces to ≥1 US and ≥1 LLR.
- **LLR:** 12/12 covered (L1.1–L1.4, L2.1–L2.4, L3.1, L4.1–L4.2, L5.1). No orphan LLR, no dangling node.
- **AT:** 11/11 realized (AT-B59-01..11), each to exactly one distinct on-disk node with an executed RED→GREEN counterfactual (C-18) + the F2 security-realization node.
- **Frozen set:** 0 diffs — the change touches only `crc_designer_view.py`, `styles.tcss`, `tests/test_crc_designer_view.py`.

**Result: zero gaps.** Both trace chains close (US→AT→observable outcome and US→HLR→LLR→verification). Gate verdict: PASS, 0 blockers.

---

*Carry-forward (not batch-59, not a gap): the 19 pre-existing `test_tc016s_*` snapshot-drift cells are batch-58's uncommitted 10th-rail baselines — CRC-free (grep `crc` in the snapshot suite → 0), regenerated canonical-CI-only.*
