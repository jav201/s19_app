# Traceability Matrix — s19_app — Batch `2026-08-01-batch-77`

> **Artifact language:** English (`state.json.language`).
> Phase-6 artifact. Owner: `docs-writer`. Merged as PR [#186](https://github.com/jav201/s19_app/pull/186), squash **`244ecf2`**, off `origin/main` @ `f8747b8`.
> **Sources:** `01-requirements.md` **revision 7** (§3, §4, §5.2, §5.3, §6.5) · `04-validation.md` (`PASS-WITH-NOTES`) · `05-postmortem.md` · `PLAN.md` (D-1…D-18, R-1…R-13).
> **Every node name and every line number below was verified against the working tree at `244ecf2`** — not copied from the specification. This matters: **six quoted figures in this batch did not reproduce on their stated source**, and the specification's own symbol line numbers had drifted by up to ~450 lines by close (`05-postmortem.md:242`). Where this document's finding differs from the specification's, the disk wins and the difference is stated.

Two chains, both complete:

- **Functional (white-box):** User Story → HLR → LLR → `TC-B77-nn` → File:line — §1
- **Behavioural (black-box):** User Story → `AT-B77-nn` → observed outcome through the shipped surface — §1b

---

## 1. Master table — functional chain (white-box)

> `File:line` is the **production** code site the LLR governs, re-derived on disk at `244ecf2`.
> `Notes` carries the pytest node that discharges the TC, plus any caveat that must not be tabulated away.

### US-77-1 → HLR-111 — every mapped run is visible, ordered by size, inside a bounded container

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-77-1 | HLR-111 | LLR-111.9 | *(geometry threshold, no TC-B77 id)* | `s19_app/tui/styles.tcss:789` `.map-band-row` · `:798` `.map-band-bar` · `:811` `.at-a-glance` | pass | Always-stack. Bar **21 → 50** @120×30. Threshold `#map_grid.region.width == .map-band-bar.region.width` asserted by `test_at073b_glance_geometry_fits_and_reflows` (`tests/test_tui_directionb.py:4839`). |
| US-77-1 | HLR-111 | LLR-111.1 | TC-B77-30 | `screens_directionb.py:2532` `_build_band_widgets` | pass | `test_tc_b77_30_b77_width_one_range_yields_two_runs` (`test_tui_map_big.py:979`). Basis **and** denominator both normative: container width × mapped-byte share. `_BAND_BAR_WIDTH` deleted outright (OQ-3) — **0 live code references**, verified. |
| US-77-1 | HLR-111 | LLR-111.7 | TC-B77-01 | `screens_directionb.py:504` `_allocate_band_widths` | pass | `test_tc_b77_01_b77_bound_empty_image_emits_no_segment` (`:788`). Empty image. |
| US-77-1 | HLR-111 | LLR-111.7 | TC-B77-02 | `screens_directionb.py:504` | pass | `test_tc_b77_02_b77_bound_single_run_takes_the_whole_bar` (`:804`). Single run. |
| US-77-1 | HLR-111 | LLR-111.7 | TC-B77-03 | `screens_directionb.py:504` | pass | **Two pytest nodes for one id** — `…_domain_edge_degrades_without_raising` (`:818`) and `…_domain_edge_differing_sizes_ties_widths` (`:859`). ⚠️ The second arm exists **because the first was vacuous**: fixture `[256] * n_runs` has no differing sizes, so the strict limb it was labelled to probe had **no subject anywhere in its sweep**. See gap **G-101**. |
| US-77-1 | HLR-111 | LLR-111.7 | TC-B77-04 | `screens_directionb.py:504` | pass | `test_tc_b77_04_b77_bound_zero_byte_run_still_paints_a_column` (`:943`). Invalid input. |
| US-77-1 | HLR-111 | LLR-111.7 | TC-B77-05 | `screens_directionb.py:504` | pass | `test_tc_b77_05_b77_bound_zero_span_image_renders_no_segments` (`:954`). Error input (`total_span ≤ 0`), short-circuits before allocation. |
| US-77-1 | HLR-111 | LLR-111.2 | *(covered by AT-B77-03 + 2 PIN nodes)* | `screens_directionb.py:2532` | pass | Gaps fold to **exactly 1** column. PINs kept green **unmodified**: `test_ac6_band_segments_do_not_widen_region_row_queries` (`tests/test_map_click_chain.py:361`), `test_ac6_gap_hatch_segments_are_not_clickable` (`:397`). Ruling **R-5** — `fold=2` collapses three runs to equal width and guts the strict limb. |
| US-77-1 | HLR-111 | LLR-111.3 | *(covered by AT-B77-03)* | `screens_directionb.py:2448` `_resize_band_segments` | pass | `bar.region.contains_region(seg.region)` ∀ segments, **in domain**. `outside` was **4 @120×30**, now **0**. |
| US-77-1 | HLR-111 | LLR-111.4 | *(covered by AT-B77-02)* | `tests/goldens/batch77/at-b77-02-gapless-band-strip.txt` | pass | Byte-exact golden. Stored blob measured: `[49,17]` @66 · `[37,13]` @50 · **0 CR bytes** under `core.autocrlf=true`, asserted via `git show :tests/goldens/batch77/at-b77-02-gapless-band-strip.txt` — never the worktree file. |
| US-77-1 | HLR-111 | LLR-111.5 | *(inspection)* | `01-requirements.md` §4, `LLR-111.5` register | pass | C-40 register: every row marked *executed* or *predicted*, **and names the METHOD that produced its payload**. **0 rows left `predicted`** at close. |
| US-77-1 | HLR-111 | LLR-111.6 | *(helper, applies to every geometry TC)* | `tests/test_tui_map_big.py` settling helper | pass | Geometry read at **settled** layout — post-pause fixed point, never a same-frame repeat. Measured: 1 of 6 trials read 23 where 5 read 21. |
| US-77-1 | HLR-111 | ~~LLR-111.8~~ | ~~TC — none allocated~~ | — | **n/a — WITHDRAWN** | **Aggregation descoped to batch-78 by ruling R-10** after **7 of 8** re-gate blockers landed in this one path. Recorded as a withdrawal record naming all six defects, **not deleted**. Its acceptance `AT-B77-17` is withdrawn with it. → carry `C-77-l`. |

### US-77-2 → HLR-112 — every ruler label names a mapped address and is legible

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-77-2 | HLR-112 | LLR-112.1 | TC-B77-06 | `screens_directionb.py:1588` `MapRuler` | pass | `test_tc_b77_06_b77_ruler_empty_image_emits_no_tick` (`test_tui_map_big.py:387`). Empty image. |
| US-77-2 | HLR-112 | LLR-112.1 | TC-B77-07 | `screens_directionb.py:1588` | pass | `test_tc_b77_07_b77_ruler_single_run_labels_start_and_last_byte` (`:405`). One tick per emitted **run** start + the last mapped byte (`span_end − 1`; ruling R-4 — `span_end` is exclusive). Retired `_TICK_COUNT = 5` percentile derivation. |
| US-77-2 | HLR-112 | LLR-112.2 | TC-B77-08 | `screens_directionb.py:1691` `MapRuler.on_resize` | pass | `test_tc_b77_08_b77_ruler_out_of_domain_elides_legibly` (`:420`). Out-of-domain elision against the **measured** ruler width at pitch `len(label) + 1 = 9`; ceiling **7 @80×24 / 5 @120×30**. `prg.s19` elides 15 → 7 and 15 → 5, no raise. |
| US-77-2 | HLR-112 | LLR-112.2 | TC-B77-09 | `screens_directionb.py:1691` | pass | `test_tc_b77_09_b77_ruler_floor_of_two_retains_both_bounds` (`:477`). First and last labels always retained. |
| US-77-2 | HLR-112 | LLR-112.3 | *(census, not a TC)* | `s19_app/tui/legend.py` · `REQUIREMENTS.md` · `.dev-flow/2026-07-15-batch-47/**` | pass | Retirement census of the 5-tick contract: **0** surviving statements. Executed total **35 sites across 13 files** against a document estimate of ~23 — **52 % higher**, and low for a **fourth consecutive revision**. See gap **G-103**. |

### US-77-3 → HLR-113 · US-77-4 → HLR-114

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-77-3 | HLR-113 | LLR-113.1 | TC-B77-10 | `screens_directionb.py:2853` `build_stats_text` | pass | `test_tc_b77_10_no_file_stats_strip_is_positively_empty` (`test_tui_directionb.py:4023`). Empty state proven **positively**. |
| US-77-3 | HLR-113 | LLR-113.1 | TC-B77-11 | `screens_directionb.py:2853` | pass | `test_tc_b77_11_full_coverage_strip_reads_100_and_a_zero_gap` (`:4055`). Expected strings **computed** via `human_bytes(…)` (`insight_style.py:124`), never hand-typed (C-42). |
| US-77-3 | HLR-113 | LLR-113.1 | TC-B77-12 | `screens_directionb.py:2853` | pass | `test_tc_b77_12_one_byte_image_strip` (`:4088`). Coverage at **exactly** four fractional digits — *"at least four"* would be satisfied by a `.6f` implementation that reddens `test_at037`'s absence clause. |
| US-77-3 | HLR-113 | LLR-113.1 / .2 | TC-B77-13 | `screens_directionb.py:2853` · `insight_style.py:124` | pass | `test_tc_b77_13_zero_span_strip_divides_by_nothing` (`:4109`). Also the LLR-113.2 largest-gap arm. `coverage_stats` untouched; `image_span` **surfaced, not computed**, so `LLR-041.7` holds by construction. |
| US-77-4 | HLR-114 | LLR-114.1 | TC-B77-14 | `screens_directionb.py:2532` · `styles.tcss` (2 rules deleted) | pass | `test_tc_b77_14_no_file_has_no_legend_and_no_strip_either` (`:5110`). Query **scoped to `#map_grid`** (C-38) — an unscoped query falsely reddens when the legend screen is open. |
| US-77-4 | HLR-114 | LLR-114.2 | TC-B77-15 | `s19_app/tui/app.py:1359` (`k` binding) · `app.py:5867` `action_show_legend` | pass | `test_tc_b77_15_legend_opened_from_the_map_and_dismissed` (`:5149`). **0 diff lines** in the binding block. |

### US-77-5 → HLR-115 — region rows are actionable with arrows and Enter

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-77-5 | HLR-115 | LLR-115.2 | TC-B77-16 | `screens_directionb.py:1301` `RegionRow` | pass | `test_tc_b77_16_b77_keys_first_and_last_row_edges_do_not_wrap` (`test_tui_map_big.py:2447`). **No wraparound** at either edge. |
| US-77-5 | HLR-115 | LLR-115.2 | TC-B77-17 | `screens_directionb.py:1301` | pass | `test_tc_b77_17_b77_keys_are_inert_with_no_file_loaded` (`:2511`). |
| US-77-5 | HLR-115 | LLR-115.2 | TC-B77-18 | `screens_directionb.py:1301` | pass | `test_tc_b77_18_b77_keys_single_region_has_nowhere_to_move` (`:2560`). |
| US-77-5 | HLR-115 | LLR-115.3 | TC-B77-19 | `screens_directionb.py:1347` `RegionRow.Activated` · `:3018` `on_region_row_activated` | pass | `test_tc_b77_19_b77_keys_enter_on_an_invalidated_row_is_inert` (`:2612`). `Enter` posts the **same** message a click posts, `chain = 1` — one policy site, no second path. |
| US-77-5 | HLR-115 | LLR-115.3 | TC-B77-20 | `screens_directionb.py:1347` · `:3018` | pass | `test_tc_b77_20_b77_keys_enter_with_no_focus_selects_nothing` (`:2681`). |
| US-77-5 | HLR-115 | LLR-115.4 | **`TC-011`** *(pre-existing, frozen)* | `screens_directionb.py:1301` `RegionRow.BINDINGS == []` · `app.py:1352/1356/1359` | pass | ⚠️ **No batch-scoped TC-B77 id covers this LLR, and that is stated rather than papered over.** Its functional coverage is the pre-existing frozen node `TC-011` (`tests/test_memory_display.py:173`, `:192`) — **green and byte-unmodified at the Inc-8 gate** — plus the two PINs `AT-B77-09` / `AT-B77-16`. `RegionRow.BINDINGS` stays `[]` **by design**: a widget-scoped binding shadows the App binding of the same key for as long as the row holds focus, and after Inc-7 a row holds focus by default on every render. |

### US-77-6 → HLR-116 — a region is focused and inspected without operator input, safely

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-77-6 | HLR-116 | LLR-116.1 | *(covered by AT-B77-08 / -11 + the display-guard node)* | `screens_directionb.py:1301` `RegionRow` (`can_focus`) | pass | `test_b77_select_focus_is_not_taken_while_the_map_screen_is_hidden` (`test_tui_map_big.py:2049`) — the **display guard is load-bearing**: `update_memory_map()` runs on every load whatever screen is active, and `Widget.focusable` consults `visible`, never `display`. Unguarded, focus moves to an **invisible** row at both regimes. Rail chain measured, not argued: 8 of 9 screens byte-identical. |
| US-77-6 | HLR-116 | LLR-116.2 | TC-B77-21 | `screens_directionb.py:2230` `render_ranges` | pass | `test_tc_b77_21_b77_select_no_file_keeps_the_hint_and_fabricates_nothing` (`:1796`). |
| US-77-6 | HLR-116 | LLR-116.2 | TC-B77-22 | `screens_directionb.py:2230` | pass | `test_tc_b77_22_b77_select_single_run_is_selected_and_marked` (`:1828`). |
| US-77-6 | HLR-116 | LLR-116.2 | TC-B77-31 | `screens_directionb.py:2230` | pass | `test_tc_b77_31_b77_select_resolution_runs_on_the_post_refresh_hook` (`:1984`). **`grid.mount()` is deferred**, so *"after the rows are mounted"* is not a synchronous point — resolution runs on `call_after_refresh`, after `_reset_detail()`. |
| US-77-6 | HLR-116 | LLR-116.4 | TC-B77-23 | `screens_directionb.py:2230` | pass | `test_tc_b77_23_b77_select_disjoint_file_switch_selects_the_new_first_run` (`:1864`). |
| US-77-6 | HLR-116 | LLR-116.4 | TC-B77-29 | `screens_directionb.py:2230` | pass | `test_tc_b77_29_b77_select_preserves_by_address_when_the_index_shifts` (`:1938`). Matching is by **address**, never index — a re-merge changes how many runs precede the selected one. |
| US-77-6 | HLR-116 | LLR-116.2 | TC-B77-24 | `screens_directionb.py:2230` | pass | `test_tc_b77_24_b77_select_zero_byte_window_selects_without_raising` (`:1893`). |
| US-77-6 | HLR-116 | LLR-116.3 | *(covered by AT-B77-11)* | `screens_directionb.py:2230` | pass | Auto-selection **never** posts `MemoryMapPanel.OpenInHexRequested` — **0** posts, co-asserted with the inspector populated in the same run (C-40). |
| US-77-6 | HLR-116 | LLR-116.5 | *(covered by AT-B77-13 / -14)* | `screens_directionb.py:3064` `_live_region_rows` | pass | Focus lands on a **LIVE** row — attached **and** among the panel's current rows. `remove_children()` is deferred, so a panel-wide `query(RegionRow)` returns stale + fresh together; identity alone reads `True` on a fully detached widget. |
| US-77-6 | HLR-116 | LLR-116.6 | *(covered by AT-B77-15a / -15b)* | `screens_directionb.py:2853`-region `build_detail_text` (A2L + `ValidationIssue` paths) | pass | Read the **painted strip**, not `.plain` — `.plain` is where the byte lives, the strip is where it escapes. The layer choice is load-bearing and the spec picked it for a reason it never stated: an unscoped absence clause fired on `_flow_block_label`, which composes its own newline. |
| US-77-6 | HLR-116 | LLR-116.7 | *(unit node)* | `screens_directionb.py:878` `safe_text` | pass | `test_b77_safe_text_scrubs_the_control_byte_class_without_damaging_identity` (`tests/test_tui_hostile_map.py:319`). Scrub selects a **byte CLASS** via `str.translate`, not an escape-sequence pattern — `U+009B` is single-byte CSI and `U+009D` single-byte OSC, so an ESC-anchored regex still lets `0x00/0x7f/0x9b/0x9d` reach the strip. Pulled **into** the batch by ruling **R-11**. See gap **G-104**. |

### US-77-7 → HLR-117 — the selected region row is visually distinguishable

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-77-7 | HLR-117 | LLR-117.1 | TC-B77-25 | `screens_directionb.py:2145` `_SELECTED_ROW_CLASS = "map-region-selected"` | pass | ⚠️ **`TC-B77-25` has no node of its own** — it is asserted **inline inside `AT-B77-12`'s node** (`tests/test_tui_map_big.py:1633` docstring, assertion at `:1669`). That is deliberate: it is a *fixture constraint* (**≥2 runs**), and with one run the "differs from every unselected row" claim is vacuously true. Marker applied **by address**, to no other row: exactly **1** (was 0). |
| US-77-7 | HLR-117 | LLR-117.2 | TC-B77-32 | `styles.tcss:864` `.map-region-row.map-region-selected` | pass | `test_tc_b77_32_b77_style_band_token_survives_selection` (`:1692`). Behavioural arm — the band channel survives a selection **MOVE**. |
| US-77-7 | HLR-117 | LLR-117.2 | TC-B77-33 | `styles.tcss:857-864` | pass | `test_tc_b77_33_b77_style_selection_rule_sets_no_foreground_no_inversion` (`:1750`). Inspection arm. ⚠️ *"Sets no `color:`"* alone is satisfied by `text-style: reverse`, **which repaints the band colour** — the clause forbids **both**. |
| US-77-7 | HLR-117 | LLR-117.2 | ~~TC-B77-26~~ · ~~TC-B77-27~~ · ~~TC-B77-28~~ | — | **n/a — WITHDRAWN** | See §3 **G-102**. Numbers **not reused**. |

---

## 1b. Behavioural chain (black-box)

> Every node drives the **shipped** surface — Textual `App.run_test()` Pilot, real key presses, real `pilot.click`, or the artifact on disk — and asserts the **deliverable**, not the mechanism. Every AT is parametrized over **both** size regimes (80×24 and 120×30) and reported **per resolved node id per arm** (CC-1).

| US | Acceptance test (id → node) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-----------------|--------------------------------|--------|
| US-77-1 | **AT-B77-01** — `test_b77_width_visible_monotone_strict` (`test_tui_map_big.py:607`) | Pilot, both regimes | `.map-band-seg[].region.width` at settled layout — visible ∧ monotone-∀ ∧ strict-∃, in domain | **pass** — pre-change **RED both arms, on different limbs** |
| US-77-1 | **AT-B77-02** — `test_b77_gapless_golden` (`:1136`) | Producer, through the acceptance's own fixture + drive helpers | `tests/goldens/batch77/at-b77-02-gapless-band-strip.txt` — the **committed blob**, byte-compared | **pass** — GATE, discharged by mutation (allocator → plain `round()`: `[49,17]→[50,16]` @66 · `[37,13]→[38,12]` @50) |
| US-77-1 | **AT-B77-03** — `test_b77_contain_no_segment_outside_the_bar` (`:675`) | Pilot, both regimes | `bar.region.contains_region(seg.region)` ∀ segments | **pass** — pre-change **RED @120×30** (4 outside) |
| US-77-1 | **AT-B77-18** — `test_b77_domain_out_of_domain_renders_and_lists_every_run` (`:732`) | Pilot, `professional_validation/case_08_heavy_fragmentation` (801 ranges) | 801 `RegionRow`s reachable in the region list; **no raise** | **pass** — the **only** out-of-domain gate; evaluable pre-change |
| US-77-1 | **AT-B77-19** 🆕 — `test_b77_bar_reapportions_without_panel_resize_or_retry` (`:2734`) | Pilot, **first render**, both incidental correctors blinded | `.map-band-seg` width vector `[1,1,1,1,1,9,7,28,1,2,1,1,1,1]`, Σ 56 + 10 gaps = 66 | **pass**, 2 arms — **escaped-bug regression**; pre-fix RED **byte-identical to CI's failure** |
| US-77-1 | ~~**AT-B77-17**~~ | — | — | **WITHDRAWN — see §3 G-105** |
| US-77-2 | **AT-072b** *(re-derived, keeps its global id)* — `test_at072b_ruler` (`:301`) | Pilot, fixture **PINNED to `case_02`** (`:292-299`, normative comment block) | `.map-ruler-tick` label set ⊆ mapped addresses ∧ ascending ∧ distinct ∧ no elided tick | **pass** — pre-change **RED**, 4 of 5 labels named unmapped addresses |
| US-77-2 | **AT-B77-04** — `test_b77_ruler_labels_every_run_start_and_the_last_byte` (`:363`) | Pilot | tick set **⊇** the lower bound | **pass** — **not optional:** `set() ⊆ admissible` is `True`, so a subset-only predicate is GREEN on a ruler that rendered **zero** ticks |
| US-77-3 | **AT-B77-05** — `test_b77_stats_strip_dual_readout_and_four_digit_coverage` (`test_tui_directionb.py:3937`) | Pilot | `#map_stats_body` rendered text (**not** the container, which renders `Blank`) | **pass** — pre-change RED |
| US-77-4 | **AT-B77-06** — `test_b77_legend_is_not_resident_in_the_map_body` (`:5009`) | Pilot | 0 `.map-band-legend` **inside `#map_grid`**, co-asserted with ≥1 `.map-band-seg` present | **pass** — pre-change RED (4 rows, 1 container) |
| US-77-4 | **AT-B77-07** — `test_b77_legend_screen_still_lists_every_band` (`:5065`) | Pilot, `k` legend screen | band-key completeness **derived from `ENTROPY_BAND_LABELS`** | **pass** — **PIN** (labelled). Derivation is strictly stronger than the hand-typed four-tuple it replaced: a four-tuple cannot fail when a fifth band is added. |
| US-77-5 | **AT-B77-08** — `test_b77_keys_arrows_move_focus_and_enter_inspects` (`test_tui_map_big.py:2149`) | Pilot — **real `down`/`down`/`up`/`enter` presses**, never `.focus()` | `app.focused` walks the rows; `Enter` commits to the inspector | **pass** — pre-change RED (`can_focus = [False]×5`). **C-16 discharged by execution:** with `can_focus` already `True`, arrows were still inert (`after_down=0`, `after_down2=0`, `after_up=0`) — **Textual gives no spatial arrow-focus for free.** |
| US-77-5 | **AT-B77-09** — `test_b77_keys_no_application_binding_is_shadowed_with_a_row_focused` (`:2282`) | Pilot, focus **ON** a row | `j` / `k` / `o` still reach the application action | **pass** — 🔒 **PIN, NOT A GATE.** GREEN before *and* after. Falsifiable only by its named mutation. |
| US-77-5 | **AT-B77-16** — `test_b77_keys_no_application_binding_is_shadowed_without_row_focus` (`:2378`) | Pilot, focus **OFF** the region list | same three keys | **pass** — 🔒 **PIN, NOT A GATE. Its originally-named mutation was proven INERT.** See §3 **G-106**. |
| US-77-5 | **AT-B77-10** — `test_ac3_single_click_inspects_and_does_not_navigate` (`test_map_click_chain.py:169`) **+** `test_ac4_double_click_navigates_to_the_region_start` (`:196`) | Pilot, single vs double click | the batch-67 N4a mouse split survives HLR-115 | **pass** — **PIN**, mapped onto the **two existing** nodes rather than minting one node covering half a two-node claim |
| US-77-6 | **AT-B77-11** — `test_b77_select_fresh_render_inspects_run_one_without_navigating` (`test_tui_map_big.py:1400`) | Pilot, **zero gestures** | `#map_detail_body` populated ∧ `app.focused` is a **live** `RegionRow` ∧ no navigation | **pass** — pre-change RED |
| US-77-6 | **AT-B77-13** — `test_b77_select_rerender_preserves_a_region_still_present` (`:1531`) | Pilot, re-render holding the region | selection **preserved by address**, focus LIVE | **pass** — pre-change RED |
| US-77-6 | **AT-B77-14** — `test_b77_select_rerender_falls_back_when_the_region_is_gone` (`:1579`) | Pilot, re-render dropping the region | fallback to the **new** first region, focus LIVE | **pass** — pre-change RED. ⚠️ Its fallback mutation **as the spec words it** raises `ValueError`; a graceful variant was run alongside to obtain an **assertion-level** failure. Reported, not reconciled. |
| US-77-6 | **AT-B77-15a** — `test_b77_hostile_symbol_is_literal_and_carries_no_span` (`test_tui_hostile_map.py:246`) | **real `pilot.click`** (Inc-2) **and** auto-select (Inc-7) | painted strip of `#map_detail_body`: every **non-control** character verbatim ∧ `spans == []` | **pass** — pre-change RED, `limb1 payload-verbatim = False` at both sizes |
| US-77-6 | **AT-B77-15b** — `test_b77_hostile_symbol_emits_no_control_byte_into_the_strip` (`:287`) | same, both drives | painted strip: **no residual C0/C1 control byte** | **pass** — labelled ***vacuously green until Inc-2***; a genuine red→green gate from Inc-2 onward |
| US-77-7 | **AT-B77-12** — `test_b77_style_selected_row_differs_from_every_unselected_row` (`test_tui_map_big.py:1630`) | Pilot | exactly 1 selection marker ∧ resolved style triple differs ∧ ≥2 runs (`TC-B77-25`, inline at `:1669`) | **pass** — pre-change RED (0 markers). Read from `widget.styles.*`, **not** `render().spans` (measured `[]`). |

**Layer-B totals.** **20 acceptance ids over 7 stories** (21 pytest nodes — `AT-B77-10` maps onto two). **13 demonstrated RED pre-change by execution** · **4 labelled PINs** (`AT-B77-07/09/10/16`) · **1 labelled vacuous-until-Inc-2** (`AT-B77-15b`) · **1 evaluable-today** (`AT-B77-18`) · **1 escaped-bug regression** (`AT-B77-19`). Every exception is labelled in `01-requirements.md` §9 — **no unlabelled exception**, which §5.3 requires.

### 🔒 The three things this matrix must state rather than tabulate away

**① `TC-B77-26` / `TC-B77-27` / `TC-B77-28` are WITHDRAWN — allocated without content, never specified anywhere.**
Their entire content was: *nothing.* The three ids appear in exactly two places in the whole batch artifact set — §3's `HLR-117` boundary list and §5.2's functional chain — **as bare ids, at every revision.** Inc-7 emitted two `HLR-117` nodes beyond `AT-B77-12`/`TC-B77-25` and Inc-8 **refused to label them 26/27/28**, because retro-fitting content into an id whose intent nobody recorded is *minting under an existing number* — it makes the id mean whatever the later increment happened to write. **The numbers are not reused.** `TC-B77-32` and `TC-B77-33` are the replacements, taking the next free ids. Allocation therefore stays **monotonic**, and an id can never mean two things. Withdrawal record: `01-requirements.md` §4 under `HLR-117 → LLR-117.x`; on disk at `tests/test_tui_map_big.py:1703`, `:1709`, inside the withdrawal record and carried by **no node**.
⚠️ **What the withdrawal does *not* establish:** it does not show that `HLR-117`'s boundary catalog is complete at two entries. It shows only that three of its entries were never real. Whether `HLR-117` needs further boundaries is a separate judgement and **none is claimed here.**

**② `AT-B77-17` is WITHDRAWN with `LLR-111.8`.**
Ruling **R-10** descoped the aggregation path to batch-78 after **7 of 8** re-gate blockers landed in that single path — six independent defects, including a monotonicity subject that does not exist on `BandSegment`, a stopping rule that terminates exactly where the strict-∃ clause dies, and an O(n²) merge loop on the UI thread. **`AT-B77-18` replaces it**, covering the out-of-domain case with the only two claims batch-77 can honestly make: **no raise**, and **region list complete**. The id is **not reused** (§5.4). This is a **recorded scope reduction, not a silent deletion** — and its sole basis for being so is carry **`C-77-l`**, which charters batch-78 with all 11 measurements already paid for. **Losing `C-77-l` retroactively converts a recorded descope into an undocumented gap.**

**③ `AT-B77-09` and `AT-B77-16` are PINs, not gates — and one of their mutations was inert.**
A **PIN** is GREEN before the change and GREEN after; its entire evidentiary value is its **named mutation**. Both PINs assert that the application's `j` / `k` / `o` bindings are not shadowed, and `RegionRow.BINDINGS` is `[]` before and after — so neither can ever be demonstrated RED by the change it guards.
The specification prescribed **one** mutation for **both** PINs: adding `Binding("k", …)` to `RegionRow.BINDINGS`. **Executed at Inc-8, that mutation reddens `AT-B77-09` at both arms and leaves `AT-B77-16` GREEN at both** — with no row focused, the widget binding is never in the resolution chain, so the mutation is **structurally unable to reach `AT-B77-16`'s subject**.
> **A PIN whose named mutation cannot move it has no demonstrated falsifiability at all. It certifies nothing.**

**Working substitute, found, executed and independently confirmed:** re-key the **application** binding — `s19_app/tui/app.py:1359`, `Binding("k", "show_legend", "Legend", show=True)`, key `"k"` → `"f9"`. *(Verified present at that exact line on disk at `244ecf2`.)* That reddens **both** PINs at **both** arms, on the **behavioural** assertion. Recorded at `LLR-115.4` at close-out (merge-gate finding M-2) — until then it existed **only in a commit message**.
`AT-B77-09` additionally clears the declaration-only objection: it reddens on its declaration limb first, but the same failing payload carries `stack_after_k: ['Screen']`, so the behavioural limb would also have reddened.

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | **8 chartered** (`US-77-1…8`); **7 in scope** — `US-77-8` classified **OUT** at Phase 0 (D-4), registered as a carry, not dropped |
| Covered user stories | **7 / 7 in scope (100 %)** — every story has ≥1 passing AT observing its outcome through the shipped surface |
| Total HLR | **7** (`HLR-111`…`HLR-117`) |
| Implemented HLR | **7 (100 %)** |
| Total LLR | **29 allocated → 27 live.** `LLR-111.8` **withdrawn** (R-10); `LLR-115.1` **moved** to `LLR-116.1` (arch B-4, one normative owner for the focus-entry path) |
| Implemented LLR | **27 / 27 live (100 %)** |
| Test cases (`TC-B77-*`) | **33 ids allocated → 30 live.** `TC-B77-26/27/28` **withdrawn**; numbers **not reused**, so the range is deliberately non-contiguous |
| TC pass | **30 / 30 live (100 %)** — 30 `test_tc_b77_*` pytest nodes cover 29 ids (`TC-B77-03` has two arms), plus `TC-B77-25` asserted inline inside `AT-B77-12` |
| TC fail | **0** |
| TC pending | **0** |
| Acceptance tests | **19 batch-scoped ids allocated → 18 live** (`AT-B77-17` withdrawn), `AT-B77-15` split into `15a`/`15b`, **plus `AT-072b` re-derived** = **20 Layer-B ids / 21 pytest nodes** |
| AT pass | **20 / 20 (100 %)** — 13 executed RED pre-change, 4 PINs, 1 vacuous-until-Inc-2, 1 evaluable-today, 1 escaped-bug regression |
| Test ledger | `2519` (`f8747b8`) **→ 2612** (`244ecf2`); `−1 +94`. Final run **2607 passed / 2 skipped / 3 xfailed**, exit 0. Re-derived at write time: `pytest --collect-only -q` → **2612 collected** |
| Snapshots | **29** → 2 marked (C-22, Inc-1b) → regenerated in **canonical CI** (run `30801949601`) → **29 passed, 0 xfailed, 0 xpassed** |
| Frozen-engine diff (C-27 dual guard) | **0** — source **and** `_ENGINE_TEST_FILES`, both halves green at **every** increment gate |
| Bidirectional surface reachability | **16 / 16** named input dimensions · **11 / 11** named deliverables — **0 gaps in either direction** |

---

## 3. Detected gaps

> Incomplete rows, requirements without TC, or TCs without code mapping — plus the acceptance-design defects that a status column cannot express.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| **G-101** | vacuous fixture | **`TC-B77-03`'s fixture had no subject.** The node is labelled *"the domain edge"*, but its fixture is `[256] * n_runs` — all runs equal — so `differing` is `False` and the strict limb it exists to probe had **no subject anywhere in its sweep**. That is why a sweep across the onset never evaluated the clause that turned out to be false. | ✅ **CLOSED** — a differing-size arm was added at Inc-1 (`test_tc_b77_03_b77_bound_domain_edge_differing_sizes_ties_widths`, `test_tui_map_big.py:859`). ⚠️ **It blocked nothing, because nobody checked it until an independent code review did** — and it is the reason Amendment D existed to be found at all. |
| **G-102** | ids allocated without content | **`TC-B77-26/27/28` were allocated and never specified** — bare ids in exactly two places, at every revision. | ✅ **CLOSED by WITHDRAWAL.** Numbers **not reused**; `TC-B77-32/33` are the replacements. See §1b ①. |
| **G-103** | census under-count | **The retired 5-tick contract's site count was a lower bound in four consecutive revisions** — 6 → 8 → 9 → ≈23 → the **executed 35 across 13 files** (52 % higher). Three *new* miss modes, each different from the last: a requirement restating its contract in its own `Validation:` row; `5-tick` written **hyphenated**, invisible to every sweep searching `5 tick`; a **second** row in a file already named at another line. | ✅ **CLOSED at Inc-5** — **0** surviving statements. Only a **claim-derived superset sweep** (`ruler\|tick`, 327 hits, every one *read*, not counted) closed it. **Standing lesson:** an id-keyed grep cannot find a prose restatement, a phrase-keyed grep cannot find a hyphenation variant, and a line-keyed census cannot find a sibling line. |
| **G-104** | false claim in shipped source | **`safe_text`'s docstring asserted it neutralised raw ANSI. It did not.** Executed on the pre-change tree, `safe_text('sensor\x1b[31m_evil[red]')` returned the string **unchanged** — ESC survived, 21 characters billed for 16 visible. Measured blast radius: **9 nodes · 5 test files · 8 render surfaces**, every one green against a guarantee the source never provided. | ✅ **CLOSED at Inc-2** (`LLR-116.7`, ruling R-11 pulled it **into** the batch). All 9 acceptances **ported, never deleted and never weakened** — each keeps its original positive claim with the new no-residual-control clause co-asserted beside it, because an absence claim alone is green on an empty render. **This is the batch's most transferable finding:** *a false claim in shipped source gets encoded into the acceptances built to catch it, and those then defend the falsehood.* |
| **G-105** | scope reduction | **`LLR-111.8` + `AT-B77-17` (aggregation) withdrawn to batch-78** — ruling R-10, after 7 of 8 re-gate blockers landed in that one path. | ✅ **RECORDED, not deleted.** `AT-B77-18` replaces the acceptance with the two claims batch-77 can honestly make. 🛑 **Carry `C-77-l` is LOAD-BEARING** — `.dev-flow/BACKLOG-CODE.md:69`, 11 measurements verbatim, `case_08_heavy_fragmentation` named as the acceptance fixture **from the start**. |
| **G-106** | inert mutation | **A PIN's named mutation was inert.** The spec prescribed *one* mutation for *two* PINs without checking it reached both subjects. Detected only when Inc-8 **executed** it. | ✅ **CLOSED** — substitute (`app.py:1359`, key `"k"` → `"f9"`) executed, reddens both PINs at both arms; recorded at `LLR-115.4` at close-out (M-2). **Control candidate:** *a PIN's mutation must be shown to reach that PIN's own subject, per PIN — one mutation shared across two PINs is one unchecked claim, not two.* |
| **G-107** | escaped product defect | **One product defect escaped ~20 review passes and every local gate**, caught by **CI** at the merge gate. On `prg.s19` @80×24 — **in domain**, bar correctly measuring 66 — every run rendered at 1 column. Two independent recovery paths existed and the defect needed **both** to miss. | ✅ **CLOSED** — event-driven fix (`BandBar.Measured`, `screens_directionb.py:1580`), regression `AT-B77-19`, 2 arms. See `06-docs/diagrams/render-and-settle.md` §1. |
| **G-108** | coverage limit | **`AT-B77-19` guards FIRST RENDER ONLY.** Re-render, terminal resize, screen switch and resize-while-inactive were verified correct but are **unguarded**. | **ACCEPTED as a carry (F-3).** All five paths ride the single `BandBar.Resize → Measured` mechanism, and first render is the only regime where the incidental correctors were load-bearing. ⚠️ **Its queue entry was found missing at the postmortem's own C-44 sweep** and written into `BACKLOG-CODE.md` at close — **read it from the queue, not from any artifact.** |
| **G-109** | dangling id | **`AT-B77-19` was cited in a test one commit *before* it had a definition** — the **fourth** instance of the dangling-id class in this one batch (`C-77-i`, `C-77-m`, `R-TUI-111`, `AT-B77-19`), landing one commit **after** the close-out repaired the third. | ✅ **CLOSED** — registered under `R-TUI-103` (`REQUIREMENTS.md:6017`). **Not a registry violation:** `AT-TC-REGISTRY` excludes letter-initial bodies by spec §2.3 — *which is exactly why a fully green suite could not catch it.* Route to the **registry lane**. |
| **G-110** | unreproducible figure | **A quoted case-count figure does not reproduce.** `859 276` is on disk (`01-requirements.md:876`) and `6.5 M` has provenance in the Inc-1 commit body; **`660k` appears in no batch artifact and in no `state.json`.** | 🔶 **OPEN — reported, not reconciled.** Either locate its producer or strike it. **Sixth** quoted figure in this batch found not to reproduce; the prior five were `13` gaps → **10** · `99.5 %` → **95.9 %** · `16 of 17` → **15 of 16** · `~23` census sites → **35** · tightest margin `case_02` → **`case_07_stress_smoke` @ 9.95×**. |
| **G-111** | known coupling | **Each `AT-B77-02` golden record is keyed by its settled bar width** (`66`, `50`), so a future CSS change that moves either **reddens the node by design**, with the allocator untouched. | **ACCEPTED — design, not drift.** *"A fixed container width"* is part of the requirement's own condition. ⚠️ Conversely, this node reddening with **no CSS change in the diff** is the real alarm: the allocator or the settle path moved. Recorded in the node docstring, because the person who hits the failure is reading the test. |
| **G-112** | out-of-domain reality | **`case_08_heavy_fragmentation` (801 ranges) is out of `HLR-111`'s domain and the bar is unreadable on it** — **768 of 801 runs** leave no distinguishable column. `HLR-112`'s domain is **materially smaller** than `HLR-111`'s: **13 of 16** fixtures at both regimes versus **15 of 16**. | **STATED, NOT FIXED — deliberately.** The batch **measurably improves** `case_08` and does not claim to fix it. What is true is also stated: **no raise**, and **all 801 regions remain reachable in the region list** (`AT-B77-18`). Excluded from `HLR-112` at both regimes: `prg.s19` (15 ticks vs 7/5 — **the batch's own showcase fixture**), `case_08` (802 ticks); excluded at 120×30 only: `case_07_stress_smoke` (6 ticks vs 5). **batch-78 owns the rest.** |
| **G-113** | process instrumentation | **`state.json` still reports `current_phase: 3`** and records **zero** Phase-3 iterations, though the batch ran **ten increments, three of which iterated**. The flow has a Phase-3 slot and never writes to it. | **OPEN — for the sync step.** Advance `current_phase`, and either count Phase-3 iterations or remove the field as misleading. The published `{0:0, 1:2, 2:3, 3:0, 4:0, 5:0, 6:0}` figure **understates the batch**. |
| **G-114** | undocumented gap in this doc set | **This batch shipped with no diagram until Phase 6.** The architect evidence checklist recorded ✗/partial: *"a two-corrector recovery path where the defect needs both to miss is exactly the flow that warrants a diagram."* | ✅ **CLOSED by this artifact set** — `06-docs/diagrams/render-and-settle.md`, two Mermaid diagrams (render-and-settle sequence, allocation flow). |

> ⚠️ **One figure quoted throughout the batch is flagged rather than asserted here.** *"Roughly twenty review passes"* is **not independently derived**. It reconciles plausibly (9 Phase-2 passes + one `code-reviewer` pass per increment + the merge gate + the post-gate re-review ≈ 21) but **no artifact states the total**. Given that six quoted figures in this batch were already wrong, this document repeats it only with that label attached.

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| **new** | `HLR-111` … `HLR-117` | Seven high-level requirements. Next free id was `HLR-111` (high-water 110; `HLR-108/109/110` live in shipped tests, absent from `REQUIREMENTS.md`). Namespace re-verified clean by the architect lane. |
| **new** | `LLR-111.1….9`, `LLR-112.1…3`, `LLR-113.1…2`, `LLR-114.1…2`, `LLR-115.2…4`, `LLR-116.1…7`, `LLR-117.1…2` | 29 allocated, **27 live**. |
| **new** | `AT-B77-01…19` (less 17) + `TC-B77-01…33` (less 26/27/28) | Batch-scoped ids. Letter-initial bodies are outside `AT-TC-REGISTRY.jsonl` authority (`_meta.governed`, spec §2.3) — **no reservation PR**. |
| **new** | `R-TUI-103` register row (`REQUIREMENTS.md:5974`) | Carries `HLR-111`'s Statement, containment domain, out-of-domain behaviour and Amendment D's precondition. **Added at close-out**, repairing merge-gate HIGH-1: the batch had shipped its centrepiece **without telling the register** — `R-TUI-111` cited at 4 shipped sites with **0** definitions. Citations 4 → 0. |
| **new** | `AT-B77-19` (`REQUIREMENTS.md:6017`) | The escaped-bug regression, registered at the post-gate re-review (F1). |
| **new** | `tests/test_tui_hostile_map.py` | New non-frozen test file for the hostile-input gates. |
| **new** | `tests/goldens/batch77/at-b77-02-gapless-band-strip.txt` | 404 B · sha256 `b2805bf0…` · **0 CR bytes in the stored blob**. `-text` added to `.gitattributes` **after** the existing `tests/goldens/** text eol=lf`, so the more specific pattern wins. |
| **new** | `BandBar(Horizontal)` + `BandBar.Measured` (`screens_directionb.py:1513`, `:1580`) | The merge-gate product fix. |
| **modified** | `R-TUI-072` (**Amendment A**) · batch-47 `LLR-072.3` (**Amendment B**) | The shipped 5-tick percentile contract retired in place — **4 of its 5 ticks named addresses in no mapped range.** B's retired *"labels fit without overlap"* criterion recorded as **vacuous** in the same block: `width: 1fr` children partition the row and **cannot** overlap, so the predicate was GREEN at 10 invisible labels. |
| **modified** | `HLR-111` Statement + `LLR-111.7` (**Amendment D**) | The strictness clause was **unsatisfiable by any allocator** on the containment domain alone — integer **quantisation**, not surplus exhaustion. Precondition `surplus × (max_bytes − min_bytes) > total_bytes`, **strict**. **`_allocate_band_widths` was NOT modified.** |
| **modified** | `LLR-072-7.1` / node `TC-519` (**Amendment E**) | **The guard watched the wrong file for four batches** (batch-72 → batch-77). Its docstring named `_render_card` / `_render_key`; its expression was `git diff … -- s19_app/tui/legend.py`, and `legend.py` contains **zero** occurrences of either (`_render_card` is at `screens.py:1093`, `_render_key` at `:1141`). Proven, not argued: with the consumer regression applied, the old pathspec returned only `legend.py` while `screens.py` — carrying the defect — **was never listed**. Replaced by a two-arm **behavioural** predicate, each arm proven to redden by executing its regression. A source hash was **considered and rejected on record** (it inverts the discrimination). Node now at `tests/test_legend_two_pane.py:714`. |
| **modified** | 9 acceptance nodes across 5 test files | Ported to co-assert no-residual-control **beside** their original positive claim (see G-104). Never deleted, never weakened. |
| **closed** | Amendment C — `test_ac6_clipped_segments_are_a_known_layout_limitation` | Retired; the dropped `outside_count > 0` observable is now carried by `test_b77_contain_no_segment_outside_the_bar` (C-40 limb 2(ii) — the retirement **printed** the dropped observable). Retirement recorded in two surviving docstrings at `test_tui_map_big.py:239`, `:681`. |
| **closed** | Carry `C-77-h` (ANSI scrub, carried OUT at revision 2) | **PULLED IN** as `LLR-116.7` at Inc-2 (ruling R-11). Deferring it would have left `LLR-116.6`'s normative `shall not` with **no verifier able to pass at close** — a red gate nothing in the batch could satisfy. |
| **closed** | Carry `C-77-i` (a claimed dangling `LLR-072.3`) | ✅ **The claim was FALSE.** It came from grepping `REQUIREMENTS.md`, which defines **zero** LLR bodies — *absence from a corpus that cannot contain the target is evidence of nothing.* Discharged at Inc-5. |
| **closed** | Carry `C-77-m` (six genuinely dangling `R-TUI-112` citations) | Minted at Inc-4, found at Inc-5, closed at Inc-6 — citations **8 → 0**. The batch's own words: *"`C-77-i`'s exact defect committed two increments after cataloguing it."* |
| **deleted** | `_BAND_BAR_WIDTH = 60` | Removed outright (OQ-3) rather than retained as a pre-layout fallback. **0 live code references** at `244ecf2`; the single surviving mention is a docstring at `tests/test_tui_map_big.py:1148` explaining the retired `[45,15]` payload. |
| **descoped** | `o` = open-hex keyboard affordance | Ruling **R-3** — `o` is bound app-wide (`app.py:1352`) and frozen under live `TC-011`. → carry **`C-77-f`**. Hex stays reachable by the unchanged N4a mouse double-click. |
| **descoped** | 2-column fold marker + humanized size label | Ruling **R-5** — measured, `fold=2` collapses three runs to equal width and **guts the strict limb**. → carry **`C-77-g`**, with an explicit reopening condition. |
| **descoped** | aggregation (`LLR-111.8`, `AT-B77-17`) | Ruling **R-10** → carry **`C-77-l`**, batch-78. |
| **out of scope** | `US-77-8` (Variant B: log-scale microbar + column-aligned rows) | D-4 — no measured defect motivates it. Registered, **reversible on request**. |

---

## 5. Quick bidirectional mapping

### 5.1 By user story

- **US-77-1** → HLR-111 → LLR-111.1, .2, .3, .4, .5, .6, .7, .9 *(.8 withdrawn)* → TC-B77-01, 02, 03, 04, 05, 30 → AT-B77-01, 02, 03, 18, 19
- **US-77-2** → HLR-112 → LLR-112.1, .2, .3 → TC-B77-06, 07, 08, 09 → AT-072b, AT-B77-04
- **US-77-3** → HLR-113 → LLR-113.1, .2 → TC-B77-10, 11, 12, 13 → AT-B77-05
- **US-77-4** → HLR-114 → LLR-114.1, .2 → TC-B77-14, 15 → AT-B77-06, 07
- **US-77-5** → HLR-115 → LLR-115.2, .3, .4 → TC-B77-16, 17, 18, 19, 20 *(+ frozen `TC-011`)* → AT-B77-08, 09, 10, 16
- **US-77-6** → HLR-116 → LLR-116.1, .2, .3, .4, .5, .6, .7 → TC-B77-21, 22, 23, 24, 29, 31 → AT-B77-11, 13, 14, 15a, 15b
- **US-77-7** → HLR-117 → LLR-117.1, .2 → TC-B77-25, 32, 33 *(26/27/28 withdrawn)* → AT-B77-12

### 5.2 By code file

| File | LLRs | Verifying nodes |
|---|---|---|
| `s19_app/tui/screens_directionb.py:504` `_allocate_band_widths` | LLR-111.7 | `TC-B77-01…05`, `TC-B77-30`; `AT-B77-01`, `AT-B77-02`, `AT-B77-18` |
| `screens_directionb.py:448` `_merge_band_runs` | §2.9 runs subject *(inherited from batch-47, **unchanged** by this batch)* | `TC-B77-30` |
| `screens_directionb.py:2532` `_build_band_widgets` | LLR-111.1, .2; LLR-114.1 | `AT-B77-01`, `AT-B77-03`, `AT-B77-06` |
| `screens_directionb.py:2448` `_resize_band_segments` · `:2432` `on_resize` · `:2436` `on_band_bar_measured` | LLR-111.3 | `AT-B77-03`, **`AT-B77-19`** |
| `screens_directionb.py:1513` `BandBar` · `:1580` `BandBar.Measured` · `:1583` `BandBar.on_resize` | LLR-111.1 *(the escaped-bug fix)* | **`AT-B77-19`** |
| `screens_directionb.py:1588` `MapRuler` · `:1691` `MapRuler.on_resize` | LLR-112.1, .2 | `TC-B77-06…09`; `AT-072b`, `AT-B77-04` |
| `screens_directionb.py:2853` `build_stats_text` | LLR-113.1, .2 | `TC-B77-10…13`; `AT-B77-05` |
| `screens_directionb.py:1301` `RegionRow` · `:1347` `RegionRow.Activated` · `:3018` `on_region_row_activated` | LLR-115.2, .3, .4; LLR-116.1 | `TC-B77-16…20`; `AT-B77-08`, `AT-B77-09`, `AT-B77-16` |
| `screens_directionb.py:2230` `render_ranges` · `:3064` `_live_region_rows` | LLR-116.2, .4, .5 | `TC-B77-21…24`, `TC-B77-29`, `TC-B77-31`; `AT-B77-11`, `AT-B77-13`, `AT-B77-14` |
| `screens_directionb.py:878` `safe_text` | LLR-116.6, .7 | `AT-B77-15a`, `AT-B77-15b`; `test_b77_safe_text_scrubs_the_control_byte_class_without_damaging_identity` |
| `screens_directionb.py:2145` `_SELECTED_ROW_CLASS` | LLR-117.1 | `TC-B77-25` *(inline)*; `AT-B77-12` |
| `s19_app/tui/styles.tcss:789/798/811` | LLR-111.9 | `test_at073b_glance_geometry_fits_and_reflows` |
| `styles.tcss:857-864` `.map-region-row.map-region-selected` | LLR-117.2 | `TC-B77-32`, `TC-B77-33` |
| `s19_app/tui/app.py:1352/1356/1359` bindings · `:5867` `action_show_legend` | LLR-114.2, LLR-115.4 | `TC-B77-15`; `AT-B77-07`; `AT-B77-09`/`16`'s **substitute** mutation; frozen `TC-011` |
| `s19_app/tui/insight_style.py:124` `human_bytes` | LLR-113.1, .2 | `TC-B77-11…13`; `AT-B77-05` |
| `s19_app/tui/legend.py` | LLR-112.3 *(census site 7 — **prose**, matching no id-keyed grep)* | Amendment A/B census; `TC-519` (re-scoped, `tests/test_legend_two_pane.py:714`) |
| `tests/goldens/batch77/at-b77-02-gapless-band-strip.txt` | LLR-111.4 | `AT-B77-02` (`test_b77_gapless_golden` + 3 supporting nodes at `:1193`, `:1220`, `:1256`) |

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-08-01-batch-77` |
| Closing date | **2026-08-03** |
| Merge | PR **#186**, squash **`244ecf2`**, off `origin/main` @ `f8747b8`; **+2 post-gate commits** (`2f427a9` product fix, `bfddcc9` record corrections) |
| Total iterations (sum of phases) | **5** recorded — `{0:0, 1:2, 2:3, 3:0, 4:0, 5:0, 6:0}`. ⚠️ **Understated:** the batch ran **10 increments, 3 of which iterated**, and the flow never writes the Phase-3 counter. See **G-113**. |
| Validation passed | **yes — `PASS-WITH-NOTES`** (`04-validation.md`). 27/27 live LLRs · 7/7 HLRs · **0 blocker fails** · 4 notes (N-A…N-D), all load-bearing for the postmortem |
| Blockers at the merge gate | **0.** The independent review returned **2 HIGH / 2 MED / 3 LOW** — **both HIGHs were record defects**; the suite was unchanged at 2605/2/3 across the corrective pass, **which is itself the evidence every edit was documentation** |
| Defects in shipped product code | **exactly 1**, across roughly twenty review passes — and **CI found it, not review** (G-107) |
| Synced to Obsidian | **no — pending.** `state.json` still reports `current_phase: 3`; advance it at sync (**G-113**) |

### Open at close

| Item | Owner |
|---|---|
| 🛑 **`C-77-l` — the batch-78 aggregation charter. LOAD-BEARING.** 11 measurements pre-paid; `case_08_heavy_fragmentation` named as the acceptance fixture from the start; a **time budget** must be added to its constraints (aggregation is O(n²) on the UI thread — measured n=1000 → 31.10 ms, n=5000 → 840.34 ms uncapped). **Losing it retroactively converts a recorded descope into an undocumented gap.** | batch-78 · `BACKLOG-CODE.md:69` |
| **`AT-B77-19`'s first-render-only carry (G-108)** — verify at batch-78's Phase 0. **Read it from the queue, not from any artifact.** | batch-78 · `BACKLOG-CODE.md` |
| `C-77-f` (`o` = open-hex) · `C-77-g` (2-col fold marker) · `C-77-j` (1-col glance-box clip, still live @80×24) · `C-77-k` (deepened stats scroll — **the widen must not be narrowed to protect it**) | `BACKLOG-CODE.md:82-85` |
| **Registry-lane rename** — `TC-519`'s node name is now inaccurate; `AT-TC-REGISTRY` binds it to that exact node path, so a rename is a **registry** change, not a test change | registry lane · `BACKLOG-CODE.md:87` |
| **G-110** — locate `660k`'s producer or strike it | this matrix / next Phase 0 |
| **G-113** — advance `state.json`; count or remove the Phase-3 iteration field | sync step |
| Four proposed controls, each needing its own `AskUserQuestion` (C-33 re-wording · C-25 extension · N-of-N runs for timing-sensitive gates · self-caught probe defects recorded in the commit body) | `BACKLOG-PROCESS.md` |
| **CC-1 encoding decision** — still owed to the operator, carried since batch-76 | operator |
| `stash@{0}` (WIP @ `fffb299`) · 8 tracked `.pyc` files under `s19_app/__pycache__/` | operator / next batch |
