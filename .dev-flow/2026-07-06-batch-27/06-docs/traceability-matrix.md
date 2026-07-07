# Traceability Matrix — s19_app — Batch 2026-07-06-batch-27

> **Audience:** engineers / reviewers auditing that every requirement in this batch is validated end-to-end.
> **Purpose:** the consolidated traceability artefact for **R-TUI-041 — Interactive Memory-Map Minimap** (US-035 / US-036 / US-037).
> Full chain, split into two provenance-honest tracks:
> **Behavioral** (US → HLR → AT observed through the shipped `#screen_map` surface) and
> **Functional** (HLR → LLR → white-box TC over the pure helpers / render path).
> All rows carry the Phase 4 verdict **PASS**. Two snapshot cells are **pending-baseline** (xfail-until-baseline by design — not failures).

Source artefacts:

- [`01-requirements.md`](../01-requirements.md) — §2.6 (US), §3 (HLR + acceptance blocks), §4 (LLR-041.1..041.11), §5.2 (dual traceability), §7 (AT/TC specs), §6.5 (Phase-1 iteration-2 amendments)
- [`03-increments/increment-001.md`](../03-increments/increment-001.md) (US-035), [`increment-002.md`](../03-increments/increment-002.md) (US-036), [`increment-003.md`](../03-increments/increment-003.md) (US-037)
- [`04-validation.md`](../04-validation.md) — §2 (Layer A white-box TC → real node → result), §3 (Layer B black-box AT → real node), §4 (bidirectional reachability), §6 (executed command outputs), §7 (provisional-id reconciliation)
- [`05-postmortem.md`](../05-postmortem.md)

**What this batch is:** a **TUI view-layer redesign**, engine-frozen. It respecifies `MemoryMapPanel` (`s19_app/tui/screens_directionb.py`), extends one call-site + adds one handler in `s19_app/tui/app.py`, and adds `#map_*` rules to `s19_app/tui/styles.tcss`. The panel performs **no new analysis** — it renders the already-computed `LoadedFile.ranges` / `range_validity` and the pre-computed `ValidationReport` issues (LLR-041.7). `git diff main` over the seven frozen engine modules is empty ([`04-validation.md`](../04-validation.md) §2 / §8; `test_engine_unchanged.py` + `test_tc031_*`).

---

## 1. Behavioral chain (black-box) — US → HLR → AT → real node

> Every AT drives the shipped surface: `action_show_screen("map")` + `update_memory_map()` under a Textual Pilot, then observes the rendered `#map_grid` / `#map_detail` / `#map_stats` widgets. Real node names are the collected `pytest` ids from [`04-validation.md`](../04-validation.md) §3.

| US | HLR | AT | Real test node (`tests/test_tui_directionb.py`) | Observed through surface | Verdict |
|----|-----|----|--------------------------------------------------|--------------------------|---------|
| US-035 | HLR-035 | AT-035 | `test_at035_minimap_grid_colours_and_header` | `#map_grid`.query(`.map-cell`) ≥1 valid + ≥1 gap class; header regex `≈\s*[\d.]+\s*KiB/cell` | PASS |
| US-036 | HLR-036 | AT-036a | `test_at036a_non_default_cell_changes_detail` | `press("right")` + `"enter"` → `#map_detail` text changes + new cell start-address token | PASS |
| US-036 | HLR-036 | AT-036a (hint) | `test_at036_detail_hint_prompts_navigation_before_selection` | pre-selection nav hint present in `#map_detail` | PASS |
| US-036 | HLR-036 | AT-036a (arrow/no-scroll) | `test_at036_arrow_moves_cell_focus_without_scrolling` | focus moves; `#map_content.scroll_offset.y` unchanged | PASS |
| US-036 | HLR-036 | AT-036b | `test_at036b_open_in_hex_focuses_cell_start` | hex row containing `cell_start` renders in `#hex_view` after jump (behavioral) | PASS |
| US-036 | HLR-036 | AT-036c | `test_at036c_valid_cell_detail` | valid status chip + covering-region bounds/size | PASS |
| US-036 | HLR-036 | AT-036d | `test_at036d_invalid_cell_seeded_issue_detail` | seeded `ERROR` issue → invalid chip + issue `code` + `0x{addr:08X}` + cell/region counts | PASS |
| US-036 | HLR-036 | AT-036e | `test_at036e_gap_cell_detail` | gap chip, no covering-region claim | PASS |
| US-036 | HLR-036 | AT-036f | `test_at036f_markup_safe_symbol_in_detail` | literal `sensor[red]` in `#map_detail`, no `MarkupError` (security B-1 / LLR-041.11) | PASS |
| US-036 | HLR-036 | AT-036g | `test_at036g_addressless_issue_excluded_from_cell_and_region` | `address=None` issue in **neither** cell list **nor** region count (R-1 default) | PASS |
| US-037 | HLR-037 | AT-037 | `test_at037_stats_strip_matches_case_02_coverage` | `#map_stats` 7 metrics; coverage-% == TC-041.8 hand-computed number | PASS |

**Behavioral coverage:** US-035 → 1 AT · US-036 → 8 AT (AT-036a expanded to 3 collected nodes — core + hint + arrow-no-scroll — the F1 follow-on; strengthens) · US-037 → 1 AT. Every output-producing story has ≥1 black-box AT through `#screen_map`. **No deliverable is observed only white-box** ([`04-validation.md`](../04-validation.md) §4).

---

## 2. Functional chain (white-box) — HLR → LLR → TC → real node

> One TC per LLR (with two LLRs split into a pair — see notes). Real node names are the collected ids from [`04-validation.md`](../04-validation.md) §2. Command: `pytest tests/test_tui_directionb.py -k "tc041 or tc025_memory" -v` → **14 passed, 107 deselected**.

| HLR | LLR | Method | TC | Real test node | Verdict |
|-----|-----|--------|----|----------------|---------|
| HLR-035 | LLR-041.1 — cell status derivation | test (unit) | TC-041.1 | `test_tc041_1_cell_status_derivation` | PASS |
| HLR-035 | LLR-041.2 — auto-scale + zero-span guard | analysis + test | TC-041.2 | `test_tc041_2_auto_scale_cell_count_and_zero_span` | PASS |
| HLR-035, HLR-036 | LLR-041.3 — colour via frozen severity map | inspection + test | TC-041.3 | `test_tc041_3_invalid_cell_carries_sev_error_class` | PASS |
| HLR-036 | LLR-041.4 — selection → detail content | test | TC-041.4 | `test_tc041_4_build_detail_text_content` | PASS |
| HLR-036 | LLR-041.4 — arrow-nav index + edge clamp | test | TC-041.4b | `test_tc041_4b_arrow_adjacent_index_and_edge_clamp` | PASS |
| HLR-036 | LLR-041.5 — cell-scoped issue join (boundary + negative) | test | TC-041.5 | `test_tc041_5_cell_issue_join_boundary_and_negative` | PASS |
| HLR-036 | LLR-041.6 — Open-in-Hex computes `focus=cell_start` | test | TC-041.6 | `test_tc041_6_open_computes_focus_equals_cell_start` | PASS |
| HLR-035/036/037 | LLR-041.7 — render-only / no new analysis | inspection | TC-041.7 | `test_tc028_memory_map_renderer_adds_no_coverage_computation` + direct AST scan of `MemoryMapPanel` body (0 I/O hits) | PASS |
| HLR-037 | LLR-041.8 — coverage stats (exact literals) | analysis + test | TC-041.8 | `test_tc041_8_coverage_stats_exact_case_02_literals` | PASS |
| HLR-037 | LLR-041.8 — single-range 100% boundary | test | TC-041.8b | `test_tc041_8_single_range_full_coverage_no_gaps` | PASS |
| HLR-035, HLR-037 | LLR-041.9 — empty / no-file state | test | TC-041.9 | `test_tc041_9_empty_state_stats_neutral_no_exception` | PASS |
| HLR-035, HLR-037 | LLR-041.9 — legacy empty (R-TUI-026 carry) | test | TC-025 | `test_tc025_memory_map_empty_state_with_no_file` / `…_clears_when_file_loads` | PASS |
| HLR-035/036 (layout) | LLR-041.10 — two-regime reflow at 119 vs 120 | test + inspection | TC-041.10 | `test_tc041_10_reflow_class_toggles_at_119_vs_120` | PASS |
| HLR-035/036 (security) | LLR-041.11 — markup-safe hostile text | test | TC-041.11 | `test_tc041_11_markup_safe_render_of_hostile_text` | PASS |

**Notes on split / method deviations (all forward-covered, [`04-validation.md`](../04-validation.md) §7):**

- **LLR-041.4** carries two nodes: `TC-041.4` (detail-text assembly) + `TC-041.4b` (arrow-nav index arithmetic + edge clamp). The arrow-nav helper `adjacent_cell_index` was added in the Increment-2 arrow-key follow-on (Inc-2 review F1 — the panel's docstring claimed arrow navigation the code did not yet provide; implemented + tested). Strengthens, does not weaken.
- **LLR-041.7** ships as `inspection` (no dedicated `pytest` node): satisfied by the pre-existing `test_tc028_memory_map_renderer_adds_no_coverage_computation` AST inspection of `update_memory_map` **plus** a direct AST scan of the `MemoryMapPanel` class body returning zero I/O hits.
- **LLR-041.8** carries two nodes: `TC-041.8` (exact hand-computed `case_02` literals — span `0x80010140`, covered `93 B`, coverage `0.000004%`, gaps `3`, largest gap `2,147,549,173 B`) + `TC-041.8b` (single-range 100%, gap 0 boundary).
- **LLR-041.9** carries the new `TC-041.9` (redesigned empty state) **and** the retained legacy `TC-025` pair (the R-TUI-026 empty-state carry — kept green through the redesign, confirming no regression on the no-file path).

---

## 3. R-* supersession — R-TUI-041 ⇄ R-TUI-026

| Field | Value |
|-------|-------|
| New living requirement | **R-TUI-041** — Interactive Memory-Map Minimap (colour-coded spatial grid + cell detail + coverage stats). Added to `REQUIREMENTS.md` in Increment 3. |
| Superseded requirement | **R-TUI-026** — the read-only monochrome per-range text-list Memory Map. Marked `Superseded by R-TUI-041`; its **statement is preserved** (mirrors the R-TUI-028 supersession pattern). |
| What is retained + strengthened | R-TUI-026's render-only contract (LLR-012.1: "read `LoadedFile.ranges`/`range_validity`, compute no new coverage data") is **carried verbatim and strengthened** into **LLR-041.7** — the redesign adds visualisation, never analysis. No contradiction ([`01-requirements.md`](../01-requirements.md) §6.4 reconciliation log). |
| What is replaced | The "monochrome text list" realisation (`_BAR_WIDTH=40` `#`-fill bars, one line per range) is replaced by the interactive `#map_grid` cell grid + `#map_detail` pane + `#map_stats` strip. |
| Legacy-test disposition | The three old TC-025 text-list assertions were superseded in Increment 1 (they asserted the retired text format; no survivor asserts old output — code-review confirmed legitimate supersession). The two **empty-state** TC-025 nodes are retained (§2) as the no-file regression guard. |

---

## 4. Coverage summary

Counts folded from [`04-validation.md`](../04-validation.md) §1–§3 and the three increment packets.

| Metric | Value |
|--------|-------|
| Total user stories | 3 (US-035, US-036, US-037) |
| Covered user stories | 3 (100%) |
| Total HLR | 3 (HLR-035, HLR-036, HLR-037) |
| HLR with verdict PASS | 3 (100%) |
| Total LLR | 11 (LLR-041.1 … LLR-041.11) |
| LLR with verdict PASS | 11 (100%) |
| White-box TC nodes (Layer A) | 14 collected — `pytest -k "tc041 or tc025_memory" -v` → **14 passed, 107 deselected in 5.13s** |
| Black-box AT nodes (Layer B) | 11 collected — `pytest -k "at035 or at036 or at037" -v` → **11 passed, 110 deselected in 13.41s** |
| TC / AT PASS | 25 / 25 (100%) |
| TC / AT partial / fail | 0 / 0 |
| Engine-frozen diffs | **0** (`test_engine_unchanged.py` → 1 passed; `test_tc031_*` pass) |
| Hard-coded severity colours in the panel | 0 (all via `css_class_for_severity`, LLR-041.3) |
| Raw file-derived text interpolated into a markup-parsed string | 0 (all via `safe_text` `Text(style=)`, LLR-041.11) |
| directionb + engine-guard suite at gate | **122 passed in 97.90s** |
| Snapshot suite at gate | **30 passed, 2 xfailed** (`-m "not slow"`, 40.77s) |
| Test ledger trajectory | 1037 → 1039 (Inc 1) → 1049 (Inc 2) → 1052 (arrow-nav follow-on) → **1058** (Inc 3) |
| Phase 4 verdict | **PASS** — no blockers |

### 4.1 Coverage by validation method

| Method | LLR / node count | Notes |
|--------|------------------|-------|
| test (unit, pure helpers) | LLR-041.1/.2/.4/.4b/.5/.8/.8b — 7 nodes | `cell_status`, `cell_count_for_geometry`/`bytes_per_cell`, `build_detail_text`, `adjacent_cell_index`, `issues_in_window`/`covering_range`, `coverage_stats`. |
| test (Pilot, black-box) | AT-035/036a(×3)/036b/036c/036d/036e/036f/036g/037 — 11 nodes | Real `#screen_map` surface under `run_test()`. |
| test (Pilot, white-box wiring) | TC-041.6, TC-041.9, TC-041.10, TC-025 | Focus math, empty state, reflow class toggle, legacy no-file carry. |
| inspection | LLR-041.3 (0 severity hex), LLR-041.7 (0 I/O in panel body) | `rg` / AST scans, each with its evidence in [`04-validation.md`](../04-validation.md). |
| test (snapshot) | 2 cells — pending-baseline | See §5. |

---

## 5. Pending-baseline snapshot cells (not failures)

Two `pytest-textual-snapshot` cells lock the redesigned layout and are **xfail-until-baseline** — a designed, documented state, not a defect. The minimap redesign necessarily drifts the SVG baseline, and baselines are regenerated **only** in the canonical CI environment (`snapshot-regen.yml`, pinned `textual==8.2.8`); local regen is forbidden ([[reference_snapshot_regen_env]], batch-25).

| Snapshot cell | Locks | State | Retirement |
|---------------|-------|-------|-----------|
| `map-comfortable-120x30` | wide-regime minimap render (detail beside grid) | `xfail(strict=False, reason="baseline-regen-pending: US-035/036/037 minimap redesign")` | Retire to green after canonical-CI baselines land (post-merge) |
| `map-comfortable-80x24` | narrow-regime reflow (detail stacked below grid, LLR-041.10) — added per qa M-2, mirroring the batch-22 patch 80×24 floor cell | same `xfail` marker | same |

The other 27 workspace snapshot cells stay green. Snapshot run at gate: **30 passed, 2 xfailed** ([`04-validation.md`](../04-validation.md) §6).

**Related carry — CARRY-F2 (non-blocking):** the shipped panel reads live `#map_grid.content_size` for the cell *count* (helper arithmetic is pure/injected for snapshot-stability). A trip-wire constant `_EXPECTED_MAP_CELLS_120x30 = 128` must be updated in lockstep with any future layout change + baseline regen. This is a documented lock, queued with the baseline regen.

---

## 6. Detected gaps

**Traceability completeness: NO GAPS.** Every one of the 3 US, 3 HLR and 11 LLR is traced end-to-end — a black-box AT through `#screen_map` **and** a white-box TC over the helper/render path — and carries a Phase 4 `PASS` verdict. There is no requirement without a validation method, no LLR without a passing TC, and no US without a passing AT. This satisfies the batch acceptance criteria in [`01-requirements.md`](../01-requirements.md) §5.3.

The items below are the explicitly **non-blocking** carries from [`04-validation.md`](../04-validation.md) §8 — none is a correctness defect, none gates the batch.

| ID | Type | Severity | Description | Disposition |
|----|------|----------|-------------|-------------|
| C-1 | Snapshot baseline | low | The 2 map snapshot cells are xfail-until-baseline (§5). | Regen in canonical CI post-merge (`snapshot-regen.yml`), then retire xfails to green. |
| C-2 | Trip-wire lock | low | CARRY-F2: `_EXPECTED_MAP_CELLS_120x30 = 128` live-geometry lock. | Update in lockstep with the baseline regen. |
| C-3 | Test-env flake | low | Pre-existing full-suite TUI global-state flake across ~1000 tests. | **Classified NOT a batch-27 regression** — the stashed-`main` control fails a different unrelated test; batch-27 suites are clean in isolation ([`04-validation.md`](../04-validation.md) §8, and each increment packet). |
| C-4 | Display precision (judgment) | low | Coverage-% uses `.6f` → `case_02` shows `0.000004%` (value correct; a coarser `.1f` would collapse to a misleading `0.0%`). | Operator decision — keep `.6f` or move to adaptive precision (`%g`) in a future polish. Value is correct either way. |

---

## 7. Quick bidirectional mapping

### 7.1 By user story

- **US-035 (colour-coded spatial minimap grid)** → HLR-035 → LLR-041.1 / .2 / .3 / .7 / .9 / .11 → TC-041.1/.2/.3/.9/.11 + AT-035
- **US-036 (cell selection → detail pane)** → HLR-036 → LLR-041.3 / .4 / .5 / .6 / .7 / .10 / .11 → TC-041.4/.4b/.5/.6/.10/.11 + AT-036a/b/c/d/e/f/g
- **US-037 (coverage stats strip)** → HLR-037 → LLR-041.7 / .8 / .9 → TC-041.8/.8b/.9 + AT-037

### 7.2 By code file (all outside the frozen engine set)

| Code file | Role in this batch | Increment | Tests |
|-----------|--------------------|-----------|-------|
| `s19_app/tui/screens_directionb.py` | `MemoryMapPanel` respecified: `MapCell` widget + 10 pure helpers (`derive_image_span`, `cell_count_for_geometry`, `bytes_per_cell`, `cell_status`, `status_to_css_class`, `safe_text`, `issues_in_window`, `covering_range`, `coverage_stats` + `CoverageStats`, `adjacent_cell_index`); `render_ranges` grid build + `build_detail_text` + `build_stats_text` + selection/arrow/Open-in-Hex handlers; `OpenInHexRequested` message | 1, 2, 3 | `tests/test_tui_directionb.py` (all TC-041.* + AT-035/036*/037) |
| `s19_app/tui/app.py` | ONE call-site change — `update_memory_map` passes `self._validation_issues` into `render_ranges` (`app.py:7211-7214`); ONE new handler — `on_memory_map_panel_open_in_hex_requested` (`app.py:7220`) switches to workspace + drives the **existing** `update_hex_view(focus_address=…)` | 2 | AT-036b, TC-041.6 |
| `s19_app/tui/styles.tcss` | `#map_header` / `#map_body` (+ `width-narrow` reflow) / `#map_grid` (`grid-size:16`) / `.map-cell` (+`:focus`) / `#map_detail` (+`width-narrow`) / `#map_detail_body` / `#map_open_hex_button` / `#map_stats` rules (`styles.tcss:529-617`) | 1, 2, 3 | TC-041.10 + the 2 snapshot cells |
| `s19_app/tui/color_policy.py` | **frozen** — `css_class_for_severity` / `SEVERITY_CLASS_MAP` consumed read-only (LLR-041.3); zero bytes changed | — | `test_engine_unchanged.py`, `test_tc031_*` |
| `s19_app/validation/model.py` | **frozen** — `ValidationIssue` (`code`/`severity`/`message`/`symbol`/`address`) read-only in the detail join; zero bytes changed | — | frozen guard |
| `tests/test_tui_directionb.py` | −3 superseded text-list TC-025 assertions; + all new TC-041.* / AT-035/036*/037 + `_install_case_04_loaded_file` helper | 1, 2, 3 | (the suite itself) |
| `tests/test_tui_snapshot.py` | `map-comfortable-120x30` + `map-comfortable-80x24` → xfail-until-baseline; scaffold cell count 28 → 29 | 1, 3 | snapshot suite |
| `REQUIREMENTS.md` | new **R-TUI-041**; **R-TUI-026** → `Superseded by R-TUI-041` (statement preserved) | 3 | — |

---

## 8. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-07-06-batch-27` |
| Batch title | R-TUI-041 — Interactive Memory-Map Minimap ("Variant B v2", operator prototype-approved) |
| Flow | `/dev-flow` (full V-model, phases 1–6), language `en` |
| Phase 3 | 3 increments (US-035 grid · US-036 selection/detail/Open-in-Hex + arrow-nav follow-on · US-037 stats strip + reflow) |
| Phase 4 verdict | **PASS** — no blockers; every story validated through `#screen_map` with boundary + negative evidence |
| Validation at gate | directionb + engine-guard **122 passed**; TC-041 `-k` slice **14 passed**; AT `-k` slice **11 passed**; snapshot **30 passed / 2 xfailed** |
| Engine freeze | verified — 0 diffs across the 7 frozen modules (`test_engine_unchanged.py` 1 passed; `test_tc031_*` pass) |
| Traceability completeness | **NO GAPS** — 3 US / 3 HLR / 11 LLR all traced (behavioral AT + functional TC) and `PASS` |
| Pending-baseline | 2 map snapshot cells (xfail-until-baseline) + CARRY-F2 lock — canonical-CI regen queued post-merge, explicitly non-blocking |
| `R-*` living-doc change | +R-TUI-041; R-TUI-026 superseded (statement preserved) |
| Synced to Obsidian | (post-merge — `/dev-flow-sync` after PR close) |
