# Traceability Matrix — s19_app (Textual TUI) — Batch 2026-07-15-batch-47 (screen-upgrades Batch A)

> **Artifact language:** English (per kickoff).
> **Basis:** `01-requirements.md` (HLR-065…074 / LLR-065.1…074.3 / §5.2 dual chains, §6.5 Amendments A–E) ·
> `04-validation.md` (Phase-4 AT→real-node reconciliation, tree HEAD `12c5d1c`) · `05-postmortem.md`.
> **Node names below are the REAL on-disk collected nodes** reconciled at Phase 4 — not the provisional
> Phase-1 paths. Authoritative gate: `pytest -q -m "not slow"` → `1416 passed, 2 skipped, 20 deselected,
> 32 xfailed`, **exit 0, 0 failed**.

> Two chains (per the Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.

---

## 1. Master table — functional chain (white-box)

> `TC` ids are the canonical Phase-1 §5.2 ids. Per the Phase-4 **V-5 fold** (`04-validation.md` §2),
> several white-box TCs were realized *inside* their black-box AT node rather than duplicated as a
> separate node (one node per observable, C-18). Those rows name the AT node and are marked `(fold)` —
> a fold, not a gap: every LLR lands on ≥1 green node.
> `File:line` = the shipped implementation site (line numbers at HEAD `12c5d1c`).

| US | HLR | LLR | TC | File:line | Green node | Status | Notes |
|----|-----|-----|----|-----------|------------|--------|-------|
| US-FND | HLR-065 | LLR-065.1 | TC-065.1 | `s19_app/tui/insight_style.py:34-62` | `tests/test_tui_insight_style.py::test_palette_constants_present_and_correct` (L42) | pass | NEW non-frozen module; 14 palette + 2 microbar constants |
| US-FND | HLR-065 | LLR-065.2 | TC-065.2 | `s19_app/tui/insight_style.py:68` (`human_bytes`), `:119` (`label_value`), `:160` (`microbar`), `:207` (`threshold_style`) | `…::test_human_bytes` (L63) · `::test_microbar` (L87) · `::test_microbar_returns_text` (L110) · `::test_label_value_returns_text` (L121) · `::test_threshold_style` (L139) | pass | **§6.5 Amendment D**: binary 1024 / `KiB…PiB`. `Text`-returning helpers are C-17-safe by construction |
| US-FND | HLR-065 | LLR-065.3 | TC-065.3 | `s19_app/tui/styles.tcss:26-31` (`$`-vars), `:237-258` (`.db-pane` tall border + `datatable--odd-row`) | `tests/test_tui_theme.py::test_at065a_palette` (L236) + TC-012/TC-013 invariant guards preserved | pass | App-wide via `Screen`; drives the 29-cell snapshot drift (§4) |
| US-FND | HLR-065 | LLR-065.4 | TC-065.4 | `s19_app/tui/styles.tcss:510-541` (`sev-*` hues); `color_policy.py` **0-diff** | `tests/test_color_policy_round_trip.py` (FROZEN, green) + `tests/test_tui_theme.py::test_at065b_sev_semantics` (L272) | pass | **§6.5 Amendment C** — hues restyled, class NAMES + semantics + families preserved |
| US-WS | HLR-066 | LLR-066.1 | TC-066.1 | `s19_app/tui/app.py::_compose_screen_workspace` (border titles on `#ws_left`/`#ws_center`/`#ws_right`) | snapshot cell + AT-066 mount setup (WS compose) | pass | (fold) pane titles observed via the AT setup + snapshot |
| US-WS | HLR-066 | LLR-066.2 | TC-066.2 | `s19_app/tui/app.py::update_sections:8453` | `tests/test_tui_directionb.py::test_at040a` (retargeted to `insight_style.microbar`) | pass | Dead `build_coverage_bar_text`/`coverage_bar_cells` removed (Inc-3 own-mess) |
| US-WS | HLR-066 | LLR-066.3 | TC-066.3 | `s19_app/tui/hexview.py::_hex_byte_style:27` → `render_hex_view_text:360` | `tests/test_tui_hexview_classed.py` — 7 TCs incl. `::test_tc066_6_printable_ascii_class_boundaries` | pass | Public hex constants (`MAX_HEX_BYTES`/`MAX_HEX_ROWS`/`HEX_WIDTH`/`SEARCH_ENCODING`) unchanged |
| US-WS | HLR-066 | LLR-066.4 | TC-066.4 | `s19_app/tui/app.py::build_loader_facts_text:852` → `#ws_stats` | AT-066a/066b/066c nodes (below) | pass | (fold) value + both entry branches asserted at the render layer |
| US-WS | HLR-066 | LLR-066.5 | TC-066.5 | `s19_app/tui/models.py:72-73` (defaulted fields) · `services/load_service.py:65,84-85` (S19) · `:123-124` (HEX) | `tests/test_tui_workspace_insight.py::test_ooo_count_populated` (L86) · `::test_entry_point_s19` (L98) · `::test_entry_point_hex_none` (L113) · `::test_fields_default_on_bare_construction` (L138, MN-6) | pass | Defaulted + appended after `entropy_windows` → ~40 omitting constructors keep compiling; **no frozen test constructs `LoadedFile`** → C-27 0-diff |
| US-WS | HLR-066 | LLR-066.6 | TC-066.6 | `s19_app/tui/app.py` `#ws_stats` Static `markup=False` | markup=False inspection (Inc-3 packet) | pass | C-17 **N/A with reason**: the line carries error COUNT + hex address only, no file-derived free text |
| US-WS | HLR-066 | LLR-066.7 | TC-066.7 | `s19_app/tui/app.py:7280-7281` (`_merge_primary_with_existing_mac`, def `:7235` — carries from `primary_loaded`) · `:7327-7328` (`_merge_mac_with_existing_primary`, def `:7284` — carries from `existing`); `_load_mac_file` `:7004` correctly takes the defaults | AT-066d node (below) | pass | **MJ-1** — writer-census (C-15.1) caught the carry-forward drop at Phase 2, before code. *(Line cites re-verified at Phase 6 — the earlier `:6954`/`:6997` were Phase-1 recon estimates that shifted as `app.py` grew.)* |
| US-WS | HLR-067 | LLR-067.1 | TC-067.1 | `s19_app/tui/app.py::update_memory_strip:8636` → `#ws_memstrip`; `entropy_style.band_style:69` | AT-067 node + `tests/test_tui_directionb.py::test_at040b` (retargeted to the Amendment-A band contract) | pass | **§6.5 Amendment A** — retires the "D3 descoped / no entropy" limitation on this surface |
| US-WS | HLR-067 | LLR-067.2 | TC-067.2 | `s19_app/tui/app.py:628` `_STRIP_GAP_GLYPH = "╱"`; applied `:8709` | AT-067 node | pass | (fold) `╱` is **app-supplied**, NOT from `entropy_style` (A2) |
| US-WS | HLR-067 | LLR-067.3 | TC-067.3 | `s19_app/tui/app.py::update_memory_strip` no-entropy branch | `tests/test_tui_directionb.py::test_at040b` (fallback branch) | pass | Empty `entropy_windows` → pre-existing valid/invalid/gap colouring, no raise |
| US-WS | HLR-067 | LLR-067.4 | TC-067.4 | `#ws_memstrip` container | Inc-3 C-29 both-axes structural invariant | pass | (analysis) geometry **measured**, not assumed |
| US-A2L | HLR-068 | LLR-068.1 | TC-068.1 | `s19_app/tui/app.py::_build_a2l_table_cells:9542` (returns `tuple[Text, ...]`) → `#a2l_tags_list` | `tests/test_tui_a2l_detail.py::test_cells_are_text_and_glyph` (L324, all-16-cells-`Text`) + AT-068 node | pass | **§6.5 Amendment E** — per-cell accents are builder-only; the severity-row contract (HLR-037) stays dominant |
| US-A2L | HLR-068 | LLR-068.2 | TC-068.2 | `s19_app/tui/app.py` → `#a2l_tags_summary` | `tests/test_tui_a2l_detail.py::test_summary_count` (L347) | pass | Count == `in_memory`-truthy tags |
| US-A2L | HLR-068 | LLR-068.3 | TC-068.3 | `s19_app/tui/app.py::_build_a2l_table_cells:9542`; `safe_text` (`screens_directionb.py:615`) | AT-069c ★ node (below) | pass | (fold) distinct sink from the card — its own gate-blocking hostile-input AT |
| US-A2L | HLR-069 | LLR-069.1 | TC-069.1 | `s19_app/tui/app.py::A2LDetailCard:734` (`#a2l_detail_card`, mounted top of `#a2l_hex_pane`) | AT-069 node + widget member-name inspection | pass | Only new member = `show_tag` → `set(dir(Widget)) ∩ {…} == ∅`; no `_nodes`/`_context` shadowing (R4) |
| US-A2L | HLR-069 | LLR-069.2 | TC-069.2 | `s19_app/tui/app.py::on_data_table_row_highlighted:6345` | AT-069 node | pass | NEW handler (RowHighlighted, not RowSelected — live cursor-move feedback, §6.2) |
| US-A2L | HLR-069 | LLR-069.3 | TC-069.3 | `s19_app/tui/app.py::_a2l_detail_card_text:668` + `_card_field` (composed at `Text` level) | AT-069b ★ node (below) | pass | (fold) MN-5/F4: never f-strings a file-derived value into markup |
| US-A2L | HLR-069 | LLR-069.4 | TC-069.4 | `#a2l_hex_pane` split | Inc-4 C-29 measured (card h=5; hex not occluded @80×24) | pass | (analysis) both axes measured |
| US-MAC | HLR-070 | LLR-070.1 | TC-070.1 | `s19_app/tui/app.py::_mac_status_glyph:583` → `_populate_mac_datatable:9192` / `update_mac_view:9043` → `#mac_records_list` | AT-070 + AT-070c + AT-070d nodes (below) | pass | 4-way glyph; **Inc-5 F1 iterate-to-fix** — re-keyed off `row[3]` `in_mem_text` (finest discriminator), not the collapsed Status string |
| US-MAC | HLR-070 | LLR-070.2 | TC-070.2 | Tag cell `Text().append`; `safe_text` (`screens_directionb.py:615`) | AT-070b ★ node (below) | pass | (fold) |
| US-MAC | HLR-071 | LLR-071.1 | TC-071.1 | `s19_app/tui/services/validation_service.py::build_mac_coverage_strip:28` → `#mac_coverage_strip` | AT-071 node + `tests/test_tui_mac_coverage.py::test_build_mac_coverage_strip_counts` (L299) | pass | `X`/`Y`/`N` from `CoverageMetrics.mac_in_s19`/`mac_total`/`a2l_mac_address_matches` |
| US-MAC | HLR-071 | LLR-071.2 | TC-071.2 | `s19_app/tui/app.py::_update_mac_coverage_strip:9150` (`show=` gate) | AT-071 node + `tests/test_tui_mac_coverage.py::test_zero_total_no_divzero` (L290, MN-3 boundary) | pass | Strip shown whenever a MAC is loaded, independent of primary file type |
| US-MAP | HLR-072 | LLR-072.1 | TC-072.1 | `screens_directionb.py::MemoryMapPanel._build_band_widgets:1505`; `_MAP_GAP_HATCH = "╱"` `:205`, applied `:1580` (`.map-band-gap`) | AT-072a node (below) | pass | **§6.5 Amendment B** — extends R-TUI-060/041 |
| US-MAP | HLR-072 | LLR-072.2 | TC-072.2 | `insight_style.human_bytes:68` consumed by the map read-outs | `tests/test_tui_insight_style.py::test_human_bytes` + AT-073/AT-074 humanized read-outs | pass | Binary sizes (Amendment D) — `0x10000` → `64.0 KiB` |
| US-MAP | HLR-072 | LLR-072.3 | TC-072.3 | `screens_directionb.py::MapRuler:1103` | AT-072b node (below) | pass | 5 ticks @ 0/25/50/75/100 %. C-29-measured grid = 66×14 @80×24 / 52×12 @120×30 → `0x` prefix dropped at 52 cols (C-13.1 fallback) |
| US-MAP | HLR-072 | LLR-072.4 | TC-072.4 | — (documentation obligation) | §6.5 Amendment B recorded + this batch's REQUIREMENTS.md amendment of R-TUI-060/041 | pass | (inspection) |
| US-MAP | HLR-073 | LLR-073.1 | TC-073.1 | `screens_directionb.py::_region_symbol_counts:1455` → `_build_region_row:1617`; `_tag_address` helper | AT-073 node (below) | pass | `N sym` via frozen `range_index` membership primitives (read-only) — **no linear scan** (inspection) |
| US-MAP | HLR-073 | LLR-073.2 | TC-073.2 | `screens_directionb.py::_build_region_row:1617` (`↵`); `RegionRow.Activated` / `OpenInHexRequested` REUSED | AT-073 / AT-074 nodes; `tests/test_tui_directionb.py` RegionRow suite green unchanged | pass | Message contract unchanged (R-TUI-062 preserved) |
| US-MAP | HLR-073 | LLR-073.3 | TC-073.3 | region-list container (`height: auto`) | Inc-6 C-29 measured → reachable-under-scroll | pass | (analysis) |
| US-MAP | HLR-074 | LLR-074.1 | TC-074.1 | `screens_directionb.py::on_region_row_activated` → `#map_detail_body`; `dominant_band_label` (`app.py:797`) | AT-074 ★ node (below) | pass | Existing message/handler reused |
| US-MAP | HLR-074 | LLR-074.2 | TC-074.2 | `screens_directionb.py::_region_hex_peek:1977` | AT-074 ★ node | pass | Peek first address == region start; ≤3 rows (C-29-measured) |
| US-MAP | HLR-074 | LLR-074.3 | TC-074.3 | `symbols_in_window` → `symbol_list_text` → `safe_text` (`screens_directionb.py:615`, usage `:1168`) | AT-074 ★ MN-4 C-17 sub-assertion | pass | (fold) A2L symbol names DO surface here → hostile-input AT **mandatory**, not conditional |

**Functional chain: 36/36 LLRs → ≥1 green node. 0 rows incomplete.**

## 1b. Behavioral chain (black-box)

> One row per **canonical AT** (20 nodes = 19 Phase-2 base + `AT-070d`, the Inc-5 C-10 fourth-branch
> addition self-owned by its increment). ★ = **C-17 gate-blocking**. Every AT drives the shipped screen
> via `App.run_test(size=…)` at **BOTH 80×24 and 120×30** inside the single node
> (`_SIZES = ((80,24),(120,30))` loop, or per-size `@parametrize` in `test_tui_workspace_insight.py`).
> Each node was grep-confirmed collected at HEAD `12c5d1c` and is part of the `1416 passed`.

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Real node | Status |
|----|----------------------------|-----------------|--------------------------------|-----------|--------|
| US-FND | AT-065a | `styles.tcss` applied app-wide via `Screen` | Screen bg == `DEPTH_BG` (`#0a0e1b`) ∧ `.db-pane` bg == `DEPTH_PANEL` (`#0f1525`); app boots | `tests/test_tui_theme.py::test_at065a_palette` (L236) | pass |
| US-FND | AT-065b | `styles.tcss` `sev-*` + FROZEN `color_policy.css_class_for_severity` | live `sev-error` resolves the pastel RED (`#fd8383`) **and** the round-trip holds for all 5 severities | `tests/test_tui_theme.py::test_at065b_sev_semantics` (L272) | pass |
| US-WS | AT-066a | `build_loader_facts_text` → `#ws_stats` | `#ws_stats` contains `⚠4 OOO` (== 4 for `examples/case_00_public/prg.s19`) | `tests/test_tui_workspace_insight.py::test_at066a_ooo` (L168) | pass |
| US-WS | AT-066b | `#ws_stats` | `Entry 0x80000000` (`case_01`); boundary — a present `0x0` renders `0x00000000`, distinct from ABSENT `—` | `…::test_at066b_entry_present` (L189) | pass |
| US-WS | AT-066c | `#ws_stats` (inline `IntelHexFile`) | HEX → `Entry —` at the render layer (type 03/05 discarded, A5) | `…::test_at066c_entry_absent_hex` (L219) | pass |
| US-WS | AT-066d | MAC-merge `app.py:7280-7281`/`:7327-7328` → `#ws_stats` | **counterfactual (MJ-1/F-1)**: load S19 OOO=4 → attach MAC → `#ws_stats` STILL `⚠4 OOO` + entry preserved | `…::test_at066d_merge_preserves_facts` (L248) | pass |
| US-WS | AT-067 | `update_memory_strip` → `#ws_memstrip` | ≥2 distinct band styles from `{· ░ ▒ ▓}` **and** ≥1 `╱` gap glyph | `…::test_at067_memstrip` (L290) | pass |
| US-A2L | AT-068 | `_build_a2l_table_cells` → `#a2l_tags_list` | glyph column shows `✓` on `in_memory`-truthy **and** `·` on falsy — **both branches by content** (C-10) | `tests/test_tui_a2l_detail.py::test_at068_glyph_branches` (L204) | pass |
| US-A2L | AT-069 | `on_data_table_row_highlighted` → `A2LDetailCard.show_tag` | highlighting a **non-default** row renders THAT tag's description + unit in the card | `…::test_at069_card_highlight` (L225) | pass |
| US-A2L | **AT-069b ★** | `A2LDetailCard` body (`_a2l_detail_card_text`) | **C-17**: full MD-1 payload verbatim in card `Text.plain`; no payload-derived span; no `MarkupError` | `…::test_at069b_c17_card` (L260) | pass |
| US-A2L | **AT-069c ★** | `_build_a2l_table_cells` → `#a2l_tags_list` | **C-17, distinct sink**: hostile A2L NAME verbatim in the table cell `Text.plain`, `spans == []` | `…::test_at069c_c17_table_name` (L294) | pass |
| US-MAC | AT-070 | `_populate_mac_datatable` → `#mac_records_list` | both `✓` (parse-ok + in-image) and `⚠` (parse-ok + out-of-image) by content (`case_02`) | `tests/test_tui_mac_coverage.py::test_at070_glyph_branches` (L131) | pass |
| US-MAC | **AT-070b ★** | MAC tag cell `Text().append` | **C-17**: hostile MAC name verbatim in `Text.plain`; no `red`/`link` span; no `MarkupError` | `…::test_at070b_c17_name` (L152) | pass |
| US-MAC | AT-070c | `#mac_records_list` | parse-error MAC record → `✗` glyph (NEW inline malformed fixture, M1) | `…::test_at070c_parse_error` (L192) | pass |
| US-MAC | AT-070d | `#mac_records_list` | **Inc-5 C-10 4th branch**: MAC-only parse-ok record → grey `·` (not a false-green `✓`) | `…::test_at070d_mac_only_unchecked_glyph` (L223) | pass |
| US-MAC | AT-071 | `build_mac_coverage_strip` → `#mac_coverage_strip` | strip contains `1 of 2` == the fixture's `CoverageMetrics` | `…::test_at071_strip` (L271) | pass |
| US-MAP | AT-072a | `MemoryMapPanel._build_band_widgets` | band strip ≥2 band styles + ≥1 `╱` hatch (`case_02`, 4 ranges) | `tests/test_tui_map_big.py::test_at072a_bands` (L92) | pass |
| US-MAP | AT-072b | `MapRuler` widget | ruler renders **exactly 5** ticks; first == span start, last == span end | `…::test_at072b_ruler` (L121) | pass |
| US-MAP | AT-073 | `_build_region_row` → `RegionRow` | per-region `N sym` == an **independent `range_index` oracle** + `↵` affordance present | `…::test_at073_sym_count` (L153) | pass |
| US-MAP | **AT-074 ★** | `on_region_row_activated` / `_region_hex_peek` → `#map_detail_body` | activate a **non-first** region → hex-peek first address == that region's start; **+ mandatory C-17 sub-assertion (MN-4)**: bracketed A2L symbol name verbatim in `#map_detail_body` | `…::test_at074_inspector` (L201) | pass |

**Behavioral chain: 21/21 canonical ATs (21st = **AT-065c** US-FND/HLR-065/LLR-065.4 -> `tests/test_tui_theme.py::test_at065c_legend_labels_match_resolved_hues`, added Inc-10 with 6.5 Amendment F: binds every legend colour LABEL to the hue its severity class resolves to, by HSV family; closes the gap AT-065b left by probing `sev-error` only) → exactly one collected on-disk node each, at both pilot sizes.
No AT covered-in-parts; no orphan; no missing node. Every US has ≥1 AT.**

### 1c. C-17 gate-blocking set (4 sinks — all green)

| Sink | AT | Node | Discriminating evidence |
|---|---|---|---|
| A2L detail card | AT-069b ★ | `test_tui_a2l_detail.py::test_at069b_c17_card` | payload verbatim in `Text.plain`, no payload span, no `MarkupError` |
| A2L table cell (distinct sink) | AT-069c ★ | `test_tui_a2l_detail.py::test_at069c_c17_table_name` | `spans == []` on the cell |
| MAC record name | AT-070b ★ | `test_tui_mac_coverage.py::test_at070b_c17_name` | no `red`/`link` span |
| Memory-Map region inspector | AT-074 ★ (sub-assert, MN-4) | `test_tui_map_big.py::test_at074_inspector` | `sensor[red]` verbatim in `#map_detail_body` |

All four assert the full **MD-1 payload set** — `[red]…[/red]` · `[link=http://x]u[/link]` ·
`\x1b[31mX\x1b[0m` (ANSI) · `sensor[unclosed` — renders **verbatim**. The unbalanced-bracket
`sensor[unclosed` is the discriminating **`Text.from_markup` counterfactual**: it would raise or
mis-span under markup parsing, so the ATs are genuine, not vacuous. Safety holds **by construction**
(`safe_text = Text(value)` + `.append`; never `Text.from_markup`, never an f-string into markup).

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 5 (US-FND, US-WS, US-A2L, US-MAC, US-MAP) |
| Covered user stories | 5 (100 %) |
| Total HLR | 10 (HLR-065…074 → R-TUI-065…074) |
| Implemented HLR | 10 (100 %) |
| Total LLR | 36 (LLR-065.1…074.3) |
| Implemented LLR | 36 (100 %) |
| Test cases (TC) | 36 canonical TC ids (LLR-level), realized across the nodes above (several V-5-folded into their AT node) |
| TC pass | 36 |
| TC fail | 0 |
| TC pending | 0 |
| Canonical ATs | 20 (19 base + AT-070d) |
| AT pass | 20 (100 %) — each single-node, both pilot sizes |
| C-17 gate-blocking ATs | 4 / 4 green |
| Authoritative gate | `1416 passed, 2 skipped, 20 deselected, 32 xfailed` — **exit 0, 0 failed** |
| Frozen-file diff (C-27 dual-guard: 7 src paths + 9 test files) | **0** at HEAD `12c5d1c` (incl. `color_policy.py` under the sev-* restyle) |

> **Note on the LLR count.** `05-postmortem.md` records "32 LLRs". The enumerated set in
> `01-requirements.md` §4 is **36** (065:4 · 066:7 · 067:4 · 068:3 · 069:4 · 070:2 · 071:2 · 072:4 ·
> 073:3 · 074:3). The post-mortem figure is a miscount; the coverage conclusion is unaffected — all 36
> are green here and in `04-validation.md` §2.

---

## 3. Detected gaps

**NONE.** Every functional row lands on ≥1 green node; every user story has a behavioral row; no AT is
covered-in-parts or orphaned; no requirement is without a TC; no TC is without a code mapping.
`04-validation.md` §5 records **no feedback edge triggered** (no `iterate-to-fix` / `iterate-to-refine`
at the gate).

The items below are **accounted, not gaps** — recorded so a reader does not mistake them for coverage
holes:

| ID | Type | Description | Disposition |
|----|------|-------------|-------------|
| N-1 | drift (accounted) | 29 batch-47 theme-drift `tc016s` snapshot cells are `xfail(strict=False)` — stale baselines still encode the pre-theme hues **by design** | **Not a failure.** Regen is canonical-CI-only (`snapshot-regen.yml`, textual==8.2.8) as a post-merge follow-up PR (`reference_snapshot_regen_env`; local regen prohibited). **0 xpassed** → the C-22 per-cell census is complete and non-masking. Retires the `_batch47_*_drift_marks` together. |
| N-2 | xfail (pre-existing) | 3 of the 32 xfails pre-date batch-47 (`test_tui_app.py:1784`, `test_tui_public_api.py:162`, `test_validation_engine.py:211`) | Outside batch-47; none is a batch-47 regression |
| N-3 | fold (accounted) | TCs `TC-066.4`/`.6`, `TC-067.2`/`.3`, `TC-068.3`, `TC-069.3`, `TC-072.1`/`.3`, `TC-073.1`, `TC-074.1`/`.2`/`.3` realized inside their AT node | **V-5 fold**, per C-18 (one node per observable). Every LLR still has a green node |
| N-4 | product follow-up | A2L per-cell accents are builder-only (§6.5 Amendment E) — subsumed by the HLR-037 severity-row contract | Surfaced, not averaged (eng-rule 7). Operator decides in a follow-up whether to promote to requirements or drop. **Not a batch-47 deliverable** — no acceptance criterion is unmet (AT-068/AT-069c assert glyph + C-17, never live-table accent colour) |

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | R-TUI-065 … R-TUI-074 | Ten NEW registry rows (REQUIREMENTS.md §37) — the batch-47 insight layer |
| new | `s19_app/tui/insight_style.py` | NEW non-frozen helper module (palette constants + 4 pure `Text`-returning helpers) |
| new | `LoadedFile.out_of_order_count` / `.entry_point` | Two NEW **derived** dataclass fields, defaulted + appended after `entropy_windows`, populated in the non-frozen `load_service` |
| new | AT-070d | Self-owned Inc-5 addition — the C-10 fourth glyph branch (MAC-only ⇒ `·`), closing the Inc-5 F1 false-green |
| modified | R-TUI-042 (c) | **§6.5 Amendment A** — the Workspace memstrip gains entropy banding + `╱` gap; the "no entropy / D3 descoped" limitation is retired for that surface (valid/invalid/gap retained as the fallback) |
| modified | R-TUI-060 / R-TUI-041 | **§6.5 Amendment B** — band-bands view extended: address ruler + `╱` hatch + humanized sizes + enriched region rows + inspector hex peek |
| modified | R-TUI-024 + §3 severity conventions | **§6.5 Amendment C** — `sev-*` hues restyled to the pastel palette; class NAMES, severity semantics, and hue families preserved; `color_policy.py` **0-diff** |
| modified | LLR-065.2 (`human_bytes`) | **§6.5 Amendment D** — binary (1024) `KiB…PiB` convention (operator decision 2026-07-15) |
| modified | LLR-068.1 (A2L accents) | **§6.5 Amendment E** — accents scoped to the builder; the severity contract stays dominant |
| retired | `build_coverage_bar_text` / `coverage_bar_cells` + its test | Dead after LLR-066.2 retargeted section rows onto `insight_style.microbar` (Inc-3, own-mess-only) |
| preserved | `RegionRow.Activated` / `MemoryMapPanel.OpenInHexRequested` | Reused unchanged (R-TUI-062 contract intact) |
| closed | — | No gap carried in from batch-46; none opened here |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-FND** → HLR-065 → LLR-065.1, .2, .3, .4 → TC-065.1–.4 → AT-065a, AT-065b
- **US-WS** → HLR-066, HLR-067 → LLR-066.1–.7, LLR-067.1–.4 → TC-066.1–.7, TC-067.1–.4 → AT-066a, AT-066b, AT-066c, AT-066d, AT-067
- **US-A2L** → HLR-068, HLR-069 → LLR-068.1–.3, LLR-069.1–.4 → TC-068.1–.3, TC-069.1–.4 → AT-068, AT-069, AT-069b ★, AT-069c ★
- **US-MAC** → HLR-070, HLR-071 → LLR-070.1–.2, LLR-071.1–.2 → TC-070.1–.2, TC-071.1–.2 → AT-070, AT-070b ★, AT-070c, AT-070d, AT-071
- **US-MAP** → HLR-072, HLR-073, HLR-074 → LLR-072.1–.4, LLR-073.1–.3, LLR-074.1–.3 → TC-072.1–.4, TC-073.1–.3, TC-074.1–.3 → AT-072a, AT-072b, AT-073, AT-074 ★

### 5.2 By code file

| File | Frozen? | LLR | Nodes |
|---|---|---|---|
| `s19_app/tui/insight_style.py` **(NEW)** | no | LLR-065.1, .2 | `tests/test_tui_insight_style.py` (6 TCs) |
| `s19_app/tui/styles.tcss` | no | LLR-065.3, .4 | `tests/test_tui_theme.py` (AT-065a/b + TC-012/013) |
| `s19_app/tui/models.py` | no | LLR-066.5 | `test_tui_workspace_insight.py::test_fields_default_on_bare_construction` |
| `s19_app/tui/services/load_service.py` | no | LLR-066.5 | `test_tui_workspace_insight.py::test_ooo_count_populated` / `::test_entry_point_s19` / `::test_entry_point_hex_none` |
| `s19_app/tui/services/validation_service.py` | no | LLR-071.1 | `test_tui_mac_coverage.py::test_build_mac_coverage_strip_counts` + AT-071 |
| `s19_app/tui/app.py` | no | LLR-066.1, .2, .4, .6, .7 · LLR-067.1–.3 · LLR-068.1–.3 · LLR-069.1–.3 · LLR-070.1, .2 · LLR-071.2 · LLR-074.1 | `test_tui_workspace_insight.py`, `test_tui_a2l_detail.py`, `test_tui_mac_coverage.py`, `test_tui_directionb.py::test_at040a/b` |
| `s19_app/tui/hexview.py` | no | LLR-066.3 | `tests/test_tui_hexview_classed.py` (7 TCs) |
| `s19_app/tui/screens_directionb.py` | no | LLR-072.1, .3 · LLR-073.1, .2 · LLR-074.1–.3 | `tests/test_tui_map_big.py` (AT-072a/b, AT-073, AT-074) |
| `s19_app/core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` | **FROZEN (C-27)** | read-only consumers only | `test_tc027` + `test_tc031` + `test_tc032` green every increment; `git diff --stat main` **empty** |

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | `2026-07-15-batch-47` |
| Closing date | 2026-07-15 |
| Tree HEAD reconciled | `12c5d1c` (branch `claude/screen-upgrades-handoff-0874f9`) |
| Total iterations (sum of phases) | 5 (phases 0–4, 1 each; phases 5–6 = 0) + 1 **in-increment** iterate-to-fix (Inc-5 F1) |
| Increments | 8 (all ≤5 files; 0 cap trips) |
| Validation passed | **yes** — 21/21 ATs, 36/36 LLRs, 0 failed, exit 0 |
| Gaps | **none** |
| Synced to Obsidian | pending (`/dev-flow-sync` after merge) |
