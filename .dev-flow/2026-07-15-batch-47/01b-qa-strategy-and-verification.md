# 01b — QA Strategy & Verification — batch-47 (screen-upgrades Batch A)

> Companion to `01-requirements.md` (architect-owned — **not** edited here). AT ids + node paths in
> this file are the **orchestrator-pinned canonical crosswalk** from `02-review.md` (the SINGLE source
> of truth). Requirement ids below (`R-TUI-065..070`) remain **provisional**, derived from the stories
> in `PLAN.md` §"Stories (Phase 0 — DoR)" and the HANDOFF-PLAN §4/§5/§6. **Final AT/TC ↔ HLR/LLR
> reconciliation completes at Phase 4** against the architect's ids (V-5). Where the architect
> renumbers a REQUIREMENT id, the AT/TC bodies stay; only the traceability column changes. The AT ids
> and node paths themselves are now fixed to the canonical crosswalk and do not float.
> Artifact language: English.

---

## 0. BLUF

- **Two-layer verification.** Layer A = white-box `TC-NNN` (unit/integration/pilot/inspection/analysis
  over the mechanism). Layer B = **black-box `AT-NNN`** driving the SHIPPED screen through
  `App.run_test(size=…)` and asserting the observed deliverable at **both** 80×24 and 120×30.
- **29 TCs, 19 ATs** across 5 stories (AT count matches the canonical crosswalk exactly). Every
  output-producing story has ≥2 ATs per pilot size.
- **3 gate-blocking C-17 hostile-input ATs** — `AT-069b` (A2L card), `AT-069c` (A2L table cell),
  `AT-070b` (MAC name) — the batch-27/batch-43 injection-sink lesson. The A2L card and A2L table cell
  are **distinct builders / distinct sinks** and each own a gate-blocking node.
- **C-10 branch discipline enforced:** entry-point S19-present vs HEX-"—", MAC in-image vs
  out-of-image vs parse-error, and A2L in-image vs not each own **one AT per branch asserting the
  CONTENT** (right glyph / bytes / string), not just non-empty output.
- **C-29 two-axis:** every "how much fits" threshold (memstrip cell count, ruler tick spacing,
  region-row visibility) is **pilot-measured on BOTH axes** in Phase 3; ATs assert **structural
  invariants** (≥2 distinct band styles; exactly 5 ruler ticks; a description substring present),
  never a hard-coded rendered row/col count.
- **Snapshot drift is MASSIVE and expected** (app-wide theme + per-screen restyle). Regen is
  **canonical-CI-only**, a post-merge follow-up PR — never a local regen.

### Verified facts backing the ATs (recon this session, real fixtures)

| Fixture | OOO | ranges | S19 terminator (entry) | MAC coverage (mac_in_s19 / mac_total) |
|---|---|---|---|---|
| `case_00_public/prg.s19` | **4** | 11 | S9 `0x0` | — |
| `case_00_public/s19_sample.s19` | 1 | 2 | S9 `0xffff` | — |
| `case_01_basic_valid/firmware.s19` | 0 | 3 | **S7 `0x80000000`** (non-zero) | 1 / 1 (all in-image) |
| `case_02_gaps_and_patch_targets/firmware.s19` | 0 | **4 (gaps)** | S7 `0x80000000` | **1 / 2** (one ✓ + one ⚠) |
| `case_07_stress_smoke/firmware.s19` | 0 | 5 | S7 `0x0` | — |

- `entropy_style.band_style(label) → (class, glyph, meaning)`. The band-glyph set is the canonical
  **`ENTROPY_BAND_GLYPH = · ░ ▒ ▓`** (`entropy_style.py:53`); the gap glyph is `╱`. **`█` is NOT a band
  glyph** — it appears only in app prose, never in `ENTROPY_BAND_GLYPH`. `·` is the constant/padding
  band. ATs assert on membership in `{· ░ ▒ ▓}` and the `╱` gap, never on `█`.
- A2L in-image flag is **`in_memory`** (a2l.py:1316), **NOT `in_image`** — assert on `in_memory`.
- `CoverageMetrics` raw fields used by the strip: `mac_total`, `mac_in_s19`, `a2l_mac_address_matches`;
  the strip's percent uses `mac_in_s19_pct` (guarded → `0.0` when `mac_total == 0`, no divide-by-zero).
- **No `.hex` fixture exists on disk** under `examples/`. The HEX entry-="—" B-branch AT (AT-066c) and
  TC-066.3 build an `IntelHexFile` **inline in the test** (no `examples/*.hex` file added) — see MN-9 /
  Testability risk T-2.

---

## 1. Provisional requirement map (reconcile to architect ids at gate)

| Prov. id | Story | Deliverable (black-box observable) |
|---|---|---|
| R-TUI-065 | US-FND | App-wide navy/pastel palette via `styles.tcss` + non-frozen `insight_style.py` pure helpers; **sev-* class NAMES + severity semantics preserved** (amend §6.5 if hues change). |
| R-TUI-066 | US-WS | Workspace MID: entropy memstrip (≥2 band styles) + `╱` gap glyph; section micro-bars; classed hex bytes; loader-facts line `Loader N err · ⚠K OOO · Entry 0x…`. Facts survive MAC-merge / primary-reload (MJ-1). |
| R-TUI-067 | US-A2L | A2L MID: zebra + colored `Text` table (every file-derived cell a Rich `Text`) + in-`in_memory` glyph column; **detail card** on row highlight (description/unit/conversion/layout/byte-order/limits). |
| R-TUI-068 | US-MAC | MAC MID: status-glyph column ✓/⚠/✗; coverage strip `MAC→S19 X of Y` from `CoverageMetrics`. |
| R-TUI-069 | US-MAP | Memory Map BIG: pastel bands + `╱` hatch gaps + **5-tick address ruler** + `N sym` count rows + region inspector w/ 3-row hex peek. **Amends R-TUI-041** (§6.5 before/after — architect owns the amendment). |
| R-TUI-070 | US-A2L/US-MAC | C-17 markup-safety contract on all new untrusted-text sinks (A2L description/unit/conversion/display_identifier **and every file-derived table cell**, MAC names) — literal render, no markup parse, no style leak, no crash. |

> If the architect folds R-TUI-070 into 067/068 rather than a standalone row, the C-17 ATs
> (`AT-069b`, `AT-069c`, `AT-070b`) re-trace there; they remain gate-blocking regardless.

---

## 2. Validation method per requirement — Layer A white-box (`TC-NNN`)

Method ∈ {test(unit) · test(integration) · test(pilot) · inspection · analysis}. Every `test`/`analysis`
row carries **Executed verification** (provisional pytest node/command per V-5, reconciled Phase 4) +
a **numeric pass threshold**. NEW tests route to **non-frozen** homes only — NEVER the 9 frozen files
(`test_core_srecord_validation`, `test_hexfile`, `test_range_index`, `test_validation_a2l`,
`test_validation_engine`, `test_validation_mac`, **`test_tui_a2l`**, **`test_tui_mac`**,
`test_color_policy_round_trip`). The NEW test files this batch — `test_tui_theme.py`,
`test_tui_insight_style.py`, `test_tui_workspace_insight.py`, `test_tui_a2l_detail.py`,
`test_tui_mac_coverage.py`, `test_tui_map_big.py` — plus the existing non-frozen `test_tui_directionb.py`
are all **non-frozen** (verified against the frozen set above; none collides).

### US-FND — R-TUI-065 (theme + helpers)

| TC | Requirement facet | Method | Executed verification (provisional) | Numeric pass threshold |
|---|---|---|---|---|
| TC-065.1 | `human_bytes(n)` humanizes bytes (BINARY, §6.5 Amendment D) | test(unit) | `pytest tests/test_tui_insight_style.py::test_human_bytes -q` | 0 fail; `0→"0 B"`, `1023→"1023 B"`, `1024→"1.0 KiB"`, `0x10000→"64.0 KiB"`, `1<<30→"1.0 GiB"` exact |
| TC-065.2 | `microbar(frac,width,style)` renders Rich `Text` of correct filled/empty split | test(unit) | `pytest tests/test_tui_insight_style.py::test_microbar -q` | 0 fail; `frac=0.0`→0 filled cells, `1.0`→`width` filled, `0.5`→`round(width/2)` |
| TC-065.3 | `threshold_style(pct,warn,bad)` picks green/yellow/red band | test(unit) | `pytest tests/test_tui_insight_style.py::test_threshold_style -q` | 0 fail; boundary pct==warn and pct==bad classified deterministically (documented edge) |
| TC-065.4 | `label_value(...)` returns a `Text` (never a markup str) — C-17 primitive | test(unit) | `pytest tests/test_tui_insight_style.py::test_label_value_returns_text -q` | 0 fail; return isinstance `rich.text.Text` |
| TC-065.5 | `styles.tcss` still defines exactly one accent-hue var + 5 sev-* rules + no light-theme variant, after palette swap | test(unit) | `pytest tests/test_tui_theme.py -q` | 0 fail; accent-hue vars == 1; sev rules == 5; light-theme variants == 0 |
| TC-065.6 | `css_class_for_severity` round-trip unchanged (color_policy frozen) | inspection + test | `pytest tests/test_color_policy_round_trip.py -q` (FROZEN — run, do not edit) | 0 fail; 0 diff vs `main` on color_policy.py |

### US-WS — R-TUI-066 (workspace insight layer)

| TC | Requirement facet | Method | Executed verification | Numeric pass threshold |
|---|---|---|---|---|
| TC-066.1 | `load_service` populates new `LoadedFile.out_of_order_count` from `get_out_of_order_records()` | test(unit) | `pytest tests/test_tui_workspace_insight.py::test_ooo_count_populated -q` | `out_of_order_count == 4` for `prg.s19`; `== 0` for `case_01/firmware.s19` |
| TC-066.2 | `load_service` populates `LoadedFile.entry_point` from S7/S8/S9 scan (S19) | test(unit) | `pytest tests/test_tui_workspace_insight.py::test_entry_point_s19 -q` | `entry_point == 0x80000000` for `case_01/firmware.s19`; `== 0x0` for `prg.s19` |
| TC-066.3 | HEX load → `entry_point is None` (built inline via `IntelHexFile`; MN-9) | test(unit) | `pytest tests/test_tui_workspace_insight.py::test_entry_point_hex_none -q` | `entry_point is None` (renders "—") for an inline-built Intel-HEX load |
| TC-066.4 | memstrip renderer maps entropy windows → ≥2 distinct band classes + `╱` on gaps | test(pilot) | `pytest tests/test_tui_workspace_insight.py::test_memstrip_bands -q` | distinct band-class count ≥ 2 AND `╱` glyph count ≥ 1 for `prg.s19` |
| TC-066.5 | section micro-bar width ∝ range size (largest range → full bar) | test(unit) | `pytest tests/test_tui_workspace_insight.py::test_section_microbar -q` | filled-cell count monotonic in range size; largest == bar width |
| TC-066.6 | classed hex: 00/FF dim, printable-ASCII cyan, rest bright (style tokens present) | test(pilot) | `pytest tests/test_tui_workspace_insight.py::test_classed_hex -q` | ≥1 cell of each of the 3 style classes present in rendered hex Text |
| TC-066.7 | **MJ-1 writer-census:** `_merge_mac_with_existing_primary` (app.py:6997) and primary-reload merge (app.py:6954) carry `out_of_order_count`/`entry_point` forward from the source payload | test(unit) | `pytest tests/test_tui_workspace_insight.py::test_merge_preserves_loader_facts -q` | after S19(OOO=4, entry set) → merge MAC: `out_of_order_count == 4` AND `entry_point` unchanged (NOT reset to 0 / None) |

### US-A2L — R-TUI-067 / R-TUI-070

| TC | Requirement facet | Method | Executed verification | Numeric pass threshold |
|---|---|---|---|---|
| TC-067.1 | `_build_a2l_table_cells` (app.py:9090) returns `tuple[Text, ...]` — EVERY file-derived cell a Rich `Text` (not markup str) + in-`in_memory` glyph | test(unit) | `pytest tests/test_tui_a2l_detail.py::test_cells_are_text_and_glyph -q` | every returned cell isinstance `Text` (all 16); glyph == ✓ when `in_memory` True, `·` when False |
| TC-067.2 | detail-card builder returns description/unit/conversion/layout/byte-order/limits for a selected tag | test(unit) | `pytest tests/test_tui_a2l_detail.py::test_detail_card_fields -q` | all 6 field substrings present for a tag that has them; graceful blank for missing |
| TC-067.3 | **C-17 (card):** hostile A2L description/unit rendered LITERALLY via `safe_text`/`Text` | test(unit) | `pytest tests/test_tui_a2l_detail.py::test_c17_card_markup_literal -q` | full payload set (see MD-1) appears verbatim in card `Text.plain`; `Text.spans` carries NO style from payload; no `MarkupError` |
| TC-067.4 | **C-17 (table cell):** hostile A2L name/unit/function_group/memory_region/raw_value/physical_value rendered LITERALLY in the TABLE CELL | test(unit) | `pytest tests/test_tui_a2l_detail.py::test_c17_cell_markup_literal -q` | full payload set verbatim in cell `Text.plain`; no payload-derived style span; no `MarkupError` |
| TC-067.5 | `#a2l_tags_summary` in-image count colored, value == count of `in_memory` tags | test(unit) | `pytest tests/test_tui_a2l_detail.py::test_summary_count -q` | rendered count == `sum(t["in_memory"])` for fixture |

### US-MAC — R-TUI-068 / R-TUI-070

| TC | Requirement facet | Method | Executed verification | Numeric pass threshold |
|---|---|---|---|---|
| TC-068.1 | status-glyph column: ✓ (parse_ok+in_s19), ⚠ (parse_ok+out), ✗ (parse_error) | test(unit) | `pytest tests/test_tui_mac_coverage.py::test_status_glyphs -q` | `case_02` rows yield exactly {✓:1, ⚠:1}; the parse-error fixture row yields ✗ |
| TC-068.2 | coverage strip text == `CoverageMetrics.mac_in_s19` of `mac_total` | test(integration) | `pytest tests/test_tui_mac_coverage.py::test_strip_counts -q` | `case_02` → strip contains `1 of 2`; `case_01` → `1 of 1` |
| TC-068.3 | strip shows whenever a MAC is loaded, independent of S19/HEX file type | test(pilot) | `pytest tests/test_tui_mac_coverage.py::test_strip_always_shown -q` | strip node non-empty for a MAC-only load |
| TC-068.4 | **C-17:** MAC name with brackets rendered LITERALLY | test(unit) | `pytest tests/test_tui_mac_coverage.py::test_c17_name_literal -q` | full payload set verbatim in `Text.plain`; no payload-derived style span; no `MarkupError` |
| TC-068.5 | **MN-3 boundary:** `mac_total == 0` → strip renders `0 of 0`, `mac_in_s19_pct` → `0.0`, no divide-by-zero on the microbar | test(unit) | `pytest tests/test_tui_mac_coverage.py::test_zero_total_no_divzero -q` | strip contains `0 of 0`; `mac_in_s19_pct == 0.0`; no `ZeroDivisionError` |

### US-MAP — R-TUI-069 (amends R-TUI-041)

| TC | Requirement facet | Method | Executed verification | Numeric pass threshold |
|---|---|---|---|---|
| TC-069.1 | address ruler renders exactly 5 tick labels at 0/25/50/75/100 % of span | test(pilot) | `pytest tests/test_tui_map_big.py::test_ruler_five_ticks -q` | tick-label count == 5; first==span start, last==span end (hex) |
| TC-069.2 | `N sym` per region == A2L enriched-tag addresses within region span (via `range_index`, not linear) | test(unit) | `pytest tests/test_tui_map_big.py::test_sym_count -q` | count == `range_in_sorted_ranges` result for the region; call uses `address_in_sorted_ranges` |
| TC-069.3 | region inspector on highlight → span, size, band, 3-row hex peek starting at region start | test(pilot) | `pytest tests/test_tui_map_big.py::test_inspector_hexpeek -q` | inspector first hex row address == region start; rows rendered == 3 (or fewer if region shorter — documented) |
| TC-069.4 | band strip uses `╱` hatch on unmapped gaps + pastel band classes | test(pilot) | `pytest tests/test_tui_map_big.py::test_band_hatch -q` | `╱` count ≥ 1 for a multi-range fixture (`case_02`, 4 ranges); ≥2 distinct band classes |
| TC-069.5 | `range_index` primitives used (analysis — no linear scan over tags×regions) | inspection | code inspection of the sym-count call site | uses `build_sorted_range_index` + `range_in_sorted_ranges`; 0 linear `for tag: for region` scans |

### Cross-cutting

| TC | Facet | Method | Executed verification | Threshold |
|---|---|---|---|---|
| TC-FRZ.1 | 0 frozen-file diffs (src) every increment | test | `pytest tests/test_engine_unchanged.py::test_tc027 tests/test_tui_directionb.py::test_tc031 -q` | 0 fail; 0 frozen src diff vs `main` |
| TC-FRZ.2 | 0 frozen-test-file diffs every increment | test | `pytest tests/test_tui_directionb.py::test_tc032 -q` | 0 fail; 0 diff on the 9 frozen test files |
| TC-REG.1 | full suite green (no new failures / hangs) | test | `pytest -q` | pass count ≥ 1394 baseline; 0 new fail; xfail set unchanged sans documented additions |

---

## 3. AT registry — Layer B black-box (`AT-NNN`) — canonical crosswalk

Each AT drives the **shipped screen** via `App.run_test(size=(W,H))` at **both** 80×24 and 120×30
and asserts the **observed deliverable** in the rendered widget content (Rich `Text.plain` / query on
the mounted node), not the service return value. C-18: every AT → one on-disk test node. Node paths
are the orchestrator-pinned provisional paths (V-5, reconciled Phase 4). **★ = gate-blocking C-17.**

### US-FND (Inc 1) — AT-065a, AT-065b

| AT | Given / When / Then | Executed verification (node) | C-10 note | Sizes |
|---|---|---|---|---|
| AT-065a | **Given** the app on any screen, **When** it renders, **Then** the new palette `$`-vars are in effect (a themed node's computed style ≠ the pre-batch default) and the app boots without crash | `test_tui_theme.py::test_at065a_palette` | structural (theme is not operator-selectable) | 80×24, 120×30 |
| AT-065b | **Given** a fixture that produces a HIGH-severity issue, **When** the Issues/row renders, **Then** the `sev-*` class is still applied and its semantic color role is intact (Red=schema fail etc.) — proves the restyle preserved severity SEMANTICS (round-trip) | `test_tui_theme.py::test_at065b_sev_semantics` | branch: assert the CONTENT (sev class name present), not just non-empty | 80×24, 120×30 |

### US-WS (Inc 2b) — AT-066a, AT-066b, AT-066c, AT-066d, AT-067

| AT | Given / When / Then | Executed verification (node) | C-10 note | Fixture | Sizes |
|---|---|---|---|---|---|
| AT-066a | **Given** `prg.s19` loaded, **When** `#ws_stats` renders, **Then** the loader-facts line contains `⚠4 OOO` (== 4 out-of-order) | `test_tui_workspace_insight.py::test_at066a_ooo` | asserts the CONTENT (the number 4), not "some OOO text" | `prg.s19` (OOO=4) | 80×24, 120×30 |
| AT-066b | **A-branch (S19 entry present):** **Given** `case_01/firmware.s19`, **When** `#ws_stats` renders, **Then** the entry token reads `Entry 0x80000000` at the RENDER layer. Note-case: a `0x0` entry (`prg.s19`) renders `Entry 0x00000000` — PRESENT (zero), **not** `—` | `test_tui_workspace_insight.py::test_at066b_entry_present` | **C-10 branch A** (MN-2) — assert the exact rendered address string; `0x0`→`0x00000000` present, distinct from absent | `case_01/firmware.s19` (S7 0x80000000); note-case `prg.s19` | 80×24, 120×30 |
| AT-066c | **B-branch (HEX entry absent):** **Given** an inline-built `IntelHexFile` load (MN-9, no `examples/*.hex`), **When** `#ws_stats` renders, **Then** the entry token reads `Entry —` at the RENDER layer | `test_tui_workspace_insight.py::test_at066c_entry_absent_hex` | **C-10 branch B** (MN-2) — assert the rendered `—` content, not empty; the C-10 pair with AT-066b | inline `IntelHexFile` (see T-2) | 80×24, 120×30 |
| AT-066d | **MJ-1 merge-preservation:** **Given** `prg.s19` (OOO=4, S9 entry) loaded, **When** a MAC is attached (triggering `_merge_mac_with_existing_primary` / primary-reload merge), **Then** `#ws_stats` STILL renders `⚠4 OOO` AND the entry token is preserved (NOT dropped to `⚠0 OOO · Entry —`) | `test_tui_workspace_insight.py::test_at066d_merge_preserves_facts` | counterfactual = the pre-fold merge dropping the new fields to `⚠0 OOO`; assert the CONTENT survives the merge | `prg.s19` + a MAC | 80×24, 120×30 |
| AT-067 | **Given** `prg.s19` loaded, **When** Workspace renders, **Then** `#ws_memstrip` shows **≥2 distinct band styles** (from `{· ░ ▒ ▓}`) AND **≥1 `╱` gap glyph** | `test_tui_workspace_insight.py::test_at067_memstrip` | structural invariant (C-29): assert ≥2 distinct + ≥1 gap, NOT a cell count | `prg.s19` (11 ranges) | 80×24, 120×30 |

### US-A2L (Inc 3) — AT-068, AT-069, AT-069b ★, AT-069c ★

| AT | Given / When / Then | Executed verification (node) | C-10 note | Fixture | Sizes |
|---|---|---|---|---|---|
| AT-068 | **Given** an A2L where some tags are in-image and some not, **When** the table renders, **Then** the glyph column shows ✓ on an `in_memory==True` row AND `·` on an `in_memory==False` row | `test_tui_a2l_detail.py::test_at068_glyph_branches` | **C-10 branch** (in-image vs not) — assert BOTH glyphs by content | A2L with mixed `in_memory` | 80×24, 120×30 |
| AT-069 | **Given** an A2L with a tag carrying a description+unit loaded, **When** a **non-default** table row is highlighted (`DataTable.RowHighlighted` on row ≠ 0), **Then** the detail card shows THAT tag's description substring + unit | `test_tui_a2l_detail.py::test_at069_card_highlight` | **C-10(a)** operator-selectable control driven to a NON-DEFAULT value; assert the observed card CHANGED to the selected tag | `case_00_public/*.a2l` (rich fields) | 80×24, 120×30 |
| AT-069b ★ | **Given** a fixture `a2l_injection` whose tag description/unit carry the full payload set (MD-1), **When** the row is selected and the detail **CARD** renders, **Then** every payload appears **verbatim** in the card `Text.plain`, no style/link span originates from the payload, and no `MarkupError`/crash | `test_tui_a2l_detail.py::test_at069b_c17_card` | **GATE-BLOCKING** C-17 — the CARD sink (`description`/`unit`) | NEW `a2l_injection` fixture | 80×24, 120×30 |
| AT-069c ★ | **MJ-3 (distinct sink):** **Given** a fixture `a2l_injection` whose tag NAME carries the full payload set (MD-1), **When** the A2L **TABLE CELL** renders (`_build_a2l_table_cells`), **Then** the hostile NAME appears **verbatim** in the cell `Text.plain`, no style span originates from the payload, and no `MarkupError`/crash | `test_tui_a2l_detail.py::test_at069c_c17_table_name` | **GATE-BLOCKING** C-17 — the TABLE-CELL sink, DISTINCT builder/path from AT-069b (the card) | NEW `a2l_injection` fixture | 80×24, 120×30 |

### US-MAC (Inc 4) — AT-070, AT-070b ★, AT-070c, AT-071

| AT | Given / When / Then | Executed verification (node) | C-10 note | Fixture | Sizes |
|---|---|---|---|---|---|
| AT-070 | **Both branches in one fixture:** **Given** `case_02` S19+MAC loaded, **When** the records table renders, **Then** the glyph column contains **both** a ✓ (in-image) and a ⚠ (out-of-image) | `test_tui_mac_coverage.py::test_at070_glyph_branches` | **C-10 branch A+B** — the 1-in / 1-out `case_02` fixture exercises both glyph branches by content | `case_02` (mac_in_s19=1, mac_total=2) | 80×24, 120×30 |
| AT-070b ★ | **Given** a fixture `mac_injection` with a record name carrying the full payload set (MD-1), **When** the MAC table renders, **Then** the name appears **verbatim** in the cell `Text.plain`, carries no payload-derived style span, and no `MarkupError`/crash | `test_tui_mac_coverage.py::test_at070b_c17_name` | **GATE-BLOCKING** C-17 | NEW `mac_injection` fixture | 80×24, 120×30 |
| AT-070c | **MJ-2 (parse-error branch):** **Given** a MAC with a record that fails parse (NEW non-frozen parse-error fixture), **When** the records table renders, **Then** the glyph column shows `✗` on that row (parse-error) | `test_tui_mac_coverage.py::test_at070c_parse_error` | **C-10 third branch** — completes ✓/⚠/✗ three-way by content | NEW parse-error MAC fixture (see MJ-2 below) | 80×24, 120×30 |
| AT-071 | **Given** `case_02` S19+MAC loaded, **When** MAC view renders, **Then** the coverage strip contains `1 of 2` (== `mac_in_s19` of `mac_total`) | `test_tui_mac_coverage.py::test_at071_strip` | asserts the CONTENT equal to `CoverageMetrics`, not "a strip exists" | `case_02_gaps_and_patch_targets` (1/2) | 80×24, 120×30 |

**MJ-2 parse-error MAC fixture (NEW, non-frozen):** define a `.mac` fixture whose body contains one
line that fails `tui/mac.py` parse — e.g. a malformed `TAG=` record with a non-hex address such as
`BADREC=ZZZZ` (or a line missing the `=`), alongside at least one well-formed record. Route it to a
**non-frozen** home — either a fixture builder in **`tests/test_tui_mac_coverage.py`** (inline string
written to `tmp_path`) or a shared non-frozen fixtures module. It must NOT modify `tui/mac.py` (frozen
parser) — the fixture exercises the parser's existing error-collection contract (records + diagnostics)
and asserts the `✗` glyph the render layer maps from a parse-error record.

### US-MAP (Inc 5) — AT-072a, AT-072b, AT-073, AT-074

| AT | Given / When / Then | Executed verification (node) | C-10 note | Fixture | Sizes |
|---|---|---|---|---|---|
| AT-072a | **Given** a multi-region image, **When** the map renders, **Then** the band strip shows **≥2 distinct band styles** (from `{· ░ ▒ ▓}`) AND **≥1 `╱` hatch** on an unmapped gap | `test_tui_map_big.py::test_at072a_bands` | **C-29 structural** — ≥2 distinct + ≥1 hatch, NOT a cell count | `case_02` (4 ranges) | 80×24, 120×30 |
| AT-072b | **Given** the same image, **When** the map renders, **Then** the address ruler has **exactly 5 tick labels** and the first == span start (0%) / last == span end (100%) | `test_tui_map_big.py::test_at072b_ruler` | **C-29 structural** — exactly 5 ticks regardless of panel width; assert the boundary tick addresses | `case_02` | 80×24, 120×30 |
| AT-073 | **Given** an A2L + S19 loaded, **When** region rows render, **Then** each row shows an `N sym` count == tags whose address ∈ that region span (== `range_index` count) with a `↵` marker | `test_tui_map_big.py::test_at073_sym_count` | asserts the COUNT content per region (via `range_index`, not linear) | S19+A2L pair | 80×24, 120×30 |
| AT-074 | **Given** a multi-region image, **When** a **non-first** region row is activated (`RegionRow.Activated`), **Then** the inspector hex-peek's first row address == that region's start. **MN-4 sub-assertion:** a bracketed A2L symbol name surfacing in `#map_detail_body` renders **literally** (no markup parse, no crash) | `test_tui_map_big.py::test_at074_inspector` | **C-10(a)** drive a NON-DEFAULT row; assert peek moved to the selected region's start (content, not "peek non-empty") + C-17 name literal | `case_02` (4 ranges) + A2L with bracketed symbol | 80×24, 120×30 |

**AT totals:** FND 2 · WS 5 · A2L 4 · MAC 4 · MAP 4 = **19 AT ids × 2 pilot sizes = 38 AT executions.**
The **3 C-17 ATs** (`AT-069b`, `AT-069c`, `AT-070b`) are gate-blocking.

**C-17 payload set (MD-1) — applied to `a2l_injection` + `mac_injection`:**
`[red]…[/red]` · `[link=http://x]u[/link]` · `\x1b[31mX\x1b[0m` (ANSI) · `sensor[unclosed` (UNBALANCED
bracket). All four MUST render **verbatim** in `Text.plain` with **NO** `MarkupError`/crash. The
unbalanced `sensor[unclosed` is the deliberate **`Text.from_markup` counterfactual** — it passes every
balanced fixture but raises `MarkupError` under `from_markup`, so it distinguishes correct `Text(value)`
(markup-safe) from an accidental `from_markup(value)` regression.

---

## 4. C-10 AT discipline — enforcement ledger

Per the two C-10 obligations, marked per AT above and summarized here:

- **(a) Operator-selectable control driven to a NON-DEFAULT value, assert the observed value changed:**
  - `AT-069` — highlights a row ≠ 0, asserts the card content is THAT tag's description (not row-0's / not empty).
  - `AT-074` — activates a NON-first region row, asserts the hex peek address == the selected region's start.
  - (Row-selection is the only operator-selectable control introduced this batch; theme/strips/rulers are non-interactive renders → structural ATs.)
- **(b) A-or-B(-or-C) policy branch → ONE AT PER BRANCH asserting CONTENT:**
  - **Entry point present vs "—" (render layer, MN-2):** `AT-066b` (S19 → `0x80000000`; note-case `0x0`→`0x00000000` PRESENT) / `AT-066c` (HEX → `—` ABSENT). The `0x0`-present vs `None`-absent contrast is the C-10 branch pair.
  - **MAC glyph three-way:** `AT-070` (the `case_02` 1-in/1-out fixture asserts **both** ✓ and ⚠ by content) + `AT-070c` (parse-error → `✗` by content). All three branches nodalized.
  - **A2L in-image vs not:** `AT-068` asserts both ✓ and `·` present by content.
  - **Loader-facts survive merge:** `AT-066d` asserts the OOO/entry content survives the MAC-merge path (MJ-1 counterfactual).

No AT asserts merely "output non-empty" where a branch/selection exists — each names the expected glyph/bytes/string.

---

## 5. Boundary catalog per story

Classes: **empty · boundary · invalid · error**. Each gets an AT or TC, or is marked N/A with a one-line reason.

### US-FND
| Class | Coverage |
|---|---|
| empty | N/A — theme applies with no file loaded; AT-065a boots the app with no fixture (implicitly empty). |
| boundary | `microbar` frac=0.0 and frac=1.0 → TC-065.2. `threshold_style` at exact warn/bad cutoffs → TC-065.3. |
| invalid | `band_style` unknown label falls through to `high/random` (existing entropy_style contract; not re-tested — engine-owned). |
| error | N/A — pure helpers raise no I/O; label_value returns Text for any input incl. empty string. |

### US-WS
| Class | Coverage |
|---|---|
| empty | **AT-067 setup assertion:** no file loaded → `#ws_memstrip` empty, no `╱`, no crash; stats shows no OOO/entry tokens. |
| boundary | image with **no gaps** (`case_01`, 3 contiguous-ish ranges) → **no `╱` glyph** expected (negative). All-one-band image → exactly 1 band style (does not violate ≥2? — **relax: assert ≥1**; only the gappy fixture asserts ≥2 in AT-067). |
| invalid | `case_04_bad_checksums` load → loader-facts `Loader N err` with N>0 rendered; no crash. |
| error | Entry point: S19 with S9 `0x0` (`prg.s19`) renders `Entry 0x00000000` — documented as a valid-but-zero entry, distinct from HEX "—" (AT-066b note-case vs AT-066c). Also the MJ-1 merge-drop error class → **AT-066d**. |

### US-A2L
| Class | Coverage |
|---|---|
| empty | **no A2L loaded** → detail card empty/absent, table empty, no crash (AT setup assertion). |
| boundary | tag with **no description** → card shows blank/placeholder for that field, other fields still render (TC-067.2). |
| invalid | tag with unparseable address → glyph column `·` (not in_memory), no crash. |
| error | **AT-069b (card) + AT-069c (table cell)** — hostile markup is the injection "error" class; literal render, no crash, across BOTH distinct sinks. |

### US-MAC
| Class | Coverage |
|---|---|
| empty | MAC loaded with 0 records → strip `0 of 0`, `mac_in_s19_pct`→0.0, no divide-by-zero on the microbar → **TC-068.5** (MN-3). |
| boundary | `case_02` = 1 of 2 (partial). `case_01` = 1 of 1 (full). Both asserted (AT-071 / TC-068.2). |
| invalid | parse_error record → ✗ glyph → **AT-070c** + TC-068.1 (NEW parse-error fixture, MJ-2). |
| error | **AT-070b** — bracketed name literal render, no crash (full MD-1 payload set). |

### US-MAP
| Class | Coverage |
|---|---|
| empty | no S19 → map panel empty, ruler absent or degenerate, no crash (AT setup assertion). |
| boundary | **single-region image** → ruler still renders **exactly 5 ticks** (TC-069.1 with a 1-range fixture) — ticks are % of span, independent of region count. **Huge-gap image** (`case_02`) → `╱` hatch present (AT-072a / TC-069.4). |
| invalid | region with 0 symbols → `0 sym` rendered (not blank) — asserted in TC-069.2. |
| error | region shorter than 3 hex rows → inspector renders fewer rows without crash (TC-069.3 documented). Bracketed A2L symbol name in inspector → literal render (AT-074 MN-4 sub-assertion). |

---

## 6. C-29 two-axis geometry note (gate-carried into Phase 3)

**Do NOT hard-code any rendered row/col count as a pass threshold.** The following thresholds depend on
"how much fits" and MUST be pilot-measured on **BOTH** axes (width in columns AND height in rows) of the
**real boxed panel** — inside the command bar / status / footer / rail chrome — at **80×24 AND 120×30**
during Phase 3, per C-29 (batch-46 origin):

- **memstrip cell count** (`#ws_memstrip`) — width-bounded; a boxed panel gets far fewer cells than the
  prototype's full-screen strip. AT asserts **≥2 distinct band styles + ≥1 gap glyph**, never "K cells".
- **map ruler tick spacing** — the 5 tick labels must fit the panel's inner width without overlap/clip at
  80 cols; AT asserts **exactly 5 tick labels**, never a pixel/column spacing.
- **region-row visibility** — how many `RegionRow`s + the inspector + ruler fit the panel HEIGHT at 24
  rows is unknown until measured; do **not** assert "all regions visible". If the measured height cannot
  show the inspector + rows together at the 80×24 floor, **relax to reachable-under-scroll** at draft time
  (the batch-46 FOLD-8 remedy) rather than shipping a physically-impossible AT.
- **A2L detail card + shrunken hex** share `#a2l_hex_pane` vertically — measure that the card does not
  starve the hex peek below the fold at 80×24 (the batch-36/46 sibling-starvation trap).

ATs above deliberately assert **structural / relative invariants** (≥2 band styles; exactly 5 ticks; the
selected tag's description substring present; entry token == exact address) that hold at any geometry.

---

## 7. Snapshot-drift census note (C-22 per-cell + C-28 shared-chrome)

**Drift is MASSIVE and by design.** The app-wide navy/pastel theme restyles `styles.tcss`, which every
screen renders; the per-screen insight layers restyle the five feature screens. Expected-drift groups:

- **`test_tc016s_density_layout_snapshot`** — the density SVG matrix (~29 baselines across
  {80×24, 120×30, 160×40} × density modes). App-wide theme drifts **most/all** cells; per-screen changes
  drift the Workspace/A2L/MAC/Map cells specifically. **Reason per-cell (C-22)**, not a flat count; a cell
  that renders the changed region below a scroll fold may NOT drift — mark each as an UPPER BOUND under a
  `strict=False` envelope.
- **Shared-chrome cells (C-28):** the theme touches Screen/Footer/Header/rail styling rendered on EVERY
  screen — including the **parked** Issues Report and Patch Editor cells. Mark those too; the change is
  **cosmetic only** (no binding add/remove this batch, so no footer-key drift — but confirm at the
  increment snapshot step, not the Phase-4 full-suite run).
- **`test_tui_theme.py` TC-065.5 (non-frozen but invariant-guarding):** asserts *exactly one accent
  hue*, *5 sev rules present and unchanged*, *severity class names match color_policy*, *no light-theme
  variant*. The palette swap MUST keep all four true — they are **not** "drift to regen"; a failure here is
  a real requirement breach (sev semantics), handled via the §6.5 before/after amendment, not a baseline regen.

**Regen policy:** baseline SVGs are regenerated **ONLY in canonical CI** (`snapshot-regen.yml`,
textual==8.2.8) as a **post-merge follow-up PR** — NEVER a local regen (`reference_snapshot_regen_env`;
local textual drift corrupts unrelated baselines). Phase 3 marks expected-drift cells; the follow-up PR regens.

---

## 8. Testability risks for the architect to fold into 01-requirements.md (before the Phase-1 gate)

- **T-1 — `prg.s19` entry point is `0x0` (S9 with zero address).** This is a **valid-but-zero** entry,
  not "no entry". The requirement MUST specify how `entry_point == 0x0` renders (recommended: literal
  `Entry 0x00000000`) and that it is **distinct from HEX `Entry —`** (None). Otherwise AT-066a/b/c can't
  distinguish "zero entry" from "absent entry". **AT-066b uses `case_01/firmware.s19` (S7 `0x80000000`,
  non-zero)** for the unambiguous A-branch, with the `0x0` rendering as a note-case (MN-2).
- **T-2 — No `.hex` fixture exists under `examples/`.** The HEX entry-="—" B-branch (AT-066c, TC-066.3)
  builds an `IntelHexFile` **inline in the test** (MN-9) — no `examples/*.hex` file is added, so the
  ≤5-file increment budget is untouched by a fixture file. Mechanism attaches to Inc-2b.
- **T-3 — A2L in-image flag is `in_memory`, not `in_image`.** ATs/TCs assert on `in_memory` (a2l.py:1316).
  Ensure the requirement text names the correct field so the implementer wires the glyph to `in_memory`.
- **T-4 — Selection event: no `RowHighlighted` handler exists today** (recon: `on_data_table_row_selected`
  only). The A2L detail card + Map inspector need a highlight/selection hook. The requirement should state
  whether the card updates on **highlight** (cursor move) or **select** (enter/click); AT-069/AT-074
  assume highlight → confirm, else the "non-default value changed" C-10(a) assertion targets the wrong event.
- **T-5 — C-17 fixtures do not yet exist** (`a2l_injection`, `mac_injection`, parse-error MAC). They must
  be created in a **non-frozen** location. Payload set (MD-1): `[red]…[/red]`, `[link=http://x]u[/link]`,
  `\x1b[31mX\x1b[0m` (ANSI), `sensor[unclosed` (unbalanced). Gate-blocking — call out in the requirement
  so they're not skipped.
- **T-6 — "all-one-band" boundary vs "≥2 band styles" invariant.** A low-entropy image may render a single
  band style; the ≥2 assertion is scoped to the **gappy/mixed fixture** (`prg.s19` / `case_02`). The
  requirement should not state "always ≥2 bands" globally, or the AT-067 boundary contradicts it.

---

## 9. Evidence checklist

- [x] Acceptance criteria use Given/When/Then — §3 AT registry.
- [x] Test cases have explicit Expected (numeric thresholds), not vague "works" — §2.
- [x] Edge cases include empty, boundary, invalid, error — §5 per story.
- [x] Regression checklist exists — TC-FRZ.1/2, TC-REG.1 (§2) + §7 snapshot census.
- [x] Exit criteria stated — §10.
- [x] No real PII / secrets — public `examples/` fixtures only; injection payloads are synthetic.
- [x] Test-results columns left **blank** — Actual/Pass columns are for Phase 3 execution; nothing marked run.
- [x] **Layer B black-box:** every output-producing story observed through the shipped screen via
      `App.run_test()` with boundary + negative (C-17) evidence — §3.
- [x] **Bidirectional surface-reachability:** each input (fixture load, MAC-merge, row highlight) AND each
      output (memstrip/strip/card/table cell/ruler/inspector) exercised through the handler/screen, not only the service API.
- [x] **No unfilled template:** no `<...>` placeholders; AT ids + node paths are the canonical crosswalk (19 nodes).

---

## 10. Exit criteria (Phase-1 QA gate)

- All TC rows have an Executed-verification node + numeric threshold. ✓ (§2)
- Every output-producing story has ≥2 ATs at BOTH 80×24 and 120×30. ✓ (§3)
- All three C-17 hostile-input ATs present and marked gate-blocking. ✓ (`AT-069b`, `AT-069c`, `AT-070b`)
- Every A-or-B(-or-C) branch and operator-selectable control has a content-asserting AT (C-10). ✓ (§4)
- Boundary catalog complete (empty/boundary/invalid/error) or N/A-justified per story. ✓ (§5)
- C-29 two-axis measurement flagged for Phase 3; no hard-coded geometry threshold in any AT. ✓ (§6)
- Snapshot-drift groups named; regen deferred to canonical-CI follow-up PR. ✓ (§7)
- Testability risks T-1…T-6 handed to the architect for requirement reconciliation. ✓ (§8)
- AT registry matches the canonical crosswalk exactly (19 nodes, provisional paths). ✓ (§3)
- All NEW tests routed to non-frozen homes; frozen guards (TC-FRZ.1/2) run every increment. ✓
