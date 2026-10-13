# Requirements Document — s19_app — Batch 2026-10-11-batch-93

> **Artifact language**
> This template is the canonical **English scaffold**. Generate the artifact in the batch's development language (`state.json` `language`). For Spanish batches, translate the **prose** — section headers and guidance — **and never a label**, and use `deberá` as the normative keyword (≡ `shall`). The normative RULES in this preamble are **language-independent** and enforced regardless of artifact language.

> **Owed in.** `core` ✓ · `full` ✓

> **Field guide:** `templates/guides/req-template.md` and its part 2, `templates/guides/req-template.part2.md`, explain each field below and the rules that read them. It ships with the flow and is not copied into this batch.

> **Reserved field names.** The **field names and block keywords below are language-independent** — the
> validator parses them literally and they are never translated:
> `Validation` · `Acceptance test(s)` · `Boundary catalog` · `Negative control` · `Premise evaluation` · `Fork preconditions` · `Ledger` · `Requirement` · `⏸ DEFER`
> Everything else on this page — headings, guidance, the prose in every cell — is translated with the batch.
> **One strategy, not two:** the flow ships no alias table, so a translated label is read as an ABSENT one and the rule keyed on it reports a true-sounding silence.
> **And one FLOW-WIDE reserved token, read out of this artifact by `V42` no matter which template minted it:** `⏸ DEFER`. It is a MARKER rather than a field name, which is why it is stated here *and* in `/dev-flow` §Language of artifacts rather than in a per-template list — a deferral can be written in any batch artifact, including the ones that carry no block at all.

---

## 1. Introduction

### 1.1 Purpose
This document is the Phase-1 contract for batch 2026-10-11-batch-93: the Memory Map
cohesion pass chartered in `prototypes/memmap2.HANDOFF.md` (the memmap2 charter). It
re-derives — never copies — the charter into user stories, high-level requirements (HLR),
low-level requirements (LLR), black-box acceptance tests (AT) and an information-flow
contract (IFC). The batch-77 map DIRECTION (the gap-fold band bar, mapped-byte widths,
run-start ruler) is settled and is not re-litigated here; what this batch contracts is the
FORMAT treatment chosen by the operator on 2026-08-06: map **variant C — the inspector
cockpit** carrying the shared cohesion kit, plus legend **A — the spec sheet**.

### 1.2 Scope
**In scope:** the Memory Map screen's presentational re-render (`s19_app/tui/screens_directionb.py`
`MemoryMapPanel` + its builders, `s19_app/tui/app.py::_compose_screen_map` where it hosts the
panel), the map view's `LegendScreen` content (`s19_app/tui/screens.py` map path + authored
data in `s19_app/tui/legend.py`), `s19_app/tui/styles.tcss` map/legend rules, the four
memmap/legend test modules' assumption updates, the new wrap-audit harness, the AT-TC
registry rows, and the contract amendments to `HLR-113` (the stats strip) and `R-TUI-061`
(the glance block) with explicit Before/After blocks (operator rule). **Out of scope:**
map variants A/B and legend B (evaluated, not chosen — nothing registered); re-litigating
the band-bar direction; the other screens' legends beyond the byte-identical no-change
control; the command-bar deletion itself (already shipped by batch-79 `HLR-118` — this
batch only carries the interlock not to resurrect it); any source change sequenced behind
batch-92's merge (this batch's P3+ holds until then).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| band | One entropy class of the image's bytes, from `services.entropy_service.ENTROPY_BANDS`: `constant/padding`, `low`, `medium`, `high/random`. The band DOMAIN strings never change in this batch. |
| run / merged run | A contiguous same-band span produced by `_merge_band_runs` from the loader-computed entropy windows — one region-row and one band-bar segment each. |
| gap hatch | The `╱` marker for unmapped address space between runs — an app-supplied fold, not a band. |
| cohesion kit | The shared format fixes that every variant carried: chromed panes, a 1-row band bar, 1-line glance chips, a 1-line always-visible stats strip, a scrollable region list, a non-wrapping peek. |
| inspector cockpit | Variant C's layout law: left pane (band bar → ruler → glance chips → region list) beside a full-height right Inspector pane (aligned fields + multi-row peek). |
| spec sheet | Legend A's law: grouped bordered boxes (Entropy bands · Map anatomy · Region row · Map keys), zero prose paragraphs, nothing wraps. |
| PANEL columns | The measured widget columns of the surface that actually renders the text — never the terminal's columns. All width thresholds in this contract are calibrated on PANEL columns (C-29 both axes measured). |
| glance chips | The at-a-glance block folded to one line: per-band `glyph count share%` tokens. |
| short band label | A display-only truncation of a band domain string for the region-row band column (e.g. `high/random` → `high/rand`, `constant/padding` → `const`); the domain string itself is untouched. |
| wrap audit | The S-6 harness: render the screen at multiple geometries, walk the authored `Text` surfaces, assert no line exceeds its widget's real width; the harness must itself fail when an over-long line is injected. |

### 1.4 References
- `prototypes/memmap2.HANDOFF.md` — the batch charter INPUT (not a spec; re-derived here).
- `prototypes/memmap2.NOTES.md` — the prototype's measured findings.
- `prototypes/memmap2.prototype.html` + `prototypes/memmap2.tui_prototype.py` + `prototypes/memmap2_*.120w.svg` — the decision board, the runnable sub-shape-A prototype, and the captures (2 baselines + 3 map variants + 2 legend variants + 2 zoom frames of C).
- `REQUIREMENTS.md` canon: `R-TUI-060`/`061` (batch-45 band view + glance), `R-TUI-072`/`073`/`074` (batch-47 extension), `HLR-111`–`HLR-117` (batch-77 direction), `HLR-113` (batch-77 stats rendering), `R-TUI-N8`/`LLR-N8-3.2` (the legend's live band key).
- `AT-TC-REGISTRY.jsonl` — the id authority (G1–G7 guard).
- Operator ruling 2026-08-06 (map C + legend A) and the standing authorization of 2026-10-11 (quoted in `state.json`).

### 1.5 Document overview
§2 restates the product context, the source user stories, the premise evaluation (C-43) and
the fork preconditions (C-52). §3 carries the HLRs. §4 carries the LLRs and the IFC (C-54).
§5 declares the two-layer validation strategy and the batch acceptance criteria. §6/§7
point at the ledger.

---

## 2. Overall description

### 2.1 Product perspective
The Memory Map is rail screen #4 of the shipped 10-screen TUI (`#screen_map`,
`app.py::_compose_screen_map`: a titled label, a scrollable `#map_content` hosting the
`MemoryMapPanel`, and an `EmptyStatePanel`). The panel is a pure presentational widget:
`S19TuiApp.update_memory_map` hands it the loader-computed `LoadedFile` snapshot
(`ranges`, `range_validity`, `entropy_windows`, `mem_map`, enriched A2L tags) and the
canonical issue list; the panel merges, formats and mounts widgets. Batch-77 settled the
band-bar direction; the operator's 2026-08-06 complaint — "already revised twice, the
format is not cohesive" — decomposed into six measured defects (premise P-1), all
presentational. This batch changes how the same computed facts are presented; it computes
nothing new.

### 2.2 Product functions
1. Render every Memory Map surface inside a workspace-idiom bordered pane with a lit title and a subtitle carrying the affordance hints.
2. Lay the cockpit out: left pane = 1-row band bar → address ruler → 1-line glance chips → scrollable region list; right pane = full-height Inspector (aligned Status/Region/Size/Band/Symbols fields + multi-row 8-byte hex peek).
3. Render region rows with column-aligned fixed-width fields and width-aware elements, preserving the batch-67 N4a click split and the batch-77 keyboard path.
4. Fold the glance block to one line of chips and the coverage stats to one always-visible width-adaptive line.
5. Stack the layout below a measured panel-width threshold; re-apportion bar/rows/peek on every resize.
6. Rebuild the map view's `k`-legend as the spec sheet, live-sourcing the band key, leaving every other view's legend byte-identical.
7. Ship the wrap audit as a real harness whose counterfactual provably fails.

### 2.3 User characteristics
The operator: an embedded-tooling user reading entropy bands, regions and coverage on a
80×24..160×48 terminal, with either keyboard or mouse. Colour-blind-safe glyph cues are a
hard requirement (C-10).

### 2.4 Constraints
- **Presentational panel (LLR-041.7 / LLR-045A.2 preserved):** no entropy/coverage/parse re-derivation in the panel; `_merge_band_runs`, `coverage_stats`, `derive_image_span` stay the only sources.
- **B3 (preserved):** no file-derived text in bar/chips/rows/stats — counts, addresses, constant band labels only; the peek renders bytes with `markup=False`.
- **Colour discipline (preserved):** colour only via the `band-*` classes (`entropy_style` + `styles.tcss`); glyphs `· ░ ▒ ▓` remain the colour-blind cue; short band labels are DISPLAY-only.
- **Remount discipline (preserved):** re-mounted children carry CLASSES, never ids (`DuplicateIds`).
- **Internal-name shadowing (preserved):** no `_nodes`/`_context` members on new widgets.
- **`styles.tcss` precedence:** id selectors beat subclass `DEFAULT_CSS` — style via `styles.tcss` edits, not widget-CSS overrides.
- **Thresholds:** every width threshold calibrated against measured PANEL columns, never terminal columns.
- **Snapshot goldens regenerate only in canonical CI** (textual==8.2.8 pin, `pyproject.toml:73`); `tui-ci` runs `-m "not slow"` on PRs — the FULL suite runs before merge and every ledger figure states which form produced it.
- **AT/TC registry:** new ids pass the G1–G7 guard (`AT-TC-REGISTRY.jsonl`).
- **Interlock:** the screen neither composes nor references `#command_bar_row` or the bar's find/goto inputs (charter §0; verified merged, premise P-2).
- **Sequencing:** P3+ holds until batch-92 (the other lane's layer-inversions refactor) merges; this batch edits no source before that gate clears (standing authorization, `state.json`).

### 2.5 Assumptions and dependencies
- The six measured defects of premise P-1 hold on the shipped tree (verified at P1 against `origin/main` @ c9dcc25).
- The command-bar deletion is merged (P-2); the variant captures render without the bar.
- The four memmap/legend test modules pin behavior that the re-render intentionally changes (row format, glance, stats) — their assumption updates are planned work, not regressions.
- The textual pin stays 8.2.8 for this batch.

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-125 | As the operator reviewing a loaded image, I want every Memory Map surface in a chromed pane with the inspector-cockpit layout — a scrollable region list beside a full-height inspector with an aligned field block and a clean multi-row hex peek — so that the screen reads cohesively with the rest of the app and the inspector never shows wrapped byte soup. | operator ruling 2026-08-06 (map C + the cohesion kit) | READY |
| US-126 | As the operator, I want the coverage stats on one always-visible line and the at-a-glance block folded to one line of chips, so that the stats stop rendering below the fold and the freed body rows serve the region list. | operator ruling 2026-08-06 + defect ④/⑤ | READY |
| US-127 | As the operator, I want region-row columns aligned, no authored line wrapping at any tested geometry, and the layout stacking on narrow panels and re-apportioning on resize, so that the map stays readable from 80×24 to 160×48. | operator ruling 2026-08-06 + the wrap-audit carry | READY |
| US-128 | As the operator, I want the map's `k`-legend rebuilt as a grouped spec sheet with a live-sourced band key, so that the legend explains the map's anatomy without prose walls and without drifting from the band domain. | operator ruling 2026-08-06 (legend A) | READY |

**Ledger pairing:** US-125, US-126, US-127 and US-128 each name **Ledger:** LED-2026-10-11-batch-93.1 (the batch's derivation entry; V26 pairs both ways).

#### Refinement log (one block per story)

**US-125 — the inspector cockpit (map C + chrome)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the operator on the Memory Map rail · outcome = chromed panes titled "Memory Map" / "N regions" / "Inspector — 0xADDR" with the affordance-hint subtitles, cockpit layout, inspector populated with zero clicks · why = the cohesion complaint (six measured defects) · out of scope = variants A/B, legend B, the bar direction.
- **Feasibility (E, S):** implementation path = presentational re-composition inside the existing `MemoryMapPanel` + `styles.tcss`; the computed inputs are untouched · dependencies/unknowns = batch-92's merge gate for P3+ · fits one batch? = yes (P0–P2 now; P3+ after batch-92).
- **Evaluability (T) — behavioral, black-box:** "When the operator loads the demo fixture and opens the Memory Map at 120×36, the user observes every map surface inside a bordered pane with a lit title, the first region auto-selected, and the inspector showing aligned fields and clean 8-byte peek rows."
- **Open questions:** the exact stacked-regime threshold re-measurement (P3, pilot-measured).
- **Classification:** `READY` — the charter's captures are the oracle; every number re-derived at P1.

**US-126 — one-line stats + glance chips**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the operator · outcome = one stats line always visible without scrolling at 120×36; glance folded to one chips line whose shares sum to 100% ± rounding · why = defect ④ (stats below the fold) + defect ⑤ (6-row static key) · out of scope = changing any statistic's arithmetic (`coverage_stats` untouched).
- **Feasibility (E, S):** path = `build_stats_text` re-render + glance builder replacement · unknowns = the compact-form breakpoint, pilot-measured at P3 · fits one batch? = yes.
- **Evaluability (T):** "When the operator loads the demo fixture, the user observes the stats line — `Mapped X / Y span (%) · N ranges (V valid) · G gaps · I issues` — in the visible viewport at 120×36 with zero scrolling."
- **Open questions:** none blocking; compact-form wording is P3's to finalize within the contract's field list.
- **Classification:** `READY`.

**US-127 — alignment, no-wrap, responsive regimes**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the operator at any terminal size · outcome = aligned rows, zero wrapped authored lines at 80/~100/120/140/160, stacked regime below the measured threshold, re-apportionment after live resize · why = the operator's wrap/alignment requirements · out of scope = terminal-column thresholds.
- **Feasibility (E, S):** path = fixed-width row fields + the ported wrap-audit harness + the existing `BandBar.Measured` re-apportion discipline extended to rows/peek · unknowns = the two thresholds re-measured at P3 · fits one batch? = yes.
- **Evaluability (T):** "When the operator resizes the terminal across the regime boundary, the user observes the layout stack/unstack and every surface re-apportioned — no line ever continues unintentionally onto the next row."
- **Open questions:** threshold re-measurement method (pilot, both axes, C-29).
- **Classification:** `READY`.

**US-128 — the legend spec sheet**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = the operator pressing `k` on the map · outcome = the grouped spec sheet; band key live from `build_band_key_rows`; Esc closes; the other views' legends unchanged · why = legend A won on drift risk · out of scope = the other views' content.
- **Feasibility (E, S):** path = a map-path content branch in `LegendScreen` + authored sample data in `legend.py`; the `LegendScreen(sections, view_key)` API survives · unknowns = none · fits one batch? = yes.
- **Evaluability (T):** "When the operator presses `k` on the map view, the user observes four grouped bordered boxes and zero wrapping prose; pressing Esc closes the modal; pressing `k` on any other view shows byte-identical content to today."
- **Open questions:** none blocking.
- **Classification:** `READY`.

### 2.7 Premise evaluation (C-43) — MANDATORY, one row per premise

| # | Premise, as a truth-apt proposition | Tier | Verdict | Executed evidence (command output / `file:line` — **NOT** a citation of another document) | Disposition |
|---|---|---|---|---|---|
| P-1 | The shipped Memory Map renders the six cohesion defects: no pane chrome; the inspector peek is wrapped byte soup (3×79 = 237 cells of peek text in a ~52-col detail pane); the region list shows 5 of 9 runs with no scrollbar/affordance; the stats strip renders below the fold of `#map_content` (invisible at 120×36); the at-a-glance block spends 6 of the ~17 viewport rows; region-row columns misalign row-by-row | measured at P1 | TRUE | SVG grid reconstruction of `prototypes/memmap2_baseline_map.120w.svg` (the shipped-state capture): content rows 8–24 = 17; glance rows 12–17 = 6 (title + 4 band rows + sparkline); region rows 20–24 = 5 of 9 with no scrollbar glyph; no `Coverage:` text anywhere in the visible grid; peek wraps at cols 66–117 with ASCII-gutter/next-address collisions (rows 19–24); rows 20–21 show `256 B` vs `2.0 KiB` shifting every later column by 2. The 79-cell row was re-derived by executing the shipped `hexview.render_hex_view` (`0x00001000  00 07 … 69  |…|` = 79 cells); `_MAP_PEEK_ROWS = 3` (`screens_directionb.py:280`) → 237 | the six defects are the WHY of US-125/126/127 |
| P-2 | The command bar's `#command_bar_row` is already deleted from the shipped tree (batch-79 `HLR-118` merged); only comments mention it, and the live `CommandBar` mounts as the palette host `#command_bar_slot` | measured at P1 | TRUE | `grep -rn "command_bar_row" s19_app/` → hits only in comments/docstrings: `command_bar.py:10`, `command_bar.py:130`, `styles.tcss:61,74-75`, `app.py:6274`; the live compose mounts `CommandBar(self._build_palette_entries()), id="command_bar_slot"` (`app.py:1894-1895`). The variant captures render with no bar rows (grid reconstruction of `memmap2_map_C.120w.svg`: rows 2–5 run title→rail→pane with no command-bar box; the baseline capture keeps it at rows 3–4) | HLR-133's interlock is a do-not-resurrect law, not a dependency to wait on |
| P-3 | The panel is presentational: it re-derives no entropy/coverage/parse facts; `_merge_band_runs`, `coverage_stats`, `derive_image_span` are the only sources | found at P1 | TRUE | `screens_directionb.py:2174-2175` (the panel's own contract docstring) and the render path: `render_ranges` consumes `_merge_band_runs(entropy_windows)` at `:2440` and `_render_stats` consumes `coverage_stats(ranges, range_validity, issues)` at `:2936` — no other computation site exists in the panel | every LLR below keeps this law (§2.4) |
| P-4 | A width-0 first render is real on the shipped path: `_build_band_widgets` apportions against `grid.region.width`, which "can report width 0 before layout" (the code's own words), and only the BAR has a correction path today (`BandBar.Measured` + `on_resize` → `_resize_band_segments`); the region rows and the peek are built once with no re-apportion | found at P1 | TRUE | `screens_directionb.py:2442-2459` (build against `#map_grid`, then `call_after_refresh(self._resize_band_segments)`), `:2518-2532` (`on_resize`/`on_band_bar_measured`), `:2674-2677` (`bar_width` 0 documented as a conforming out-of-domain input); rows/peek are composed inside `_build_band_widgets`/`_region_hex_peek` with no measured-width hook | LLR-131.2/.3 extend the bar's correction discipline to rows/peek |
| P-5 | The registry's next free numeric blocks are the AT block above 286 and TC-649.. (max numeric AT = 286; TC-649..660 FREE; the `TC-1728` row is a BURNED seed sentinel) | measured at P1 | TRUE | executed parse of `AT-TC-REGISTRY.jsonl` (numeric-id scan): max numeric AT = 286 (AT-284/285/286 LIVE); no numeric TC ≥ 649 present except the BURNED `TC-1728` seed | the batch's reservation (the AT block above 286 + TC-649..684) was written at P0 |
| P-6 | The variant-C and legend-A captures render the decided layout WITHOUT the command bar, and the demo fixture they carry populates 9 merged runs over 5 ranges (5376 B mapped, span ≈ 511.9 MiB, 4 gaps, 0 issues; chips 19/5/57/19 %) | measured at P1 | TRUE | grid reconstructions: `memmap2_map_C.120w.svg` header `Entropy bands - 9 region(s), 5376 B mapped`, stats `Mapped 5.2 KiB / 511.9 MiB span (0.0010% · 5 ranges (5 valid) · 4 gaps · 0 issues`, chips `· 1 19% ░ 1 5% ▒ 4 57% ▓ 3 19%`; `memmap2_legend_A.120w.svg` renders the four grouped boxes. The fixture population is re-derived from the prototype's `_fixture()` (`memmap2.tui_prototype.py:75-101`): 5 `put` blocks + `compute_entropy` | the ATs drive the same deterministic fixture shape |
| P-7 | textual is pinned ==8.2.8 for the snapshot baselines; snapshot goldens regenerate only in canonical CI | found at P1 | TRUE | `pyproject.toml:73` (`textual==8.2.8` in the dev pin block, with the CI-drift comment at :69) | §2.4 constraint; HLR-130's harness runs under the same pin |

- **Premise evaluation:** 7 premise(s) · ✅ TRUE ×7

### 2.8 Fork preconditions (C-52) — MANDATORY, and the declared empty when the batch does not fork

- **Fork preconditions:** none — this batch runs ONE lane on the main checkout. (Cross-batch, not intra-batch: batch-92 — the other agent's layer-inversions refactor — owns the source lane; batch-93's P3+ holds until it merges per the standing authorization in `state.json`. The coordination note `COORDINATION-batch93-memmap.md` is owed in the batch-92 lane's directory; it does not exist yet at P1 — logged as a watch-item in PLAN.md and in the P2 review, and the P3 hold does not lift without it.)

---

## 3. High-level requirements (HLR)

### HLR-125 — The chrome kit: every map surface sits in a lit, titled pane
- **Traceability:** US-125
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** When the Memory Map screen renders with a file loaded, the system shall present every map surface inside a workspace-idiom bordered pane with a lit border title and subtitle: the map surface titled `Memory Map` (subtitle `{N} regions · ░▒▓ k`, N = the merged-run count), the region list and band surfaces grouped under it, and the inspector surface titled `Inspector — 0x{selected:08X}` (subtitle `↑↓ · ↵ hex`), matching the `.db-pane` look (`styles.tcss:334-346` — `border: tall`, lit title, navy surface) rather than any hand-typed style list.
- **Rationale (informative):** defect ① of P-1 — no pane chrome while every other screen uses the bordered title/subtitle idiom; the variant-C capture (`memmap2_map_C.120w.svg` row 6) shows the decided look.
- **Validation:** `test` + `inspection`
- **Executed verification:** P1: the baseline-vs-variant grid reconstructions (P-1/P-6) — the chrome delta is measured from the captures. Owed at P4: the TC minted from TC-649..684 driving the shipped screen at 120×36 and asserting each pane's border + title + subtitle from the rendered DOM (`python -m pytest tests/test_tui_map_big.py -q`).
- **Numeric pass threshold:** at 120×36 with the demo fixture: 3 addressed surfaces (map, regions, inspector), 3 lit titles, 2 subtitles carrying the exact affordance strings; 0 map surface rendered outside a bordered pane.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** every map surface the operator sees sits inside a bordered pane whose title is lit, matching the workspace panes; the affordance hints live in the subtitles, not in the body.
  - **Shipped surface:** the `#screen_map` rail screen (`MemoryMapPanel` + `styles.tcss`).
  - **Acceptance test(s):** AT-292 (the chrome-kit half of the Layer-B acceptance)
  - **Boundary catalog (QC-3):** ☑ empty — the no-file state (no surfaces mounted beyond the neutral note, preserved by LLR-041.9) renders no chrome to assert on.
  - **Negative control:** the shipped render (P-1) — zero lit pane titles at 120×36; the same assertion against today's tree goes RED.

### HLR-126 — The inspector cockpit layout
- **Traceability:** US-125
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** When the Memory Map renders a loaded image, the system shall lay the cockpit out as: a left pane carrying the 1-row band bar, the address ruler, the 1-line glance chips and the scrollable region list (with a visible scrollbar when the rows overflow), beside a full-height right Inspector pane whose aligned field block (Status / Region / Size / Band / Symbols) and multi-row hex peek are always populated; the first region shall be auto-selected after render so the inspector is never empty with a file loaded, and every region shall be reachable keyboard-only and mouse-only.
- **Rationale (informative):** defects ② (wrapped peek) and ③ (5-of-9 rows, no scrollbar) of P-1; S-2 of the charter. The batch-77 auto-selection law (HLR-116) is carried, not re-decided.
- **Validation:** `test`
- **Executed verification:** P1: the cockpit order and the auto-selected inspector are measured in the variant-C capture (rows 7-18: bar, ruler, chips, list; inspector fields populated for `0x00000000` with zero clicks). Owed at P4: `python -m pytest tests/test_tui_map_big.py tests/test_map_click_chain.py -q` (TCs from the reserved block).
- **Numeric pass threshold:** at 120×36 with the demo fixture (9 runs): all 9 rows reachable by arrows/`j`/`k` and by click; the region list scrolls (its scrollbar is visible while 9 rows overflow the ~5-row viewport); the first region is selected and the inspector shows its fields + ≥1 peek row before any input.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator lands on a fully populated inspector with zero clicks; scrolling the list reaches every region; the scrollbar is visible whenever the list overflows.
  - **Shipped surface:** `#screen_map` — the region list and the inspector pane.
  - **Acceptance test(s):** AT-289
  - **Boundary catalog (QC-3):** ☑ empty — the no-file state mounts no list (neutral note preserved); ☑ boundary — a single-region image (inspector = that region, list nowhere to scroll).
  - **Negative control:** the shipped render (P-1) — 5 of 9 rows reachable without scrolling, no scrollbar; the same reachability assertion on today's tree goes RED.

### HLR-127 — Column-aligned region rows with preserved row semantics
- **Traceability:** US-127
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** When region rows render, the system shall compose each row from fixed-width fields — band glyph · `0xADDR` (10 cells) · size (>7 cells, right-aligned) · size microbar (4 cells) · symbol count (>2 cells) · band short label (≤9 cells, display-only) · `↵` — so that every field of every rendered row starts at the same column; the row shall be width-aware (the microbar drops below ~43 available columns); and the `RegionRow` semantics shall be preserved verbatim: focusable rows, `↑↓`/`j`/`k` movement, single-click inspect, double-click open-in-hex (batch-67 N4a), auto-selection by address across re-renders. **Amends `R-TUI-073`'s row format (single-space separators → fixed-width fields); the amendment's Before/After ships in the ledger entry per the operator rule.**
- **Rationale (informative):** the operator's mid-review ruling — region-row columns misalign row-by-row (P-1: the shipped `256 B` vs `2.0 KiB` shifts every later column by 2); `constant/padding` (16 chars) and `high/random` (11) cannot sit in a ≤9-cell band column without short labels.
- **Validation:** `test`
- **Executed verification:** P1: the fixed offsets are measured from the variant-C capture (glyph col 28 · `0xADDR` cols 31-40 · size right-aligned cols 41-47 · sym col 50 · band col 52 ≤9 · `↵` col 61, for all 5 visible rows); the shipped row measures 50 cells with the widest band label (executed: `▒ 0x08000000 2.0 KiB ████ 3 sym constant/padding ↵`). Owed at P4: `python -m pytest tests/test_tui_map_big.py tests/test_map_click_chain.py -q`.
- **Numeric pass threshold:** parsed-offset assertion over every rendered row at every tested geometry: 0 field-offset mismatches; sizes right-aligned (0 left-aligned exceptions); every band-domain value's short label ≤9 cells (including `constant/padding`); the N4a split and the keyboard path unchanged (the batch-67 AC-3/4/5 modules stay green, adapted only for the row format).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator reads a column-straight table; every band label fits its column; clicks and keys behave exactly as they did.
  - **Shipped surface:** the region list (`RegionRow`s on `#screen_map`).
  - **Acceptance test(s):** AT-290
  - **Boundary catalog (QC-3):** ☑ boundary — the narrowest side-by-side pane (~41 available cols at 120×36, measured in the capture) drops the microbar while keeping every other field aligned; the widest labels of the band domain render without wrap.
  - **Negative control:** the shipped single-space rows (P-1) — the parsed-offset assertion counts 2-cell shifts across rows; the alignment assertion on today's tree goes RED.

### HLR-128 — The non-wrapping 8-byte peek
- **Traceability:** US-125
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** When the inspector renders a region's hex peek, the system shall render 8-byte rows of the form `ADDR  hh×8` — 8-hex address, no ASCII gutter, no `0x` prefix — sized to the inspector pane so that no row can wrap (33 cells, the widest row that cannot wrap in a ~40-col inspector pane), with unmapped bytes rendered `··`; this surface replaces the wrapped `build_detail_text`/`_region_hex_peek` 16-byte render on this screen.
- **Rationale (informative):** defect ② of P-1 — the shipped peek is 237 cells of text in a ~52-col pane (3×79); the 8-byte row is the widest non-wrapping form (the 16-byte row is 79 cells — measured, not guessed).
- **Validation:** `test`
- **Executed verification:** P1: 79 cells re-derived by executing the shipped `render_hex_view` (HEX_WIDTH=16); the 8-byte row measured at 33 cells; the variant-C capture rows 13-18 show `00000000  08 00 12 00 08 00 16 00` at 6 consecutive 8-aligned addresses. Owed at P4: `python -m pytest tests/test_tui_map_big.py -q`.
- **Numeric pass threshold:** 0 peek rows exceeding the inspector pane's measured width at any tested geometry; every peek row ≤ the pane width; unmapped holes render `··` (asserted with a gapped fixture).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator reads whole hex rows, never a continuation line, never an ASCII gutter.
  - **Shipped surface:** the inspector pane's peek block on `#screen_map`.
  - **Acceptance test(s):** AT-289 (peek cleanliness observed through the inspector outcome) + AT-291 (the wrap audit over the peek surface).
  - **Boundary catalog (QC-3):** ☑ boundary — unmapped bytes inside a peek row (`··`); a region shorter than one 8-byte row; an empty `mem_map` (no file) yields an empty peek, never a raise (shipped law preserved).
  - **Negative control:** the shipped 16-byte peek (79 cells/row) overflows the 41-col inspector pane of the variant-C capture — the wrap audit goes RED on today's `_region_hex_peek` output.

### HLR-129 — One-line stats and glance chips (amends HLR-113 + R-TUI-061)
- **Traceability:** US-126
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** When the Memory Map renders a loaded image, the system shall render the coverage stats as ONE always-visible line — `Mapped X / Y span (%) · N ranges (V valid) · G gaps · I issues` — placed so it renders in the visible viewport at 120×36 WITHOUT any scrolling, width-adaptive (a compact form below the measured ~84-panel-column threshold, derived from the row budget at P3); and shall fold the at-a-glance block to ONE line of per-band chips (`glyph count share%`) whose shares sum to 100% ± rounding. **No statistic's arithmetic changes — `coverage_stats` is untouched; this amends the RENDER of `HLR-113`'s strip and replaces `R-TUI-061`'s docked block. The Before/After amendment ships in the ledger entry per the operator rule.**
- **Rationale (informative):** defects ④ (stats below the fold at 120×36 — invisible in the baseline capture) and ⑤ (the glance block spends 6 of ~17 viewport rows on a static key) of P-1.
- **Validation:** `test`
- **Executed verification:** P1: the baseline capture contains no `Coverage:` text in its 17 visible content rows (defect ④ measured); the variant-C capture shows the one-line form at row 23, inside the viewport, content 84 cells. The shipped `build_stats_text` body (5 appended segments, `:2982-2993`) is the amendment's Before. Owed at P4: `python -m pytest tests/test_tui_map_big.py tests/test_memmap_entropy_merge.py -q`.
- **Numeric pass threshold:** at 120×36 with the demo fixture, the stats line's full form renders with zero scrolling (asserted against the shipped surface's visible region); the chips' shares sum to 100 ± 0.5 (rounding) across the fixture's bands; the no-file path keeps the strip positively blank (LLR-041.9 / TC-B77-10 preserved).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator sees the coverage line and the chips line on first paint, no scrolling; the numbers are the same seven statistics as today.
  - **Shipped surface:** the stats strip + glance line on `#screen_map`.
  - **Acceptance test(s):** AT-288 (stats visibility; counterfactual = the shipped below-fold render) · TC-663 (the glance chips' one-line form + share sum, discriminating).
  - **Boundary catalog (QC-3):** ☑ boundary — the compact form below the measured threshold (both forms asserted); ☑ empty — the no-file/no-entropy paths keep their distinct neutral notes (AC-3 of `test_memmap_entropy_merge.py` preserved).
  - **Negative control:** the shipped render (P-1) — the stats strip is not in the visible viewport at 120×36; the visibility assertion on today's tree goes RED.

### HLR-130 — The wrap audit ships as a real harness
- **Traceability:** US-127
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** When this batch's validation runs, the system shall include the ported wrap audit as a real test harness: render the map screen at the geometries 80 (below the audited 100-column floor), ~100, 120, 140 and 160 columns, walk the authored `Text` surfaces, and assert no line exceeds its widget's real width; and the harness shall FAIL when a deliberately over-long line is injected (an audit that cannot fail proves nothing).
- **Rationale (informative):** S-6 of the charter — the operator's "no unintentional line continuation at any zoom" requirement; the prototype's audit caught five real defects on its own way to CLEAN.
- **Validation:** `test`
- **Executed verification:** P1: the prototype's audit run is recorded in `memmap2.NOTES.md` (405 renders, zero overflows — cited as charter evidence, re-executed by P3 under the batch's own harness). Owed at P4: `python -m pytest <the new wrap-audit module> -q` (TC from the reserved block).
- **Numeric pass threshold:** 0 overflow lines across every tested geometry; the counterfactual injection produces ≥1 failure (the harness goes RED exactly when an over-long line exists).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator never sees an authored line continue onto the next row at any tested geometry.
  - **Shipped surface:** every authored text surface of `#screen_map`.
  - **Acceptance test(s):** AT-291
  - **Boundary catalog (QC-3):** ☑ boundary — 80 cols (below the audited floor) is in the matrix; ☑ error — the injected over-long line is the harness's error class.
  - **Negative control:** the injected over-long line MUST fail the audit (executed at P4; the prototype run demonstrated the same counterfactual). Without it the AT is vacuous (C-43).

### HLR-131 — Responsive regimes and resize re-apportionment
- **Traceability:** US-127
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** When the panel's measured width crosses the threshold derived from the measured row budget (~84 PANEL columns; re-measured at P3 and recorded), the system shall stack the inspector under the map pane below it and render side-by-side above it, mirroring the existing `width-narrow` two-regime reflow (LLR-041.10); on every live resize — including the first frame, where a width of 0 is a conforming input — the system shall re-apportion the band bar, the region rows and the peek against the measured width, and no surface shall retain a width-0-derived layout.
- **Rationale (informative):** S-7 of the charter + P-4 (the shipped path already knows the width-0 hazard for the bar and solves only the bar); the app hands panels far narrower than the terminal (rail/narrow behavior), so the threshold is a PANEL quantity.
- **Validation:** `test`
- **Executed verification:** P1: P-4's code reading (the bar's correction path at `screens_directionb.py:2518-2532` vs the rows/peek built once); the 100×30 and 160×48 captures show the two regimes' rendering. Owed at P4: `python -m pytest tests/test_tui_map_big.py -q` (a resize-driving TC).
- **Numeric pass threshold:** the regime assertion reads the PANEL's measured width (pilot, C-29), never the terminal's: stacked below / side-by-side above at the recorded threshold, 0 mismatches; after a piloted resize across the boundary, every re-apportioned surface's width equals its measured container width (0 stale-width surfaces).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** narrowing the terminal stacks the panes; widening restores side-by-side; nothing keeps a stale layout after a resize.
  - **Shipped surface:** the map body's layout + the bar/rows/peek on `#screen_map`.
  - **Acceptance test(s):** AT-292
  - **Boundary catalog (QC-3):** ☑ boundary — the threshold itself (a resize crossing it), the 80×24 floor, and the width-0 first frame.
  - **Negative control:** a render whose re-apportionment is skipped — the stale-width assertion goes RED (the shipped code's bar-only correction is the closest live counterfactual: rows/peek today never re-apportion).

### HLR-132 — Legend A: the spec sheet on the map view
- **Traceability:** US-128
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** When the operator opens the legend on the map view (`k`), the system shall render the spec sheet: grouped bordered boxes — **Entropy bands** (the live-sourced `build_band_key_rows()` rows plus the gap-hatch row) · **Map anatomy** (one-line rendered sample → one-line meaning, one line each) · **Region row** (a rendered sample row + its field key) · **Map keys** (batch-94: the title names what the pinned line documents — the MAP's keys, not the modal's) — with zero prose paragraphs and no wrapping line; Esc shall close the modal; the `LegendScreen(sections, view_key)` API shall survive unchanged; and the OTHER views' legends shall render byte-identical to pre-change content (the N8 scoping control).
- **Rationale (informative):** S-8 of the charter — legend A won on drift risk (live band key vs a hand-drawn mini-map); the baseline-legend capture shows today's wrapping prose the operator rejected.
- **Validation:** `test`
- **Executed verification:** P1: the legend-A capture reconstruction (rows 5-29: four boxes, the band rows `[0,1) [1,5) [5,7.2) [7.2,8]`, the gap row, four anatomy samples, the region-row sample + field key, the Keys line; zero wrap artifacts); the shipped map legend path (`screens.py:1169-1186`) is the Before. Owed at P4: `python -m pytest tests/test_legend_n8.py tests/test_tui_legend.py -q`.
- **Numeric pass threshold:** 4 boxes render in order; band rows == `len(ENTROPY_BANDS)` (4) + 1 gap-hatch row; every line's cell width ≤ its container's measured width at 80×24 and 120×36 (0 wrapped lines); Esc dismisses; the other four views' legend content hashes byte-identical to the pre-change capture (0 diffs).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator gets a scannable spec sheet that always matches the band domain; the other views' legends look exactly as before.
  - **Shipped surface:** the `k`-legend modal (`LegendScreen`, map `view_key`).
  - **Acceptance test(s):** AT-293
  - **Boundary catalog (QC-3):** ☑ boundary — a band label mutated upstream appears in the sheet with zero legend-code change (the live-source test); the 80×24 floor geometry; Esc-close. ☑ empty — a view with no card (view_key `None`) keeps the pre-N8 behavior untouched.
  - **Negative control:** hand-copying a band label into legend-authored data — the live-source test (mutate `ENTROPY_BANDS` upstream in-fixture) goes RED on the copied label; and the byte-identical control over any other view goes RED if the map path leaks into the shared rows.

### HLR-133 — The command-bar interlock
- **Traceability:** US-125
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** When this batch's changes ship, the Memory Map screen shall neither compose nor reference `#command_bar_row` nor the bar's find/goto inputs — not as chrome, not as a "restore" of what the baseline captures show; every variant capture in the charter's board renders without that bar.
- **Rationale (informative):** charter §0 — the command bar is being deleted by another batch; the interlock is already satisfied on the shipped tree (P-2) and must stay satisfied.
- **Validation:** `test` + `inspection`
- **Executed verification:** P1: the grep of P-2 (only comments mention `#command_bar_row`; the live `CommandBar` mounts as `#command_bar_slot`, `app.py:1894-1895`). Owed at P4: a registry-listed grep-style TC over the batch's touched files.
- **Numeric pass threshold:** 0 occurrences of `command_bar_row` / the find/goto input ids introduced by this batch's diff; the live map screen queryable with no command-bar widget.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the operator sees the map exactly as the variant captures render — no bar above it.
  - **Shipped surface:** `#screen_map` + the batch's diff.
  - **Acceptance test(s):** AT-295
  - **Boundary catalog (QC-3):** none — an interlock has no input classes; the grep is the whole check.
  - **Negative control:** any introduced reference to `command_bar_row` makes the grep TC go RED.

---

## 4. Low-level requirements (LLR)

> Each LLR decomposes an HLR into a verifiable property at the implementation level.
> Same regime: EARS syntax owed in `full`, recommended in `core`. ID format: `LLR-<HLR>.<M>`.

### LLR-125.1 — Pane chrome per surface
- **Traceability:** HLR-125
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The map surfaces shall be composed as bordered panes with lit border titles (`Memory Map`; `Inspector — 0x{selected:08X}`), styled through `styles.tcss` under the existing `.db-pane` idiom (border, title color/background, navy surface), never through subclass `DEFAULT_CSS` overrides on shared ids.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — TC from TC-649..684 driving `S19TuiApp.run_test(size=(120,36))` with the demo fixture, querying the pane borders/titles in the DOM.
- **Numeric pass threshold:** 3/3 surfaces bordered + titled at 120×36; 0 hand-typed style overrides on the new pane ids.
- **Negative control:** an untitled/unbordered surface — the DOM assertion goes RED.
- **Boundary catalog:** none — chrome is state-independent (the no-file state renders the neutral note, no panes).

### LLR-125.2 — Subtitle affordance hints
- **Traceability:** HLR-125
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The panes' border subtitles shall carry the affordance hints — the map pane `{N} regions · ░▒▓ k` (N = the merged-run count; `9 regions · ░▒▓ k` on the demo fixture) and the inspector pane `↑↓ · ↵ hex` — so the hints live in chrome, not body rows.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — same TC module, asserting the subtitle strings against the rendered DOM.
- **Numeric pass threshold:** both subtitle strings exact (the `N` limb re-derived per fixture: 9 for the demo fixture); 0 hint rows inside the panes' bodies.
- **Negative control:** a missing/incorrect subtitle — the string assertion goes RED.
- **Boundary catalog:** none.

### LLR-126.1 — Left-pane stack order
- **Traceability:** HLR-126
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The left pane shall stack, in order: the 1-row proportional band bar (the batch-77 allocator, untouched), the run-start address ruler (`MapRuler`, untouched), the 1-line glance chips, and the scrollable region list.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — TC asserting the DOM sibling order at two geometries.
- **Numeric pass threshold:** 4/4 surfaces in the exact order at 120×36 and 80×24; band bar height exactly 1 row.
- **Negative control:** a reordered or double-height bar — the order/height assertion goes RED.
- **Boundary catalog:** none.

### LLR-126.2 — Aligned inspector fields
- **Traceability:** HLR-126
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The Inspector pane shall render the aligned field block `Status` / `Region` / `Size` / `Band` / `Symbols` at fixed columns (values aligned, the capture's two-space field gutter preserved), followed by the `Peek` block; the values come from the already-selected region only — the panel re-derives nothing (P-3).
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — TC asserting the parsed field offsets for the demo fixture's first region.
- **Numeric pass threshold:** 5/5 fields at identical offsets across selections and re-renders; 0 offset mismatches.
- **Negative control:** a value-dependent field offset — the parsed-offset assertion goes RED.
- **Boundary catalog:** ☑ boundary — an invalid region and a gap-less single region both render their Status/Region values without shifting the offsets.

### LLR-126.3 — Multi-row peek sized to the pane
- **Traceability:** HLR-126 · HLR-128
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The Inspector peek shall render as many 8-byte rows as the pane height admits (multi-row, filling the inspector below the field block), re-cut against the pane on resize together with the bar/rows (LLR-131.2).
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — TC asserting the rendered peek row count grows with the inspector height at 120×36 vs 160×48.
- **Numeric pass threshold:** ≥1 peek row whenever a region is selected; the row count at 160×48 > at 120×36 > at 100×30 (monotone in the measured pane height).
- **Negative control:** a fixed-row peek that ignores the pane height — the monotonicity assertion goes RED.
- **Boundary catalog:** ☑ boundary — a region shorter than 8 bytes renders one partial row; an empty `mem_map` renders no peek rows and never raises.

### LLR-126.4 — Auto-selection with a file loaded
- **Traceability:** HLR-126
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** After every render with a file loaded, the first region shall be auto-selected (the batch-77 HLR-116 resolution law preserved verbatim — by start address across re-renders), the inspector populated, and focus given to the selected row; with no file the neutral hint stays and nothing is fabricated (HLR-116.2 preserved).
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — the existing `test_b77_select_*` family stays green (adapted only for the new DOM); TC-B77-21/22 semantics unchanged.
- **Numeric pass threshold:** 0 clicks before the inspector is populated at every tested geometry; the no-file hint path produces 0 mounted rows.
- **Negative control:** the shipped modules' `test_b77_select_no_file_keeps_the_hint_and_fabricates_nothing` — goes RED if auto-selection fabricates a selection with no file.
- **Boundary catalog:** ☑ empty — the no-file path (preserved law).

### LLR-127.1 — Fixed-width row fields
- **Traceability:** HLR-127
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** Each region row shall be composed from fixed-width fields — glyph (1) · space · `0x{start:08X}` (10) · size field (>7, right-aligned humanized) · symbol count field (>2) · band short-label field (≤9) · space · `↵` — with single-space inter-field separators only inside a field never across fields, so parsed offsets are constant for every row and value.
- **Validation:** `test (unit)`
- **Executed verification:** P1 executed: the field offsets measured from the variant-C capture (glyph 28 · addr 31-40 · size 41-47 · sym 50 · band 52-60 · `↵` 61). Owed at P4 — a unit TC parsing every rendered row's offsets across fixtures whose sizes force different humanized widths (`256 B` vs `2.0 KiB` vs `64.0 KiB`).
- **Numeric pass threshold:** 0 offset mismatches across every row of every fixture at every geometry.
- **Negative control:** the shipped single-space row format (P-1) — 2-cell shifts; the offset assertion goes RED on today's format.
- **Boundary catalog:** ☑ boundary — the widest humanized sizes and the widest band labels of the domain (`constant/padding` → `const` ≤9) render without wrap or offset change.

### LLR-127.2 — Short band labels are display-only
- **Traceability:** HLR-127
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The band column shall display short labels for domain labels wider than 9 cells (`constant/padding` → `const`, `high/random` → `high/rand`), derived from the band domain via one explicit display mapping; the band domain strings, `entropy_style.ENTROPY_BAND_LABELS`, and every other surface's labels shall remain byte-identical.
- **Validation:** `test (unit)`
- **Executed verification:** P1 executed: the domain label lengths measured (`constant/padding` 16 · `low` 3 · `medium` 6 · `high/random` 11 — two exceed 9). Owed at P4 — a unit TC over the mapping for every `ENTROPY_BANDS` label.
- **Numeric pass threshold:** every domain label's display form ≤9 cells; the domain strings themselves unchanged (a census diff over `ENTROPY_BAND_LABELS` shows 0 changes).
- **Negative control:** a row rendering the raw `constant/padding` in the 9-cell column — the width assertion goes RED (as it would on the shipped row: 50 cells).
- **Boundary catalog:** ☑ boundary — exactly-9-cell labels (`high/rand`) render at the column edge without wrap.

### LLR-127.3 — Width-aware microbar
- **Traceability:** HLR-127
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The 4-cell size microbar shall render only when the row's available width is ≥ the measured ~43-column threshold (re-measured at P3), dropping cleanly — without disturbing the other fields' offsets — below it.
- **Validation:** `test (integration)`
- **Executed verification:** P1: the microbar is absent in the 120×36 variant-C capture (left-pane interior 41 cols < ~43) and present in the 160×48 capture (rows show `256 ░░░░` / `2.0 Ki█████` overlays). Owed at P4 — a TC rendering both regimes.
- **Numeric pass threshold:** with the threshold T recorded at P3: available ≥ T ⇒ microbar present; < T ⇒ absent; the surviving fields' parsed offsets identical in both limbs.
- **Negative control:** a microbar that renders (or shifts the offsets) below the threshold — the drop assertion goes RED.
- **Boundary catalog:** ☑ boundary — the threshold itself is a tested input.

### LLR-127.4 — RegionRow semantics preserved
- **Traceability:** HLR-127
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The `RegionRow` interaction contract shall survive the re-format unchanged: `can_focus = True`, `↑↓`/`j`/`k` focus movement without wrap, `Enter` posts `Activated(chain=1)`, a real click posts the chain Textual measured, single click inspects and posts no navigation, a chain ≥2 inspects and posts exactly one `OpenInHexRequested` carrying the region start (batch-67 N4a), and no application binding is shadowed while a row holds focus.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — `python -m pytest tests/test_map_click_chain.py tests/test_tui_map_big.py -q` (the batch-67 AC-3/4/5 modules and the batch-77 `test_b77_keys_*` family stay green, adapted only for the new DOM).
- **Numeric pass threshold:** 0 behavior changes across the adapted modules; AC-5's counterfactual (the old single-click-navigates contract stays FALSE) still passes.
- **Negative control:** AC-5 itself — it goes RED if a single click ever navigates again.
- **Boundary catalog:** ☑ boundary — first/last row edges (no wrap, TC-B77-16 preserved); an invalidated row's Enter is inert (TC-B77-19 preserved).

### LLR-128.1 — The 8-byte peek row format
- **Traceability:** HLR-128
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** Each peek row shall render exactly `f"{addr:08X}  " + " ".join(f"{byte:02X}")` over 8 bytes — 8-hex address, two spaces, eight 2-hex bytes (33 cells), no ASCII gutter, no `0x` prefix — assembled as `Text` with `markup=False` content; the shipped 16-byte `render_hex_view` peek surface on this screen is retired by this replacement.
- **Validation:** `test (unit)`
- **Executed verification:** P1 executed: 33 cells re-derived (`00000000  00 01 02 03 04 05 06 07`); 79 cells re-derived for the shipped row (HEX_WIDTH=16). Owed at P4 — a unit TC on the row builder.
- **Numeric pass threshold:** row length 33 for a fully mapped row; 0 ASCII-gutter characters in any peek row.
- **Negative control:** the shipped `_region_hex_peek` output (79-cell rows + gutter) — the format assertion goes RED on today's code.
- **Boundary catalog:** ☑ boundary — unmapped bytes render `··` (measured 2 cells, keeping the 33-cell row width); a region not 8-aligned starts at its containing 8-aligned address (the shipped alignment convention preserved).

### LLR-129.1 — One always-visible stats line
- **Traceability:** HLR-129
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** `build_stats_text`'s successor shall render the seven statistics as ONE line in the field order `Mapped {covered} / {span} span ({pct} · {valid}+{invalid} ranges as N ranges (V valid) · G gaps · I issues`, placed outside any scroll region so it paints in the visible viewport at 120×36 without scrolling; the empty/no-file paths keep the positively-blank strip (LLR-041.9) and the no-entropy note stays distinct (`_NO_ENTROPY_TEXT`).
- **Validation:** `test (unit)` + `test (integration)`
- **Executed verification:** P1: the one-line form measured in the variant-C capture (row 23, 84 content cells, inside the viewport box). Owed at P4 — unit TC on the builder + the AT-288 visibility pilot.
- **Numeric pass threshold:** exactly 1 line (0 embedded newlines) with a loaded image; 7/7 statistics present in the contract's field order; the visible-viewport assertion green at 120×36.
- **Negative control:** a multi-line render — the shipped `build_stats_text` body (`\n` at every segment) goes RED on the one-line assertion; that RED is the P1 counterfactual for AT-288.
- **Boundary catalog:** ☑ empty — no-file (blank strip) and no-entropy (stats from real ranges, note preserved) paths.

### LLR-129.2 — Width-adaptive stats forms
- **Traceability:** HLR-129
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The stats line shall carry a compact form that renders below the measured ~84-panel-column threshold (the full form's 84 content cells do not fit a panel narrower than that), switching at the P3-recorded threshold; both forms assert the same seven statistics, only the separators/labels shorten.
- **Validation:** `test (integration)`
- **Executed verification:** P1: the full form's 84 content cells measured from the capture. Owed at P4 — a TC rendering panels on both sides of the recorded threshold.
- **Numeric pass threshold:** at panel width ≥ threshold the full form renders unwrapped; below it the compact form renders unwrapped; 0 wrapped stats lines at either limb.
- **Negative control:** a stats line that wraps below the threshold — the wrap audit (LLR-130.1) goes RED.
- **Boundary catalog:** ☑ boundary — the threshold itself is a tested input.

### LLR-129.3 — Glance chips
- **Traceability:** HLR-129
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The glance block's successor shall render ONE line of per-band chips in canonical band order — `{glyph} {count} {share}%` per occupied band — where `count` is the band's merged-run tally (consistent with the region list) and `share%` is the band's mapped bytes over the total mapped bytes, each chip ≤ its field width, colour via the `band-*` classes only.
- **Validation:** `test (unit)`
- **Executed verification:** P1: the chips line measured in the variant-C capture (`· 1 19%   ░ 1 5%   ▒ 4 57%   ▓ 3 19%` — counts 1+1+4+3 = 9 runs, shares 19+5+57+19 = 100). Owed at P4 — a unit TC on the chip builder over the demo fixture.
- **Numeric pass threshold:** shares sum to 100 ± 0.5 across the fixture's bands; chips render in `ENTROPY_BAND_LABELS` order; 1 line (0 newlines).
- **Negative control:** chips that sum off 100 (a share arithmetic regression) — the sum assertion goes RED; a per-band presence-only check is the vacuous form this threshold forbids (C-43).
- **Boundary catalog:** ☑ boundary — a single-band image renders one chip summing to 100; an occupied-band subset renders only its chips (no zero chips).

### LLR-130.1 — The wrap-audit harness at five geometries
- **Traceability:** HLR-130
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The audit harness shall run under textual==8.2.8, render the shipped map screen at 80, ~100, 120, 140 and 160 columns (80 deliberately below the audited 100-column floor), walk every authored `Text` surface, and assert each line's cell width ≤ its widget's measured `region.width` — never a terminal-width proxy.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — `python -m pytest <wrap-audit module> -q` under the pin.
- **Numeric pass threshold:** 0 overflow lines across all geometries × surfaces; the harness reports per-surface line widths so a failure names the offending line.
- **Negative control:** LLR-130.2's injected line — the audit goes RED exactly there.
- **Boundary catalog:** ☑ boundary — the 80-col floor and the width-0 first frame are in the matrix.

### LLR-130.2 — The audit's counterfactual
- **Traceability:** HLR-130
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The harness shall expose a test-only injection point that mounts one deliberately over-long authored line, and the audit shall FAIL on it; the injection is the harness's own unit test, separate from the screen renders.
- **Validation:** `test (unit)`
- **Executed verification:** owed at P4 — the injection's unit TC.
- **Numeric pass threshold:** exactly ≥1 failure per injected line; 0 false passes.
- **Negative control:** the injection passing would be the RED — the TC asserts the FAIL (an audit that cannot fail proves nothing; C-43).
- **Boundary catalog:** none.

### LLR-131.1 — The two regime layouts
- **Traceability:** HLR-131
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** Below the recorded panel-width threshold the inspector shall stack under the map pane (mirroring `width-narrow`, LLR-041.10 — reusing the existing class, not a new breakpoint); at or above it the panes render side-by-side; the regime decision shall read the measured panel width (pilot, C-29), never the terminal width.
- **Validation:** `test (integration)`
- **Executed verification:** P1: the 100×30 capture (side-by-side) and the charter's measured budget (~84 panel cols ≈ a stacked regime below it) bound the threshold's re-measurement. Owed at P4 — a TC piloting both regimes.
- **Numeric pass threshold:** 0 regime mismatches across the tested widths; the threshold and its measured evidence recorded in the increment packet.
- **Negative control:** a regime keyed on terminal width — the pilot-measured assertion goes RED the moment the rail narrows the panel (the shipped trap P-4 warns of).
- **Boundary catalog:** ☑ boundary — the threshold ±1 col and the 80×24 floor.

### LLR-131.2 — Re-apportionment on resize
- **Traceability:** HLR-131
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** On every resize — panel `events.Resize`, the bar's `Measured` message, and the first-frame width-0 case — the band bar, the region rows and the peek shall re-apportion against the then-measured width, by the same `call_after_refresh`/`Measured` discipline the shipped bar uses (`screens_directionb.py:2442-2460, 2518-2532`); the bounded single retry on width 0 is the shipped precedent and stays bounded.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — a TC piloting a live resize across the regime boundary and asserting the re-apportioned widths.
- **Numeric pass threshold:** after any resize, every surface's width equals its container's measured width (0 stale); the width-0 first frame never ships a 0-width-derived layout to the screen.
- **Negative control:** a build-once render (the shipped rows/peek of P-4) — the stale-width assertion goes RED on today's code.
- **Boundary catalog:** ☑ boundary — width 0 (first frame) and the resize-across-the-threshold case.

### LLR-131.3 — No width-0-derived layout ships
- **Traceability:** HLR-131
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** A render pass shall not leave any surface apportioned against a zero or stale width once the widget has been laid out; where the width is genuinely 0 (pre-layout), the correction path shall re-run exactly once more frame (the bounded retry) and then on every real resize — never spinning.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — TC asserting the bounded retry and the post-layout convergence.
- **Numeric pass threshold:** 0 surfaces with a 0-derived width after layout settles; the retry count per settle ≤ 2 (the shipped bound preserved).
- **Negative control:** an unbounded re-arm (the shipped code's own warning at `screens_directionb.py:2564-2568`) — a frame-spin detector goes RED.
- **Boundary catalog:** ☑ error — the width-0 input class.

### LLR-132.1 — The four grouped boxes
- **Traceability:** HLR-132
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The map legend's content shall render as grouped bordered boxes in order: **Entropy bands** (the `build_band_key_rows()` rows — glyph, label, `[lo,hi)` range, meaning — plus the `╱` gap-hatch row) · **Map anatomy** (one rendered sample line per map surface → one meaning line each: band bar, ruler, glance chips, stats line) · **Region row** (one rendered sample row + one field-key line) · **Map keys** (batch-94; the pinned line is unchanged) (one line: `↑↓ / j k select · click inspect · double-click / ↵ open hex · Esc close`).
- **Validation:** `test (integration)`
- **Executed verification:** P1: the legend-A capture reconstruction (rows 7-29) is the layout oracle. Owed at P4 — `python -m pytest tests/test_legend_n8.py -q`.
- **Numeric pass threshold:** 4/4 boxes in order; band rows == `len(ENTROPY_BANDS)` (4) + 1 gap row; anatomy == 4 samples; the region-row sample + field key render; the Keys line renders.
- **Negative control:** a prose paragraph anywhere in the sheet — a paragraph-detection assertion (authored lines vs caption role) goes RED.
- **Boundary catalog:** none.

### LLR-132.2 — No wrap, Esc closes
- **Traceability:** HLR-132
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** No line of the sheet shall exceed its container's measured width at 80×24 or 120×36 (the wrap audit covers this surface too), and `Esc` shall dismiss the modal.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — the wrap audit over the legend surface + a pilot Esc key press.
- **Numeric pass threshold:** 0 wrapped lines at both geometries; Esc dismisses 1/1.
- **Negative control:** an injected over-long legend line — the audit goes RED (LLR-130.2's injection point serves this surface too).
- **Boundary catalog:** ☑ boundary — the 80×24 floor geometry.

### LLR-132.3 — The API and the other-view control
- **Traceability:** HLR-132
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The `LegendScreen(sections, view_key)` constructor signature and the `k`/button call sites (`app.py:5973-5995`) shall survive unchanged; the map content change shall live entirely in the map `view_key` path and in `legend.py` map-authored data; the workspace/A2L/MAC/Issues views' legends shall render byte-identical content to the pre-change tree.
- **Validation:** `test (integration)`
- **Executed verification:** owed at P4 — `python -m pytest tests/test_legend_n8.py tests/test_tui_legend.py -q` (the N8 per-view suite + the scope suite stay green).
- **Numeric pass threshold:** 0 diffs in the other views' rendered content (byte-comparison against the pre-change capture); the call-site grep shows the untouched signature.
- **Negative control:** any shared-row edit leaking into another view — the byte-identical control goes RED.
- **Boundary catalog:** ☑ empty — `view_key=None` preserves the pre-N8 fallback; `sections=()` (example-only views) unchanged.

### LLR-132.4 — The band key stays live-sourced
- **Traceability:** HLR-132
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The Entropy-bands box shall derive its rows from `build_band_key_rows()` at render time (the N8 LLR-N8-3.2 live-source law preserved), never from a hand-copied label list; a band label mutated upstream shall appear in the sheet with zero legend-code change; the `[lo,hi)` ranges render `markup=False` (literal brackets, TC-N8-11 precedent).
- **Validation:** `test (unit)`
- **Executed verification:** owed at P4 — the mutated-label unit TC (the N8 anti-drift pattern) + `test_band_key_rows_are_derived_from_entropy_bands` stays green.
- **Numeric pass threshold:** the sheet's band rows equal `build_band_key_rows()` output for the live domain, 0 hand-copied labels (a drift detector over `legend.py` finds no domain-string literals).
- **Negative control:** the mutated-label TC — it goes RED the moment a label is hand-copied into legend data.
- **Boundary catalog:** none.

### LLR-133.1 — The interlock TC
- **Traceability:** HLR-133
- **Ledger:** LED-2026-10-11-batch-93.1
- **Statement:** The batch's diff shall introduce no occurrence of `command_bar_row` nor of the bar's find/goto input ids in any source, test or style file it touches; the map screen shall compose no command-bar widget.
- **Validation:** `test` + `inspection`
- **Executed verification:** P1 executed (the tree state of P-2). Owed at P4 — a registry-listed grep TC over the batch's diff.
- **Numeric pass threshold:** 0 introduced occurrences.
- **Negative control:** any introduced reference — the grep TC goes RED.
- **Boundary catalog:** none.

### Information Flow Contract (IFC) — C-54

> Part A in every batch; Part B when the system's boundary has components a consumer can address independently. The block syntax, its fields and the rules that read them are in `templates/ifc-template.md`, which ships with the flow and is not copied into this batch.

- **Part A — flows:**

```
FLOW: the Memory Map cohesion pass — a presentational re-render of already-computed LoadedFile facts
  SOURCE : the LoadedFile snapshot (ranges, range_validity, entropy_windows, mem_map) + the canonical
           issue list + the enriched A2L tags, handed in by S19TuiApp.update_memory_map; the band
           domain (ENTROPY_BANDS via entropy_style); the legend's authored data (legend.py) and the
           LegendScreen(sections, view_key) push (app.py:5973-5995)
  NODES  :
    - fn    : pane chrome + subtitles (bordered panes, lit titles, affordance hints)
      owner : LLR-125.1
    - fn    : left-pane stack order (bar -> ruler -> chips -> list)
      owner : LLR-126.1
    - fn    : inspector aligned field block
      owner : LLR-126.2
    - fn    : multi-row peek sizing
      owner : LLR-126.3
    - fn    : first-region auto-selection + focus
      owner : LLR-126.4
    - fn    : fixed-width region-row fields
      owner : LLR-127.1
    - fn    : display-only short band labels
      owner : LLR-127.2
    - fn    : width-aware microbar drop
      owner : LLR-127.3
    - fn    : RegionRow interaction semantics (N4a split, keyboard path)
      owner : LLR-127.4
    - fn    : 8-byte peek row format (33 cells, no ascii, .. unmapped)
      owner : LLR-128.1
    - fn    : one-line always-visible stats strip
      owner : LLR-129.1
    - fn    : width-adaptive stats compact form
      owner : LLR-129.2
    - fn    : glance chips line (shares sum to 100 +/- rounding)
      owner : LLR-129.3
    - fn    : wrap-audit harness at five geometries
      owner : LLR-130.1
    - fn    : the audit counterfactual injection
      owner : LLR-130.2
    - fn    : two-regime stack/side-by-side layout
      owner : LLR-131.1
    - fn    : resize re-apportionment (bar, rows, peek)
      owner : LLR-131.2
    - fn    : bounded width-0 convergence
      owner : LLR-131.3
    - fn    : the four legend boxes (bands / anatomy / region row / keys)
      owner : LLR-132.1
    - fn    : legend no-wrap + Esc close
      owner : LLR-132.2
    - fn    : LegendScreen API + other-view byte-identical control
      owner : LLR-132.3
    - fn    : live-sourced band key
      owner : LLR-132.4
    - fn    : command-bar interlock
      owner : LLR-133.1
  SINK   : the #screen_map shipped surface (the operator's terminal) and the k LegendScreen modal;
           the verification records (tests/, the wrap-audit harness, AT-TC-REGISTRY.jsonl)
```

- **Part B — boundary decomposition:** `no — the batch changes no consumer-addressable boundary component` (the panel and the modal exist; no new addressable API is minted — the `LegendScreen(sections, view_key)` signature is preserved by LLR-132.3).

---

## 5. Validation strategy

### 5.1 Methods

> **Two layers** (per the Two-layer validation rule). Every batch declares BOTH:
> - **Layer A — white-box / functional (`TC-NNN`):** validates the HLR/LLR mechanism (the HOW). Methods: `test`, `inspection`, `analysis`.
> - **Layer B — black-box / behavioral acceptance (`AT-NNN`):** validates the user story's outcome through the shipped surface (the WHAT). Method: `acceptance`.

Layer A: LLR-level TCs minted from the reserved block **TC-649..684** (P0 writes the RESERVED
registry rows) across the four existing memmap/legend modules + the new wrap-audit module;
every TC passes the G1–G7 guard. Layer B: **AT-292/293/295** (the shipped acceptances; the P0 block drifted -- G-93-01),
each driving the shipped surface through `App.run_test(size=…)`:

| AT | Story | Outcome observed through the shipped surface | Counterfactual / negative side |
|----|-------|--------------------------------------------|-------------------------------|
| AT-292 | US-125 | every map surface chromed at 120×36 (Layer-B through the shipped surface) | the shipped render: 0 lit titles |
| AT-288 | US-126 | the stats line paints in the visible viewport at 120×36, zero scrolling | the shipped below-fold render (P-1) |
| AT-289 | US-125 | all 9 regions reachable keyboard-only and mouse-only; visible scrollbar on overflow; first region auto-selected; inspector populated with 0 clicks; peek rows clean | the shipped 5-of-9, no-scrollbar render |
| AT-290 | US-127 | region-row parsed field offsets identical across all rows; sizes right-aligned; every band-domain short label ≤9 cells | the shipped single-space rows (2-cell shifts) |
| AT-291 | US-127 | 0 authored lines exceeding their widget's real width at 80/~100/120/140/160 | the injected over-long line MUST fail the audit |
| AT-292 | US-127 | stack below / side-by-side above the recorded PANEL threshold; post-resize re-apportionment leaves 0 stale-width surfaces | the shipped bar-only re-apportionment (rows/peek stale) |
| AT-293 | US-128 | the four legend boxes; the mutated band label flows through with 0 legend-code change; Esc closes; the other views' legends byte-identical | the hand-copied label (live-source TC reddens) |
| TC-663 | US-126 | the glance chips: one line, the shares sum to 100 ± 0.5 across the fixture's bands | a presence-only chips check (the vacuous form) is not the oracle |
| AT-295 | US-125 | the batch's diff introduces 0 `command_bar_row` / find-goto references; the map screen composes no bar | any introduced reference reddens the grep |

### 5.2 Batch acceptance criteria
- Every LLR (125.1–133.1) is covered by ≥1 TC minted from TC-649..684 with a pass result under textual==8.2.8; every story (US-125..128) has ≥1 passing black-box AT (AT-292/293/295) observing its outcome through the shipped surface — with boundary + negative evidence.
- The wrap audit (LLR-130.1) reports 0 overflows at all five geometries, and its counterfactual (LLR-130.2) demonstrably fails on the injected line.
- The four amended-areas' negative controls execute RED on the shipped tree and GREEN after P3 (the alignment assertion on shipped rows; the one-line stats assertion on `build_stats_text`; the peek format on `_region_hex_peek`; the stats visibility at 120×36).
- `HLR-113` + `R-TUI-061` (and `R-TUI-073`'s row format) carry explicit Before/After amendment blocks in the ledger entry, per the operator rule.
- The other views' legends render byte-identical content (0 diffs); the `LegendScreen(sections, view_key)` signature is untouched; the interlock grep shows 0 introduced references.
- The full suite (`python -m pytest tests -q`, not the `-m "not slow"` PR form) stays green before merge; every ledger figure states which form produced it.
- The batch's P3+ does not start until batch-92 has merged and the coordination note exists on disk.

---

## 6. Appendices (optional)

### 6.1 Extended glossary
See §1.3.

### 6.2 Relevant design decisions
- The operator's 2026-08-06 ruling: map C + legend A; variants A/B and legend B evaluated and not chosen (nothing registered for them).
- The batch-77 direction (gap-fold band bar, mapped-byte widths, run-start ruler) is carried untouched — every LLR above says "preserved"/"untouched" where it applies.
- PANEL-column calibration (never terminal columns) is a contract-wide constraint (§2.4).

### 6.3 Open risks
- The ~84- and ~43-column thresholds are charter-measured; P3 re-measures them pilot-style (C-29) and records the values — a drift here changes LLR-129.2/131.1/127.3's asserted constants.
- The region list's visible scrollbar is asserted behaviorally (scroll + DOM); the 120×36 variant-C capture does not glyph-render it (capture limitation, noted in the P2 review).
- batch-92's merge date is outside this batch's control; the P3+ hold is the mitigation (standing authorization).

### 6.4 Phase-1 reconciliation log — moved to the ledger (§7)

### 6.5 Requirement amendments — moved to the ledger (§7)

---

## 7. The ledger — authored as a SEPARATE FILE

The fence below is the ledger's seed: `devflow-init.py` writes it to `01-requirements-ledger.md`. The shape of an entry is in the field guide.

```markdown
# Requirements ledger — s19_app — Batch 2026-10-11-batch-93

> Append-only. Entries are added in chronological order and never rewritten. The live
> contract is `01-requirements.md`; this file records how it came to say what it says.
> Every entry names the requirement it amends; every requirement names its entries. `V26`
> compares the two sets of pairs both ways.

_No entries yet. The first amendment to the live contract writes the first one, in the
shape the field guide's §7 shows (`req-template.part2.md` in the guide directory init prints), and nothing
above this line is ever edited._
```
