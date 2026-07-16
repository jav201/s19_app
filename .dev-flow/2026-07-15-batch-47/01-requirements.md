# Requirements Document — s19_app (Textual TUI) — Batch 47 (screen-upgrades Batch A)

> **Artifact language:** English (per kickoff). Normative keyword: `shall`.
> **Origin:** `prototypes/screen_upgrades.HANDOFF-PLAN.md` (operator-approved 2026-07-15) → `.dev-flow/2026-07-15-batch-47/PLAN.md`.
> **Author:** Phase-1 architect. **Companion:** `01b-qa-strategy-and-verification.md` (qa-reviewer authors the executed-verification commands + numeric pass thresholds for every `TC-NNN`/`AT-NNN`; this document authors the acceptance blocks, boundary catalogs, and both traceability chains).

---

## 1. Introduction

### 1.1 Purpose
Define the requirements for **Batch A of the screen-upgrade "visual data-insight layer"**: a render-level enrichment of five TUI screens (Foundation theme + Workspace MID + A2L Explorer MID + MAC View MID + Memory Map BIG). This is a **presentation-only** batch — no parser, engine, or validation-logic change. It surfaces data the system already computes (entropy windows, coverage metrics, out-of-order records, entry point, A2L enriched-tag fields) through richer rendered surfaces.

### 1.2 Scope
**In scope (5 stories):**
- **US-FND** — app-wide navy/pastel dolphie theme (`styles.tcss`) + a new non-frozen helper module `s19_app/tui/insight_style.py`, with `sev-*` class names + severity semantics preserved.
- **US-WS** — Workspace MID: pane border titles, entropy-colored memstrip with band + gap glyphs, section micro-bars + entropy glyphs, classed hex bytes, loader facts in the stats pane.
- **US-A2L** — A2L Explorer MID: zebra + colored tag table with in-image glyph, colored summary, and a new detail card above the hex pane.
- **US-MAC** — MAC View MID: leading status-glyph column, cyan addresses, zebra, and a coverage strip.
- **US-MAP** — Memory Map BIG: pastel entropy bands + hatch gaps, address ruler, enriched region rows (size micro-bar + symbol count + open-in-hex affordance), region inspector with hex peek.

**Explicitly OUT (non-goals):** Issues Report tiers (PARKED); Patch Editor BIG (Batch B, blocked on batch-46 lineage); raising the 120-col layout caps; Flow Builder; v1 chrome ideas (identity header / curated footer / help overlay); any parser/engine/validation behavior change; any new file-system or execution surface.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| MID / BIG | Cumulative upgrade tiers (MID ⊇ EASY; BIG ⊇ MID) — see `prototypes/screen_upgrades.NOTES.md`. |
| Insight layer | The render-level visual enrichment added by this batch; no data recomputation. |
| Memstrip | The `#ws_memstrip` proportional address strip in the Workspace screen. |
| Band | An entropy classification (`constant/padding` · `low` · `medium` · `high/random`) with a CSS class token + texture glyph, from `entropy_style.py`. |
| Gap glyph | `╱` — an **app-supplied** indicator for an unmapped address gap; NOT an entropy band and NOT sourced from `entropy_style`. |
| OOO | Out-of-order S-records (`S19File.get_out_of_order_records()`). |
| In-image / in-memory | An A2L symbol's address is covered by the loaded image's memory map; flag field is `in_memory` (NOT `in_image`). |
| Engine-frozen | The C-27 dual-guarded set of parser/engine files + 9 test files that must show 0 diff vs `main`. |
| C-17 | Untrusted-text markup-safety control: file-derived text rendered via `safe_text` / Rich `Text` / `markup=False`, never f-strung into markup. |
| C-29 | Two-axis geometry-budget measurement control (measure BOTH width-cols and height-rows of the real boxed panel at target regimes). |
| AT / TC | Black-box acceptance test (`AT-NNN`, the WHAT) / white-box functional test case (`TC-NNN`, the HOW). |

### 1.4 References
- `prototypes/screen_upgrades.HANDOFF-PLAN.md` — approved scope + technical map (§3 foundation, §4.1–§4.4 per screen).
- `prototypes/screen_upgrades.NOTES.md` — tier semantics, dolphie idiom, widget-internal-name-shadowing gotcha.
- `.dev-flow/2026-07-15-batch-47/PLAN.md` — living plan, kickoff auth, verified facts.
- `docs/engineering-rules.md` — C-13 / C-13.1 / C-22 / C-23 / C-28 / C-29 (geometry + snapshot controls).
- `REQUIREMENTS.md` — severity/colour conventions (sev-* contract); existing `R-TUI-*` rows.
- Memory: `project_screen_upgrades_prototype_2026-07-15`, `reference_textual_internal_name_shadowing`.

### 1.5 Document overview
§2 overall description + constraints + source stories (with INVEST refinement). §3 HLRs (EARS). §4 LLRs with grep-verified `file:line` citations or `NEW`/`assumed` flags. §5 validation strategy skeleton + dual traceability. §6 appendices, including §6.4 reconciliation log and §6.5 amendments (memstrip entropy, memory-map band-bands extension, conditional sev-* restyle).

---

## 2. Overall description

### 2.1 Product perspective
The system has three layers (parsers → range/validation engine → TUI services + view code). This batch touches **only the TUI view/service layer**. Every data value it renders is already computed upstream: `LoadedFile.entropy_windows` (worker-thread cached, batch-45), `CoverageMetrics`, `_a2l_enriched_tags`, `S19File.get_out_of_order_records()`, and the entry-point records. The batch adds two new **derived** `LoadedFile` fields (`out_of_order_count`, `entry_point`) populated in the non-frozen `load_service`; it does not re-parse anything.

### 2.2 Product functions
1. App-wide navy/pastel theme + reusable pure render helpers (`insight_style.py`).
2. Workspace: border titles, loader facts, classed hex, section micro-bars, entropy memstrip.
3. A2L: colored/zebra tag table + in-image glyph + detail card.
4. MAC: status-glyph column + coverage strip.
5. Memory Map: pastel bands + hatch gaps + address ruler + enriched region rows + region inspector.

### 2.3 User characteristics
Single role: **firmware analyst** operating the `s19tui` TUI at terminal sizes from 80×24 (tight) to ≥120×30 (comfortable). Expects deterministic, glanceable read-outs of file structure, entropy, coverage, and symbol placement. No new privileges or input surfaces.

### 2.4 Constraints
1. **Engine-frozen (C-27 dual-guard), never edited:** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`, plus the 9 frozen test files (`test_core_srecord_validation`, `test_hexfile`, `test_range_index`, `test_validation_a2l/engine/mac`, `test_tui_a2l`, `test_tui_mac`, `test_color_policy_round_trip`). All work lands in `app.py` / `screens_directionb.py` / new `insight_style.py` / `services/load_service.py` / `models.py` / `styles.tcss` / non-frozen test files. **No new test may land in a frozen test file.** Run `test_tc027` + `test_tc031` + `test_tc032` every increment.
2. **C-17 markup-safety (mandatory per untrusted surface):** A2L `description`/`unit`/`conversion`/`display_identifier` and MAC names are file-derived and untrusted → rendered via `safe_text` (`screens_directionb.py:615`) / Rich `Text` / `markup=False`; NEVER f-strung into markup. A hostile-input AT is required per such surface (Phase-1 requirement, not a Phase-2 catch).
3. **`sev-*` semantics are requirements-level:** class NAMES (`sev-ok`/`sev-error`/`sev-warning`/`sev-info`/`sev-neutral`) and severity meanings (Red = schema/structural failure · Green = memory-checked + present · White = valid record without image hit · Grey = not-yet-checked · Orange = MAC warning) are preserved. `color_policy.py` (the map + `css_class_for_severity` round-trip) stays frozen. Restyling happens ONLY in `styles.tcss`; if the new palette changes any `sev-*` hue, a §6.5 Before/After amendment is required.
4. **C-29 two-axis geometry:** memstrip width, map address ruler tick spacing, map region-row count budget, map inspector hex-peek height, and A2L detail-card/hex vertical split all depend on how much fits in a BOXED panel. Every such geometry claim is flagged `assumed — pilot-measure BOTH axes (width cols + height rows) of the real panel at 80×24 AND 120×30 in Phase 3`. No rendered row/col count is asserted as fact; the throwaway prototype's full-screen budget is NOT inherited.
5. **Textual internal-name shadowing:** new widget members must NEVER be named `_nodes` or `_context` (silent mount crash / idle boot deadlock, no traceback). Check `set(dir(Widget)) & {new private names}` for any new widget.
6. **Snapshot drift is massive by design** (tc016s density matrix + shared-chrome). Baselines are regenerated ONLY in canonical CI (`snapshot-regen.yml`, textual==8.2.8) as a follow-up PR — never locally. C-22 per-cell prediction / C-28 shared-chrome census.

### 2.5 Assumptions and dependencies
- **A1.** `LoadedFile.entropy_windows` is populated on the worker thread for every load (batch-45); renderers only read it. Cite `models.py:65`. *If false → US-WS memstrip + US-MAP bands are invalidated.*
- **A2.** `entropy_style.band_style(label) -> (class, glyph, meaning)` (`entropy_style.py:69`) with glyph set `· ░ ▒ ▓` (`ENTROPY_BAND_GLYPH`, `entropy_style.py:53`) is the single source of band styling. The `█` mentioned in the handoff prose and the `╱` gap glyph are **app-supplied, NEW, and NOT part of `entropy_style`**. *If a designer expects `█` from `entropy_style`, that expectation is wrong — flag at Phase 3.*
- **A3.** `CoverageMetrics` exposes `mac_total` / `mac_in_s19` / `a2l_mac_address_matches` (`validation/model.py:168`/`169`/`173`). *If renamed → US-MAC coverage strip invalidated (but these are frozen `validation/` — will not change this batch).*
- **A4.** `_a2l_enriched_tags` is `list[dict]` (`app.py:882`) whose per-tag in-image flag key is `in_memory` (`a2l.py:1316`), NOT `in_image`. *A spec or test naming `in_image` is wrong.*
- **A5.** Intel-HEX loads discard type 03/05 start-address records (`hexfile.py:135-137`) → no entry point for HEX; `entry_point` is `None` and renders `—`.
- **A6.** The autonomous-through-self-merge run mode is granted for this batch only (kickoff, per `feedback_standing_auth_per_batch`).

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-FND | As a firmware analyst, I want a consistent navy/pastel theme and a shared set of formatting helpers, so that every screen reads as one polished system and the insight cues are uniform and reusable. | HANDOFF-PLAN §3 | READY |
| US-WS | As a firmware analyst, I want the Workspace to show pane titles, an entropy-colored memory strip, per-section size/entropy micro-cues, classed hex bytes, and loader facts, so that I can judge a file's structure and load health at a glance. | HANDOFF-PLAN §4.1 | READY |
| US-A2L | As a firmware analyst, I want the A2L tag table colored/zebra with an in-image glyph and a detail card that shows the selected tag's hidden fields, so that I can read a symbol's metadata without leaving the screen. | HANDOFF-PLAN §4.2 | READY |
| US-MAC | As a firmware analyst, I want each MAC record to carry a status glyph and the view to show a MAC→S19 coverage strip, so that I can see per-record health and overall coverage immediately. | HANDOFF-PLAN §4.3 | READY |
| US-MAP | As a firmware analyst, I want the Memory Map to show pastel entropy bands with hatched gaps, an address ruler, enriched region rows, and a region inspector with a hex peek, so that I can navigate and understand memory layout spatially. | HANDOFF-PLAN §4.4 | READY |

Dependency order: **US-FND → {US-WS, US-A2L, US-MAC, US-MAP}** (the four screen stories are independent of each other once the foundation lands).

#### Refinement log

**US-FND — Foundation theme + `insight_style.py` helpers**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = analyst on any screen · outcome = uniform navy/pastel palette + reusable Rich-Text helpers · why = one visual system + C-17-safe formatting primitives · out of scope = per-screen feature logic, raising col caps.
- **Feasibility:** path = new non-frozen `insight_style.py` (pattern of `entropy_style.py`) + `styles.tcss` additions · dependencies = none · one batch? yes (own increment).
- **Evaluability:** "When any screen renders, the analyst observes the new palette variables, AND the `sev-*` classes keep their names + severity meaning (round-trip intact)." → AT-065a/AT-065b.
- **Classification:** READY.

**US-WS — Workspace MID**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = analyst inspecting a loaded S19/HEX · outcome = titled panes, entropy memstrip, section micro-cues, classed hex, loader facts · why = glanceable structure + load health · out of scope = new parsing (entropy already computed).
- **Feasibility:** path = render-side over `update_sections` / `update_memory_strip` / hex view + new derived `LoadedFile` fields in `load_service` · dependencies = US-FND helpers · unknowns = memstrip width budget (C-29) · one batch? yes.
- **Evaluability:** "When a gapped fixture is loaded, the memstrip shows ≥2 distinct band styles + the gap glyph, and `#ws_stats` shows `Loader N err · ⚠K OOO · Entry 0x…`." → AT-066a/066b/066c/066d, AT-067.
- **Classification:** READY.

**US-A2L — A2L Explorer MID**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = analyst browsing A2L tags · outcome = colored/zebra table + in-image glyph + detail card of hidden fields · why = read metadata in place · out of scope = editing A2L, new pane.
- **Feasibility:** path = render over `_build_a2l_table_cells` + new detail-card widget in `#a2l_hex_pane` + a highlight handler · dependencies = US-FND · unknowns = RowHighlighted handler is NEW; card/hex vertical split budget (C-29) · one batch? yes.
- **Evaluability:** "When the analyst highlights a tag row, the detail card renders that tag's description/unit; a bracket/ANSI-hostile description renders literally (C-17)." → AT-068/AT-069.
- **Classification:** READY.

**US-MAC — MAC View MID**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = analyst reviewing MAC records · outcome = per-record status glyph + coverage strip · why = per-record + overall coverage at a glance · out of scope = MAC editing.
- **Feasibility:** path = render over `update_mac_view` / `_populate_mac_datatable` + new coverage-strip Static · dependencies = US-FND · unknowns = strip must show whenever a MAC is loaded (today conditional) · one batch? yes.
- **Evaluability:** "When a MAC is loaded, the strip shows `MAC→S19 X of Y` equal to `CoverageMetrics`, and each record carries ✓/⚠/✗; a hostile MAC name renders literally (C-17)." → AT-070/AT-071.
- **Classification:** READY.

**US-MAP — Memory Map BIG**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = analyst navigating memory layout · outcome = pastel bands + hatch gaps + address ruler + enriched region rows + region inspector w/ hex peek · why = spatial understanding + navigation · out of scope = new parsing; linear scans for symbol counts (must use `range_index`).
- **Feasibility:** path = render over `MemoryMapPanel` / `RegionRow` + reuse `RegionRow.Activated`/`OpenInHexRequested` + new ruler widget · dependencies = US-FND · unknowns = ruler tick spacing / row-count / hex-peek budgets (C-29) · one batch? yes.
- **Evaluability:** "When the analyst activates a region row, the inspector shows a hex peek at the region start; each row shows an `N sym` count matching a `range_index` membership count; ruler ticks match the span." → AT-072a/072b, AT-073, AT-074.
- **Classification:** READY.

---

## 3. High-level requirements (HLR)

> One HLR per shipped-requirement row. HLR-065…HLR-074 map 1:1 to the new `R-TUI-065`…`R-TUI-074` requirement rows (highest existing = R-TUI-064). Every HLR traces to a source US.

### HLR-065 — Foundation: navy/pastel theme + `insight_style` helpers (R-TUI-065)
- **Traceability:** US-FND
- **Statement:** The TUI shall provide an app-wide navy/pastel theme in `styles.tcss` and a non-frozen `insight_style` helper module exposing pure formatting primitives, while preserving the `sev-*` class names and severity semantics.
- **Rationale:** One visual system + reusable, C-17-safe Rich-`Text` primitives that every screen story consumes; the `sev-*` contract is a requirements-level invariant.
- **Validation:** `test` + `inspection`
- **Executed verification:** → `01b-qa-strategy-and-verification.md` (unit tests over `insight_style` helpers; `test_color_policy_round_trip` unchanged; inspection of `styles.tcss` `sev-*` block).
- **Numeric pass threshold:** → `01b-qa-strategy-and-verification.md` (target: helper unit tests pass; `sev-*` round-trip 0 failures; 0 frozen-file diffs).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** any screen renders with the new palette variables; `sev-*`-classed rows keep their severity meaning and class names.
  - **Shipped surface:** `styles.tcss` applied app-wide + `insight_style` helpers used by screen renderers.
  - **Deliverable + observation:** rendered screen shows navy panel background + pastel accents; `css_class_for_severity` round-trip intact (a `sev-error` row is still red-classed). Observed via Pilot snapshot/state assertion.
  - **Acceptance test(s):** `AT-065a` (palette applied app-wide — `test_tui_theme.py::test_at065a_palette`), `AT-065b` (`sev-*` names + semantics preserved via round-trip — `test_tui_theme.py::test_at065b_sev_semantics`).
  - **Boundary catalog:** ☐ empty = N/A (theme always applies) · ☐ boundary = smallest terminal 80×24 renders theme · ☐ invalid = N/A (no input) · ☐ error = N/A (pure CSS/helpers, no failure path). `human_bytes(0)` boundary covered by unit TC.

### HLR-066 — Workspace: pane titles, section micro-cues, classed hex, loader facts (R-TUI-066)
- **Traceability:** US-WS
- **Statement:** When a file is loaded, the Workspace screen shall render border titles on its three panes, section rows with an in-range glyph + cyan address + humanized size + size micro-bar + entropy glyph, classed hex bytes, and a loader-facts line in `#ws_stats`.
- **Rationale:** Glanceable structure + load health without re-parsing; all values already computed or derived at load.
- **Validation:** `test`
- **Executed verification:** → `01b-qa-strategy-and-verification.md`.
- **Numeric pass threshold:** → `01b-qa-strategy-and-verification.md`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** `#ws_stats` shows `Loader N err · ⚠K OOO · Entry 0x…`; section rows show glyph + humanized size; hex bytes are classed by kind.
  - **Shipped surface:** `_compose_screen_workspace` + `update_sections` + hex view + `#ws_stats`.
  - **Deliverable + observation:** for the 4-OOO fixture `examples/case_00_public/prg.s19`, `#ws_stats` renders `⚠4 OOO` and an `Entry 0x…` value; a present-but-zero entry (`0x0`) renders `0x00000000` and remains distinct from an ABSENT entry (HEX → `—`); and after attaching a MAC to a loaded S19 the loader facts stay unchanged (merge preserves OOO/entry). Observed via Pilot text assertion.
  - **Acceptance test(s):** `AT-066a` (loader-facts OOO `⚠4 OOO` for `prg.s19` — `test_tui_workspace_insight.py::test_at066a_ooo`), `AT-066b` (entry PRESENT S19 `0x80000000` for `case_01`; `0x0` renders `0x00000000` not `—` — `…::test_at066b_entry_present`), `AT-066c` (entry ABSENT HEX `—` via inline hex builder — `…::test_at066c_entry_absent_hex`), `AT-066d` (**F-1 merge-carry**: load S19 OOO=4 → attach MAC → stats still `⚠4 OOO` + entry preserved — `…::test_at066d_merge_preserves_facts`).
  - **Boundary catalog:** ☐ empty = no file loaded → stats blank/placeholder (no crash) · ☐ boundary = 0 errors / 0 OOO renders `Loader 0 err · ⚠0 OOO` · ☐ invalid = N/A (read-only render) · ☐ error = HEX load → `Entry —` (no start record). MAC-merge onto a loaded S19 must NOT reset OOO/entry (LLR-066.7, AT-066d).

### HLR-067 — Workspace: entropy-colored memstrip with band + gap glyphs (R-TUI-067)
- **Traceability:** US-WS
- **Statement:** When a file with computed entropy windows is loaded, the `#ws_memstrip` shall color each address segment by its entropy band (class + texture glyph from `entropy_style.band_style`) and shall mark unmapped address gaps with the `╱` gap glyph.
- **Rationale:** Surfaces entropy that is already computed but currently descoped from the memstrip (`update_memory_strip` renders valid/invalid/gap only — "No entropy (D3 descoped)").
- **Validation:** `test`
- **Executed verification:** → `01b-qa-strategy-and-verification.md`.
- **Numeric pass threshold:** → `01b-qa-strategy-and-verification.md`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the memstrip shows ≥2 distinct band styles and the `╱` gap glyph for a fixture containing gaps.
  - **Shipped surface:** `update_memory_strip` → `#ws_memstrip`.
  - **Deliverable + observation:** for a gapped fixture, the rendered memstrip contains ≥2 of the glyphs `· ░ ▒ ▓` and at least one `╱`; observed via Pilot text/state assertion.
  - **Acceptance test(s):** `AT-067`
  - **Boundary catalog:** ☐ empty = no entropy windows → memstrip falls back to the pre-existing valid/invalid/gap coloring (no crash) · ☐ boundary = a single-band file → ≥1 band style (not necessarily 2) · ☐ invalid = N/A · ☐ error = N/A. **§6.5 amendment (memstrip adds entropy).**

### HLR-068 — A2L: colored/zebra tag table + in-image glyph + colored summary (R-TUI-068)
- **Traceability:** US-A2L
- **Statement:** When A2L tags are displayed, the tag table shall render zebra rows with Rich-`Text` cells (name bright, address cyan, source muted) and a leading in-image glyph (`✓`/`·`) derived from each tag's `in_memory` flag, and `#a2l_tags_summary` shall show a colored in-image count.
- **Rationale:** Distinguish in-image vs absent symbols at a glance; all fields already parsed.
- **Validation:** `test`
- **Executed verification:** → `01b-qa-strategy-and-verification.md`.
- **Numeric pass threshold:** → `01b-qa-strategy-and-verification.md`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** tags render zebra + colored with a leading `✓`/`·`; summary shows a colored count.
  - **Shipped surface:** `_build_a2l_table_cells` → `#a2l_tags_list` + `#a2l_tags_summary`.
  - **Deliverable + observation:** for a real A2L fixture, ≥1 row shows `✓` and ≥1 shows `·` matching `in_memory`; observed via Pilot cell assertion.
  - **Acceptance test(s):** `AT-068` (glyph branches — `test_tui_a2l_detail.py::test_at068_glyph_branches`), `AT-069c` ★ (C-17: hostile A2L table-cell name renders verbatim — `…::test_at069c_c17_table_name`, gate-blocking).
  - **Boundary catalog:** ☐ empty = no A2L loaded → empty table, summary `0` · ☐ boundary = all-in-image / none-in-image → uniform glyph column · ☐ invalid = malformed tag rows still render (parser already tolerant) · ☐ error = untrusted name/text in ANY file-derived cell → literal render (C-17, see LLR-068.1/068.3, AT-069c).

### HLR-069 — A2L: detail card on row highlight (R-TUI-069)
- **Traceability:** US-A2L
- **Statement:** When an A2L tag row is highlighted, the system shall render a detail card at the top of `#a2l_hex_pane` (hex view shrinking below in the same pane) showing the selected tag's description, unit·conversion, record layout, byte order, and limits, with all file-derived text rendered C-17-safe.
- **Rationale:** Surfaces the ~14 hidden A2L fields without a new pane; untrusted text must render literally.
- **Validation:** `test`
- **Executed verification:** → `01b-qa-strategy-and-verification.md`.
- **Numeric pass threshold:** → `01b-qa-strategy-and-verification.md`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** highlighting a row renders that tag's description/unit in the card; a hostile description renders literally.
  - **Shipped surface:** NEW `on_data_table_row_highlighted` handler + NEW detail-card widget in `#a2l_hex_pane`.
  - **Deliverable + observation:** highlighting a known tag shows its description text in the card; a fixture tag whose description contains `[red]`/ANSI renders those characters literally (no markup applied). Observed via Pilot text assertion.
  - **Acceptance test(s):** `AT-069` (behavioral — `test_tui_a2l_detail.py::test_at069_card_highlight`), `AT-069b` ★ (C-17 card description/unit literal — `…::test_at069b_c17_card`). Sibling table-cell C-17 is `AT-069c` (LLR-068.3), a distinct sink.
  - **Boundary catalog:** ☐ empty = no selection → card shows placeholder/hint · ☐ boundary = tag with empty optional fields → card renders `—`/blank rows without crash · ☐ invalid = tag with missing keys → defensive default · ☐ error = untrusted markup/ANSI in any field → literal (C-17).

### HLR-070 — MAC: status-glyph column + cyan addresses + zebra (R-TUI-070)
- **Traceability:** US-MAC
- **Statement:** When MAC records are displayed, each record row shall carry a leading colored status glyph — `✓` (parse-ok + in-image) / `⚠` (parse-ok + out-of-image) / `✗` (parse-error) — with cyan addresses and zebra rows, and MAC names rendered C-17-safe.
- **Rationale:** Per-record health at a glance; `⚠` matches the existing Orange MAC-warning semantics.
- **Validation:** `test`
- **Executed verification:** → `01b-qa-strategy-and-verification.md`.
- **Numeric pass threshold:** → `01b-qa-strategy-and-verification.md`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** each MAC row shows a colored `✓`/`⚠`/`✗`; a hostile MAC name renders literally.
  - **Shipped surface:** `update_mac_view` / `_populate_mac_datatable` → `#mac_records_list`.
  - **Deliverable + observation:** for a mixed fixture (`case_02`), rows render the `✓` and `⚠` classes matching status; a NEW parse-error MAC fixture drives the `✗` branch; a fixture MAC name containing `[red]`/ANSI renders literally. Observed via Pilot cell assertion.
  - **Acceptance test(s):** `AT-070` (`✓` AND `⚠` by content, `case_02` — `test_tui_mac_coverage.py::test_at070_glyph_branches`), `AT-070b` ★ (C-17 MAC name literal — `…::test_at070b_c17_name`), `AT-070c` (**M1**: parse-error record → `✗` — `…::test_at070c_parse_error`, drives a NEW non-frozen parse-error MAC fixture, Phase-3 budget).
  - **Boundary catalog:** ☐ empty = no MAC loaded → empty table · ☐ boundary = all-ok / all-error → uniform glyph column · ☐ invalid = parse-error record → `✗` glyph (AT-070c, NEW fixture) · ☐ error = untrusted name → literal (C-17).

### HLR-071 — MAC: coverage strip (R-TUI-071)
- **Traceability:** US-MAC
- **Statement:** While a MAC file is loaded, the MAC View shall render a coverage strip above `#mac_records_list` reading `MAC→S19 X of Y ▓▓▓░░ · A2L↔MAC N matches`, with `X`/`Y`/`N` taken from `CoverageMetrics.mac_in_s19`/`mac_total`/`a2l_mac_address_matches`, independent of the loaded file type.
- **Rationale:** Overall coverage is currently only a conditional pct-line; make it always-visible when a MAC exists.
- **Validation:** `test`
- **Executed verification:** → `01b-qa-strategy-and-verification.md`.
- **Numeric pass threshold:** → `01b-qa-strategy-and-verification.md`.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the strip shows `X of Y` equal to the fixture's `CoverageMetrics`.
  - **Shipped surface:** NEW coverage-strip Static above `#mac_records_list` in `_compose_screen_mac`.
  - **Deliverable + observation:** for a fixture, the rendered `X of Y` equals `mac_in_s19`/`mac_total`; the strip appears whenever a MAC is loaded. Observed via Pilot text assertion.
  - **Acceptance test(s):** `AT-071`
  - **Boundary catalog:** ☐ empty = no MAC → strip absent (gate on MAC loaded) · ☐ boundary = `mac_total == 0` → `0 of 0`, empty micro-bar (no divide-by-zero; `mac_in_s19_pct` returns 0.0) · ☐ invalid = N/A (read-only) · ☐ error = N/A.

### HLR-072 — Memory Map: pastel bands + hatch gaps + address ruler + humanized sizes (R-TUI-072)
- **Traceability:** US-MAP
- **Statement:** When the Memory Map renders, the proportional strip shall color each segment by entropy band with a `╱` hatch for unmapped gaps, display humanized sizes, and render an address ruler beneath the strip with 5 tick labels at 0/25/50/75/100 % of the address span.
- **Rationale:** Spatial legibility; extends the batch-45 band-bands view (R-TUI-060/041) with ruler + hatch + humanization.
- **Validation:** `test`
- **Executed verification:** → `01b-qa-strategy-and-verification.md`.
- **Numeric pass threshold:** → `01b-qa-strategy-and-verification.md`.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** the strip shows ≥2 band styles + a hatched gap; the ruler's ticks match the span endpoints.
  - **Shipped surface:** `MemoryMapPanel` (`_build_band_widgets`) + NEW ruler widget under the strip.
  - **Deliverable + observation:** for a gapped fixture, the strip renders ≥2 of `· ░ ▒ ▓` + ≥1 `╱`; ruler tick 0 % == span start, tick 100 % == span end. Observed via Pilot text assertion.
  - **Acceptance test(s):** `AT-072a` (≥2 band styles + `╱` hatch — `test_tui_map_big.py::test_at072a_bands`), `AT-072b` (ruler exactly 5 ticks; 0 % == span start, 100 % == span end — `…::test_at072b_ruler`).
  - **Boundary catalog:** ☐ empty = no file → panel shows hint, no ruler crash · ☐ boundary = single contiguous range (no gap) → no `╱`; ruler still spans start→end · ☐ invalid = N/A · ☐ error = N/A. **§6.5 amendment (R-TUI-060/041 band-bands extension).** Ruler tick spacing = **geometry claim, C-29 flagged.**

### HLR-073 — Memory Map: enriched region rows (size micro-bar + symbol count + open-in-hex) (R-TUI-073)
- **Traceability:** US-MAP
- **Statement:** When region rows render, each `RegionRow` shall show a size micro-bar (region size ÷ largest region), an `N sym` count of A2L enriched-tag addresses within the region span computed via `range_index` membership primitives (not linear scans), and an explicit `↵` open-in-hex affordance.
- **Rationale:** Per-region density + one-key navigation; the open action already exists (`RegionRow.Activated` / `OpenInHexRequested`).
- **Validation:** `test`
- **Executed verification:** → `01b-qa-strategy-and-verification.md`.
- **Numeric pass threshold:** → `01b-qa-strategy-and-verification.md`.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** each region row shows a size micro-bar, an `N sym` count, and an `↵` affordance.
  - **Shipped surface:** `RegionRow` render + `range_index` membership.
  - **Deliverable + observation:** for a fixture with A2L symbols in a region, the row's `N sym` equals the `range_index` membership count for that span; `↵` present. Observed via Pilot cell assertion.
  - **Acceptance test(s):** `AT-073`
  - **Boundary catalog:** ☐ empty = region with 0 symbols → `0 sym` · ☐ boundary = all symbols in one region → that row's count == total · ☐ invalid = no A2L loaded → all rows `0 sym` (or count suppressed) · ☐ error = N/A. Region-row count budget = **geometry claim, C-29 flagged.**

### HLR-074 — Memory Map: region inspector with hex peek (R-TUI-074)
- **Traceability:** US-MAP
- **Statement:** When a region row is activated, the system shall populate the existing `#map_detail` pane with the region's span, size, dominant band, and a 3-row hex peek at the region start, with any file-derived symbol text rendered C-17-safe.
- **Rationale:** Inspect a region without leaving the map; reuses the existing `RegionRow.Activated` → `on_region_row_activated` path.
- **Validation:** `test`
- **Executed verification:** → `01b-qa-strategy-and-verification.md`.
- **Numeric pass threshold:** → `01b-qa-strategy-and-verification.md`.
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** activating a region row updates the inspector with a hex peek starting at that region's start address.
  - **Shipped surface:** `on_region_row_activated` → `#map_detail_body`.
  - **Deliverable + observation:** activating a NON-first region row renders hex bytes whose first address equals that region's start; and a bracketed A2L symbol name that surfaces in the inspector (`symbols_in_window` → `symbol_list_text`) renders literally in `#map_detail_body` (C-17). Observed via Pilot text assertion.
  - **Acceptance test(s):** `AT-074` (inspector hex peek @ NON-first region start — `test_tui_map_big.py::test_at074_inspector` — **with a mandatory C-17 sub-assertion**: a `[red]`/`sensor[unclosed` symbol name renders verbatim in `#map_detail_body`, MN-4).
  - **Boundary catalog:** ☐ empty = no region activated → inspector shows hint (`_DETAIL_HINT`) · ☐ boundary = region shorter than 3 rows → peek shows available bytes only · ☐ invalid = N/A · ☐ error = untrusted symbol text in the detail → literal (C-17, existing `safe_text` usage at `screens_directionb.py:1168`; A2L symbol names DO surface here — see LLR-074.3). Hex-peek height = **geometry claim, C-29 flagged.**

---

## 4. Low-level requirements (LLR)

> Same EARS regime. `file:line` citations are grep-verified in the current worktree unless flagged `NEW` (created in Phase 3) or `assumed` (geometry, verify in Phase 3). Executed-verification commands + numeric thresholds for `test` LLRs are authored in `01b-qa-strategy-and-verification.md` (division of labor per kickoff).

### HLR-065 — Foundation

**LLR-065.1 — `insight_style.py` palette constants**
- **Traceability:** HLR-065
- **Statement:** The system shall define, in a NEW non-frozen module `s19_app/tui/insight_style.py`, the dolphie-derived palette constants (label `#c5c7d2`, value `#e9e9e9`, green `#54efae`, yellow `#f6ff8f`, red `#fd8383`, hilite `#91abec`, lblue `#bbc8e8`, dgray `#969aad`, purple `#b565f3`, cyan `#7dd3fc`, depth stack bg `#0a0e1b` / panel `#0f1525` / odd-row `#131a2c` / border `#1b233a`).
- **Symbols:** `s19_app/tui/insight_style.py` `NEW — created in Phase 3` (pattern = `entropy_style.py`).
- **Validation:** `inspection` (module exists, constants present).
- **Acceptance criteria:** palette constants importable; values match the operator-approved SVG palette.

**LLR-065.2 — pure formatting helpers**
- **Traceability:** HLR-065
- **Statement:** `insight_style` shall expose pure, unit-testable helpers `human_bytes(n) -> str`, `label_value(label, value, style) -> Text`, `microbar(frac, width, style) -> Text`, and `threshold_style(pct, warn, bad) -> str`, where the `Text`-returning helpers construct Rich `Text` objects (C-17-safe by construction, never markup-parsed).
- **Symbols:** all four `NEW — created in Phase 3`. `Text` = `rich.text.Text`.
- **Validation:** `test (unit)` — → `01b-qa-strategy-and-verification.md` for command + threshold.
- **Acceptance criteria:** `human_bytes(0)`, boundary values, and `microbar(0.0/1.0)` produce deterministic output; `label_value`/`microbar` return `Text` (not `str`).

**LLR-065.3 — `styles.tcss` navy/pastel theme + chrome**
- **Traceability:** HLR-065
- **Statement:** `styles.tcss` shall apply the navy/pastel palette to the app `$`-variables and add panel `border: tall` + `border-title-*` styling, zebra variables, and chip-button styles, applied app-wide via the `Screen` rule.
- **Symbols:** `$`-vars `styles.tcss:26-30` (`$accent-calm`/`$bg-base`/`$bg-panel`/`$fg-base`/`$rule`); `Screen` rule `styles.tcss:32`; existing `border-title`/`border: tall` occurrences present in `styles.tcss` (baseline).
- **Validation:** `inspection` (CSS diff) + snapshot (regen in canonical CI only).
- **Acceptance criteria:** theme vars applied; app-wide (touches every screen's snapshot — expected drift, C-22/C-28 census).

**LLR-065.4 — `sev-*` name + semantics preservation**
- **Traceability:** HLR-065
- **Statement:** The batch shall preserve the `sev-*` class NAMES (`sev-ok`/`sev-error`/`sev-warning`/`sev-info`/`sev-neutral`) and their severity semantics; `color_policy.py` and `css_class_for_severity` shall remain frozen and untouched; any hue change to a `sev-*` rule in `styles.tcss` shall be recorded as a §6.5 Before/After amendment.
- **Symbols:** `sev-*` rules `styles.tcss:499-515`; `band-*` rules `styles.tcss:529-541`; `color_policy.py` (frozen, C-27); `css_class_for_severity` (frozen).
- **Validation:** `test (round-trip)` — `test_color_policy_round_trip` unchanged (frozen) + `inspection` of `styles.tcss` sev-* block.
- **Acceptance criteria:** 0 diff in `color_policy.py`; sev-* class names unchanged; §6.5 amendment present iff any sev-* hue changed.

### HLR-066 — Workspace core

**LLR-066.1 — pane border titles**
- **Traceability:** HLR-066
- **Statement:** `_compose_screen_workspace` shall set border titles/subtitles on the three Workspace panes.
- **Symbols:** `_compose_screen_workspace` `app.py:1324`; `#ws_left` `app.py:1373`, `#ws_center` `app.py:1389`, `#ws_right` `app.py:1400`.
- **Validation:** `test (pilot)` / snapshot.
- **Acceptance criteria:** each pane renders a border title.

**LLR-066.2 — section rows enriched**
- **Traceability:** HLR-066
- **Statement:** `update_sections` shall render each section row with an in-range glyph (`✓`), a cyan address, a right-aligned humanized size (`human_bytes`), a size micro-bar (`microbar(size / biggest)`), and an entropy glyph.
- **Symbols:** `update_sections` `app.py:8137`; `#sections_list` `app.py:1372`; existing coverage bar `build_coverage_bar_text` `app.py:8187`; `human_bytes`/`microbar` (NEW, LLR-065.2); entropy glyph via `entropy_style.band_style` `entropy_style.py:69`.
- **Validation:** `test (pilot)`.
- **Acceptance criteria:** a fixture section row shows glyph + humanized size + micro-bar; entropy glyph one of `· ░ ▒ ▓`.

**LLR-066.3 — classed hex bytes**
- **Traceability:** HLR-066
- **Statement:** The hex rendering shall class each byte: `00`/`FF` dim-gray, printable-ASCII cyan, all other bytes bright, without changing the public hex constants `MAX_HEX_BYTES`/`MAX_HEX_ROWS`/`HEX_WIDTH`/`SEARCH_ENCODING`.
- **Symbols:** `render_hex_view_text` in `tui/hexview.py` (NOT frozen; constants are public API exported from `tui/__init__.py`). **Mechanism choice (flag):** styling applied EITHER inside `render_hex_view_text` OR post-styled in the view layer — Phase 3 selects; constants untouched either way.
- **Validation:** `test (pilot)` / snapshot.
- **Acceptance criteria:** a `00`/`FF` byte renders dim; a printable-ASCII byte renders cyan; constants unchanged.

**LLR-066.4 — loader-facts line**
- **Traceability:** HLR-066
- **Statement:** The Workspace stats pane `#ws_stats` shall render `Loader N err · ⚠K OOO · Entry 0x…`, where `N` = `len(LoadedFile.errors)`, `K` = `LoadedFile.out_of_order_count`, and `Entry` = `LoadedFile.entry_point` (or `—` when absent).
- **Symbols:** `#ws_stats` Static (`markup=False`) `app.py:1394`; `LoadedFile.errors` `models.py` (existing); `out_of_order_count`/`entry_point` `NEW — created in Phase 3` (LLR-066.5).
- **Validation:** `test (pilot)` — value assertion over `prg.s19` (4-OOO fixture).
- **Acceptance criteria:** `⚠4 OOO` for `examples/case_00_public/prg.s19`; `Entry —` for a HEX load.

**LLR-066.5 — derived `LoadedFile` fields**
- **Traceability:** HLR-066
- **Statement:** `load_service` shall populate two NEW `LoadedFile` fields at construction: `out_of_order_count = len(S19File.get_out_of_order_records())` and `entry_point` = the address of the S7/S8/S9 record scanned from `s19.records` (or `None` for Intel-HEX loads, which discard type 03/05 records). The two fields shall be declared **defaulted, appended after `entropy_windows`** on the `LoadedFile` dataclass — `out_of_order_count: int = 0`, `entry_point: Optional[int] = None` — so that every existing constructor that omits them keeps compiling and takes the safe defaults.
- **Symbols:** `LoadedFile` `models.py:10`; `entropy_windows` field `models.py:65` (new fields appended AFTER it); NEW fields `out_of_order_count: int = 0`, `entry_point: Optional[int] = None` `NEW — created in Phase 3` (dataclass fields on `LoadedFile`, not a Widget → `_nodes`/`_context` shadowing rule N/A here; noted for widget members only); `build_loaded_s19` `load_service.py:18` (construct site `61-76`), `build_loaded_hex` `load_service.py:79` (construct site `94-108`); `S19File.get_out_of_order_records()` `core.py:542` (returns `List[dict]` → `len`); HEX discard `hexfile.py:135-137`.
- **Constructor-census (MN-6):** ~40 non-frozen test `LoadedFile(` sites plus `crc.py:1425` and `placeholders.py:67` omit the two new fields and take the defaults (no behavior change). **No frozen test file constructs `LoadedFile`**, so appending defaulted fields keeps C-27 at 0-diff for the frozen src+test set.
- **Validation:** `test (unit)` — construct over fixtures; `analysis` for the HEX-`None` path.
- **Acceptance criteria:** `out_of_order_count == 4` for `prg.s19`; `entry_point is None` for a HEX fixture; defaults preserve every omitting constructor; 0 frozen-file diff.

**LLR-066.6 — Workspace stats C-17 disposition**
- **Traceability:** HLR-066
- **Statement:** The loader-facts line shall render only numeric counts and a hex entry address (no untrusted file-derived text); `#ws_stats` shall keep `markup=False`.
- **Symbols:** `#ws_stats` `markup=False` `app.py:1394`.
- **Validation:** `inspection`.
- **Acceptance criteria:** N/A for untrusted-text AT — the line carries no file-derived free text (error COUNT only, not error message text). Marked N/A with reason.

**LLR-066.7 — MAC-merge / primary-reload preserve derived facts (writer-census, MJ-1)**
- **Traceability:** HLR-066
- **Statement:** When a MAC is attached to an already-loaded S19 (or the primary is reloaded while a MAC is preserved), the merge that rebuilds the `LoadedFile` snapshot shall **carry `out_of_order_count` and `entry_point` forward from the source payload**, and shall NOT re-default them to `0`/`None`. After loading an S19 with `out_of_order_count == 4` and a non-`None` entry, attaching a MAC shall leave `#ws_stats` reading `⚠4 OOO` with the entry unchanged.
- **Symbols:** primary-reload-preserving-MAC merge `app.py:6954`; `_merge_mac_with_existing_primary` `app.py:6997` — both field-copy the prior snapshot and, without this LLR, would leave the two new fields at their dataclass defaults; source payload = the `LoadedFile` produced by `load_service` (LLR-066.5). Compute sites `load_service.py:61`/`:94` (correct by construction); MAC-load site `_load_mac_file` `app.py:6791` (MAC carries no OOO/entry → defaults are correct there).
- **Validation:** `test (pilot)` — load S19 (OOO=4, entry present) → attach MAC → assert `#ws_stats` still shows `⚠4 OOO` + preserved entry.
- **Acceptance criteria:** OOO/entry survive the MAC-merge and primary-reload paths (AT-066d); the four `LoadedFile(` construction sites are reconciled in §6.4 writer-census.

### HLR-067 — Workspace memstrip

**LLR-067.1 — entropy-banded memstrip segments**
- **Traceability:** HLR-067
- **Statement:** `update_memory_strip` shall color each `#ws_memstrip` segment by its entropy band using `entropy_style.band_style(label) -> (class, glyph, meaning)`, reading `LoadedFile.entropy_windows`.
- **Symbols:** `update_memory_strip` `app.py:8289`; `#ws_memstrip` Container `app.py:1409`; `LoadedFile.entropy_windows` `models.py:65`; `band_style` `entropy_style.py:69`; glyphs `ENTROPY_BAND_GLYPH` (`· ░ ▒ ▓`) `entropy_style.py:53`.
- **Validation:** `test (pilot)`.
- **Acceptance criteria:** ≥2 distinct band styles for a multi-band fixture.

**LLR-067.2 — gap glyph for unmapped segments**
- **Traceability:** HLR-067
- **Statement:** `update_memory_strip` shall mark unmapped address gaps with the `╱` glyph, which is app-supplied and NOT sourced from `entropy_style`.
- **Symbols:** `╱` `NEW — app-supplied` (confirmed absent from `ENTROPY_BAND_GLYPH` `entropy_style.py:53`; the handoff-prose `█` is NOT the canonical `high/random` glyph, which is `▓`).
- **Validation:** `test (pilot)`.
- **Acceptance criteria:** ≥1 `╱` for a gapped fixture.

**LLR-067.3 — memstrip fallback (no entropy)**
- **Traceability:** HLR-067
- **Statement:** If `LoadedFile.entropy_windows` is empty, then `update_memory_strip` shall fall back to the pre-existing valid/invalid/gap coloring without error.
- **Symbols:** `update_memory_strip` current behavior `app.py:8300` ("No entropy (D3 descoped)").
- **Validation:** `test (unit)` — empty-windows path.
- **Acceptance criteria:** no exception; strip still renders.

**LLR-067.4 — memstrip width geometry (C-29)**
- **Traceability:** HLR-067
- **Statement:** The memstrip cell count / width shall fit the `#ws_memstrip` container's real budget at 80×24 and 120×30.
- **Symbols:** `#ws_memstrip` `app.py:1409`.
- **Geometry:** `assumed — pilot-measure BOTH axes (width cols + height rows) of the #ws_memstrip container at 80×24 AND 120×30 in Phase 3`. No cell count asserted here.
- **Validation:** `analysis` (Phase-3 pilot measurement).
- **Acceptance criteria:** memstrip renders within its box at both regimes (no overflow/clip of the gap/band glyphs).

### HLR-068 — A2L table

**LLR-068.1 — zebra + colored cells + in-image glyph (every file-derived cell is Rich `Text`)**
- **Traceability:** HLR-068
- **Statement:** `_build_a2l_table_cells` shall emit zebra-striped rows and shall return a `tuple[Text, ...]` in which **every file-derived cell is a Rich `Text`** (via `safe_text` or equivalent), never a bare `str` — specifically `name` (bright), `source` (muted), `unit`, `function_group`, `memory_region`, `raw_value`, and `physical_value`, plus the cyan address and the leading in-image glyph (`✓` when `in_memory` is truthy, else `·`). No file-derived value is f-strung into a markup string.
- **Symbols:** `_build_a2l_table_cells` `app.py:9090` (returns `tuple[Text, ...]` — was a 16-tuple of plain `str`); `#a2l_tags_list` `app.py:3932`; in-image flag key `in_memory` `a2l.py:1316` (NOT `in_image`); `_a2l_enriched_tags` `list[dict]` `app.py:882`; `safe_text` `screens_directionb.py:615`; `Text` = `rich.text.Text`.
- **Validation:** `test (pilot)` for glyph/zebra/colour; `test (pilot, hostile-input)` for the "every cell is `Text`" C-17 property (AT-069c).
- **Acceptance criteria:** ≥1 `✓` row + ≥1 `·` row matching `in_memory`; the builder returns `tuple[Text, ...]` (every cell is a `Text`, the property TC-068.1 / AT-069c assert).

**LLR-068.2 — colored in-image summary**
- **Traceability:** HLR-068
- **Statement:** `#a2l_tags_summary` shall render a colored in-image count.
- **Symbols:** `#a2l_tags_summary` `app.py:3937`.
- **Validation:** `test (pilot)`.
- **Acceptance criteria:** summary count equals number of `in_memory`-truthy tags.

**LLR-068.3 — A2L cell C-17 safety (all file-derived cells, distinct sink from the card)**
- **Traceability:** HLR-068
- **Statement:** Every file-derived A2L value rendered into a table cell — `name`, `source`, `unit`, `function_group`, `memory_region`, `raw_value`, `physical_value` — shall be rendered as a Rich `Text` (via `safe_text` or equivalent) / `markup=False`, never f-strung into markup. This sink is distinct from the detail-card builder (LLR-069.3): the table cell path (`_build_a2l_table_cells`) has its own gate-blocking hostile-input AT and is NOT covered by the card's AT-069b.
- **Symbols:** `_build_a2l_table_cells` `app.py:9090`; `safe_text` `screens_directionb.py:615`; `Text` = `rich.text.Text`.
- **Validation:** `test (pilot, hostile-input)` — a table-cell hostile fixture (`a2l_injection`) asserts literal render in the cell; gate-blocking.
- **Acceptance criteria:** a tag `name` (and any file-derived cell) containing `[red]`/`[link=…]`/ANSI/`sensor[unclosed` renders literally in `#a2l_tags_list` with no `MarkupError` (AT-069c).

### HLR-069 — A2L detail card

**LLR-069.1 — detail-card widget in hex pane**
- **Traceability:** HLR-069
- **Statement:** The system shall mount a NEW detail-card widget at the top of `#a2l_hex_pane`, with the hex view rendered below it in the same pane (vertical split, no new pane); the widget's private members shall NOT be named `_nodes` or `_context`. The card body shall be composed at the `Text` level (append/join Rich `Text` objects), OR any `Static` that receives a composed string shall set `markup=False`; a file-derived value shall NEVER be f-strung into a markup string (MN-5 / security F4).
- **Symbols:** `#a2l_hex_pane` `app.py:3954`; detail-card widget `NEW — created in Phase 3`; `safe_text` `screens_directionb.py:615`; `Text` = `rich.text.Text`.
- **Validation:** `test (pilot)` + `inspection` (member-name check `set(dir(Widget)) & {new private names} == ∅`; compose-at-`Text` / `markup=False` inspection).
- **Acceptance criteria:** card present above hex; no `_nodes`/`_context` shadowing; card composed at `Text` level or `markup=False` (no f-strung file-derived value into markup).

**LLR-069.2 — row-highlight update handler**
- **Traceability:** HLR-069
- **Statement:** When an `#a2l_tags_list` row is highlighted, a NEW `on_data_table_row_highlighted` handler shall update the detail card with the selected tag's description, unit·conversion, record layout, byte order, and limits.
- **Symbols:** NEW `on_data_table_row_highlighted` `NEW — created in Phase 3` (**no RowHighlighted handler exists today**; the existing selection handler is `on_data_table_row_selected` `app.py:6038`, RowSelected only). Mechanism choice: RowHighlighted (updates on cursor move) is specified over reusing RowSelected, for live feedback.
- **Validation:** `test (pilot)`.
- **Acceptance criteria:** highlighting a known tag renders its description/unit in the card.

**LLR-069.3 — detail-card C-17 safety**
- **Traceability:** HLR-069
- **Statement:** All detail-card fields (description, unit, conversion, display_identifier, record layout) shall render via `safe_text` / Rich `Text` / `markup=False`. The composition shall occur at the `Text` level (append/join `Text`), or any `Static` receiving a composed string shall set `markup=False`; a file-derived value shall NEVER be f-strung into a markup string (MN-5 / security F4).
- **Symbols:** `safe_text` `screens_directionb.py:615`; `Text` = `rich.text.Text`.
- **Validation:** `test (pilot, hostile-input)`.
- **Acceptance criteria:** a hostile `description` (brackets/`[link=…]`/ANSI/`sensor[unclosed`) renders literally in the card with no `MarkupError` (AT-069b).

**LLR-069.4 — card/hex vertical-split geometry (C-29)**
- **Traceability:** HLR-069
- **Statement:** The detail card plus the shrunken hex view shall both fit `#a2l_hex_pane`'s real budget at 80×24 and 120×30.
- **Geometry:** `assumed — pilot-measure BOTH axes of #a2l_hex_pane at 80×24 AND 120×30 in Phase 3`. Card height / hex-rows-remaining not asserted here.
- **Validation:** `analysis` (Phase-3 pilot).
- **Acceptance criteria:** both regions visible/reachable; hex not fully occluded at 80×24.

### HLR-070 — MAC status glyphs

**LLR-070.1 — status-glyph column + cyan addr + zebra**
- **Traceability:** HLR-070
- **Statement:** `update_mac_view` / `_populate_mac_datatable` shall render a leading colored status glyph per record — `✓` (parse-ok + in-image) / `⚠` (parse-ok + out-of-image, Orange semantics) / `✗` (parse-error) — with cyan addresses; the table already sets `zebra_stripes=True`.
- **Symbols:** `update_mac_view` `app.py:8668`; `_populate_mac_datatable` `app.py:8771`; `#mac_records_list` `app.py:4007` (`zebra_stripes=True`).
- **Validation:** `test (pilot)`.
- **Acceptance criteria:** a mixed fixture renders all three glyph classes matching status.

**LLR-070.2 — MAC name C-17 safety**
- **Traceability:** HLR-070
- **Statement:** MAC names (untrusted, file-derived) shall render via `safe_text` / Rich `Text` / `markup=False`.
- **Symbols:** `safe_text` `screens_directionb.py:615`.
- **Validation:** `test (pilot, hostile-input)`.
- **Acceptance criteria:** a hostile MAC name renders literally (AT-070b).

### HLR-071 — MAC coverage strip

**LLR-071.1 — coverage strip content**
- **Traceability:** HLR-071
- **Statement:** A NEW Static coverage strip above `#mac_records_list` shall render `MAC→S19 X of Y ▓▓▓░░ · A2L↔MAC N matches`, with `X = CoverageMetrics.mac_in_s19`, `Y = mac_total`, `N = a2l_mac_address_matches`, and the micro-bar via `insight_style.microbar`.
- **Symbols:** coverage strip Static `NEW — created in Phase 3` in `_compose_screen_mac` `app.py:3966`; `#mac_records_list` `app.py:4007`; `mac_in_s19` `validation/model.py:169`, `mac_total` `:168`, `a2l_mac_address_matches` `:173`; `mac_in_s19_pct` `:175` (0.0 when `mac_total == 0`).
- **Validation:** `test (pilot)`.
- **Acceptance criteria:** rendered `X of Y` equals the fixture's `CoverageMetrics`.

**LLR-071.2 — strip visibility gating**
- **Traceability:** HLR-071
- **Statement:** While any MAC file is loaded, the coverage strip shall be shown independent of the primary file type (superseding the current conditional pct-line render).
- **Symbols:** current conditional at `validation_service.py:287`, gate at `app.py:~8759`.
- **Validation:** `test (pilot)` — MAC-loaded → strip present; no-MAC → strip absent.
- **Acceptance criteria:** strip present whenever a MAC is loaded; absent otherwise.

### HLR-072 — Memory Map bands + ruler

**LLR-072.1 — pastel bands + hatch gaps**
- **Traceability:** HLR-072
- **Statement:** `MemoryMapPanel._build_band_widgets` shall color each strip segment by entropy band (via `band_style`) and render a `╱` hatch for unmapped gaps.
- **Symbols:** `MemoryMapPanel` `screens_directionb.py:1039`; `_build_band_widgets` `screens_directionb.py:1284`; `band_style` `entropy_style.py:69`; `╱` NEW app-supplied.
- **Validation:** `test (pilot)`.
- **Acceptance criteria:** ≥2 band styles + ≥1 `╱` for a gapped fixture.

**LLR-072.2 — humanized sizes**
- **Traceability:** HLR-072
- **Statement:** Region/size read-outs in the map shall use `insight_style.human_bytes`.
- **Symbols:** `human_bytes` (NEW, LLR-065.2).
- **Validation:** `test (pilot)` / unit.
- **Acceptance criteria:** a large region shows a humanized size (e.g. `64.0 KB`).

**LLR-072.3 — address ruler**
- **Traceability:** HLR-072
- **Statement:** A NEW ruler widget beneath the strip shall render 5 tick labels at 0/25/50/75/100 % of the address span, tick 0 % == span start and tick 100 % == span end.
- **Symbols:** ruler widget `NEW — created in Phase 3` (no ruler id exists today; `#map_grid`/`#map_detail`/`#map_body` present, `screens_directionb.py:1078`).
- **Geometry:** tick spacing `assumed — pilot-measure BOTH axes of the map strip container at 80×24 AND 120×30 in Phase 3`.
- **Validation:** `test (pilot)` for tick values; `analysis` for spacing fit.
- **Acceptance criteria:** tick 0 % / 100 % equal span endpoints; labels fit without overlap at both regimes.

**LLR-072.4 — band-bands amendment**
- **Traceability:** HLR-072
- **Statement:** This requirement shall extend the batch-45 band-bands memory-map view (R-TUI-060 / R-TUI-041) with the ruler, hatch, and humanized sizes; the extension shall be recorded in §6.5.
- **Symbols:** R-TUI-060/041 (REQUIREMENTS.md).
- **Validation:** `inspection` (§6.5 present).
- **Acceptance criteria:** §6.5 amendment block exists.

### HLR-073 — Memory Map region rows

**LLR-073.1 — size micro-bar + symbol count (range_index)**
- **Traceability:** HLR-073
- **Statement:** Each `RegionRow` shall render a size micro-bar (`microbar(region_size / largest_region)`) and an `N sym` count of A2L enriched-tag addresses within the region span, computed via `range_index` membership primitives — `build_sorted_range_index` / `address_in_sorted_ranges` / `range_in_sorted_ranges` — NOT a linear scan.
- **Symbols:** `RegionRow` `screens_directionb.py:976`; `range_index` primitives `build_sorted_range_index`/`address_in_sorted_ranges`/`range_in_sorted_ranges` (frozen `range_index.py`, read-only use); `_a2l_enriched_tags` `app.py:882`; `microbar` (NEW).
- **Validation:** `test (pilot)` — `N sym` equals an independent `range_index` count.
- **Acceptance criteria:** `N sym` matches the membership count for the region span; no linear scan in the implementation (inspection).

**LLR-073.2 — open-in-hex affordance**
- **Traceability:** HLR-073
- **Statement:** Each `RegionRow` shall render an explicit `↵` open-in-hex affordance; the activation action already exists and shall be reused.
- **Symbols:** `RegionRow.Activated` `screens_directionb.py:1009`; `MemoryMapPanel.OpenInHexRequested` `screens_directionb.py:1100`; existing `on_region_row_activated` `screens_directionb.py:1627`.
- **Validation:** `test (pilot)`.
- **Acceptance criteria:** `↵` present; activation still fires `OpenInHexRequested`.

**LLR-073.3 — region-row count geometry (C-29)**
- **Traceability:** HLR-073
- **Statement:** The number of region rows rendered shall fit the region-list container's real budget at 80×24 and 120×30.
- **Geometry:** `assumed — pilot-measure BOTH axes of the region-list container at 80×24 AND 120×30 in Phase 3`. Row count not asserted.
- **Validation:** `analysis` (Phase-3 pilot).
- **Acceptance criteria:** enriched rows render within the box; overflow reachable under scroll (not clipped).

### HLR-074 — Memory Map inspector

**LLR-074.1 — inspector content on activation**
- **Traceability:** HLR-074
- **Statement:** When `RegionRow.Activated` fires, `on_region_row_activated` shall populate `#map_detail_body` with the region's span, size, dominant band, and a hex peek, reusing the existing message/handler.
- **Symbols:** `RegionRow.Activated` `screens_directionb.py:1009`; `on_region_row_activated` `screens_directionb.py:1627`; `#map_detail_body` `screens_directionb.py:1168`; `#map_detail` `screens_directionb.py:1169`; existing `safe_text` usage `screens_directionb.py:1168`.
- **Validation:** `test (pilot)`.
- **Acceptance criteria:** activating a region row updates the inspector with span/size/band + hex.

**LLR-074.2 — 3-row hex peek at region start (C-29)**
- **Traceability:** HLR-074
- **Statement:** The inspector shall render a hex peek of up to 3 rows starting at the region's start address, using the plain hex renderer; for a region shorter than 3 rows only the available bytes shall be shown.
- **Symbols:** plain hex render (`render_hex_view` / plain renderer, `tui/hexview.py`).
- **Geometry:** the "3-row" budget is `assumed — pilot-measure the #map_detail height at 80×24 AND 120×30 in Phase 3`; reduce rows if the panel cannot fit 3.
- **Validation:** `test (pilot)` — first hex address equals region start.
- **Acceptance criteria:** first byte address == region start; ≤3 rows; no overflow of `#map_detail`.

**LLR-074.3 — inspector C-17 safety (A2L symbol names DO surface — unconditional)**
- **Traceability:** HLR-074
- **Statement:** File-derived A2L symbol names surface in the inspector via `symbols_in_window` → `symbol_list_text` → `safe_text` (the batch-43-hardened path); therefore every file-derived symbol/region value in `#map_detail_body` shall render via `safe_text` / Rich `Text` / `markup=False`. A hostile-input AT for this sink is **mandatory (not conditional)**.
- **Symbols:** `safe_text` `screens_directionb.py:615`, existing usage `:1168`; `#map_detail_body` `screens_directionb.py:1168`; `symbols_in_window` → `symbol_list_text` (batch-43 A2L-symbol region-name path).
- **Validation:** `inspection` + `test (pilot, hostile-input)` — a bracketed symbol name renders literally in `#map_detail_body`.
- **Acceptance criteria:** a `[red]`/`sensor[unclosed` symbol name renders verbatim in the inspector with no `MarkupError` (AT-074 C-17 sub-assertion, MN-4).

---

## 5. Validation strategy

> **Division of labor (per kickoff):** this document authors the acceptance (black-box) blocks, boundary catalogs, and BOTH traceability chains below. The companion `01b-qa-strategy-and-verification.md` (qa-reviewer) authors, for every `TC-NNN` and `AT-NNN`, the **executed verification** command and the **numeric pass threshold**. A `test`/`analysis` requirement is not gate-complete until its `01b` row carries both fields — that completion is tracked in `01b`, not re-derived here.

### 5.1 Methods
- **Layer A — white-box / functional (`TC-NNN`):** `test (unit)` for `insight_style` helpers + derived `LoadedFile` fields; `test (pilot)` for renderer output; `inspection` for CSS / frozen-file diffs / member-name shadowing; `analysis` for C-29 geometry measurements.
- **Layer B — black-box / behavioral acceptance (`AT-NNN`):** Textual Pilot e2e at **80×24 AND 120×30**, asserting each story's outcome through the shipped surface with representative + boundary + negative (C-17 hostile-input) evidence. `AT` ids are provisional-until-Phase-3 (V-5) and reconciled at Phase 4.
- **C-17 hostile-input ATs are mandatory** for the A2L detail card (`AT-069b` ★), A2L table cells (`AT-069c` ★, a distinct sink from the card), MAC names (`AT-070b` ★), and the Memory-Map region inspector (`AT-074` C-17 sub-assertion — A2L symbol names surface there, MN-4). Negative-control payload set: `[red]…[/red]`, `[link=http://x]u[/link]`, `\x1b[31mX\x1b[0m` (ANSI), `sensor[unclosed` (lone bracket — the `Text.from_markup` counterfactual, MD-1).
- **Geometry (C-29):** every `assumed` geometry claim (LLR-067.4, LLR-069.4, LLR-072.3, LLR-073.3, LLR-074.2) is a Phase-3 pilot measurement of BOTH axes at 80×24 and 120×30 before any row/col/tick budget is fixed.
- **Snapshots:** massive expected drift; baselines regenerated ONLY in canonical CI (`snapshot-regen.yml`, textual==8.2.8) as a follow-up PR (C-22 per-cell prediction, C-28 shared-chrome census).

### 5.2 Dual-traceability table

**Behavioral chain (black-box) — per user story:**

> One row per **canonical AT** (19 nodes, orchestrator-pinned crosswalk). C-17 gate-blocking ATs marked ★. Every AT drives the shipped screen via `App.run_test()` at **BOTH 80×24 and 120×30**. Provisional node paths (V-5), reconciled Phase 4. Executed-verification command + numeric pass threshold for each AT → `01b-qa-strategy-and-verification.md`.

| US | Canonical AT | Observable outcome (black-box) | Shipped surface | Provisional node | Observed? |
|----|--------------|--------------------------------|-----------------|------------------|-----------|
| US-FND | AT-065a | palette applied app-wide | `styles.tcss` app-wide + `insight_style` | `test_tui_theme.py::test_at065a_palette` | → 01b |
| US-FND | AT-065b | `sev-*` names + semantics preserved (round-trip) | `styles.tcss` sev-* + frozen `color_policy.py` | `test_tui_theme.py::test_at065b_sev_semantics` | → 01b |
| US-WS | AT-066a | loader-facts OOO `⚠4 OOO` (`prg.s19`) | `#ws_stats` / `update_sections` | `test_tui_workspace_insight.py::test_at066a_ooo` | → 01b |
| US-WS | AT-066b | entry PRESENT S19 `0x80000000` (`case_01`); `0x0` → `0x00000000` not `—` | `#ws_stats` | `…::test_at066b_entry_present` | → 01b |
| US-WS | AT-066c | entry ABSENT HEX `—` (inline hex builder) | `#ws_stats` | `…::test_at066c_entry_absent_hex` | → 01b |
| US-WS | AT-066d | **F-1**: S19 OOO=4 → attach MAC → stats still `⚠4 OOO` + entry preserved | MAC-merge `app.py:6954`/`:6997` → `#ws_stats` | `…::test_at066d_merge_preserves_facts` | → 01b |
| US-WS | AT-067 | memstrip ≥2 band styles + `╱` gap | `update_memory_strip` / `#ws_memstrip` | `…::test_at067_memstrip` | → 01b |
| US-A2L | AT-068 | A2L glyph `✓` AND `·` by content | `_build_a2l_table_cells` / `#a2l_tags_list` | `test_tui_a2l_detail.py::test_at068_glyph_branches` | → 01b |
| US-A2L | AT-069 | detail card on NON-default highlight | `on_data_table_row_highlighted` + detail card | `…::test_at069_card_highlight` | → 01b |
| US-A2L | AT-069b ★ | C-17 A2L card description/unit literal | detail card | `…::test_at069b_c17_card` | → 01b |
| US-A2L | AT-069c ★ | **M2**: C-17 A2L table-cell name literal | `_build_a2l_table_cells` / `#a2l_tags_list` | `…::test_at069c_c17_table_name` | → 01b |
| US-MAC | AT-070 | MAC `✓` AND `⚠` by content (`case_02`) | `update_mac_view` / `#mac_records_list` | `test_tui_mac_coverage.py::test_at070_glyph_branches` | → 01b |
| US-MAC | AT-070b ★ | C-17 MAC name literal | `#mac_records_list` | `…::test_at070b_c17_name` | → 01b |
| US-MAC | AT-070c | **M1**: MAC parse-error `✗` (+ NEW fixture) | `#mac_records_list` | `…::test_at070c_parse_error` | → 01b |
| US-MAC | AT-071 | coverage strip `1 of 2` == `CoverageMetrics` | coverage-strip Static | `…::test_at071_strip` | → 01b |
| US-MAP | AT-072a | map ≥2 band styles + `╱` hatch | `MemoryMapPanel` | `test_tui_map_big.py::test_at072a_bands` | → 01b |
| US-MAP | AT-072b | ruler exactly 5 ticks; 0 % == span start, 100 % == span end | ruler widget | `…::test_at072b_ruler` | → 01b |
| US-MAP | AT-073 | `N sym` per region == `range_index` count + `↵` | `RegionRow` render | `…::test_at073_sym_count` | → 01b |
| US-MAP | AT-074 ★ | inspector hex peek @ NON-first region start (+ MN-4 C-17 name literal) | `on_region_row_activated` / `#map_detail_body` | `…::test_at074_inspector` | → 01b |

**Functional chain (white-box) — per requirement (provisional `TC-NNN`, reconciled Phase 4):**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-065 | test (pilot) + inspection | TC-065.a, TC-065.b | theme applied; sev-* round-trip |
| LLR-065.1 | inspection | TC-065.1 | palette constants present |
| LLR-065.2 | test (unit) | TC-065.2 | `human_bytes`/`label_value`/`microbar`/`threshold_style`; returns `Text` |
| LLR-065.3 | inspection + snapshot | TC-065.3 | CSS vars app-wide |
| LLR-065.4 | test (round-trip) + inspection | TC-065.4 | `color_policy.py` 0-diff; sev-* names |
| HLR-066 | test (pilot) | TC-066 | Workspace enriched |
| LLR-066.1 | test (pilot)/snapshot | TC-066.1 | pane titles |
| LLR-066.2 | test (pilot) | TC-066.2 | section rows |
| LLR-066.3 | test (pilot)/snapshot | TC-066.3 | classed hex; constants unchanged |
| LLR-066.4 | test (pilot) | TC-066.4 | loader-facts value |
| LLR-066.5 | test (unit) + analysis | TC-066.5 | derived fields; HEX→None |
| LLR-066.6 | inspection | TC-066.6 | markup=False; no untrusted text |
| LLR-066.7 | test (pilot) | TC-066.7 | MAC-merge/reload carry OOO+entry forward (AT-066d) |
| HLR-067 | test (pilot) | TC-067 | memstrip entropy |
| LLR-067.1 | test (pilot) | TC-067.1 | banded segments |
| LLR-067.2 | test (pilot) | TC-067.2 | gap glyph |
| LLR-067.3 | test (unit) | TC-067.3 | empty-windows fallback |
| LLR-067.4 | analysis | TC-067.4 | C-29 pilot both axes |
| HLR-068 | test (pilot) | TC-068 | A2L table |
| LLR-068.1 | test (pilot) | TC-068.1 | zebra/colored/glyph |
| LLR-068.2 | test (pilot) | TC-068.2 | summary count |
| LLR-068.3 | test (pilot, hostile) | TC-068.3 | cell C-17 |
| HLR-069 | test (pilot) | TC-069 | detail card |
| LLR-069.1 | test (pilot) + inspection | TC-069.1 | card mounted; no `_nodes`/`_context` |
| LLR-069.2 | test (pilot) | TC-069.2 | RowHighlighted handler |
| LLR-069.3 | test (pilot, hostile) | TC-069.3 | card C-17 |
| LLR-069.4 | analysis | TC-069.4 | C-29 pilot both axes |
| HLR-070 | test (pilot) | TC-070 | MAC glyphs |
| LLR-070.1 | test (pilot) | TC-070.1 | status column |
| LLR-070.2 | test (pilot, hostile) | TC-070.2 | MAC name C-17 |
| HLR-071 | test (pilot) | TC-071 | coverage strip |
| LLR-071.1 | test (pilot) | TC-071.1 | X of Y == metrics |
| LLR-071.2 | test (pilot) | TC-071.2 | visibility gating |
| HLR-072 | test (pilot) | TC-072 | map bands+ruler |
| LLR-072.1 | test (pilot) | TC-072.1 | bands + hatch |
| LLR-072.2 | test (pilot)/unit | TC-072.2 | humanized sizes |
| LLR-072.3 | test (pilot) + analysis | TC-072.3 | ruler ticks + C-29 spacing |
| LLR-072.4 | inspection | TC-072.4 | §6.5 present |
| HLR-073 | test (pilot) | TC-073 | region rows |
| LLR-073.1 | test (pilot) + inspection | TC-073.1 | N sym == range_index; no linear scan |
| LLR-073.2 | test (pilot) | TC-073.2 | ↵ affordance; action reused |
| LLR-073.3 | analysis | TC-073.3 | C-29 pilot both axes |
| HLR-074 | test (pilot) | TC-074 | inspector |
| LLR-074.1 | test (pilot) | TC-074.1 | inspector content |
| LLR-074.2 | test (pilot) + analysis | TC-074.2 | hex peek @ region start; C-29 rows |
| LLR-074.3 | inspection + test (pilot, hostile) | TC-074.3 | inspector C-17 |

### 5.3 Batch acceptance criteria
- 100 % of LLRs covered by ≥1 `TC` with a pass result (thresholds in `01b`).
- Every user story has ≥1 passing `AT-NNN` observing its outcome through the shipped surface at BOTH 80×24 and 120×30, with boundary + negative (C-17) evidence.
- 0 frozen-file diffs (src AND tests) — `test_tc027` + `test_tc031` + `test_tc032` pass every increment.
- 0 blocker fails; full `pytest -q` green (baseline ~1394 pass; a timeout hang is a real bug, not the retired flake).
- Every `assumed` geometry claim replaced by a Phase-3 pilot measurement (both axes) OR the acceptance relaxed at draft-equivalent (reachable-under-scroll) before the AT is finalized.
- No `AT`/`TC` references an internal symbol in a way that breaks black-box purity for the `AT` layer.

---

## 6. Appendices

### 6.1 Extended glossary
See §1.3. Additional: **dolphie idiom** = muted label / bright value, soft pastel semantics, navy depth stack, humanized numbers, threshold coloring (`prototypes/screen_upgrades.NOTES.md`).

### 6.2 Relevant design decisions
- **Render-only, no engine change:** all data pre-computed; two new *derived* `LoadedFile` fields only, in non-frozen `load_service`.
- **RowHighlighted over RowSelected:** the A2L detail card uses a NEW `on_data_table_row_highlighted` handler (live cursor-move feedback) rather than reusing `on_data_table_row_selected` (`app.py:6038`), which fires only on explicit selection.
- **Glyph sourcing:** entropy band glyphs come from `entropy_style.band_style` (`· ░ ▒ ▓`); the `╱` gap glyph and the handoff-prose `█` are app-supplied, not from `entropy_style`.
- **sev-* restyle in CSS only:** hues may change in `styles.tcss`; the frozen `color_policy.py` map and `css_class_for_severity` round-trip are untouched.

### 6.3 Open risks
- **R1 (snapshot drift, high):** app-wide theme + per-screen enrichments drift the tc016s density matrix + shared-chrome cells. Mitigate: C-22 per-cell / C-28 shared-chrome census up front; canonical-CI regen follow-up PR.
- **R2 (C-17 injection, high):** A2L text + MAC names are new render sinks. Mitigate: mandatory hostile-input ATs + pre-code security pass.
- **R3 (geometry, medium):** memstrip width, map ruler/rows, inspector hex-peek, A2L card/hex split — all boxed-panel budgets. Mitigate: C-29 both-axes pilot measurement at 80×24 + 120×30 before fixing any budget.
- **R4 (widget-name shadowing, medium):** new widgets (A2L detail card, ruler) must not use `_nodes`/`_context`. Mitigate: `dir(Widget)` collision check (LLR-069.1).
- **R5 (reverse census, medium):** touched symbols (`_build_a2l_table_cells`, `update_sections`, `update_memory_strip`, `MemoryMapPanel`, `RegionRow`, `update_mac_view`) have interaction/snapshot tests; C-26 reverse-census each before edit.

### 6.4 Phase-2 reconciliation log

**Writer-census — all four `LoadedFile(` construction sites (MJ-1 / F-1).** The two new derived fields (`out_of_order_count`, `entry_point`, LLR-066.5) must be produced or carried at every site that builds a `LoadedFile`:

| Site | `file:line` | Role | Disposition for the two new fields |
|------|-------------|------|-------------------------------------|
| `build_loaded_s19` | `load_service.py:61` | compute (S19) | Populates both from source (`get_out_of_order_records()` len + S7/8/9 scan). Correct by construction. |
| `build_loaded_hex` | `load_service.py:94` | compute (HEX) | `out_of_order_count` computed; `entry_point = None` (type 03/05 discarded). Correct by construction. |
| `_load_mac_file` | `app.py:6791` | MAC-load | MAC carries no OOO/entry → dataclass defaults (`0`/`None`) are correct here. No change. |
| primary-reload-preserving-MAC merge | `app.py:6954` | merge | **MUST carry forward** OOO/entry from the source payload (LLR-066.7) — else defaults them, shipping AT-066d's bug. |
| `_merge_mac_with_existing_primary` | `app.py:6997` | merge | **MUST carry forward** OOO/entry from the source payload (LLR-066.7). |

**Per-decision audit table (body-first — each fold's body edit landed in §3/§4/§6.5 before this row).**

| Decision ID | What changed | Parent HLR re-read? | Body edit landed? |
|-------------|--------------|---------------------|-------------------|
| MJ-1 (F-1) | NEW LLR-066.7 (MAC-merge/reload carry OOO+entry forward) + NEW AT-066d + writer-census (above) | HLR-066 ✓ | §4 LLR-066.7 (new block) · §3 HLR-066 acceptance (AT-066d) · §5.2 behavioral row AT-066d + functional row LLR-066.7 |
| MJ-3 (M2 + sec F1) | LLR-068.1 → `tuple[Text, …]`, every file-derived A2L cell is Rich `Text`; LLR-068.3 rewritten as distinct table-cell sink; NEW AT-069c | HLR-068/069 ✓ | §4 LLR-068.1 + LLR-068.3 (rewritten) · §3 HLR-068 acceptance (AT-069c) + HLR-069 sibling note · §5.2 behavioral row AT-069c |
| MJ-2 (M1) | NEW AT-070c (parse-error → `✗`) + NEW non-frozen parse-error MAC fixture (Phase-3) | HLR-070 ✓ | §3 HLR-070 acceptance + boundary (AT-070c, NEW fixture) · §5.2 behavioral row AT-070c |
| MJ-4 (M3 + F-4) | C-18 AT split → canonical letter-suffixed set: AT-065a/b, AT-066a/b/c/d, AT-072a/b (kept AT-067/068/069/069b/069c/070/070b/070c/071/073/074) with exact node paths | HLR-065/066/072 ✓ | §3 HLR-065/066/072 acceptance (split) · §5.2 behavioral table (one row per canonical AT, 19 nodes) · §2.6 + §6.5 family pointers updated |
| MN-4 (sec F2) | LLR-074.3 made UNCONDITIONAL (A2L symbol names DO surface via `symbols_in_window`→`symbol_list_text`→`safe_text`); AT-074 gains a C-17 sub-assertion | HLR-074 ✓ | §4 LLR-074.3 (rewritten, conditional removed) · §3 HLR-074 acceptance (C-17 sub-assertion) · §5.1 mandatory-C-17 list |
| MN-5 (sec F4) | LLR-069.1/069.3 note: compose card at `Text` level (append/join) OR `Static` `markup=False`; never f-string a file-derived value into markup | HLR-069 ✓ | §4 LLR-069.1 + LLR-069.3 (compose-at-`Text` note) |
| MN-6 (F-2) | LLR-066.5: two new fields DEFAULTED after `entropy_windows` (`out_of_order_count: int = 0`, `entry_point: Optional[int] = None`); ~40 non-frozen test sites + `crc.py:1425`/`placeholders.py:67` take defaults; no frozen test file constructs `LoadedFile` → C-27 0-diff | HLR-066 ✓ | §4 LLR-066.5 (defaulted-field statement + constructor-census note) |

**AT-set split record (MJ-4).** Canonical AT count after split = **19 nodes**: AT-065a, AT-065b, AT-066a, AT-066b, AT-066c, AT-066d, AT-067, AT-068, AT-069, AT-069b ★, AT-069c ★, AT-070, AT-070b ★, AT-070c, AT-071, AT-072a, AT-072b, AT-073, AT-074 ★. Node paths per the orchestrator-pinned crosswalk (02-review §Canonical AT crosswalk), provisional-until-Phase-4 (V-5).

### 6.5 Requirement amendments (Before / After · Deleted / New)

**Amendment A — Workspace memstrip adds entropy coloring (US-WS / HLR-067)**
- **Before:** The Workspace memory strip (`update_memory_strip`, `app.py:8289`; container `#ws_memstrip`, `app.py:1409`) colors segments by valid/invalid/gap ONLY — "No entropy (D3 descoped)" (`app.py:8300`, docstring `app.py:667-668`).
- **After:** The memstrip colors each segment by its entropy band (class + glyph via `entropy_style.band_style`) reading `LoadedFile.entropy_windows`, and marks unmapped gaps with `╱`. Valid/invalid/gap coloring is retained as the no-entropy fallback (LLR-067.3).
- **Deleted / New tokens:** New — entropy band styling on `#ws_memstrip`, `╱` gap glyph. Deleted — the "D3 descoped" no-entropy limitation for this surface.
- **Parent-HLR re-read:** HLR-067 is the new parent; no prior HLR relaxed. `sev-*` semantics unaffected (bands use `band-*`, not `sev-*`).
- **Re-derived reqs:** HLR-067 · LLR-067.1–067.4 · AT-067.

**Amendment B — Memory-Map band-bands view extended with ruler + hatch + humanized sizes (US-MAP / HLR-072, amends R-TUI-060 / R-TUI-041)**
- **Before:** R-TUI-060/041 — the batch-45 band-bands Memory-Map view renders entropy bands in `MemoryMapPanel` (`_build_band_widgets`, `screens_directionb.py:1284`) without an address ruler, without a `╱` hatch for gaps, and without humanized sizes; region rows carry no size micro-bar / symbol count; the inspector (`#map_detail`) carries no hex peek.
- **After:** the view adds a `╱` hatch for unmapped gaps, an address ruler (5 ticks 0/25/50/75/100 % of span), humanized sizes, enriched region rows (size micro-bar + `N sym` via `range_index` + `↵` affordance), and a region inspector hex peek at region start.
- **Deleted / New tokens:** New — ruler widget, `╱` hatch, `N sym` count, size micro-bar, inspector hex peek. Deleted — none.
- **Parent-HLR re-read:** extends R-TUI-060/041; band-style contract and `RegionRow.Activated`/`OpenInHexRequested` messages unchanged (reused, `screens_directionb.py:1009`/`:1100`).
- **C-26 reverse-census (MN-7 — run BEFORE the map edit):** the map surfaces already carry interaction/snapshot tests that this edit will touch. Enumerate and re-run them first — in `test_tui_directionb.py`: the **`MemoryMapPanel` interaction tests (23)** and the **`RegionRow` interaction tests (9)** — plus the canonical-CI snapshot cells for the Memory-Map BIG screen. No moved/renamed leaf ids may silently drop from these (C-26 touched-symbol reverse census; census keyed on the moved leaf ids, per the batch-46 C-29/C-26 lesson).
- **Re-derived reqs:** HLR-072 (LLR-072.1–072.4) · HLR-073 (LLR-073.1–073.3) · HLR-074 (LLR-074.1–074.3) · AT-072a/072b/073/074. **Status update:** any Manual R-TUI-060/041 rows whose checks become Automated by AT-072a/072b/073/074 are promoted in REQUIREMENTS.md at Phase 6.

**Amendment C — Conditional `sev-*` hue restyle (US-FND / HLR-065, LLR-065.4)**
- **Before:** `sev-*` rules in `styles.tcss:499-515` carry their current hues.
- **After (conditional):** IF the navy/pastel palette changes any `sev-*` rule's hue, the specific Before → After hue is recorded here at the increment that makes the change; class NAMES and severity semantics (Red/Green/White/Grey + Orange MAC) are preserved regardless, and `color_policy.py` stays frozen (0-diff).
- **Deleted / New tokens:** none unless a hue changes (then: Before hex → After hex per class, filled at Phase 3).
- **Parent-HLR re-read:** HLR-065 / LLR-065.4 already mandate name+semantics preservation; this block is the placeholder the Phase-3 increment fills if hues move.
- **Re-derived reqs:** LLR-065.4 · TC-065.4 (round-trip) · AT-065a/AT-065b.

**Amendment D — `human_bytes` binary (1024) size convention (US-FND / HLR-065, LLR-065.2 — operator decision 2026-07-15, applied Inc-1)**
- **Before:** `human_bytes(n)` used the DECIMAL/SI (1000) divisor + `KB/MB/GB` units (Inc-1 first cut, matching the initial qa TC-065.1 threshold `10**9 → "1.0 GB"`).
- **After:** `human_bytes(n)` uses the BINARY (1024) divisor + `KiB/MiB/GiB/TiB/PiB` units — a `0x10000` (65536-byte) region reads `"64.0 KiB"`; byte cutoff is `< 1024`. Rationale: firmware/memory spans are powers of two, so a decimal read-out misaligns with the underlying hex ranges the analyst reads.
- **Deleted / New tokens:** Deleted — decimal-1000 divisor · `KB/MB/GB` units · the `10**9 → "1.0 GB"` threshold. New — binary-1024 divisor · `KiB/MiB/GiB/TiB/PiB` units · thresholds `1024 → "1.0 KiB"`, `0x10000 → "64.0 KiB"`, `1<<30 → "1.0 GiB"`.
- **Parent-HLR re-read:** HLR-065 is satisfied either way (it mandates humanized numbers, not a base); LLR-065.2's signature is unchanged — only the divisor/unit convention. No `sev-*` / frozen-file impact.
- **Re-derived reqs:** LLR-065.2 · TC-065.1 (threshold updated in `01b-qa-strategy-and-verification.md`). Verified green in Inc-1 (6 passed, ruff clean).
- **Provenance:** operator AskUserQuestion 2026-07-15 — "Binary (KiB/MiB, 1024)".
