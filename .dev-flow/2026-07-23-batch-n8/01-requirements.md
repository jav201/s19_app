# Requirements Document — s19_app — Batch 2026-07-23-batch-n8 (N8: comprehensive per-view Legend)

> **Artifact language:** English (project default for engineering artifacts).
> Normative keyword: `shall`. `should`/`may`/`will` are informative only and never appear inside an HLR/LLR statement.

---

## 1. Introduction

### 1.1 Purpose
Turn each rail view's in-app **Legend** modal (`LegendScreen`) from a bare colour key into a **comprehensive per-view reference**: for the active view, explain *every* informational element it shows — text fields, info tiles, numbers, table columns, glyphs and colours — via an annotated example **CARD on top**, then the real colour/entropy **key below**. Density is FULL (no cuts). This EXTENDS N1 (per-screen legend scoping, already shipped: `_SCREEN_LEGEND_SECTIONS` in `app.py:5378` + `LegendScreen(sections=…)` in `screens.py:782`).

### 1.2 Scope
**In scope** — the Legend modal for 5 rail views: Workspace, A2L Explorer, Memory Map, MAC, Issues. Each gets an annotated example card; A2L/MAC/Issues additionally keep their severity colour key; Memory Map gets the 4-band entropy key; Workspace is example-only (no colour key). Two mandatory cross-cutting fold-ins: (1) render key rows + card lines with `Static` (wraps) not `Label` (truncates); (2) MAC orange-vs-pale-yellow reconciliation block.

**Out of scope** — the Patch Editor / Diff / Checks legends (they keep the current `("Hex",)` / `("Issues",)` behaviour, no card); the Hex overlay key content; any change to the frozen severity/entropy engines; any new keybinding or button (the `k` binding / Legend buttons already open the modal — N1). The report legend (`report_service._legend_lines`) is untouched.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Card | The annotated example block rendered on top of the modal: sub-heading + rendered sample line + dim annotation, per informational element. |
| Colour key | The rows of `LEGEND_TABLE[section]` painted through `css_class_for_severity` (the `sev-*` classes). |
| Band key | The 4 entropy bands from `ENTROPY_BANDS`, painted through the `band-*` classes. Bands are an ENTROPY domain, **not** severities. |
| View key | The `_active_screen_key` string (`workspace`/`a2l`/`map`/`mac`/`issues`/…) tracked at `app.py:1444,5477`. |
| Reconciliation block | The MAC-only lines that show a warning row painted in the actual inline orange `#d9a35b` and state the C-10 "trust the glyph + Status over hue" rule. |

### 1.4 References
- `prototypes/legend_n8.kimi.NOTES.md` (pre-approved copy + density notes), `prototypes/legend_n8.INVENTORY.md` (code-grounded element catalog), `prototypes/legend_n8.kimi.prototype.py` (runnable card-on-top layout).
- N1 shipped: `.dev-flow/2026-07-20-batch-51/01-requirements.md` (AC-1..AC-3, per-screen scoping).
- C-10 (glyph-primary / colour-secondary accessibility); §6.5 Amendment F (warning rows pale yellow, orange re-scoped to MAC-specific cues) — CLAUDE.md severity conventions.

### 1.5 Document overview
§2 overall description + the 5 source user stories. §3 HLR (one per story + one cross-cutting Static-render HLR). §4 LLR decomposition. §5 dual-traceability + validation strategy. §6 appendices (design decisions, open risks, draft-time verification ledger).

---

## 2. Overall description

### 2.1 Product perspective
The Legend modal is a single `ModalScreen` (`screens.py:750 LegendScreen`) opened by `S19TuiApp.action_show_legend` (`app.py:5528`). N1 already scopes it per active screen. N8 enriches WHAT it renders: a per-view example card + the correct key type, without adding any new open path or keybinding.

### 2.2 Product functions
1. Render a per-view annotated example card explaining each informational element the active view shows.
2. Keep the real severity colour key for A2L/MAC/Issues; render the entropy band key for Memory Map; render no colour key for Workspace.
3. Render every wrapping line with `Static` so long meanings/annotations do not truncate at the viewport width.
4. On MAC, reconcile the pale-yellow (severity word) vs orange (inline table paint) conflict with an honest sample row + the C-10 rule.

### 2.3 User characteristics
Single operator (embedded-firmware analyst) using the TUI. Reads the Legend to decode a dense view. Expects the modal to explain what is on the *current* screen, and to read completely at both the 80-col floor (C-13) and the 120-col comfortable regime.

### 2.4 Constraints
- **Frozen engines — READ-only, never edited:** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`. The legend READS `color_policy.css_class_for_severity` and imports `MAC_ADDRESS_OVERLAY_STYLE` (already at `legend.py:27`); it never edits them.
- **Editable surface (this batch):** `s19_app/tui/legend.py`, `s19_app/tui/screens.py`, `s19_app/tui/app.py`, `s19_app/tui/styles.tcss`, and the test file(s). Content data lives in `legend.py`; render logic in `LegendScreen.compose`; the view-key wire-through in `action_show_legend`.
- **Geometry (C-13/C-29):** the modal `#legend_body` scrolls (`styles.tcss:1543 height:1fr; overflow-y:auto`), so the card + key may exceed one viewport; it must remain readable (wrap, not truncate) at 80×24 and 120×40.
- **Glyph-primary (C-10):** every band/status the legend teaches is carried by a distinct glyph; colour is the secondary cue.

### 2.5 Assumptions and dependencies
- **A1:** `_active_screen_key` (`app.py:1444` init `"workspace"`, set `app.py:5477`) is the authoritative view identity at the moment the Legend opens. `action_show_legend` (`app.py:5553`) already reads it. *If this were stale, the card/key would target the wrong view.* — VERIFIED on disk.
- **A2:** The Legend modal is NOT captured by the `tc016s` density snapshots — VERIFIED: grep of `tests/test_tui_snapshot.py` for `action_show_legend` / `legend_close` / a `press("k")` / `LegendScreen` returns **no matches**; the two `legend` hits (`:454`, `:859`) are the Memory-Map band-legend *screen widget* and the A2L *Legend button* footer drift, not the modal. So enriching the modal drifts no SVG baseline.
- **A3:** `Static` wraps and `Label` truncates at viewport width (textual 8.2.8) — prototype-verified empirically (`legend_n8.kimi.NOTES.md` §"Second found gotcha"). `Static` is already imported in `screens.py:24`.
- **A4:** `legend.py` importing `entropy_service.ENTROPY_BANDS` + `entropy_style.band_style` introduces no import cycle — VERIFIED: grep of `entropy_service.py` for `legend` returns no matches; the prototype (`legend_n8.kimi.prototype.py:57-60`) imports all four modules together and runs.

---

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-N8-1 | As the operator, I want the Workspace Legend to explain every element the Workspace shows (memory strip, loaded panel, data sections, hex view, coverage/context stats, status bar) via an annotated example, so that I can decode the busiest screen without a colour key it doesn't use. | N8 backlog / `legend_n8.INVENTORY.md` §Workspace | READY |
| US-N8-2 | As the operator, I want the A2L Explorer Legend to explain the 16 columns, the summary/filter rows and the detail card, plus the Red/Green/White/Grey row-colour key, so that I can read any A2L row and know why it is coloured. | N8 backlog / `legend_n8.INVENTORY.md` §A2L | READY |
| US-N8-3 | As the operator, I want the Memory Map Legend to explain the band bar, region rows, at-a-glance histogram/sparkline and inspector, plus the 4-band entropy key (with the "bands ≠ severities" note), so that I don't misread an entropy band as a validity severity. | N8 backlog / `legend_n8.INVENTORY.md` §Memory Map | READY |
| US-N8-4 | As the operator, I want the MAC Legend to explain the coverage strip, the 8 columns and the status glyphs, plus the colour key AND a reconciliation that shows warning rows actually paint orange in the table, so that I trust the glyph + Status column when the hue disagrees with the key word. | N8 backlog / `legend_n8.INVENTORY.md` §MAC | READY |
| US-N8-5 | As the operator, I want the Issues Legend to explain the severity strip, filter row, grouped list, code families and summary/hex-peek, plus the Errors/Warnings/Optional-info key, so that I can interpret any issue row and its severity. | N8 backlog / `legend_n8.INVENTORY.md` §Issues | READY |

#### Refinement log

**US-N8-1 — Workspace comprehensive legend (example-only)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = operator on `#screen_workspace` · outcome = opening the Legend shows an annotated card for every Workspace element · why = the Workspace is the densest view and today (`workspace` absent from `_SCREEN_LEGEND_SECTIONS:5378`) its Legend falls through to the FULL severity table — content that doesn't match the screen · out of scope = any colour key on this view (Workspace shows no severity-coloured rows).
- **Feasibility:** path = add `LEGEND_EXAMPLES["workspace"]` (legend.py, NEW) + `_SCREEN_LEGEND_SECTIONS["workspace"] = ()` (app.py) so the severity loop renders nothing + render the card in `LegendScreen.compose` · deps = the view-key wire-through (shared with all stories) · one batch = yes.
- **Evaluability (black-box):** "When the operator opens the Legend on Workspace, they observe the Workspace card elements (e.g. `Memory strip`, `Coverage`) AND observe NO A2L/MAC/Issues severity rows." → AT-N8-01.
- **Classification:** READY.

**US-N8-2 — A2L Explorer comprehensive legend**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = operator on `#screen_a2l` · outcome = card explaining the 16 columns + summary/filter/detail, above the existing A2L Red/Green/White/Grey key · out of scope = adding fields beyond the shipped columns.
- **Feasibility:** path = `LEGEND_EXAMPLES["a2l"]` + keep `sections=("A2L",)` key (already mapped `app.py:5379`) · one batch = yes.
- **Evaluability:** "When opened on A2L, the operator observes a column-gloss card element AND the four A2L key rows (Red/Green/White/Grey)." → AT-N8-02.
- **Classification:** READY.

**US-N8-3 — Memory Map comprehensive legend (band key)**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = operator on `#screen_map` · outcome = card explaining band bar/region rows/at-a-glance/inspector + the 4-band entropy key + the "bands ≠ severities" note · out of scope = the Hex overlay severity rows (see §6.3 open risk R-1).
- **Feasibility:** path = `LEGEND_EXAMPLES["map"]` + a band-key path in compose built from `ENTROPY_BANDS` (entropy_service.py:41) via `band_style` (entropy_style.py:69) + change `_SCREEN_LEGEND_SECTIONS["map"]` from `("Hex",)` to `()` so the band key (not the Hex severity rows) is the map key · one batch = yes.
- **Evaluability:** "When opened on Map, the operator observes a band-bar/region-row card element AND the four band rows (constant/padding, low, medium, high/random) + the gap-hatch row + the 'bands ≠ severities' note, and observes NO A2L severity rows." → AT-N8-03.
- **Classification:** READY.

**US-N8-4 — MAC comprehensive legend + reconciliation**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = operator on `#screen_mac` · outcome = card (coverage strip, 8 columns, status glyphs, status vocab) + the MAC key + a reconciliation block that shows a warning row painted in the actual inline orange `#d9a35b` and states "trust the glyph (✗⚠✓·) and Status column over hue" (C-10) · out of scope = changing the MAC table's inline paint (frozen `tui/mac.py`).
- **Feasibility:** path = `LEGEND_EXAMPLES["mac"]` + keep `sections=("MAC",)` (`app.py:5380`) + a reconciliation block (legend.py data, rendered after the key) · one batch = yes.
- **Evaluability:** "When opened on MAC, the operator observes the 8-column/status-glyph card AND the MAC key rows AND a reconciliation line naming the orange table paint + the trust-the-glyph rule." → AT-N8-04 (card + key), AT-N8-07 (reconciliation).
- **Classification:** READY.

**US-N8-5 — Issues comprehensive legend**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality:** user = operator on `#screen_issues` · outcome = card (severity strip, filter, grouped list, code families, summary + hex peek) + the Errors/Warnings/Optional-info key · out of scope = the full 17-code census as normative content (it lives in REQUIREMENTS.md; the card names the families).
- **Feasibility:** path = `LEGEND_EXAMPLES["issues"]` + keep `sections=("Issues",)` (`app.py:5381`) · one batch = yes.
- **Evaluability:** "When opened on Issues, the operator observes a code-family / severity-strip card element AND the three Issues key rows (Errors/Warnings/Optional info)." → AT-N8-05.
- **Classification:** READY.

> The Static-wrap fold-in (mandatory fold-in #1) is a cross-cutting mechanism serving all 5 stories; it is captured as HLR-N8-6 with its own AT-N8-06, and traces to every US.

---

## 3. High-level requirements (HLR)

### HLR-N8-1 — Workspace comprehensive legend (example-only)
- **Traceability:** US-N8-1
- **Statement:** When the operator opens the Legend while the active screen is `workspace`, the system shall render an annotated example card explaining each Workspace informational element (memory strip, loaded panel, data sections, hex view, context/coverage stats, status bar) and shall render no severity colour-key rows.
- **Rationale (informative):** Today `workspace` is absent from `_SCREEN_LEGEND_SECTIONS` (`app.py:5378`), so `.get()` returns `None` and the modal falls back to the FULL severity table (`screens.py:797`) — content that doesn't match the screen. The Workspace shows no severity-coloured rows, so it needs an example, not a key.
- **Validation:** test (pilot)
- **Executed verification:** `pytest tests/test_legend_n8.py -t AT-N8-01` (node id provisional-until-Phase-3, V-5)
- **Numeric pass threshold:** AT-N8-01 passes; 0 regressions in the pre-existing legend suite (`tests/test_tui_legend.py`).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** The Legend opened on Workspace shows Workspace card elements and no foreign severity rows.
  - **Shipped surface:** `LegendScreen` pushed by `S19TuiApp.action_show_legend` (`app.py:5528`) while `_active_screen_key == "workspace"`.
  - **Deliverable + observation:** rendered modal element — via Textual Pilot: set the workspace screen active, invoke `action_show_legend`, read the rendered text of `#legend_body`; assert it CONTAINS a Workspace card label + annotation (e.g. `Memory strip` and `Coverage`) and DOES NOT CONTAIN the A2L row text `schema/structural failure`.
  - **Acceptance test(s):** AT-N8-01
  - **Boundary catalog (QC-3):** ☑ empty (no file loaded — the card still renders; card is static content, AT loads no file) · ☑ boundary (the "no colour key" closing note is present — proves example-only) · ☑ invalid (N/A — legend takes no user input; reason: read-only modal) · ☑ error (negative assertion: foreign severity rows absent).

### HLR-N8-2 — A2L Explorer comprehensive legend
- **Traceability:** US-N8-2
- **Statement:** When the operator opens the Legend while the active screen is `a2l`, the system shall render an annotated example card explaining the 16 A2L Explorer columns, the summary line, the filter row and the detail card, above the existing A2L colour key (Red/Green/White/Grey).
- **Rationale (informative):** The A2L view is 16 columns wide; the four-row colour key alone under-explains it.
- **Validation:** test (pilot)
- **Executed verification:** `pytest tests/test_legend_n8.py -t AT-N8-02`
- **Numeric pass threshold:** AT-N8-02 passes; the four A2L key rows present.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** Legend on A2L shows a column-gloss card + the four A2L key rows.
  - **Shipped surface:** `LegendScreen(sections=("A2L",))` via `action_show_legend` (`app.py:5553`, mapping `app.py:5379`).
  - **Deliverable + observation:** rendered `#legend_body` text CONTAINS an A2L card element (e.g. `Explorer columns` / `Address`) AND the key rows `memory checked` (Green) and `schema/structural failure` (Red).
  - **Acceptance test(s):** AT-N8-02
  - **Boundary catalog (QC-3):** ☑ empty (N/A — static card) · ☑ boundary (all four key rows present, ordered as `LEGEND_TABLE["A2L"]`) · ☑ invalid (N/A) · ☑ error (N/A — reason: no input).

### HLR-N8-3 — Memory Map comprehensive legend (entropy band key)
- **Traceability:** US-N8-3
- **Statement:** When the operator opens the Legend while the active screen is `map`, the system shall render an annotated example card explaining the band bar, region rows, the at-a-glance histogram/sparkline and the inspector, and shall render the four entropy band rows (constant/padding, low, medium, high/random) plus a gap-hatch row and a closing note stating that bands are an entropy domain distinct from severities.
- **Rationale (informative):** The Memory Map is an entropy view, not a validity map; rendering the `sev-*` severity key there would teach the wrong domain. The band key uses the `band-*` classes (`styles.tcss:665-679`).
- **Validation:** test (pilot)
- **Executed verification:** `pytest tests/test_legend_n8.py -t AT-N8-03`
- **Numeric pass threshold:** AT-N8-03 passes; 4 band rows + gap row + "bands ≠ severities" note present; no A2L severity row present.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** Legend on Map shows a band-bar/region card + the 4 band rows + the domain-separation note, and no severity rows.
  - **Shipped surface:** `LegendScreen` via `action_show_legend` while `_active_screen_key == "map"`; band-key path in `compose`.
  - **Deliverable + observation:** rendered `#legend_body` text CONTAINS a Map card element (e.g. `band bar` / `region`) AND all four band meanings (`padding / fill`, `structured / tables`, `calibration / data`, `code / compressed / random`) AND the substring `not` in a "bands ≠ severities" note; and DOES NOT CONTAIN `schema/structural failure`.
  - **Acceptance test(s):** AT-N8-03
  - **Boundary catalog (QC-3):** ☑ empty (N/A — static card) · ☑ boundary (all 4 bands + gap-hatch row present) · ☑ invalid (N/A) · ☑ error (negative: A2L severity rows absent — proves the map renders bands not the Hex/severity key).

### HLR-N8-4 — MAC comprehensive legend + orange/pale-yellow reconciliation
- **Traceability:** US-N8-4
- **Statement:** When the operator opens the Legend while the active screen is `mac`, the system shall render an annotated example card explaining the coverage strip, the 8 MAC columns and the status glyphs, above the existing MAC colour key, and shall render a reconciliation block that (a) shows a sample warning row painted in the actual inline MAC orange `#d9a35b` and (b) states the rule that the glyph (`✗ ⚠ ✓ ·`) and the Status column are authoritative over hue.
- **Rationale (informative):** The colour key names the SEVERITY word "Pale yellow" (`.sev-warning #f6ff8f`), but the MAC DataTable paints warning rows with an INLINE orange (`orange3 ≈ #d9a35b`, `styles.tcss:657 .mac_out_of_range`). Without reconciliation the key contradicts the screen. C-10: the glyph and Status vocabulary are identical in both pipelines and are the reliable signal.
- **Validation:** test (pilot)
- **Executed verification:** `pytest tests/test_legend_n8.py -t AT-N8-04 -t AT-N8-07`
- **Numeric pass threshold:** AT-N8-04 (card + key) and AT-N8-07 (reconciliation) both pass.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** Legend on MAC shows the MAC card + key + a reconciliation block naming the orange table paint and the trust-the-glyph rule.
  - **Shipped surface:** `LegendScreen(sections=("MAC",))` via `action_show_legend` (`app.py:5380`); reconciliation block rendered after the key.
  - **Deliverable + observation:** rendered `#legend_body` text CONTAINS a MAC card element (e.g. `Status` / `8 columns` / a status-glyph line) AND the MAC key rows (`exact name + address match`, warning row text) AND a reconciliation line containing both `orange` and a trust-the-glyph phrase (e.g. `Status`/`glyph` + `hue`).
  - **Acceptance test(s):** AT-N8-04, AT-N8-07
  - **Boundary catalog (QC-3):** ☑ empty (N/A — static card) · ☑ boundary (all five MAC key rows present) · ☑ invalid (N/A) · ☑ error (the reconciliation asserts the contradictory-hue case is explained, not silently wrong).

### HLR-N8-5 — Issues comprehensive legend
- **Traceability:** US-N8-5
- **Statement:** When the operator opens the Legend while the active screen is `issues`, the system shall render an annotated example card explaining the severity strip, the filter row, the grouped list, the issue-code families and the summary/hex-peek, above the existing Issues colour key (Errors/Warnings/Optional info).
- **Rationale (informative):** The Issues view groups 17 codes across 3 severities; the card names the families and the strip so a row can be interpreted.
- **Validation:** test (pilot)
- **Executed verification:** `pytest tests/test_legend_n8.py -t AT-N8-05`
- **Numeric pass threshold:** AT-N8-05 passes; the three Issues key rows present.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** Legend on Issues shows a code-family/severity-strip card + the three Issues key rows.
  - **Shipped surface:** `LegendScreen(sections=("Issues",))` via `action_show_legend` (`app.py:5381`).
  - **Deliverable + observation:** rendered `#legend_body` text CONTAINS an Issues card element (e.g. `families` / `Severity strip` / `Hex Peek`) AND the key rows `Errors` and `Optional info`.
  - **Acceptance test(s):** AT-N8-05
  - **Boundary catalog (QC-3):** ☑ empty (N/A — static card) · ☑ boundary (all three severity key rows present) · ☑ invalid (N/A) · ☑ error (N/A — reason: no input).

### HLR-N8-6 — Non-truncating render (Static wraps; long meanings keep their tail)
- **Traceability:** US-N8-1, US-N8-2, US-N8-3, US-N8-4, US-N8-5 (cross-cutting; mandatory fold-in #1)
- **Statement:** The system shall render the Legend's colour-/band-key rows and every card line with a widget that wraps at the viewport width (`Static`), such that a long key meaning presents its full text (including its tail) in the rendered output at the 120-column regime.
- **Rationale (informative):** `LegendScreen.compose` currently uses `Label` (`screens.py:795,799,809`), which truncates at viewport width; the Issues "Errors" meaning (148 chars, `legend.py:160-165`) loses its tail `same-name mismatch` at ~120 cols. `Static` wraps (A3).
- **Validation:** test (pilot)
- **Executed verification:** `pytest tests/test_legend_n8.py -t AT-N8-06`
- **Numeric pass threshold:** AT-N8-06 passes — the tail token `same-name mismatch` is present in the rendered `#legend_body` text at size 120×40.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** A long key meaning's tail is visible (not truncated) in the rendered Legend.
  - **Shipped surface:** `LegendScreen.compose` rows rendered via `Static`; opened on Issues at 120×40.
  - **Deliverable + observation:** rendered `#legend_body` text CONTAINS the substring `same-name mismatch` (the tail of the Issues "Errors" meaning). A `Label`-rendered baseline would truncate it — the AT is a genuine regression guard.
  - **Acceptance test(s):** AT-N8-06
  - **Boundary catalog (QC-3):** ☑ empty (N/A) · ☑ boundary (the single longest meaning, 148 chars) · ☑ invalid (N/A) · ☑ error (negative: assert the tail is NOT lost — the test would fail against the current `Label` implementation).

---

## 4. Low-level requirements (LLR)

> **Draft-time symbol status.** `LEGEND_EXAMPLES`, the band-key data/helper, the `view_key` param, the `_SCREEN_LEGEND_SECTIONS["workspace"]` entry, and the new `styles.tcss` card classes are **NEW — created in Phase 3**. All cited existing symbols carry a grep-verified `file:line`. Executed-verification file paths, `-k` selectors and node ids are **provisional-until-Phase-3 (V-5)**.

### LLR-N8-1.1 — LEGEND_EXAMPLES workspace card data
- **Traceability:** HLR-N8-1
- **Statement:** `legend.py` shall define `LEGEND_EXAMPLES` (a mapping keyed by view key) **[NEW — created in Phase 3]** whose `"workspace"` entry carries ordered card lines (sub-heading / sample / annotation triples) covering the memory strip, loaded panel, data sections, hex view, context/coverage stats and status bar, mirroring `prototypes/legend_n8.INVENTORY.md` §Workspace and `legend_n8.kimi.NOTES.md` §1 at FULL density.
- **Validation:** test (unit) — Executed verification: `pytest tests/test_legend_n8.py -k workspace_example_data` · Numeric pass threshold: the `"workspace"` entry exists and its concatenated text contains `Memory strip`, `Loaded panel`, `Data Sections`, `Hex view`, `Coverage`, `Status bar` (6/6).
- **Acceptance criteria:** the data is a pure module constant (no widget import in `legend.py`); markup-bearing lines use Rich markup with literal brackets escaped.

### LLR-N8-1.2 — Workspace mapped to an empty section set (example-only)
- **Traceability:** HLR-N8-1
- **Statement:** `_SCREEN_LEGEND_SECTIONS` (`app.py:5378`) shall gain `"workspace": ()` **[NEW entry]** so `action_show_legend` (`app.py:5553`) passes `sections=()` for Workspace, and the `LegendScreen.compose` severity loop (`screens.py:796-810`) renders zero severity rows for Workspace (every artifact filtered by `artifact not in ()` at `screens.py:797`).
- **Validation:** test (unit) — Executed verification: `pytest tests/test_legend_n8.py -k workspace_no_severity_rows` · Numeric pass threshold: rendered Workspace legend text contains 0 of the strings `schema/structural failure`, `memory checked` (0/2).
- **Acceptance criteria:** the empty tuple (not `None`) is passed — `None` would re-trigger the full-table fallback the current bug exhibits.

### LLR-N8-1.3 — compose renders the workspace card + closing note
- **Traceability:** HLR-N8-1
- **Statement:** `LegendScreen.compose` shall, when its view key is `"workspace"`, render the `LEGEND_EXAMPLES["workspace"]` card at the top of `#legend_body` (`styles.tcss:1543`) followed by a closing note stating this view has no severity colour key.
- **Validation:** test (pilot) — Executed verification: `pytest tests/test_legend_n8.py -t AT-N8-01` · Numeric pass threshold: card element + closing note present, foreign severity rows absent (AT-N8-01).
- **Acceptance criteria:** the card precedes any key content in DOM order.

### LLR-N8-1.4 — view_key wire-through (shared enabler)
- **Traceability:** HLR-N8-1 (shared by HLR-N8-2..6)
- **Statement:** `LegendScreen.__init__` (`screens.py:782`) shall accept an optional `view_key: Optional[str]` param **[NEW]** and `S19TuiApp.action_show_legend` (`app.py:5528`) shall pass `view_key=self._active_screen_key` (`app.py:5477`) in addition to the existing `sections=` argument, so `compose` can select the per-view card and key type.
- **Validation:** test (unit) — Executed verification: `pytest tests/test_legend_n8.py -k view_key_passed` · Numeric pass threshold: constructing `LegendScreen(view_key="mac")` renders the MAC card; default `view_key=None` renders the N1/batch-51 behaviour (no card) — 2/2.
- **Acceptance criteria:** `view_key=None` preserves the exact pre-N8 render (backward-compatible with existing `tests/test_tui_legend.py`).

### LLR-N8-2.1 — LEGEND_EXAMPLES a2l card data
- **Traceability:** HLR-N8-2
- **Statement:** `LEGEND_EXAMPLES["a2l"]` **[NEW]** shall carry card lines covering the 16 Explorer columns (in two halves), the summary line, the filter row and the detail card, mirroring `legend_n8.INVENTORY.md` §A2L / `NOTES.md` §2.
- **Validation:** test (unit) — Executed verification: `pytest tests/test_legend_n8.py -k a2l_example_data` · Numeric pass threshold: concatenated `"a2l"` text contains `Explorer columns`, `Address`, `InMem`, `Summary`, `Filter`, `Detail card` (6/6).
- **Acceptance criteria:** column names match the shipped A2L table (INVENTORY §A2L is the oracle).

### LLR-N8-2.2 — a2l card above the existing A2L key
- **Traceability:** HLR-N8-2
- **Statement:** `compose` shall render the `"a2l"` card above the `LEGEND_TABLE["A2L"]` colour key (`legend.py:114-133`), painted through `css_class_for_severity` exactly as today (`screens.py:800-809`), for `sections=("A2L",)` (`app.py:5379`).
- **Validation:** test (pilot) — Executed verification: `pytest tests/test_legend_n8.py -t AT-N8-02` · Numeric pass threshold: card element + 4 A2L key rows present (AT-N8-02).
- **Acceptance criteria:** the four A2L rows keep their `sev-error`/`sev-ok`/(none)/`sev-neutral` classes.

### LLR-N8-3.1 — LEGEND_EXAMPLES map card data
- **Traceability:** HLR-N8-3
- **Statement:** `LEGEND_EXAMPLES["map"]` **[NEW]** shall carry card lines covering the header + band bar, region rows, at-a-glance histogram/sparkline and coverage/inspector, mirroring `legend_n8.INVENTORY.md` §Memory Map / `NOTES.md` §3.
- **Validation:** test (unit) — Executed verification: `pytest tests/test_legend_n8.py -k map_example_data` · Numeric pass threshold: concatenated `"map"` text contains `band bar`, `region`, `At a glance`, `inspector` (4/4).
- **Acceptance criteria:** the card band-bar sample uses the band glyphs `·░▒▓` and the gap glyph `╱`.

### LLR-N8-3.2 — entropy band key rendered for the map view
- **Traceability:** HLR-N8-3
- **Statement:** For view key `"map"`, `compose` shall render a band key built from `ENTROPY_BANDS` (`entropy_service.py:41-46`) via `band_style` (`entropy_style.py:69`) — one row per band painted with its `band-*` class (`styles.tcss:665-679`), each showing glyph + label + `[lo,hi)` range + meaning — plus a gap-hatch row (no colour class) and a closing note stating bands are an entropy domain distinct from the `sev-*` severity domain.
- **Validation:** test (unit + pilot) — Executed verification: `pytest tests/test_legend_n8.py -k map_band_key` and `-t AT-N8-03` · Numeric pass threshold: 4 band meanings (`padding / fill`, `structured / tables`, `calibration / data`, `code / compressed / random`) + gap row + domain note present; the band data is DERIVED from `ENTROPY_BANDS` (not hardcoded) so an upstream band change flows through (assert row count == `len(ENTROPY_BANDS)` == 4).
- **Acceptance criteria:** band rows carry `band-*` classes, never `sev-*`; the "high/random" upper bound displays as `8` (matching NOTES.md §3, though `ENTROPY_BANDS` stores `8.000001`).

### LLR-N8-3.3 — map section changed from Hex to empty (band key replaces severity key)
- **Traceability:** HLR-N8-3
- **Statement:** `_SCREEN_LEGEND_SECTIONS["map"]` shall change from `("Hex",)` (`app.py:5382`) to `()` so the Memory-Map legend renders the band key (LLR-N8-3.2) rather than the `LEGEND_TABLE["Hex"]` severity/overlay rows; `"patch"` and `"diff"` (`app.py:5383-5384`) shall remain `("Hex",)` (out of N8 scope).
- **Validation:** inspection — file/section: `app.py:5378-5386` · observable condition: `map` value is `()`, `patch`/`diff` values unchanged at `("Hex",)`.
- **Acceptance criteria:** see §6.3 R-1 — this removes the Hex overlay legend from the Map view; confirmed against the pre-approved prototype (Map shows the band key). Open question flagged to the orchestrator.

### LLR-N8-4.1 — LEGEND_EXAMPLES mac card data
- **Traceability:** HLR-N8-4
- **Statement:** `LEGEND_EXAMPLES["mac"]` **[NEW]** shall carry card lines covering the coverage strip, the 8 columns, the tag status glyphs (`✗ ⚠ ✓ ·`) and the status→row-colour vocabulary, mirroring `legend_n8.INVENTORY.md` §MAC / `NOTES.md` §4.
- **Validation:** test (unit) — Executed verification: `pytest tests/test_legend_n8.py -k mac_example_data` · Numeric pass threshold: concatenated `"mac"` text contains `Coverage strip`, `8 columns`, `status glyph`, `Status`, and all four glyphs `✗`,`⚠`,`✓`,`·` (glyphs 4/4).
- **Acceptance criteria:** glyphs match the shipped MAC glyph set (INVENTORY §MAC is the oracle).

### LLR-N8-4.2 — mac card above the existing MAC key
- **Traceability:** HLR-N8-4
- **Statement:** `compose` shall render the `"mac"` card above the `LEGEND_TABLE["MAC"]` colour key (`legend.py:134-158`) for `sections=("MAC",)` (`app.py:5380`).
- **Validation:** test (pilot) — Executed verification: `pytest tests/test_legend_n8.py -t AT-N8-04` · Numeric pass threshold: card element + 5 MAC key rows present (AT-N8-04).
- **Acceptance criteria:** the five MAC rows keep their existing classes; "Pale yellow" row painted `sev-warning`.

### LLR-N8-4.3 — MAC reconciliation block (mandatory fold-in #2)
- **Traceability:** HLR-N8-4
- **Statement:** For view key `"mac"`, `compose` shall render, after the MAC key, a reconciliation block that (a) renders a sample warning row using the actual inline MAC orange `#d9a35b` (the hue of `styles.tcss:657 .mac_out_of_range` / frozen `MAC_ADDRESS_OVERLAY_STYLE` imported at `legend.py:27`), and (b) states that the key names the SEVERITY (`.sev-warning #f6ff8f`) while the MAC table paints warning rows orange, and that the operator shall trust the glyph (`✗ ⚠ ✓ ·`) and the Status column over hue (C-10).
- **Validation:** test (pilot) — Executed verification: `pytest tests/test_legend_n8.py -t AT-N8-07` · Numeric pass threshold: rendered text contains `orange` AND a trust-the-glyph phrase (both `Status`/`glyph` and `hue`) — 2/2.
- **Acceptance criteria:** the orange sample is inline Rich markup (`#d9a35b`), NOT a `sev-*`/`band-*` class — it is an interaction cue, not a severity.

### LLR-N8-5.1 — LEGEND_EXAMPLES issues card data
- **Traceability:** HLR-N8-5
- **Statement:** `LEGEND_EXAMPLES["issues"]` **[NEW]** shall carry card lines covering the severity strip, the filter row, the grouped list, the issue-code families (MAC_* / A2L_* / CROSS_* / TRIPLE_*) and the summary + hex peek, mirroring `legend_n8.INVENTORY.md` §Issues / `NOTES.md` §5.
- **Validation:** test (unit) — Executed verification: `pytest tests/test_legend_n8.py -k issues_example_data` · Numeric pass threshold: concatenated `"issues"` text contains `Severity strip`, `Grouped list`, `families`, `Hex Peek` (4/4).
- **Acceptance criteria:** the card names the families, not the full 17-code census (census stays in REQUIREMENTS.md).

### LLR-N8-5.2 — issues card above the existing Issues key
- **Traceability:** HLR-N8-5
- **Statement:** `compose` shall render the `"issues"` card above the `LEGEND_TABLE["Issues"]` colour key (`legend.py:159-176`) for `sections=("Issues",)` (`app.py:5381`).
- **Validation:** test (pilot) — Executed verification: `pytest tests/test_legend_n8.py -t AT-N8-05` · Numeric pass threshold: card element + 3 Issues key rows present (AT-N8-05).
- **Acceptance criteria:** Errors=`sev-error`, Warnings=`sev-warning`, Optional info=`sev-info`.

### LLR-N8-6.1 — key rows + card lines rendered with Static (wrap, not truncate)
- **Traceability:** HLR-N8-6
- **Statement:** `LegendScreen.compose` shall render all wrapping content — the colour-/band-key rows (currently `Label` at `screens.py:809`) and the card lines — with `Static` (imported `screens.py:24`) rather than `Label`, so text wraps at the viewport width instead of truncating. The `legend-artifact` sub-heading (`screens.py:799`, short fixed strings) may remain `Label`.
- **Validation:** test (pilot) — Executed verification: `pytest tests/test_legend_n8.py -t AT-N8-06` · Numeric pass threshold: at 120×40 the rendered `#legend_body` contains `same-name mismatch` (the tail of the 148-char Issues "Errors" meaning, `legend.py:160-165`) — 1/1; the same assertion FAILS against a `Label`-rendered control.
- **Acceptance criteria:** rows keep their `legend-row {sev_class}` / `band-*` classes; only the widget type changes.

### LLR-N8-6.2 — new card CSS classes carry no colour of their own
- **Traceability:** HLR-N8-6
- **Statement:** `styles.tcss` shall gain card presentation classes **[NEW]** (e.g. a sub-heading class and a dim-annotation class) for the example-card lines; these classes shall carry only weight/dim/layout, never a `sev-*` or `band-*` colour, so the card cannot be mistaken for a colour-key row.
- **Validation:** inspection — file/section: the new `styles.tcss` legend-card block · observable condition: no `color:` referencing a severity/band hex; the card classes are disjoint from `.sev-*` (`:628-646`) and `.band-*` (`:665-679`).
- **Acceptance criteria:** `.legend-row` (class-only, no dedicated tcss rule today — verified: no `.legend-row` rule in `styles.tcss`) is unchanged.

---

## 5. Validation strategy

### 5.1 Methods
- **Layer A (white-box, `TC-NNN`):** `test (unit)` on the `LEGEND_EXAMPLES` data + band-key derivation + `_SCREEN_LEGEND_SECTIONS` mapping; `inspection` on the `styles.tcss` card block and the map/patch section values.
- **Layer B (black-box, `AT-NNN`):** Textual Pilot (`App.run_test(size=…)`) drives `action_show_legend` per active screen and asserts the rendered `#legend_body` text — representative + boundary + negative evidence. This is the `test (pilot)` idiom, not `demo`. Note (A2): the modal is not covered by the `tc016s` density snapshots, so the ATs are the sole automated observation of the enriched modal.

### 5.2 Dual-traceability table

**Behavioral chain (black-box) — per user story:**

| US | Observable outcome | Shipped surface | Acceptance test | Observed? |
|----|--------------------|-----------------|-----------------|-----------|
| US-N8-1 | Workspace card + no severity key | `LegendScreen` (view_key=workspace) | AT-N8-01 | pilot text of `#legend_body` |
| US-N8-2 | A2L card + Red/Green/White/Grey key | `LegendScreen(sections=("A2L",))` | AT-N8-02 | pilot text |
| US-N8-3 | Map card + 4-band key + "bands ≠ sev" note | `LegendScreen` (view_key=map) | AT-N8-03 | pilot text |
| US-N8-4 | MAC card + key + reconciliation | `LegendScreen(sections=("MAC",))` | AT-N8-04, AT-N8-07 | pilot text |
| US-N8-5 | Issues card + 3-severity key | `LegendScreen(sections=("Issues",))` | AT-N8-05 | pilot text |
| US-N8-1..5 | long key meaning tail not truncated | `LegendScreen.compose` via `Static` | AT-N8-06 | pilot text @120×40 |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case | Notes |
|-------------|--------|-----------|-------|
| HLR-N8-1 | test (pilot) | AT-N8-01 | + TC via LLR-N8-1.* |
| LLR-N8-1.1 | test (unit) | TC-N8-01 | workspace example data |
| LLR-N8-1.2 | test (unit) | TC-N8-02 | empty-section, no severity rows |
| LLR-N8-1.3 | test (pilot) | AT-N8-01 | card + closing note |
| LLR-N8-1.4 | test (unit) | TC-N8-03 | view_key wire-through + None back-compat |
| HLR-N8-2 | test (pilot) | AT-N8-02 | |
| LLR-N8-2.1 | test (unit) | TC-N8-04 | a2l example data |
| LLR-N8-2.2 | test (pilot) | AT-N8-02 | card above key |
| HLR-N8-3 | test (pilot) | AT-N8-03 | |
| LLR-N8-3.1 | test (unit) | TC-N8-05 | map example data |
| LLR-N8-3.2 | test (unit)+pilot | TC-N8-06, AT-N8-03 | band key derived from ENTROPY_BANDS |
| LLR-N8-3.3 | inspection | TC-N8-07 | map=() ; patch/diff unchanged |
| HLR-N8-4 | test (pilot) | AT-N8-04, AT-N8-07 | |
| LLR-N8-4.1 | test (unit) | TC-N8-08 | mac example data + glyphs |
| LLR-N8-4.2 | test (pilot) | AT-N8-04 | card above key |
| LLR-N8-4.3 | test (pilot) | AT-N8-07 | reconciliation block |
| HLR-N8-5 | test (pilot) | AT-N8-05 | |
| LLR-N8-5.1 | test (unit) | TC-N8-09 | issues example data |
| LLR-N8-5.2 | test (pilot) | AT-N8-05 | card above key |
| HLR-N8-6 | test (pilot) | AT-N8-06 | Static wrap |
| LLR-N8-6.1 | test (pilot) | AT-N8-06 | tail present @120×40 |
| LLR-N8-6.2 | inspection | TC-N8-10 | card classes carry no sev/band colour |

### 5.3 Batch acceptance criteria
- 100% of LLRs covered by ≥1 TC/AT with a pass result.
- Every user story has ≥1 passing `AT-NNN` observing its outcome through the shipped modal, with boundary + negative evidence.
- 0 regressions in `tests/test_tui_legend.py` (N1/batch-51 behaviour preserved when `view_key=None`).
- Full suite green except the 19 pre-existing batch-58/59 `tc016s` snapshot advisories (not caused by N8; A2 — the modal is not snapshotted).
- No frozen-engine file diffed vs `main` (engine-frozen guard clean).

---

## 6. Appendices

### 6.1 Extended glossary
See §1.3.

### 6.2 Relevant design decisions
- **D-1 — View-key-driven render, not section-only.** The card + key-type decision is per VIEW, but the map view's key is the entropy band key (not a `LEGEND_TABLE` section) and Workspace has no key. Section-token keying (as N1 uses) cannot distinguish `map` (bands + card) from `patch`/`diff` (plain Hex key, no card), both currently `("Hex",)`. Therefore `LegendScreen` gains a `view_key` param (LLR-N8-1.4); `compose` selects `LEGEND_EXAMPLES[view_key]` for the card and branches the key type on the view key, while the existing `sections=` argument continues to drive the severity rows unchanged. This keeps N1 fully backward-compatible (`view_key=None` → pre-N8 render).
- **D-2 — Content data lives in `legend.py`, render in `screens.py`.** `LEGEND_EXAMPLES` and the band-key derivation are pure data/helpers in the non-frozen `legend.py` (which already owns `LEGEND_TABLE`), imported and laid out by `LegendScreen.compose`. This mirrors the existing `LEGEND_TABLE` → `compose` split and keeps `screens.py` free of literal copy.
- **D-3 — Band key derived, not hardcoded.** The band rows are built from `ENTROPY_BANDS` + `band_style` (as the prototype does), so an upstream band change flows through — matching the existing anti-drift discipline of `legend.py` (`COLOUR_SEVERITY` ↔ `SEVERITY_CLASS_MAP`).
- **D-4 — Static everywhere text wraps.** Fold-in #1: `Label` → `Static` for key rows and card lines; the short `legend-artifact` sub-heading may stay `Label`. Verified: `Static` already imported (`screens.py:24`).
- **D-5 — Reversibility.** Every change is additive/reversible except D-1's `view_key` signature (a new optional param) and the `map` section value change (LLR-N8-3.3) — both easily reverted. No frozen file touched. No new dependency.

### 6.3 Open risks
- **R-1 (map loses the Hex overlay legend) — flagged to orchestrator.** Changing `_SCREEN_LEGEND_SECTIONS["map"]` from `("Hex",)` to `()` (LLR-N8-3.3) means the Map legend no longer shows the Hex byte-cell overlay rows (search/goto focus, MAC-address overlay — `legend.py "Hex"`/`_HEX_ROWS`). The pre-approved prototype shows the band key for Map, so this matches the design; but the Map hex-peek does render those overlays. **Mitigation option:** fold the two Hex overlay meanings into the Map card's inspector caption. **Open question (see summary):** keep Map example-only for overlays inside the card, or also render the `("Hex",)` rows beneath the band key? Reversible either way.
- **R-2 (import cycle) — LOW, verified absent (A4).** `legend.py` importing `entropy_service`/`entropy_style` — no cycle (grep clean; prototype runs). Re-confirm at Phase-3 import time.
- **R-3 (file budget).** Editable set is `legend.py`, `screens.py`, `app.py`, `styles.tcss` (4 source) + the test file — at/above the CLAUDE.md 5-file soft cap. Phase-3 may split into increments (data → render → Static/reconciliation) but all four source files are genuinely required.
- **R-4 (80-col regime).** At 80×24 the FULL-density card wraps taller and the `#legend_body` scroll (C-13) carries it; the ATs assert content presence in the rendered text, not on-screen position, so wrapping does not fail them. Confirm the scroll container still contains the card at 80×24 in Phase 4.

### 6.4 Phase-1 reconciliation log
No LLR threshold/statement changed after first draft; no promotion/removal. No audit table required this batch.

### 6.5 Requirement amendments (Before / After · Deleted / New)

NEW requirements: HLR-N8-1..6, LLR-N8-1.1..6.2. The `map` section-value change (LLR-N8-3.3) re-scopes N1's `map→("Hex",)` (batch-51) under D-1. Below: the Phase-1 gate orchestrator reconciliations (id authority, qa F-1 fold, operator R-1 ruling, N1-test amendments), recorded per the §6.5 Before/After contract.

**AMD-1 — ID reconciliation (architect authoritative).** The Phase-1 qa-catalog proposed `AT-150..156` / `TC-370..375`; the architect's set is canonical. **Before:** two id schemes. **After:** canonical = `AT-N8-01..07` / `TC-N8-*`; qa's `AT-150..156`/`TC-370..375` **superseded** (1:1 map: 150→01, 151→02, 152→03, 153→04+07, 154→05, 155→06; TC-370..375 → the architect's TC-N8-* equivalents). qa's `AT-156` (C-10(a) cross-view differential) is **NOT dropped** — folded as a **method rider** on the per-view ATs (each per-view AT drives a NON-default view and asserts its fingerprint differs from the workspace default).

**AMD-2 — AT-N8-06 / AT-N8-07 observation method → PAINTED output (qa finding F-1).** **Before:** AT-N8-06 asserts the 148-char Issues "Errors" meaning tail survives in the *rendered text* (`.render().plain`); the AT-N8-07 orange assertion reads rendered text. **After:** both MUST observe **painted** output — `render_line(y)` joined across `widget.size.height` (or the widget's rendered line count) — because `Label ⊂ Static` and BOTH return the full renderable via `.render().plain`, so `.plain` is **blind to truncation** (truncation is a paint-time clip). Counterfactual restored: on the pre-fix `Label` tree the painted line is clipped to viewport width so the tail `same-name mismatch` is ABSENT from the painted output → AT-N8-06 RED; with `Static` the row wraps (height > 1) and the tail is present → GREEN. Reason (LLR-N8-6.1) unchanged; only the AT's observation surface is corrected. TC-N8 for "rows are Static" uses `type(row) is Static` (NOT `isinstance`, since `Label ⊂ Static`).

**AMD-3 — Memory Map Hex overlays explained in the card (operator R-1 ruling, 2026-07-23).** R-1 RESOLVED by operator: "band key + explain the 2 Hex overlays in the card." **Before:** LLR-N8-3.1 map card covers header/band-bar/region/at-a-glance/inspector; the 2 Hex byte-cell overlays (search/goto-focus highlight; MAC-address overlay — `LEGEND_TABLE["Hex"]`, `legend.py:87-111`) were dropped when `map→()` (they paint in the Map hex-peek, so "explain everything" leaves them uncovered). **After:** `map` stays `()` (band key, LLR-N8-3.3 unchanged) AND LLR-N8-3.1's map card SHALL include a line explaining both Hex overlay meanings (search/goto-focus highlight; MAC-address byte overlay) so the Map legend covers every element its hex-peek paints. New acceptance on LLR-N8-3.1: the map card text contains both overlay meanings; AT-N8-03 asserts their presence.

**AMD-5..12 — Phase-2 cross-review resolutions (PRECEDENCE: on any conflict, §6.5 AMD-* OVERRIDES the §3/§4 body — implementers follow the amended predicate here).** Recorded from the Phase-2 architect (4 major/5 minor) + qa (1 blocker/4 minor) + security (1 LOW) reviews. `iterate-to-refine` on B-1.

- **AMD-5 (qa B-1 BLOCKER — corrects AMD-2, the load-bearing fold-in counterfactual).** AMD-2's "tail absent via render_line on the pre-fix Label" premise is EMPIRICALLY FALSE (Textual 8.2.8 probe: `Label` row = `139×1`, `Static` row = `120×2`, tail present in `render_line` for BOTH — `Label{width:auto}` makes the row content-width, not viewport-clamped, and `render_line` reads the widget's own 139-wide buffer, bypassing the compositor's `overflow-x:auto` clip). **Before:** AT-N8-06 / HLR-N8-6 / LLR-N8-6.1 pass = "tail token `same-name mismatch` present in the rendered/painted `#legend_body` text". **After:** pass predicate = **`type(long_row) is Static AND long_row.size.height >= 2`** (the wrap actually occurred) — the tail substring is a SECONDARY readability check only, never the counterfactual. Counterfactual restored: pre-fix `Label` → `size.height == 1` → RED; `Static` → `size.height >= 2` → GREEN. `type(row) is Static` (NOT `isinstance` — `Label ⊂ Static`). AT-N8-06 also asserts `size.height >= 2` IS the observed wrap (self-verifies the width precondition — qa m-4).

- **AMD-6 (architect MAJOR-2 — fold AMD-3 into the executable body).** LLR-N8-3.1 threshold AND AT-N8-03 deliverable SHALL additionally assert BOTH Hex-overlay meanings are present in the map card: the search/goto-focus highlight and the MAC-address byte overlay (`LEGEND_TABLE["Hex"]` meanings, `legend.py:87-96`). The 4/4 map-card threshold becomes 6/6 (band bar, region, At a glance, inspector, + 2 overlay meanings).

- **AMD-7 (architect MAJOR-3 — MAC reconciliation colour source CORRECTED).** The MAC DataTable WARNING row is painted **Rich `orange3`** (the inline `_SEVERITY_TO_RICH_STYLE` for WARNING), NOT `#d9a35b`. `#d9a35b` is the DISTINCT `.mac_out_of_range` CSS hue / the `MAC_ADDRESS_OVERLAY_STYLE`-family overlay — a different orange. **Before:** LLR-N8-4.3 paints the sample `#d9a35b` "= the hue of MAC_ADDRESS_OVERLAY_STYLE" (wrong; that constant is `"bold orange3"` ≈ `#d78700`). **After:** the reconciliation sample row is painted inline **`orange3`** (the actual colour the MAC WARNING row renders), and AT-N8-07 reads the painted segment's colour and couples it to the MAC row's real inline WARNING style — NOT a hex literal. Note in the card that this orange is an interaction/severity-in-table cue distinct from the pale-yellow severity WORD.

- **AMD-8 (architect MAJOR-4 + qa — restore the C-31 live-column oracle).** LLR-N8-2.1 / AT-N8-02 / TC-N8-04 SHALL derive the A2L column-coverage check from the LIVE `#a2l_tags_list.columns` (guard `len >= 16`), asserting every live column label has a legend line — so a 17th A2L column without a legend entry goes RED. The 6 hand-picked substrings are NOT the oracle.

- **AMD-9 (security F3 LOW — markup round-trip guard, NEW TC).** NEW **TC-N8-11**: iterate every line of every `LEGEND_EXAMPLES` entry, construct the widget / `Content.from_markup`, assert (a) NO `MarkupError` raised and (b) visible `.plain` matches the intended bracket-bearing text (so `\[` round-trips to literal `[`, no stray span). Guards the invariant that N8 INTRODUCES markup into legend lines (breaking `LEGEND_TABLE`'s bracket-free rule, `legend.py:86`) against a future unescaped-bracket author error crashing the modal.

- **AMD-10 (minors — cutoff single-source; workspace glyphs derived).** (a) qa m-1 / architect MINOR-7: the band cutoffs shown in the map card AND asserted by AT-N8-03 SHALL pass through ONE format helper single-sourced from `ENTROPY_BANDS` (trim trailing `.0`; clamp `8.000001`→`8`), so display value and assertion share the transform (no hand-list). (b) qa m-3: the workspace memory-strip glyphs `·░▒▓` SHALL be derived from `entropy_style.band_style` (the same source the map card uses), not hand-listed.

- **AMD-11 (minor m-2 — stable id for the orange sample).** The MAC reconciliation sample row gets a stable id **`#legend_mac_warning_sample`** so AT-N8-07 reads one segment's colour, not a brittle all-segment scan.

- **AMD-12 (minors — citations/formatting).** (a) MINOR-5: entropy source path corrected to `s19_app/tui/services/entropy_service.py:41` (services subdir; `entropy_style.py` is at `tui/` root). (b) MINOR-8: the `may remain Label` permissive moves from the LLR-N8-6.1 STATEMENT to an acceptance-criteria line (no non-`shall` modal inside a normative statement). (c) MINOR-9 / AMD-4: the N1 tests are `tests/test_legend_scope_and_logwidth.py::test_n1_legend_scoped_per_screen` (map heading) and `::test_n1_unmapped_screen_shows_full_table` (workspace) — cited here. (d) MINOR-6: TC crosswalk — qa TC-373(band count)→TC-N8-05, TC-374(live columns)→TC-N8-04, TC-375(colour source)→the AT-N8-07 segment read; none dropped.

**AMD-4 — N1 test amendments (the map + workspace mapping changes touch shipped N1 tests).** **Before → After, per N1 test:** (a) the N1 test asserting the Map legend heading set `== ["Hex"]` → now asserts the Map renders the **band key** (no `Hex` severity rows); (b) `test_n1_unmapped_screen_shows_full_table` treated workspace as UNMAPPED → full-table fallback → now workspace is **explicitly mapped to `()`** (example-only), so that test is updated to assert workspace renders its example card with **zero `sev-*` rows** (its example-only contract), and the "unmapped → full table" invariant is re-pointed to a genuinely unmapped screen (e.g. `flow`/`crc`) if one remains, else retired with reason. These are the only two N1 regressions; both are intended and recorded here (not silent edits). Frozen-set unaffected (N1 tests are non-frozen).

### 6.6 Draft-time verification ledger (symbol-citation rule)
| Symbol / constant | Status | Evidence (file:line) |
|-------------------|--------|----------------------|
| `LEGEND_TABLE` (A2L/MAC/Issues/Hex rows) | verified | `legend.py:113-180` |
| `COLOUR_SEVERITY` | verified | `legend.py:198-204` |
| `MAC_ADDRESS_OVERLAY_STYLE` import | verified | `legend.py:27` |
| `LegendScreen` + `.compose` (Label rows) | verified | `screens.py:750,794-821` (Label at :795,:799,:809) |
| `LegendScreen.__init__(sections=…)` | verified | `screens.py:782-792` |
| `Static` imported in screens | verified | `screens.py:24` |
| `_SCREEN_LEGEND_SECTIONS` (workspace ABSENT; map=("Hex",)) | verified | `app.py:5378-5386` |
| `action_show_legend` (passes sections, not view_key) | verified | `app.py:5528-5554` |
| `_active_screen_key` (init/set) | verified | `app.py:1444,5477` |
| `.sev-*` classes + hexes | verified | `styles.tcss:628-646` |
| `.band-*` classes + hexes | verified | `styles.tcss:665-679` |
| `.mac_out_of_range #d9a35b` | verified | `styles.tcss:657` |
| `#legend_body` scroll · `.legend-artifact` | verified | `styles.tcss:1543-1551` |
| `.legend-row` dedicated tcss rule | verified ABSENT (class-only) | no match in `styles.tcss` |
| `ENTROPY_BANDS` (4 bands, `high` hi=8.000001) | verified | `entropy_service.py:41-46` |
| `band_style` → (class,glyph,meaning) · glyph/meaning maps | verified | `entropy_style.py:45-65,69` |
| entropy_service imports legend (cycle check) | verified ABSENT | grep `legend` in `entropy_service.py` → 0 |
| Legend modal in `tc016s` density snapshots | verified ABSENT | grep `action_show_legend`/`legend_close`/`LegendScreen` in `tests/test_tui_snapshot.py` → 0 |
| `LEGEND_EXAMPLES`, band-key helper, `view_key` param, `styles.tcss` card classes, `_SCREEN_LEGEND_SECTIONS["workspace"]` | NEW — created in Phase 3 | — |
| `tests/test_legend_n8.py`, all `TC-N8-*`/`AT-N8-*` node ids/`-k` selectors | NEW — provisional-until-Phase-3 (V-5) | — |
