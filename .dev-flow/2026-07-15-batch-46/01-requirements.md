# Requirements Document — s19_app — Batch 46

> **Artifact language:** English (batch default).
> **Normative convention:** IEEE 830 + EARS. `shall` = binding, only inside HLR/LLR statements. `should`/`may`/`will` are informative elsewhere.
> **Scope class:** LAYOUT-ONLY view change. No parser / range-engine / validation / behavior / wiring change. Frozen-engine diff MUST be 0.

---

## 1. Introduction

### 1.1 Purpose
Specify the requirements for restructuring the TUI `PatchEditorPanel` from its current 2×2 four-pane grid into a **responsive three-window layout** — three bordered windows **PATCH SCRIPT · CHECKS · JSON EDIT**, each with its action buttons **docked outside the scrollable body**, laid out **3 columns when wide (≥120 cols)** and **vertically stacked at the 80×24 floor**. This closes field-audit findings **B2** (action buttons overflow a starved `1fr` grid cell and become unreachable; ~5 fragmented scroll regions) and **U8** (weak visual gestalt — labeled sections read as one crowded surface rather than separated windows).

### 1.2 Scope

**In scope.** Compose-tree restructure of `PatchEditorPanel.compose` (`s19_app/tui/screens_directionb.py:2271-2567`) and the patch CSS block (`s19_app/tui/styles.tcss` `#patch_editor_panel` and siblings, verified spans `801-852` and `985-1009`), plus supersession of the tests that pin the old 2×2 structure, plus REQUIREMENTS.md row additions/amendments.

**Out of scope (explicit).**
- Any change to patch/check/variant/save-back **behavior**, action routing, key bindings, or the message contract the app uses to drive the panel.
- Any new Python breakpoint, resize handler, or `TabbedContent` widget. **D1 (operator-locked):** the responsive switch is **pure CSS reusing the existing `width-narrow` regime** (see §2.4).
- Any edit to a frozen-engine module (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) or a frozen test file (`test_tui_a2l.py`, `test_tui_mac.py`, `test_validation_*`, `test_core_srecord_validation.py`, `test_hexfile.py`, `test_range_index.py`, `test_color_policy_round_trip.py`, and `test_tui_directionb.py::test_tc031_*`). None of this batch's touched files are in that set — confirmed in §2.4 / §6.2.

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Window | A bordered `Container` (title `Label` + scrollable body + docked button row(s)) — the U8 "real separated window" gestalt, replacing a bare labeled section. |
| Docked (button row) | A button-row `Horizontal` that is a **sibling of, not a child of**, its window's scrollable body — so it is never trapped below that body's scroll fold. The B2 fix. |
| `width-narrow` | Existing App-level CSS class toggled on `#workspace_shell` + `#workspace_body` at `width < 120` (`app.py:4930`), driven by `on_resize` (`app.py:4938`). |
| Regime | A terminal-width band: **wide** (≥120 cols) vs **narrow** (<120 cols, incl. the 80×24 floor). |
| Host content width | `#patch_editor_panel.content_region.width` — the usable interior after padding; the pane/window budget denominator. |
| Reparent-safety | The invariant that moving widget sub-trees between containers preserves every leaf widget id and its (message-based) app wiring. |

### 1.4 References
- Batch objective + D1 lock + reparent-safety map (operator-approved kickoff, 2026-07-15).
- `docs/engineering-rules.md` — project stack controls **C-13 / C-13.1 / C-22 / C-23 / C-28**.
- Field audit `project_field_audit_2026-07-14.md` — findings **B2**, **U8**.
- REQUIREMENTS.md §28 (`R-PATCH-2X2-*`, batch-22), §29 (`R-PATCH-VARIANT-SELECT-001`, batch-23), §33 (`R-TUI-046`, batch-36) — the rows amended here.
- Prior-art reflow pattern: `styles.tcss:626` (`#workspace_body.width-narrow #map_body { layout: vertical }`) and `:649` (`.map-band-row` horizontal→vertical), batch-45.
- Prototype (non-transferring, C-16): `prototypes/patch_editor_layout.prototype.py` (sibling worktree `.claude/worktrees/rail-8-snapshot-baselines-481a06/`).

### 1.5 Document overview
§2 overall description + source stories + refinement log. §3 HLR (with first-class black-box Acceptance blocks + `AT-NNN`). §4 LLR. §5 validation strategy + dual traceability. §6 appendices: design decisions, risks, reconciliation log, and the §6.5 Before/After amendment records for the three superseded REQUIREMENTS.md rows.

---

## 2. Overall description

### 2.1 Product perspective
`PatchEditorPanel` is the patch-editor screen of the ~5k-line orchestration-only `S19TuiApp` (`app.py`). The app resolves the panel by id (`#patch_editor_panel`) and drives it through **messages and method calls**, never by querying the pane-container ids — so a container restructure is wiring-safe as long as leaf ids and the message contract survive (verified §2.4). This batch touches only the view layer; the parser → range/validation engine layers are untouched (frozen diff = 0).

### 2.2 Product functions
1. Render the patch editor as three bordered windows (PATCH SCRIPT · CHECKS · JSON EDIT).
2. Lay the windows out 3-across when wide (≥120), stacked vertically when narrow (<120), via the existing `width-narrow` CSS toggle.
3. Keep every window's action buttons docked outside its scrollable body so they are reachable at both regimes (the B2 fix).
4. Preserve every patch leaf-widget id, the `.hidden`-toggled container ids, and all existing action/handler/binding behavior (reparent-safety).

### 2.3 User characteristics
Single-role: the S19/HEX firmware operator using the TUI at terminal sizes from the 80×24 floor upward. No permission or auth surface. No user data processing beyond the already-loaded local firmware/patch artifacts (privacy: unchanged — no new persistence, network, or external-state surface).

### 2.4 Constraints
- **D1 — STACKED, CSS-ONLY, no `TabbedContent`.** The wide↔narrow switch reuses the existing `width-narrow` class. Mechanism verified: `#patch_editor_panel` is a descendant of `#workspace_body`, so selectors of the form `#workspace_body.width-narrow #patch_editor_panel …` fire automatically on the existing toggle (`_apply_width_regime`, `app.py:4903-4936`; `on_resize`, `app.py:4938-4940`). No new Python, no new breakpoint, no recompose. This is exactly the batch-45 map-reflow pattern (`styles.tcss:626`, `:649`).
- **Frozen-engine diff = 0.** Touched source: `screens_directionb.py`, `styles.tcss` — both NON-frozen (verified: not in `_ENGINE_PATHS`). Touched tests: `test_tui_patch_layout.py`, `test_tui_patch_editor_v2.py`, `test_tui_snapshot.py`, `test_tui_directionb.py` (non-`tc031` nodes only), `test_tui_patch_variant.py` — all NON-frozen.
- **C-13 / C-13.1 / C-23 — geometry discipline.** All rendered-size claims (window widths at 3-across, docked-row height vs body budget) MUST be established by pilot measurement at **both** 80×24 and 120×30, never by `fr`-math. Un-measured values are flagged `assumed — pilot-measure in Phase 3`.
- **C-16 — prototype non-transfer.** The prototype used a simplified widget set; its numbers/interactions do not transfer to the full widget set. Treated as `assumed — verify in Phase 3`.
- **C-22 — snapshot drift bounded.** The two `patch-comfortable-*` snapshot cells drift; marked `xfail(strict=False)` as an upper bound, regenerated in canonical CI post-merge (local regen forbidden).
- **C-28 — NOT triggered.** No App-level `Binding(show=True)` change and no shared-chrome (Footer/Header/rail) change. Verified: all patch bindings are `show=False` — `6`→patch (`app.py:807`), `ctrl+z`/`ctrl+y` (`app.py:824-825`), `b`→before/after (`app.py:801`). Stated per the control's "state this" requirement; no footer census needed.

### 2.5 Assumptions and dependencies
- **A1 (verified).** App wiring is message/id-based, not pane-container-based. The app never `query_one`s `#patch_pane_entries/changefile/checks/variant`; it drives leaf ids and reacts to panel messages. If this were false the reparent would break wiring — it is not (grep of `app.py` for the pane ids returns 0 hits; the panel-reveal sites use `#patch_saveback_row` / `#patch_before_after_row`, `screens_directionb.py:2924,2933,2948,2966`).
- **A2 (assumed — pilot-measure Phase 3).** At 120 cols the measured host content is ~92 cols (batch-22 measurement, `styles.tcss:799-800`). Split three ways minus **three** window borders/gutters yields ~28-30 usable cols/window. The batch-22 figure was measured in a **two**-pane, border-light layout; three bordered windows consume width it did not account for → **re-measure the whole window budget in Phase 3** (C-13/C-23).
- **A3 (assumed — pilot-measure Phase 3).** At 80×24, three stacked bordered windows each need title + body + docked row(s); whether the panel-level vertical scroll suffices or inner window bodies also need their own scroll is a **budget question**, not settled by this spec. Open question O-1 (§6.3).
- **Dependency.** The existing `width-narrow` toggle (`app.py:4903-4940`) and `#workspace_body` ancestry of the panel. If a future refactor moves the panel out of `#workspace_body`, the CSS selectors break — flagged as a reversibility note (§6.2).

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-U8 | As a firmware operator, I want the patch editor's PATCH SCRIPT, CHECKS, and JSON-EDIT areas rendered as three visually separated windows that sit 3-across on a wide terminal and stack vertically on a small one, so that I can tell the areas apart at a glance and use each at any terminal size. | Field audit U8 | READY |
| US-B2 | As a firmware operator, I want every action button in each area to stay reachable (never trapped below a scroll fold or off-screen) at both the 80×24 floor and a wide terminal, so that I can run Load/Apply/Save/Run-checks/Execute/Parse/Write without hunting through nested scroll regions. | Field audit B2 | READY |

#### Refinement log

**US-U8 — Responsive 3-window patch layout**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = operator; outcome = three bordered windows, 3-across ≥120 / stacked <120; why = distinguish areas + usable at any size; out of scope = any behavior/wiring change, any content-set change beyond re-parenting.
- **Feasibility (E, S):** path = compose restructure into 3 window containers + CSS reusing `width-narrow`; dependencies = the existing toggle + `#workspace_body` ancestry (verified); fits one batch = yes (layout-only, 3 increments).
- **Evaluability (T) — behavioral, black-box:** "When the patch screen is shown at 120×30, the operator observes three windows side-by-side (3 distinct column origins); at 80×24 the three windows stack (1 column origin, ascending rows)." → **AT-063a / AT-063b**.
- **Open questions:** O-1 (inner-body scroll at 80×24, §6.3); O-2 (variant/execute placement — resolved §6.2 D-3).
- **Classification:** READY.

**US-B2 — Docked action-button reachability**
- **INVEST:** I ✓ · N ✓ · V ✓ · E ✓ · S ✓ · T ✓
- **Functionality (V, N):** user = operator; outcome = every named action button docked outside its window body's scroll, reachable at both regimes; why = current 2×2 traps change-file/entries buttons below a starved `1fr` cell fold; out of scope = adding/removing any button or its handler.
- **Feasibility (E, S):** path = each window = title + `VerticalScroll` body + docked button `Horizontal`(s) as body siblings; dependencies = pilot-measured docked-row budget (assumed → Phase 3); fits one batch = yes.
- **Evaluability (T) — behavioral, black-box:** "When the patch screen is shown at 80×24 (and 120×30), each named action button, with its window in view, renders fully within the screen region and is not clipped by its window body's scroll fold." → **AT-064a / AT-064b**.
- **Open questions:** docked-row height vs body budget at 80×24 (C-13/C-23, assumed → Phase 3); fallback ladder if PATCH SCRIPT docked rows overflow (§6.2 D-3, C-13.1).
- **Classification:** READY.

---

## 3. High-level requirements (HLR)

### HLR-063 — Responsive three-window patch layout
- **Traceability:** US-U8. (REQUIREMENTS.md row: **R-TUI-063**.)
- **Statement:** When the Patch Editor screen is shown, the system **shall** render its content as three bordered windows — PATCH SCRIPT, CHECKS, and JSON EDIT — and **shall** lay them out three-across while the terminal is ≥120 columns and stacked vertically while it is <120 columns, using the existing `width-narrow` CSS regime with no new Python breakpoint or `TabbedContent`.
- **Rationale (informative):** Fixes U8. Three real windows give the gestalt separation labeled sections lack; reusing `width-narrow` keeps the responsive switch declarative and reversible.
- **Validation:** `test` (Layer B acceptance via Pilot geometry) + `inspection` (CSS selector reuse).
- **Executed verification:** `pytest tests/test_tui_patch_layout.py -k "at_063"` (pilot at 80×24 and 120×30); inspection of `styles.tcss` for `#workspace_body.width-narrow #patch_editor_panel` selectors.
- **Numeric pass threshold:** wide → exactly **3 distinct window `region.x`**; narrow → exactly **1 distinct window `region.x`** with **3 ascending `region.y`**; 0 frozen-engine diff.
- **Priority:** high
- **Acceptance (black-box) — the user-verified outcome (the WHAT):**
  - **Observable outcome:** three separated windows, 3-across when wide, stacked when narrow.
  - **Shipped surface:** `S19TuiApp.run_test(size=…)` → `action_show_screen("patch")`; the rendered `#patch_win_script` / `#patch_win_checks` / `#patch_win_json` regions.
  - **Deliverable + observation:** rendered window elements — asserted via `region.x`/`region.y` distinctness + non-overlap + within-host-budget, no on-disk artifact.
  - **Acceptance test(s):** **AT-063a** (wide, 120×30 → 3 distinct x, each one column, no overlap, within host budget; RED on current 2×2 → 2 distinct x / 4 panes), **AT-063b** (narrow, 80×24 → 1 distinct x, 3 ascending y, each full-width; RED on 2×2 → 2 distinct x), **AT-063c** (reparent-safety at 80×24 AND 120×30 — every must-preserve leaf id resolves once, and one action per window routes to its observable effect: `add_entry` grows the table, Load present/routes, `run_checks` emits a `Checks:` log line, execute button present).
  - **Boundary catalog (QC-3):** ☑ boundary — the 80×24 floor (AT-063b/AT-064a) and 120×30 (AT-063a/AT-064b); ☑ invalid/reparent — AT-063c leaf-id + routing; ☐ empty — N/A (the panel always composes a fixed widget set, no data-driven emptiness in layout); ☐ error — N/A (pure layout, no failure path).

### HLR-064 — Docked action-button reachability at both regimes
- **Traceability:** US-B2. (REQUIREMENTS.md row: **R-TUI-064**.)
- **Statement:** Where the Patch Editor renders its three windows, each window's action-button row(s) **shall** be composed as sibling(s) of — not descendants of — that window's scrollable body, so that at both the 80×24 floor and a ≥120-column terminal every named action button renders within the screen region and is not clipped below its window body's scroll fold.
- **Rationale (informative):** Fixes B2. Docking the buttons outside the body is the structural fix for buttons trapped below a starved `1fr` cell fold in the current grid.
- **Validation:** `test` (Layer B acceptance via Pilot geometry).
- **Executed verification:** `pytest tests/test_tui_patch_layout.py -k "at_064"` (pilot at 80×24 and 120×30).
- **Numeric pass threshold:** every named action button region ∈ screen region **and** NOT inside its window body's clipped-below-fold content, at both sizes; 0 buttons clipped.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** every named action button reachable (docked, not below a fold) at both regimes.
  - **Shipped surface:** patch screen via Pilot; the named button regions vs the screen region and their window-body scroll fold.
  - **Deliverable + observation:** rendered button elements; geometry oracle (qa-reviewer defines the exact fold discriminator + RED capture).
  - **Acceptance test(s):** **AT-064a** (80×24 floor — each named button docked, not clipped below its body fold; RED on current 2×2 → change-file/entries buttons sit below the starved `1fr` cell fold, region off-screen/clipped), **AT-064b** (120×30 — same reachability).
  - **Boundary catalog (QC-3):** ☑ boundary — 80×24 (tightest, AT-064a) + 120×30 (AT-064b); ☐ empty / ☐ invalid / ☐ error — N/A (fixed button set, pure layout).

---

## 4. Low-level requirements (LLR)

### LLR-063.1 — Compose three window containers with docked button rows
- **Traceability:** HLR-063, HLR-064.
- **Statement:** `PatchEditorPanel.compose` (`screens_directionb.py:2271`, currently 4× `#patch_pane_*` + spanning cells) **shall** yield three bordered window `Container`s — **NEW ids `#patch_win_script`, `#patch_win_checks`, `#patch_win_json`** (`NEW — created in Phase 3`) — each composed as a title `Label` + a scrollable body container + one or more docked button-row `Horizontal`(s) that are siblings of the body, re-parenting the existing widget sub-trees wholesale per the §6.2 D-1 window→content map.
- **Validation:** `test (integration)` + `inspection`.
- **Executed verification:** `pytest tests/test_tui_patch_layout.py -k "at_063 or tc_window"`; inspection of `compose` structure.
- **Numeric pass threshold:** 3 window ids resolve to exactly one widget each; every must-preserve leaf id (LLR-063.4) resolves to exactly one widget.
- **Acceptance criteria:**
  - The three window ids exist and each contains a title `Label`, a scrollable body, and its docked button row(s).
  - No leaf id renamed or dropped; sub-trees moved intact.

### LLR-063.2 — Wide regime: three windows horizontal
- **Traceability:** HLR-063.
- **Statement:** While the terminal width is ≥120 columns, `#patch_editor_panel` **shall** lay the three windows out horizontally (three columns), each window within the host column budget and non-overlapping, with no right-edge clip past the panel region.
- **Validation:** `test (e2e / pilot)`.
- **Executed verification:** `pytest tests/test_tui_patch_layout.py::test_at_063a_three_across_at_120` (provisional node id, reconciled Phase 4 per V-5).
- **Numeric pass threshold:** exactly 3 distinct window `region.x`; each `region.width ≤ host_content_w // 3` (computed at runtime, not asserted as a literal); `x + width ≤ panel.region.right` for all three.
- **Acceptance criteria:**
  - `#patch_editor_panel` base layout is `layout: horizontal` (or `grid` with 3 columns) at the wide regime.
  - Window widths sum within host content; **`host_content_w // 3` ≈ 28-30 cols/window @120 is `assumed — pilot-measure in Phase 3`** (A2, C-13/C-23; three window borders/gutters not in the batch-22 two-pane measurement).

### LLR-063.3 — Narrow regime: stack vertical via existing `width-narrow`
- **Traceability:** HLR-063.
- **Statement:** While the terminal width is <120 columns, the CSS rule `#workspace_body.width-narrow #patch_editor_panel` (and the window-row selector) **shall** reflow the three-window layout from horizontal to vertical, reusing the existing `width-narrow` toggle (`app.py:4930`), with no new Python, breakpoint, or resize handler.
- **Validation:** `test (e2e / pilot)` + `inspection`.
- **Executed verification:** `pytest tests/test_tui_patch_layout.py::test_at_063b_stacked_at_80` (provisional); inspection of `styles.tcss` confirming the `#workspace_body.width-narrow #patch_editor_panel` selector mirrors `:626`/`:649`.
- **Numeric pass threshold:** at 80×24 → exactly 1 distinct window `region.x`, 3 ascending `region.y`, each window full-width; diff of `app.py` = 0 lines (no Python change).
- **Acceptance criteria:**
  - The narrow rule uses the existing class, not a new one (grep `styles.tcss` for `width-narrow #patch_editor_panel`).
  - `app.py` untouched (the batch's Python diff is confined to `screens_directionb.py`).

### LLR-063.4 — Reparent-safety: preserve every leaf id and the `.hidden`-toggled containers
- **Traceability:** HLR-063, HLR-064.
- **Statement:** The compose restructure **shall** preserve every must-preserve widget id so the app's message/method wiring stays intact.
- **Must-preserve leaf ids (censused; each verified present in current `compose`, `screens_directionb.py:2316-2567`):**
  - Wiring-critical (14): `patch_edit_json_button` (:2528), `patch_undo_button` (:2368), `patch_redo_button` (:2369), `patch_entry_edit_json_button` (:2358), `patch_doc_file_select` (:2381), `patch_variant_select` (:2480), `patch_doc_entries_table` (:2321), `patch_doc_empty_state` (:2327), `patch_doc_issue_count` (:2451), `patch_doc_issues` (:2454), `patch_saveback_name_input` (:2535), `patch_saveback_width_button` (:2539), `patch_checks_status` (:2461), `patch_checks_results` (:2465).
  - Additional census-pinned leaf/structural ids: `patch_doc_path_input` (:2390), `patch_doc_load_button` (:2406), `patch_doc_refresh_button` (:2412), `patch_doc_validate_button` (:2413), `patch_doc_apply_button` (:2414), `patch_doc_save_button` (:2415), `patch_checks_run_button` (:2424), `patch_checks_help` (:2440), `patch_paste_text` (:2520), `patch_paste_parse_button` (:2522), `patch_entry_address_input` (:2337), `patch_entry_value_input` (:2342), `patch_entry_bytes_input` (:2346), `patch_entry_add_button` (:2349), `patch_entry_edit_button` (:2350), `patch_entry_remove_button` (:2351), `patch_variant_info_button` (:2485), `patch_execute_scope_button` (:2497), `patch_execute_run_button` (:2499), `patch_saveback_confirm_button` (:2541), `patch_saveback_decline_button` (:2542), `patch_before_after_button` (:2561).
  - Section labels + containers pinned by `test_at057a` / `TC-319`: `patch_script_section_label` (:2402), `patch_checks_section_label` (:2420), `patch_doc_controls` (:2416, must keep its 5 buttons Load/Refresh/Validate/Apply/Save), `patch_checks_controls` (:2443, Run-checks + help). These MAY move into the new windows; ids + membership preserved.
  - `.hidden`-toggled containers (id-resolved in Python, `screens_directionb.py:2924/2933/2948/2966`): `patch_saveback_row` (:2545), `patch_before_after_row` (:2565) — ids preserved.
- **SAFE to retire (structural-only, referenced only by CSS + census tests, superseded in LLR-063.5):** `patch_pane_entries` (:2374), `patch_pane_changefile` (:2447), `patch_pane_checks` (:2466), `patch_pane_variant` (:2504), `patch_doc_file_row` (:2445), the `#patch_editor_panel` grid, and the `#patch_paste_row` full-width-span structure.
- **Validation:** `test (integration)`.
- **Executed verification:** `pytest tests/test_tui_patch_editor_v2.py -k "id_census or reparent"` + `tests/test_tui_patch_layout.py -k at_063c`.
- **Numeric pass threshold:** all must-preserve ids resolve to exactly one widget at 80×24 AND 120×30; one action per window routes to its observable effect (AT-063c).
- **Acceptance criteria:** message-based wiring intact; the variant `Select` group stays ABOVE the execute group (preserves `R-PATCH-VARIANT-SELECT-001` / TC-035.2 order invariant).

### LLR-064.1 — Docked button rows outside window bodies
- **Traceability:** HLR-064.
- **Statement:** In each of the three windows, the action-button row(s) **shall** be composed as sibling(s) of the window's scrollable body container (not descendants of it), so a button is never inside the body's clipped-below-fold content at either 80×24 or 120×30.
- **Validation:** `test (e2e / pilot)`.
- **Executed verification:** `pytest tests/test_tui_patch_layout.py -k "at_064"`.
- **Numeric pass threshold:** for every named action button, at both sizes: the button is NOT a descendant of a `VerticalScroll` that has clipped it below its fold, and (with its window in view) its region ∈ screen region; 0 clipped.
- **Acceptance criteria:**
  - The docked rows carry the buttons enumerated in the §6.2 D-1 map.
  - Structural check: each docked button-row `Horizontal` is a direct child of its window `Container`, sibling of the body — not a descendant of the body's `VerticalScroll`.

### LLR-064.2 — Docked-row budget is measured, not fr-derived (C-13/C-23) + fallback ladder
- **Traceability:** HLR-064.
- **Statement:** The docked-row total height vs each window's body budget at 80×24 **shall** be established by pilot measurement in Phase 3 (never `fr`-math), and if the PATCH SCRIPT window's docked rows plus a usable body do not fit the 80×24 floor, the pre-committed fallback ladder (§6.2 D-3, C-13.1) **shall** be applied lowest-viable-rung-first.
- **Validation:** `analysis` (geometry budget) — deferred measurement.
- **Executed verification:** Phase-3 pilot: `App.run_test(size=(80,24))` + `action_show_screen("patch")`, read each window's `content_region` and each docked-row `region`.
- **Numeric pass threshold:** at 80×24, each window shows ≥1 body line at scroll 0 AND all its docked buttons reachable (per LLR-064.1 threshold). **Docked-row-fits-body budget = `assumed — pilot-measure in Phase 3`** (C-13/C-23; prototype numbers non-transferring, C-16).
- **Acceptance criteria:**
  - PATCH SCRIPT is the heaviest window (entries table + inputs + change-file + variant + execute + 3 docked rows) → it carries the tightest budget and the highest measurement risk.
  - Fallback ladder recorded and each rung tagged with the deficit range it recovers (§6.2 D-3).

### LLR-064.3 — Test-supersession census (C-26): declare every touched structural symbol
- **Traceability:** HLR-063, HLR-064.
- **Statement:** The batch **shall** supersede every test that pins the old 2×2 structural contract to the new three-window contract, preserving every leaf-id assertion. The reverse-census (executed at draft, results below) enumerates the touched symbols and their disposition; **the increment gate — running the actual edited files against the real suite — is the completeness guarantee (A-2), the census a Phase-1 cost-reduction heuristic.**
- **Executed reverse-census (grep `tests/` for `patch_pane_entries|patch_pane_changefile|patch_pane_checks|patch_pane_variant|patch_doc_file_row|patch_editor_panel`, run 2026-07-15):** 82 hits across 10 files; the files asserting on the retiring **structural** ids (not merely leaf ids) are:
  1. `tests/test_tui_patch_layout.py` — `_PANE_IDS` (:36-41), `test_at_033a`/`test_at_033b` 2×2 geometry, `test_tc_pane_styles_and_grid` (panel `grid` + `#patch_doc_controls` grid-3), `TC-319` change-file structure (:351), `test_at058a_paste_editor_in_viewport_and_separated` (:534). **Disposition:** SUPERSEDE 2×2 geometry → AT-063a/AT-063b; add three-window panel-layout + docked-row white-box TC; TC-319 → update parentage, PRESERVE section labels + `#patch_doc_controls` 5-button census + `#patch_checks_controls` membership; AT-058a → fold its "JSON editor in-viewport at scroll 0" intent into the JSON-EDIT window (AT-063a/063c) or a renamed AT.
  2. `tests/test_tui_patch_editor_v2.py` — `_PRESERVED_REGROUP_IDS` (:2255, includes `patch_doc_file_row`, `patch_pane_changefile`), `test_at057a` (:2274), `_PATCH_PRESERVED_IDS` (:2451), `test_at058b` (:2470), and `scroll_end("#patch_pane_entries")` at :3214 and :3499. **Disposition:** update the preserved-id SET to the new window ids; every LEAF id stays; re-target the two `scroll_end` calls to the new PATCH-SCRIPT body container. (`NEW_WIDGET_IDS`/`RETIRED_WIDGET_IDS` at :61-78 reference NO pane id → `test_panel_composition` unaffected.)
  3. `tests/test_tui_snapshot.py` — `patch-comfortable-80x24` / `-120x30` cells (`_SCAFFOLD_CELLS` :541, `_SCAFFOLD_SCREENS` includes `patch` :110). **Disposition:** add a `_batch46_patch_drift_marks(...)` helper (`xfail(strict=False)`, 2 patch cells, C-22 upper bound); regen in canonical CI post-merge (local regen forbidden).
  4. **FINDING — not in the kickoff's named set:** `tests/test_tui_directionb.py` — `#patch_pane_entries .patch-section-title` selector at :7955 (+ docstring :7916, :8006). **Disposition:** SUPERSEDE the selector to the new PATCH-SCRIPT window/body id. Verified non-frozen: only `test_tui_directionb.py::test_tc031_*` is engine-frozen; the section-title test is a distinct node — `assumed — Phase 3 confirm the specific node ≠ test_tc031_*`.
  5. **FINDING — not in the kickoff's named set:** `tests/test_tui_patch_variant.py` — `#patch_pane_variant` at :339, :388, :661, :670 (TC-035.2 variant-group-above-execute + AT-035a region before/after). **Disposition:** re-target to the new variant container/window; PRESERVE the variant-above-execute order invariant (`R-PATCH-VARIANT-SELECT-001`).
- **Validation:** `inspection` (census completeness) + the increment gate (`pytest -q`).
- **Numeric pass threshold:** post-supersession, `pytest -q` green with the 2 patch snapshot cells `xfail(strict=False)`; 0 stray reference to a retired structural id outside a "they're gone" negative assertion.
- **Acceptance criteria:** the two FINDING files (4, 5) are added to the increment file budget (§6.2 D-4); no leaf-id assertion weakened.

---

## 5. Validation strategy

### 5.1 Methods
- **Layer A — white-box / functional (`TC-NNN`):** `inspection` of `compose` structure (window ids, docked-row parentage) and `styles.tcss` (selector reuse, no new class); `test (integration)` of the leaf-id census; `analysis` of the 80×24 docked-row budget (LLR-064.2, deferred to Phase-3 pilot).
- **Layer B — black-box / behavioral acceptance (`AT-NNN`):** Textual Pilot e2e via `App.run_test(size=…)` + `action_show_screen("patch")`, asserting window/button geometry through the shipped surface with boundary (80×24 + 120×30) + reparent + RED-counterfactual evidence. `AT` ids are provisional-until-Phase-3 (V-5) and reconciled at Phase 4.
- All `AT`/`TC` node ids, `-k` selectors, and file paths above are **provisional-until-Phase-3** (V-5) and reconciled from the real tree at Phase 4.

### 5.2 Dual-traceability table

**Behavioral chain (black-box) — per user story:**

| US | Observable outcome | Shipped surface | Acceptance test (`AT-NNN`) | Observed? |
|----|--------------------|-----------------|----------------------------|-----------|
| US-U8 | 3 windows 3-across when wide | patch screen @120×30 | AT-063a | Phase 4 |
| US-U8 | 3 windows stacked when narrow | patch screen @80×24 | AT-063b | Phase 4 |
| US-U8 | leaf ids resolve + one action/window routes after reparent | patch screen @80×24 + @120×30 | AT-063c | Phase 4 |
| US-B2 | every named button docked/reachable at floor | patch screen @80×24 | AT-064a | Phase 4 |
| US-B2 | every named button docked/reachable when wide | patch screen @120×30 | AT-064b | Phase 4 |

**Functional chain (white-box) — per requirement:**

| Requirement | Method | Test Case (`TC-NNN`) | Notes |
|-------------|--------|----------------------|-------|
| HLR-063 | test (pilot) | AT-063a, AT-063b, AT-063c | behavioral gate |
| HLR-064 | test (pilot) | AT-064a, AT-064b | behavioral gate |
| LLR-063.1 | inspection + test | TC-063.1 (window ids + docked-row structure) | new white-box, supersedes `test_tc_pane_styles_and_grid` |
| LLR-063.2 | test (pilot) | AT-063a | wide budget |
| LLR-063.3 | test + inspection | AT-063b + `styles.tcss` selector grep | no-new-Python check (`app.py` diff = 0) |
| LLR-063.4 | test (integration) | AT-063c + updated `_PATCH_PRESERVED_IDS` / `_PRESERVED_REGROUP_IDS` census | leaf-id preservation |
| LLR-064.1 | test (pilot) | AT-064a, AT-064b | docked parentage |
| LLR-064.2 | analysis (deferred) | Phase-3 pilot measurement | `assumed — pilot-measure` |
| LLR-064.3 | inspection + gate | census (§4) + `pytest -q` | C-26 |

### 5.3 Batch acceptance criteria
- Every user story has ≥1 passing `AT` observing its outcome through the shipped surface, with boundary (80×24 + 120×30) + RED-counterfactual evidence.
- Every LLR covered by ≥1 `TC`/`AT` with a pass result (LLR-064.2 explicitly deferred-with-flag to Phase 3).
- `pytest -q` green with exactly the 2 `patch-comfortable-*` snapshot cells `xfail(strict=False)` (C-22 upper bound).
- **Frozen-engine diff = 0** (`test_engine_unchanged.py` + `test_tui_directionb.py::test_tc031_*` clean); `app.py` diff = 0 lines.
- 0 blocker fails; no requirement without an assigned validation method.

---

## 6. Appendices

### 6.2 Relevant design decisions

**D-1 — Window → content map (finalized).**
- **PATCH SCRIPT (`#patch_win_script`):** body = entries `DataTable` + empty-state + entry inputs (addr/value/bytes) + change-file `Select` + path input + variant `Select`+info + execute-scope. Docked rows = (a) entry Add/Edit/Remove/Edit-JSON + Undo/Redo; (b) Load/Refresh/Validate/Apply/Save; (c) Execute-scope + Execute. **Heaviest window — tightest docked budget (LLR-064.2).**
- **CHECKS (`#patch_win_checks`):** body = issue count + issues + checks status + results + checks help. Docked = Run checks.
- **JSON EDIT (`#patch_win_json`):** body = paste `CappedTextArea` + (revealed) save-back name input + before/after rows. Docked = Parse-pasted + Edit-JSON; save-back Write/Don't-save/Width; Write-before/after-report.

**D-2 — CSS-only responsive switch (D1-locked).** Reuse `width-narrow`; add `#workspace_body.width-narrow #patch_editor_panel { layout: vertical }` (+ window-row selector) mirroring `styles.tcss:626`/`:649`. No new Python. Reversibility: **one-way-door risk is LOW** — this is a declarative CSS reflow; reverting is deleting the rule. The only coupling is the panel's `#workspace_body` ancestry (A2.5 dependency) — flagged, not blocking.

**D-3 — Variant/execute placement + fallback ladder (resolves O-2, C-13.1).** Variant + execute-over-variants live in **PATCH SCRIPT** (semantically the "what/how to apply" column) despite it being heaviest, keeping the `R-PATCH-VARIANT-SELECT-001` variant-above-execute invariant local. **Pre-committed fallback if the 80×24 docked budget overflows (lowest-viable-rung-first, C-13.1):** (1) collapse the two entry-button rows into one wrapped row (recovers ~1 row); (2) relocate variant+execute into the CHECKS or JSON window (recovers a full group's rows — unbounded); (3) move a docked row to an off-screen key binding (last resort, unbounded). Rung selected in Phase 3 against the measured deficit, not bikeshedded at the gate.

**D-4 — Increment cut (≤5 files each; adjusted for the two FINDING files).**
- **Inc-1 (RED-first, 3 files):** `screens_directionb.py` (compose restructure) + `styles.tcss` (3-window layout + `width-narrow` reflow + docked rows; reconcile the patch CSS at `801-852` AND `985-1009`, incl. the duplicate `#patch_saveback_row` rule at `:838` and `:999`) + `test_tui_patch_layout.py` (supersede 2×2 → AT-063a/b/c + new TC-063.1 + docked-row AT-064a/b).
- **Inc-2 (census supersession, 4 files):** `test_tui_patch_editor_v2.py` (preserved-id set → window ids; re-target 2× `scroll_end`) + `test_tui_directionb.py` (section-title selector, FINDING 4) + `test_tui_patch_variant.py` (`#patch_pane_variant` re-target, FINDING 5) + `test_tui_snapshot.py` (`_batch46_patch_drift_marks` xfail set).
- **Inc-3 (docs, 2 files):** REQUIREMENTS.md (add R-TUI-063 / R-TUI-064 rows; §6.5 amendments to R-PATCH-2X2-LAYOUT-001, R-PATCH-2X2-SNAPSHOT-001, R-TUI-046, and a note on R-PATCH-VARIANT-SELECT-001) + this spec's traceability closeout.

**D-5 — C-28 not triggered.** All patch bindings `show=False` (`app.py:801,807,824,825`); no shared-chrome change → no footer snapshot census (stated per the control).

### 6.3 Open risks
- **R-1 (geometry, HIGH-attention).** Three bordered windows @120 may starve a window below usable width (A2). *Mitigation:* mandatory Phase-3 whole-budget pilot re-measure (C-13/C-23); if a window clips, D-3 rung 2 (relocate a group) applies.
- **R-2 (80×24 docked budget, HIGH-attention).** PATCH SCRIPT's 3 docked rows + a usable body may not fit the floor (LLR-064.2). *Mitigation:* D-3 fallback ladder, measured not derived.
- **O-1 (open question).** At 80×24 stacked, does the panel-level scroll suffice, or must inner window bodies each scroll (nested scroll)? *Resolve in Phase 3 by pilot; if nested scroll is needed, confirm AT-064a's "docked, not below fold" oracle still discriminates.* Flag for operator if it changes the UX (a window whose body scrolls independently inside a stacked panel).
- **R-3 (snapshot).** 2 patch cells drift; absorbed by `xfail(strict=False)`, regen in canonical CI (local regen forbidden — `reference_snapshot_regen_env`).
- **R-4 (census completeness).** The reverse-census is a heuristic, not a proof (A-2); the increment gate is the guarantee. Two files were already found beyond the kickoff's named set — treat any further gate-surfaced reference as a Phase-3 finding, not a failure.

### 6.4 Phase-1 reconciliation log
No LLR threshold was relaxed or promoted during drafting (first draft of a new batch). The only reconciliations are the §6.5 amendments to prior locked rows (below), each with a parent re-read. No `§3/§4` HLR/LLR threshold contradicts its decomposition.

### 6.5 Requirement amendments (Before / After · Deleted / New)

**Amendment A-1 — R-PATCH-2X2-LAYOUT-001 (REQUIREMENTS.md:3290) — SUPERSEDED.**
- **Before:** "The Patch Editor shall lay its four area-panes out as a 2×2 grid — `#patch_pane_entries` … `#patch_pane_variant` … `#patch_editor_panel` shall be `layout: grid; grid-size: 2 3` with `grid-rows: 1fr 1fr auto` … `#patch_doc_controls` … `layout: grid; grid-size: 3` … The 2×2 holds at both supported terminal sizes."
- **Stale-text reconciliation (required before amending):** the row's text says `grid-size: 2 3` / `grid-rows: 1fr 1fr auto`, but the LIVE code is `grid-size: 2 4` / `grid-rows: 1fr 2fr 2fr auto` (`styles.tcss:806-808`), changed by batch-36 US-058 (paste reparent) without updating this row. The amendment supersedes the whole grid regardless of which text was current.
- **After:** superseded by **R-TUI-063** (responsive three-window layout) + **R-TUI-064** (docked reachability). The four-pane 2×2 grid is retired; `#patch_editor_panel` becomes a three-window horizontal/stacked layout.
- **Deleted tokens:** `#patch_pane_entries`, `#patch_pane_changefile`, `#patch_pane_checks`, `#patch_pane_variant`, `grid-size: 2 3`/`2 4`, `grid-rows: 1fr 1fr auto`/`1fr 2fr 2fr auto`, `#patch_doc_controls grid-size: 3` (as a 2×2-fit device), AT-033a/AT-033b/AT-033c, TC-033.
- **New tokens:** `#patch_win_script`, `#patch_win_checks`, `#patch_win_json`, `#workspace_body.width-narrow #patch_editor_panel`, AT-063a/AT-063b/AT-063c, TC-063.1.
- **Parent-HLR re-read:** parent was batch-22 HLR-033 (2×2 reparent). Re-read → the reparent-safety intent (every leaf id survives) is PRESERVED and carried forward verbatim in LLR-063.4; only the geometry (2×2 → 3-window) changes. No orphaned LLR: LLR-033.1-033.4 are wholly superseded by LLR-063.1-063.4.
- **Re-derived requirement + tests:** R-TUI-063 (AT-063a/b/c, TC-063.1); R-TUI-064 (AT-064a/b).

**Amendment A-2 — R-PATCH-2X2-SNAPSHOT-001 (REQUIREMENTS.md:3295) — SUPERSEDED.**
- **Before:** "The Patch Editor 2×2 layout shall be pixel-locked by SVG snapshot cells at 80×24 and 120×30 … both patch cells ride `xfail(strict=False)` until the CI baseline lands."
- **After:** the pixel lock now targets the three-window layout; the two `patch-comfortable-*` cells re-drift and ride `_batch46_patch_drift_marks` (`xfail(strict=False)`) until the post-merge canonical-CI regen, then flip to `Automated`.
- **Deleted tokens:** AT-034a/AT-034b as 2×2 locks; the batch-22 baseline.
- **New tokens:** `_batch46_patch_drift_marks`; the regenerated three-window `patch-comfortable-*` baselines.
- **Parent-HLR re-read:** batch-22 HLR-034 (snapshot lock). Re-read → the "lock the pixels once the CI baseline exists, behavioral proof carries the gate" mechanism is unchanged; only the pinned layout changes. No threshold relaxed.
- **Re-derived tests:** `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-80x24 / -120x30]` under the new drift-marks helper.

**Amendment A-3 — R-TUI-046 (REQUIREMENTS.md:3438, batch-36 paste reparent) — AMENDED.**
- **Before:** "The Patch Editor shall render the change-set paste editor (`#patch_paste_text`, wrapped by `#patch_paste_row`) in its own top-level panel cell — reparented out of the crowded `#patch_pane_changefile` pane and column-spanning both grid columns …"
- **After:** the paste editor moves into the **JSON EDIT window** (`#patch_win_json`) body; its "first line in-viewport at `scroll_y == 0`, separated from the change-file cluster" intent is preserved and re-observed by the JSON-window Acceptance (AT-063a for placement + AT-063c for reparent-safety). `#patch_paste_row` structure and `column-span: 2` are retired.
- **Deleted tokens:** `#patch_pane_changefile` (as the paste's ex-parent), `column-span: 2` paste cell, `grid-size: 2 4`/`grid-rows: 1fr 2fr 2fr auto`, AT-058a's 2×2-context assertion.
- **New tokens:** `#patch_win_json` as the paste's parent window; the JSON-window in-viewport assertion folded into AT-063a/063c.
- **Parent-HLR re-read:** batch-36 HLR (US-058 readable paste cell). Re-read → the readability outcome (paste first line in-viewport, not below a fold) is STRENGTHENED (a dedicated window body, not a crowded pane); the `#patch_paste_text` leaf id is preserved (LLR-063.4). No behavior change.

**Amendment A-4 — R-PATCH-VARIANT-SELECT-001 (REQUIREMENTS.md:3306, batch-23) — NOTE (no statement change).**
- **Note:** the variant `Select`+info and execute rows move from `#patch_pane_variant` into the PATCH SCRIPT window (`#patch_win_script`, §6.2 D-3). The row's normative content — `#patch_variant_select` present/disabled behavior, activation pipeline, persist-on-save, variant-**above**-execute order — is UNCHANGED and preserved by LLR-063.4. Only the container id `#patch_pane_variant` (a structural id, not in the row's normative leaf set) is retired; `tests/test_tui_patch_variant.py` references to it are re-targeted (LLR-064.3 FINDING 5). No parent-HLR threshold change.

---

### 6.6 Phase-2 review fold (AUTHORITATIVE amendments — supersede the sections they name)

> Triple review folded 2026-07-15 (full record + affirmations: `02-review.md`). No blockers; the D1 CSS-reuse
> and app-side reparent-safety mechanisms were independently VERIFIED. The deltas below are binding for Phase 3.

- **FOLD-1 (design change — supersedes LLR-063.4 "SAFE to retire" + LLR-064.3 disposition + §6.2 D-1/D-4; M-A2/M-A1).**
  **PRESERVE, do not retire, the structural container ids** `patch_pane_entries` (:2374), `patch_pane_changefile` (:2447),
  `patch_pane_variant` (:2504), and `patch_doc_file_row` (:2445) — re-cast as **non-scrolling grouping sub-containers**
  (`height: auto`, scroll lives on the window body) inside the three new windows. Rationale: keeps
  `test_tui_patch_variant.py` (`#patch_pane_variant` children order, TC-035.2) and `test_tui_directionb.py`
  (`#patch_pane_entries .patch-section-title`) GREEN unchanged, and holds a 5-file atomic green boundary (no >5-file
  exception). `patch_pane_checks` (:2466) is referenced ONLY by the superseded `test_tui_patch_layout.py` → may be
  retired or reused as the CHECKS window body. **NEW must-preserve ids:** `patch_variant_row` (:2488),
  `patch_execute_row` (:2502). **KEEP (a-m2)** the intermediate containers `patch_doc_entry_inputs`,
  `patch_doc_entry_buttons`, `patch_history_controls`, `patch_paste_controls`, `patch_saveback_buttons`,
  `patch_before_after_buttons` (CSS-referenced; retiring orphans their rules).
- **FOLD-2 (supersedes LLR-063.2 numeric threshold; M-A3 + M-Q1).** Wide-regime threshold becomes: *each window
  `region.width` ≥ `MIN_USABLE_W` and `region.height` ≥ `MIN_USABLE_H` (both pilot-measured @80×24 + @120×30, C-23),
  the three sum within host content, non-overlapping, no right-edge clip.* The wide column ratio is **NOT** operator-locked
  (only the narrow STACK is D1) → an asymmetric `grid-columns: 2fr 1fr 1fr` keeping variant/execute local in PATCH SCRIPT
  is permitted; the ratio is a Phase-3 pilot-measured, then-recorded design call.
- **FOLD-3 (strengthens AT-063c; M-Q2 + C-10).** Reparent-safety AT asserts an **observable effect per window**: PATCH
  SCRIPT `add_entry`→row_count+1; CHECKS `run_checks`→`Checks:` log line; JSON EDIT — seed `#patch_paste_text` + `parse_pasted`
  → observable effect (entries populate / status changes); NOT mere `resolves`.
- **FOLD-4 (restores the R-TUI-046 verifier; M-Q3 — reconciles Amendment A-3 with 01b §6).** Add `#patch_paste_text` to
  the `_fully_visible` named set AND a dedicated **JSON-window in-viewport TC** (paste first line within its window body at
  `scroll_y == 0`). This is the single authoritative destination for the paste-in-viewport outcome (A-3's "AT-063a/063c"
  and 01b §6's "AT-064a/b/TC-46.2" are both superseded by this).
- **FOLD-5 (NEW gate-blocking acceptance AT-064c; M-Q4 + C-21).** `AT-064c` (US-B2): reveal `#patch_saveback_row` +
  `#patch_before_after_row` (drive the reveal), pause, assert `_fully_visible` on `patch_saveback_confirm_button`,
  `patch_saveback_decline_button`, `patch_saveback_width_button`, `patch_before_after_button` at 80×24. Registered under
  HLR-064; owned by Inc-1. **AT registry is now AT-063a/b/c + AT-064a/b/c (6).**
- **FOLD-6 (C-17 hardening; security F1/F4 → TC-46.3).** The reparent-safety TC additionally asserts
  `app.query_one("#patch_checks_status", Label)._markup is False`, `app.query_one("#patch_doc_issues", Static)._markup is False`,
  and `isinstance(app.query_one("#patch_paste_text"), CappedTextArea)`. C-17 backstops (cited, must not be weakened in Inc-1):
  `test_tui_patch_editor_v2.py::AT-051e` + `test_loadfilescreen_input.py::test_ac2h`. Window titles stay CONSTANT strings
  (never a `border_title` with file-derived text).
- **FOLD-7 (minor reconciliations).** Canonical window ids `patch_win_script/_checks/_json` (q-m1). AT-063a/b RED
  counterfactual keyed to the **preserved pane-lead ids** for a true 2-vs-3-column discriminator (q-m2). TC-46.1 made
  **layout-agnostic** (assert 3-window structure + width-narrow rule, not `layout.name`) (q-m3). The 14 leaf ids are the
  **wiring-critical subset** explicitly guarded; the rest are covered by the increment gate (a-m1). Drop the dead
  `#patch_saveback_row { column-span: 2 }` at `styles.tcss:838`; the `:999`-block rule survives (a-m3).
- **Re-cut increment plan (supersedes §6.2 D-4):** Inc-1 = `screens_directionb.py` + `styles.tcss` +
  `test_tui_patch_layout.py` + `test_tui_snapshot.py` + `test_tui_patch_editor_v2.py` (5 files, atomic green). Inc-2 =
  `REQUIREMENTS.md` + this spec's closeout (2 files). `test_tui_patch_variant.py` + `test_tui_directionb.py` DROPPED
  (pass unchanged under FOLD-1; confirmed at the Inc-1 full-suite gate).

- **FOLD-8 (ITERATE-TO-REFINE — Phase-3 measurement-driven amendment of AT-064; operator-approved 2026-07-15).**
  **Trigger:** Inc-1 pilot measurement (real app, current tree) — the patch panel content area is **70w × 5h @80×24**
  and **92w × 11h @120×30**; Textual `Button` height = 3. 17 named buttons + 3 window titles **cannot** be
  simultaneously visible in the 5-row @80×24 viewport under ANY docking strategy (the app chrome — command bar +
  status + footer — consumes the rest, and `app.py` layout is frozen 0-diff this batch). This is the **deferred
  app-start-geometry starvation** realized on the vertical axis (C-16 prototype-non-transfer: the prototype ran the
  patch editor as the whole ~22-row screen). The original AT-064a/064c threshold ("every named button `_fully_visible`,
  `off == []`, at 80×24") is therefore **physically unachievable** — the requirement is wrong, not the implementation
  (black-box-fails / white-box-would-pass ⇒ iterate-to-refine).
  - **Before (AT-064a / AT-064c):** at 80×24 every named action button is `_fully_visible` (`off == []`).
  - **After (AT-064a / AT-064c — REACHABLE-UNDER-SCROLL):** at 80×24 every named action button is **reachable** — it
    becomes `_fully_visible` after its window is scrolled into the panel viewport — and **none is trapped below an
    inner-body fold** (the docked button-row is a sibling of, not inside, the window's `VerticalScroll`, so scrolling
    the window/panel brings it into view; a button reachable ONLY by scrolling a nested inner body = FAIL). This is the
    ACTUAL field-audit B2 defect (buttons overflow a starved `1fr` cell fold, scroll fragmented across ~5 regions).
  - **AT-064b (120×30):** TARGET remains strict all-visible (`off == []`); the implementer applies the §6.2 D-3
    fallback ladder (consolidate the two entry-button rows → relocate variant/execute → key-binding) to fit the
    heaviest (PATCH SCRIPT) column in 11 rows. If measurement proves even the consolidated layout cannot fit all
    docked buttons at 120×30 for a window, that window falls back to reachable-under-scroll at 120×30 too, with the
    measured deficit + applied rung RECORDED (a pre-approved degradation, not a new blocker).
  - **Deleted tokens:** `off == [] @80×24` as the AT-064a/064c gate.
  - **New tokens:** reachable-under-scroll oracle (`_fully_visible` after `scroll_visible`/window-into-viewport); the
    "none trapped below an inner-body fold" invariant (docked-row-is-body-sibling, already TC-46.x).
  - **Parent-HLR re-read:** HLR-064 ("each window's buttons docked outside its scrollable body … so every button
    renders within the screen region and is not clipped below its window body's scroll fold"). Re-read → the DOCKING
    mechanism + "not clipped below the BODY fold" intent is PRESERVED and is the real fix; only the over-strong
    "all simultaneously visible at the 5-row floor" acceptance is relaxed to reachability. HLR-064 statement amended:
    "…is reachable (visible when its window is scrolled into view) and not clipped below its window body's scroll fold."
  - **Re-derived tests:** AT-064a/064c reachability oracle; AT-064b strict-with-fallback. No change to AT-063a/b/c.

---

### Evidence checklist (architect)
- [x] Constraints stated explicitly — §2.4 (D1, frozen diff, C-13/C-13.1/C-22/C-23/C-28).
- [x] ≥2 alternatives considered — §6.2 D-3 (variant placement + 3-rung fallback ladder); id-preservation strategy (retire-all vs the leaf-only preserve, resolved to retire-structural + supersede-tests).
- [x] Recommendation tied to constraints — D1-locked CSS reuse (`app.py:4903-4940`), reparent-safety from the verified message-based wiring (A1).
- [x] Risks listed — §6.3 (geometry R-1, docked budget R-2, open question O-1, snapshot R-3, census completeness R-4).
- [x] Cost/latency — N/A (pure view layout; no runtime cost surface). Geometry budget flagged `assumed — pilot-measure Phase 3`.
- [x] Diagram — not required (layout described by the window→content map D-1; the geometry is measured, not drawn).
- [x] What would change the recommendation — if the Phase-3 pilot shows a window starves below usable width (A2) or the 80×24 docked budget overflows (R-2), apply the D-3 fallback ladder; if the panel is moved out of `#workspace_body`, the CSS reuse (D-2) breaks and a new selector root is needed.
- [x] Two-layer requirements — every US has a first-class Acceptance block + `AT-NNN` (§3) and both traceability chains exist (§5.2).
