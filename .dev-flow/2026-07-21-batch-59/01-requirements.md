# Requirements Document — s19_app — Batch 59 (CRC Designer VIEW-FIDELITY rebuild — the "coverage-first bench")

> Artifact language: **English** (engineering batch). Normative keyword: `shall`.
> Governing design (APPROVED): Variant B "coverage-first bench" — prototype `prototypes/crc_designer.b59.inapp_prototype.py` (validated sub-shape A; mounts inside the real `S19TuiApp`).
> Predecessor: batch-58 (MERGED #112, origin/main `ef5145b`) shipped the CRC Designer **function** correctly. Its **functional requirements** (US-E4/E5/E6, US-V1..V8; HLR/LLR-E4..V8) are SATISFIED and are **referenced, not re-derived** here.
> Branch: `feat/batch-59-crc-designer-bench` (base = origin/main tip).

---

## 1. Introduction

### 1.1 Purpose
Specify batch-59: a **VIEW-FIDELITY rebuild** of the CRC Algorithm Designer screen. batch-58 shipped the engine, live KAT verdict, multi-range coverage compute, gap-safety, Load/Save and JSON preview — all functionally correct — but rendered them as a **single flat vertical form** that does NOT match the approved **Variant B "coverage-first bench"** design. Batch-59 fixes ONLY the layout/presentation: re-composing `CrcDesignerPanel.compose` into the bench and adding the supporting `styles.tcss` layout. **Zero engine change; zero functional-behavior change.**

### 1.2 Scope
**In scope (LAYOUT / fidelity layer only)**
- Re-compose `s19_app/tui/crc_designer_view.py::CrcDesignerPanel.compose` into the Variant B bench:
  - a **hero ROW** at the top (`#crc_hero_row`): the wide rendered coverage-window (`#crc_coverage_window`, 2fr — block-glyph rendering of the multi-range memory window: present bytes / erased gap / pad-filled gap, plus the two policy CRCs and the store-word bytes) beside a **right column** (`#crc_top_right`, 1fr) holding the KAT **verdict hero** above the **Warnings** tile;
  - a **3-column bench** below (col1 = Algorithm + Serialization; col2 = Coverage controls + Custom vector; col3 = Job JSON (roomy) + Template + Load/Save). *(Operator layout refinement, 2026-07-21: verdict + Warnings moved OUT of col3 into the hero row; see §6.7 amendment A1.)*
- Add the supporting CSS in `s19_app/tui/styles.tcss` (the `crc-*` classes + the new `#crc_hero_row`, `#crc_top_right`, `#crc_bench*`, `#crc_coverage_window`, `#crc_live_verify` rules), honoring the existing `width-narrow` reflow cascade for BOTH the hero row and the bench.
- Add ONE view-side render method for the coverage-window glyphs (view logic, non-frozen; reuses `crc_designer_model` primitives verbatim — no new math).
- Add **design-fidelity + preservation acceptance tests** (new/extended non-frozen test file).

**Out of scope**
- Any engine change. `crc_kernel`, `crc_designer_model`, `crc_template`, `crc.py`, all `operations/` primitives are REUSED VERBATIM.
- Any change to `#crc_*` widget **ids**, their **handlers**, or the recompute wiring (`on_input_changed` / `on_switch_changed` / `on_select_changed` / `on_button_pressed` / `_recompute`). Same ids ⇒ the shipped KAT / coverage / JSON / Load-Save handlers stay wired.
- Any change to `app.py::_compose_screen_crc_designer` (it mounts `CrcDesignerPanel()`; the bench lives entirely inside the panel).
- Any change to the rail wiring (`RAIL_ENTRIES`, `SCREEN_CONTAINER_IDS`, key `0`) — already shipped in batch-58.
- New functional behavior (no new field, no new compute, no new Load/Save path).
- The engine-frozen set (§2.4).

### 1.3 Definitions, acronyms, abbreviations
| Term | Definition |
|------|------------|
| Bench | The Variant B layout: a full-width **hero row** (coverage window + verdict/warnings right column) over a 3-column grid of parameter groups. |
| Hero row | The full-width top row `#crc_hero_row` (Horizontal) holding `#crc_coverage_window` (2fr) beside `#crc_top_right` (1fr, Vertical) which stacks the verdict hero above the Warnings tile. |
| Coverage window (hero) | A rendered `Static` (`#crc_coverage_window`, NEW) drawing the multi-range memory window in block glyphs (`█` present / `░` erased gap / `█`-in-warning-hue pad-filled gap) plus the concat/fill policy CRCs and the store-word bytes. It **renders** coverage, it does not label it. |
| Verdict hero | The KAT verdict container (`#crc_live_verify`, existing id) placed in the hero row's `#crc_top_right`, styled as a distinct **center-aligned** (`content-align: center middle`) `crc-hero` box holding `#crc_kat_verdict`. The distinguishing property is the center alignment, NOT a border (every `.crc-field-group` already has a border). |
| Design-fidelity acceptance | An AT that asserts the **signature layout elements** exist and are rendered on the shipped `#screen_crc_designer` (rendered+colored window, multi-column container, verdict hero) — not merely that functional widgets exist. Closes the batch-58 gap. |
| Preservation | A batch-58 functional behavior still fires through the re-nested widget tree (same id ⇒ same handler). |

### 1.4 References
- Prototype (validated target layout): `prototypes/crc_designer.b59.inapp_prototype.py`.
- Shipped panel (re-arranged, not re-implemented): `s19_app/tui/crc_designer_view.py`.
- batch-58 requirements (functional layer, satisfied — referenced): `.dev-flow/2026-07-20-batch-58/01-requirements.md`.
- Central stylesheet + theme tokens: `s19_app/tui/styles.tcss` (`$accent-calm: #91abec` `styles.tcss:26`; `.sev-warning { color:#f6ff8f }` `styles.tcss:636-637`; `width-narrow` reflow cascade `styles.tcss:243-326`).
- Existing view tests (extended): `tests/test_crc_designer_view.py`.
- Stack controls: `docs/engineering-rules.md` (C-13/C-13.1/C-23 geometry; C-22/C-28 snapshot census; C-30 restyle sequencing). Global controls: C-10 branch-ATs, C-16 prototype-fidelity, C-17 markup-safety, C-31 assert-painted-result / input-set-is-an-oracle, C-35 draft-time execution probe.

### 1.5 Document overview
§2 overall description + constraints. §3 HLR (EARS). §4 LLR. §5 validation strategy + dual traceability. §6 appendices (design decisions, risks, draft-time verification log, open questions, evidence checklist).

---

## 2. Overall description

### 2.1 Product perspective
The CRC Designer function is complete and green (batch-58). The operator's complaint is presentational: the approved Variant B bench renders the coverage as the visual centerpiece, but the shipped screen is a plain top-to-bottom form (because the referenced `crc-*` CSS classes are **entirely undefined** — see §6.4 V-1 — so the panel falls back to Textual's default vertical stacking). Batch-59 supplies the missing layout: the CSS the classes were always meant to have, a 3-column re-composition, and the signature rendered coverage window — reusing every shipped widget id and handler so the function is carried across untouched.

### 2.2 Product functions
1. Present the multi-range coverage as a **rendered block-glyph window** in a full-width **hero row** at the top, beside the verdict + Warnings right column.
2. Lay the parameters out as a **3-column bench** (col3 = Job JSON roomy + Template + Load/Save) rather than one vertical column.
3. Present the **KAT verdict** as a distinct **center-aligned** `crc-hero` element in the hero row's right column.
4. **Preserve every batch-58 functional behavior** through the re-nested layout (proven by a reused handler firing + the existing suite passing unchanged).
5. Encode **design-fidelity acceptance** with structural teeth: the ATs assert the signature elements in a way a flat-form regression would fail.

### 2.3 User characteristics
Single role: the **operator** (firmware engineer) already using the CRC Designer rail screen (key `0`). No new permissions; the view stays preview-only (US-V8, batch-58, PRESERVED).

### 2.4 Constraints
- **C-16 (prototype-fidelity):** the prototype is Python/Textual — the same framework as the target — but its LAYOUT and its coverage-window RENDER content are unverified until the real `CrcDesignerPanel` is re-composed. Every fidelity AT drives the REAL shipped `#screen_crc_designer` through Textual Pilot (`App.run_test()`), never the prototype and never a proxy widget.
- **C-17 (markup-safety) — PRESERVED, not re-derived:** every file/template-derived sink in the panel already renders `markup=False` (`crc_designer_view.py` help/verdict/vector/preview/warnings/status/coverage Statics, e.g. `:352-357`, `:326`). Batch-59 re-nests these widgets verbatim and introduces exactly one NEW sink — the coverage window `#crc_coverage_window` — which shall ALSO render `markup=False`. On the happy path it draws from `mem_map` bytes + typed range ints, but on the invalid-range branch the operator's raw range token reaches the sink verbatim (`_parse_ranges` echoes `{token!r}`, `crc_designer_view.py:764`), so the sink's safety rests on **`markup=False`**, NOT on the source being int-only (security F2, §6.7 A11). AT-B59-09 proves the literal render. No new untrusted-text surface bypasses `markup=False`.
- **Engine-frozen set OFF-LIMITS (0 diffs):** `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`, and the frozen TEST files (`tests/test_engine_unchanged.py`, `tests/test_tui_directionb.py::test_tc031_*`). `crc_designer_view.py` is a VIEW (non-frozen). All batch-59 edits land in `crc_designer_view.py`, `styles.tcss`, and a non-frozen test file.
- **`app.py` orchestration-only (CLAUDE.md):** untouched — the bench is composed inside the panel, not in `app.py`.
- **Geometry (C-13/C-13.1/C-23):** the 3-column bench shall honor the existing `#workspace_body.width-narrow` reflow (`styles.tcss:243-326`) — at the narrow regime the columns stack rather than crush to unreadable widths. No hand-asserted column widths; the fit is pilot-measured at Phase 3 (C-23), measuring BOTH axes of the real boxed panel, not a full-screen prototype budget (C-29).
- **Snapshot census (C-22/C-28):** measured, not assumed. The `test_tc016s_*` suite captures `workspace/a2l/mac/issues/map/patch/diff` ONLY (`test_tui_snapshot.py:109-110`) — `crc_designer` is NOT among them and there is NO crc-specific SVG baseline (verified §6.4 V-5). The predicted drift is therefore **zero existing tc016s cells**. Phase 3 runs the census to CONFIRM 0 drift (a shared-renderer/self-contained change that drifts 0 foreign cells validates the sequencing, C-30 corollary); any surprise drift is regen'd only in canonical CI (`snapshot-regen.yml`, textual==8.2.8) — local regen FORBIDDEN.

### 2.5 Assumptions and dependencies
- **A1 — every `#crc_*` id and handler is carried verbatim.** Verified: all 29 ids used by handlers exist in the shipped `compose` (§6.4 V-2). The re-composition only moves them into column containers; `query_one("#…")` resolves a descendant anywhere in the subtree, so every handler keeps working. If a rename is proposed mid-implementation, the binding LLR must be re-reconciled and the preservation ATs re-run.
- **A2 — the `crc-*` CSS classes are currently undefined.** Verified (§6.4 V-1): `styles.tcss` contains zero `crc` matches and the panel has no `DEFAULT_CSS`. Batch-59 DEFINES them for the first time — additive CSS, no override risk.
- **A3 — the coverage window renders LIVE from data the view already computes.** The hero draws from the current ranges (`_parse_ranges`), the loaded `mem_map` (`self.app.current_file.mem_map`), the pad byte and the policy CRCs — all already produced by `_build_coverage_target` / `compute_target_crc` / `_coverage_preview_text` (`crc_designer_view.py:735-875`). It reuses those primitives; it adds NO engine math. (Decision D-1, §6.2 — the prototype's window is a hardcoded MOCK; the shipped window must render real coverage per the "renders, not labels" design intent.)
- **A4 — theme tokens exist for two of the three cues.** Verified: `$accent-calm=#91abec` (present-byte accent) and `.sev-warning=#f6ff8f` (pad-fill yellow) are declared (§6.4 V-4). The prototype's remaining hardcoded hexes (success green `#8ff6a0`, panel borders `#2b3a5e`/`#161d31`) are `assumed — reconcile to theme tokens or declare new tokens at Phase 3`; the CSS shall not hardcode `$accent-calm`'s value.
- **A5 — Textual-framework fidelity (C-16).** Interaction assumptions (the window re-renders on a range edit via `_recompute`; the bench reflows via the `width-narrow` cascade) are `assumed — verify in Textual at Phase 3`; the ATs drive the real events.

### 2.6 Source user stories

| ID | User Story | Source | DoR |
|----|------------|--------|-----|
| US-L1 | As the operator, I want the multi-range coverage rendered as a wide block-glyph window at the top of the CRC Designer, colored by coverage state, so that I SEE the memory window and the effect of my policy choices at a glance instead of reading a label. | Variant B hero; prototype `_coverage_window` + `#crc_coverage_window` | READY |
| US-L2 | As the operator, I want the parameters laid out in a 3-column bench below the window, so that the algorithm, coverage and verdict groups are scannable side-by-side rather than stacked in one long vertical scroll. | Variant B 3-column grid; prototype `#crc_bench`/`_c1..c3` | READY |
| US-L3 | As the operator, I want the known-answer verdict presented as a distinct bordered hero box, so that the single most important correctness signal is visually unmistakable. | Variant B verdict hero; prototype `#crc_live_verify` styling | READY |
| US-L4 | As the operator, I want every batch-58 behavior (KAT recompute, coverage preview, JSON round-trip, Load/Save) to keep working exactly as before through the new layout, so that the re-skin costs me nothing functionally. | Preservation requirement; batch-58 US-V1..V8 | READY |
| US-L5 | As the reviewer, I want the acceptance tests to assert the signature layout elements are present and rendered on the shipped screen — with assertions a reverted flat form would fail — so that a future regression to the vertical form is caught, not silently shipped. | Design-fidelity discipline (closes the batch-58 gap); C-10/C-31 | READY |

#### Refinement log (condensed)

**US-L1 — coverage-window hero** · INVEST ✓✓✓✓✓✓ · user=operator · outcome=`#crc_coverage_window` Static renders block glyphs (`█`/`░`) in ≥2 colors reflecting present/erased/pad-filled state, plus the concat+fill policy CRCs and store-word bytes; content DELTAS when ranges change; empty-image → a graceful note · out of scope: any NEW compute (reuses `_coverage_preview_text` data). Evaluability: window present + glyph chars + ≥1 colored span (AT-B59-01); glyph segmentation changes on a range edit (AT-B59-02). C-17: `markup=False`, mem_map/int-only source. Class: READY.

**US-L2 — 3-column bench** · INVEST ✓✓✓✓✓✓ · outcome=`compose` yields `#crc_bench` (Horizontal) with `#crc_bench_c1/_c2/_c3` (Vertical) holding the regrouped `.crc-field-group`s (c3 = Job JSON roomy + Template + Load/Save); the algorithm (c1), coverage controls (c2) and Job JSON (c3) live in DISTINCT bench columns (the verdict + warnings live ABOVE the bench in the hero row); honors `width-narrow` stack. Evaluability: multi-column container present + `#crc_field_width`/`#crc_coverage_ranges`/`#crc_json_preview` in pairwise-distinct column ancestors (AT-B59-03); columns stack at width-narrow (AT-B59-04). Class: READY.

**US-L3 — verdict hero** · INVEST ✓✓✓✓✓✓ · outcome=`#crc_live_verify` in the hero row's `#crc_top_right` carries the center-aligned `crc-hero` styling (`content-align: center middle` — the distinguishing property; every group already has a border), `#crc_kat_verdict` is its descendant. Evaluability: hero container present in the hero row + `content_align == center/middle` (finest discriminator) + verdict descendant (AT-B59-05). Class: READY.

**US-L4 — functional preservation** · INVEST ✓✓✓✓✓✓ · outcome=all 29 `#crc_*` ids + handlers unchanged; a reused handler fires through the new tree; the existing `tests/test_crc_designer_view.py` suite passes unchanged. Evaluability: KAT recompute transitions through the re-nested widget (AT-B59-06); full existing suite green (AT-B59-07). Class: READY.

**US-L5 — fidelity gate with teeth** · INVEST ✓✓✓✓✓✓ · user=reviewer · outcome=the L1-L3 ATs derive their asserted set from the composed tree (C-31) and assert a property the flat form LACKS (colored block-glyphs / distinct column ancestors / bordered hero), so a single-column revert fails ≥1 fidelity AT. Evaluability: the "distinct column ancestors" assertion (AT-B59-03) is FALSE in the shipped flat form → teeth demonstrated (AT-B59-08). Class: READY.

---

## 3. High-level requirements (HLR)

### HLR-L1 — Rendered coverage-window hero
- **Traceability:** US-L1
- **Statement:** The CRC Designer view shall present, at the top of `#screen_crc_designer` above the parameter columns, a rendered coverage window (`#crc_coverage_window`) that draws the current target's multi-range memory window in block glyphs colored by coverage state (present bytes in the accent hue, erased inter-range gap in a muted hue, pad-filled gap in the warning hue) together with the concat and fill policy CRC values and the store-word bytes, re-rendered whenever the coverage inputs change, and rendered `markup=False`.
- **Rationale (informative):** the Variant B signature — the screen renders the coverage rather than labeling it.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k coverage_window`
- **Numeric pass threshold:** exit 0.
  - **AT-B59-01 (rendered + colored + live-content + markup-safe):** on the mounted screen with the §3.2 batch-58 `_fixture_mem` image loaded (the two-range `0x8000-0x8008, 0x8010-0x8018` seed, `join="fill"`), `#crc_coverage_window` exists, its rendered content is non-empty and contains ≥1 block-glyph char (`█` or `░`); its rendered spans carry **≥2 DISTINCT colors** — `len({span.style for span in rendered.spans}) >= 2` (distinct styles, NOT ≥2 span objects — a monochrome window with 3 same-color runs is exactly the label this rejects); the sink is markup-safe — `window._render_markup is False` (the one NEW C-17 sink); and the rendered `.plain` CONTAINS the pinned oracles **`0x9C5BCBBD`** (concat policy CRC) AND **`0x2A8A3950`** (fill policy CRC) — the exact `test_crc_designer_view.py:617-620,687-688` oracle values for this fixture, proving the window renders LIVE computed coverage, not a hardcoded-hex mock (OQ-1 / B2). *(m3 — the color assertion reads `rendered.spans` from `Static(text, markup=False).render()`; the positive direction — a styled `rich.Text` keeps its spans through `markup=False` — is `assumed — verify Phase 3`; if `Static` drops the spans, read the renderable directly so the color assertion stays executable.)*
  - **AT-B59-02 (delta + oracle re-pins on live data):** after changing `#crc_coverage_ranges` to a SINGLE range through the mounted input, the window's rendered content DIFFERS from the two-range content (a measured delta, not "content present"), AND the shown concat/fill hexes equal the recomputed single-range oracles (`compute_target_crc` over the same `mem_map`, reused verbatim — 0 new math) — a range-width-only mock that never touches `mem_map`/CRC would delta but MISS the oracle, closing the partial-mock hole (B2).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** a colored block-glyph window renders at the top of the hero row, reflecting the active ranges/policy AND the real computed policy CRCs.
  - **Shipped surface:** `#crc_coverage_window` (NEW id, `markup=False`) in `#crc_hero_row` of `CrcDesignerPanel.compose`, fed by a NEW view-side `_render_coverage_window()` reading `mem_map` + the coverage-target ints (reuses `_build_coverage_target` `:771` / `compute_target_crc`, `crc_designer_view.py:771-875`), wired into `_recompute` (`:877`).
  - **Deliverable + observation:** the mounted window widget's rendered `Text`, read via Pilot; glyphs + distinct-color set + `_render_markup` + the concat/fill oracle substrings asserted; the two-range→one-range delta + re-pinned oracle observed.
  - **Boundary catalog:** ☑ empty (no image loaded → graceful empty-state note reusing the shipped `_coverage_preview_text` string `crc_designer_view.py:850-851`, no glyph compute — **AT-B59-10**) ☑ boundary (single range → no inter-range gap segment — AT-B59-02) ☑ invalid (malformed ranges → markup-safe note, no crash — reuses `_parse_ranges` fault path — **AT-B59-11**; hostile markup — **AT-B59-09**) ☑ error (window never mutates `mem_map`, US-V8 preserved; R-4).

### HLR-L2 — 3-column bench layout
- **Traceability:** US-L2
- **Statement:** The view shall compose the parameter groups into a three-column bench (`#crc_bench`) BELOW the hero row — column 1 the Algorithm and Serialization groups, column 2 the Coverage and Custom-vector groups, column 3 the Job JSON (roomy), Template and Load/Save groups — such that the three columns render side-by-side at the comfortable width and stack under the existing `width-narrow` regime. *(The verdict hero and Warnings do NOT live in the bench — they occupy the hero row's `#crc_top_right`, per LLR-L2.3; operator layout refinement, §6.7 A1.)*
- **Rationale (informative):** the Variant B grid replaces the single vertical column; the two most-scanned signals (coverage window, verdict) sit ABOVE the bench in the hero row.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k bench_columns`
- **Numeric pass threshold:** exit 0.
  - **AT-B59-03 (structural teeth — re-derived to the confirmed layout):** on the mounted screen a `#crc_bench` container exists with ≥3 child column containers, and the three probe widgets `#crc_field_width` (c1), `#crc_coverage_ranges` (c2) and `#crc_json_preview` (c3) — all chosen from the ACTUAL bench columns — have **PAIRWISE-DISTINCT ancestor containers** among `{#crc_bench_c1, #crc_bench_c2, #crc_bench_c3}`. The assertion computes `len({column_ancestor(w) for w in the three}) == 3`; in the shipped flat form all three collapse to the single `#crc_designer_panel` ancestor → set size 1 → the assertion is FALSE, so the teeth survive the fold. *(Verdict is deliberately NOT a probe here — it is not in the bench; its placement is asserted by AT-B59-05.)*
  - **AT-B59-04 (reflow, C-13/C-16/C-23 — real narrow drive):** the bench honors `#workspace_body.width-narrow` — driven through a REAL resize `app.run_test(size=(80,24))` so the `width-narrow` class toggles through the production `on_resize` path (NEVER hand-add the class — that is a C-16 proxy), asserting the **geometric stacking effect** (e.g. `c2.region.y >= c1.region.y + c1.region.height`, i.e. c2 sits below c1, not beside it), NOT `"width-narrow" in workspace_body.classes` (class-presence is vacuous). Pilot-measured at BOTH the 80×24 floor and the comfortable 120×30.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** three side-by-side bench columns at width, stacked when narrow.
  - **Shipped surface:** `#crc_bench` (Horizontal) + `#crc_bench_c1/_c2/_c3` (Vertical) NEW ids in `compose`; CSS in `styles.tcss` (`#crc_bench` `layout: horizontal`; column `width: 1fr`; `#workspace_body.width-narrow #crc_bench { layout: vertical }`).
  - **Deliverable + observation:** the mounted tree walked via Pilot; pairwise-distinct column ancestry computed; reflow's geometric stacking measured at a real narrow size.
  - **Boundary catalog:** ☑ empty (columns render with seed content) ☑ boundary (width-narrow floor → stacked, still scrollable) ☑ invalid N/A ☑ error N/A.

### HLR-L3 — Verdict hero
- **Traceability:** US-L3
- **Statement:** The view shall present the known-answer verdict container (`#crc_live_verify`) in the hero row's `#crc_top_right` (above the Warnings tile) as a distinct **center-aligned** `crc-hero` element (`content-align: center middle`) containing `#crc_kat_verdict`, visually separated from the surrounding groups.
- **Rationale (informative):** the single most important correctness signal must be unmistakable; it sits in the hero row beside the coverage window, not buried in a bench column.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k verdict_hero`
- **Numeric pass threshold:** exit 0. **AT-B59-05:** `#crc_live_verify` exists on the mounted screen and resolves under `#crc_top_right` (the hero row, NOT a `#crc_bench_c*` ancestor), `#crc_kat_verdict` is its descendant, and its post-mount `styles.content_align == ("center", "middle")` — the **finest discriminator** that the plain `.crc-field-group`s never set. The AT keys on `content_align` (and/or the `crc-hero` class), NOT on "has a border": every `.crc-field-group` already carries a `border` (prototype `:57-59` vs `:67-69`), so "border the plain groups lack" is a collapsed proxy that is FALSE (M1).
- **Priority:** medium
- **Acceptance (black-box):**
  - **Observable outcome:** a center-aligned box in the hero row's right column frames the verdict, distinct from the bench groups.
  - **Shipped surface:** `#crc_live_verify` (existing id, `crc_designer_view.py:322`) moved into `#crc_top_right` and restyled (`crc-hero`, `content-align: center middle`) in `styles.tcss`; `#crc_kat_verdict` (existing id, `:326`) unchanged.
  - **Deliverable + observation:** the mounted hero container's applied `styles.content_align` + `#crc_top_right` ancestry read via Pilot; verdict-descendant relationship asserted.
  - **Boundary catalog:** ☑ empty (seed MATCH renders centered in the hero) ☑ boundary (long "Cannot compute" text wraps inside the hero, does not break the box) ☑ invalid N/A ☑ error N/A.

### HLR-L4 — Functional preservation through the new layout
- **Traceability:** US-L4
- **Statement:** The re-composition shall preserve every `#crc_*` widget id and its handler wiring, such that every batch-58 behavior (preset population, live KAT recompute, custom vector, JSON preview round-trip, Load/Save, coverage preview, gap-conflict, preview-only guard) continues to fire through the re-nested widget tree, and the existing `tests/test_crc_designer_view.py` suite passes unchanged.
- **Rationale (informative):** a re-skin must cost nothing functionally (CLAUDE.md rule 3 — surgical change).
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py`
- **Numeric pass threshold:** exit 0. **AT-B59-06 (reused handler through the layout):** via Pilot on the re-composed screen, setting `#crc_field_xorout` to `0x00000000` transitions `#crc_kat_verdict` `MATCH → MISMATCH` (the same `_recompute` handler fires through the re-nested widget). **AT-B59-07 (regression gate):** the FULL pre-existing `tests/test_crc_designer_view.py` suite passes unchanged (0 new failures) after the re-composition — the strongest preservation proof.
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** every shipped behavior still works; no batch-58 test regresses.
  - **Shipped surface:** all 29 `#crc_*` ids + `on_*_changed` / `on_button_pressed` / `_recompute` handlers, moved (not modified) into the columns.
  - **Deliverable + observation:** the KAT transition observed through the new tree; the batch-58 suite re-run green.
  - **Boundary catalog:** ☑ empty (mount-time `_recompute` still populates seed surfaces) ☑ boundary (Load/Save button in col3 still routes `on_button_pressed`) ☑ invalid (non-hex field still renders a markup-safe warning across surfaces) ☑ error (out-of-range width still caught, no crash — A5/batch-58).

### HLR-L5 — Design-fidelity gate with structural teeth
- **Traceability:** US-L5
- **Statement:** The fidelity acceptance tests shall derive their asserted set from the composed widget tree (not a hand-listed "looks right") and shall each assert a structural property that the shipped flat form lacks, such that a revert to a single vertical column fails at least one fidelity assertion.
- **Rationale (informative):** closes the exact batch-58 gap — a test that cannot fail when the layout regresses is worthless (C-31).
- **Validation:** `test (pilot)` + `inspection`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k bench_columns` + review of the AT assertions.
- **Numeric pass threshold:** exit 0. **AT-B59-08 (teeth — COMPUTED, not prose):** the AT-B59-03 pairwise-distinct-ancestor property is demonstrated executably: on the live bench tree the assertion computes `len({column_ancestor(w) for w in (#crc_field_width, #crc_coverage_ranges, #crc_json_preview)}) == 3` (True); the test also computes, in-code, that a single-`#crc_designer_panel`-ancestor flat compose collapses the set to `len(...) == 1` (the flat-form-failing algebra) — the demonstration is the executed `len(distinct) == 3` vs `== 1` comparison, documented in the docstring but PROVEN by the computed assertion, not prose alone (qa-m2).
- **Priority:** high
- **Acceptance (black-box):**
  - **Observable outcome:** the fidelity ATs assert colored-glyph rendering, distinct-column ancestry, and a bordered hero — each a flat-form-failing property.
  - **Shipped surface:** the new/extended `tests/test_crc_designer_view.py` fidelity tests.
  - **Deliverable + observation:** the assertions read the mounted tree; the ancestry-distinctness comparison is the demonstrated teeth.
  - **Boundary catalog:** ☑ empty N/A ☑ boundary (single-column revert → AT-B59-03 fails) ☑ invalid N/A ☑ error N/A.

---

## 4. Low-level requirements (LLR)

### LLR-L1.1 — `_render_coverage_window` builder
- **Traceability:** HLR-L1
- **Statement:** `CrcDesignerPanel._render_coverage_window()` shall build a `rich.text.Text` drawing one block-glyph run per range (present bytes) and one run per inter-range gap (erased when `join="concat"` / pad-filled in the warning hue when `join="fill"`), append the **live-computed** concat and fill policy CRC hex + the store-word bytes, and return the shipped empty-state note when no image is loaded — reusing `_parse_ranges`, `_build_coverage_target` (`:771`) and `compute_target_crc` with NO new math. **Safety rationale (F2, corrected):** the sink's safety rests on `markup=False` (LLR-L1.2), NOT on the source being int-only — on the invalid-range branch `_parse_ranges` echoes the raw operator token (`crc_designer_view.py:764`, `range {token!r} …`), so operator-controlled text CAN reach the sink and is rendered literally; AT-B59-09 is the proof.
- **Validation:** `test (pilot)` + `inspection`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k coverage_window` + inspect that the method imports no new engine symbol.
- **Numeric pass threshold:** returns a `Text` with ≥1 `█`/`░` glyph and ≥2 DISTINCT-color spans for the loaded fixture; the concat/fill hexes shown **equal the pinned oracles `0x9C5BCBBD` (concat) / `0x2A8A3950` (fill)** for the §3.2 `_fixture_mem` two-range `join="fill"` inputs — i.e. equal the `_coverage_preview_text` / `compute_target_crc` values, PINNED so a hardcoded-hex mock fails (B2); when `mem_map` is falsy it returns the SAME empty-state string the shipped `_coverage_preview_text` uses — `"Load an image to preview coverage CRCs over real bytes."` (`crc_designer_view.py:850-851`) — so the two surfaces do not diverge (arch-minor).
- **Acceptance criteria:** NEW method in `crc_designer_view.py` (non-frozen); source data = `self.app.current_file.mem_map` + `_build_coverage_target()` (`:771`); glyph cap bounded — the window truncates long ranges to a fixed glyph count whose value is **pilot-measured at Phase 3 against the REAL boxed `#crc_coverage_window` (2fr) width at 80×24** (C-23), NOT inherited from the prototype's 150-col line (C-29 non-transfer, §6.7 A5 / OQ-3).

### LLR-L1.2 — Window widget + recompute wiring
- **Traceability:** HLR-L1
- **Statement:** `compose` shall yield `Static(_render_coverage_window(), id="crc_coverage_window", markup=False)` as the 2fr left child of `#crc_hero_row` (above the bench), and `_recompute` shall refresh it via `.update(self._render_coverage_window())` on every change event alongside the existing surfaces.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k coverage_window`
- **Numeric pass threshold:** the mounted `#crc_coverage_window` content changes after a `#crc_coverage_ranges` edit (AT-B59-02); the `NoMatches` mid-mount guard in `_recompute` (`:914`) still swallows the pre-mount event (window query added inside the guarded block).
- **Acceptance criteria:** NEW id `#crc_coverage_window`; `_recompute` extended (`crc_designer_view.py:877-932`) to include the window update; `markup=False` (C-17).

### LLR-L1.3 — Window color policy binds theme tokens
- **Traceability:** HLR-L1
- **Statement:** The window's present-byte glyphs shall use the declared `$accent-calm` accent, its pad-filled-gap glyphs the declared `.sev-warning` hue (`#f6ff8f`), and its erased-gap glyphs a muted grey; no color shall duplicate the literal value of `$accent-calm`.
- **Validation:** `test (pilot)` + `inspection`
- **Executed verification:** inspect the render styles + `pytest -k coverage_window` (span-count assertion).
- **Numeric pass threshold:** ≥2 distinct span styles present; the accent style resolves to the theme token, not a hardcoded `#91abec` duplicate.
- **Acceptance criteria:** binds `$accent-calm` (`styles.tcss:26`) + `.sev-warning` (`:636`); success-green / border hexes reconciled to tokens or declared NEW tokens (A4, Phase-3 obligation).

### LLR-L1.4 — Window boundary + hostile-input acceptance (new-sink evidence)
- **Traceability:** HLR-L1, HLR-L5
- **Statement:** The window shall degrade gracefully at its boundaries and render hostile input literally: with no image loaded it returns the empty-state note (no glyph compute, no crash); a malformed/inverted range returns a markup-safe note (no crash, reusing the `_parse_ranges`/`_build_target` fault path); and a markup-bearing range string is rendered verbatim with no input-derived style span.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k "coverage_window and (boundary or hostile)"`
- **Numeric pass threshold:**
  - **AT-B59-10 (empty image, qa-m1):** with `app.current_file = None` (no `mem_map`), `#crc_coverage_window` renders the shipped empty-state string, contains ≥0 glyphs, and the mount does not crash.
  - **AT-B59-11 (malformed range, qa-m1):** with an image loaded and `#crc_coverage_ranges` set to an inverted/malformed range (e.g. `0x8010-0x8000`, `zzz`), the window renders a markup-safe note, does not crash, and does not mutate `mem_map`.
  - **AT-B59-09 (hostile markup, security F1):** with the §3.2 image loaded, set `#crc_coverage_ranges` to a hostile string carrying markup + ANSI metacharacters (`[link=evil]0x8000-0x8008[/]` plus a bare `[` token), read the mounted `#crc_coverage_window` rendered `Text`, and assert (a) no crash, (b) the raw operator substring appears in `.plain` **verbatim**, (c) `rendered.spans` carry ONLY the window's own present/erased/pad-fill style spans — **no span whose payload derives from the input** (no injected `link`/style span). Mirrors the batch-58 `load_save_and_markup` discipline (`test_crc_designer_view.py:471-489`) for the one new sink; crash-only is insufficient (MEMORY "Markup-sink SWEEP rule": assert `.plain` verbatim AND spans carry no injected span).
- **Acceptance criteria:** three NEW ATs on the NEW sink; reuse the batch-58 through-surface harness (`app.current_file = _loaded(_fixture_mem())`, `test_crc_designer_view.py:612-621`); 0 new engine math; lands with Inc-2 (window) except AT-B59-09 which may land Inc-3 with the fidelity/security tests.

### LLR-L2.1 — Bench composition
- **Traceability:** HLR-L2
- **Statement:** `compose` shall assemble the eight existing bench `.crc-field-group` containers into three `Vertical` columns (`#crc_bench_c1` = `#crc_algorithm_fields` + `#crc_serialization_fields`; `#crc_bench_c2` = `#crc_coverage_group` + `#crc_custom_vector_group`; `#crc_bench_c3` = `#crc_json_preview_group` + `#crc_template_fields` + `#crc_loadsave_group`) wrapped in a `Horizontal(id="crc_bench")`, preserving every child widget id. The verdict hero (`#crc_live_verify`) and Warnings (`#crc_warnings_group`) are NOT in the bench — they compose into the hero row's `#crc_top_right` (LLR-L2.3). *(B1 fold — verdict+warnings moved OUT of the former col3; §6.7 A1.)*
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k bench_columns`
- **Numeric pass threshold:** `#crc_bench` has exactly 3 column children; the probe widgets `#crc_field_width`/`#crc_coverage_ranges`/`#crc_json_preview` resolve under `#crc_bench_c1`/`_c2`/`_c3` respectively (AT-B59-03); all 29 `#crc_*` ids still resolve via `query_one`.
- **Acceptance criteria:** NEW ids `#crc_bench`/`_c1`/`_c2`/`_c3`; existing group ids UNCHANGED; the preset selector + help remain full-width above the hero row, the hero row (window + verdict + warnings) is above the bench (matching the confirmed prototype `compose:167-178`).

### LLR-L2.2 — Bench + group CSS with reflow
- **Traceability:** HLR-L2
- **Statement:** `styles.tcss` shall define the `crc-*` group/label/row classes (border, padding, group-title accent) and `#crc_bench` (`layout: horizontal; height: auto`), the columns (`width: 1fr`), plus a `#workspace_body.width-narrow #crc_bench { layout: vertical }` reflow rule, using theme tokens.
- **Validation:** `test (pilot)` + `inspection`
- **Executed verification:** `pytest -k "bench_columns or reflow"` + CSS review.
- **Numeric pass threshold:** at the comfortable width the columns lay horizontally; under `width-narrow` they stack (AT-B59-04); `.crc-group-title` uses `$accent-calm`.
- **Acceptance criteria:** additive CSS in `styles.tcss` (the `crc-*` classes were undefined pre-batch, §6.4 V-1); reflow keyed on the existing `#workspace_body.width-narrow` cascade (`styles.tcss:243-326`); C-13/C-23 geometry pilot-measured at Phase 3.

### LLR-L2.3 — Hero-row composition (NEW containers)
- **Traceability:** HLR-L1, HLR-L2, HLR-L3
- **Statement:** `compose` shall yield a `Horizontal(id="crc_hero_row")` above `#crc_bench`, holding `#crc_coverage_window` (2fr) as its left child and a `Vertical(id="crc_top_right")` (1fr) as its right child; `#crc_top_right` shall stack `#crc_live_verify` (the verdict hero) above `#crc_warnings_group`, preserving both existing child ids.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -k "hero_row or bench_columns"`
- **Numeric pass threshold:** `#crc_hero_row` exists with exactly two children (`#crc_coverage_window`, `#crc_top_right`); `#crc_live_verify` and `#crc_warnings_group` both resolve under `#crc_top_right`; neither resolves under any `#crc_bench_c*` (consistency with AT-B59-03/05).
- **Acceptance criteria:** NEW ids `#crc_hero_row`, `#crc_top_right`; existing ids `#crc_coverage_window` (from LLR-L1.2), `#crc_live_verify`, `#crc_warnings_group` UNCHANGED; matches the confirmed prototype `compose:167-171`.

### LLR-L2.4 — Hero-row CSS with reflow (C-23/C-29)
- **Traceability:** HLR-L1, HLR-L2
- **Statement:** `styles.tcss` shall define `#crc_hero_row` (`layout: horizontal; height: auto`), `#crc_coverage_window` (`width: 2fr`), `#crc_top_right` (`width: 1fr`), plus a `#workspace_body.width-narrow #crc_hero_row { layout: vertical }` reflow so the 2fr window does NOT crush at the 80×24 floor — it stacks ABOVE the verdict/warnings column instead.
- **Validation:** `test (pilot)` + `inspection`
- **Executed verification:** `pytest -k "hero_row or reflow"` + CSS review + Phase-3 pilot measure.
- **Numeric pass threshold:** at the comfortable width the window (2fr) and right column (1fr) lay horizontally; under a REAL `run_test(size=(80,24))` the hero row stacks (window `region.y` < right-column `region.y`) and the window's usable width is measured (feeds the LLR-L1.1 glyph cap). The prototype's 40-glyph window line was measured at 150 cols — a NON-transferable budget (C-29); Phase 3 re-measures the boxed 2fr window at the floor.
- **Acceptance criteria:** additive CSS; reflow keyed on the existing `#workspace_body.width-narrow` cascade; BOTH the hero row and the bench get a width-narrow stack rule (LLR-L2.2 + LLR-L2.4); C-23 both-axes pilot measure at Phase 3.

### LLR-L3.1 — Verdict-hero styling
- **Traceability:** HLR-L3
- **Statement:** `styles.tcss` shall style `#crc_live_verify` (in `#crc_top_right`) as a `crc-hero` element with `content-align: center middle` — the distinguishing property the plain `.crc-field-group`s never set — leaving `#crc_kat_verdict` as its child. A border/hue may also be applied but is NOT the discriminator (every group already has a border).
- **Validation:** `test (pilot)` + `inspection`
- **Executed verification:** `pytest -k verdict_hero` + CSS review.
- **Numeric pass threshold:** `#crc_live_verify.styles.content_align == ("center", "middle")`; `#crc_kat_verdict` is its descendant; `#crc_live_verify` resolves under `#crc_top_right` (AT-B59-05).
- **Acceptance criteria:** `#crc_live_verify` id rule / `crc-hero` class NEW in `styles.tcss`; container id already exists (`crc_designer_view.py:322`); mirrors the confirmed prototype `#crc_live_verify` rule (border + center) but the AT keys on center-align, not border (M1).

### LLR-L4.1 — Ids + handlers unchanged
- **Traceability:** HLR-L4
- **Statement:** No `#crc_*` id, no `on_input_changed`/`on_switch_changed`/`on_select_changed`/`on_button_pressed` handler, and no `_recompute`/`_save_template`/`_load_template`/`_apply_algorithm`/`_apply_template` method body shall change except `_recompute` gaining the one window-update line (LLR-L1.2); the compute/Load/Save helper methods are byte-unchanged.
- **Validation:** `inspection` + `test (pilot)`
- **Executed verification:** `git diff` review + `pytest tests/test_crc_designer_view.py`.
- **Numeric pass threshold:** the diff touches only `compose`, `_recompute` (+1 line), and the NEW `_render_coverage_window`; all handler bodies otherwise identical.
- **Acceptance criteria:** surgical-change discipline (CLAUDE.md rule 3); the 29 ids enumerated in §6.4 V-2 all preserved.

### LLR-L4.2 — Existing suite green
- **Traceability:** HLR-L4
- **Statement:** The full pre-existing `tests/test_crc_designer_view.py` suite (routing, form_and_preset, live_verdict, custom_vector, json_preview, load_save_and_markup, coverage_preview, gap_conflict, preview_only) shall pass unchanged after the re-composition.
- **Validation:** `test (pilot)`
- **Executed verification:** `pytest tests/test_crc_designer_view.py -q`
- **Numeric pass threshold:** 0 new failures vs the batch-58 baseline; every `query_one("#crc_*")` in those tests resolves.
- **Acceptance criteria:** the batch-58 tests are the regression oracle (C-31 input-set-is-an-oracle); if any test hard-codes a parent relationship it is a legitimate fidelity finding — surface, do not silently patch.

### LLR-L5.1 — Fidelity assertions derive from the tree
- **Traceability:** HLR-L5
- **Statement:** Each fidelity AT (AT-B59-01/03/05) shall compute its asserted set from the mounted tree — glyph chars + DISTINCT-color span set + `_render_markup` read from the rendered window; column-ancestor containers walked from `#crc_field_width`/`#crc_coverage_ranges`/`#crc_json_preview` (the confirmed bench probes); hero `content_align` + `#crc_top_right` ancestry read from the applied styles — and AT-B59-03 shall assert the three bench probes have PAIRWISE-DISTINCT column-ancestor containers among `{#crc_bench_c1, _c2, _c3}` (the flat-form-failing property; verdict is NOT a bench probe, it is asserted in the hero row by AT-B59-05).
- **Validation:** `test (pilot)` + `inspection`
- **Executed verification:** `pytest -k bench_columns` + assertion review (AT-B59-08).
- **Numeric pass threshold:** the ancestry-distinctness assertion evaluates `len(distinct)==1` (False) against a single-column flat ancestry and `len(distinct)==3` (True) against the bench; no fidelity assertion is presence-only (span count → distinct-color set; border → content_align).
- **Acceptance criteria:** C-10 (assert the branch, not the shape), C-31 (assert the painted result); the teeth are the computed pairwise-distinct-ancestor comparison (AT-B59-08), documented in the test docstring.

---

## 5. Validation strategy + traceability

### 5.1 Strategy
- **Pilot-driven, real-screen only (C-16):** every AT mounts `S19TuiApp` via `App.run_test()`, presses key `0` to show `#screen_crc_designer`, and asserts against the REAL panel — never the prototype, never a headless render.
- **Two proofs of preservation:** a reused handler firing through the new tree (AT-B59-06) AND the entire batch-58 suite passing unchanged (AT-B59-07/LLR-L4.2).
- **Structural fidelity with teeth (C-31):** the signature-element ATs assert flat-form-failing properties (≥2 distinct COLORS in the window, pairwise-distinct bench-column ancestors, center-aligned hero), demonstrated teeth at AT-B59-08.
- **Live-window fidelity (OQ-1 / B2):** AT-B59-01/02 pin the rendered concat/fill CRC hexes to the real computed oracles (`0x9C5BCBBD` / `0x2A8A3950`), so a partial hardcoded-hex mock fails the live gate.
- **New-sink hostile-input + boundary (C-17 / F1 / qa-m1):** AT-B59-09/10/11 drive hostile markup, empty-image and malformed-range through `#crc_coverage_window` and assert verbatim `.plain` + no injected span / graceful notes.
- **Snapshot census (C-22/C-28), measured at Phase 3:** predicted 0 tc016s drift (crc not captured, §6.4 V-5); confirm by running the suite; regen only in canonical CI if surprised.
- **Markup-safety (C-17):** the one new sink (`#crc_coverage_window`) renders `markup=False`; safety rests on `markup=False` (NOT int-only source — operator text reaches the fault branch, F2) and is PROVEN by AT-B59-09, not inspection alone.

### 5.2 Dual traceability

**Behavioral chain (US → AT → observable outcome):**
| US | AT | Observable outcome |
|----|----|--------------------|
| US-L1 | AT-B59-01, AT-B59-02 | ≥2-color block-glyph window renders + LIVE concat/fill oracle hexes; deltas + re-pins on range edit |
| US-L1 | AT-B59-10, AT-B59-11 | window degrades gracefully: empty-image note; malformed-range markup-safe note (no crash) |
| US-L2 | AT-B59-03, AT-B59-04 | 3 pairwise-distinct bench columns (`#crc_field_width`/`#crc_coverage_ranges`/`#crc_json_preview`); geometric stack under a real narrow size |
| US-L3 | AT-B59-05 | center-aligned verdict hero in `#crc_top_right` framing `#crc_kat_verdict` |
| US-L4 | AT-B59-06, AT-B59-07 | KAT recompute fires through new tree; batch-58 suite green |
| US-L5 | AT-B59-08 | computed pairwise-distinct-ancestor assertion (`len==3` vs flat `len==1`) — teeth |
| US-L5 | AT-B59-09 | hostile markup range → verbatim `.plain`, no injected span (C-17 tooth on the new sink) |

**Functional chain (US → HLR → LLR → verification):**
| US | HLR | LLR | Verification |
|----|-----|-----|--------------|
| US-L1 | HLR-L1 | LLR-L1.1, LLR-L1.2, LLR-L1.3, LLR-L1.4 | `pytest -k coverage_window` |
| US-L2 | HLR-L2 | LLR-L2.1, LLR-L2.2, LLR-L2.3, LLR-L2.4 | `pytest -k "bench_columns or hero_row or reflow"` |
| US-L3 | HLR-L3 | LLR-L3.1 | `pytest -k verdict_hero` |
| US-L4 | HLR-L4 | LLR-L4.1, LLR-L4.2 | `pytest tests/test_crc_designer_view.py` |
| US-L5 | HLR-L5 | LLR-L5.1, LLR-L1.4 | `pytest -k "bench_columns or hostile"` + assertion review |

### 5.3 Increment order (≤5 files/increment)
*Re-derived after the Phase-2 fold (C-21 — the AT set changed: +AT-B59-09/10/11, verdict left the bench). Inc-1 now builds the FINAL ancestry (hero row + bench) so LLR-L4.2's full-suite guard runs against the tree the batch ships — not an intermediate one where verdict is still bench-adjacent (R-1).*
1. **Inc-1 — hero row + bench skeleton + CSS (FINAL ancestry).** `compose` re-arranged into `#crc_hero_row` (`#crc_coverage_window` empty-placeholder Static 2fr + `#crc_top_right` 1fr = `#crc_live_verify` verdict hero above `#crc_warnings_group`) over `#crc_bench` + 3 columns (c1 algo+serial, c2 coverage+vector, c3 json+template+loadsave); `styles.tcss` gains the `crc-*` classes, `#crc_hero_row`/`#crc_top_right`/`#crc_coverage_window` layout, `#crc_bench*` layout, `#crc_live_verify` `crc-hero` (content-align center middle), width-narrow reflow for BOTH the hero row AND the bench. Files: `crc_designer_view.py`, `styles.tcss` (2). Gate: FULL existing suite green (AT-B59-07, the R-1 ancestor-coupling guard against the FINAL tree) + AT-B59-03/04/05.
2. **Inc-2 — rendered coverage window + window ATs.** `_render_coverage_window()` (live glyphs + pinned oracle hexes + shipped empty-state string) + populate `#crc_coverage_window` + `_recompute` wiring (inside the `NoMatches` guard); add the window ATs. Files: `crc_designer_view.py`, `tests/test_crc_designer_view.py` (2). Gate: AT-B59-01/02 (oracle-pinned) + AT-B59-10/11 (boundary).
3. **Inc-3 — fidelity + preservation + security ATs.** New/extended tests: fidelity teeth (AT-B59-08 computed), reused-handler-through-layout (AT-B59-06), hostile-markup on the new sink (AT-B59-09). Files: `tests/test_crc_designer_view.py` (1). Gate: AT-B59-06/08/09 + full suite.
Total distinct files across the batch: 3 (`crc_designer_view.py`, `styles.tcss`, `tests/test_crc_designer_view.py`); per-increment file counts 2/2/1 (≤5). `app.py`, `rail.py` untouched.

---

## 6. Appendices

### 6.1 Glossary
See §1.3.

### 6.2 Design decisions
- **D-1 — the coverage window renders LIVE, not a static mock.** The prototype's `_coverage_window()` returns hardcoded glyphs + hardcoded hexes (`prototypes/…b59…py:32-44`). Shipping that verbatim would be a fidelity LIE (it would not reflect the operator's actual ranges/mem_map) and would fail the "renders, not labels" design intent. **Decision:** the shipped window renders from the live coverage data the view already computes (A3), adding one view-side render method and zero engine math. Rejected alternative (static illustration): cheaper, but the AT could pass while the window is a lie — violates US-L5/C-31. Effort delta over "pure re-arrangement" is honestly ~one bounded render method; flagged in the increment order.
- **D-2 — CSS lands in `styles.tcss`, not `DEFAULT_CSS`.** The reflow rule must key off the ancestor `#workspace_body.width-narrow` cascade that lives in the central stylesheet; co-locating there (per the tasking brief) keeps the width-narrow regime consistent with every other screen. The prototype used `DEFAULT_CSS` only because it is a throwaway subclass.
- **D-3 — keep the shipped functional labels.** The prototype renames some labels ("Preset"→"algorithm_ref", "Template JSON preview"→"Job JSON preview"). Those are copy changes, not layout; default is to KEEP the batch-58 labels to minimize surface (open question OQ-2). Layout is the batch-59 remit.

### 6.3 Risks
| ID | Risk | Severity | Mitigation |
|----|------|----------|-----------|
| R-1 | A batch-58 test hard-codes a parent/ancestor relationship and breaks on re-nesting (a hidden coupling). | Medium | LLR-L4.2 runs the full suite at Inc-1; any such test is a legitimate fidelity finding — surface + reconcile, do not silently patch. |
| R-2 | The width-narrow reflow crushes the 3 bench columns OR the 2fr hero window to unreadable widths at the 80×24 floor (C-13/C-29 non-transfer — the prototype was shot at 150 cols). | Medium | LLR-L2.2 stacks the bench + LLR-L2.4 stacks the hero row under `width-narrow`; the boxed 2fr window is pilot-measured at Phase 3 (C-23 both axes, real `run_test(size=(80,24))`), feeding the LLR-L1.1 glyph cap. |
| R-3 | Surprise snapshot drift despite the 0-prediction (e.g. an incidental footer/rail recapture). | Low | C-22/C-28 census run at Phase 3; regen ONLY in canonical CI (textual==8.2.8); local regen forbidden. |
| R-4 | The new coverage-window render mutates or over-reads `mem_map` (breaks US-V8 preview-only). | Medium | LLR-L1.1 reuses read-only primitives; AT re-asserts `mem_map` object-unchanged (batch-58 AT-058-09 preserved). |
| R-5 | Hardcoded prototype hexes (green/borders) drift from the navy/pastel theme. | Low | A4/LLR-L1.3 bind `$accent-calm` + `.sev-warning`; reconcile the rest to tokens at Phase 3. |
| R-6 | `_recompute`'s mid-mount `NoMatches` guard misses the new window query → mount crash. | Low | LLR-L1.2 adds the window query INSIDE the existing guarded block (`crc_designer_view.py:908-916`). |

### 6.4 Draft-time verification log (C-35 / C-15)
| # | Claim | Result | Evidence |
|---|-------|--------|----------|
| V-1 | The `crc-*` CSS classes are currently UNDEFINED (⇒ flat form). | **CONFIRMED** | `grep -i crc styles.tcss` → 0 matches; `grep DEFAULT_CSS crc_designer_view.py` → NONE. |
| V-2 | All 29 `#crc_*` ids used by handlers exist in the shipped `compose`. | **CONFIRMED** | `crc_designer_view.py:221-368` — `crc_preset_select`, `crc_field_{name,aliases,width,poly,init,refin,refout,xorout,check,output_address,store_width,store_endianness}`, `crc_coverage_{ranges,intra_gap,join,pad_byte,on_gap_conflict,preview}`, `crc_kat_verdict`, `crc_custom_vector{,_mode,_result}`, `crc_json_preview`, `crc_warnings`, `crc_load_path`, `crc_{save,load}_btn`, `crc_loadsave_status`. |
| V-3 | `#crc_kat_verdict` lives inside `#crc_live_verify`. | **CONFIRMED** | `crc_designer_view.py:322-326` (`Vertical(id="crc_live_verify")` → `Static(id="crc_kat_verdict")`). |
| V-4 | Theme tokens `$accent-calm=#91abec` and `.sev-warning=#f6ff8f` are declared. | **CONFIRMED** | `styles.tcss:26`, `:636-637`. |
| V-5 | The snapshot suite does NOT capture `crc_designer` and no crc SVG baseline exists ⇒ predicted 0 tc016s drift. | **CONFIRMED (corrects the tasking brief)** | `test_tui_snapshot.py:109-110` (`_RESTYLED_SCREENS`/`_SCAFFOLD_SCREENS` = workspace/a2l/mac/issues/map/patch/diff); `find tests -iname "*crc*" -path "*snapshot*"` → none. |
| V-6 | `app.py::_compose_screen_crc_designer` just mounts `CrcDesignerPanel()` ⇒ bench lives in the panel, app.py untouched. | **CONFIRMED** | `app.py:2219-2224`. |
| V-7 | Coverage vocab tuples (`INTRA_GAP/JOIN/ENDIANNESS/ON_GAP_CONFLICT`) exist in the model for reuse. | **CONFIRMED** | `crc_designer_model.py:48-56`. |
| V-8 | The prototype's coverage window is a hardcoded mock (drives D-1). | **CONFIRMED** | `prototypes/…b59…py:32-44` (literal glyphs + `0x9C5BCBBD`/`0x2A8A3950`). |
| A-1 | Prototype non-`$accent-calm` hexes map to theme tokens. | **ASSUMED — verify Phase 3** | success `#8ff6a0` / borders `#2b3a5e`,`#161d31` not found as declared tokens (A4). |
| A-2 | The `width-narrow` cascade stacks BOTH the bench AND the hero row (2fr window) as spec'd. | **ASSUMED — verify Phase 3 (C-16/C-23/C-29)** | reflow class exists + toggles on `#workspace_body` (`styles.tcss:243-326`; `app.py:5692-5697`); `#crc_bench` + `#crc_hero_row` rules are NEW; prototype measured at 150 cols (non-transferable). |
| V-9 | The shipped `_coverage_preview_text` has a reusable empty-state string + oracle fixtures exist. | **CONFIRMED** | `crc_designer_view.py:850-851` (`"Load an image to preview coverage CRCs over real bytes."`); oracles `0x9C5BCBBD`/`0x2A8A3950` at `test_crc_designer_view.py:617-620,687-688`. |
| V-10 | `width-narrow` toggles on `#workspace_body` via the real resize path ⇒ the reflow rule is reachable. | **CONFIRMED** | `app.py:5692-5697` adds/removes `width-narrow` on `#workspace_shell` + `#workspace_body` at the 120-col breakpoint. |

### 6.5 Open questions — RESOLVED at the Phase-1/Phase-2 gates
- **OQ-1 (coverage-window scope) — RESOLVED (operator, 2026-07-21):** LIVE window (D-1) confirmed; NOT the static mock. Encoded in LLR-L1.1 + the AT-B59-01/02 oracle-hex pins (B2).
- **OQ-2 (label copy) — RESOLVED (default):** keep the batch-58 field labels; layout-only remit (D-3).
- **OQ-3 (window glyph budget) — DEFERRED to Phase 3 (C-23/C-29):** the fixed glyph-count cap is pilot-measured against the REAL boxed 2fr `#crc_coverage_window` width at 80×24 (LLR-L1.1/L2.4) — NOT inherited from the prototype's 150-col line (C-29 non-transfer). Confirm truncation for a wide range at the floor.
- **OQ-4 (col3 density) — RESOLVED/RELAXED:** the fold moved verdict + Warnings OUT of col3 into the hero row, so col3 now holds **3** groups (Job JSON roomy + Template + Load/Save), not 5 — the vertical-budget risk is materially lower. Still Phase-3-confirmed at 120×30 because JSON is "roomy"; C-13.1 scroll fallback pre-committed if it overflows.

### 6.6 Evidence checklist
- [x] Constraints stated explicitly — §2.4.
- [x] At least 2 alternatives considered — D-1 (live vs static window), D-2 (styles.tcss vs DEFAULT_CSS).
- [x] Recommendation has rationale tied to constraints — D-1/D-2/D-3.
- [x] Risks listed (operational, cost, coupling) — §6.3 R-1..R-6.
- [x] Cost/latency — N/A (local TUI render); geometry budget deferred to Phase-3 pilot measure (C-23).
- [x] Diagram — flow is trivial (single-screen re-layout); the prototype `compose` is the reference structure (§1.4).
- [x] What would change the recommendation — OQ-3 (window glyph budget at the boxed floor), R-1 (hidden ancestor coupling in batch-58 tests).
- [x] Two-layer requirements — every US has a first-class Acceptance block + AT-B59-NN; BOTH traceability chains present (§5.2).
- [x] Draft-time verification — §6.4 (8 confirmed on disk, 2 flagged assumed for Phase 3).
- [x] Phase-2 fold amendments recorded Before→After with Deleted/New tokens — §6.7.

### 6.7 Phase-2 fold amendment log (Before → After)

Applied 2026-07-21 to discharge the Phase-2 cross-review (architect/qa/security CHANGES-REQUESTED). Every locked-requirement edit is recorded here; the amendments reconcile the doc to `state.json.confirmed_design_decisions.layout_refinement` and close the AT-vacuity + live-window + new-sink gaps. Post-fold counts: **5 US / 5 HLR / 12 LLR / 11 AT** (was 5 / 5 / 10 / 8).

| # | Finding | Where | Before | After |
|---|---------|-------|--------|-------|
| A1 | B1 layout fold | §1.2, §2.2, §1.3, HLR-L2, LLR-L2.1, §5.2 | col3 = verdict hero + JSON + Warnings + Template + Load/Save; verdict in the bench | verdict hero + Warnings → **hero row** `#crc_hero_row`→`#crc_top_right` (sibling of `#crc_coverage_window`); **col3 = JSON(roomy) + Template + Load/Save** only |
| A2 | B1 teeth re-derivation | AT-B59-03, AT-B59-08, LLR-L5.1 | probes `#crc_kat_verdict`/`#crc_coverage_ranges`/`#crc_field_width`; "different **bench-column** ancestor" (unsatisfiable — verdict has no `#crc_bench_c*` ancestor) | probes **`#crc_field_width`(c1)/`#crc_coverage_ranges`(c2)/`#crc_json_preview`(c3)**; "**pairwise-distinct ancestor CONTAINER**", computed `len(distinct)==3` vs flat `len==1` |
| A3 | B2 live-window oracle | AT-B59-01, AT-B59-02, LLR-L1.1 | glyphs + "≥2 style spans" + range-edit delta only | + rendered `.plain` **CONTAINS `0x9C5BCBBD` (concat) AND `0x2A8A3950` (fill)** pinned oracles for the §3.2 fixture (defeats a partial hardcoded-hex mock) |
| A4 | M2 distinct colors + markup | AT-B59-01 | "≥2 distinct style spans" (span-object count — a monochrome window passes) | **`len({span.style …}) >= 2`** (distinct COLORS) + **`window._render_markup is False`** |
| A5 | M1 hero discriminator | AT-B59-05, §1.3, §2.2, LLR-L3.1 | "a `border` … the plain groups do not [have]" (FALSE — every group has a border) | keys on **`content_align == ("center","middle")`** (and/or `crc-hero` class) + `#crc_top_right` ancestry; border is NOT the discriminator |
| A6 | M3 real narrow drive | AT-B59-04, LLR-L2.4 | "exact assertion form set at Phase 3" (open to a vacuous class-presence check) | REAL **`run_test(size=(80,24))`** + assert **geometric stacking** (`c2.region.y >= c1.region.y + c1.region.height`), never hand-add the class (C-16) |
| A7 | hero-row containers (new) | LLR-L2.3, LLR-L2.4 (NEW) | absent | LLR-L2.3 composes `#crc_hero_row` + `#crc_top_right`; LLR-L2.4 adds their CSS + a `#workspace_body.width-narrow #crc_hero_row { layout: vertical }` reflow so the 2fr window does not crush (C-23/C-29) |
| A8 | Inc-1 final-ancestry | §5.3 | Inc-1 built only the bench (verdict still bench-adjacent); hero row deferred | Inc-1 builds the **FINAL ancestry** (hero row + bench) so LLR-L4.2's full-suite R-1 guard runs against the shipped tree (C-21 re-derive) |
| A9 | F1 hostile-input AT (new) | LLR-L1.4 → **AT-B59-09** (NEW) | no hostile-markup test on the new sink (crash-only boundary) | AT-B59-09: hostile markup range → no crash, raw substring in `.plain` verbatim, no input-derived span |
| A10 | qa-m1 boundary ATs (new) | LLR-L1.4 → **AT-B59-10 / AT-B59-11** (NEW) | HLR-L1 boundary catalog listed empty/malformed but no AT carried them | AT-B59-10 (empty image → shipped empty-state note) + AT-B59-11 (malformed range → markup-safe note, no crash) |
| A11 | F2 rationale correction | LLR-L1.1, §5.1, §2.4 | window is safe because it draws "int-only, no untrusted string" | safety rests on **`markup=False`**; operator range text reaches the sink verbatim on the `_parse_ranges` fault branch (`:764`) — AT-B59-09 is the proof |
| A12 | arch-minor empty-state reuse | LLR-L1.1 | "a graceful markup-safe note" (generic) | reuse the SHIPPED string `"Load an image to preview coverage CRCs over real bytes."` (`crc_designer_view.py:850-851`) so the window + preview do not diverge |
| A13 | qa-m3 flag | AT-B59-01 | (none) | flagged `assumed — verify Phase 3`: styled `rich.Text` spans surviving `Static(markup=False).render()`; else read the renderable directly |

**New tokens:** `#crc_hero_row`, `#crc_top_right` (containers); `crc-hero` (class); AT-B59-09, AT-B59-10, AT-B59-11; LLR-L1.4, LLR-L2.3, LLR-L2.4.
**Deleted tokens:** none renamed — `#crc_live_verify`, `#crc_warnings_group`, `#crc_json_preview` all keep their ids; only their PARENT changed (verdict/warnings → hero row; JSON stays in c3). The former "col3 = 5 groups" phrasing is superseded (A1).
**Traceability integrity:** both chains re-checked (§5.2) — every AT-B59-01..11 maps to a US and an observable outcome; every US maps HLR→LLR with a verification command. No orphan LLR, no dangling AT.
