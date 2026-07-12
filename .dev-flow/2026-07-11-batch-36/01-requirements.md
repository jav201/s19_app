# 01 — Requirements — 2026-07-11-batch-36

> Phase-0 story intake below (§2.6). §3 Acceptance / §4 HLR-LLR are derived in Phase 1 once
> the Definition-of-Ready gate approves which stories proceed. Language: English.

## 2.6 — Story intake & refinement (INVEST + Definition of Ready)

RC-1: PASS @ `7df60dd` (origin/main tip = HEAD = merge-base). Already-shipped grep run per
story below — 0 hits; nothing shipped.

---

### US-058 (B-22) — Patch Editor: readable paste box + uncluttered controls
- **User / value:** an operator pasting or editing a v2 change-set JSON in the Patch Editor.
  Today the "Paste change-set (v2 JSON)" `TextArea#patch_paste_text` renders in a cramped
  shared pane (1–2 usable lines) and the right column packs Change-file + Patch-script +
  Checks together (screenshot-confirmed). Friction: the operator cannot read/edit multi-line
  JSON, and mixed controls invite mis-clicks.
- **Outcome (WHAT — black-box):** the paste input shows enough lines to read/edit a
  multi-line change-set, and the Patch Editor's control groups (entries · change-file ·
  patch-script · checks · paste) are visually separated with **no clipping or overlap at
  80 and 120 cols**.
- **Out of scope:** any change to patch/check *behavior* or button wiring — compose + CSS
  only (same constraint B-07/US-057 honored). Undo/redo (B-19) and JSON popup (B-14) excluded.
- **INVEST:** Independent ✓ · Negotiable ✓ (mechanism open) · Valuable ✓ · Estimable ✓ ·
  Small ✓ (1 increment) · Testable ✓ (SVG snapshot @80/120 + geometry assertion).
- **Feasibility:** Textual grid/CSS reparent. Current panel = `grid-size: 2 3`
  (styles.tcss:702). **C-13 geometry-budget risk:** 3 columns at 80 cols is tight
  (host content ~70 cols @80 per the batch-22 measurement) → flag `assumed — measure in Phase 1`.
- **Black-box AC (→ AT in Phase 1):** "When the Patch Editor is rendered at 80 and at 120
  cols, the operator observes the paste box across ≥ N lines (not 1–2) and each control group
  in a distinct, non-clipped region." Exact N + region layout set in Phase 1.
- **Open question (Phase 1):** 3-column reflow **vs.** a taller dedicated paste pane — the
  architect measures both against the 80-col budget and picks the lowest-risk mechanism that
  meets the outcome. Mechanism intentionally NOT locked at Phase 0.
- **Class:** **READY** (outcome observable through the shipped surface; mechanism deferred).

### US-059 (B-24) — Workspace hex-view color legend
- **User / value:** an operator reading the Workspace hex view (and the project report). The
  hex cells are colour-coded, but `legend.py::LEGEND_TABLE` documents only A2L / MAC / Issues
  — there is **no Hex section**, so the operator can't tell what the hex colours mean in
  either the in-app `LegendScreen` modal or the report legend.
- **Outcome (WHAT — black-box):** both legend surfaces (the `LegendScreen` modal and the
  report's legend section) include a **Hex** section mapping each hex-cell colour to its
  meaning.
- **Out of scope:** changing the hex view's *colouring* logic (color_policy is engine-frozen);
  this is documentation of the existing colours only.
- **INVEST:** Independent ✓ · Valuable ✓ · Estimable ✓ · Small ✓ · Testable ✓.
- **Feasibility:** add a "Hex" block to the non-frozen `legend.py::LEGEND_TABLE`; both
  consumers (LegendScreen in screens.py, report_service legend) already iterate the table.
  Phase 1 owes: enumerate the hex view's actual colour classes (read hexview.py / the
  `sev-*` classes the hex cells use) so the rows match shipped behaviour, and decide whether
  the anti-drift `COLOUR_SEVERITY` coupling test extends to hex.
- **Black-box AC (→ AT in Phase 1):** "When the operator opens the legend modal (and when a
  report is generated), a Hex section is present naming each hex colour and its meaning."
- **Open question (Phase 1):** the exact hex colour set + meanings, sourced from the shipped
  hex-render classes (not invented).
- **Class:** **READY**.

### US-060 (B-23) — Relocate test inputs to examples/ + prune heavy A2Ls
- **User / value:** repo maintainer. (a) `tmp/stress_smoke/` (git-tracked: stress.a2l/.mac/.s19,
  9 KB) is an ad-hoc test-input folder outside the canonical `examples/` tree; (b) `examples/`
  is **96 M**, 90 M of which is two real-vendor firmware A2Ls used only by stress smoke tests —
  heavier than a repo should carry.
- **Outcome (WHAT — black-box / inspection):**
  1. the `tmp/stress_smoke/` inputs live under `examples/` as a proper case, with any
     references updated (grep shows **0** today — to re-verify);
  2. unnecessary heavy fixtures are removed so `examples/` is materially smaller, **retaining
     a bare-minimum real-vendor large-A2L fixture** (operator constraint D-1);
  3. the (possibly slimmed) example smoke / pilot-gif tests **still pass and still cover the
     same functional requirements** — no coverage regression.
- **Out of scope:** git **history** rewrite (existing clone size is not reclaimed without a
  separate, separately-approved filter-repo pass).
- **INVEST:** Independent ✓ · Valuable ✓ (repo weight) · Estimable ✓ · Small–Medium ✓ ·
  Testable ✓ (suite green + size measured before/after + coverage mapping preserved).
- **Feasibility:** move 3 tiny files; delete heavy A2L(s); adjust `test_examples_smoke.py`
  (`SLOW_CASE_IDS`) + `test_examples_pilot_gifs.py`; possibly snapshot/gif baselines
  (**C-14 location-move census** over save/e2e observers). Data: 36M top-level
  `case_06_large_nested_a2l` runs in the normal suite; 54M `professional_validation` copy is
  the `pv__case_06_large_nested_a2l` **slow** (~490s) outlier.
- **Black-box AC (→ AT/inspection in Phase 1):** "After the change, `examples/` contains the
  relocated `stress_smoke` case, `tmp/stress_smoke/` is gone, `examples/` size is reduced by
  ~X, a real-vendor large-A2L case is retained, and the example test suite passes asserting
  the same functional coverage."
- **Open questions (Phase 1):** which real-vendor large A2L is the retained "bare minimum"
  (candidate: keep 36M, drop 54M slow duplicate); are the two `case_06_large_nested_a2l`
  copies genuinely duplicative; exact test-file edits + which tests map to which requirement
  so coverage is provably preserved.
- **Operator constraint (verbatim, 2026-07-11):** "ensure the test cases cover functionality,
  requirements. I am interested in deleting information not necessary. However, if we can keep
  at least the bare minimum of real-vendor files let's do it."
- **Class:** **READY** (outcome + constraint clear; file selection is Phase-1 design).

### Non-US chore — refresh `.dev-flow/BACKLOG.md`
The tracked backlog is stale (last refresh 2026-07-03, batch-24; still lists #8/#12 as the
queue). Refresh to current reality (tip `7df60dd`; all P1 shipped; open set B-11..B-19 +
B-22..B-24 + hygiene carries). Delivered as a Phase-6 docs deliverable, not a formal US.

---

## Definition-of-Ready summary
- **READY → Phase 1:** US-058, US-059, US-060 (all three; mechanisms/file-selection are
  legitimately Phase-1 design, not Phase-0 gaps).
- **REFINE / SPIKE / OUT:** none.
- **Gate axis check:** Coverage — each story has ≥1 black-box AC through the shipped surface;
  Certainty — each AC is observable + falsifiable; Evidence — RC-1 cited, code seams cited.
  No unmet axis identified → recommend `approve`.

---

> **Normative keyword contract (§3-§5):** `shall` appears ONLY inside HLR/LLR statements.
> `should` never appears in a normative statement (informative prose only). Every `file:line`
> below was verified against the worktree tree at `7df60dd` (= HEAD = origin/main) during
> Phase-1 drafting, 2026-07-11, unless flagged `assumed — verify in Phase N`. New symbols are
> flagged `NEW — created in Phase 3`. Requirement-ledger sites proposed: **R-TUI-046** (US-058),
> **R-TUI-047** (US-059), **R-TUI-048** (US-060) — highest existing id is `R-TUI-045`
> (REQUIREMENTS.md), so 046/047/048 are free.
>
> **Id sequence (probed 2026-07-11):** highest AT in the tree = `AT-057b`; ATs start at
> **AT-058a**. Highest TC in use = **TC-320** (REQUIREMENTS.md LLR-057.4; highest in `tests/`
> is TC-319); new TCs continue at **TC-321**.

## 3. Acceptance blocks (black-box, first-class)

> Each block is independent of the §4 LLR decomposition. C-10 = the AT drives a non-default
> value / asserts CONTENT, not mere non-emptiness. C-12 = output-then-consume: the AT observes
> the consumer over the HANDLER-PRODUCED artifact, never one the AT wrote itself. C-17
> (render-mode flip over file-derived text) is **N/A for all three stories** — US-058 changes
> only compose/CSS geometry (no file-derived text), US-059 legend rows are static in-repo
> literals (no file-derived text), US-060 touches only fixtures/tests (no rendered text). Stated
> explicitly so the C-17 obligation is discharged, not skipped.

### AT-058a — Patch Editor paste box in-viewport + control cluster separated (US-058)
> AMENDED batch-36 Phase-2 (A-01 · Q-01 · Q-02 · Q-03 · A-05 + new finding F-01). The prior
> "≥6 lines @80x24 / ≥8 @120x30 + five pairwise-disjoint regions" outcome was BOTH unsatisfiable
> (nested containers) and measurement-refuted (the panel is 5 rows tall @80x24, not the assumed
> ~18) and CSS-invariant on `region.height`. See §6.5 records R-A01, R-Q01, R-Q02/F-01, R-Q03, R-A05.
- **Observable outcome:** at 80x24 AND at 120x30, opening the Patch Editor renders the
  `#patch_paste_text` editor with its FIRST line inside the visible content-region of its scroll
  pane at `scroll_y == 0` — i.e. the paste editor is no longer below the fold — showing at least
  **N_w** visible byte-editable lines, where **N_w is a per-width MEASURED pin (LLR-058.1),
  width-decoupled, each strictly greater than today's 0 in-viewport lines**; the paste group
  (`#patch_paste_row`) is NOT a descendant of the crowded `#patch_pane_changefile` pane (it is
  reparented into its own panel cell); and the paste group's region is disjoint from the
  change-file/patch-script/checks CLUSTER region (`#patch_doc_file_row`), asserted at the SIBLING
  level only. Nested pairs (`#patch_doc_controls` / `#patch_checks_controls` are children of
  `#patch_doc_file_row`, `screens_directionb.py:1879,1906,1908`) are asserted as child ⊂ parent
  CONTAINMENT, never disjointness.
- **Shipped surface:** Patch Editor screen (`action_show_screen("patch")`, `PatchEditorPanel.compose`
  at `screens_directionb.py:1765`; changefile pane `:1848-1923`).
- **Deliverable + observation:** the rendered widget geometry read through a Textual pilot
  (`app.run_test(size=...)`). The **C-10 discriminator** is the content-region PLACEMENT idiom
  (mirrors `tests/test_tui_patch_variant.py:427-438`, TC-035.2): with `pane` = the paste editor's
  scroll container, assert at `scroll_y == 0` — `pane.content_region.y <= paste.region.y` AND
  `paste.region.y + N_w <= pane.content_region.bottom` — guarded by
  `if paste.region.width and paste.region.height` (a fully-scrolled-out widget reports a NULL (0,0)
  region). Structural cheap guards (NOT the discriminator): `#patch_paste_row` is not among
  `#patch_pane_changefile`'s descendants, and the sibling-level region-disjointness of
  `#patch_paste_row` vs `#patch_doc_file_row` (rectangle-intersection idiom,
  `tests/test_tui_patch_layout.py:161-176`). **Never `region.height >= N`** — it equals the CSS
  `height: 8` whether the box is visible or below the fold (`styles.tcss:949-951`), so it carries
  no counterfactual (Q-01).
- **Counterfactual (RED today):** the paste editor is fully below the fold — MEASURED
  `#patch_paste_text.region.y == 38` while the changefile pane content-region is `[8,10)` @80x24
  (and `region.y == 36` vs pane content `[8,13)` @120x30), so **0** paste lines are in-viewport at
  scroll 0 → the placement predicate fails RED at both widths (probe P24).
- **Acceptance test(s):** AT-058a (geometry pilot at BOTH widths — one on-disk node, C-18).
  Boundary: 80x24 is the floor; 120x30 the comfortable case.
- **Boundary catalog:** ☑ empty (N/A — layout-only, no data input) · ☑ boundary (80x24 floor — the
  measured vertical ceiling of ~2 pane rows caps N_80; LLR-058.1) · ☑ invalid (N/A — no new input
  surface) · ☑ error (N/A — no new failure path; wiring covered by AT-058b).

### AT-058b — Zero behavior change: ids + wiring survive the regroup (US-058)
- **Observable outcome:** every pre-batch `patch_*` widget id is still queryable after the
  compose/CSS change, and each patch button still produces its pre-batch status/side-effect when
  pressed (Load / Validate / Apply / Save / Run-checks / Parse-pasted).
- **Shipped surface:** Patch Editor screen.
- **Deliverable + observation:** pilot `query_one(id)` for the 15-id census (LLR-058.3) +
  the AT-032b check-run status idiom (`tests/test_tui_patch_editor_v2.py:1811-1850`) re-asserted
  unchanged. C-12: the status line the AT reads is produced by the real handler, not injected.
- **Acceptance test(s):** AT-058b (id census + wiring regression, one node).
- **Boundary catalog:** ☑ empty (N/A) · ☑ boundary (the AT-032a `#patch_checks_help` locked
  token span, `_CHECKS_HELP_TOKEN`, survives) · ☑ invalid (N/A) · ☑ error (existing handlers
  regression-covered here).

### AT-059a — Hex colour legend present in the LegendScreen modal (US-059)
> AMENDED batch-36 Phase-2 (A-06 / Q-08 · C-21). The single bundled AT was SPLIT into AT-059a
> (modal) + AT-059b (report reread, C-12) so §3/§5 match 01b §2.3 and the C-12 report arm lives in
> its correct report-seam home. See §6.5 record R-A06.
- **Observable outcome:** the in-app `LegendScreen` modal contains a **Hex** section whose rows
  carry the documented meanings of the two shipped hex-cell overlay colours — the yellow
  search/goto-focus highlight and the orange MAC-overlay highlight — matching the semantics of
  `FOCUS_HIGHLIGHT_STYLE` / `MAC_ADDRESS_OVERLAY_STYLE` (`color_policy.py:13-14`).
- **Shipped surface:** the `LegendScreen` modal (opened by the `k` binding / per-view Legend
  buttons, `screens.py:493`; rows rendered at `screens.py:527-539`).
- **Deliverable + observation:** the modal `#legend_body Label` rendered text (`_modal_meanings`
  idiom, `test_tui_legend.py:47`) after driving the real `k` binding. C-10: the AT asserts the two
  specific Hex meaning strings appear, not merely that a "Hex" heading exists.
- **Acceptance test(s):** AT-059a (modal content assertion, one node — `tests/test_tui_legend.py`).
- **Boundary catalog:** ☑ empty (N/A — static in-repo table) · ☑ boundary (renders with no file
  loaded, `test_tui_legend.py:284-300` pattern) · ☑ invalid (N/A) · ☑ error (N/A — anti-drift
  covered by TC-322).

### AT-059b — Hex colour legend present in the generated report (US-059, C-12)
- **Observable outcome:** a project report generated through the shipped report path contains a
  Hex legend section whose bullets carry the same two Hex overlay-colour meanings, present in the
  bytes actually written to `reports/*.md`.
- **Shipped surface:** the project report's `## Legend` section (`report_service._legend_lines`,
  `report_service.py:1290`, emitted by `generate_project_report` when `include_legend`).
- **Deliverable + observation:** C-12 output-then-consume — the AT drives `generate_project_report`
  / the report flow, lets the handler WRITE the file, RE-READS the produced `reports/*.md` from
  disk, and asserts the two Hex meaning strings are in the file (never writes the legend itself).
  Idiom home: the report-seam reread pattern (`tests/test_tui_report_seam.py:182-221`,
  `test_report_seam_writes_real_file_on_disk`). C-10: exact meaning strings, not "a Hex heading
  exists".
- **Acceptance test(s):** AT-059b (report reread content assertion, one node —
  `tests/test_tui_report_seam.py`).
- **Boundary catalog:** ☑ empty (N/A) · ☑ boundary (the single `LEGEND_TABLE` reaches both
  surfaces — one added block must emit into the file) · ☑ invalid (N/A) · ☑ error (N/A).

### AT-060a — Fixtures relocated, heavy duplicate pruned, coverage preserved (US-060)
- **Observable outcome:** after the change, (1) `tmp/stress_smoke/` is absent and a
  `examples/case_07_stress_smoke/` case exists whose primary image loads to a non-empty
  `LoadedFile`; (2) `examples/professional_validation/case_06_large_nested_a2l/` (the 54 MB
  slow duplicate) is absent while the retained large A2L
  `examples/case_06_large_nested_a2l/firmware.a2l` (~36 MB, normal-suite case) is present; (3)
  the example smoke suite passes over the newly-discovered case set with the same functional
  assertions (load → enrich → validate).
- **Shipped surface:** the `examples/` fixture tree consumed by
  `tests/test_examples_smoke.py::test_case_loads_through_service_layer` (dynamic discovery,
  `_discover_cases` :47).
- **Deliverable + observation:** the on-disk `examples/` tree (path presence/absence checks) +
  a green run of `pytest tests/test_examples_smoke.py -q`; the new case asserted to produce
  mapped memory (C-10 — content, not just directory presence). C-12: the smoke test drives the
  real service pipeline over the relocated fixture.
- **Acceptance test(s):** AT-060a (relocation + prune + green smoke over discovered set, one
  node) + TC-323 (discovery/coverage-map unit assertions). The prune arm is AUTHORIZED only after
  the I-060-1 construct-equivalence gate (LLR-060.2) passes and its census evidence is recorded
  BEFORE the `git rm` (A-08/Q-04).
- **Boundary catalog:** ☑ empty (N/A) · ☑ boundary (`SLOW_CASE_IDS` becomes empty — no slow
  case remains in the smoke file; asserted) · ☑ invalid (N/A — no input surface) · ☑ error
  (a case dir lacking a primary image still `skip`s cleanly — existing `_pick_primary` None
  guard, unchanged).

## 4. HLR / LLR decomposition

### HLR-058 — Patch Editor readable paste box + separated controls (US-058)
- **Traceability:** US-058 · **Priority:** medium · **Validation:** test (pilot geometry +
  snapshot) · **Ledger:** R-TUI-046 (proposed).
- **Statement:** The system shall render the Patch Editor so that, at both an 80x24 and a
  120x30 terminal, the change-set paste editor (`#patch_paste_text`) has its first line inside its
  scroll pane's visible content-region at `scroll_y == 0` (no longer below the fold), presenting at
  least a per-width measured minimum of visible byte-editable lines (LLR-058.1), with the paste
  group reparented out of the crowded `#patch_pane_changefile` pane into its own panel cell whose
  region is sibling-disjoint from the change-file/patch-script/checks cluster and does not exceed
  the panel host width, while preserving every existing patch-editor widget id and the behaviour of
  every existing handler and key binding.
- **Rationale (informative):** the top-right `#patch_pane_changefile` pane currently stacks
  `#patch_doc_file_row` (change-file + patch-script + checks) above `#patch_paste_row` in a single
  1fr grid cell, so the 8-line paste editor is pushed below the fold — MEASURED at scroll 0 it
  reports region.y=38 while the pane's visible content-region is only rows [8,10) @80x24, i.e. 0
  in-viewport paste lines (see §6 draft-time finding DF-1 and probe P24). Giving the paste editor
  its own panel cell fits the 80-col horizontal budget (a three-column reflow does not — LLR-058.1).
  Note the vertical budget is severely constrained: the whole `#patch_editor_panel` content is only
  5 rows @80x24 / 11 @120x30 (MEASURED, F-01), so the achievable visible-line minimum is small at
  the 80x24 floor and is pinned per width in Phase 3.
- **Executed verification:** `pytest tests/test_tui_patch_layout.py tests/test_tui_patch_editor_v2.py -q`
  + AT-058a/AT-058b via `pytest -k at058`.
- **Numeric pass threshold:** 0 failures; at scroll 0 `#patch_paste_text.region.y` lies within its
  pane's visible content-region at both widths with ≥ N_w visible lines (N_w Phase-3-measured,
  each > 0); `#patch_paste_row` not a descendant of `#patch_pane_changefile`; paste-vs-cluster
  region intersection area == 0 at the sibling level; all 15 ids (LLR-058.3) queryable.

#### LLR-058.1 — Mechanism = dedicated paste region; three-column reflow rejected by the 80-col budget (C-13); N re-derived from MEASURED vertical budget (F-01)
- **Traceability:** HLR-058 · **Validation:** test (pilot geometry).
- **Statement:** The paste group (`#patch_paste_row`: its label, `#patch_paste_text`, and the
  `#patch_paste_parse_button` row) shall be reparented out of the top-right `#patch_pane_changefile`
  grid cell into its own dedicated panel cell — no longer sharing a cell with the change-file,
  patch-script, and checks groups — such that at `scroll_y == 0` the paste editor's first line lies
  inside its pane's visible content-region (not below the fold) and it shows at least **N_w** visible
  lines, where **N_w is measured per width from the post-fix capture and pinned at the Phase-3 gate**
  (§ measured budget below); and the panel shall NOT be reflowed to three grid columns.
- **C-13 geometry budget (measured, DRAFT-TIME):**
  - *Host content width* (measured comment, `styles.tcss:695-696`): **70 cols @80 / 92 @120**.
  - *Current 2-column grid* (`grid-columns: 1fr 1fr`, no grid-gutter, `styles.tcss:702-703`):
    pane content ≈ **35 cols @80 / 46 @120**. Widest inner row = `#patch_doc_controls`
    (`grid-size: 3; grid-gutter: 0 1`, `styles.tcss:902-908`): per-cell ≈ (35 − 2)/3 ≈
    **11 cols @80**; the longest button label `"Validate"` = 8 chars → fits (11 ≥ 8). ✓
  - *Hypothetical 3-column reflow* (`grid-columns: 1fr 1fr 1fr`): pane content ≈ 70/3 ≈
    **23 cols @80**; button-grid per-cell ≈ (23 − 2)/3 ≈ **7 cols @80** < 8 → `"Validate"`
    **clips** — a within-pane clip masked by the pane's `overflow-x: hidden` (`styles.tcss:713`),
    exactly the failure class C-13/AT-033a guards. **Three-column reflow REJECTED at the 80-col
    floor.** (Even @120: 92/3 ≈ 30/pane → cell ≈ 9 ≥ 8 barely — but 80 is the binding floor.)
- **C-13.MEASURED vertical budget (F-01 — re-measured 2026-07-11, probe P24; SUPERSEDES the draft
  estimate):** the earlier "~9 rows @24 per 1fr pane" figure was WRONG by ~4.5×. Measured via a
  Textual pilot at scroll 0 (`grid-size: 2 3`, current tree):
  - `#patch_editor_panel` content height = **5 rows @80x24 / 11 @120x30** (the host
    `workspace_shell` is `1fr` but capped to 9 rows @80x24 by a sibling occupying the lower shell,
    so the panel is height-starved — ancestor chain: `patch_editor_panel(1fr) ⊂ screen_patch(100h)
    ⊂ workspace_body(100h) ⊂ workspace_shell(1fr, region h=9 @80x24)`).
  - the two `1fr` grid rows split that: each pane content ≈ **2 rows @80x24 / 5-6 @120x30**
    (measured: `#patch_pane_changefile` content_h = 2 @80x24, 5 @120x30). This corroborates the
    existing TC-035.2, which already documents ~2-row panes @80x24 and widgets scrolling to a NULL
    region (`test_tui_patch_variant.py:414-448`).
  - **Consequence:** a `grid-size: 2 4` (three `1fr` rows) would split 5 rows @80x24 into ~1.6/cell
    → a dedicated paste cell of ~2 rows, minus the paste label (1) + parse button (1) inside
    `#patch_paste_row`, yields **~0-1 visible editor lines @80x24**. The original a-priori
    "≥6 @80x24 / ≥8 @120x30" is **physically unsatisfiable** under compose+CSS-only in the current
    shell. Horizontal budget is unchanged (paste width stays 35/46; JSON scrolls horizontally
    inside the `TextArea`).
  - **N re-derivation (arithmetic):** @80x24 the achievable ceiling for a compose+CSS paste cell is
    ~1 in-viewport editor line (2-row cell − label − button); @120x30 a WEIGHTED paste row (e.g.
    `grid-rows: 1fr 1fr 2fr auto` giving the paste ~5 of the 11 rows) admits ~3-4 editor lines.
    Therefore **N_80 provisional = 1, N_120 provisional = 3** (each strictly > today's measured 0
    in-viewport lines) — but both are **Phase-3 MEASURED pins from the post-fix capture, recorded at
    the gate**, not asserted a priori. The always-satisfiable acceptance is the content-region
    PLACEMENT (first line in-viewport at scroll 0), which the raw-`region.height` metric could not
    express.
- **Chosen realization (informative, C-13.1 deficit-matched ladder — Phase-3 picks the rung AND
  pins N_w):**
  - *Rung 1 (preferred):* restructure the panel grid to give `#patch_paste_row` its own cell
    reparented out of `#patch_pane_changefile`, with a **weighted** row allocation (not an equal
    `1fr` split, which the measured budget shows starves the paste cell) so the paste cell wins the
    largest share the shell allows; every `patch_*` id preserved, no handler touched.
  - *Rung 2 (fallback):* keep the paste group in the TR pane but give `#patch_paste_row` a
    `min-height`/weighted allocation and relocate the long `#patch_checks_help` text so the editor
    is not queued behind the file-row stack.
- **Residual scope tension (Phase-2 escalation, R-Q02/F-01):** even the best compose+CSS rung
  cannot reach the story's "read a multi-line change-set" aspiration @80x24 (physical ceiling ~1-2
  lines). Either the batch accepts a low N_80 (paste first line visible — a real improvement over
  the below-fold 0) with full readability being a 120x30 affordance, OR the mechanism expands beyond
  the story's "compose + CSS only" scope (e.g. a focus-to-expand paste box or a dedicated paste
  sub-view) — which is a scope change requiring re-approval. This LLR takes the FIRST option;
  flagged for the re-gate.
- **Executed verification:** AT-058a geometry pilot at 80x24 + 120x30 (content-region placement +
  measured N_w).
- **Numeric pass threshold:** at scroll 0, `#patch_paste_text` first line within its pane's visible
  content-region at both widths; visible lines ≥ N_80 @80x24 and ≥ N_120 @120x30 (Phase-3-pinned,
  each > 0); button-grid cell width ≥ 8 (no `"Validate"` clip) at both widths.
- **Acceptance criteria:** the widest inner row remains the 3-column button grid; the panel keeps
  its 2-column grid; `#patch_paste_text { height: 8 }` is retained or increased, never reduced.

#### LLR-058.2 — Paste group reparented + sibling-disjoint from the control cluster, no clip at 80 and 120
> AMENDED batch-36 Phase-2 (A-01 · Q-03). The prior "five control-group rectangles pairwise
> disjoint" predicate was UNSATISFIABLE: `#patch_doc_controls` and `#patch_checks_controls` are
> children of `#patch_doc_file_row` (`screens_directionb.py:1879,1906,1908`), so a parent⊃child
> rectangle can never be disjoint from its own descendant (and the overlap idiom
> `test_tui_patch_layout.py:161-176` counts containment as overlap). Redesigned to sibling-level
> disjointness + non-descendant + child⊂parent containment. See §6.5 record R-A01.
- **Traceability:** HLR-058 · **Validation:** test (pilot geometry + snapshot).
- **Statement:** The change-set paste group (`#patch_paste_row`) shall render under its own
  `patch-field-label` heading in a region that (a) is NOT a descendant of `#patch_pane_changefile`
  (reparented into its own panel cell), (b) does not overlap the change-file/patch-script/checks
  CLUSTER region (`#patch_doc_file_row`) at the SIBLING level, and (c) whose right edge does not
  exceed the panel host width; at both 80x24 and 120x30. The nested control groups
  (`#patch_doc_controls`, `#patch_checks_controls`) shall each remain a child of `#patch_doc_file_row`
  (child ⊂ parent containment), NOT disjoint from it.
- **Validation:** test · **Executed verification:** AT-058a (non-descendant + sibling-disjointness +
  containment predicates at both widths) + the snapshot cells (LLR-058.4).
- **Numeric pass threshold:** `#patch_paste_row` ∉ descendants of `#patch_pane_changefile`;
  region-rectangle intersection area == 0 for the sibling pair (`#patch_paste_row`,
  `#patch_doc_file_row`); each nested control group's rectangle ⊆ its parent's; `region.right <= host`
  for each at both widths.
- **Acceptance criteria:** builds on the batch-35 US-057 two-section labels
  (`#patch_script_section_label` / `#patch_checks_section_label`, `screens_directionb.py:1869`,
  `:1881`), which stay; this LLR adds the paste-group separation. The sibling-disjointness assertion
  is a CHEAP GUARD (a vertical stack is trivially non-overlapping before and after — Q-03); the C-10
  discriminator for readability is the AT-058a content-region placement, not this predicate.

#### LLR-058.3 — Zero behaviour change: id + wiring preservation (compose + CSS only)
- **Traceability:** HLR-058 · **Validation:** test (pilot regression).
- **Statement:** The change shall be compose-tree and CSS only; it shall not alter any
  `on_button_pressed` branch, any handler, or any key binding, and it shall preserve every
  existing patch-editor widget id — the 15-id census: `patch_doc_entries_table`,
  `patch_doc_path_input`, `patch_doc_file_select`, `patch_doc_load_button`,
  `patch_doc_validate_button`, `patch_doc_apply_button`, `patch_doc_save_button`,
  `patch_checks_run_button`, `patch_checks_help`, `patch_paste_text`,
  `patch_paste_parse_button`, `patch_variant_select`, `patch_execute_run_button`,
  `patch_saveback_name_input`, `patch_saveback_confirm_button` — plus the AT-032a locked
  `_CHECKS_HELP_TOKEN` span.
- **Validation:** test · **Executed verification:** AT-058b (id census + wiring regression) +
  existing `tests/test_tui_patch_editor_v2.py` suite unmodified.
- **Numeric pass threshold:** all 15 ids queryable; AT-032a token span present; existing patch
  suite green with 0 un-censused edits to assertion bodies.
- **Acceptance criteria:** mirrors the batch-35 US-057 no-behaviour-change contract
  (LLR-057.3); the id list is the census pre-state — verified present at
  `screens_directionb.py:1806-1980`.
- **Supersession census (change-first — the pins US-058 perturbs):**
  - **TC-319** `test_tc319_regroup_section_structure_census` (`tests/test_tui_patch_layout.py:351-438`)
    — **DISPOSITION: SURVIVES (rerun as regression).** RE-VERIFIED (probe P25): TC-319 asserts only
    (i) the 15-id census (`len(app.query("#id")) == 1` for each — invariant under a reparent, since
    `#patch_paste_row` still exists, just under a new parent), and (ii) the INTERNAL child order of
    `#patch_doc_file_row` (`patch_script_section_label`→`patch_doc_controls`,
    `patch_checks_section_label`→`patch_checks_controls`) and that `#patch_doc_controls` holds exactly
    Load/Validate/Apply/Save and `#patch_checks_controls` holds Run-checks+help. It queries
    `#patch_doc_file_row.children` — which does NOT include `#patch_paste_row` (already a sibling, not
    a child). US-058 rung-1 moves `#patch_paste_row` to a NEW sibling cell OUT of
    `#patch_pane_changefile`; `#patch_doc_file_row`'s internal parentage is UNTOUCHED. Therefore
    TC-319 SURVIVES unchanged. It must only be UPDATED (docstring note) IF a rung reorders
    `#patch_doc_file_row`'s own children — no rung does. This is the pin that makes A-01 undeniable
    (it demands the nesting the old five-region-disjoint predicate contradicted); the redesigned
    LLR-058.2 respects that nesting, so no conflict remains.
  - **AT-033a/b + grid-size-3 no-clip** (`tests/test_tui_patch_layout.py:79-215`) — SURVIVES (outer
    2×2 pane grid + `#patch_doc_controls` grid-3 untouched); EXTEND with a docstring note only if the
    chosen rung perturbs `#patch_doc_controls`.
  - **id-census region test** (`tests/test_tui_patch_editor_v2.py`) — SURVIVES (compose-only).

#### LLR-058.4 — Snapshot rebaseline (deferred to canonical CI)
- **Traceability:** HLR-058 · **Validation:** test (snapshot).
- **Statement:** The patch-editor SVG snapshot cells that render the paste region shall be
  re-baselined in the canonical `textual==8.2.8` CI environment; until then the drifted cells
  shall carry `xfail(strict=False)` marks.
- **Validation:** test · **Executed verification:** TC-321 (xfail-set assertion over the patch
  snapshot cells) — cell ids **`patch-comfortable-80x24`** / **`patch-comfortable-120x30`**
  (VERIFIED on disk, probe P26; `assumed` flag retired — corrects the draft `patch-80x24`, A-07/Q-06).
- **Numeric pass threshold:** the declared xfail set matches the observed drift; suite tail =
  green + declared xfail + 0 unexpected.
- **Acceptance criteria:** local regen is forbidden (drifts unrelated baselines,
  `reference_snapshot_regen_env`); the post-merge canonical regen retires the marks. Note the
  batch-35 `patch-comfortable-120x30` mark (LLR-057.4) is already parked — this batch supersedes
  whatever it left.

### HLR-059 — Workspace hex-view colour legend (US-059)
- **Traceability:** US-059 · **Priority:** medium · **Validation:** test (pilot + unit) ·
  **Ledger:** R-TUI-047 (proposed).
- **Statement:** The system shall document the hex view's cell colours by adding a Hex section
  to the shared legend table so that both the in-app `LegendScreen` modal and the generated
  project report's legend present, for each hex-cell overlay colour, its colour name and
  meaning, without modifying the engine-frozen `color_policy.py`.
- **Rationale (informative):** the hex view paints exactly two byte-cell overlay styles —
  `FOCUS_HIGHLIGHT_STYLE = "bold yellow"` (search / goto-focus span) and
  `MAC_ADDRESS_OVERLAY_STYLE = "bold orange3"` (MAC address overlay), applied in
  `render_hex_view_text` (`hexview.py:397-433`) — but `LEGEND_TABLE` documents only A2L / MAC /
  Issues, so the operator has no key for the hex colours. These overlay styles are interaction
  highlights, NOT `sev-*` validation severities (they are not in `SEVERITY_CLASS_MAP`).
- **Executed verification:** `pytest tests/test_tui_legend.py tests/test_report_service.py -q`
  + AT-059a via `pytest -k at059`.
- **Numeric pass threshold:** 0 failures; the two Hex meanings present in BOTH the modal body
  and the report legend; anti-drift TC-322 green.

#### LLR-059.1 — Add a Hex block to `LEGEND_TABLE` sourced from the shipped overlay styles
- **Traceability:** HLR-059 · **Validation:** test (unit).
- **Statement:** `s19_app/tui/legend.py::LEGEND_TABLE` shall gain a `"Hex"` entry with exactly
  two classification rows — one for the yellow search/goto-focus highlight and one for the
  orange MAC-overlay highlight — each row's meaning describing the byte condition the colour
  marks in the hex view, and the colour NAMES shall be DERIVED deterministically from the style
  constants `color_policy.FOCUS_HIGHLIGHT_STYLE` (`"bold yellow"`) and
  `color_policy.MAC_ADDRESS_OVERLAY_STYLE` (`"bold orange3"`) via the canonicalization transform
  defined in LLR-059.3 (not hardcoded), which are read (never edited) from the engine-frozen module.
  The two Hex meaning strings shall contain no Textual/console-markup metacharacters (`[` / `]`)
  since the modal renders each row via a markup-enabled `Label` (`screens.py:538`, no `markup=False`);
  the rows are static in-repo literals with no file-derived input, so this is an authoring
  constraint, not an injection fix (S-01).
- **Validation:** test · **Executed verification:** TC-322 (Hex block present, two rows,
  non-blank colour + meaning; colours coupled to the two `color_policy` constants; no `[`/`]` in the
  meaning strings).
- **Numeric pass threshold:** `set(LEGEND_TABLE) == {"A2L","MAC","Issues","Hex"}`; the Hex block
  has 2 rows; neither meaning blank; neither meaning contains `[` or `]`.
- **Acceptance criteria:** the `>`-glyph goto focus-row marker (R-TUI-040, a plain non-styled
  prefix, `hexview.py:406-408`) is deliberately NOT a legend colour row — it is a glyph, not a
  colour; recorded so the exclusion is a decision, not an omission. Plain (unhighlighted) bytes
  need no row (the default foreground, mirroring the absent "White" severity rationale in
  `legend.py:18-19`).

#### LLR-059.2 — One added block reaches BOTH legend surfaces (single-source, C-12)
- **Traceability:** HLR-059 · **Validation:** test (pilot + unit).
- **Statement:** The Hex block shall be rendered by both consumers without any duplicated
  literal: the `LegendScreen` modal (which iterates `LEGEND_TABLE.items()`, `screens.py:527`)
  and `report_service._legend_lines` (which iterates the same table, `report_service.py:1318`).
- **Validation:** test · **Executed verification:** AT-059a (both surfaces show the two Hex
  meanings) + TC-322 structure.
- **Numeric pass threshold:** both surfaces contain both Hex meaning strings; 0 duplicated Hex
  literal outside `LEGEND_TABLE`.
- **Acceptance criteria:** with the LLR-059.3 canonicalization (`"Yellow"` / `"Orange3"`, shade
  digit retained), the modal's per-row severity lookup `COLOUR_SEVERITY.get(colour)` returns `None`
  for BOTH Hex overlay colours and the modal already renders `sev_class = ""` in that case
  (`screens.py:530-535`) — so the Hex rows render with no `sev-*` class and no crash. (Had the name
  been the digit-stripped `"Orange"`, the lookup would return WARNING and paint the row `sev-warning`
  — the reason the canonicalization retains the digit; R-A04.) In the report, since classification ==
  colour for each Hex row, `_legend_lines` emits `- **Yellow** — …` / `- **Orange3** — …` with no
  parenthetical suffix (the suffix shows only when colour differs from the classification label,
  `report_service.py:1321`).

#### LLR-059.3 — Anti-drift: Hex block decoupled from `COLOUR_SEVERITY`, coupled to overlay styles
- **Traceability:** HLR-059 · **Validation:** test (unit).
- **Statement:** The existing `COLOUR_SEVERITY`↔`SEVERITY_CLASS_MAP` anti-drift coupling
  (TC-S1, `test_tui_legend.py:58`) shall NOT be extended to the Hex overlay colours — because
  those colours are interaction styles, not validation severities — and the TC-S1 orphan-colour
  assertion (`test_tui_legend.py:70`) and the artifact/row-set assertion
  (`test_tui_legend.py:78`) shall be updated to admit the `"Hex"` artifact and to scope the
  severity-orphan check to the severity-driven artifacts (A2L/MAC/Issues) so the Hex overlay
  colours are exempt without loosening the strict severity guard, with a NEW coupling asserting the
  Hex block's colour set is DERIVED from the two `color_policy` overlay-style constants so the hex
  legend cannot silently diverge from the shipped hex render.
- **Colour-name canonicalization transform (A-04 / Q-07 — the EXACT rule):** `legend.py` shall
  expose a deterministic `hex-colour-name → style-constant` mapping built by a helper
  `_colour_name_from_style(style: str) -> str` that (1) splits the style string on whitespace,
  (2) discards the Rich modifier tokens `{bold, italic, dim, underline, reverse, blink, strike}`,
  (3) takes the remaining colour token, and (4) title-cases it AS-IS (shade digit retained):
  `"bold yellow" → "Yellow"`, `"bold orange3" → "Orange3"`. **The shade digit is deliberately
  RETAINED** (`"Orange3"`, not `"Orange"`): stripping it would collide with the existing
  `COLOUR_SEVERITY` key `"Orange"` (→ WARNING), which would make the modal paint the Hex overlay row
  with `sev-warning` and contradict the D-059 "not a severity" design + LLR-059.2's "severity column
  empty for Hex rows" invariant. `_colour_name_from_style` is defined in the non-frozen `legend.py`;
  the frozen `color_policy.py` is only READ. (NOTE: the Phase-2 orchestrator's shorthand wrote
  "Orange"; the code-grounded resolution is `"Orange3"` — see §6.5 record R-A04 for the rationale.)
- **Validation:** test · **Executed verification:** TC-322 (extends TC-S1: `"Hex"` admitted; the
  orphan check scoped to A2L/MAC/Issues; `set(HEX_LEGEND_STYLES.values()) ==
  {FOCUS_HIGHLIGHT_STYLE, MAC_ADDRESS_OVERLAY_STYLE}` identity; `_colour_name_from_style("bold
  orange3") == "Orange3"` and `("bold yellow") == "Yellow"` pinned; Hex block colour names ==
  `set(HEX_LEGEND_STYLES)`).
- **Numeric pass threshold:** `SEVERITY_CLASS_MAP ⊆ COLOUR_SEVERITY.values()` still holds (no
  new severity); the scoped orphan assertion passes; the Hex-to-`color_policy` coupling fails if
  either overlay constant is renamed/removed or the derived name diverges.
- **Acceptance criteria:** RE-VERIFIED finding (A-02 / Q-05, probe P13) — adding `"Hex"` to
  `LEGEND_TABLE` breaks exactly **TWO** existing assertions today, not three:
  (i) `set(LEGEND_TABLE) == {"A2L","MAC","Issues"}` (`test_tui_legend.py:78`) — breaks; and
  (ii) the orphan-colour check `used_colours <= set(COLOUR_SEVERITY) | {"White"}` (`:70`) — breaks
  because the new `"Yellow"` (and `"Orange3"`) are ∉ `COLOUR_SEVERITY ∪ {White}`. The modal-header
  equality `headers == list(LEGEND_TABLE)` (`:322`) **SURVIVES** — both sides derive dynamically
  from `LEGEND_TABLE` (`screens.py:527`), so `"Hex"` appears on both sides and the equality holds;
  it is a surviving single-source regression guard and is NOT modified (it reruns green). Likewise
  `len(meanings) == _TOTAL_ROWS` (`:323`) survives (`_TOTAL_ROWS` is a live sum). Both broken
  assertions live in the NON-frozen `tests/test_tui_legend.py` and are updated by this LLR; the
  frozen `color_policy.py` is only READ (constants imported), so `test_engine_unchanged` and
  `test_legend_data_not_in_frozen_color_policy` (`:104`) stay green. With the `"Orange3"`
  canonicalization above, `COLOUR_SEVERITY.get("Orange3")` and `.get("Yellow")` both return `None`,
  so the modal severity column is empty for BOTH Hex rows (consistent with LLR-059.2 and D-059).

### HLR-060 — Relocate test inputs into `examples/` and prune the heavy duplicate A2L (US-060)
- **Traceability:** US-060 · **Priority:** medium · **Validation:** test (smoke green) +
  inspection · **Ledger:** R-TUI-048 (proposed).
- **Statement:** The system's example-fixture tree shall relocate the git-tracked
  `tmp/stress_smoke/` inputs into `examples/` as a discoverable case, shall remove the
  redundant 54 MB slow-only large-A2L duplicate while retaining one large-A2L fixture, and shall
  do so with no reduction in the functional coverage of the example smoke and pilot tests.
- **Rationale (informative):** `examples/` is 96 MB, of which two `case_06_large_nested_a2l`
  copies (36 MB top-level + 54 MB under `professional_validation/`) carry ~90 MB; the 54 MB copy
  is the `pv__case_06_large_nested_a2l` slow (~490 s) case that runs only on push-to-main full
  CI, whereas the 36 MB top-level case runs on every PR in the normal suite — so the 36 MB copy
  is the higher-value fixture to keep. See §6 DF-2 for the provenance caveat.
- **Executed verification:** `pytest tests/test_examples_smoke.py -q` (green over the
  newly-discovered case set) + AT-060a + TC-323 + a before/after `du -sh examples`.
- **Numeric pass threshold:** smoke suite 0 failures; `examples/` reduced by ~54 MB (≈ 96 MB →
  ≈ 42 MB); `tmp/stress_smoke/` absent; the retained 36 MB A2L present.

#### LLR-060.1 — Relocate `tmp/stress_smoke/` into a discoverable `examples/` case
- **Traceability:** HLR-060 · **Validation:** test (smoke) + inspection.
- **Statement:** The three tracked files `tmp/stress_smoke/stress.{a2l,mac,s19}` shall be moved
  with **`git mv`** (not a raw-FS move — index consistency + reversibility, S-02) into a new
  `examples/case_07_stress_smoke/` directory (image renamed to the discovery-preferred
  `firmware.{s19,a2l,mac}` names, or left as `stress.*` which the fallback globs also resolve),
  `tmp/stress_smoke/` shall be removed, and any reference to the old path shall be updated. After
  the move, `git ls-files tmp/stress_smoke` shall be empty and `git status` shall show the change as
  renames, not untracked orphans.
- **Validation:** test · **Executed verification:** grep `stress_smoke` across `tests/`, `s19_app/`,
  docs → **0 hits today** (probed 2026-07-11; re-verify at Phase 3) so no reference update is
  required beyond docs; AT-060a asserts the new case loads and the old path is gone.
- **Numeric pass threshold:** `tmp/stress_smoke/` absent; `git ls-files tmp/stress_smoke` empty;
  `examples/case_07_stress_smoke/` present with a loadable primary image producing a non-empty
  `LoadedFile`.
- **Acceptance criteria:** `_discover_cases` (`test_examples_smoke.py:47`, `_pilot_gifs:49`)
  auto-picks up any new `examples/<dir>/` as a case — so the relocated files GAIN normal-suite
  pipeline coverage they lack in `tmp/`; `_pick_primary/_pick_a2l/_pick_mac` resolve either
  `firmware.*` or `stress.*` via their fallback globs (`test_examples_smoke.py:73-104`).

#### LLR-060.2 — Prune the 54 MB slow duplicate, retain the 36 MB large A2L
- **Traceability:** HLR-060 · **Validation:** inspection + test.
- **Statement:** `examples/professional_validation/case_06_large_nested_a2l/` (54 MB, the
  `pv__case_06_large_nested_a2l` slow case) shall be deleted with **`git rm -r`** (not a raw-FS
  delete — index consistency + `git revert` reversibility, S-02), and
  `examples/case_06_large_nested_a2l/firmware.a2l` (~36 MB, exercised by the normal smoke suite)
  shall be retained as the bare-minimum large-A2L fixture (operator constraint D-1); the other
  seven `professional_validation/` cases (negligible size) shall be retained. **The delete shall be
  BLOCKED until the I-060-1 construct-equivalence gate below passes and its evidence is recorded.**
- **I-060-1 — HARD verify-before-delete gate (A-08 / Q-04 — a precondition, not a size check):**
  before `git rm`, a construct-kind subset census shall PROVE the retained 36 MB
  `case_06/firmware.a2l` exercises the same A2L construct kinds as the 54 MB duplicate — i.e. the
  54 MB is a pure SCALE duplicate, not a superset carrying a unique parser/validator branch. **Exact
  check:** extract the distinct `/begin <KIND>` block-keyword set from each file —
  `grep -ohE '/begin[[:space:]]+[A-Z_]+' <file> | awk '{print $2}' | sort -u` (or the equivalent
  parse of section kinds via `s19_app/tui/a2l.py`: MEASUREMENT / CHARACTERISTIC / COMPU_METHOD /
  RECORD_LAYOUT / AXIS_PTS / GROUP / FUNCTION / MODULE / MOD_COMMON / MOD_PAR / DEF_CHARACTERISTIC /
  REF_CHARACTERISTIC / HEADER / PROJECT). **Pass condition:** `kinds(54 MB) ⊆ kinds(36 MB)`. If any
  kind is present ONLY in the 54 MB copy → **BLOCK the delete** until that branch is covered
  elsewhere. The census evidence (both kind-sets + the ⊆ verdict) shall be recorded in the Phase-3
  gate BEFORE the irreversible `git rm`.
- **Validation:** inspection · **Executed verification:**
  - Sizes verified 2026-07-11: `case_06_large_nested_a2l/firmware.a2l` = 37,742,888 B;
    `professional_validation/case_06_.../firmware.a2l` = 56,046,631 B; `professional_validation/`
    total du = 54 M (≈ all case_06).
  - I-060-1 DRAFT-TIME PREVIEW (probe P27, 2026-07-11): both files' `/begin` kind-sets are
    **IDENTICAL** — {CHARACTERISTIC, COMPU_METHOD, DEF_CHARACTERISTIC, FUNCTION, GROUP, HEADER,
    MEASUREMENT, MODULE, MOD_COMMON, MOD_PAR, PROJECT, RECORD_LAYOUT, REF_CHARACTERISTIC} (13 kinds
    each) → `kinds(54 MB) ⊆ kinds(36 MB)` holds; the 54 MB is a pure scale duplicate. **Phase 3 must
    RE-RUN and RECORD this census before `git rm`** (draft preview is not the recorded gate evidence).
- **Numeric pass threshold:** I-060-1 census recorded with `kinds(54 MB) ⊆ kinds(36 MB)` TRUE; the
  54 MB path absent; the 36 MB path present; `du -sh examples` ≈ 42 M.
- **Acceptance criteria:** DF-2 (provenance) — the retained fixture is documented "synthetic,
  not tied to any OEM/ECU/vendor" (`case_00_public/MANIFEST.md:25`); D-1's "real-vendor" intent
  is satisfied by keeping the representative large A2L regardless of provenance labelling (a
  larger real-vendor set does not exist in-repo). If the operator meant a different, genuinely
  vendor-sourced file, that is a Phase-2 clarification — the keep/delete decision is unchanged.

#### LLR-060.3 — Test edits + coverage-preservation map
- **Traceability:** HLR-060 · **Validation:** test.
- **Statement:** `tests/test_examples_smoke.py` shall be updated so `SLOW_CASE_IDS` no longer
  names the deleted case (becoming empty) and its module docstring case counts reflect the new
  tree (top-level 7→8, nested 8→7); no functional assertion shall be removed; the pilot-gif and
  snapshot observers shall be swept per the C-14 location-move census.
- **Validation:** test · **Executed verification:** C-14 census (probed 2026-07-11):
  - `test_examples_smoke.py:44` `SLOW_CASE_IDS = {"pv__case_06_large_nested_a2l"}` → set to
    `set()`; docstring `:8-9` counts updated.
  - `test_examples_pilot_gifs.py` — dynamic discovery (`_discover_cases` :49), whole test is
    `@pytest.mark.slow` (:183); NO edit required (it drops the pv gif, gains a stress gif); slow
    artifacts under `tests/_artifacts/` (gitignored).
  - `test_tui_snapshot.py:685-703` — a forbidden-token guard asserting snapshot SETUP code does
    NOT reference `professional_validation` / `case_0N_` / absolute paths; UNAFFECTED (we neither
    add those tokens to setup helpers nor require the deleted dir to exist); the new
    `case_07_stress_smoke` token is not on the forbidden list.
  - `docs/architecture.md:152` names `pv__case_06_large_nested_a2l` as the pinned slow case →
    stale after deletion; updated as a Phase-6 docs deliverable.
  - `examples/case_00_public/MANIFEST.md:21-22` describes the RETAINED 36 MB `case_06` (~35 MB)
    — still accurate; add a `case_07_stress_smoke` entry (docs).
  - No hard-coded case-count assertion exists (both discovery loops are dynamic; no `== 8`).
- **Coverage-preservation map (each affected requirement → still-covered-by):**

  | Functional coverage today | Provided by (before) | After the change |
  |---|---|---|
  | Parser→enrich→validate over a LARGE nested A2L | 36 MB `case_06` (normal) + 54 MB `pv__case_06` (slow) | 36 MB `case_06` (normal suite, every PR) — same pipeline, same assertions, now the sole large-A2L case |
  | Per-case load/enrich/validate smoke | all `examples/*` + `pv/*` (dynamic) | same set minus pv/case_06, PLUS the new `case_07_stress_smoke` (net +1 small case) |
  | Pilot-driven TUI GIF/SVG evidence | all cases (slow) | same, minus pv/case_06 gif, plus stress gif |
  | Stress fixtures (`tmp/stress_smoke`) | NOT exercised by any test (orphan in `tmp/`) | now exercised by the smoke + pilot pipeline (coverage GAIN) |

- **Numeric pass threshold:** `SLOW_CASE_IDS == set()`; `test_examples_smoke.py` green over the
  8 top-level + 7 nested discovered cases; 0 functional assertions removed.
- **Acceptance criteria:** no requirement loses coverage — the "large nested A2L" pipeline is
  still exercised (by the retained 36 MB case, in the NORMAL suite rather than slow-only), and
  the relocated stress files move from zero coverage to full pipeline coverage.

#### LLR-060.4 — Measured size reduction + `tmp/` cleanup
- **Traceability:** HLR-060 · **Validation:** inspection.
- **Statement:** After the change the `examples/` tree shall be materially smaller (≈ 96 MB →
  ≈ 42 MB, a ~54 MB reduction) and `tmp/stress_smoke/` (and `tmp/` if left empty) shall be
  removed from the working tree; git history size is out of scope (no filter-repo pass).
- **Validation:** inspection · **Executed verification:** `du -sh examples` before (96 M) /
  after (≈ 42 M); `tmp/` absent or empty.
- **Numeric pass threshold:** `examples/` ≤ 45 M; `tmp/stress_smoke/` absent.
- **Acceptance criteria:** working-tree reduction only; existing clone/history weight is not
  reclaimed (out of scope, would need a separate approved history rewrite).

## 5. Traceability

### 5.1 Behavioral chain (US → AT → observable outcome, black-box)

| US | Observable outcome | Shipped surface | Acceptance test | Observed? |
|----|--------------------|-----------------|-----------------|-----------|
| US-058 | Paste editor first line in-viewport at scroll 0 (vs below-fold today) with ≥ N_w measured lines; paste group reparented out of `#patch_pane_changefile`, sibling-disjoint from the control cluster | Patch Editor screen | AT-058a | Phase 4 |
| US-058 | All 15 patch ids queryable; every button/binding behaves as pre-batch | Patch Editor screen | AT-058b | Phase 4 |
| US-059 | LegendScreen modal shows a Hex section with the two overlay-colour meanings | LegendScreen modal | AT-059a | Phase 4 |
| US-059 | Generated report's legend shows a Hex section with the two overlay-colour meanings (C-12 reread) | project-report legend (`reports/*.md`) | AT-059b | Phase 4 |
| US-060 | `tmp/stress_smoke` gone; `examples/case_07_stress_smoke` loads; 54 MB duplicate gone (I-060-1-gated), 36 MB retained; smoke green | `examples/` tree via smoke suite | AT-060a | Phase 4 |

### 5.2 Functional chain (US → HLR → LLR → TC/AT, white-box)

| US | HLR | LLR | Test case / AT | Notes |
|----|-----|-----|----------------|-------|
| US-058 | HLR-058 | LLR-058.1 | AT-058a | C-13: 3-col reflow clips `Validate` @80 (7<8) → dedicated paste cell; N_w measured (F-01) |
| US-058 | HLR-058 | LLR-058.2 | AT-058a | paste reparented + sibling-disjoint from cluster; nested pairs = containment (not disjoint) |
| US-058 | HLR-058 | LLR-058.3 | AT-058b | 15-id census + wiring regression; TC-319 SURVIVES |
| US-058 | HLR-058 | LLR-058.4 | TC-321 | patch snapshot xfail set (`patch-comfortable-80x24`/`-120x30`), canonical regen |
| US-059 | HLR-059 | LLR-059.1 | TC-322 | Hex block added, colour names derived from color_policy constants; no `[ ]` markup |
| US-059 | HLR-059 | LLR-059.2 | AT-059a + AT-059b | both surfaces render the one block (single source) |
| US-059 | HLR-059 | LLR-059.3 | TC-322 | TC-S1: admit "Hex", scope orphan check to severity artifacts, couple to overlay styles (2 assertions break, not 3) |
| US-060 | HLR-060 | LLR-060.1 | AT-060a | relocation via `git mv`; new case auto-discovered + loads |
| US-060 | HLR-060 | LLR-060.2 | AT-060a (inspection), I-060-1 gate | 54 MB pruned via `git rm` (construct-census-gated), 36 MB retained |
| US-060 | HLR-060 | LLR-060.3 | TC-323 | discovery + SLOW_CASE_IDS empty + coverage map |
| US-060 | HLR-060 | LLR-060.4 | AT-060a (inspection) | size 96 M → ~42 M; tmp removed |

**Coverage:** 3 US → 3 HLR → 11 LLR; every HLR traces to exactly one US; every LLR to its
parent HLR; every US has ≥1 AT observing its outcome through the shipped surface. New ATs:
**AT-058a, AT-058b, AT-059a, AT-059b, AT-060a (5)** — AT-059b added by the batch-36 Phase-2 fold
(A-06/Q-08, C-21: registry reconciled BEFORE any Phase-3 increment cut). New TCs: TC-321, TC-322,
TC-323 (3).

## 6. Probe ledger, draft-time findings, decisions, evidence checklist

### 6.1 Probe ledger (executed at draft, 2026-07-11, tree `7df60dd`)

| # | Claim to verify | Probe (file:line / command) | Result |
|---|-----------------|-----------------------------|--------|
| P1 | Highest AT id in tree | `grep -rhoE 'AT-[0-9]{3}[a-z0-9]?' --include=*.py --include=*.md .` | max `AT-057b` → AT-058a free ✓ |
| P2 | Highest TC id in use | `grep TC- tests/` → max TC-319; REQUIREMENTS.md → `TC-320` | continue TC-321 ✓ |
| P3 | Highest R-TUI id | `grep R-TUI- REQUIREMENTS.md` → `R-TUI-045` | 046/047/048 free ✓ |
| P4 | Patch paste editor height | `styles.tcss:949-951` `#patch_paste_text { height: 8 }` | already 8 — see DF-1 ✓ |
| P5 | Patch panel grid + host budget | `styles.tcss:695-704` (host 70@80/92@120; `grid-size: 2 3`; `grid-columns: 1fr 1fr`) | 2-col ⇒ ~35/pane @80 ✓ |
| P6 | Button-grid columns | `styles.tcss:902-908` `#patch_doc_controls { grid-size: 3; grid-gutter: 0 1 }` | cell ≈11@80 / ≈7@80 if 3-col panel ✓ |
| P7 | Pane scroll + clip mask | `styles.tcss:707-714` (`overflow-y: auto; overflow-x: hidden`) | within-pane clip masked ✓ |
| P8 | Compose ids + two US-057 section labels | `screens_directionb.py:1806-1980` (`#patch_script_section_label:1869`, `#patch_checks_section_label:1881`, `#patch_paste_text:1915`) | 15-id census confirmed ✓ |
| P9 | Hex cell colouring mechanism | `hexview.py:16, 397-433`; `color_policy.py:13-14` | two overlay styles: `bold yellow`, `bold orange3`; NO `sev-*` on hex cells ✓ |
| P10 | `>` focus-row marker is plain | `hexview.py:406-408` (`text.append("> ")`, no `style=`) | glyph, not colour (R-TUI-040) ✓ |
| P11 | Both legend consumers iterate `LEGEND_TABLE` | `screens.py:527`, `report_service.py:1318` | one block reaches both ✓ |
| P12 | Modal handles unknown colour | `screens.py:530-535` (`COLOUR_SEVERITY.get` → `""`) | Hex rows render, no crash ✓ |
| P13 | Anti-drift test that breaks on "Hex" | `test_tui_legend.py:58-85` (orphan check :70; artifact-set :78) + `:322` modal headers | **2** assertions break (:70, :78); `:322` SURVIVES (dynamic) — CORRECTED from draft "3", A-02/Q-05 ✓ |
| P14 | Frozen-diff guard on color_policy | `test_tui_legend.py:104-120`; CLAUDE.md `_ENGINE_PATHS` | color_policy READ-only → guard green ✓ |
| P15 | Two large A2L sizes | `find examples -name *.a2l -size +1M` | 36 MB top-level, 54 MB pv ✓ |
| P16 | pv/case_06 is the slow case | `test_examples_smoke.py:41-44` `SLOW_CASE_IDS` | ~490 s, slow-only ✓ |
| P17 | `examples/` + `tmp/` sizes | `du -sh examples tmp` | 96 M / 9 K ✓ |
| P18 | Discovery is dynamic (no hard count) | `test_examples_smoke.py:47-70`, `test_examples_pilot_gifs.py:49-62` | auto-picks new case; no `== 8` ✓ |
| P19 | `stress_smoke` references repo-wide | `grep -rI stress_smoke` (excl. batch-36) | **0 hits** ✓ |
| P20 | CI slow policy | `.github/workflows/tui-ci.yml:47` `-m "not slow"`; pyproject.toml:53 | PRs skip slow; pushes run full ✓ |
| P21 | Other refs to the deleted case | `grep -rI case_06 / professional_validation` (active worktree) | `docs/architecture.md:152` (update), `MANIFEST.md:21` (refers to retained 36 MB) ✓ |
| P22 | Snapshot forbidden-token guard scope | `test_tui_snapshot.py:685-703` | forbids tokens in SETUP code only; unaffected ✓ |
| P23 | Fixture provenance | `case_00_public/MANIFEST.md:25` | "synthetic, not tied to any OEM/ECU/vendor" — see DF-2 ✓ |
| P24 | US-058 paste vertical budget (Phase-2 re-measure) | Textual pilot @80x24 + @120x30, `action_show_screen("patch")`, scroll 0 | `#patch_editor_panel` content h = **5 @80x24 / 11 @120x30**; `#patch_pane_changefile` content h = **2 / 5**; `#patch_paste_text.region.y` = **38 (vs pane [8,10))** @80 / **36 (vs [8,13))** @120 → **0 in-viewport paste lines today**; ancestor cap = `workspace_shell` region h=9 @80. Draft "~9 rows/pane" WRONG ~4.5× (F-01) ✓ |
| P25 | TC-319 disposition under US-058 reparent | `tests/test_tui_patch_layout.py:351-438` | asserts 15-id census + `#patch_doc_file_row` INTERNAL child order only; does NOT pin `#patch_paste_row` parentage → **SURVIVES** a paste reparent (A-03) ✓ |
| P26 | Snapshot cell ids for LLR-058.4 | `ls tests/__snapshots__/test_tui_snapshot/` | on disk: `…[patch-comfortable-80x24].svg` + `…[patch-comfortable-120x30].svg` → corrects draft `patch-80x24`; `assumed` retired (A-07/Q-06) ✓ |
| P27 | I-060-1 construct-kind subset (US-060) | `grep -ohE '/begin +[A-Z_]+' <a2l> \| awk '{print $2}' \| sort -u` on both firmware.a2l | both = IDENTICAL 13 kinds {CHARACTERISTIC,COMPU_METHOD,DEF_CHARACTERISTIC,FUNCTION,GROUP,HEADER,MEASUREMENT,MODULE,MOD_COMMON,MOD_PAR,PROJECT,RECORD_LAYOUT,REF_CHARACTERISTIC} → `kinds(54M) ⊆ kinds(36M)` (pure scale dup); **Phase 3 re-runs + records before `git rm`** (A-08/Q-04) ✓ |

### 6.2 Draft-time findings (contradictions reconciled)
- **DF-1 (US-058) — the paste box is already `height: 8`.** The §2.6 intake's "1-2 usable
  lines" is NOT the widget's configured height (`styles.tcss:949`, batch-31 B-05 set it to 8);
  it is a VISIBLE-lines-below-the-fold symptom of the overstuffed TR pane (LLR-058.1 vertical
  budget). Consequence: AT-058a asserts VISIBLE/rendered lines in the pane viewport via the
  content-region placement idiom, never the `height` style property (which is already satisfactory).
  The fix is vertical separation, not enlarging the editor.
  **F-01 (Phase-2 re-measure, SUPERSEDES DF-1's "~9-row" figure):** the actual measured budget is
  far smaller — `#patch_editor_panel` content is only **5 rows @80x24 / 11 @120x30**, each 1fr pane
  ~2/~5 rows, and the paste box is **0** in-viewport lines today (region.y=38 vs pane [8,10) @80x24;
  probe P24). This refutes the a-priori "≥6 @80x24 / ≥8 @120x30" targets — they are physically
  unsatisfiable under compose+CSS-only — so N_w became a per-width Phase-3 MEASURED pin (LLR-058.1)
  and the 80x24 readability aspiration is flagged as a residual scope tension for the re-gate.
- **DF-2 (US-060) — "real-vendor" vs "synthetic".** The intake and operator constraint D-1 call
  the large A2Ls "real-vendor", but `case_00_public/MANIFEST.md:25` states the fixtures are
  "synthetic and not tied to any OEM, ECU, or vendor". Reconciliation: keep the representative
  large A2L (36 MB) regardless of the provenance label; the keep/delete decision is unchanged. A
  genuinely vendor-sourced file would be a Phase-2 clarification, not a blocker.

### 6.3 Design decisions
- **D-058 — mechanism = dedicated paste region; three-column reflow rejected** by the measured
  80-col horizontal budget (button-grid cell 7 < 8 cols; LLR-058.1). C-13.1 deficit-matched
  ladder recorded (rung-1 grid restructure, rung-2 in-pane `1fr`).
- **D-059 — Hex overlay colours are interaction styles, not severities.** The Hex legend block
  is decoupled from `COLOUR_SEVERITY`/`SEVERITY_CLASS_MAP` and coupled instead to the two
  `color_policy` overlay-style constants; TC-S1 is extended (non-frozen test file), the frozen
  `color_policy.py` only read. The `>` goto marker is excluded (glyph, not colour).
- **D-060 — keep 36 MB (normal-suite), delete 54 MB (slow-only duplicate).** Higher routine
  coverage per CI-second and smaller; relocate `tmp/stress_smoke` into a discoverable case
  (coverage GAIN); no history rewrite.

### 6.4 Evidence checklist
- ✓ **Normative-keyword compliance** — `shall` only in HLR/LLR statements (§4); informative
  prose uses `should`/plain indicative; verified by reading each statement block.
- ✓ **Traceability completeness** — 3 US → 3 HLR → 11 LLR; every HLR→one US, every LLR→parent
  HLR, every US→≥1 AT (§5.1/§5.2 tables).
- ✓ **Every output-producing requirement names its deliverable + observation** — AT-058a (pilot
  region geometry), AT-059a (modal Labels + report legend file, C-12), AT-060a (`examples/` tree
  + green smoke), LLR-060.4 (`du` measurement).
- ✓ **C-13 budget stated for US-058** — LLR-058.1: host 70@80/92@120; 2-col ⇒ 35/pane, cell 11
  (fits `Validate`=8); 3-col ⇒ 23/pane, cell 7 (clips) → reflow rejected. **Vertical budget now
  MEASURED (F-01, P24), not estimated:** panel content 5@80x24 / 11@120x30, panes ~2/~5 rows, paste
  0 in-viewport today → N_w is a per-width Phase-3 measured pin, the "≥6/≥8" a-priori targets
  retired as physically unsatisfiable.
- ✓ **Hex colour set sourced from shipped code for US-059** — `hexview.py:397-433` +
  `color_policy.py:13-14`: exactly `bold yellow` (search/focus) and `bold orange3` (MAC
  overlay); `>` marker is a plain glyph; NO invented colours.
- ✓ **C-14 census + coverage-preservation map for US-060** — LLR-060.3 census (smoke, pilot-gif,
  snapshot guard, docs, MANIFEST) + the coverage table; keep-36/delete-54 preserves the
  large-A2L pipeline in the normal suite and adds coverage for the relocated stress files. **The
  delete is now HARD-GATED on the I-060-1 construct-kind subset census (LLR-060.2), recorded before
  `git rm`** (previously size-only — A-08/Q-04 resolved).
- ✓ **C-10 honored (vacuous-AT items RESOLVED)** — AT-058a's discriminator is now the content-region
  PLACEMENT (first line in-viewport at scroll 0, MEASURED counterfactual = 0 today), replacing the
  CSS-invariant `region.height >= N` (Q-01) and the unsatisfiable five-region pairwise-disjoint
  predicate (A-01/Q-03, now sibling-disjoint + containment); AT-059a/AT-059b assert the two specific
  Hex meanings in each surface; AT-060a asserts the new case yields mapped memory (content, not mere
  presence).
- ✓ **C-12 honored** — AT-059b drives `generate_project_report` and rereads the written
  `reports/*.md` (report-seam idiom); AT-060a drives the real service pipeline; AT-058b reads the
  real handler's status line.
- ✓ **C-17 discharged** — N/A for all three (no file-derived rendered text); stated in §3.
- ✓ **Snapshot cell ids (LLR-058.4)** — VERIFIED on disk (probe P26): `patch-comfortable-80x24` /
  `patch-comfortable-120x30`; the draft `patch-80x24` corrected, the `assumed` flag retired
  (A-07/Q-06).
- ✓ **Two-layer / AT-registry reconciled (C-21)** — every US carries a first-class black-box AT
  (AT-058a, AT-059a/b, AT-060a) + the functional US→HLR→LLR→TC chain; the hex-legend AT split into
  AT-059a (modal) + AT-059b (report reread) is consistent across §3/§5.1/§5.2; the registry (5 ATs)
  was reconciled in THIS amendment, BEFORE any Phase-3 increment cut, so C-21 is satisfied.

### 6.5 Amendment log (Phase-2 fold — Before -> After, re-verified not folded blind)

> Every fold below was re-verified against the worktree tree (`heuristic-wu-1c7c49` @ base `7df60dd`)
> on 2026-07-11 with the file:line / probe cited. Findings from `02-review.md` (+ the three
> `02-review-*.md`). Operator approved iterate-to-refine. No story killed — all folds are
> corrections/gates. Sections edited in place; this log is the audit trail.

**R-A01 — US-058 AT-058a / LLR-058.2 five-region pairwise-disjoint predicate (BLOCKER, A-01 + Q-03).**
- **Before:** "the five control groups (entries · change-file · patch-script · checks · paste) each
  occupy a distinct region with no region rectangle overlapping another … pairwise region-rectangle
  intersection area == 0 for the five groups."
- **After:** paste group asserted NOT a descendant of `#patch_pane_changefile` + sibling-disjoint from
  the `#patch_doc_file_row` cluster; nested pairs (`#patch_doc_controls`/`#patch_checks_controls`)
  asserted as child in parent CONTAINMENT, never disjointness.
- **Re-verification:** `screens_directionb.py:1848-1923` — `#patch_doc_controls` (`:1879`) and
  `#patch_checks_controls` (`:1906`) are children of `#patch_doc_file_row` (`:1908`); the overlap
  idiom counts containment as overlap (`tests/test_tui_patch_layout.py:161-176`). Predicate was
  unsatisfiable; redesigned to satisfiable sibling-level + containment. OK

**R-A03 — US-058 LLR-058.3 supersession census missing TC-319 (MAJOR, A-03).**
- **Before:** LLR-058.3 census listed the 15-id list only; TC-319 absent.
- **After:** TC-319 added to the LLR-058.3 census with disposition **SURVIVES** (rerun as regression),
  with the explicit reasoning that a paste reparent leaves `#patch_doc_file_row`'s internal parentage
  untouched.
- **Re-verification:** `tests/test_tui_patch_layout.py:351-438` (probe P25) — TC-319 asserts the
  15-id census + `#patch_doc_file_row.children` internal order; it does NOT pin `#patch_paste_row`'s
  parentage, so a reparent to a new sibling cell keeps it green. SURVIVES. OK

**R-Q01 — US-058 AT-058a paste metric `region.height >= N` is CSS-invariant (BLOCKER, Q-01 + A-05).**
- **Before:** "`query_one("#patch_paste_text").region` height >= the pinned N in the visible viewport …
  paste region visible height >= 6 rows @80x24 and >= 8 @120x30."
- **After:** content-region PLACEMENT idiom — at `scroll_y == 0`, `pane.content_region.y <=
  paste.region.y` and `paste.region.y + N_w <= pane.content_region.bottom`, null-region guard
  `if paste.region.width and paste.region.height`; raw `region.height` explicitly banned.
- **Re-verification:** `styles.tcss:949-951` (`#patch_paste_text { height: 8 }` — invariant);
  precedent idiom `tests/test_tui_patch_variant.py:427-438` (TC-035.2). Counterfactual measured RED:
  paste region.y=38 vs pane content [8,10) @80x24 (probe P24). OK

**R-Q02 / F-01 — US-058 N re-derivation + measured vertical-budget refutation (BLOCKER-adjacent, Q-02
+ A-05 + NEW finding F-01 beyond the three reviews).**
- **Before:** "a dedicated 1fr paste region (~9 rows @24, ~12 @30) clears the >=6/>=8 targets"; N
  pinned a priori at 6@80 / 8@120.
- **After:** measured budget block — `#patch_editor_panel` content = 5 rows @80x24 / 11 @120x30, panes
  ~2/~5 rows; the a-priori >=6/>=8 targets are physically unsatisfiable under compose+CSS-only; N_w is
  a per-width Phase-3 MEASURED pin (provisional N_80=1, N_120=3, each > today's 0); rung must weight
  the paste row; residual scope tension flagged for the re-gate.
- **Re-verification:** Textual pilot @80x24 + @120x30 (probe P24); corroborated by TC-035.2's own
  documentation of ~2-row panes @80x24 with widgets scrolling to a NULL region
  (`test_tui_patch_variant.py:414-448`). The draft "~9 rows/pane" was ~4.5x too large. **This is the
  finding that could not be cleanly folded to the reviewers' assumed N — see the return note.**

**R-Q04 / A-08 — US-060 LLR-060.2 delete authorized on SIZE alone (BLOCKER, Q-04 + A-08).**
- **Before:** LLR-060.2 "Executed verification" = byte sizes only (37.7 MB / 56.0 MB); no
  construct-diff precondition.
- **After:** HARD I-060-1 verify-before-delete gate — construct-kind subset census
  (`grep -ohE '/begin +[A-Z_]+'` kind-sets), `kinds(54M) subset-of kinds(36M)` required, evidence
  recorded BEFORE `git rm`; delete BLOCKED if a kind is 54M-only.
- **Re-verification:** probe P27 preview — both files' kind-sets IDENTICAL (13 kinds) → subset holds,
  pure scale duplicate; Phase 3 re-runs + records before the delete. A2L kind vocabulary confirmed in
  `s19_app/tui/a2l.py:48-84`. OK

**R-A02 / Q-05 — US-059 LLR-059.3 "breaks THREE assertions" is FALSE (MAJOR->minor, A-02 + Q-05).**
- **Before:** "adding `"Hex"` … breaks THREE existing assertions: (i) :78 artifact-set, (ii) :70
  orphan-colour, (iii) the modal-header equality `headers == list(LEGEND_TABLE)` (:322)."
- **After:** breaks exactly **TWO** (:70, :78); `:322` SURVIVES (both sides derive from `LEGEND_TABLE`,
  `screens.py:527`) and is NOT modified; `:323` `_TOTAL_ROWS` also survives.
- **Re-verification:** `tests/test_tui_legend.py:70` (orphan check), `:78` (artifact-set), `:322`
  (`assert headers == list(LEGEND_TABLE)`), `:322`-`:323` dynamic (probe P13). OK

**R-A04 / Q-07 — US-059 Hex↔color_policy colour-name coupling under-specified (minor, A-04 + Q-07).**
- **Before:** "the colour names shall correspond to `FOCUS_HIGHLIGHT_STYLE` …
  `MAC_ADDRESS_OVERLAY_STYLE`" with no defined canonicalization.
- **After:** exact transform `_colour_name_from_style` — split → drop Rich modifier tokens
  {bold,italic,dim,underline,reverse,blink,strike} → title-case the remaining colour token AS-IS
  (shade digit retained): `"bold yellow"->"Yellow"`, `"bold orange3"->"Orange3"`; a `HEX_LEGEND_STYLES`
  map whose values are the two constants (identity); TC-322 pins the transform + identity.
- **Re-verification:** `color_policy.py:13-14` (`"bold yellow"`, `"bold orange3"`); `legend.py:106`
  (`"Orange"`->WARNING already a `COLOUR_SEVERITY` key); `screens.py:530-538` (`.get(colour)` drives
  sev-class). **DEVIATION from the orchestrator's shorthand:** the orchestrator wrote the target as
  "Orange"; the code-grounded resolution is **"Orange3"** — the digit-stripped "Orange" collides with
  the existing WARNING colour key, which would paint the Hex overlay row `sev-warning` and contradict
  D-059 + LLR-059.2's "severity column empty for Hex rows". "Orange3" keeps `COLOUR_SEVERITY.get ->
  None` for both Hex rows. Flagged for operator awareness. OK

**R-A06 / Q-08 — US-059 AT-registry drift, hex-legend AT not split (minor, A-06 + Q-08, C-21).**
- **Before:** §3/§5 folded both legend surfaces into a single AT-059a; 01b §2.3 split AT-059a (modal)
  + AT-059b (report reread).
- **After:** §3 defines AT-059a (modal, `test_tui_legend.py`) + AT-059b (report reread,
  `test_tui_report_seam.py`, C-12); §5.1/§5.2 register both; AT count 4->5. Registry reconciled BEFORE
  any Phase-3 increment cut → C-21 satisfied.
- **Re-verification:** report-seam reread idiom `tests/test_tui_report_seam.py:182-221`; both
  consumers dynamic (`screens.py:527`, `report_service.py:1318`). OK

**R-A07 / Q-06 — US-058 LLR-058.4 snapshot cell ids wrong (minor, A-07 + Q-06).**
- **Before:** provisional `patch-80x24` / `patch-comfortable-120x30`, flagged `assumed`.
- **After:** `patch-comfortable-80x24` / `patch-comfortable-120x30`, `assumed` retired; §6.4 checklist
  item flipped X->OK.
- **Re-verification:** `ls tests/__snapshots__/test_tui_snapshot/` →
  `…[patch-comfortable-80x24].svg`, `…[patch-comfortable-120x30].svg` (probe P26). OK

**R-S01 — US-059 Hex meaning strings must be markup-free (low, S-01).**
- **Before:** no authoring constraint on the new Hex strings.
- **After:** LLR-059.1 requires the two Hex meaning strings contain no `[`/`]`; TC-322 asserts it.
- **Re-verification:** `screens.py:538` renders each row via a markup-enabled `Label` (no
  `markup=False`); rows are static literals (no injection vector) — authoring constraint, not a
  hardening fix. OK

**R-S02 — US-060 move/delete must use git plumbing (low, S-02).**
- **Before:** LLR-060.1/060.2 said "moved"/"deleted" without specifying git.
- **After:** LLR-060.1 uses `git mv` (+ `git ls-files tmp/stress_smoke` empty post-move);
  LLR-060.2 uses `git rm -r` (index consistency + `git revert` reversibility).
- **Re-verification:** security review S-02 (`02-review-security.md:38-49`); `.gitignore` ignores
  neither `tmp/` nor `examples/` → real tracked move/delete. OK
