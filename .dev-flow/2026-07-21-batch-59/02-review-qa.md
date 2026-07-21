# Phase-2 Cross-Review — QA dimension (testability + AT non-vacuity) — batch-59

> Reviewer: qa-reviewer. Scope: the 8 acceptance tests AT-B59-01..08 in `01-requirements.md`, judged for through-surface reach, non-vacuity, input-set-as-oracle, output-then-consume preservation, and live-window fidelity. I own the C-10/C-11/C-31/C-12 AT-authoring checks deferred from Phase 1.
> Verdict: **CHANGES-REQUESTED** — 2 blockers, 3 majors, 3 minors. The core issue is that §3/§4/§5 of the requirements predate the operator's hero-row layout refinement (recorded in `state.json.confirmed_design_decisions` + the prototype), so the centerpiece teeth AT (AT-B59-03) and the verdict-hero AT (AT-B59-05) assert against a layout that will not be built. The live-window AT set also under-verifies the exact fidelity the OQ-1 "live window" decision was made to guarantee.

---

## BLUF

- **What's strong:** every AT drives the real `#screen_crc_designer` via Pilot key `0` (C-16 clean). AT-B59-06 is a correct output-then-consume preservation chain (C-12). AT-B59-07 (full-suite regression) is a genuinely strong preservation oracle — and by inspection the batch-58 suite will survive re-nesting (see Positive Confirmation P-1). AT-B59-02's delta shape defeats a *fully* static mock.
- **What blocks:** (B1) AT-B59-03 names `#crc_kat_verdict` as its column-3 representative, but the confirmed layout moves the verdict into the **hero row**, not a bench column — so the assertion is unsatisfiable against the approved design. (B2) No AT asserts the coverage window's rendered CRC hexes equal the real computed oracles, so a *partial* mock (live glyph runs + hardcoded hexes — exactly the prototype's `0x9C5BCBBD`/`0x2A8A3950`) passes the live-window gate, defeating OQ-1.
- **What to fix before Inc-1:** reconcile §3 HLR-L2, §4 LLR-L2.1, §5.2 and AT-B59-03/05 to the hero-row layout; add the oracle-hex assertion to the window AT.

---

## Root consistency defect (drives B1 + M1)

`state.json.confirmed_design_decisions.layout_refinement` (operator, 2026-07-21) and the prototype `crc_designer.b59.inapp_prototype.py:126-178` place the **verdict hero + Warnings in the hero row** (`#crc_top_right`, sibling of `#crc_coverage_window` inside `#crc_hero_row`), with the 3-column bench holding only `c1 algorithm+serialization | c2 coverage+vector | c3 json+template+load/save`.

But the requirements body was **not folded** to match:
- §3 HLR-L2 statement: "column 3 the verdict hero, Job JSON, Warnings, Template and Load/Save".
- §4 LLR-L2.1: "`#crc_bench_c3` = `#crc_live_verify` + `#crc_json_preview_group` + `#crc_warnings_group` + `#crc_template_fields` + `#crc_loadsave_group`".
- §3 AT-B59-03: asserts `#crc_kat_verdict` resolves to a distinct **bench-column** ancestor.

`state.json` itself flags the fold as pending ("Fold into US-L3/AT-B59-03 … verdict now in the hero row, not a bench column"). Phase 2 is where that fold must land. Until it does, the implementer faces a contradiction: build the hero row (approved) and AT-B59-03 fails, or satisfy AT-B59-03 and violate the approved placement.

---

## Per-AT findings

### AT-B59-01 — coverage window is rendered + colored
- **Through-surface (C-16):** PASS — mounts `S19TuiApp`, presses `0`, reads `#crc_coverage_window`.
- **Non-vacuity (C-10):** PARTIAL → **M2**. "≥2 distinct style spans" must count distinct **styles**, not ≥2 span objects. A monochrome window with 3 same-color runs has ≥2 spans but is exactly the "monochrome label" the AT means to reject. Assert `len({span.style for span in rendered.spans}) >= 2`.
- **Input-set-as-oracle (C-31):** PASS — the span/glyph set is read from the mounted tree, threshold-guarded, not hand-listed.
- **Live-window (check 5):** FAIL → **B2** (see below). Glyphs + span count do not pin the *content* to real data.
- **C-17 (new sink):** GAP → fold into M2. The window is the one NEW markup sink; the AT should assert `widget._render_markup is False` (the batch-58 pattern, `test_crc_designer_view.py:341,488,597`).
- **Testability caveat → m3:** the AT reads `rendered.spans` from `Static(text, markup=False).render()`. The hostile-template test proves spans==[] for a *plain str*; the positive direction (a styled `rich.Text` keeps its spans through `markup=False`) is unproven. Verify at Phase 3; if `Static` drops the spans, read the renderable directly so the color assertion stays executable.

### AT-B59-02 — window deltas on a range edit
- **Through-surface:** PASS.
- **Non-vacuity:** PASS for defeating a *fully* static mock — two-range vs one-range rendered content differ.
- **Live-window (check 5):** WEAK → **B2**. A window that renders glyph runs purely from parsed range widths (never touching `mem_map` or the CRC) still deltas on a range edit. The delta alone does not prove the window reflects computed coverage; it only proves it reflects the *range text*. The strong live-window guarantee needs the oracle-hex assertion (B2).

### AT-B59-03 — distinct bench-column ancestors (the teeth AT)
- **Through-surface:** PASS.
- **Non-vacuity (C-10):** the pairwise-distinct-ancestor shape IS flat-form-failing — good teeth design. But the **widget set is stale** → **B1**. `#crc_kat_verdict` will live in `#crc_top_right` (hero row), which has no `#crc_bench_c*` ancestor, so `column_ancestor(#crc_kat_verdict)` is undefined and the assertion cannot pass on the approved design.
- **Input-set-as-oracle (C-31):** the "`#crc_bench` has ≥3 column children" count is derived (good); the three probe widgets are hand-picked (acceptable for a targeted structural claim) — but must be picked from the **actual** bench. Fix: `#crc_field_width` (c1), `#crc_coverage_ranges` (c2), `#crc_json_preview` (c3) — all three live in distinct confirmed bench columns.

### AT-B59-04 — width-narrow reflow
- **Through-surface:** deferred to Phase 3.
- **Non-vacuity:** UNDER-SPECIFIED → **M3**. "the exact assertion form set at Phase 3" leaves open a vacuous class-presence check. Require the Phase-3 form to (a) drive a REAL narrow size via `run_test(size=(80,24))` so the `width-narrow` class toggles through the real resize path (never hand-add the class — that is a C-16 proxy), and (b) assert the **geometric stacking effect** (e.g. `c2.region.y >= c1.region.y + c1.region.height`, or the resolved `#crc_bench` layout is vertical), not merely `"width-narrow" in workspace_body.classes`.

### AT-B59-05 — verdict hero
- **Through-surface:** PASS.
- **Non-vacuity (C-10):** FAIL as written → **M1**. The AT asserts a "border … that the plain `.crc-field-group` do not [have]". In the prototype, **every** `.crc-field-group` carries `border: round #2b3a5e` (`prototype:57-59`) and `#crc_live_verify` carries `border: round #8ff6a0` — both have borders, so "has a border the plain groups lack" is FALSE and the assertion is a collapsed proxy. Key the hero teeth on the actually-distinguishing property: `content_align == ("center","middle")` (the field-groups never set it) and/or a dedicated `crc-hero` class. Reading `widget.styles.content_align` post-mount is the finest discriminator.
- **Layout fold:** update the AT to assert the hero is in the hero row (`#crc_top_right`), not a bench column (ties to B1).

### AT-B59-06 — reused handler through the layout
- **Through-surface:** PASS.
- **Non-vacuity / C-12:** PASS — this is a correct output-then-consume preservation chain: a real `Input.Changed` on `#crc_field_xorout` drives the reused `_recompute`, and the assertion observes the **recomputed verdict content** (`MATCH → MISMATCH`, `before != after`) through the re-nested tree, not mere widget existence. Mirrors `test_live_verdict_transitions` (`:184`) but re-proves it fires post-re-nest. Keep as-is.

### AT-B59-07 — full existing suite green
- **Non-vacuity:** PASS — the batch-58 suite is a real regression oracle (C-31 input-set-is-an-oracle). Strongest preservation proof.
- See P-1: the suite will survive re-nesting by inspection.

### AT-B59-08 — teeth demonstration
- **Non-vacuity:** PARTIAL → **m2**. "inspection-confirmed in the docstring + a computed ancestor comparison" is fine, but make the demonstration **executable**, not prose: assert the live tree yields exactly 3 distinct column ancestors AND document (in-code) that a single-`#crc_designer_panel`-ancestor flat compose collapses the set to 1 — the assertion's own algebra (`len(distinct_columns) == 3`) is the flat-form-failing property. Prose-only teeth are not teeth.

---

## Missing coverage (new sink)

- **m1 — no boundary AT for the NEW `#crc_coverage_window` sink.** HLR-L1's boundary catalog lists empty-image (graceful note, no glyph compute) and malformed-ranges (markup-safe note, no crash) but no AT number carries them. The existing `test_coverage_no_image_shows_empty_state`/`test_coverage_inverted_range_warns_not_crash` cover the **preview** widget, not the window. Add two cheap boundary ATs on the window: (1) no image → graceful note, ≥0 glyphs, no crash; (2) inverted/malformed ranges → markup-safe note. New sink ⇒ new boundary evidence (C-17 + boundary discipline).

---

## Positive confirmations (evidence for the gate)

- **P-1 — AT-B59-07 preservation is sound (R-1 risk is LOW by inspection).** All 18 batch-58 tests resolve widgets via `query_one("#id")` / `query("#id")`, which match a descendant **anywhere** in the subtree; none asserts a parent/ancestor relationship. Re-nesting the same ids into columns cannot break them. Evidence: `test_crc_designer_view.py` — every `query_one("#crc_*")` call site (`:78,127-149,181,204-211,272-283,311-313,338-343,394-428,468-476,509-512,534-538,563-597,661-667,798-811,852-876`) is id-scoped; the only structural assertion is `.hidden` on rail *screens* (`:80-84`), untouched by the panel re-compose. R-1's "hidden ancestor coupling" is therefore not present in the current suite.
- **P-2 — through-surface harness is proven.** The fixture-load pattern the window ATs need already exists: `app.current_file = _loaded(_fixture_mem())` with pinned oracles `concat==0x9C5BCBBD` / `fill==0x2A8A3950` (`:612-621,670-688`). The window oracle assertion (B2) can reuse these verbatim — no new math, matching A3/D-1.
- **P-3 — AT-B59-06 + AT-B59-02 defeat the two easy false-greens** (static verdict / fully-static window). The remaining hole is only the *partial* window mock (B2).

---

## Required changes (blocking the Phase-2 gate)

| ID | Sev | AT | Vacuity class | Fix |
|----|-----|-----|---------------|-----|
| B1 | blocker | AT-B59-03 (+HLR-L2, LLR-L2.1, §5.2) | unsatisfiable-against-approved-design | Fold the requirements to the hero-row layout; re-derive the 3 distinct-column probes as `#crc_field_width` (c1) / `#crc_coverage_ranges` (c2) / `#crc_json_preview` (c3). Move verdict+Warnings out of `c3` in HLR-L2/LLR-L2.1 into `#crc_top_right`. |
| B2 | blocker | AT-B59-01/02 (LLR-L1.1) | live-window fidelity hole (C-31 / OQ-1) | Add an oracle assertion: §3.2 fixture loaded + two-range `join="fill"` ⇒ window text contains `0x9C5BCBBD` (concat) AND `0x2A8A3950` (fill), the pinned oracles. Without it a hardcoded-hex mock passes the "live" gate the operator explicitly ordered closed. |
| M1 | major | AT-B59-05 | collapsed-proxy discriminator (C-10) | Assert `content_align == center/middle` (and/or a `crc-hero` class), not "has a border" — the plain groups also have borders. |
| M2 | major | AT-B59-01 | monochrome-passes + missing C-17 assertion | Assert `len({span.style …}) >= 2` (distinct colors) and `window._render_markup is False`. |
| M3 | major | AT-B59-04 | under-specified / class-presence-vacuous (C-16/C-23) | Specify: drive real narrow `size=`, assert the geometric stacking effect, not the class flag. |
| m1 | minor | (new) | missing new-sink boundary coverage | Add window empty-image + malformed-ranges boundary ATs. |
| m2 | minor | AT-B59-08 | prose-only teeth | Make the ancestor-distinctness demonstration a computed assertion. |
| m3 | minor | AT-B59-01 | unproven framework assumption | Verify styled-`Text` spans survive `Static(…, markup=False).render()`; else read the renderable. |

---

## Evidence checklist (per finding)

- [x] B1 — `state.json:18` layout_refinement (verdict in hero row) vs `01-requirements.md` §3 HLR-L2 / §4 LLR-L2.1 / AT-B59-03 (verdict in c3); prototype `crc_designer.b59.inapp_prototype.py:167-178` (`verify_grp` in `#crc_top_right`, not `#crc_bench`). ✓
- [x] B2 — `01-requirements.md` LLR-L1.1 threshold ("concat/fill hexes shown equal the `_coverage_preview_text` values") is not encoded in AT-B59-01/02; prototype mock hardcodes `0x9C5BCBBD`/`0x2A8A3950` (`prototype:41-42`); oracle available `test_crc_designer_view.py:617-620,687-688`. ✓
- [x] M1 — prototype `.crc-field-group { border: round #2b3a5e }` (`:57-59`) AND `#crc_live_verify { border: round #8ff6a0 }` (`:67-69`) both bordered; content-align is the only free discriminator. ✓
- [x] M2 — AT-B59-01 text "≥2 distinct style spans"; markup=False pattern at `test_crc_designer_view.py:341,488,597`. ✓
- [x] M3 — AT-B59-04 "exact assertion form set at Phase 3"; width-narrow cascade `styles.tcss:243-326` (per §1.4). ✓
- [x] m1 — HLR-L1 boundary catalog lists empty/malformed but no AT id; existing window-less coverage tests `:709-714,768-775`. ✓
- [x] m2 — AT-B59-08 "docstring + a computed ancestor comparison". ✓
- [x] m3 — hostile test proves spans==[] for plain str `:471-489`; positive direction unproven. ✓
- [x] P-1 — all `query_one("#crc_*")` id-scoped; no parent assertion in `test_crc_designer_view.py`. ✓
- [x] No real PII / secrets in any proposed test data (fixtures are synthetic `mem_map` dicts). ✓
- [x] Test-results sections left blank (this is a spec review, no execution). ✓
- [x] Layer B (black-box): AT-B59-06/07 + the B2 oracle observe the shipped surface through Pilot. ✓
- [x] Bidirectional surface-reachability: input (range edit) → output (window hexes) exercised through the panel once B2 lands. ✓
- [x] No unfilled template: this artifact has no placeholders. ✓

## Verdict

**CHANGES-REQUESTED.** Discharge B1 and B2 (both Certainty-axis blockers) and fold the hero-row layout into §3/§4/§5 before Inc-1; address M1–M3 in the same fold. m1–m3 may be resolved at Phase 3 with the pilot-measured geometry, but m1 (new-sink boundary ATs) is cheap and should land with Inc-2. Re-review the folded AT set before the implementation gate.
