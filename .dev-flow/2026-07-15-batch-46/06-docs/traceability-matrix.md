# Traceability Matrix — batch-46 (Patch Editor responsive three-window layout)

> **Audience:** engineering + QA reviewers closing out the /dev-flow V-model.
> **Purpose:** the complete, gap-free bidirectional trace US → HLR → LLR → TC/AT, plus the
> behavioral US → AT chain, reconciled against the **real collected nodes** on
> `feat/batch-46-patch-3col` (Inc-1 `e05ffec` + Inc-2 `9e44f2a`).
> **Sources of truth:** `01-requirements.md` (§3/§4 + §6.5 amendments + §6.6 FOLD-1..8) and
> `04-validation.md` (the AT → real-node reconciliation, C-18 verdict). All node ids below are the
> `--collect-only` real nodes in `tests/test_tui_patch_layout.py` unless another file is named.
> **Language:** English (batch default).

---

## 0. Scope key

- **Scope class:** LAYOUT-ONLY view change — no parser / range-engine / validation / behavior / wiring
  change. Frozen-engine diff = 0, `app.py` diff = 0 (confirmed `04-validation.md §5`).
- **Two user stories:** US-U8 (responsive 3-window gestalt, closes field-audit **U8**) and US-B2 (docked
  button reachability, closes field-audit **B2**).
- **Two HLR / seven LLR / six AT / two white-box TC**, all bound to real nodes below.

---

## 1. Forward trace — US → HLR → LLR → TC/AT (no gaps)

| US | HLR | LLR | Covering TC / AT (real node) | Method |
|----|-----|-----|------------------------------|--------|
| **US-U8** | **HLR-063** (3 windows, 3-across ≥120 / stacked <120 via `width-narrow`) | **LLR-063.1** compose 3 window containers + docked rows | `TC-46.1` `test_tc46_1_window_structure_layout_agnostic` | inspection + integration |
| US-U8 | HLR-063 | **LLR-063.2** wide regime: 3 windows horizontal within budget | `AT-063a` `test_at063a_three_across_at_120` | e2e / pilot |
| US-U8 | HLR-063 | **LLR-063.3** narrow regime: stack via existing `width-narrow` (no new Python) | `AT-063b` `test_at063b_stacked_at_80` + `TC-46.1` selector grep (`app.py` diff = 0) | e2e / pilot + inspection |
| US-U8 | HLR-063 | **LLR-063.4** reparent-safety: preserve every leaf id + `.hidden` containers | `AT-063c` `test_at063c_reparent_safety_at_80` **+** `test_at063c_reparent_safety_at_120` (46-id `_MUST_PRESERVE` census + 3 observable routes) | integration |
| **US-B2** | **HLR-064** (docked buttons reachable both regimes) | **LLR-064.1** docked rows are body siblings, not descendants | `AT-064a` `test_at064a_reachable_under_scroll_at_80` + `AT-064b` `test_at064b_reachable_under_scroll_at_120` + `TC-46.1` `docked_not_in_body` | e2e / pilot |
| US-B2 | HLR-064 | **LLR-064.2** docked-row budget measured, not fr-derived (C-13/C-23) + D-3 fallback ladder | **analysis deferred → Phase-3 pilot MEASURED** (`03-increments/increment-001.md §5`; no D-3 rung needed) | analysis (deferred-then-measured) |
| US-B2 | HLR-064 | **LLR-064.3** test-supersession census (C-26): declare every touched structural symbol | census (`01-requirements.md §4 LLR-064.3` + FOLD-1/FOLD-7 re-cut) + `pytest -q` green | inspection + increment gate |

**Coverage — no LLR uncovered.** Every LLR-063.1–.4 and LLR-064.1–.3 has ≥1 passing TC/AT; LLR-064.2 is
the single explicitly-deferred item (deferred at Phase 1, measured at Phase 3 — `04-validation.md §2`).

---

## 2. Behavioral chain (black-box) — US → AT through the shipped surface

Every AT drives the **real patch screen** via `S19TuiApp(base_dir=tmp_path).run_test(size=…)` +
`app.action_show_screen("patch")` (`test_tui_patch_layout.py:229-234, 345-350, 437-441`) — not a bare
`PatchEditorPanel` mount. C-18: one on-disk node drives each AT's whole named chain.

| US | Observable outcome (the WHAT) | Shipped surface | AT (real node) | Regime(s) | RED counterfactual (recorded) |
|----|-------------------------------|-----------------|----------------|-----------|-------------------------------|
| US-U8 | 3 windows **3-across** when wide | patch screen @120×30 | `AT-063a` `test_at063a_three_across_at_120` | 120×30 (wide) | `#patch_win_*` absent on 2×2 tree → `counts==1` fails; preserved `#patch_pane_*` still resolve as 2 columns → real 2-vs-3 discriminator |
| US-U8 | 3 windows **stacked** when narrow | patch screen @80×24 | `AT-063b` `test_at063b_stacked_at_80` | 80×24 (narrow) | 2×2 tree → 2 distinct `x` (grid), not 1 → RED; a dropped `width-narrow` stack rule leaks 3-col to 80 → RED |
| US-U8 | leaf ids resolve + **one action/window routes** after reparent | patch screen @80×24 + @120×30 | `AT-063c` `test_at063c_reparent_safety_at_80` + `test_at063c_reparent_safety_at_120` | both | rename/drop any leaf id (e.g. `#patch_doc_entries_table`) or break `request_action` routing → census/routing flips RED (the batch-37 C-26 failure mode) |
| US-B2 | every named button **docked/reachable** at the floor | patch screen @80×24 | `AT-064a` `test_at064a_reachable_under_scroll_at_80` | 80×24 | 2×2 tree → change-file/entry buttons below the starved `1fr` cell fold, no window scroll reaches them → RED |
| US-B2 | every named button **docked/reachable** when wide | patch screen @120×30 | `AT-064b` `test_at064b_reachable_under_scroll_at_120` | 120×30 | same starved-column buttons below-fold → RED |
| US-B2 | **revealed** save-back + before/after buttons reachable | patch screen @80×24 (reveal path) | `AT-064c` `test_at064c_revealed_rows_reachable_at_80` | 80×24 | a regression trapping a revealed row below a fold (the exact B2 class) → RED |

**AT registry (6, FOLD-5):** AT-063a / AT-063b / AT-063c / AT-064a / AT-064b / AT-064c.
AT-063c is one AT realized as two size-parametrized nodes; each independently runs the full census +
tri-window routing chain at its regime (not a split of one chain across nodes — `04-validation.md §1`).
RED was executed at Inc-1 against the stashed 2×2 source: **7 failed / 2 passed** (the 7 geometry/
reachability ATs fail on the old tree; the 2 that pass are the reparent leaf-id nets, expected).

---

## 3. White-box (Layer A) TC ledger

| TC (spec id) | Real node (`test_tui_patch_layout.py`) | Asserts | Traces |
|--------------|-----------------------------------------|---------|--------|
| **TC-46.1** (= `TC-063.1`) | `test_tc46_1_window_structure_layout_agnostic` (`:562`) | each `patch_win_script/_checks/_json` holds a `.patch-window-title` Label + a `VerticalScroll` body + a **docked row that is a body sibling** (`docked.parent is win and body.parent is win`) and **NOT** a body descendant (`docked_not_in_body`); **plus** the `#workspace_body.width-narrow #patch_editor_panel` reflow selector exists in `styles.tcss`. No `layout.name` pinned (wide token is a design call — FOLD-2/FOLD-7). | LLR-063.1 · LLR-064.1 · LLR-063.3 · R-TUI-063/064 |
| **TC-46.2** | `test_tc46_2_paste_in_viewport_at_body_scroll0` (`:627`) | JSON window body starts unscrolled (`scroll_y==0`) and `#patch_paste_text` first line lies inside the body's visible `content_region` — the single authoritative paste-in-viewport verifier (FOLD-4). | R-TUI-046 (amended A-3) |

### Folded white-box guards (relocated, not lost)

| Planned guard | Landed in (real node) | Assertion |
|---------------|-----------------------|-----------|
| Leaf-id census (planned `TC-46.3`) | inside **AT-063c** `_MUST_PRESERVE_IDS` 46-id census (`test_tui_patch_layout.py:67-120, 352-354, 391-395`) | 14 wiring-critical ids + census-pinned leaf ids + section labels + preserved structural containers + 2 `.hidden` rows |
| FOLD-6 markup-safety + `CappedTextArea` census | `test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent` | `#patch_checks_status`._render_markup is False · `#patch_doc_issues`._render_markup is False · `isinstance(#patch_paste_text, CappedTextArea)` (C-17 / F1 / F4) |
| 5-button + section-label census (planned `TC-46.4`) | `test_tc319…` in `test_tui_patch_editor_v2.py` (parentage unchanged) | `#patch_doc_controls` `[load, refresh, validate, apply, save]` + `#patch_checks_controls` `[run, help]` docked intact |

---

## 4. REQUIREMENTS.md rows (§36) + amendments

| Row | Kind | Location | Disposition |
|-----|------|----------|-------------|
| **R-TUI-063** | NEW | `REQUIREMENTS.md:4004-4028` | Responsive three-window layout (US-U8 / HLR-063, LLR-063.1–.4). **Status: Automated**, frozen-engine diff = 0. |
| **R-TUI-064** | NEW | `REQUIREMENTS.md:4030-4047` | Docked reachability with **FOLD-8 reachable-under-scroll floor** @80×24, strict all-visible target @120×30 (US-B2 / HLR-064, LLR-064.1–.3). **Status: Automated**. |
| **R-PATCH-2X2-LAYOUT-001** | SUPERSEDED (A-1) | `REQUIREMENTS.md:3294` | 4-pane 2×2 grid retired → R-TUI-063 + R-TUI-064. Stale-text note: live code was `grid-size: 2 4` (batch-36), not the row's `2 3`. |
| **R-PATCH-2X2-SNAPSHOT-001** | SUPERSEDED (A-2) | `REQUIREMENTS.md:3300` | Pixel lock now targets the three-window layout; the two `patch-comfortable-*` cells ride `_batch46_patch_drift_marks` (`xfail(strict=False)`) until canonical-CI regen, then flip to Automated. |
| **R-TUI-046** | AMENDED (A-3) | `REQUIREMENTS.md:3471` | Paste editor moves into `#patch_win_json`; still a `CappedTextArea`; in-viewport intent re-observed by TC-46.2. |
| **R-PATCH-VARIANT-SELECT-001** | NOTE (A-4) | `REQUIREMENTS.md:3312` | Variant/execute rows relocate into `#patch_win_script`; normative content UNCHANGED; variant-above-execute preserved; `test_tui_patch_variant.py` 12/12 green. |

---

## 5. Gate + regression evidence (from `04-validation.md`)

| Check | Result |
|-------|--------|
| Authoritative gate (C-25, orchestrator-owned) | `pytest -q -m "not slow"` → **1394 passed · 2 skipped · 20 deselected · 5 xfailed · 0 failed · exit 0** |
| xfailed breakdown | 2 batch-46 patch snapshot cells (`_batch46_patch_drift_marks`, C-22) + 3 pre-existing |
| Frozen-engine diff (C-27 dual-guard) | **0** — no `core.py / hexfile.py / range_index.py / validation/ / tui/a2l.py / tui/mac.py / color_policy.py` in the diff |
| `app.py` diff | **0 lines** — responsive switch is pure CSS reusing `width-narrow`; no `TabbedContent`, no new breakpoint |
| FOLD-1 pass-unchanged | `test_tui_patch_variant.py` + `test_tui_directionb.py` NOT in the diff → pass unchanged (preserved `#patch_pane_*` grouping containers) |
| C-26 census-miss | `test_tui_variants.py` (2 sites) caught + fixed (6th approved file); inside the 1394-green run |
| C-28 | NOT triggered — all patch bindings `show=False` (`6`/`ctrl+z`/`ctrl+y`/`b`); no shared-chrome change |

**C-18 verdict:** PASS — every AT maps to exactly one distinct on-disk node driving its whole named chain.
**Batch verdict:** APPROVE (Phase 4).

---

## 6. Bidirectional surface-reachability (input × output, all through `action_show_screen("patch")`)

| Axis | Dimension / deliverable | Exercised through shipped surface by |
|------|-------------------------|--------------------------------------|
| Input: width regime | wide (≥120) | AT-063a, AT-064b, TC-46.1, TC-46.2, AT-063c@120 |
| | narrow (<120) | AT-063b, AT-064a, AT-064c, AT-063c@80 |
| Input: per-window | PATCH SCRIPT `#patch_win_script` | TC-46.1 · AT-063c (add_entry route) · AT-064a/b |
| | CHECKS `#patch_win_checks` | TC-46.1 · AT-063c (run_checks route) · AT-064a/b |
| | JSON EDIT `#patch_win_json` | TC-46.1 · AT-063c (parse_paste route) · TC-46.2 · AT-064a/b |
| Input: row visibility | always-present rows (scroll 0) | AT-064a/b (17 named buttons) |
| | revealed `.hidden` rows | AT-064c |
| Output: layout | 3 windows 3-across @wide | AT-063a |
| | 3 windows stacked @narrow | AT-063b |
| Output: reachability | 17 action buttons reachable both regimes | AT-064a + AT-064b |
| | 4 revealed save-back/before-after buttons | AT-064c |
| Output: paste readability | paste first line in-viewport | TC-46.2 |
| Output: wiring preserved | 46 must-preserve ids + 3 observable routes | AT-063c (both sizes) |
| Output: security invariants | markup=False ×2 sinks + CappedTextArea | `test_at058b` (FOLD-6) |

**Matrix result — COMPLETE.** No input dimension or deliverable is verified only through a service API.
