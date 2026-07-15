# 04 — Validation (Phase 4) · batch-46 (Patch Editor responsive three-window layout)

> Phase-4 gate. **CONSUMES** the orchestrator's authoritative full-suite gate run (C-25);
> reconciles Layer B (black-box acceptance) + Layer A (white-box TC) against the final
> committed state (`feat/batch-46-patch-3col`, Inc-1 `e05ffec` + Inc-2 `9e44f2a`). No full
> re-run performed here — only targeted `--collect-only` / `git diff` reconciliation of node
> ids. Language: English. Stack: Textual TUI + `pytest` + `pytest-textual-snapshot`.

## BLUF — APPROVE

**Recommendation: APPROVE → advance to Phase 5 / self-merge.** All three axes met.
Every US has ≥1 passing AT through the shipped patch screen with boundary (both regimes) +
a documented RED counterfactual; every LLR has a passing TC/AT (LLR-064.2 deferred-then-measured
in Phase 3); **0 blocker fails**. C-18 holds (one on-disk node drives each AT's whole named chain).
`app.py` diff = 0, 0 frozen-engine diffs (C-27 dual-guard green), FOLD-1 pass-unchanged confirmed,
the batch-37-class C-26 census-miss (`test_tui_variants.py`) fixed and inside the green suite.

**Authoritative gate run (orchestrator-owned, C-25/C-19):**
`pytest -q -m "not slow"` @ final committed state → **1394 passed · 2 skipped · 20 deselected ·
5 xfailed · 0 failed · exit 0** (731.93s). The 5 xfailed = 2 batch-46 patch snapshot cells
(`_batch46_patch_drift_marks`) + 3 pre-existing. The "2 mismatched snapshots" are exactly those
2 xfailed patch cells (canonical-CI regen post-merge; local regen forbidden — `reference_snapshot_regen_env`).

---

## 1. Layer B — behavioral (black-box) acceptance through the SHIPPED surface

All 6 ATs drive the real app via `S19TuiApp(base_dir=tmp_path).run_test(size=…)` +
`app.action_show_screen("patch")` (`tests/test_tui_patch_layout.py:229-234, 345-350, 437-441`) —
the shipped patch screen, not a bare `PatchEditorPanel` mount. Node ids reconciled against
`pytest --collect-only tests/test_tui_patch_layout.py -q` (9 nodes collected).

### AT → real collected node reconciliation (C-18: one node drives the whole named chain)

| AT (spec id) | Real collected node (on-disk) | Regime(s) | Drives the whole chain? | Boundary | RED counterfactual (recorded) |
|---|---|---|---|---|---|
| **AT-063a** 3-across | `test_tui_patch_layout.py::test_at063a_three_across_at_120` | 120×30 (wide) | ✓ one node: 3 distinct `region.x` + `MIN_USABLE_W/H` floors + no-overlap + no right-edge clip, all in one node | 120 = breakpoint edge (`<120` is narrow → 120 is wide) | `#patch_win_*` ids ABSENT on 2×2 tree → `counts==1` fails (cardinality-0); preserved `#patch_pane_*` still resolve as 2-column → real 2-vs-3 discriminator (q-m2) |
| **AT-063b** stacked | `test_tui_patch_layout.py::test_at063b_stacked_at_80` | 80×24 (narrow) | ✓ one node: 1 distinct `x` + 3 strictly-ascending non-overlapping `y` + floors | 80×24 = supported minimum | 2×2 tree → 2 distinct `x` (grid) not 1 → RED; also a dropped `width-narrow` stack rule leaks 3-col to 80 → RED |
| **AT-063c** reparent-safety | `test_at063c_reparent_safety_at_80` **+** `test_at063c_reparent_safety_at_120` | 80×24 **and** 120×30 | ✓ each size-node drives the FULL chain: 46-id `_MUST_PRESERVE` census + 3 observable routes (add_entry grows table · run_checks emits `Checks:` · parse_paste populates `_change_service.document`) | both regimes (structural resolvability is size-invariant; routing pauses differ under starved layout → both run) | rename/drop any leaf id (e.g. `#patch_doc_entries_table`) or break `request_action` routing → census/routing flips RED (the exact batch-37 C-26 failure) |
| **AT-064a** reachable@80 | `test_tui_patch_layout.py::test_at064a_reachable_under_scroll_at_80` | 80×24 | ✓ one node: per-button `trapped==[]` (docked row is a sibling, not a `VerticalScroll` descendant) **and** `unreachable==[]` after `_reach` scroll, over all 17 named buttons | 80×24 = worst-case vertical budget | 2×2 tree → change-file/entry buttons below the starved `1fr` cell fold, no window scroll reaches them → `_fully_visible==False` → RED |
| **AT-064b** reachable@120 | `test_tui_patch_layout.py::test_at064b_reachable_under_scroll_at_120` | 120×30 | ✓ one node: identical oracle over the same 17 buttons at the wide regime | 120×30 | same starved-column buttons below-fold → RED |
| **AT-064c** revealed-reachable | `test_tui_patch_layout.py::test_at064c_revealed_rows_reachable_at_80` | 80×24 (reveal path) | ✓ one node: drives `panel.show_save_prompt("out.s19")` + `show_before_after_prompt()` reveal, then `trapped==[]` + `unreachable==[]` over the 4 revealed save-back / before-after buttons | 80×24 | a regression trapping a revealed row below a fold (the exact B2 class) → RED |

**C-18 verdict — PASS.** Every §3 AT maps to exactly one distinct on-disk node that drives its
*whole* named chain through the shipped surface — never "covered in parts". AT-063c is a single
AT realized as two size-parametrized nodes (`_at_80` / `_at_120`), each independently executing the
complete census + tri-window routing chain at its regime — the mandated both-regimes discipline
(mirrors the retired `test_at_033c_*_at_80/_at_120` precedent), not a split of one chain across nodes.

**Boundary + negative evidence — PRESENT for every AT.** Both terminal regimes exercised
(063a/064b @120 · 063b/064a/064c @80 · 063c @both); each AT names its RED counterfactual on the
pre-restructure 2×2 tree (module docstring `test_tui_patch_layout.py:32-38` + per-test docstrings).
RED was executed at Inc-1 (packet §4: "RED-first vs stashed old 2×2 source: 7 failed, 2 passed" —
the 7 geometry/reachability ATs fail on the old tree; the 2 that pass are the reparent leaf-id nets,
expected, not geometry discriminators).

**Reachable-under-scroll (FOLD-8) — the amended oracle.** `_fully_visible`
(`test_tui_patch_layout.py:144-164`, lifted verbatim from `prototypes/patch_editor_layout.prototype.py:243-259`)
requires the button region to be non-empty, screen-contained, AND contained by every *real*
scrollable ancestor's `content_region`. `_scrollers` (`:167-183`) uses `show_vertical_scrollbar`
(not the widget-type `is_scrollable`, which is True for every container) to single out the genuine
scroll container the operator scrolls. `_reach` (`:186-200`) drives that scroller's `scroll_y`
directly (Textual 8.2.8 `scroll_visible`/`scroll_to_widget` did not propagate through the nested
auto-scroll containers). The B2 discriminator is the structural `trapped` check: a docked row that
is a `VerticalScroll` descendant is trapped below the body's inner fold → RED regardless of scroll.

---

## 2. Layer A — functional (white-box) TC reconciliation ↔ HLR/LLR

Two white-box TCs shipped in `test_tui_patch_layout.py` (spec `TC-063.1`/`TC-46.1` and `TC-46.2`);
the remaining planned white-box guards were folded into AT-063c's census and into
`test_tui_patch_editor_v2.py::test_at058b` (FOLD-6). Node ids from `--collect-only`.

| TC (shipped node) | Asserts (white-box) | Trace |
|---|---|---|
| **TC-46.1** `test_tc46_1_window_structure_layout_agnostic` (`:562`) | each of `patch_win_script/_checks/_json` holds a `.patch-window-title` Label + a `VerticalScroll` body + a **docked row that is a body sibling** (`docked.parent is win and body.parent is win`) and **NOT** a body descendant (`docked_not_in_body`) — the B2 structural precondition; **plus** the `#workspace_body.width-narrow #patch_editor_panel` reflow selector exists in `styles.tcss` (source grep, `:621`). No `layout.name` pinned (wide token is a design call, M-A3/q-m3). | LLR-063.1 (window structure) · LLR-064.1 (docked-sibling) · LLR-063.3 (width-narrow reuse / `app.py` diff = 0) · R-TUI-063/064 |
| **TC-46.2** `test_tc46_2_paste_in_viewport_at_body_scroll0` (`:627`) | JSON window body starts unscrolled (`scroll_y==0`) and the `#patch_paste_text` first line lies inside the body's visible `content_region` (`content_top <= paste_y < content_bottom`) — the single authoritative paste-in-viewport verifier. | R-TUI-046 (amended, FOLD-4) |

**Folded white-box guards (not lost — relocated):**
- **Leaf-id census (planned TC-46.3)** → the `_MUST_PRESERVE_IDS` 46-id census inside
  **AT-063c** (`test_tui_patch_layout.py:67-120, 352-354, 391-395`): the 14 wiring-critical ids +
  census-pinned leaf ids + section labels + preserved structural containers
  (`patch_pane_entries/changefile/variant`, `patch_doc_file_row`, `patch_variant_row`,
  `patch_execute_row`) + the 2 `.hidden`-toggled rows. This is the static structural half of AT-063c.
- **FOLD-6 markup-safety + CappedTextArea census** →
  `test_tui_patch_editor_v2.py::test_at058b_id_census_and_wiring_survive_reparent` (diff `+2516..+2557`):
  `#patch_checks_status`._render_markup is False · `#patch_doc_issues`._render_markup is False ·
  `isinstance(#patch_paste_text, CappedTextArea)` — the C-17/F1/F4 net asserting the reparent did not
  downgrade the two file-derived-text sinks or swap the 64 KiB paste cap.
- **5-button + section-label census (planned TC-46.4)** → preserved intact by the docked-row moving
  `#patch_doc_controls` `[load, refresh, validate, apply, save]` + `#patch_checks_controls` [run, help]
  out as docked siblings (`test_tc319…` in `test_tui_patch_editor_v2.py`, unchanged parentage; not in
  the touched-symbol RED set — the census MUST-NOT-churn contract held).

### LLR coverage ledger (01-requirements.md:241-247)

| LLR | Covering TC/AT (passing) | Status |
|---|---|---|
| LLR-063.1 (compose 3 windows + docked rows) | TC-46.1 | ✓ pass |
| LLR-063.2 (wide 3-across within budget) | AT-063a | ✓ pass |
| LLR-063.3 (narrow stack via `width-narrow`, no new Python) | AT-063b + TC-46.1 selector grep (`app.py` diff = 0 confirmed) | ✓ pass |
| LLR-063.4 (reparent-safety, all leaf + hidden ids) | AT-063c (both sizes) | ✓ pass |
| LLR-064.1 (docked rows outside window bodies) | AT-064a + AT-064b + TC-46.1 `docked_not_in_body` | ✓ pass |
| **LLR-064.2** (docked-row budget measured, not fr-derived; D-3 ladder) | **analysis deferred → Phase-3 pilot MEASURED** | ✓ deferred-then-measured |
| LLR-064.3 (test-supersession census, C-26) | census (§5) + `pytest -q` green | ✓ pass |

**LLR-064.2 deferred-then-measured — confirmed.** The Phase-1 spec explicitly deferred the 80×24
docked-row budget to a Phase-3 pilot (`01-requirements.md:194-196, 246`: "`analysis (deferred)` …
`assumed — pilot-measure in Phase 3`"). The pilot **was run** and recorded in
`03-increments/increment-001.md §5`: window regions at both regimes
(wide widths {44, 22, 23} · heights all 11; narrow width 68 · heights {28, 14, 7}),
`MIN_USABLE_W = 15` / `MIN_USABLE_H = 5` (floors set below every measured window yet reject a starved
one), button height = 3 (Textual default, no compact override per directive), narrow panel scrolls
(`max_scroll_y = 45`). **D-3 fallback rung applied: NONE of rungs 1-3** — the `off==[]`@120×30 deficit
is bound by the app-frozen panel viewport height (5 rows @80×24, 11 @120×30; `app.py` 0-diff mandated),
not by docked-row count, so rung-1/2 recover 0 rows and rung-3 (new binding) is forbidden. The
load-bearing fix that recovered the last 2 execute buttons from *unreachable* → *reachable* was the
`#patch_variant_select_row { height: 3 }` bound (Select-overlay phantom auto-height). LLR-064.2's
numeric threshold ("each window ≥1 body line at scroll 0 AND all docked buttons reachable") is met.

---

## 3. Bidirectional surface-reachability matrix

Every named **input dimension** AND every named **output/deliverable** is exercised/observed through
the shipped patch screen (`action_show_screen("patch")`), not only a service API.

| Axis | Dimension / deliverable | Exercised/observed through shipped surface by |
|---|---|---|
| **Input: terminal width regime** | wide (≥120) | AT-063a, AT-064b, TC-46.1, TC-46.2, AT-063c@120 |
| | narrow (<120) | AT-063b, AT-064a, AT-064c, AT-063c@80 |
| **Input: per-window** | PATCH SCRIPT (`#patch_win_script`) | TC-46.1 (structure) · AT-063c (add_entry route) · AT-064a/b (its docked buttons) |
| | CHECKS (`#patch_win_checks`) | TC-46.1 · AT-063c (run_checks route) · AT-064a/b (Run checks button) |
| | JSON EDIT (`#patch_win_json`) | TC-46.1 · AT-063c (parse_paste route) · TC-46.2 (paste in-viewport) · AT-064a/b (Parse/Edit-JSON) |
| **Input: row visibility** | always-present rows (scroll 0) | AT-064a/b (17 named buttons) |
| | revealed `.hidden` rows (save-back + before/after) | AT-064c (reveal-then-reach path) |
| **Output: layout deliverable** | 3 windows, 3-across @wide | AT-063a (3 distinct `x`, no overlap, no clip) |
| | 3 windows stacked @narrow | AT-063b (1 `x`, 3 ascending `y`) |
| **Output: docked reachability** | all 17 action buttons reachable-under-scroll @both regimes | AT-064a (80) + AT-064b (120) |
| | 4 revealed save-back/before-after buttons reachable | AT-064c |
| **Output: paste readability** | paste editor first line in-viewport | TC-46.2 |
| **Output: wiring preserved** | 46 must-preserve ids + 3 observable routes | AT-063c (both sizes) |
| **Output: security invariants** | markup=False ×2 sinks + CappedTextArea | `test_at058b` (FOLD-6) |

**Matrix result — COMPLETE.** No input dimension or deliverable is verified only through a service
API; the responsive axis (both widths) and every window/button/paste/wiring output round-trips through
`action_show_screen("patch")`.

---

## 4. Feedback edges + amendments (§6.5-style)

**FOLD-8 (the iterate-to-refine that resolved a black-box-fails / white-box-would-pass edge).**
The Phase-1 AT-064a/064c contract asked for `off == []` at scroll 0 @80×24 (all 17 buttons
simultaneously visible without scrolling). Phase-3 pilot measurement revealed the patch panel gets
only **~5 rows @80×24** (11 @120×30) of viewport — a deferred **app-geometry starvation** in the
frozen `app.py` layout (0-diff mandated this batch). With 17 buttons + an 8-line paste editor +
10-line entries table dominating the body, *no* CSS restructure can make all buttons visible at
scroll 0 at the floor. This is a **requirement-wrong** edge (the target is physically impossible under
the frozen viewport), **not implementation-wrong**: the B2 defect being fixed is buttons *trapped
below an inner-body fold with no scroll able to reach them*; docking every button row as a body
sibling makes all 17 **reachable-under-scroll**, which is the real user-observable fix.

- **Resolution (operator-approved Option A, PLAN.md:18-20, 183-186):** AT-064a/064c @80×24 relaxed
  from strict all-visible → **reachable-under-scroll** (button visible once its window scrolls into
  view; none trapped below an inner fold). AT-064b @120×30 kept the strict target with the D-3
  fallback ladder — and, per the pilot, also fell back to reachable-under-scroll (only 1/17 visible
  at scroll 0), the deficit recorded in the packet (§5) rather than hidden.
- **Requirement record:** `REQUIREMENTS.md` R-TUI-064 status line encodes "FOLD-8 reachable-under-scroll
  floor" (`REQUIREMENTS.md:4036, 4046`); the §6.5 amendments A-1..A-4 supersede/amend/note the locked
  2×2 rows without silent edits:
  - **A-1** R-PATCH-2X2-LAYOUT-001 → SUPERSEDED batch-46 (`REQUIREMENTS.md:3294`).
  - **A-2** R-PATCH-2X2-SNAPSHOT-001 → SUPERSEDED batch-46 (`:3300`).
  - **A-3** R-TUI-046 → AMENDED batch-46 (paste editor still `CappedTextArea`) (`:3471`).
  - **A-4** R-PATCH-VARIANT-SELECT-001 → NOTE batch-46 (variant/execute rows relocate into
    `#patch_win_script`; normative content UNCHANGED, `test_tui_patch_variant.py` 12/12 green) (`:3312`).

This edge is the healthy Layer-B-catches-what-Layer-A-misses signal: a white-box TC over the CSS
mechanism ("docked row is a body sibling") passes, while the black-box AT ("all buttons visible at
the floor") failed — surfacing that the *requirement*, not the code, was infeasible. Refined, not
forced green.

---

## 5. Frozen-engine + regression

**C-27 dual-guard — 0 frozen diffs.** No frozen-engine path in the diff
(`git diff --name-only main` grep for `core.py|hexfile.py|range_index.py|validation/|tui/a2l.py|tui/mac.py|color_policy.py`
→ NONE). Both guards present in the green suite:
`test_engine_unchanged.py::test_tc027_engine_modules_unchanged_vs_main` +
`test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main` /
`::test_tc031_engine_modules_have_no_name_only_diff_vs_main` / `::test_tc032_engine_test_files_unmodified_vs_main` /
`::test_tc032_no_engine_test_function_is_skipped` (collected, in the 1394-pass run).

**`app.py` diff = 0.** `git diff --stat main -- s19_app/tui/app.py` → empty. The wide↔narrow switch is
pure CSS reusing the existing `width-narrow` regime; zero Python, no `TabbedContent`, no new breakpoint.

**FOLD-1 pass-unchanged.** `test_tui_patch_variant.py` and `test_tui_directionb.py` are **NOT** in the
diff (`git diff --name-only main` confirms) → they pass unchanged. Preserving `patch_pane_entries/
changefile/variant` + `patch_doc_file_row` + `patch_variant_row`/`patch_execute_row` as non-scrolling
grouping sub-containers kept TC-035.2 (variant-above-execute) and the `#patch_pane_entries
.patch-section-title` selector green (Inc-1 packet §4: variant 12/12; directionb `at065a`/`tc332` pass).

**C-26 census-miss FIXED and in the green suite.** The reverse-census caught `test_tui_variants.py`
(2 sites: `test_at067a_variant_info_button_opens_help_modal` + `test_variant_help_modal_fits_at_both_sizes`)
doing `pilot.click("#patch_variant_info_button")` @120×30 without scrolling — the info button now docks
below the fold → `OutOfBounds`. Fixed (approved 6th file): AT-067a prepends
`app.query_one("#patch_win_script").scroll_end(animate=False)` before the real click (same retarget as
`test_at068`); the modal-geometry check opens the modal via the `VariantHelpRequested` message it posts
(keeping that test focused on modal geometry, not the click mechanism). Both now pass inside the
1394-green run — the batch-37 C-26 failure mode did not recur to Phase 4.

**Snapshot drift (C-22).** Exactly 2 patch cells drift (`patch-comfortable-80x24` / `-120x30`), riding
`_batch46_patch_drift_marks` `xfail(strict=False)` — the whole-panel 2×2→3-window relayout. These are 2
of the 5 xfailed in the authoritative run; regen is a **canonical-CI-only post-merge follow-up**
(`snapshot-regen.yml`, `textual==8.2.8`) — local regen forbidden. C-28 NOT triggered (no `show=True`
binding added/removed; patch bindings `6`/`ctrl+z`/`ctrl+y`/`b` are `show=False`).

---

## 6. Evidence checklist

- [✓] **Acceptance criteria use Given/When/Then (WHAT), black-box through the shipped surface.** All 6
  ATs drive `run_test` + `action_show_screen("patch")`. Evidence: `test_tui_patch_layout.py:229-234,
  345-350, 437-441`.
- [✓] **Test cases have explicit Expected, not vague "works".** AT oracles assert cardinality/ordering/
  containment/routing; TCs assert structure + in-viewport. Evidence: `test_at063a` `len(xs)==3` (`:282`);
  `test_at064a` `trapped==[] and unreachable==[]` (`:486-492`).
- [✓] **Edge cases include empty/boundary/invalid/error.** Boundary = both regimes (80×24 floor + 120×30);
  empty = default empty patch document; the RED-on-2×2 counterfactual is the negative case. Evidence:
  module docstring `test_tui_patch_layout.py:32-38`.
- [✓] **Regression checklist exists.** §5: C-27 dual-guard, `app.py` 0-diff, FOLD-1 unchanged, C-26 fix,
  C-22 drift, C-28 not-triggered.
- [✓] **Exit criteria stated.** §Axis verdict below: every US ≥1 passing AT w/ boundary + RED; every LLR
  a passing TC/AT; 0 blocker fails; C-18 holds.
- [✓] **No real PII / secrets.** All fixtures synthetic (`base_dir=tmp_path`, empty patch doc, minimal
  `s19app-changeset` seed). Evidence: `_changeset_text()` `test_tui_patch_layout.py:203-216`.
- [✓] **Test-results section reflects the orchestrator-owned run (not fabricated here).** Numbers are the
  C-25 authoritative gate (1394/2 skip/5 xfail/0 fail); Phase 4 only reconciled node ids
  (`--collect-only`, `git diff`). Evidence: §BLUF gate-run line; Inc-1 packet §4.
- [✓] **Layer B (black-box):** every output-producing story observed through the SHIPPED patch screen with
  boundary (both regimes) + negative (RED-on-2×2) evidence — not only white-box TCs on the CSS mechanism.
  Evidence: §1 AT table; RED executed at Inc-1 (7 failed / 2 passed on stashed 2×2).
- [✓] **Bidirectional surface-reachability:** every named input dimension (wide/narrow · 3 windows ·
  revealed/hidden rows) AND every output/deliverable (3-window layout · 17 docked buttons · paste
  in-viewport · 46 preserved ids · security invariants) exercised through the handler, not only a service
  API. Evidence: §3 matrix.
- [✓] **No unfilled template:** no `<...>` / `TC-NNN` placeholders; every AT/TC bound to a real collected
  node id; the single Phase-1 `_WINDOW_IDS` placeholder resolved to `patch_win_script/_checks/_json`.

---

## Axis verdict

- **Coverage — MET.** Both US covered: US-U8/R-TUI-063 by AT-063a/b (+ AT-063c reparent) at both regimes;
  US-B2/R-TUI-064 by AT-064a/b/c. Every LLR-063.1–.4 / 064.1–.3 has a passing TC/AT; LLR-064.2
  deferred-then-measured in Phase 3 (no D-3 rung needed). The Phase-2 gaps (M-Q3 lost paste verifier,
  M-Q4 unguarded revealed buttons) are closed by TC-46.2 and AT-064c respectively.
- **Certainty — MET.** No vacuous pass: `MIN_USABLE_W/H` floors close the 0-width-passes-distinct-x hole
  (M-Q1); AT-063c routes three *observable* effects (M-Q2); the RED counterfactual is a real 2-vs-3
  discriminator via the preserved `#patch_pane_*` ids (q-m2). C-18 holds — one on-disk node per AT drives
  the whole named chain.
- **Evidence — MET.** Every claim cited to `file:line` / collected node id / `git diff` output; 0 frozen
  diffs and `app.py` 0-diff verified directly; the authoritative gate is the orchestrator's C-25 run.

**No open gap. Recommendation: APPROVE (advance to Phase 5 / self-merge).** The single degradation —
`off != []` at scroll 0 (wide layout still requires scrolling to reach most buttons) — is the
operator-approved **FOLD-8 reachable-under-scroll** contract, bounded by the app's frozen patch viewport
height (an out-of-scope app-geometry carry), not a Phase-4 blocker.
