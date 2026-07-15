# Increment 1 — Review Packet (batch-46, Patch Editor three-window layout)

> Phase 3, atomic structural increment. 5 files. Contract: FOLD-8
> (reachable-under-scroll @80×24; strict-all-visible TARGET @120×30 with the
> pre-approved reachable-under-scroll fallback). No compact buttons.

## 1. What changed
Restructured the Patch Editor from the 2×2 four-pane grid into three responsive
bordered **windows** — PATCH SCRIPT (`#patch_win_script`), CHECKS
(`#patch_win_checks`), JSON EDIT (`#patch_win_json`) — each = a **constant title
Label** + a **scrollable `VerticalScroll` body** + **docked button-row siblings
of that body** (the B2 fix: buttons never trapped below the body's inner fold).
The four pre-existing grouping sub-containers (`patch_pane_entries`,
`patch_pane_changefile`, `patch_pane_variant`, `patch_doc_file_row`) are
preserved intact as non-scrolling groups (FOLD-1); only their button rows moved
out to the docked region. Every leaf id + the `.hidden`-toggled rows +
`patch_variant_row`/`patch_execute_row` are preserved; window titles are
constant strings (C-17/F3). The wide↔narrow switch is **pure CSS reusing the
existing `width-narrow` regime** (`app.py` diff = 0): 3 columns (`grid-columns`
= `2fr 1fr 1fr`, PATCH SCRIPT widest) when ≥120, stacked with a panel-level
scroll when <120. Docked button rows wrap via `grid-size: 2` so no button clips
horizontally in the narrow wide-columns. A one-line CSS bound on
`#patch_variant_select_row { height: 3 }` stops the Textual `Select`'s 12-line
dropdown overlay from inflating the docked group's auto-height (which had left
the execute buttons 1 row past the scrollable content, unreachable).

## 2. Files modified (5 — within cap)
- `s19_app/tui/screens_directionb.py` — `PatchEditorPanel.compose` rewritten
  into 3 windows (title + `VerticalScroll` body + docked siblings); added
  `VerticalScroll` import; `patch_checks_section_label` relocated to the CHECKS
  window (kept for `test_at057a`). No behavior/wiring/id change.
- `s19_app/tui/styles.tcss` — replaced the `#patch_editor_panel` 2×2 grid block
  with the 3-window horizontal/`width-narrow`-vertical layout, `.patch-window` /
  `.patch-window-title` / `.patch-window-body` / `.patch-docked-row|group`
  rules, grid-wrapping docked button rows, and the `#patch_variant_select_row`
  height bound. Dropped the dead `#patch_saveback_row { column-span: 2 }` (a-m3);
  reconciled both patch CSS blocks; preserved `#patch_paste_text { height: 8 }`.
- `tests/test_tui_patch_layout.py` — fully superseded: AT-063a/b (geometry +
  `MIN_USABLE_W/H`), AT-063c (reparent census + observable routing per window),
  AT-064a/b/c (reachable-under-scroll oracle + docked-sibling structural check),
  TC-46.1 (layout-agnostic structure + `width-narrow` rule), TC-46.2
  (paste-in-viewport, FOLD-4). Lifts the `_fully_visible` predicate from the
  prototype; adds a `_reach` helper.
- `tests/test_tui_patch_editor_v2.py` — retargeted the 2× `scroll_end(
  "#patch_pane_entries")` → `#patch_win_script` (the window is the scroller that
  reveals docked buttons); added FOLD-6 census asserts to `test_at058b`
  (`#patch_checks_status`/`#patch_doc_issues` `_render_markup is False`,
  `#patch_paste_text` is `CappedTextArea`).
- `tests/test_tui_snapshot.py` — added `_batch46_patch_drift_marks` (2 `patch`
  cells `xfail(strict=False)`, C-22 upper bound) wired into the scaffold marks.

## 3. How to test
```bash
# Primary gate (one run):
pytest -q tests/test_tui_patch_layout.py tests/test_tui_patch_editor_v2.py \
        tests/test_tui_snapshot.py -p no:cacheprovider
# Must-pass-unchanged (FOLD-1):
pytest -q tests/test_tui_patch_variant.py
pytest -q tests/test_tui_directionb.py -k "at065a or tc332"
# C-27 frozen-engine dual guard (0 diffs expected):
pytest -q tests/test_engine_unchanged.py
pytest -q tests/test_tui_directionb.py -k "tc031 or tc032"
# Lint:
ruff check s19_app/tui/screens_directionb.py tests/test_tui_patch_layout.py \
           tests/test_tui_snapshot.py tests/test_tui_patch_editor_v2.py
```

## 4. Test results (actual)
- **Primary gate (one run): `91 passed, 2 xfailed` (exit 0), 145.98s.** The 2
  xfailed are exactly the `patch-comfortable-80x24` / `-120x30` snapshot cells
  (`_batch46_patch_drift_marks`, regen pending in canonical CI).
- **RED-first (new tests vs stashed old 2×2 source): `7 failed, 2 passed`** —
  AT-063a/b + AT-064a/b/c + TC-46.1/46.2 fail (window ids absent / docked
  buttons unreachable); the 2 that pass are the reparent-safety nets (leaf ids
  preserved in both trees — expected, not geometry discriminators).
- **Must-pass-unchanged:** `test_tui_patch_variant.py` `12 passed` (TC-035.2
  variant-above-execute unchanged); `test_tui_directionb.py -k "at065a or
  tc332"` passed (the `#patch_pane_entries .patch-section-title` selector holds);
  `test_at057a` / `test_at058b` / `test_at068a` / `test_at068b` pass.
- **C-27 dual guard:** `test_tc027_engine_modules_unchanged_vs_main` PASSED +
  `tc031`/`tc032` guards passed → **0 frozen-engine diffs** (none of the 5 files
  is frozen).
- **ruff:** `All checks passed!`
- **Broader `pytest -q -m "not slow"`: `2 failed, 1392 passed, 2 skipped, 5
  xfailed` (797s).** The 2 failures are in **`tests/test_tui_variants.py`** (NOT
  in the approved 5-file set) — `test_at067a_variant_info_button_opens_help_modal`
  and `test_variant_help_modal_fits_at_both_sizes`. Both do
  `pilot.click("#patch_variant_info_button")` at 120×30 without scrolling; the
  "?" button is now docked at the bottom of the PATCH SCRIPT window (below the
  11-row fold), so the click raises `textual.pilot.OutOfBounds`. **Confirmed
  fix (verified in a harness):** prepend `app.query_one("#patch_win_script")
  .scroll_end(animate=False)` before each click (same retarget as the
  `test_at068` fix) → the modal opens. This is a **census miss** — the spec
  enumerated `test_tui_patch_variant.py` (FINDING 5) but not the separate
  `test_tui_variants.py`. Fixing it is a **6th file → exceeds the 5-file cap →
  STOPPED for approval** (do not silently absorb).

## 5. Pilot-measured geometry (C-13/C-23 — measured, not fr-derived)
| Regime | Panel content | Window regions (x,y,w,h) | Distinct x / y |
|---|---|---|---|
| Wide 120×30 | 92×11 | script (25,8,**44**,11) · checks (70,8,**22**,11) · json (93,8,**23**,11) | 3 x / 1 y |
| Narrow 80×24 | 70×**5** | script (7,8,68,**28**) · checks (7,37,68,14) · json (7,52,68,**7**) | 1 x / 3 y |
- Wide ratio `grid-columns: 2fr 1fr 1fr` (PATCH SCRIPT widest); asymmetry is a
  measured design call (FOLD-2), not operator-locked.
- `MIN_USABLE_W = 15`, `MIN_USABLE_H = 5` — floors set below every measured
  window (min wide width 22, min height across regimes 7) yet reject a starved
  window.
- Button height = **3** (Textual default; no compact override — per directive).
  Docked rows wrap `grid-size: 2`. Narrow panel scrolls (`max_scroll_y = 45`).
- **Reachability (17/17 named buttons reachable-under-scroll at BOTH sizes)**;
  revealed save-back/before-after buttons also 4/4 (AT-064c). Visible-at-scroll-0:
  **0/17 @80×24**, **1/17 @120×30**.
- **D-3 fallback rung applied: NONE of rungs 1–3.** The `off == []` @120×30
  deficit (16/17 not visible at scroll 0) is bound by the **app-frozen panel
  VIEWPORT height** (5 rows @80×24, 11 @120×30 — `app.py` layout, 0-diff
  mandated), not by docked-row count, so consolidating entry rows (rung 1) or
  relocating variant/execute (rung 2) recovers **0 rows** of the deficit and
  rung 3 (key-binding) is forbidden ("no new binding"). Applied the pre-approved
  **FOLD-8 reachable-under-scroll** directly. The load-bearing fix that recovered
  the last 2 (execute) buttons from *unreachable* → *reachable* was the
  `#patch_variant_select_row { height: 3 }` bound (Select-overlay phantom).

## 6. Risks
- **Snapshot baselines:** the 2 `patch` cells will mismatch until regenerated in
  canonical CI (`snapshot-regen.yml`, textual==8.2.8). They ride
  `xfail(strict=False)` — do NOT regen locally (drifts unrelated baselines).
- **`off == []` @120×30 not met** (only 1/17 visible at scroll 0). This is the
  pre-approved FOLD-8 degradation, not a defect — but it means the wide layout
  still requires scrolling to reach most buttons; UX is bounded by the app's
  11-row patch viewport, which this batch cannot change.
- **`_reach` test helper** drives `scroll_y` directly because Textual 8.2.8's
  `scroll_visible`/`scroll_to_widget` did not propagate through the nested
  auto-scroll containers here. A real user reaches the same buttons via
  mouse-wheel/pane scroll; keyboard focus-scroll (which uses `scroll_visible`)
  may be less reliable — flagged, not in this increment's scope.
- **`_render_markup`** (not `_markup`) is the Textual 8.2.8 attribute the FOLD-6
  markup-safety assert reads; a Textual upgrade could rename it.
- **Branch:** working tree is on `claude/app-screens-audit-c58d94`, not the
  `feat/batch-46-patch-3col` named in the kickoff. Not committed (orchestrator
  gates). Flagging the discrepancy for the orchestrator to reconcile before
  commit.

## 7. Pending items
- **BLOCKER for full-suite green (needs approval): a 6th file.** Retarget the 2
  `pilot.click("#patch_variant_info_button")` sites in `tests/test_tui_variants.py`
  (`test_at067a_variant_info_button_opens_help_modal` ~line 461,
  `test_variant_help_modal_fits_at_both_sizes` ~line 558) to
  `scroll_end("#patch_win_script")` first. Confirmed low-risk (same pattern as
  `test_at068`; verified the modal then opens). Exceeds the 5-file cap → awaiting
  the orchestrator's go.
- Canonical-CI snapshot regen of the 2 `patch` cells (post-merge follow-up).
- Inc-2 (docs, 2 files): `REQUIREMENTS.md` R-TUI-063/064 rows + §6.5 amendments
  (A-1..A-4) + `01-requirements.md` traceability closeout.

## 8. Evidence checklist
- [x] Tests/type checks/lint pass — primary gate 91 passed/2 xfailed; ruff clean.
- [x] No secrets in code or output.
- [x] No destructive commands (the `git stash push/pop` for RED was reverted;
  no `-f`, no reset --hard, no commit).
- [x] File count within cap — exactly 5 files.
- [x] Review packet attached (this file).
- [x] C-27 frozen-engine diff = 0 (tc027 + tc031 + tc032 green).
- [x] Must-pass-unchanged confirmed (variant 12/12, directionb section-title,
  at057a/at058b/at068a/at068b).

## Suggested next task
**Inc-2 — docs (2 files):** add `R-TUI-063` / `R-TUI-064` rows to
`REQUIREMENTS.md`, apply the §6.5 Before/After amendments (A-1 R-PATCH-2X2-
LAYOUT-001, A-2 R-PATCH-2X2-SNAPSHOT-001, A-3 R-TUI-046, A-4 NOTE
R-PATCH-VARIANT-SELECT-001), record FOLD-8, and close out the traceability table
in `01-requirements.md`.
