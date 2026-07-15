# PLAN — batch-46 · Patch Editor responsive 3-column redesign (field-audit B2 + U8)

> Living compendium. Created Phase 0 (2026-07-15). Updated at every gate.
> **STATUS: Phase 3 Inc-1 GATED + COMMITTED (`e05ffec`) → Inc-2 (docs) next. D1=STACKED; run-mode=AUTONOMOUS-THROUGH-SELF-MERGE. Branch `feat/batch-46-patch-3col`.**
>
> **Inc-1 result:** 3-window layout shipped (app.py diff = 0, pure-CSS). Gate 1394 passed / 0 failed / 5 xfailed
> (2 batch-46 patch-drift + 3 pre-existing), C-27 clean, ruff clean, code-review APPROVE-WITH-NITS (all applied).
> 6 files (census-miss +1: `test_tui_variants.py`). Reachable-under-scroll oracle RED-proven + independently
> verified valid. Committed to protect against a concurrent session's branch-switching.
>
> **Inc-1 measured blocker → FOLD-8 (operator Option A):** pilot showed the patch panel gets only **5 rows @80×24**
> (deferred app-geometry starvation; frozen `app.py`), so all 17 buttons can't be simultaneously visible at the floor.
> AT-064a/064c @80×24 relaxed to **reachable-under-scroll** (button visible once its window scrolls into view; none
> trapped below an inner-body fold — the real B2 defect); AT-064b @120×30 keeps strict all-visible with the D-3
> fallback ladder. Dev resumed with this contract.
>
> **Phase-2 fold (02-review.md · 01-req §6.6):** 0 blockers; D1 CSS-reuse + reparent-safety VERIFIED. KEY design
> change FOLD-1 — **PRESERVE pane container ids as non-scrolling sub-containers** (not retire) → `test_tui_patch_variant.py`
> + `test_tui_directionb.py` stay green unchanged, 5-file atomic increment, no >5-file exception. +AT-064c (revealed
> saveback/before-after reachability). +MIN_USABLE_W/H floor + asymmetric-column allowance. +C-17 markup-safety asserts.
> AT registry = 6 (063a/b/c · 064a/b/c). Re-cut: Inc-1 (5 files, atomic) / Inc-2 (docs).
>
> **Phase-1 result:** US=2, HLR=2 (HLR-063 responsive 3-window · HLR-064 docked reachability),
> LLR=7, AT=5 (063a/b/c · 064a/b). New rows R-TUI-063/064; §6.5 supersede R-PATCH-2X2-LAYOUT-001
> + R-PATCH-2X2-SNAPSHOT-001, amend R-TUI-046, note R-PATCH-VARIANT-SELECT-001. Canonical window
> ids = `patch_win_script/_checks/_json`. Reverse-census found 2 files beyond kickoff
> (`test_tui_directionb.py:7955`, `test_tui_patch_variant.py`) + a duplicate `#patch_saveback_row`
> CSS rule (styles.tcss:838+999). Carries → Phase 3: O-1 nested-scroll @80×24 (pilot; escalate if
> UX-affecting), A2/R-2 whole-budget re-measure, duplicate-CSS reconcile.

## BLUF
Restructure `PatchEditorPanel` from the current 2×2 grid into **three bordered windows —
PATCH SCRIPT / CHECKS / JSON EDIT — with docked button rows always reachable**, laid out
**3-columns when wide (≥120 cols) and vertically stacked at the 80×24 floor**. This fixes
**B2** (patch buttons overflow an under-weighted `1fr` grid cell, unreachable; scroll fragmented
across ~5 regions) and **U8** (weak gestalt — labeled sections vs. real separated windows).
Realized as **CSS + compose restructure only, reusing the existing `width-narrow` 120-col
regime — zero new Python, no `TabbedContent`, no new breakpoint.** Deferred (operator):
app start width/height + font scale.

## Objective & scope
- **In scope:** B2 (buttons unreachable / 3 scrollbars) + U8 (3-window gestalt). Compose +
  CSS restructure of `PatchEditorPanel`; docked button rows; responsive 3-col↔stacked via the
  existing regime; supersede the pinned 2×2-grid layout/census tests; snapshot drift marks.
- **Out of scope (deferred):** app start geometry + font scale; any behavior/wiring change
  (this is layout-only — every action, message, and service call is preserved); the other
  field-audit items (B1 Issues paging, B3 A2L two-chars, N2 Issues filter/sort, N4 paste-everywhere).

## RC-1 (base currency) — PASS @ `1bf3b19`
`git fetch` clean; working branch == `origin/main` tip `1bf3b19` ("#84 … next = patch 3-column");
merge-base == tip, no rebase. **Already-shipped check:** the responsive 3-window layout is
NOT implemented — `PatchEditorPanel.compose` is the 2×2 grid (`screens_directionb.py:2271-2567`),
`#patch_editor_panel` is `layout: grid; grid-size: 2 4` (`styles.tcss:801-809`). Stories proceed.
Branch to cut: `feat/batch-46-patch-3col` off `origin/main`.

## Phase 0 — Definition of Ready
| Story | Statement (observable outcome) | INVEST | Class |
|---|---|---|---|
| **US-B2** | *As an operator at any terminal width, every Patch Editor action button (Load/Refresh/Validate/Apply/Save, Run checks, entry Add/Edit/Remove/Edit-JSON, Undo/Redo, Parse/Edit-JSON, variant Execute, save-back Write) is reachable without a button being trapped below a starved pane fold — buttons dock outside the scroll region.* | ✓ all | **READY** |
| **US-U8** | *As an operator, the Patch Editor presents three visually-separated windows (PATCH SCRIPT / CHECKS / JSON EDIT) — 3 columns side-by-side when the terminal is wide (≥120), stacked full-width when narrow (<120) — so the three concerns read as distinct workspaces, not labeled sections in one stack.* | ✓ all | **READY** |

Both are user-verified observable behaviors (WHAT), black-box observable through the shipped
patch screen at pilot sizes 80×24 + 120×30. No REFINE/SPIKE/OUT.

## Design decision **D1** (KEY — needs operator confirmation)
**Recommended: CSS-driven 3-window layout, stacked (not tabbed) at the floor, no `TabbedContent`.**

The prototype tested variant 1 (3-col, cramped at 80×24) and variant 3 (true tabs, roomy at
floor). The operator direction says "tabbed/**stacked** at the 80×24 floor" — stacked is within
the approved direction. I recommend **stacked** over **tabbed** because:
- **Reuse, not new machinery.** Stacked = pure CSS on the existing `width-narrow` regime
  (`#workspace_body.width-narrow #patch_editor_panel { layout: vertical }`), exactly the
  batch-45 map-reflow pattern. **Zero new Python, no new breakpoint, no widget-tree swap.**
- **True tabs (variant 3) would require recompose-on-resize** (swap 3 columns ⇄ `TabbedContent`
  as width crosses 120) — the kind of stateful widget-tree churn that has bitten us before
  (recompose timing, id-query races, focus/scroll-state loss). Higher risk, against the
  operator's "extra careful" stance.
- Both options fix B2 (docked buttons) + U8 (3 windows) equally. Stacked's only cost is the
  floor experience is scroll-a-window rather than tab-between; buttons stay docked/reachable.

**If the operator wants true tabs at the floor**, that's a scoped upgrade: +1 increment, a
regime-watch recompose, and structural snapshot/geometry rework. Flagging as the one design
fork to confirm before Phase 1 derivation locks.

### Window → content mapping (proposed; architect finalizes in Phase 1)
| Window | Body (scrollable) | Docked button row(s) |
|---|---|---|
| **PATCH SCRIPT** | entries table + empty-state + entry inputs (addr/value/bytes); change-file select + path; variant select+info; execute-scope | entry Add/Edit/Remove/Edit-JSON + Undo/Redo; Load/Refresh/Validate/Apply/Save; Execute |
| **CHECKS** | issue count + issues; checks status; checks results; checks help | Run checks |
| **JSON EDIT** | paste TextArea; (save-back name input + before/after — revealed rows) | Parse pasted + Edit JSON; save-back Write/Don't-save/Width; Write before/after report |
> Open Phase-1 question: PATCH SCRIPT carries the most content (entries + change-file + variant).
> The architect may split variant/execute into the CHECKS or JSON column for balance, or keep a
> 4th concern. Docked-row count per window is a C-23 pilot-measured decision at 80×24.

## Requirements outline (Phase 1 will formalize as R-TUI-06x + HLR/LLR)
- **HLR-B2** the panel *shall* dock each window's action buttons outside that window's scroll
  region so no button is clipped below a fold at 80×24 or 120×30.
- **HLR-U8** the panel *shall* render three bordered windows; horizontal (3-col) at width ≥120,
  vertical stack at width <120, via the existing `width-narrow` regime.
- **LLR set:** compose restructure (reparent all widgets into 3 window containers, preserving
  every load-bearing leaf id + the 2 hidden-row ids); `styles.tcss` patch rules (wide 3-col /
  narrow stack / docked rows / TextArea min-height preserved); no Python/wiring change.
- **Acceptance (black-box):** AT-B2 (every named button in-viewport/reachable at 80×24 **and**
  120×30 — RED on the current starved-grid tree); AT-U8a (3 windows, 3 distinct `region.x` at
  ≥120 — one column each); AT-U8b (3 windows, 1 distinct `region.x` / stacked `region.y` at <120);
  AT-reparent (all leaf ids resolve + one action per window routes to its observable effect).

## Reparent-safety map (from the app read-across — grounds the LLR)
- **Wiring is message-based, not pane-id-based.** App resolves `#patch_editor_panel` and calls
  `set_edit_json_enabled` / `set_undo_redo_enabled` / `set_entry_edit_json_enabled` /
  `set_variants` / `set_change_files`; reacts to `ActionRequested`/`SaveBackDecision`/… messages.
- **Must-preserve leaf ids (14):** `patch_edit_json_button`, `patch_undo_button`,
  `patch_redo_button`, `patch_entry_edit_json_button`, `patch_doc_file_select`,
  `patch_variant_select`, `patch_doc_entries_table`, `patch_doc_empty_state`,
  `patch_doc_issue_count`, `patch_doc_issues`, `patch_saveback_name_input`,
  `patch_saveback_width_button`, `patch_checks_status`, `patch_checks_results`.
- **Must-preserve container ids (`.hidden` toggled in Python):** `patch_saveback_row`,
  `patch_before_after_row`.
- **Safe to retire/rename (structural-only, CSS+census tests):** `patch_pane_entries/changefile/
  checks/variant`, `patch_editor_panel` layout, `patch_doc_file_row` structure.

## Test-supersession census (C-26 — THE risk; reverse-grep each touched id across `tests/`)
Superseded from the 2×2 contract → the 3-window contract (RED-first, then rewrite):
1. `test_tui_patch_layout.py::test_at_033a/033b` (2×2 grid geometry) → **AT-U8a/U8b** 3-window geometry.
2. `…::test_tc_pane_styles_and_grid` (panel `grid` + `#patch_doc_controls` grid-3) → new panel
   layout + docked-row layout assertions.
3. `…::test_tc319_regroup_section_structure_census` (change-file pane structure) → update to the
   new window parentage; **section labels + `#patch_doc_controls` 5-button census PRESERVED**.
4. `…::test_at058a_paste_editor_in_viewport_and_separated` (paste vs `#patch_pane_changefile`) →
   **AT-B2/JSON** paste editor in-viewport in JSON EDIT window, both regimes.
5. `test_tui_patch_editor_v2.py::test_at057a` / `test_at058b` / `test_panel_composition`
   (id + reparent census; `#patch_pane_changefile` is in the preserved-id list) → update the
   preserved-id set to the new window ids; every **leaf** id stays.
6. `test_tui_snapshot.py` `patch-comfortable-80x24 / -120x30` cells → **drift** (whole relayout);
   add `_batch46_patch_drift_marks` xfail(strict=False), regen in canonical CI post-merge.
> Reverse-grep list to run at Phase 2/3: `patch_editor_panel`, `patch_pane_entries`,
> `patch_pane_changefile`, `patch_pane_checks`, `patch_pane_variant`, `patch_doc_file_row`,
> `patch_paste_row`, `patch_doc_controls`, `patch_checks_controls`.

## Controls consulted (project `docs/engineering-rules.md` + global)
- **C-13 / C-13.1 / C-23 (geometry, pilot-measure):** every geometry claim (column count, docked-row
  height, TextArea fold, 80×24 button reachability) established by `App.run_test(size=…)` region
  reads at **both** 80×24 and 120×30 — never `fr`-math. Re-measure the whole pane budget.
- **C-22 (per-cell snapshot drift):** name the 2 patch cells + reason per-cell under a
  `strict=False` envelope; exact count is an upper bound.
- **C-28 (shared-chrome binding drift):** **NOT triggered** — no `show=True` binding added/removed
  (patch bindings `6`/`ctrl+z`/`ctrl+y`/`b` are `show=False`; verified).
- **C-16 (prototype-fidelity):** prototype IS Textual (same framework) → layout transfers, but
  the responsive 3-col↔stacked switch and docked-button reachability are `assumed — pilot-measure
  in Phase 3` at both regimes.
- **C-26 (touched-symbol reverse census):** the supersession list above; reverse-grep at gate.
- **No new control proposed** — the existing set covers this batch. If a genuine root-cause gap
  surfaces (e.g. a responsive-both-regimes AT rule), it goes to `docs/engineering-rules.md`, not
  the global command (operator placement policy).

## Increment cut (proposed; ≤5 files each — architect refines in Phase 1)
- **Inc-1 — source restructure + geometry tests.** `screens_directionb.py` (compose → 3 windows)
  + `styles.tcss` (3-col/stack/docked) + `test_tui_patch_layout.py` (supersede AT-033x/tc_pane/
  at058a → 3-window geometry + docked-button reachability, RED-first). ~3 files.
- **Inc-2 — census + reparent-safety + snapshot.** `test_tui_patch_editor_v2.py` (at057a/at058b/
  composition id supersession + reparent-safety AT) + `test_tui_snapshot.py` (drift marks). ~2 files.
- **Inc-3 — REQUIREMENTS.md** (R-TUI-06x add + amend the 2×2 R-TUI-030/033 rows via §6.5
  before/after) + any overflow. ~1 file.

## Risks / watch-items
- **R1 (highest):** superseding 6 pinned tests — a missed reverse-grep re-breaks at Phase-4
  full-suite (the batch-37 C-26 failure mode). Mitigation: reverse-grep list above, run at Phase 2.
- **R2:** docked-button geometry at the 80×24 floor stacked — each window's docked row must not
  clip; pilot-measure (C-23), don't assume the prototype's numbers transfer to the full widget set.
- **R3:** snapshot regen is canonical-CI-only (local regen drifts unrelated cells,
  `reference_snapshot_regen_env`) — a post-merge follow-up PR, not part of this batch's gate.
- **R4:** PATCH SCRIPT window content density (entries + change-file + variant) may overflow at
  80×24 stacked — the docked buttons still reach, but the body scrolls; acceptable per B2 (fix is
  reachability, not zero-scroll).

## Decision log
- 2026-07-15 · Phase 0 · RC-1 PASS @ `1bf3b19`; US-B2 + US-U8 READY; design decision D1
  (CSS-only stacked-at-floor) recommended; plan presented.
- 2026-07-15 · Phase-0/1 gate · **APPROVED.** Operator (AskUserQuestion): **D1 = STACKED (CSS-only)**;
  **run-mode = AUTONOMOUS THROUGH SELF-MERGE** (final PR-QA pass gates the merge; HIGH blocks →
  operator). Branch `feat/batch-46-patch-3col` cut off `1bf3b19`. → Phase 1 derivation (architect +
  qa-reviewer in parallel).

## Out-of-scope carries
- App start geometry + font scale (operator-deferred).
- Field-audit B1 / B3 / N2 / N4 (separate future batches per BACKLOG).
