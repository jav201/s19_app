# 04 — Validation (Phase 4) — 2026-07-11-batch-37

> BLUF: **PASS.** All 5 stories (US-061/062/063/064a/064b) validate on both layers.
> **8/8 black-box ATs green** — each reconciles to EXACTLY ONE on-disk node (C-18), drives the
> SHIPPED surface, asserts the DELIVERABLE content (C-10), and has a real, recorded counterfactual
> (C-20). **10/10 white-box nodes green** (TC-324..331 + TC-319 + AT-036b). Orchestrator gate run
> (C-25) `pytest -q -m "not slow"` = **1358 passed, 2 skipped, 20 deselected, 5 xfailed, 0 failed**
> (exit 0, 11:56). Engine-frozen = **0 diffs**. Ledger `--collect-only` = **1385** (reconciles).
> Residuals are all accepted (2 canonical-regen-pending snapshot cells + 8 LOW carries). One
> Phase-4 finding (TC-319 cross-file census miss, orchestrator-fixed, control candidate proposed).
> Language: English.

---

## 1. Gate-run evidence (C-25 — orchestrator-owned; NOT re-run here)

The full CI-equivalent run is orchestrator-owned per C-25. Recorded tail (post the TC-319 fix,
first-run failure described in §7):

```
1358 passed, 2 skipped, 20 deselected, 5 xfailed, 0 failed   — exit 0, 11:56
```

**Ledger reconciliation:** `1358 passed + 2 skipped + 5 xfailed = 1365 collected-and-run` under
`-m "not slow"`; `+ 20 deselected-slow = 1385` total collected → equals the `--collect-only`
count I re-confirmed this phase (see §5). Consistent.

**The 5 xfailed set** (grepped + confirmed this phase — NOT a hidden regression):
| # | Node | Origin | Disposition |
|---|------|--------|-------------|
| 1 | `test_tc036s_entropy_modal_snapshot[entropy-comfortable-80x24]` | **batch-37 Inc-3/4** | canonical-CI baseline regen post-merge (local regen forbidden — snapshot-regen convention) |
| 2 | `test_tc036s_entropy_modal_snapshot[entropy-comfortable-120x30]` | **batch-37 Inc-3/4** | same |
| 3 | `test_tui_app.py:1784` | pre-existing | not batch-37 |
| 4 | `test_tui_public_api.py:162` | pre-existing | not batch-37 |
| 5 | `test_validation_engine.py:211` | pre-existing | not batch-37 |

Only cells 1–2 are batch-37's (`_batch37_entropy_drift_marks`, `test_tui_snapshot.py:613-634`,
`xfail(strict=False)`, reason names US-062 `#entropy_controls`/`page P/Q` + US-063
`#entropy_legend`/`#entropy_cell_k`). The other three are unrelated pre-existing xfails in the
tree. I did NOT re-run the full ~12-min suite; I re-ran only targeted nodes + the snapshot file.

---

## 2. Layer A (white-box) — TC + regression nodes → on-disk fn → executed PASS

Run this phase (targeted, fast):
`pytest tests/test_tui_entropy_viewer.py::{9 nodes} -q` → **9 passed in 15.88s**;
`pytest tests/test_tui_patch_editor_v2.py::{6 nodes} -q` → **6 passed in 8.55s**;
`pytest test_before_after_report.py::{2} test_tui_patch_layout.py::{1} -q` → **3 passed in 2.51s**.

| Node | On-disk fn (file:line) | LLR | Result |
|------|------------------------|-----|--------|
| TC-324 | `test_tc324_page_slice_math` — `tests/test_tui_entropy_viewer.py:626` | 062.1 (page slice/clamp/indicator/union-reachable) | PASS |
| TC-325 | `test_tc325_sort_key_no_mutation_and_remap` — `:670` | 062.2 (entropy desc + addr tie-break; `_windows` unmutated; page reset; remap) | PASS |
| TC-326 | `test_tc326_legend_derived_from_band_colour` — `:816` | 063.1 (`set(legend)==set(ENTROPY_BAND_COLOUR)`; non-blank; no `[`/`]`) | PASS |
| TC-327 | `test_tc327_action_jump_remap_and_bound` — `:851` | 063.2 (`_window_for_row` remap under sort/page; S-03 out-of-range no-op) | PASS |
| TC-328 | `test_tc328_refresh_uses_source_path_not_widget_and_noops_when_unloaded` — `tests/test_tui_patch_editor_v2.py:2622` | 064a.1 (A-03: `source_path` not widget; None-guard) | PASS |
| TC-329 | `test_tc329_popup_seed_and_load_text_apply_seam` — `:2961` | 064b.1/.2 (seed==buffer; Confirm→`load_text` ×1; Cancel→0) | PASS |
| TC-330 | `test_tc330_before_after_row_reveal_hide_state_machine` — `tests/test_before_after_report.py:1258` | 061.1 (default-hidden/show/hide/route) | PASS |
| TC-331 | `test_tc331_disable_guard_predicate_tracks_source_path` — `tests/test_tui_patch_editor_v2.py:3041` | 064b.4 (disabled tracks `source_path` live) | PASS |
| **TC-319** | `test_tc319_regroup_section_structure_census` — `tests/test_tui_patch_layout.py:351` | cross-increment census (Phase-4 fix, §7) | **PASS (green post-fix)** |
| AT-036b | `test_at036b_jump_second_row_moves_focus` — `tests/test_tui_entropy_viewer.py:139` | 062.2 load-bearing remap regression guard (2-window addr sort, page0, row1 → `0x4000`) | PASS |

---

## 3. Layer B (black-box) — 8 ATs → EXACTLY ONE node (C-18/V-5) + per-AT counterfactual

All 8 executed by nodeid this phase (green, cited above). Each drives the shipped surface, asserts
the DELIVERABLE content (C-10), and its RED counterfactual (from the increment packet) is a real
feature-absence failure, not an incidental error.

| AT | One on-disk node (file:line) | Shipped surface driven | Deliverable asserted (C-10) | Counterfactual (C-20 RED) |
|----|------------------------------|------------------------|-----------------------------|---------------------------|
| **AT-061a** | `test_at_061a_persistent_control_survives_then_writes_pair_and_clears` — `test_before_after_report.py:1108` | real save-back → `#patch_before_after_row` revealed; `.press()` on `#patch_before_after_button` routes `on_button_pressed`→`BeforeAfterReportRequested`→`action_before_after_report` | control queryable AFTER an unrelated `add_entry` + re-render (persistence proxy, Q-06); **reread of the produced `reports/*.md` off disk** asserts Run-diff heading + provenance header (C-12 output-then-consume); clear-on-context arm re-hides | `NoMatches: '#patch_before_after_row'` — widget absent; transient `notify` cannot satisfy the node |
| **AT-062a** | `test_at062a_page_past_cap_reaches_later_window` — `test_tui_entropy_viewer.py:475` | `#entropy_page_next` / `PgDn` over a `large_s19` >512-window fixture (both 80x24 + 120x30) | jump list shows a window index ≥512 with the correct `0xADDR band H=…` label; selecting it dismisses with THAT window's `start` | `AttributeError: no attribute '_page_size'/'_display_windows'` + `#entropy_page_indicator` absent |
| **AT-062b** | `test_at062b_sort_entropy_top_row_is_max` — `:551` | `#entropy_sort_button` / `s` toggle | row 0 `.entropy == max(w.entropy for w in windows)` + its address == that window `start`; strip cell order follows the same permutation; page reset to 0 | same `_page_size`/sort-attr AttributeError set (sort absent) |
| **AT-063a** | `test_at063a_band_legend_present_with_meanings` — `:708` | `#entropy_legend` in `#entropy_body` (renders for empty image too) | all four `ENTROPY_BAND_COLOUR` band meanings + the low-confidence dim cue present in rendered Labels | `#entropy_legend NoMatches` / `AttributeError: no attribute '_legend_lines'` |
| **AT-063b** | `test_at063b_click_strip_cell_dismisses_with_address` — `:761` | **real `await pilot.click("#entropy_cell_k")`** (C-16, per-cell widget, no offset math) under a non-default `entropy` sort + shrunken page budget | dismiss with the EXACT clicked cell's window `start` — `cell_0`→`0x1200` (max), `cell_1`→`0x1100` (last-of-page); never a proxy `action_jump` call | `#entropy_cell_k` absent; `action_jump` is `None` (not callable) |
| **AT-064a** | `test_at064a_refresh_rereads_edited_file_into_editor` — `test_tui_patch_editor_v2.py:2556` | `#patch_doc_refresh_button` press → `ActionRequested(refresh_doc)` → `ChangeService.load` over `document.source_path` | external-edit then Refresh → entries table shows the NEW `0x555` entry that exists ONLY in the second on-disk version (C-12 reads the consumer the real handler produced) | `NoMatches: '#patch_doc_refresh_button'` |
| **AT-064b** | `test_at064b_json_popup_edit_confirm_cancel_and_geometry` — `:2737` | paste-seed → "Edit JSON" (`#patch_edit_json_button`) → `ChangeSetJsonScreen` `#changeset_json_text` edit → **Confirm** → `parse_paste`→`load_text` | entries table (consumer `load_text` produced) shows the new `0x777` entry; Cancel leaves doc `["0x100"]`; geometry arm pins N_80≥7, N_120≥13 editable lines | `NoMatches: '#patch_edit_json_button'` |
| **AT-064c** | `test_at064c_edit_json_disabled_for_file_backed_document` — `:2865` | load a real change FILE (`source_path` set) vs. parse a PASTE (`source_path None`) — both states in ONE node | file-loaded → button `disabled`; a directly-posted `EditJsonRequested` does NOT push `ChangeSetJsonScreen` (queryable-absent) and mutates 0 entries (A-01 no-clobber); paste-authored → `enabled` + popup opens | `NoMatches: '#patch_edit_json_button'` (guard/button absent) |

**C-18 verdict:** 8 ATs → 8 distinct on-disk nodes, no fan-out, no AT split across nodes. The
two-size (80x24 + 120x30) requirement for AT-062a/b/063a/b is met by looping sizes INSIDE each
single node (C-18-compliant), not by parametrizing extra nodes.

---

## 4. Bidirectional surface-reachability matrix (input dim + output/deliverable through the handler)

Every named INPUT dimension is exercised through the real handler and every named OUTPUT/deliverable
is OBSERVED through the shipped surface (not the service API directly).

| Story | INPUT dimension → handler | OUTPUT / deliverable ← observed surface | Node |
|-------|---------------------------|------------------------------------------|------|
| US-061 | successful save-back → `on_patch_editor_panel_save_back_decision` reveals row; `.press()` → message → `action_before_after_report` | `reports/*.md` + `reports/*.html` pair **reread off disk** (content) + control queryable post-re-render | AT-061a |
| US-062 (page) | `#entropy_page_next`/`PgDn` → `action_page_next` → clamped page index | `#entropy_jump_list` rows for index≥512 + `dismiss(window.start)` value | AT-062a |
| US-062 (sort) | `#entropy_sort_button`/`s` → `action_toggle_sort` (display copy) | `#entropy_jump_list` row 0 content + strip cell permutation | AT-062b |
| US-063 (legend) | modal push → `compose`→`_legend_widget` | `#entropy_legend` rendered Label rows (4 bands + dim) | AT-063a |
| US-063 (click) | `pilot.click("#entropy_cell_k")` → `EntropyCell.Selected` → `action_jump` → `_window_for_row` | modal `dismiss(window.start)` value (exact address) | AT-063b |
| US-064a | `#patch_doc_refresh_button` → `ActionRequested(refresh_doc)` → `ChangeService.load(source_path)` | `refresh_entries` table rows (new on-disk entry) | AT-064a |
| US-064b | `#patch_edit_json_button` → popup → Confirm → `parse_paste`→`load_text` | `ChangeService.document` via entries table (edited entry present) | AT-064b |
| US-064c | `load_doc` sets `source_path` (disable) vs `parse_paste` clears it (enable) | button `.disabled` state + `ChangeSetJsonScreen` push presence + entries unchanged (no clobber) | AT-064c |

No output-producing story is asserted only white-box: each deliverable is observed through the
Pilot e2e surface (report file on disk, dismiss value, table rows, disabled-state + screen-absent)
with boundary + negative evidence in the same node.

---

## 5. Engine-frozen + ledger (re-run this phase)

- **Engine-frozen guards:** `pytest test_engine_unchanged.py + tc031×3 -q` → **4 passed in 0.31s**
  → **0 diffs**. Frozen set (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`,
  `tui/mac.py`, `tui/color_policy.py`) + `entropy_service.py` untouched. All batch-37 code landed in
  NON-frozen modules (`screens.py`, `screens_directionb.py`, `app.py`, `styles.tcss`).
- **Ledger:** `pytest --collect-only -q` → **1385 tests collected**. Matches Inc-5 post-count
  (`1381 − 0 + 4 = 1385`) and the gate-run reconciliation (§1).
- **Snapshot suite:** `pytest test_tui_snapshot.py -q` → **32 passed, 2 xfailed** — exactly the two
  batch-37 entropy cells xfail; no NEW failure.

---

## 6. Residuals (ACCEPTED — not defects)

1. **2 entropy snapshot cells xfail** (`entropy-comfortable-80x24` / `-120x30`) → canonical-CI
   baseline regen post-merge; local regen forbidden (snapshot-regen convention). `xfail(strict=False)`.
2. **LOW carries** (reviewer-accepted, per-increment):
   - Inc-1 F1: TC-328 uses a status-line proxy for the None-guard (structural, not wall-clock).
   - Inc-2 F1/F2: AT-061a activation via `.press()` not `pilot.click` (zero `pilot.click` precedent
     in suite; still routes end-to-end through `on_button_pressed`→message→handler — NOT a proxy);
     b-path assertions distributed across the node.
   - Inc-3 F1: `ENTROPY_STRIP_MAX_CELLS` vestigial after fixed-512 page budget. F2: drift-mark arg.
   - Inc-4 F1: page-2 real-click is unit-covered (TC-327), AT drives page-0 cells. F2: `_refresh_view`
     deferred-mount race is benign (prune-then-mount via `call_after_refresh`, GREEN across toggles).
   - Inc-5 F1: `Escape` not bound on `ChangeSetJsonScreen` (Cancel button is; data-safe).
3. **Pre-existing backlog (reviewer-flagged, NOT introduced by batch-37):** neither `#patch_paste_text`
   nor the new `#changeset_json_text` popup caps native bracketed paste at 64 KiB — both are plain
   `TextArea`s inheriting Textual's native paste; the 65 KiB `os_clipboard_input` funnel guards a
   different ingress. US-064b adds NO new/second uncapped ingress (S-01 discharged: identical widget
   class to the existing box). The uncapped native-paste bound is a **separate backlog item**, not a
   batch-37 regression.
4. **Owed to Phase 6 (docs):** REQUIREMENTS.md rows R-TUI-049..053 (proposed, not yet added);
   BACKLOG.md refresh (B-11..B-14 → done); docstrings/README as needed.

---

## 7. Phase-4 finding — TC-319 cross-file census miss (orchestrator-fixed) + control candidate

**Finding (process, severity LOW — caught + fixed in-phase, zero shipped defect).** The first gate
run had **1 FAILURE**: `test_tui_patch_layout.py::test_tc319_regroup_section_structure_census`. Inc-1
added `#patch_doc_refresh_button` to `#patch_doc_controls` and updated its HOME-file census
(`test_at057a_...` in `test_tui_patch_editor_v2.py`) — but NOT the SIBLING census
`test_tc319_regroup_section_structure_census` in `test_tui_patch_layout.py`, because the per-increment
run was scoped to `test_tui_patch_editor_v2.py`. The sibling census pins the SAME `#patch_doc_controls`
child order in a different file, so the additive button broke it.

**Resolution (test-only supersession):** the orchestrator added `patch_doc_refresh_button` to TC-319's
expected child list, matching the SHIPPED order (Load / Refresh / …). The clean re-run in §1 is
post-fix; I re-ran TC-319 by nodeid this phase → **PASS**. This is a behaviour-tracking census update,
not a weakened assertion.

**Process lesson → proposed control candidate (for Phase 5 encode approval):**
> **C-CAND (census cross-file sweep):** when an increment mutates a widget/layout surface, the
> supersession census MUST sweep ALL test files that pin that surface — not only the increment's
> home file. Grep the touched id/container across `tests/` before declaring the census closed.
This is a **C-14 family** extension (location-move census sweeps e2e observers) generalized to
same-surface pins in sibling files. Flagged for AskUserQuestion approval at Phase 5, per the
control-encode-approval rule.

---

## 8. Evidence checklist (C-18 / two-layer / bidirectional gate)

- [x] **Acceptance criteria Given/When/Then** — §3 AT blocks (from 01-req §3) are observable+falsifiable.
- [x] **TCs have explicit Expected** — §2 each node asserts specific content (addresses, entry ids,
  band meanings, indicator text), not vague "works".
- [x] **Edge cases empty/boundary/invalid/error** — covered per AT boundary catalog (01-req §3): 0-window
  empty state, 512-window single page, malformed-JSON collect-don't-abort, deleted-file diagnostic,
  file→paste transition, out-of-range click no-op.
- [x] **Regression checklist** — AT-036b (remap load-bearing guard) green; Inc-1/2 shared-file suites
  55 passed; TC-036.5 truncation nodes redefined (not xfailed); frozen 0 diffs.
- [x] **Exit criteria stated** — 0 gate failures; 8/8 ATs green; ledger 1385; frozen 0 diffs (met).
- [x] **No real PII/secrets** — fixtures only (`large_s19`, `tmp_path`, `0x555`/`0x777` synthetic).
- [x] **Test-results left blank for human** — N/A: these ran and are cited with real output, not claimed.
- [x] **Layer B black-box** — every output-producing story observed through the SHIPPED surface
  (report-on-disk, dismiss value, table rows, disabled-state) with boundary + negative evidence (§3/§4).
- [x] **Bidirectional surface-reachability** — every input dimension AND every output/deliverable
  exercised through the handler, not only the service API (§4 matrix).
- [x] **No unfilled template** — no `<...>` / `TC-NNN` placeholders remain; the phase ran.

---

## 9. Axis verdict

| Axis | Assessment |
|------|-----------|
| **Coverage** | 5/5 stories; 8/8 black-box ATs (each ≥1 shipped-surface AC); 10/10 white-box nodes; boundary catalogs discharged; both index directions (input→handler, deliverable←surface) exercised. **No uncovered story or deliverable.** |
| **Certainty** | Every AT falsifiable + counterfactual RED recorded (real feature-absence). AT-036b regression guard proves the sort/page remap did not break the pre-existing dismiss contract. A-01 data-loss footgun closed + proven (AT-064c: 0 mutation on guarded open). |
| **Evidence** | Gate tail `1358 passed … 0 failed` (C-25); targeted re-runs 9+6+3+4 green with cited output; frozen 0 diffs; ledger 1385 reconciles; xfail set (5) fully explained (2 batch-37 canonical-regen-pending + 3 pre-existing). |

**VERDICT: PASS.** No named gap blocks the gate. Residuals are all accepted (canonical-regen-pending
snapshot cells + LOW carries) or belong to a separate backlog item. The single Phase-4 finding
(TC-319 census miss) was caught and fixed in-phase with a control candidate proposed for Phase 5.
