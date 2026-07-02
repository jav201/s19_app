# Increment 1 — HLR-035 (US-028 inline variant dropdown) — the single planned increment

> `Select#patch_variant_select` in the Variant pane switches the active variant through the EXISTING `_handle_select_variant` pipeline; persist-on-save only (Q2); disabled placeholder for degenerate states (Q1); switch-during-load picks suppressed (LLR-035.7). 5 files (at cap). All 11 new nodes green first run; targeted regression 66/66; ruff clean; counterfactual RED captured. Frozen-engine diff = 0.

## 1. What changed (per LLR)

- **LLR-035.1 (compose presence):** `#patch_variant_row` (Label "Active variant" + `Select#patch_variant_select`, `allow_blank=True`, prompt `"Variants in project"`, `disabled=True` at construction — F-8) composed inside `#patch_pane_variant`, always present regardless of project state. No inner `patch_*` id renamed/removed.
- **LLR-035.2 (geometry, C-13):** the variant group composes ABOVE `#patch_execute_row`. New `styles.tcss` rule `#patch_variant_row, #patch_execute_row { width:100%; height:auto }` — **required**: a bare `Container` defaults to `height: 1fr`, which would split the measured 35×3 @80×24 pane between the two groups and clip the Select. Verified live: Select first row = pane content row +1 (visible at scroll 0) at both 80×24 and 120×30; execute group scrolls below the fold @80×24 via the batch-22 `overflow-y: auto` rung. A-1 resolved by measurement: Label+Select = 4 rows, first Select row visible → the sacrificial-Label contingency was NOT needed.
- **LLR-035.3 (options refresh + preselection):** new `S19TuiApp._refresh_patch_variant_select` — N≥2 → `(variant_id, variant_id)` options in `ProjectVariantSet` model order (mirrors `_prefill_diff_variants`) + `value = active_id`; N<2/no project → `set_variants([])` → blank + disabled, NO single-id preselection (F-2). Trigger set (F-3): (a) `action_show_screen("patch")` branch, alongside `_prefill_patch_change_files`; (b) the tail of `update_project_labels` — **every variant-set mutation site already funnels through it** (project load :4188-equiv, save, variant append, activation apply-finalize), so variant-set changes while the screen is shown re-sync with zero extra call sites. F-4 ordering: `set_options` strictly before value assignment in `PatchEditorPanel.set_variants`.
- **LLR-035.4 (wholesale routing):** new `PatchEditorPanel.VariantSelected` message (mirrors `ChangeFileSelected`); `on_select_changed` gained the variant branch (blank sentinel filtered in the panel); new app handler `on_patch_editor_panel_variant_selected` → `_handle_select_variant(variant_id)` UNCHANGED — all guards (no set / unknown id / missing file) and the `_pending_variant_id` → `load_from_path` → `_apply_prepared_load` stamping reused, none duplicated. Same-as-active short-circuit in the handler absorbs the F-4 repopulate echo pair.
- **LLR-035.5 (disabled invariant, Q1):** `disabled = len(options) < 2` inside `set_variants` (co-located with population; app passes `[]` for N<2). Construction default `disabled=True` holds the invariant from first paint.
- **LLR-035.6 (no new write surface, Q2):** zero disk writes added — the handler chain only stamps in-memory state via the existing pipeline. Inspection cross-check: `git diff origin/main -- s19_app | grep -c manifest_writer` = **0** (no new writer call sites).
- **LLR-035.7 (switch-during-load, security F2) — mechanism chosen: suppress-while-loading.** New `_variant_load_in_flight()` = `_pending_variant_id is not None` OR any unfinished `"load"`-group worker; the dropdown handler drops such picks with a status line (`"Variant switch ignored - a load is already in progress."`). **Why this option:** zero edits to the shared load pipeline (`_handle_select_variant` / `_start_load_worker` / `_apply_prepared_load` untouched) → the modal path is *demonstrably unaffected* (no shared-code change; regression suite confirms). The `is_cancelled`-check alternative leaves a check-to-dispatch window (worker passes the check, then the pick lands before its queued apply runs); the generation-stamp alternative requires threading a token through `load_from_path → worker → PreparedLoad` (largest blast radius). The stale display value after a suppressed pick self-heals at the in-flight activation's apply-finalize (LLR-035.3 re-sync). The pending+worker-group OR also covers a pick during a plain (non-variant) load — closing the phantom-copy side-door for the new surface entirely.

## 2. Files modified (5 of ≤5 — at cap, as roadmapped §6.6)

| File | Change | Lines |
|---|---|---|
| `s19_app/tui/screens_directionb.py` | `VariantSelected` message (:538-562); `set_variants` (:614-664); compose variant row (:797-808) + docstring; `on_select_changed` variant branch (:1025-1034) + docstring | +124/−9 |
| `s19_app/tui/app.py` | `_refresh_patch_variant_select` (:2278); `_variant_load_in_flight` (:2329); `on_patch_editor_panel_variant_selected` (:2366); patch-activation hook (:3401); `update_project_labels` tail hook (:7830) + docstring | +144 |
| `s19_app/tui/styles.tcss` | `#patch_variant_row, #patch_execute_row { height: auto }` + rationale comment (:585-596) | +12 |
| `tests/test_tui_patch_variant.py` | NEW — AT-035a/b/c + TC-035.1–.7 (11 nodes, 797 lines) | new |
| `REQUIREMENTS.md` | index line 25 + §29 `R-PATCH-VARIANT-SELECT-001` (status `Automated`) | +12 |

Engine-frozen set: **0 diffs** (`git diff main` over `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` → empty).

## 3. How to test

```
python -m pytest tests/test_tui_patch_variant.py -v
python -m pytest tests/test_tui_patch_layout.py tests/test_tui_variants.py tests/test_tui_manifest_save.py tests/test_variant_execution.py tests/test_tui_patch_editor_v2.py tests/test_engine_unchanged.py -q
python -m ruff check s19_app/tui/screens_directionb.py s19_app/tui/app.py tests/test_tui_patch_variant.py
```

Full-suite gate run = orchestrator's (not run here per the long-run stall-avoidance instruction).

## 4. Test results (verbatim tails)

**New file — 11/11 green (first run, no fabrication):**
```
tests/test_tui_patch_variant.py::test_at035a_dropdown_switch_updates_label_and_image PASSED [  9%]
tests/test_tui_patch_variant.py::test_at035b_switch_persists_on_save_and_load_consumes PASSED [ 18%]
tests/test_tui_patch_variant.py::test_at035c_no_project_disabled_placeholder PASSED [ 27%]
tests/test_tui_patch_variant.py::test_at035c_single_variant_disabled_placeholder PASSED [ 36%]
tests/test_tui_patch_variant.py::test_tc_035_1_compose_presence PASSED   [ 45%]
tests/test_tui_patch_variant.py::test_tc_035_2_variant_group_above_execute_row PASSED [ 54%]
tests/test_tui_patch_variant.py::test_tc_035_3_options_order_preselection_and_triggers PASSED [ 63%]
tests/test_tui_patch_variant.py::test_tc_035_4_routing_guards PASSED     [ 72%]
tests/test_tui_patch_variant.py::test_tc_035_5_disabled_state_table PASSED [ 81%]
tests/test_tui_patch_variant.py::test_tc_035_6_switch_writes_nothing_to_disk PASSED [ 90%]
tests/test_tui_patch_variant.py::test_tc_035_7_rapid_double_pick_stays_consistent PASSED [100%]
============================= 11 passed in 31.35s =============================
```

**Targeted regression — 0 failures:**
```
..................................................................       [100%]
66 passed in 69.04s (0:01:09)
```

**Ruff:** `All checks passed!`

**Counterfactual RED (QC-2, AT-035a):** routing reverted (handler body short-circuited to `return`), run, captured, restored, re-green:
```
>       assert "proj:b (2/2)" in label_after, (
            f"dropdown switch must relabel to proj:b (2/2), got {label_after!r}"
        )
E       AssertionError: dropdown switch must relabel to proj:b (2/2), got 'Project: proj:a (1/2)'
E       assert 'proj:b (2/2)' in 'Project: proj:a (1/2)'
tests\test_tui_patch_variant.py:166: AssertionError
FAILED tests/test_tui_patch_variant.py::test_at035a_dropdown_switch_updates_label_and_image
============================== 1 failed in 3.95s ==============================
```
(Exactly the silent-no-op failure mode the gate exists to catch.) Post-restore: `11 passed in 31.38s`.

**Test-count delta:** `pytest --collect-only -q -m "not slow"` → **1002 collected** (base 991 → **+11**).

## LLR → test-node coverage table (V-5 reconciliation input)

| Requirement | Test node (tests/test_tui_patch_variant.py) | `-k` selector |
|---|---|---|
| AT-035a (GATE, C-10) | `test_at035a_dropdown_switch_updates_label_and_image` | `at035a` |
| AT-035b (GATE, C-12) | `test_at035b_switch_persists_on_save_and_load_consumes` | `at035b` |
| AT-035c (GATE) | `test_at035c_no_project_disabled_placeholder` + `test_at035c_single_variant_disabled_placeholder` | `at035c` |
| LLR-035.1 / TC-035.1 | `test_tc_035_1_compose_presence` | `tc_035_1` |
| LLR-035.2 / TC-035.2 | `test_tc_035_2_variant_group_above_execute_row` (80×24 + 120×30) | `tc_035_2` |
| LLR-035.3 / TC-035.3 | `test_tc_035_3_options_order_preselection_and_triggers` (order trio, dup-stem, both F-3 triggers, F-2 blank) | `tc_035_3` |
| LLR-035.4 / TC-035.4 | `test_tc_035_4_routing_guards` (1 activation; echo/blank/unknown/missing-file = 0) | `tc_035_4` |
| LLR-035.5 / TC-035.5 | `test_tc_035_5_disabled_state_table` | `tc_035_5` |
| LLR-035.6 / TC-035.6 | `test_tc_035_6_switch_writes_nothing_to_disk` (+ diff inspection: 0 new `manifest_writer` call sites) | `tc_035_6` |
| LLR-035.7 / TC-035.7 | `test_tc_035_7_rapid_double_pick_stays_consistent` (b→c pick while b in flight; also covers content=label coherence + 0 files) | `tc_035_7` |
| C-12 guard (kept, not gate) | `tests/test_variant_execution.py::test_load_project_honors_manifest_active_variant` (pre-existing, untouched, green in regression) | — |

## Deviations from spec (§6.5-style Before/After — FLAGGED LOUDLY)

- **D-1 (sentinel binding — framework fact, not a behavior change).**
  **Before (spec/01b text):** blank sentinel = `Select.BLANK`; asserts `select.value is Select.BLANK`.
  **After (as implemented):** blank sentinel = **`Select.NULL`**. In the installed textual **8.2.5** the blank value is `Select.NULL` (a `NoSelection` instance, verified live: repopulate emits `Changed(Select.NULL)` then `Changed(active)`); `Select.BLANK` resolves to an unrelated inherited `Widget.BLANK` bool (`False`) and **never matches a blank value**. The panel filter and all test asserts bind to `Select.NULL`; the LLR's observable contract (blank placeholder, echo-pair absorption) is unchanged. **Side finding (out of scope, chipped):** the pre-existing US-026 change-file branch uses `event.value is Select.BLANK` — a dead filter; on a repopulate reset it can post `ChangeFileSelected("Select.NULL")` and surface a spurious load-error status. Left untouched (surgical rule); flagged as background task "Fix dead blank-filter in change-file dropdown" (task_478df389).
- **D-2 (AT-035b drive detail).**
  **Before (01b sketch):** save back into the SAME loaded project `"proj"`.
  **After (as implemented):** save into a sibling project `"proj2"` pre-seeded with `a.s19`.
  **Why:** the shipped save flow unconditionally copies `current_file.path` (the workarea-temp copy of `b.s19`) into the target dir; saving into `"proj"` collides with the existing `proj/b.s19` and `copy_into_workarea`'s dedup renames it `b_1.s19` → the handler-written manifest would legitimately carry `active_variant == "b_1"`, failing the `== "b"` assert against a CORRECT implementation. That dedup-on-resave is pre-existing save-flow behavior, out of US-028's scope. The `"proj2"`-with-preseeded-`a.s19` drive preserves every C-12 property: shipped save handler writes the manifest over a 2-variant {a, b} set, raw `json.loads` re-read, counterfactual power intact (reverted route → manifest carries `"a"` → RED), and the consume leg is meaningful (`a` sorts first, so a manifest-ignoring load observably lands on `a`).
- **D-3 (TC-035.2 threshold binding @80×24).** The numeric `region.y` ordering (`vrow.region.y < erow.region.y`) is asserted whenever the execute row is compositor-mapped (always @120×30). @80×24 the execute row can be fully below the fold, where Textual reports the NULL region (0,0,0,0) — the ordering there is carried by the structural compose-order assert (`pane.children == [patch_variant_row, patch_execute_row]`, the LLR's own acceptance criterion) plus the Select-first-row-visible-at-scroll-0 numeric assert, which held at BOTH sizes.

## 5. Risks

- **Suppress-while-loading UX:** a pick during a load is dropped (status line), not queued. The dropdown may briefly display the suppressed id until the in-flight apply re-syncs it (self-healing, tested in TC-035.7). Accepted per LLR-035.7's design space.
- **Modal path exposure unchanged:** the pre-existing modal race window (spec rationale: "pre-existing surface") remains — by design; the acceptance criterion required only that the modal be unaffected or inherit, and this mechanism leaves it byte-identical.
- **`update_project_labels` hook:** the variant-dropdown re-sync now rides every label refresh (including A2L loads, where it's a harmless no-op repopulate). Single-site future-proof trigger; documented in both docstrings.
- **Batch-22 SVG snapshot cells:** pane tree changed → the two `patch-comfortable-*` cells will need regeneration once CI baselines land; they are xfail-until-baseline today (no red) — pre-declared in §6.1 of 01-requirements.
- **Pre-existing dead blank-filter** in the change-file branch (D-1 side finding) — chipped, not fixed here.

## 6. Pending items

- Full-suite gate run + V-5 reconciliation of the provisional ids against this doc's coverage table (orchestrator, Phase 4).
- 01-requirements §6.5: fold D-1 (Select.NULL binding) and D-2 (AT-035b drive) as reconciliation records if the gate accepts them.
- Background chip task_478df389 (US-026 blank-filter one-token fix + regression test) — separate session.

## 7. Suggested next task

Phase 4 validation gate: full non-slow suite (expect 1002 collected, 0 new failures vs main), V-5 id reconciliation from the coverage table above, then the Phase-5 post-mortem — with feature #8 (patch-editor overhaul) now fully closed (US-026/027/029 b21, US-030/031 b22, US-028 b23).

## Evidence checklist

- [x] Tests/type checks/lint pass — 11/11 new (31.35s), 66/66 targeted regression (69.04s), ruff clean (§4 verbatim). Full suite deliberately deferred to the orchestrator gate per task instruction.
- [x] No secrets in code or output — synthetic S19 constants + tmp_path projects only.
- [x] No destructive commands run — counterfactual was a reversible in-place edit, restored and re-verified green (`11 passed in 31.38s`).
- [x] File count within cap — 5 of ≤5 (§2 table), matching the §6.6 roadmap.
- [x] Review packet attached — this document (7 sections + coverage table + deviations).

---

## Orchestrator gate addendum (2026-07-02)

- **Independent code review (code-reviewer): APPROVE-WITH-NITS** — 3 LOW. All lens audits HELD: (a) F-4 echo pair absorbed (panel NULL filter screens_directionb.py:1030 + same-as-active app.py:2401, stamp :6283 sequenced before refresh :6382); (b) LLR-035.7 guard race-free in-handler, NO stuck-flag path (pending cleared at all 6 failure sites incl. _handle_load_error :6668; worker leg uses is_finished); (c) trigger funnel COMPLETE (all _variant_set mutation sites → update_project_labels; no project-close path exists in the codebase). Deviations D-1/D-2 independently re-verified (Select.BLANK is False on textual 8.2.5; proj2 drive keeps full C-12 counterfactual power via the a/a_1 dedup collision).
- **Nits folded by orchestrator:** F1 (4 docstring spots: BLANK prose → "blank sentinel (Select.NULL)") + F2 (TC-035.7 timing-assumption comment). F3 = observation-only, no change (behavior satisfies both LLR-035.4 and .7; noted for the Phase-4 validation narrative).
- **Full non-slow suite (orchestrator-run): 969 passed / 30 skipped / 3 xfailed / 0 FAILED (467s).** Collected 991 → 1002 (+11, −0). Post-fold re-verify: new file 11/11 green, ruff clean.
- **Frozen set:** 0-diff vs origin/main (verified directly).
- **Ledger:** post = 991 − 0 + 11 = **1002** ✓ reconciled.
