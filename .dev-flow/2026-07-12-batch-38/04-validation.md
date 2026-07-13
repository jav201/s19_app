# 04 — Validation (Phase 4) — 2026-07-12-batch-38

> **Owner:** qa-reviewer (Phase 4). Consumes the ONE orchestrator-owned gate run (C-25) and reconciles the two validation layers against the shipped surface. The full suite was **not** re-run here; only targeted frozen-guard nodes were executed to confirm the freeze.

## BLUF

**Gate verdict: PASS.** The orchestrator's single gate run is **1377 passed, 2 skipped, 20 deselected, 5 xfailed, 0 failed (exit 0)**. All 6 black-box ATs and all 14 white-box TCs (TC-332…TC-345) reconcile to distinct GREEN on-disk nodes; each AT drives the shipped surface with a real RED counterfactual (all captured RED-first per the increment packets). 0 engine-frozen SOURCE diffs and 0 engine-frozen TEST diffs vs `main` (`test_tui_a2l.py` restored byte-identical after the Phase-3 relocation; `tc032` green). The 5 xfails = 3 pre-existing declared markers + 2 batch-38 snapshot-drift cells (`xfail(strict=False)`); **no batch-38 xfail masks a real regression**. Every story has a black-box deliverable observation — **no blocker**.

**Axis verdict — Coverage: PASS · Certainty: PASS · Evidence: PASS.**

---

## Gate run consumed (orchestrator-owned, C-25)

`python -m pytest -q -m "not slow"` → **1377 passed, 2 skipped, 20 deselected, 5 xfailed, 0 failed, exit 0** in 732s (12:12). Snapshot report: 29 passed, 2 mismatched (the 2 batch-38 patch cells under `xfail(strict=False)`). Log: `…/0c2d80d4-…/scratchpad/batch38_gate_run2.log`. Phase-4 did not re-run it (C-25).

---

## 1. Layer B — black-box AT reconciliation (C-18: one AT → exactly one on-disk node)

Each AT drives the SHIPPED surface via Textual Pilot; each maps to exactly one distinct on-disk test-function node (verified by grep of the exact function id). Counterfactuals are the real RED conditions captured in the increment packets (RED-first).

| AT | Story | On-disk node (file::function) | C-18 | Real counterfactual (why RED pre-impl) | Deliverable observed through shipped surface |
|----|-------|-------------------------------|------|-----------------------------------------|-----------------------------------------------|
| **AT-065a** | US-065 | `tests/test_tui_directionb.py::test_at065a_change_doc_label_reads_as_dropdown_alternative` (:7492) | single | At `main`, placeholder is `"path to v2 change-set .json"` (:1904) + title `"Change document (v2 JSON)"` (:1854) → verbatim-equality + "no `v2`" assertions fail RED (captured `AssertionError` Inc-1 §4) | Rendered `#patch_doc_path_input.placeholder` + section-title `Label.renderable` via `query_one` on the live composed panel |
| **AT-066a** | US-066 | `tests/test_tui_a2l_issue_recolor.py::test_at_066a_oversized_a2l_address_warns_naming_tag` (:532) — **RELOCATED** from frozen `test_tui_a2l.py` in Phase 3 | single | At `main`, no `>0xFFFFFFFF` producer → 0 `A2L_ADDRESS_EXCEEDS_32BIT` on the issues surface → assertion fails RED (Inc-2) | WARNING `IssueRow` on `GroupedIssuesPanel`, driven by the **app load handler** (not the service API), naming tag `BIG_TAG`; sibling `0xFFFFFFFF` negative control = no warning |
| **AT-066b** | US-066 (C-17) | `tests/test_tui_a2l_issue_recolor.py::test_at_066b_oversized_hostile_tag_name_renders_safely` (:446) | single (distinct fn, same file) | If the tag name were interpolated into a markup-parsed string, `[red]…[/red]` would be consumed as style (brackets absent) or raise `MarkupError` → fails RED (Inc-2) | Rendered WARNING message text via issues surface: brackets/`[link=…]` **verbatim**, ANSI **neutralized/stripped**, 0 `MarkupError` |
| **AT-067a** | US-067 (C-16) | `tests/test_tui_variants.py::test_at067a_variant_info_button_opens_help_modal` (:435) | single | At `main`, `#patch_variant_info_button` absent → real `pilot.click` raises `NoMatches` (no click target) → fails RED (Inc-3) | Real `pilot.click` → `app.screen` is `VariantHelpScreen`; body contains the 3 explanation tokens; dismiss returns to prior screen |
| **AT-068a** | US-068a (C-16, + A-01) | `tests/test_tui_patch_editor_v2.py::test_at068a_undo_redo_roundtrip_through_surface` (:3121) | single | At `main`, `#patch_undo_button` absent → real `pilot.click` raises `NoMatches` → fails RED (Inc-4) | Real Undo/Redo clicks → `#patch_doc_entries_table` rows restore byte/field-for-field (`0x200='REV_A'`) then re-apply; empty-history no-op. **A-01 branch** in its own discriminating node `test_tc344_undo_redo_disabled_for_file_backed_document` (:3201) |
| **AT-068b** | US-068b (C-16, + A-01) | `tests/test_tui_patch_editor_v2.py::test_at068b_per_entry_json_popup_edits_only_selected_entry` (:3396) | single (distinct fn from AT-068a) | At `main`, `EntryJsonScreen` / `#patch_entry_edit_json_button` absent → `ImportError` / no click target → fails RED (Inc-5) | Real click on the NEW `#patch_entry_edit_json_button` → single-entry-seed popup (no `entries` key, `address=='0x300'`); Confirm edits only entry *i*, siblings byte-identical. **A-01 branch** in its own node `test_tc345_entry_edit_json_disabled_for_file_backed_document` (:3499) |

**A-01 boundary branches:** AT-068a and AT-068b each fold their A-01 file-backed disable-guard into a **separate discriminating node** (TC-344 / TC-345), each asserting both states (file-loaded → disabled, paste-authored → enabled) in one node — C-10 discriminator, batch-37 AT-064c precedent. C-18 holds: AT-066a/AT-066b are two distinct functions in the same file, and AT-068a/AT-068b are two distinct functions in `test_tui_patch_editor_v2.py` — one AT → one node at node granularity.

---

## 2. Layer A — white-box TC reconciliation (TC-332…TC-345 → LLR, node, result)

Every TC maps to its LLR, exists on disk (grep-verified), and is GREEN inside the gate run.

| TC | LLR (R-TUI-) | On-disk node | Result |
|----|--------------|--------------|--------|
| **TC-332** | LLR-065.1/.2 (054) | `test_tui_directionb.py::test_tc332_change_doc_copy_pins_verbatim` (:7528) | GREEN |
| **TC-333** | LLR-066.1 (055) | `test_validation_service_supplemental.py::test_tc_333_oversized_address_producer_emits_named_warning` (:652) | GREEN |
| **TC-334** | LLR-066.2 (055) | `test_validation_service_supplemental.py::test_tc_334_oversized_warning_merges_in_both_branches_and_colours` (:672) | GREEN |
| **TC-335** | LLR-066.3 boundary (055) | `test_validation_service_supplemental.py::test_tc_335_oversized_address_boundary_and_non_int` (:719) | GREEN |
| **TC-336** | LLR-067.1 (056) | `test_tui_variants.py::test_tc336_tc337_help_message_pushes_modal_with_content` (:498) | GREEN |
| **TC-337** | LLR-067.2/.3 (056) | `test_tui_variants.py::test_tc336_tc337_help_message_pushes_modal_with_content` (:498) | GREEN |
| **TC-338** | LLR-068a.1 (057) | `test_change_service.py::test_tc338_history_bounded_and_deep_copy_no_alias` (:657) | GREEN |
| **TC-339** | LLR-068a.2 (057) | `test_change_service.py::test_tc339_undo_redo_restore_semantics_and_empty_noop` (:692) | GREEN |
| **TC-340** | LLR-068a.3 bound (057) | folded into TC-338/TC-339 (bound + empty no-op asserted in both) | GREEN |
| **TC-341** | LLR-068b.1 (058) | `test_tui_patch_editor_v2.py::test_tc341_entry_seed_json_is_single_entry_scoped_to_index` (:3296) | GREEN |
| **TC-342** | LLR-068b.2 (058) | `test_tui_patch_editor_v2.py::test_tc342_edit_entry_json_mutates_only_the_selected_index` (:3325) | GREEN |
| **TC-343** | LLR-068b.3 route (058) | `test_tui_patch_editor_v2.py::test_tc343_edit_entry_json_rejects_malformed_without_mutation` (:3356) | GREEN |
| **TC-344** | LLR-068a.4 A-01 (057) | `test_tui_patch_editor_v2.py::test_tc344_undo_redo_disabled_for_file_backed_document` (:3201) | GREEN |
| **TC-345** | LLR-068b.4 A-01 (058) | `test_tui_patch_editor_v2.py::test_tc345_entry_edit_json_disabled_for_file_backed_document` (:3499) | GREEN |

**Node-count note (V-5 reconciliation):** TC-337 is co-located with TC-336 in one combined node (`test_tc336_tc337_…`), and TC-340 (history bound + empty no-op) is asserted inside TC-338/TC-339 rather than a standalone `test_tc340` — both consistent with the §5.2 mapping (TC-332 covers the copy pair; TC-337 covers routing + content). Every LLR retains ≥1 GREEN TC. TC-336 is `.py`-live because the geometry pilot-measure lives beside it (`test_variant_help_modal_fits_at_both_sizes` :543, C-23 inspection — additive, non-gating).

---

## 3. Bidirectional surface-reachability matrix (input dim → handler; deliverable → observed surface)

Every named input dimension AND every named deliverable is exercised/observed **through the handler**, not only the service API.

| Story | Input dimension → handler path | Deliverable → observed surface | Reachable both ways? |
|-------|--------------------------------|--------------------------------|----------------------|
| US-065 | Patch-editor compose (open) | `#patch_doc_path_input.placeholder` + section-title `Label.renderable` on the live widget (AT-065a) | ✓ |
| US-066 (warn) | A2L `address` field → **app load handler** → `validation_service.build_validation_report` | WARNING `IssueRow` (`A2L_ADDRESS_EXCEEDS_32BIT`) on `GroupedIssuesPanel` (AT-066a) | ✓ (input via load handler, not `enrich_tags_and_render`; output via issues panel) |
| US-066 (safety) | hostile **tag name** → load handler | rendered WARNING message `.plain` on the issues surface (AT-066b) | ✓ |
| US-067 | real `pilot.click` on `#patch_variant_info_button` → panel message → app handler | help `ModalScreen` in `app.screen` + body tokens (AT-067a) | ✓ |
| US-068a | entry mutation via patch-editor controls → undo/redo real clicks → app handlers → `ChangeService.undo/redo` | restored/re-applied `#patch_doc_entries_table` rows; Undo/Redo disabled when file-backed (AT-068a + TC-344) | ✓ |
| US-068b | entry select + real `pilot.click` on `#patch_entry_edit_json_button` → app handler → `EntryJsonScreen` → `edit_entry_json` | single-entry popup seed + post-confirm entries table (siblings byte-identical); control disabled when file-backed (AT-068b + TC-345) | ✓ |

All 5 stories: every input dimension flows through the shipped handler and every deliverable is observed through the shipped surface. White-box TCs may call the service directly; the black-box ATs are the reachability guarantee.

---

## 4. xfail / skip / deselect reconciliation

**5 xfailed = 3 pre-existing + 2 batch-38 — no batch-38 xfail masks a real regression.**

**3 pre-existing (declared `@pytest.mark.xfail` markers, unrelated to batch-38 — the batch-37 baseline set):**
1. `tests/test_tui_app.py:1784` — pre-existing documented Finding.
2. `tests/test_tui_public_api.py:162` — pre-existing documented Finding (turns to pass when the underlying Finding is fixed).
3. `tests/test_validation_engine.py:211` — pre-existing documented Finding in the engine (frozen module; not touched this batch).

These three carry over unchanged from batch-37 (`test_tui_directionb.py:5477-78` explicitly documents the batch baseline of "3 documented xfailed cases"). None sits in a batch-38-touched code path.

**2 batch-38 (`xfail(strict=False)` snapshot-drift cells — expected, not masking):**
4. `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-80x24]`
5. `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-120x30]`

Both marked by `_batch38_drift_marks` (`test_tui_snapshot.py:493`), reason: *"batch-38 re-renders both patch cells: US-065 change-doc relabel (title 'Change document (JSON)' + rewritten #patch_doc_path_input placeholder) AND US-067 variant info button ('?' beside #patch_variant_select); baseline regen pending in canonical CI"*. These are **known, intended** UI changes (US-065 copy + US-067 info button + US-068a undo/redo row + US-068b per-entry button all fold into the same two `patch` cells). `strict=False` + canonical-CI-only regen is the batch-33/36/37 precedent (PR #67/#69 pattern). **They do not mask a regression** — the behavioral correctness of those UI changes is proven GREEN by AT-065a / AT-067a / AT-068a / AT-068b through the live surface; the snapshot is a cosmetic pixel-oracle awaiting canonical baseline regen.

**2 skipped:** consistent with the batch-37 baseline (2 pre-existing skips; unchanged count across the batch). No batch-38 code introduces a skip.

**20 deselected:** the `slow`-marked stress/perf smoke tests excluded by `-m "not slow"` (pyproject `slow` marker) — identical count to batch-37. Expected/pre-existing.

---

## 5. Engine-frozen check

`git diff --name-only main` (13 files) contains **0 engine-frozen SOURCE files** and **0 engine-frozen TEST files**:

- **Frozen SOURCE set** (`core.py` / `hexfile.py` / `range_index.py` / `validation/*` / `tui/a2l.py` / `tui/mac.py` / `tui/color_policy.py`): **none present** in the diff. US-066's WARNING is produced in the non-frozen `s19_app/tui/services/validation_service.py` (sibling of `supplemental_a2l_row_issues`), which IS in the diff but is NOT frozen. ✓
- **Frozen TEST set** (`_ENGINE_TEST_FILES`, incl. `test_tui_a2l.py`): **`tests/test_tui_a2l.py` is NOT in the diff** → byte-identical to `main`. The Inc-2 POST-GATE FIX relocated AT-066a out of the frozen `test_tui_a2l.py` into non-frozen `test_tui_a2l_issue_recolor.py`, restoring the freeze (the batch-level `test_tc032` RED flagged in Inc-5 §6 is now resolved). ✓

**Guard run (Phase-4 targeted):** `pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py -k "tc031 or tc032" -q` → **6 passed, 160 deselected in 0.48s** (tc031 ×3 source-freeze + tc032 test-file-freeze + engine_unchanged nodes) — 0 frozen diffs, incl. `test_tui_a2l.py == main`.

---

## 6. Blocker check — every story has a black-box deliverable observation

| Story | Black-box AT observing the deliverable through the shipped surface | Status |
|-------|-------------------------------------------------------------------|--------|
| US-065 | AT-065a (rendered widget text) | ✓ present |
| US-066 | AT-066a (issues panel) + AT-066b (rendered message) | ✓ present |
| US-067 | AT-067a (modal in `app.screen`) | ✓ present |
| US-068a | AT-068a (entries table round-trip) | ✓ present |
| US-068b | AT-068b (entries table + single-entry popup) | ✓ present |

No story is validated by white-box TCs alone. **No blocker.**

---

## 7. Gaps

- **None gating.** The only open items are the **canonical-CI snapshot regen** for the 2 `patch` xfail cells (follow-up PR, batch-33/36/37 precedent) and the **3 pre-existing xfails** (documented Findings carried from prior batches, out of batch-38 scope). Neither blocks the gate.
- L1 (uncapped native-paste on the new `#entry_json_text` TextArea) is a **batch-39 carry** per the security review (02-review.md), not a batch-38 defect.

---

## 8. Evidence checklist (Phase-4 gate)

- [✓] **Acceptance criteria Given/When/Then / observable-outcome form** — §3 ATs of `01-requirements.md`; each AT states outcome + shipped surface + deliverable.
- [✓] **Test cases have explicit Expected, not vague "works"** — TC table §2; each TC asserts a specific value (verbatim copy, WARNING code, byte-identical siblings, disabled iff `source_path is not None`).
- [✓] **Edge cases: empty / boundary / invalid / error** — boundary TC-335 (`0xFFFFFFFF` vs `0x100000000`), TC-338/339 (history bound + empty no-op), invalid/route TC-343 (malformed JSON, `MF-JSON-PARSE`, no mutation), hostile AT-066b.
- [✓] **Regression checklist / frozen guard exists** — §5 engine-frozen (6 passed, 0 diffs); C-26 sibling-census sweeps green in every increment (18–19 passed unmodified).
- [✓] **Exit criteria stated** — §5.3 of `01-requirements.md`; axis verdict below.
- [✓] **No real PII / secrets** — fixtures are synthetic A2L / change-set data; hostile payloads are inert markup strings; no I/O or network added.
- [✓] **Test-results left blank unless actually run** — this artifact reports the orchestrator's real gate run (1377 passed) + Phase-4 targeted frozen-guard run (6 passed) + node-existence greps; nothing fabricated.
- [✓] **Layer B (black-box) through the SHIPPED surface with boundary + negative evidence** — §1: every output-producing story observed via Pilot e2e over the issues panel / modal / entries table / rendered widget; AT-066a in-range negative control; AT-068a empty-history + file-backed boundary.
- [✓] **Bidirectional surface-reachability** — §3 matrix: every input dim + every deliverable through the handler for all 5 stories.
- [✓] **No unfilled template** — all TC/AT/LLR ids concrete and node-resolved; no `<...>` / `TC-NNN` placeholders remain.

---

## Gate verdict (exit-criteria axes)

- **Coverage — PASS.** 6/6 ATs + 14/14 TCs map to distinct GREEN on-disk nodes; every LLR (R-TUI-054…058) has ≥1 passing TC; every US has ≥1 passing AT observing its outcome through the shipped surface with boundary + negative evidence.
- **Certainty — PASS.** Every AT has a real RED counterfactual captured RED-first (verbatim copy / missing producer / `NoMatches` / `ImportError`); the Phase-2 blockers (B1 issue-code, B2 unsound counterfactual) are closed; 0 engine-frozen diffs (source + test, incl. `test_tui_a2l.py == main`).
- **Evidence — PASS.** One complete gate run (1377 passed, 0 failed, exit 0) consumed per C-25; 5 xfails fully reconciled (3 pre-existing + 2 batch-38 strict-false snapshot drift, none masking a regression); 2 skips + 20 deselected are the pre-existing/slow-marked expected set.

**Overall: PASS — proceed to Phase 5.**
