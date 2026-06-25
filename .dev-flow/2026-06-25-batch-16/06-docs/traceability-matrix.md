# Traceability Matrix — s19_app — Batch 2026-06-25-batch-16 (Phase 6)

**Story:** US-017 — Per-variant file-assignment at project save (closes batch-11 SCOPE-1).
**Verdict source:** `04-validation.md` — full suite **933 collected · 900+ passed · 0 failed · exit 0** (932 → 933 after the Phase-4 e2e AT). All node ids below are the **real reconciled `def test_*` nodes** verified on disk (V-5), not provisional spec ids.

Two chains are required for completeness (the Two-layer validation rule): a **behavioral** chain (black-box, the WHAT — the user-verified outcome through the shipped surface) and a **functional** chain (white-box, the HOW — HLR → LLR → TC). Both exist and are all PASS.

---

## A. Behavioral chain (black-box) — US-017 → AT → observed outcome

| US | Observable outcome (the WHAT) | Shipped surface | Acceptance test (real node) | File | Observed | Pre-fix | Result |
|----|-------------------------------|-----------------|-----------------------------|------|----------|---------|--------|
| US-017 | `project.json` carries `assignments[vid]` + `batch`, re-reads 0-drift, `active_variant` preserved | save dialog → `_handle_save_dialog` (pilot) | `test_at017_1_save_persists_and_round_trips_composition` | `test_tui_manifest_save.py` | on-disk round-trip | **RED** (`TypeError …'batch'`) | **PASS** |
| US-017 | consumer plan tuple **exactly equals** `batch + assignments[vid]` (`("doc.json","extra.json")` resolved) | `plan_variant_executions` over the disk-read manifest | `test_at017_2_consumer_pickup_of_saved_composition` | `test_variant_execution.py` | exact tuple | GREEN¹ (consumer-contract guard) | **PASS** |
| US-017 | consumer pickup observed **end-to-end through the handler** (re-reads handler-written `project.json`, feeds `plan_variant_executions`) | save handler → `read_project_manifest` → `plan_variant_executions` | `test_at017_2_e2e_consumer_pickup_through_handler` | `test_tui_manifest_save.py` | on-disk + plan tuple | (Phase-4 e2e; G-3 closure) | **PASS** |
| US-017 | zero-selection save re-reads identically (no regression), `active_variant` preserved | save handler, empty payload | `test_at017_3_zero_selection_save_no_regression` | `test_tui_manifest_save.py` | on-disk empty | GREEN² (no-regression guard) | **PASS** |
| US-017 | escaping assignment → POSITIVE refusal notice surfaced AND `project.json` not written | save handler + `_reject_unsafe_entry` | `test_at017_4_escaping_assignment_refused_no_file_written` | `test_tui_manifest_save.py` | refusal + no-file | **RED** (`TypeError …'batch'`) | **PASS** |
| US-017 | stem-collision (`fw.s19`+`fw.hex`) round-trips + picked up under **full-filename** id `fw.hex` (D-KEY) | save handler → consumer | `test_at017_5_stem_collision_assignment_keyed_by_full_filename` | `test_tui_manifest_save.py` | on-disk + plan | **RED** (`TypeError …'batch'`) | **PASS** |

¹ Correct, **not vacuous** (G-3). AT-017.2 writes `project.json` directly and exercises only the unchanged consumer `plan_variant_executions` — it is a **consumer-contract guard**, not a handler counterfactual, so it is correctly GREEN pre-fix. The genuine handler counterfactuals are AT-017.1 / AT-017.4 / AT-017.5 + TC-302/303 (all proven RED). The end-to-end through-handler observation is `test_at017_2_e2e_consumer_pickup_through_handler` (G-3 closure).
² Expected — a no-regression guard, not a counterfactual; the empty payload re-reads identically pre- and post-fix by design.

**The four genuine handler counterfactuals (RED pre-fix, GREEN post-fix):** AT-017.1, AT-017.4, AT-017.5, and TC-302/303 — each fails on the pre-feature tree with `TypeError: SaveProjectPayload.__init__() got an unexpected keyword argument 'batch'` (the handler/payload composition path does not exist pre-fix), proving SCOPE-1 closure through the shipped surface.

---

## B. Functional chain (white-box) — US-017 → HLR-017 → LLR → TC

| Requirement | Method | Test case(s) — real node | File:line (per `04-validation.md`) | Result |
|-------------|--------|--------------------------|------------------------------------|--------|
| **HLR-017** rollup | test (pilot) | `test_at017_1_save_persists_and_round_trips_composition`; `test_at017_2_consumer_pickup_of_saved_composition` | `test_tui_manifest_save.py:352`; `test_variant_execution.py:473` | **PASS** |
| **LLR-017.1** payload carries composition | test (unit) | `test_tc301_payload_carries_batch_and_assignments` | `test_tui_manifest_save.py:537` | **PASS** |
| **LLR-017.2** handler threads write + verify | test (integration) + inspection | `test_tc302_303_handler_threads_batch_assignments_to_write_and_verify` | `test_tui_manifest_save.py:557` (R1 `verify == write` `:611-612`) | **PASS** |
| **LLR-017.3** assignment UI, workarea-restricted, key from `variant_id` | test (pilot) | `test_tc304_...`; `test_tc305_...`; `test_tc306_...` | `test_tui_manifest_save.py:644`; `:705`; `:762` | **PASS** |
| **LLR-017.4** reader-as-oracle round-trip + consumer pickup | test (pilot) | `test_at017_1_...`; `test_at017_2_...`; `test_at017_5_...` | `test_tui_manifest_save.py:352`; `test_variant_execution.py:473`; `test_tui_manifest_save.py:477` | **PASS** |

**100% of LLR-017.\* covered by ≥1 passing TC.** Every functional row has an executed-verification node and a met numeric threshold (exact tuples / deep-equals, per `04-validation.md` STEP 3.1).

---

## C. LLR ↔ TC ↔ AT cross-map (the spine)

| LLR | TC (white-box) | AT (black-box) supporting the same property |
|-----|----------------|---------------------------------------------|
| LLR-017.1 | TC-301 | — (unit payload; surfaced via AT-017.1) |
| LLR-017.2 | TC-302/303 | AT-017.1 (write+verify both threaded; R1 intent identity) |
| LLR-017.3 | TC-304, TC-305, TC-306 | AT-017.4 (escape refusal through UI→handler), AT-017.5 (D-KEY collision) |
| LLR-017.4 | (round-trip oracle) | AT-017.1, AT-017.2, AT-017.2 e2e, AT-017.5 |

---

## D. Invariants verified (from `04-validation.md` STEP 3.4)

| Invariant | Status | Anchored node / evidence |
|-----------|--------|--------------------------|
| **R1** write-intent == verify-intent | ✓ | TC-302/303 `verify_calls[-1] == write_calls[-1]` (`test_tui_manifest_save.py:611-612`) |
| **D-KEY** key by full filename on collision | ✓ | AT-017.5 asserts `assignments == {"fw.hex": …}`; `_collect_composition` keys from `variant_id`, no `Path.stem` (`screens.py:298-303`) |
| **Exact-tuple consumer pickup** | ✓ | AT-017.2 `files_by_id["b"] == (doc.json, extra.json)` resolved; unassigned `a` gets `(doc.json,)` only |
| **Escape refused — positive + no-file** | ✓ | AT-017.4 refusal notice present AND `not (project_dir / PROJECT_MANIFEST_NAME).exists()` |
| **Zero-selection no-regression** | ✓ | AT-017.3 `batch==[]`/`assignments=={}`, `active_variant` preserved |
| **0 engine-frozen edits** | ✓ | `git diff --name-only origin/main` over the 7 frozen paths = empty |
| **`manifest_writer.py` + `variant_execution_service.py` EDIT-FREE** | ✓ | same diff over both service paths = empty (read-only substrate) |

---

## E. Notes (non-blocking, from `04-validation.md` §3.5)

- **G-3 (consumer-contract guard vs e2e through-handler AT):** AT-017.2 (`test_at017_2_consumer_pickup_of_saved_composition`) writes `project.json` directly and exercises only the unchanged consumer — it is a consumer-contract guard, **correctly GREEN pre-fix**, not a vacuous pass. The genuine handler counterfactuals are AT-017.1/.4/.5 + TC-302/303. The Phase-4 iteration added `test_at017_2_e2e_consumer_pickup_through_handler`, which observes the same exact-tuple pickup **end-to-end through the shipped handler** (re-reads the handler-written manifest), closing G-3. Both the guard and the e2e AT are retained.
- **G-1 (standing carry, not introduced):** `app.py` ruff C-7 (F401/F402) carried from batch-15; not in this batch's scope.
- **Provisional-id drift (V-5):** fully reconciled — all `TC-301..306` / `AT-017.1..5` provisional spec ids map to the real on-disk `def test_*` nodes above (node names encode `tc30x`/`at017_x`); no rename chore owed.

**Both chains complete · all rows PASS · 0 frozen/substrate edits. Dual traceability satisfied for US-017.**
