# Increment E5a — multi-variant workspace + models — batch-07

**Date:** 2026-06-10 · **LLRs:** 005.1, 005.2, 005.3, 007.7-partial · **TCs:** TC-025..TC-027 (+ reports-dir neutrality)

## 1. What changed
- **`workspace.py`**: `validate_project_files` no longer rejects N S19/HEX (single-MAC/single-A2L rejections preserved verbatim); `data_files` returned in deterministic `(name.lower(), name)` order; NEW `build_variant_set(project_name, data_files, active_id=None)` (lives here — needs the extension sets; models stays pure data; raises on unknown explicit `active_id` = the E6 manifest boundary).
- **`models.py`**: frozen `VariantDescriptor {variant_id=stem, path, file_type}` + `ProjectVariantSet {project_name, variants ordered, active_id}`; `LoadedFile.variant_id: Optional[str] = None` appended LAST (no field removed/retyped/reordered).
- **`tests/test_workspace_variants.py`** (NEW, 12 tests): N-variant acceptance + order, MAC/A2L rejections held, single-S19 equivalence, reports/-dir neutrality, dataclass construction, build_variant_set semantics.
- **Reported deviation (ratify):** 3 legacy cardinality-lock tests contradicted the relaxation by definition and were flipped (test-only): `test_tui_helpers.py` (rejects-multiple-data → accepts), `test_tui_directionb.py::tc034` (two-S19 block), `test_tui_workspace.py::tc048` (case-collision — vacuous on NTFS, real on ubuntu CI). Conflict rule: newer requirement supersedes batch-06-era locks; surfaced, not silent.

## 2. Files
4 planned + 3 lock-test flips (49 lines) = 7.

## 3. Results (orchestrator-verified)
- `test_workspace_variants.py` + `test_tui_workspace.py`: `45 passed` · survival guards `66 passed, 1 xfailed` (LoadedFile compat proven) · Lean: **`630 passed / 0 failed`** — ledger exact 618 + 12 = 630 ✓ (agent's pre-flip intermediate run showed exactly the 2 predicted legacy reds).

## 4. Risks / flags for next increments
- **Duplicate `variant_id`** if `fw.s19` + `fw.hex` coexist (stems collide) — affects `active_id`/manifest semantics; **decide at E6** (suffix-qualified ids or rejection).
- Case-only collisions on Linux now yield two variants silently (was error) — same E6 discussion.
- **`_sync_loaded_file_to_project` (analysis, untouched):** no warning becomes wrong, BUT loading a 2nd S19 over an active project silently skips sync (`:2549-2552`) — E5b decides append-as-variant.
- **`_handle_save_project` stale guard (`:2453-2459`):** cross-suffix block now contradicts the variant model — E5b reworks.

## 5. Deviations
The 3 lock-test flips (above, ratify at gate). Otherwise none.

## 6. Pending
E5b: selector UI + label + the two app.py findings. E6: manifest + variant_id collision decision.

## 7. Next
E5b — `SelectVariantScreen`, `action_select_variant`, `update_project_labels (i/N)`, thread-contract activation path (005.4/.5), first-variant default (005.6-partial), rework the save-project guard, decide sync-append.
