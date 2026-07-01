# Increment 1 — HLR-031 (US-027 dedicated patches folder)

> Change-document saves move from the workarea ROOT to `…/.s19tool/workarea/patches/`. 5 files. **code-reviewer: APPROVE** (0 HIGH/MED).

## 1. What changed
`WORKAREA_PATCHES="patches"` + `ensure_workarea` creates `patches/`; `write_change_document` routes final placement to `workarea/patches/` (internal default, no new param → zero caller churn). Folder-creation + no-clobber dedup are inherited from `copy_into_workarea` (not re-coded). `temp/` stays staging-only (unlinked in `finally`).

## 2. Files modified (5 of ≤5)
- `s19_app/tui/workspace.py` (LLR-031.1: const :19, mkdir :48)
- `s19_app/tui/changes/io.py` (LLR-031.2: import :57, placement `workarea / WORKAREA_PATCHES` :1354; Data Flow docstring)
- `tests/test_unified_write.py` (NET-NEW `test_tc031_write_target_resolves_under_patches_folder`)
- `tests/test_tui_patch_editor_v2.py` (NET-NEW `test_at031a_*` + `test_at031b_*`; glob→rglob fix in `test_action_routing_observable_effects`)
- `tests/test_change_service.py` (glob→rglob fix in `test_v2_save_load_round_trip`)

## 3. How to test
```
python -m pytest tests/test_unified_write.py::test_tc031_write_target_resolves_under_patches_folder \
  "tests/test_tui_patch_editor_v2.py::test_at031a_save_doc_lands_in_patches_folder" \
  "tests/test_tui_patch_editor_v2.py::test_at031b_two_saves_are_distinct_no_clobber" \
  tests/test_change_service.py::test_v2_save_load_round_trip -q
python -m pytest -q -m "not slow"
```

## 4. Test results
- New green: TC-031 (placement `is_relative_to(workarea/"patches")` + folder-creation), AT-031a (`save_doc` → file under `patches/`, parses v2), AT-031b (`len==2` AND distinct names). Plus 2 fixed pre-existing tests.
- **Counterfactual RED (QC-2):** revert placement to `workarea` root ⇒ TC-031 + AT-031a RED ("found []" / file one level up). Restored → green.
- Full non-slow: **974 → 977 collected (+3)**; 945 passed / 0 failed (vs origin/main ec3a2a7). 2 fixed tests = rewrite-in-place (net 0).
- ruff clean. **Frozen-engine diff 0** (verified vs origin/main). ≤5 files.

## 5. Independent review
- **code-reviewer: APPROVE.** rglob double-count risk **cleared** (temp stager unlinked in `finally` io.py:1367-1371 before assertions; ATs use non-recursive `.glob` on `patches/`). Placement/import/signature/dedup all verified. 1 LOW nit N1 (pre-existing "later increment" docstring on `write_change_document` — out of scope, future touch).
- **Security:** unchanged — the `copy_into_workarea` reparse/size/containment guards still cover the new `patches/` dest (resolves under the same workarea root). F1 read-path guard is an Inc2 concern.

## 6. Process note (for post-mortem)
The Phase-2 **supersession census missed 2 e2e placement globs** (`test_change_service.py:147`, `test_tui_patch_editor_v2.py:394`) that pinned the OLD root location non-recursively — it keyed on the white-box `tc018` placement tests, not the e2e save-observing tests. `software-dev` caught + fixed them (glob→rglob, intent preserved), reported not silently patched. Census-scope lesson → Phase 5.

## 7. Pending / next
- **Inc2 (HLR-030 dropdown)** — consumes this folder; includes the F1 read-path containment guard.
- **Inc3 (HLR-032 Checks clarity).**
